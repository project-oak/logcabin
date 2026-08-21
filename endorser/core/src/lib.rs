//
// Copyright 2026 The LogCabin Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Core Endorser: manages append only ledgers.
//!
//! Implemented as a state machine using type state pattern.
//! Valid transitions:
//!
//! - [none] --new_endorser()--> Uninitialized
//! - Uninitialized --activate()--> Active
//! - Active --finalize()--> Finalized

#![no_std]

extern crate alloc;

mod ledger;
mod takeover;
use logcabin_base::receipts;

pub use ledger::{Ledgers, SignedLedgerBlock};
pub use logcabin_base::{
    CohortConfig, CohortData, CohortFinalization, ConfigId, EndorserData, EndorserFinalization,
    EntryContents, InvalidConfigError, LedgerBlock, Sha256Digest,
};
pub use takeover::CohortTakeOver;

use alloc::boxed::Box;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// State types — each carries the fields valid only for that state.
// ---------------------------------------------------------------------------

/// The endorser has been created but not yet activated with a cohort config.
pub struct Uninitialized {
    signing_key: Box<SigningKey>,
}

/// The endorser is activated and actively serving.
pub struct Active {
    /// The ECDSA signing key, heap-allocated to avoid copying.
    signing_key: Box<SigningKey>,
    /// Public keys of the current cohort.
    cohort_config: CohortConfig,
    /// Instance ID: SHA-256 of the first cohort's concatenated verifying keys.
    instance_id: ConfigId,
    /// Map from ledger ID to the latest block in that ledger.
    ledgers: Ledgers,
    /// Activation receipt, computed once during activation.
    activation_receipt: Signature,
}

/// The endorser has been finalized: the signing key has been erased, and
/// the finalization receipt is available. The endorser cannot sign anything
/// new, but can still serve its receipts and ledger state.
pub struct Finalized {
    /// Instance ID inherited from (or computed during) activation.
    instance_id: ConfigId,
    /// Ledger state at finalization time, in ascending ledger_id order.
    ledgers: Ledgers,
    /// Activation receipt (carried over from the Active state).
    activation_receipt: Signature,
    /// ECDSA P-256 finalization receipt.
    finalization_receipt: Signature,
}

// ---------------------------------------------------------------------------
// Endorser
// ---------------------------------------------------------------------------

/// Core endorser.
///
/// The generic parameter `S` is the state type, which carries the data
/// relevant to the endorser's lifecycle phase. Common identity fields
/// (`alias`, `verifying_key`) live in the `Endorser` itself.
///
/// The signing key is heap-allocated (`Box<SigningKey>`) so it is never
/// copied — only the pointer is moved during state transitions.
pub struct Endorser<S> {
    /// Opaque identifier: first 8 bytes (big-endian u64) of
    /// SHA-256(SEC1 uncompressed verifying key).
    alias: u64,
    /// Public (verifying) ECDSA P-256 key.
    verifying_key: VerifyingKey,
    /// State-specific data.
    state: S,
}

impl Endorser<Uninitialized> {
    /// Creates a new endorser with a random ECDSA P-256 key pair.
    pub fn new() -> Endorser<Uninitialized> {
        let signing_key = Box::new(SigningKey::random(&mut rand_core::OsRng));
        let verifying_key = *signing_key.verifying_key();
        let alias = compute_alias(&verifying_key);
        Endorser {
            alias,
            verifying_key,
            state: Uninitialized { signing_key },
        }
    }
    /// Activates the endorser.
    ///
    /// If `prev_cohort_takeover` is `None`, starts a new service instance
    /// from scratch: the `instance_id` is computed as SHA-256 of the cohort
    /// config, and a default ledger (ID 0) is created.
    ///
    /// If `prev_cohort_takeover` is `Some`, activates via finalization data
    /// from a previous cohort: the endorser adopts the existing `instance_id`
    /// and the finalized ledger states, after verifying finalization receipts
    /// from the previous cohort (quorum check).
    ///
    /// Consumes the `Uninitialized` endorser and returns an `Active` one.
    /// On failure, the endorser is returned inside the error so the caller
    /// can reclaim it.
    pub fn activate(
        self,
        cohort_config: CohortConfig,
        prev_cohort_takeover: Option<CohortTakeOver>,
    ) -> Result<Endorser<Active>, ActivationError> {
        if !cohort_config.contains(&self.verifying_key) {
            return Err(ActivationError::KeyNotInConfig { endorser: self });
        }
        match prev_cohort_takeover {
            None => Ok(self.activate_new_instance(cohort_config)),
            Some(takeover) => self.activate_from_prev(cohort_config, takeover),
        }
    }

    /// Activates as a new service instance (no previous cohort).
    fn activate_new_instance(self, cohort_config: CohortConfig) -> Endorser<Active> {
        let instance_id = cohort_config.config_id();
        let mut ledgers = Ledgers::new();
        ledgers.insert(
            0,
            LedgerBlock {
                entry: [0u8; 32],
                index: 0,
                hash_chain_tail: [0u8; 32],
            },
        );
        let message = receipts::build_activate_new_instance_message(&instance_id);
        let activation_receipt = self.state.signing_key.sign(&message);

        Endorser {
            alias: self.alias,
            verifying_key: self.verifying_key,
            state: Active {
                signing_key: self.state.signing_key, // Moves the Box pointer, not the key.
                cohort_config,
                instance_id,
                ledgers,
                activation_receipt,
            },
        }
    }

    /// Activates via finalization data from a previous cohort.
    fn activate_from_prev(
        self,
        new_cohort_config: CohortConfig,
        prev_cohort_takeover: CohortTakeOver,
    ) -> Result<Endorser<Active>, ActivationError> {
        if !prev_cohort_takeover.verify(&new_cohort_config) {
            return Err(ActivationError::NoQuorum { endorser: self });
        }
        let (instance_id, prev_cohort_finalization, ledgers) = prev_cohort_takeover.into_parts();
        let message = receipts::build_activate_from_prev_message(
            &instance_id,
            &prev_cohort_finalization.config_id(),
            &new_cohort_config.config_id(),
            &ledgers.hash(),
        );
        let activation_receipt = self.state.signing_key.sign(&message);

        Ok(Endorser {
            alias: self.alias,
            verifying_key: self.verifying_key,
            state: Active {
                signing_key: self.state.signing_key, // Moves the Box pointer, not the key.
                cohort_config: new_cohort_config,
                instance_id,
                ledgers,
                activation_receipt,
            },
        })
    }
}

impl Endorser<Active> {
    /// Creates a new ledger with the given ID and an empty initial block.
    ///
    /// Returns the ECDSA P-256 signature (RAW R || S) over the
    /// `create_ledger` receipt message (see [`receipts`]).
    pub fn create_ledger(&mut self, ledger_id: u32) -> Result<Signature, CreateLedgerError> {
        if self.state.ledgers.contains_key(&ledger_id) {
            return Err(CreateLedgerError::AlreadyExists { ledger_id });
        }

        self.state.ledgers.insert(
            ledger_id,
            LedgerBlock {
                entry: [0u8; 32],
                index: 0,
                hash_chain_tail: [0u8; 32],
            },
        );

        let message = receipts::build_create_ledger_message(&self.state.instance_id, ledger_id);
        Ok(self.state.signing_key.sign(&message))
    }

    /// Returns the number of ledgers currently held by this endorser.
    pub fn ledger_count(&self) -> usize {
        self.state.ledgers.len()
    }

    /// Appends a new entry to a ledger.
    ///
    /// Updates the ledger block:
    ///   - `hash_chain_tail ← SHA256(old_tail || old_entry)`
    ///   - `index ← index + 1`
    ///   - `entry ← new entry`
    ///
    /// Returns the ECDSA P-256 signature (RAW R || S) over the
    /// `append_entry` receipt message (see [`receipts`]).
    pub fn append_entry(
        &mut self,
        ledger_id: u32,
        entry: EntryContents,
        expected_index: u64,
    ) -> Result<Signature, AppendEntryError> {
        let block =
            self.state
                .ledgers
                .get_mut(&ledger_id)
                .ok_or(AppendEntryError::LedgerNotFound(LedgerNotFoundError {
                    ledger_id,
                }))?;

        let new_index = block.index + 1;
        if expected_index != new_index {
            return Err(AppendEntryError::WrongIndex {
                expected: expected_index,
                actual: new_index,
            });
        }

        // Compute new hash chain tail: SHA256(old_tail || old_entry).
        let new_tail: Sha256Digest = {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(&block.hash_chain_tail);
            hasher.update(&block.entry);
            hasher.finalize().into()
        };

        // Update the ledger block.
        block.hash_chain_tail = new_tail;
        block.index = new_index;
        block.entry = entry;

        let message = receipts::build_append_entry_message(
            &self.state.instance_id,
            ledger_id,
            &entry,
            new_index,
            &new_tail,
        );
        Ok(self.state.signing_key.sign(&message))
    }

    /// Reads the latest entry from a ledger.
    ///
    /// Returns a [`SignedLedgerBlock`] containing the current ledger state
    /// and an ECDSA P-256 signature binding it to the supplied nonce.
    pub fn read_latest(
        &self,
        ledger_id: u32,
        nonce: u64,
    ) -> Result<SignedLedgerBlock, LedgerNotFoundError> {
        let block: &LedgerBlock = self
            .state
            .ledgers
            .get(&ledger_id)
            .ok_or(LedgerNotFoundError { ledger_id })?;

        Ok(SignedLedgerBlock::new(
            block,
            nonce,
            ledger_id,
            &self.state.instance_id,
            &self.state.signing_key,
        ))
    }

    /// Returns the activation receipt.
    ///
    /// This receipt is computed once during activation and is immutable.
    pub fn activation_receipt(&self) -> &Signature {
        &self.state.activation_receipt
    }

    /// Returns the instance ID.
    pub fn instance_id(&self) -> &ConfigId {
        &self.state.instance_id
    }

    /// Returns the cohort configuration.
    pub fn cohort_config(&self) -> &CohortConfig {
        &self.state.cohort_config
    }

    /// Finalizes the endorser, producing a finalization receipt and securely
    /// erasing the signing key.
    ///
    /// Consumes the `Active` endorser and returns a `Finalized` one. The
    /// `Box<SigningKey>` is dropped during the transition, triggering
    /// `ZeroizeOnDrop` which overwrites the key material with zeros.
    ///
    /// The receipt signs the `finalize` receipt message (see [`receipts`]).
    pub fn finalize(self, next_cohort_config: &CohortConfig) -> Endorser<Finalized> {
        let message = receipts::build_finalize_message(
            &self.state.instance_id,
            &self.state.cohort_config.config_id(),
            &next_cohort_config.config_id(),
            &self.state.ledgers.hash(),
        );

        let finalization_receipt = self.state.signing_key.sign(&message);
        // Dropping self.state.signing_key triggers ZeroizeOnDrop.
        Endorser {
            alias: self.alias,
            verifying_key: self.verifying_key,
            state: Finalized {
                instance_id: self.state.instance_id,
                ledgers: self.state.ledgers,
                activation_receipt: self.state.activation_receipt,
                finalization_receipt,
            },
        }
    }

    /// Returns a raw pointer to the `SigningKey` inside the `Box`.
    ///
    /// Intended only for testing that `ZeroizeOnDrop` works correctly.
    /// The pointer becomes dangling after `finalize()` drops the `Box`.
    #[cfg(test)]
    fn signing_key_ptr(&self) -> *const u8 {
        self.state.signing_key.as_ref() as *const SigningKey as *const u8
    }
}

impl Endorser<Finalized> {
    /// Returns the finalization receipt.
    pub fn finalization_receipt(&self) -> &Signature {
        &self.state.finalization_receipt
    }

    /// Returns the ledger state at finalization time.
    pub fn ledgers(&self) -> &Ledgers {
        &self.state.ledgers
    }

    /// Returns the activation receipt.
    pub fn activation_receipt(&self) -> &Signature {
        &self.state.activation_receipt
    }

    /// Returns the instance ID.
    pub fn instance_id(&self) -> &ConfigId {
        &self.state.instance_id
    }
}

impl<S> Endorser<S> {
    /// Returns the public (verifying) key of this endorser.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns the opaque endorser alias.
    pub fn alias(&self) -> u64 {
        self.alias
    }
}

impl Endorser<Uninitialized> {
    /// Returns a raw pointer to the `SigningKey` inside the `Box`.
    ///
    /// Intended only for testing that `ZeroizeOnDrop` works correctly
    /// and that the key pointer is stable across state transitions.
    #[cfg(test)]
    fn signing_key_ptr(&self) -> *const u8 {
        self.state.signing_key.as_ref() as *const SigningKey as *const u8
    }
}

/// Computes the endorser alias from a verifying key.
///
/// The alias is the first 8 bytes of SHA-256(SEC1 uncompressed verifying key),
/// interpreted as a big-endian u64.
// TODO: b/476380752 - Change to little-endian.
fn compute_alias(verifying_key: &VerifyingKey) -> u64 {
    use sha2::Digest;
    let vk_bytes = verifying_key.to_sec1_bytes();
    let hash = Sha256::digest(&vk_bytes);
    u64::from_be_bytes(
        hash[..8]
            .try_into()
            .expect("SHA-256 produces at least 8 bytes"),
    )
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error returned by [`Endorser::activate`] when activation fails.
///
/// Contains the unconsumed `Endorser<Uninitialized>` so the caller can
/// reclaim it (e.g. put it back in a collection) rather than losing it.
/// This follows the same pattern as `std::sync::mpsc::SendError<T>`.
pub enum ActivationError {
    /// The endorser's own verifying key is not in the cohort config.
    KeyNotInConfig { endorser: Endorser<Uninitialized> },
    /// The finalization receipts do not form a quorum (strict majority).
    /// Only returned when activating from a previous cohort.
    NoQuorum { endorser: Endorser<Uninitialized> },
}

impl ActivationError {
    /// Recovers the endorser which activation failed. Consumes the error.
    pub fn reclaim_endorser(self) -> Endorser<Uninitialized> {
        match self {
            Self::KeyNotInConfig { endorser } | Self::NoQuorum { endorser } => endorser,
        }
    }
}

impl core::fmt::Debug for ActivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyNotInConfig { endorser } => f
                .debug_struct("ActivationError::KeyNotInConfig")
                .field("alias", &endorser.alias())
                .finish(),
            Self::NoQuorum { endorser } => f
                .debug_struct("ActivationError::NoQuorum")
                .field("alias", &endorser.alias())
                .finish(),
        }
    }
}

impl core::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KeyNotInConfig { endorser } => write!(
                f,
                "endorser with alias {}'s verifying key is not in the cohort config",
                endorser.alias()
            ),
            Self::NoQuorum { endorser } => write!(
                f,
                "endorser with alias {}: finalization receipts do not form a quorum",
                endorser.alias()
            ),
        }
    }
}

/// Error returned when a ledger with the given ID is not found.
#[derive(Debug)]
pub struct LedgerNotFoundError {
    pub ledger_id: u32,
}

/// Error returned by [`Endorser::create_ledger`].
#[derive(Debug)]
pub enum CreateLedgerError {
    /// A ledger with the given ID already exists.
    AlreadyExists { ledger_id: u32 },
}

/// Error returned by [`Endorser::append_entry`].
#[derive(Debug)]
pub enum AppendEntryError {
    /// The specified ledger does not exist.
    LedgerNotFound(LedgerNotFoundError),
    /// The expected index does not match the next block index.
    WrongIndex { expected: u64, actual: u64 },
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_base::compute_config_id;
    use p256::ecdsa::signature::Verifier;
    use sha2::Digest;

    fn sorted_config(mut keys: std::vec::Vec<VerifyingKey>) -> CohortConfig {
        keys.sort_by(|a, b| a.to_sec1_bytes().as_ref().cmp(b.to_sec1_bytes().as_ref()));
        CohortConfig::try_from_keys(keys).unwrap()
    }

    /// Reads `len` bytes from `ptr` using volatile reads to avoid UB
    /// optimizations on potentially-freed memory.
    unsafe fn read_bytes_volatile(ptr: *const u8, len: usize) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; len];
        for i in 0..len {
            buf[i] = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        }
        buf
    }

    #[test]
    fn activate_fails_if_key_not_in_config() {
        let uninit_endorser = Endorser::new();
        let alias = uninit_endorser.alias();

        let other_key = *SigningKey::random(&mut rand_core::OsRng).verifying_key();
        let cohort_config = sorted_config(std::vec![other_key]);

        let err = match uninit_endorser.activate(cohort_config, None) {
            Err(e) => e,
            Ok(_) => {
                panic!("activate should fail if the endorser's key is not in the config")
            }
        };

        assert!(
            err.reclaim_endorser().alias() == alias,
            "the returned endorser should be the same one that was passed in"
        );
    }

    #[test]
    fn activate_preserves_keys_and_stores_cohort_config() {
        let uninit_endorser = Endorser::new();

        // Capture the signing key pointer and verifying key before activate.
        let signing_key_ptr_before = uninit_endorser.signing_key_ptr();
        let verifying_key_before = *uninit_endorser.verifying_key();

        let key_size = core::mem::size_of::<SigningKey>();
        let key_bytes_before = unsafe { read_bytes_volatile(signing_key_ptr_before, key_size) };

        // Create a cohort config with two keys (the endorser's own + another).
        let other_key = *SigningKey::random(&mut rand_core::OsRng).verifying_key();
        let cohort_config = sorted_config(std::vec![verifying_key_before, other_key]);

        let active_endorser = uninit_endorser.activate(cohort_config, None).unwrap();

        // The signing key should be at the same heap address (Box moved, not copied).
        assert_eq!(
            signing_key_ptr_before,
            active_endorser.signing_key_ptr(),
            "signing key must remain at the same heap address after activate"
        );

        // The signing key contents should not change.
        let key_bytes_after =
            unsafe { read_bytes_volatile(active_endorser.signing_key_ptr(), key_size) };
        assert_eq!(
            key_bytes_before, key_bytes_after,
            "signing key contents must not change after activate"
        );

        // The verifying key should be unchanged.
        assert_eq!(
            &verifying_key_before,
            active_endorser.verifying_key(),
            "verifying key must be preserved after activate"
        );

        // The cohort config should match what was passed in: it contains our key.
        assert!(
            active_endorser
                .cohort_config()
                .contains(&verifying_key_before),
            "cohort config must contain the endorser's own key"
        );
    }

    #[test]
    fn alias_matches_sha256_of_verifying_key() {
        let endorser = Endorser::new();
        let vk_bytes = endorser.verifying_key().to_sec1_bytes();

        // Manually compute the expected ID.
        let hash = Sha256::digest(&vk_bytes);
        let expected_id = u64::from_be_bytes(hash[..8].try_into().unwrap());

        assert_eq!(
            endorser.alias(),
            expected_id,
            "alias must equal the first 8 bytes of SHA-256(verifying key), big-endian"
        );
    }

    #[test]
    fn alias_is_nonzero_and_preserved_after_activate() {
        let endorser = Endorser::new();
        let id_before = endorser.alias();

        // An ID derived from a random key should be non-zero with overwhelming
        // probability (probability of zero: 2^{-64}).
        assert_ne!(id_before, 0, "alias should be non-zero");

        let own_key = *endorser.verifying_key();
        let active = endorser
            .activate(sorted_config(std::vec![own_key]), None)
            .unwrap();

        assert_eq!(
            id_before,
            active.alias(),
            "alias must be preserved after activate"
        );
    }

    #[test]
    fn different_endorsers_have_different_aliases() {
        let e1 = Endorser::new();
        let e2 = Endorser::new();

        // Two random keys should produce different IDs with overwhelming
        // probability (collision probability: 2^{-64}).
        assert_ne!(
            e1.alias(),
            e2.alias(),
            "two independently created endorsers should have different aliases"
        );
    }

    #[test]
    fn create_ledger_returns_valid_signature() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();

        let sig = active.create_ledger(42).unwrap();

        // Reconstruct the signed message and verify.
        let instance_id = compute_config_id([vk].iter());
        let message = receipts::build_create_ledger_message(&instance_id, 42);
        vk.verify(&message, &sig)
            .expect("create_ledger receipt must verify with the endorser's verifying key");
    }

    #[test]
    fn create_ledger_fails_for_duplicate_id() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();

        // Ledger 0 was created during activate.
        let err = active.create_ledger(0).unwrap_err();
        assert!(
            matches!(err, CreateLedgerError::AlreadyExists { ledger_id: 0 }),
            "error should be AlreadyExists with ledger_id 0, got: {err:?}"
        );

        // A new ledger should succeed, then fail on second attempt.
        active.create_ledger(1).unwrap();
        let err = active.create_ledger(1).unwrap_err();
        assert!(matches!(
            err,
            CreateLedgerError::AlreadyExists { ledger_id: 1 }
        ));
    }

    #[test]
    fn append_entry_returns_valid_signature() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();
        let ledger_id: u32 = 1;
        active.create_ledger(ledger_id).unwrap();

        let entry = [0xABu8; 32];
        let sig = active.append_entry(ledger_id, entry, 1).unwrap();

        // Compute expected new tail: SHA256(old_tail || old_entry).
        // After create_ledger, old_tail = [0;32], old_entry = [0;32].
        let expected_tail: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0u8; 32]); // old tail
            h.update([0u8; 32]); // old entry
            h.finalize().into()
        };

        let instance_id = compute_config_id([vk].iter());
        let message = receipts::build_append_entry_message(
            &instance_id,
            ledger_id,
            &entry,
            1,
            &expected_tail,
        );

        vk.verify(&message, &sig)
            .expect("append_entry receipt must verify");
    }

    #[test]
    fn append_entry_wrong_index_fails() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();
        active.create_ledger(1).unwrap();

        // First append should have expected_index = 1, pass 0 instead.
        let err = active.append_entry(1, [0xAAu8; 32], 0).unwrap_err();
        match err {
            AppendEntryError::WrongIndex { expected, actual } => {
                assert_eq!(expected, 0);
                assert_eq!(actual, 1);
            }
            _ => panic!("expected WrongIndex error"),
        }
    }

    #[test]
    fn append_entry_ledger_not_found_fails() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();

        let err = active.append_entry(99, [0xAAu8; 32], 1).unwrap_err();
        match err {
            AppendEntryError::LedgerNotFound(err) => {
                assert_eq!(err.ledger_id, 99);
            }
            _ => panic!("expected LedgerNotFound error"),
        }
    }

    #[test]
    fn append_entry_hash_chain_is_cumulative() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();
        active.create_ledger(1).unwrap();

        let entry_a = [0xAAu8; 32];
        let entry_b = [0xBBu8; 32];

        // Append entry A (index 1).
        active.append_entry(1, entry_a, 1).unwrap();

        // Append entry B (index 2) — the tail should chain from entry A.
        let sig = active.append_entry(1, entry_b, 2).unwrap();

        // Manually compute the expected tail after two appends.
        // After create:  tail_0 = [0;32], entry_0 = [0;32]
        // After append A: tail_1 = SHA256(tail_0 || entry_0), entry_1 = entry_a
        // After append B: tail_2 = SHA256(tail_1 || entry_1), entry_2 = entry_b
        let tail_1: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0u8; 32]);
            h.update([0u8; 32]);
            h.finalize().into()
        };
        let tail_2: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(tail_1);
            h.update(entry_a);
            h.finalize().into()
        };

        // Verify the second append's signature covers the chained tail.
        let instance_id = compute_config_id([vk].iter());
        let message = receipts::build_append_entry_message(&instance_id, 1, &entry_b, 2, &tail_2);

        vk.verify(&message, &sig)
            .expect("second append_entry receipt must verify with chained tail");
    }

    #[test]
    fn read_latest_on_empty_ledger_returns_valid_signature() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();
        let ledger_id: u32 = 1;
        active.create_ledger(ledger_id).unwrap();

        let nonce: u64 = 0x0102030405060708;
        let result = active.read_latest(ledger_id, nonce).unwrap();

        // After create_ledger, the initial state should be all zeros.
        assert_eq!(result.entry, [0u8; 32]);
        assert_eq!(result.index, 0);
        assert_eq!(result.hash_chain_tail, [0u8; 32]);
        assert_eq!(result.nonce, nonce);

        // Verify the signature.
        let instance_id = compute_config_id([vk].iter());
        let message = receipts::build_read_latest_message(
            &instance_id,
            ledger_id,
            &result.entry,
            result.index,
            &result.hash_chain_tail,
            nonce,
        );

        vk.verify(&message, &result.signature)
            .expect("read_latest signature must verify");
    }

    #[test]
    fn read_latest_after_append_returns_appended_entry() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let mut active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();
        let ledger_id: u32 = 1;
        active.create_ledger(ledger_id).unwrap();

        let entry = [0xABu8; 32];
        active.append_entry(ledger_id, entry, 1).unwrap();

        let nonce: u64 = 42;
        let result = active.read_latest(ledger_id, nonce).unwrap();

        assert_eq!(result.entry, entry);
        assert_eq!(result.index, 1);
        assert_eq!(result.nonce, nonce);

        // Verify the signature covers the latest state.
        let expected_tail: [u8; 32] = {
            let mut h = Sha256::new();
            h.update([0u8; 32]); // old tail
            h.update([0u8; 32]); // old entry
            h.finalize().into()
        };
        assert_eq!(result.hash_chain_tail, expected_tail);

        let instance_id = compute_config_id([vk].iter());
        let message = receipts::build_read_latest_message(
            &instance_id,
            ledger_id,
            &entry,
            1,
            &expected_tail,
            nonce,
        );

        vk.verify(&message, &result.signature)
            .expect("read_latest signature must verify after append");
    }

    #[test]
    fn read_latest_ledger_not_found() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();

        let err = active.read_latest(99, 0).unwrap_err();
        assert_eq!(err.ledger_id, 99);
    }

    /// Verifies that the signing key's secret scalar is overwritten after
    /// calling `finalize()`.
    ///
    /// `SigningKey` implements `ZeroizeOnDrop` which zeroes the secret scalar
    /// when the key is dropped. After zeroing, the allocator may write
    /// free-list metadata into the freed region, so we verify that the
    /// original key bytes are **no longer present** rather than asserting
    /// all zeros.
    #[test]
    fn finalize_erases_signing_key() {
        let endorser = Endorser::new();

        // Get a raw pointer to the SigningKey inside the Box.
        let key_ptr = endorser.signing_key_ptr();
        let key_size = core::mem::size_of::<SigningKey>();

        // Snapshot all key bytes before finalize using volatile reads.
        let pre_bytes = unsafe { read_bytes_volatile(key_ptr, key_size) };

        // Sanity: key should contain non-zero data.
        assert!(
            pre_bytes.iter().any(|&b| b != 0),
            "signing key should not be all zeros before finalize"
        );

        // Transition to Active. The Box pointer is moved, not the key material.
        let own_key = *endorser.verifying_key();
        let active = endorser
            .activate(sorted_config(std::vec![own_key]), None)
            .unwrap();

        // Checkpoint: key material should be unchanged after activate().
        let mid_bytes = unsafe { read_bytes_volatile(key_ptr, key_size) };
        assert_eq!(
            pre_bytes, mid_bytes,
            "signing key must be unchanged after activate (Box pointer move only)"
        );

        // Finalize: the endorser is consumed and the Box<SigningKey> is
        // dropped, triggering ZeroizeOnDrop.
        active.finalize(&sorted_config(std::vec![own_key]));

        // Read the memory after finalize using volatile reads.
        let post_bytes = unsafe { read_bytes_volatile(key_ptr, key_size) };

        // The original key material should no longer be present.
        assert_ne!(
            pre_bytes, post_bytes,
            "signing key memory must be modified after finalize (ZeroizeOnDrop)"
        );

        // Specifically verify the first 32 bytes (the secret scalar).
        assert_ne!(
            &pre_bytes[..32],
            &post_bytes[..32],
            "the secret scalar (first 32 bytes) must be erased after finalize"
        );
    }

    /// Builds sorted `EndorserFinalization` entries from
    /// `(VerifyingKey, Option<Signature>)` pairs.
    fn sorted_finalizations(
        mut entries: std::vec::Vec<(VerifyingKey, Option<Signature>)>,
    ) -> std::vec::Vec<EndorserFinalization> {
        entries.sort_by(|a, b| {
            a.0.to_sec1_bytes()
                .as_ref()
                .cmp(b.0.to_sec1_bytes().as_ref())
        });
        entries
            .into_iter()
            .map(|(k, r)| EndorserData {
                endorser_key: k,
                maybe_receipt: r,
            })
            .collect()
    }

    /// Signs a finalization receipt for a given endorser, matching the format
    /// expected by `CohortTakeOver::verify`.
    fn sign_finalization_receipt(
        signing_key: &SigningKey,
        instance_id: &[u8; 32],
        prev_config: &CohortConfig,
        new_config: &CohortConfig,
        ledgers: &Ledgers,
    ) -> Signature {
        use p256::ecdsa::signature::Signer as _;
        let message = receipts::build_finalize_message(
            instance_id,
            &prev_config.config_id(),
            &new_config.config_id(),
            &ledgers.hash(),
        );
        signing_key.sign(&message)
    }

    /// Common setup for finalization-based activation tests: a previous cohort
    /// of 3 endorsers, a single-endorser new cohort, a fixed instance ID, and
    /// empty ledgers.
    struct FinalizationTestSetup {
        prev_signing_keys: std::vec::Vec<SigningKey>,
        prev_vks: std::vec::Vec<VerifyingKey>,
        prev_config: CohortConfig,
        new_endorser: Endorser<Uninitialized>,
        new_config: CohortConfig,
        instance_id: [u8; 32],
        ledgers: Ledgers,
    }

    fn finalization_test_setup() -> FinalizationTestSetup {
        let prev_signing_keys: std::vec::Vec<_> = (0..3)
            .map(|_| SigningKey::random(&mut rand_core::OsRng))
            .collect();
        let prev_vks: std::vec::Vec<_> = prev_signing_keys
            .iter()
            .map(|sk| *sk.verifying_key())
            .collect();
        let prev_config = sorted_config(prev_vks.clone());

        let new_endorser = Endorser::new();
        let new_vk = *new_endorser.verifying_key();
        let new_config = sorted_config(std::vec![new_vk]);

        FinalizationTestSetup {
            prev_signing_keys,
            prev_vks,
            prev_config,
            new_endorser,
            new_config,
            instance_id: [42u8; 32],
            ledgers: Ledgers::new(),
        }
    }

    #[test]
    fn activation_fails_without_finalization_quorum() {
        let setup = finalization_test_setup();

        // Only the first endorser produces a valid receipt (1 out of 3).
        let receipt_0 = sign_finalization_receipt(
            &setup.prev_signing_keys[0],
            &setup.instance_id,
            &setup.prev_config,
            &setup.new_config,
            &setup.ledgers,
        );
        let finalizations = sorted_finalizations(std::vec![
            (setup.prev_vks[0], Some(receipt_0)),
            (setup.prev_vks[1], None),
            (setup.prev_vks[2], None),
        ]);

        let result = setup.new_endorser.activate(
            setup.new_config,
            Some(CohortTakeOver::new(
                setup.instance_id,
                CohortFinalization::try_new(finalizations).unwrap(),
                setup.ledgers,
            )),
        );
        assert!(
            matches!(result, Err(ActivationError::NoQuorum { .. })),
            "expected NoQuorum"
        );
    }

    #[test]
    fn activation_fails_with_wrong_next_config() {
        // All 3 endorsers sign receipts, but for a different next config
        // than the one passed to activate.
        let setup = finalization_test_setup();

        let wrong_next_config =
            sorted_config(std::vec![
                *SigningKey::random(&mut rand_core::OsRng).verifying_key(),
            ]);
        let receipts: std::vec::Vec<_> = setup
            .prev_signing_keys
            .iter()
            .map(|sk| {
                sign_finalization_receipt(
                    sk,
                    &setup.instance_id,
                    &setup.prev_config,
                    &wrong_next_config,
                    &setup.ledgers,
                )
            })
            .collect();
        let finalizations = sorted_finalizations(
            setup
                .prev_vks
                .iter()
                .zip(receipts)
                .map(|(vk, r)| (*vk, Some(r)))
                .collect(),
        );

        let result = setup.new_endorser.activate(
            setup.new_config,
            Some(CohortTakeOver::new(
                setup.instance_id,
                CohortFinalization::try_new(finalizations).unwrap(),
                setup.ledgers,
            )),
        );
        assert!(
            matches!(result, Err(ActivationError::NoQuorum { .. })),
            "expected NoQuorum: receipts were signed for a different next config"
        );
    }

    #[test]
    fn activation_fails_with_wrong_ledgers() {
        // All 3 endorsers sign receipts, but over different ledger state
        // than what is passed to activate.
        let setup = finalization_test_setup();

        let mut wrong_ledgers = Ledgers::new();
        wrong_ledgers.insert(
            0,
            LedgerBlock {
                entry: [0xFFu8; 32],
                index: 7,
                hash_chain_tail: [0xAAu8; 32],
            },
        );
        let receipts: std::vec::Vec<_> = setup
            .prev_signing_keys
            .iter()
            .map(|sk| {
                sign_finalization_receipt(
                    sk,
                    &setup.instance_id,
                    &setup.prev_config,
                    &setup.new_config,
                    &wrong_ledgers,
                )
            })
            .collect();
        let finalizations = sorted_finalizations(
            setup
                .prev_vks
                .iter()
                .zip(receipts)
                .map(|(vk, r)| (*vk, Some(r)))
                .collect(),
        );

        let result = setup.new_endorser.activate(
            setup.new_config,
            Some(CohortTakeOver::new(
                setup.instance_id,
                CohortFinalization::try_new(finalizations).unwrap(),
                setup.ledgers,
            )),
        );
        assert!(
            matches!(result, Err(ActivationError::NoQuorum { .. })),
            "expected NoQuorum: receipts were signed over different ledger state"
        );
    }

    #[test]
    fn activation_succeeds_with_finalization_quorum() {
        let setup = finalization_test_setup();

        // 2 out of 3 endorsers produce valid receipts → quorum (2 > 1.5).
        let receipt_0 = sign_finalization_receipt(
            &setup.prev_signing_keys[0],
            &setup.instance_id,
            &setup.prev_config,
            &setup.new_config,
            &setup.ledgers,
        );
        let receipt_1 = sign_finalization_receipt(
            &setup.prev_signing_keys[1],
            &setup.instance_id,
            &setup.prev_config,
            &setup.new_config,
            &setup.ledgers,
        );
        let finalizations = sorted_finalizations(std::vec![
            (setup.prev_vks[0], Some(receipt_0)),
            (setup.prev_vks[1], Some(receipt_1)),
            (setup.prev_vks[2], None),
        ]);

        let new_vk = *setup.new_endorser.verifying_key();
        let active = setup
            .new_endorser
            .activate(
                setup.new_config,
                Some(CohortTakeOver::new(
                    setup.instance_id,
                    CohortFinalization::try_new(finalizations).unwrap(),
                    setup.ledgers,
                )),
            )
            .expect("should succeed with quorum");
        assert_eq!(active.verifying_key(), &new_vk);
    }

    #[test]
    fn new_instance_activation_receipt_verifies() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();

        let instance_id = compute_config_id([vk].iter());
        let message = receipts::build_activate_new_instance_message(&instance_id);

        vk.verify(&message, active.activation_receipt())
            .expect("new-instance activation receipt must verify");
    }

    #[test]
    fn new_instance_creates_default_ledger() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let active = endorser
            .activate(sorted_config(std::vec![vk]), None)
            .unwrap();

        // Ledger 0 should exist with zero-state.
        let result = active.read_latest(0, 0).unwrap();
        assert_eq!(result.entry, [0u8; 32], "default ledger entry must be zero");
        assert_eq!(result.index, 0, "default ledger index must be 0");
        assert_eq!(
            result.hash_chain_tail, [0u8; 32],
            "default ledger hash chain tail must be zero"
        );

        // Only ledger 0 should exist.
        assert_eq!(active.ledger_count(), 1, "should have exactly 1 ledger");
    }

    #[test]
    fn finalization_activation_receipt_verifies() {
        let setup = finalization_test_setup();

        // All 3 endorsers produce valid receipts.
        let receipts: std::vec::Vec<_> = setup
            .prev_signing_keys
            .iter()
            .map(|sk| {
                sign_finalization_receipt(
                    sk,
                    &setup.instance_id,
                    &setup.prev_config,
                    &setup.new_config,
                    &setup.ledgers,
                )
            })
            .collect();
        let finalizations = sorted_finalizations(
            setup
                .prev_vks
                .iter()
                .zip(receipts)
                .map(|(vk, r)| (*vk, Some(r)))
                .collect(),
        );

        // Compute expected message before activate consumes the configs.
        let expected_message = receipts::build_activate_from_prev_message(
            &setup.instance_id,
            &setup.prev_config.config_id(),
            &setup.new_config.config_id(),
            &setup.ledgers.hash(),
        );

        let new_vk = *setup.new_endorser.verifying_key();
        let active = setup
            .new_endorser
            .activate(
                setup.new_config,
                Some(CohortTakeOver::new(
                    setup.instance_id,
                    CohortFinalization::try_new(finalizations).unwrap(),
                    setup.ledgers,
                )),
            )
            .expect("should succeed with full quorum");

        new_vk
            .verify(&expected_message, active.activation_receipt())
            .expect("finalization activation receipt must verify");
    }

    #[test]
    fn finalization_adopts_ledger_state() {
        let setup = finalization_test_setup();

        // Build non-trivial ledger state to hand over.
        let mut ledgers = Ledgers::new();
        ledgers.insert(
            0,
            LedgerBlock {
                entry: [0xAAu8; 32],
                index: 5,
                hash_chain_tail: [0xBBu8; 32],
            },
        );
        ledgers.insert(
            42,
            LedgerBlock {
                entry: [0xCCu8; 32],
                index: 10,
                hash_chain_tail: [0xDDu8; 32],
            },
        );

        // Sign finalization receipts over the non-trivial ledger state.
        let receipts: std::vec::Vec<_> = setup
            .prev_signing_keys
            .iter()
            .map(|sk| {
                sign_finalization_receipt(
                    sk,
                    &setup.instance_id,
                    &setup.prev_config,
                    &setup.new_config,
                    &ledgers,
                )
            })
            .collect();
        let finalizations = sorted_finalizations(
            setup
                .prev_vks
                .iter()
                .zip(receipts)
                .map(|(vk, r)| (*vk, Some(r)))
                .collect(),
        );

        let active = setup
            .new_endorser
            .activate(
                setup.new_config,
                Some(CohortTakeOver::new(
                    setup.instance_id,
                    CohortFinalization::try_new(finalizations).unwrap(),
                    ledgers,
                )),
            )
            .expect("should succeed");

        // Verify adopted ledger state via read_latest.
        let block_0 = active.read_latest(0, 0).unwrap();
        assert_eq!(block_0.entry, [0xAAu8; 32]);
        assert_eq!(block_0.index, 5);
        assert_eq!(block_0.hash_chain_tail, [0xBBu8; 32]);

        let block_42 = active.read_latest(42, 0).unwrap();
        assert_eq!(block_42.entry, [0xCCu8; 32]);
        assert_eq!(block_42.index, 10);
        assert_eq!(block_42.hash_chain_tail, [0xDDu8; 32]);

        assert_eq!(active.ledger_count(), 2);

        // Non-existent ledger should still fail.
        assert!(active.read_latest(99, 0).is_err());
    }

    #[test]
    fn finalization_preserves_instance_id() {
        let setup = finalization_test_setup();

        let receipts: std::vec::Vec<_> = setup
            .prev_signing_keys
            .iter()
            .map(|sk| {
                sign_finalization_receipt(
                    sk,
                    &setup.instance_id,
                    &setup.prev_config,
                    &setup.new_config,
                    &setup.ledgers,
                )
            })
            .collect();
        let finalizations = sorted_finalizations(
            setup
                .prev_vks
                .iter()
                .zip(receipts)
                .map(|(vk, r)| (*vk, Some(r)))
                .collect(),
        );

        let active = setup
            .new_endorser
            .activate(
                setup.new_config,
                Some(CohortTakeOver::new(
                    setup.instance_id,
                    CohortFinalization::try_new(finalizations).unwrap(),
                    setup.ledgers,
                )),
            )
            .expect("should succeed");

        assert_eq!(
            active.instance_id(),
            &setup.instance_id,
            "instance_id must be preserved from the cohort finalization"
        );
    }

    #[test]
    fn finalization_quorum_boundary() {
        // With an even number of endorsers, exactly N/2 receipts must NOT
        // constitute a quorum (strict majority requires > N/2).
        let prev_signing_keys: std::vec::Vec<_> = (0..4)
            .map(|_| SigningKey::random(&mut rand_core::OsRng))
            .collect();
        let prev_vks: std::vec::Vec<_> = prev_signing_keys
            .iter()
            .map(|sk| *sk.verifying_key())
            .collect();
        let prev_config = sorted_config(prev_vks.clone());

        let new_endorser = Endorser::new();
        let new_vk = *new_endorser.verifying_key();
        let instance_id = [42u8; 32];

        // Sign exactly 2 out of 4 receipts (= N/2, not > N/2).
        let new_config = sorted_config(std::vec![new_vk]);
        let ledgers = Ledgers::new();
        let receipt_0 = sign_finalization_receipt(
            &prev_signing_keys[0],
            &instance_id,
            &prev_config,
            &new_config,
            &ledgers,
        );
        let receipt_1 = sign_finalization_receipt(
            &prev_signing_keys[1],
            &instance_id,
            &prev_config,
            &new_config,
            &ledgers,
        );
        let finalizations = sorted_finalizations(std::vec![
            (prev_vks[0], Some(receipt_0)),
            (prev_vks[1], Some(receipt_1)),
            (prev_vks[2], None),
            (prev_vks[3], None),
        ]);

        let result = new_endorser.activate(
            new_config,
            Some(CohortTakeOver::new(
                instance_id,
                CohortFinalization::try_new(finalizations).unwrap(),
                ledgers,
            )),
        );
        assert!(
            matches!(result, Err(ActivationError::NoQuorum { .. })),
            "exactly N/2 receipts must not form a quorum"
        );

        // Now verify that N/2 + 1 = 3 out of 4 does succeed.
        let new_endorser = match result {
            Err(e) => e.reclaim_endorser(),
            Ok(_) => panic!("expected NoQuorum error"),
        };
        let new_config = sorted_config(std::vec![new_vk]);
        let ledgers = Ledgers::new();
        let receipt_0 = sign_finalization_receipt(
            &prev_signing_keys[0],
            &instance_id,
            &prev_config,
            &new_config,
            &ledgers,
        );
        let receipt_1 = sign_finalization_receipt(
            &prev_signing_keys[1],
            &instance_id,
            &prev_config,
            &new_config,
            &ledgers,
        );
        let receipt_2 = sign_finalization_receipt(
            &prev_signing_keys[2],
            &instance_id,
            &prev_config,
            &new_config,
            &ledgers,
        );
        let finalizations = sorted_finalizations(std::vec![
            (prev_vks[0], Some(receipt_0)),
            (prev_vks[1], Some(receipt_1)),
            (prev_vks[2], Some(receipt_2)),
            (prev_vks[3], None),
        ]);

        new_endorser
            .activate(
                new_config,
                Some(CohortTakeOver::new(
                    instance_id,
                    CohortFinalization::try_new(finalizations).unwrap(),
                    ledgers,
                )),
            )
            .expect("N/2 + 1 receipts must form a quorum");
    }

    #[test]
    fn finalize_receipt_verifies() {
        let endorser = Endorser::new();
        let vk = *endorser.verifying_key();
        let cohort_config = sorted_config(std::vec![vk]);
        let cohort_config_id = cohort_config.config_id();
        let mut active = endorser.activate(cohort_config, None).unwrap();

        // Create a ledger and append an entry so finalization covers
        // non-trivial state.
        active.create_ledger(1).unwrap();
        active.append_entry(1, [0xABu8; 32], 1).unwrap();

        let next_config = sorted_config(std::vec![
            *SigningKey::random(&mut rand_core::OsRng).verifying_key(),
        ]);

        let finalized = active.finalize(&next_config);

        // Reconstruct the expected finalize message and verify.
        let message = receipts::build_finalize_message(
            &cohort_config_id,
            &cohort_config_id,
            &next_config.config_id(),
            &finalized.ledgers().hash(),
        );

        vk.verify(&message, finalized.finalization_receipt())
            .expect("finalization receipt must verify");

        // Verify the returned ledgers contain the expected state.
        assert_eq!(
            finalized.ledgers().len(),
            2,
            "should have 2 ledgers (0 and 1)"
        );
        assert!(finalized.ledgers().contains_key(&0));
        assert!(finalized.ledgers().contains_key(&1));
        let ledger_1 = finalized.ledgers().get(&1).unwrap();
        assert_eq!(ledger_1.entry, [0xABu8; 32]);
        assert_eq!(ledger_1.index, 1);
    }
}
