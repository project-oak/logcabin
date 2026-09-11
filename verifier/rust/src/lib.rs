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

//! LogCabin receipt verifier library.
//!
//! Allows verifying that a given ledger entry has been committed to a
//! LogCabin cohort. Two types of verification are supported:
//!
//! - **Read verification**: confirms that a `read_latest` response is backed
//!   by a quorum of endorser signatures.
//! - **Append verification**: confirms that an `append_entry` operation was
//!   accepted and committed by a quorum of endorsers.
//!
//! The [`Verifier`] tracks a trusted cohort configuration
//! and can evolve its trust through cohort handovers.
//!
//! # Usage
//!
//! ```ignore
//! let verifier = Verifier::new(initial_config);
//! verifier.apply_handover(&finalization, activation)?;
//! let block = verifier.verify_read_latest(&responses, nonce, ledger_id)?;
//! ```

#![no_std]

extern crate alloc;

use logcabin_base::{receipts, CohortConfig, ConfigId, LedgerBlock, Sha256Digest};
use p256::ecdsa::signature::Verifier as _;

mod handover;
mod ledger_receipts;

pub use handover::{
    CohortActivation, CohortHandover, EndorserActivation, HandoverError, QuorumError,
};
pub use ledger_receipts::{LedgerReceipt, LedgerReceipts};
pub use logcabin_base::{CohortFinalization, EndorserData, EndorserFinalization};

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Stateful verifier for LogCabin endorser receipts.
///
/// Tracks a trusted [`CohortConfig`] and instance ID. Trust can be evolved
/// through cohort handovers via [`apply_handover`](Verifier::apply_handover),
/// and receipts can be verified against the current trusted config via
/// [`verify_read_latest`](Verifier::verify_read_latest).
pub struct Verifier {
    /// The currently trusted cohort configuration.
    trusted_config: CohortConfig,
    /// The instance ID of the LogCabin service.
    instance_id: ConfigId,
}

impl Verifier {
    /// Creates a new verifier trusting the given initial cohort.
    ///
    /// This is used for the case where the given config is the initial config
    /// for the cohort. The instance ID is derived from it: SHA-256 of the
    /// concatenated SEC1 verifying keys.
    pub fn new(trusted_config: CohortConfig) -> Self {
        // TODO: b/476380752 - Analyze if we must verify activation receipts at
        // this point. That would assure the verifier that all endorsers in the
        // config have adopted the config. However, that is also checked when
        // verifying ledger receipts.
        Self {
            instance_id: trusted_config.config_id(),
            trusted_config,
        }
    }

    /// Creates a new verifier trusting the given cohort and instance ID.
    ///
    /// Use this when the trusted config is *not* the first cohort of the
    /// instance - the instance started with a different cohort and
    /// has since evolved, but the verifier trusts that this instance_id
    /// belongs to this cohort.
    pub fn new_with_instance_id(trusted_config: CohortConfig, instance_id: ConfigId) -> Self {
        // TODO: b/476380752 - Analyze if we must verify activation here.
        Self {
            trusted_config,
            instance_id,
        }
    }

    /// Returns the currently trusted cohort configuration.
    pub fn trusted_config(&self) -> &CohortConfig {
        &self.trusted_config
    }

    /// Returns the instance ID.
    pub fn instance_id(&self) -> &ConfigId {
        &self.instance_id
    }

    /// Processes a cohort handover: checks that the finalization matches the
    /// current trusted config, then delegates internal handover verification
    /// to [`CohortHandover::verify`] and evolves the trusted config.
    pub fn apply_handover(&mut self, handover: CohortHandover) -> Result<(), HandoverError> {
        // Handover must be from our currently trusted cohort.
        if handover.finalization.config_id() != self.trusted_config.config_id() {
            return Err(HandoverError::FinalizationConfigMismatch);
        }

        // Internal cryptographic verification of handover including both quorums.
        let new_config = handover.verify(&self.instance_id)?;

        // Evolve trust. Instance ID does not change.
        self.trusted_config = new_config;
        Ok(())
    }

    /// Verifies a set of ReadLatest receipts against the current trusted
    /// cohort configuration.
    ///
    /// Verification checks that a strict majority (quorum) of endorsers in
    /// the currently trusted config have signed a ledger block agreeing on
    /// the same entry, entry index, and hash chain tail values, as well as
    /// the client-supplied `nonce`. The caller should pass the same nonce
    /// it originally sent to the service.
    ///
    /// This includes checking that ledger receipts are signed by unique keys,
    /// i.e., each endorser key is used at most once. Instead of providing
    /// the actual keys, key indices to the trusted_config are provided, which
    /// guarantees only trusted keys are used.
    ///
    /// Returns the verified ledger block if quorum is met.
    pub fn verify_read_latest(
        &self,
        ledger_receipts: &LedgerReceipts,
        nonce: u64,
        ledger_id: u32,
    ) -> Result<LedgerBlock, VerifyError> {
        // Use the first receipt as reference to compare against.
        // TODO: b/476380752 - Currently takes the first receipt as reference
        // but it could be part of a minority of endorsers disagreeing. The
        // majority could still agree. Look for that majority.
        let reference = ledger_receipts.first().ok_or(VerifyError::NoReceipts)?;
        let expected_message = receipts::build_tip_receipt_message(
            &self.instance_id,
            ledger_id,
            &reference.entry,
            reference.index,
            &reference.hash_chain_tail,
            nonce,
        );

        self.verify_ledger_receipts(ledger_receipts, &expected_message)
    }

    /// Verifies a set of AppendEntry receipts against the current trusted
    /// cohort configuration.
    ///
    /// In addition to checking quorum (same as `verify_read_latest`), this
    /// verifies that the appended entry has the caller-supplied
    /// `expected_index`. This check is critical: expected_index acts as a
    /// nonce (in addition to ensuring consistent ordering). Without this, an
    /// attacker could return the receipt for an earlier equal payload append.
    ///
    /// Returns the verified ledger block if quorum is met and the index
    /// matches.
    // TODO: b/476380752 - Assess if the protocol can accept a nonce for append
    // calls and merge the 2 verification methods. In practice, there will be 3
    // sources of receipts to be verified: from `append`, from `read_latest`,
    // and from a `get_by_index` call which is entirely handled by the
    // coordinator, retrieving receipts from storage.
    pub fn verify_append(
        &self,
        ledger_receipts: &LedgerReceipts,
        expected_index: u64,
        ledger_id: u32,
    ) -> Result<LedgerBlock, VerifyError> {
        // Use the first receipt as reference to compare against.
        let reference = ledger_receipts.first().ok_or(VerifyError::NoReceipts)?;
        let expected_message = receipts::build_entry_receipt_message(
            &self.instance_id,
            ledger_id,
            &reference.entry,
            reference.index,
            &reference.hash_chain_tail,
        );

        let block = self.verify_ledger_receipts(ledger_receipts, &expected_message)?;

        // Important check: expected_index acts as a nonce.
        if block.index != expected_index {
            return Err(VerifyError::UnexpectedIndex {
                expected: expected_index,
                actual: block.index,
            });
        }

        Ok(block)
    }

    /// Common verification logic for ledger receipts.
    ///
    /// Checks key index bounds and uniqueness via a bitmap, verifies that
    /// a quorum of endorsers signed the same block with the given
    /// `expected_message`, and returns the agreed-upon [`LedgerBlock`].
    fn verify_ledger_receipts(
        &self,
        ledger_receipts: &LedgerReceipts,
        expected_message: &[u8],
    ) -> Result<LedgerBlock, VerifyError> {
        let reference = &ledger_receipts[0];

        let cohort_size = self.trusted_config.len();
        let mut seen_keys = alloc::vec![false; cohort_size];
        let mut valid_count = 0;

        for r in ledger_receipts.iter() {
            // Bounds check.
            if r.key_index >= cohort_size {
                return Err(VerifyError::KeyIndexOutOfBounds);
            }

            // Uniqueness check via bitmap.
            if seen_keys[r.key_index] {
                return Err(VerifyError::DuplicateKeyIndex);
            }
            seen_keys[r.key_index] = true;

            // Check block agreement and signature in one pass.
            if r.block == reference.block
                && self.trusted_config.endorsers()[r.key_index]
                    .endorser_key
                    .verify(expected_message, &r.signature)
                    .is_ok()
            {
                valid_count += 1;
            }
        }

        if valid_count * 2 > cohort_size {
            Ok(reference.block.clone())
        } else {
            Err(VerifyError::QuorumNotMet(QuorumError {
                valid: valid_count,
                required: cohort_size / 2 + 1,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error returned by [`Verifier::verify_read_latest`] and
/// [`Verifier::verify_append`].
#[derive(Debug)]
pub enum VerifyError {
    /// No receipts were provided.
    NoReceipts,
    /// A `key_index` in the receipts exceeds the trusted config size.
    KeyIndexOutOfBounds,
    /// Two receipts have the same `key_index`.
    DuplicateKeyIndex,
    /// Not enough valid signatures to meet the quorum threshold.
    QuorumNotMet(QuorumError),
    /// The verified block index does not match the expected index
    /// (returned by [`Verifier::verify_append`]).
    UnexpectedIndex {
        /// The index the caller expected.
        expected: u64,
        /// The index in the verified block.
        actual: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{SigningKey, VerifyingKey};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Generates `n` signing keys with their verifying keys sorted in
    /// SEC1-lexicographic order. Returns `(signing_keys, verifying_keys)`.
    fn sorted_key_pairs(n: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
        let mut pairs: Vec<(SigningKey, VerifyingKey)> = (0..n)
            .map(|_| {
                let sk = SigningKey::random(&mut rand_core::OsRng);
                let vk = *sk.verifying_key();
                (sk, vk)
            })
            .collect();
        pairs.sort_by(|a, b| {
            a.1.to_sec1_bytes()
                .as_ref()
                .cmp(b.1.to_sec1_bytes().as_ref())
        });
        pairs.into_iter().unzip()
    }

    /// Computes the ledgers hash that the endorser would produce for a set of
    /// ledger blocks. Here we use a single-ledger hash for simplicity.
    fn compute_ledgers_hash(blocks: &[(u32, &LedgerBlock)]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        // Must match endorser's Ledgers::hash() format.
        hasher.update(&(blocks.len() as u32).to_be_bytes());
        for (id, block) in blocks {
            hasher.update(&id.to_be_bytes());
            hasher.update(&block.entry);
            hasher.update(&block.index.to_be_bytes());
            hasher.update(&block.hash_chain_tail);
        }
        hasher.finalize().into()
    }

    /// A test setup for handover scenarios.
    struct HandoverSetup {
        verifier: Verifier,
        old_sks: Vec<SigningKey>,
        old_vks: Vec<VerifyingKey>,
        new_sks: Vec<SigningKey>,
        new_vks: Vec<VerifyingKey>,
        instance_id: [u8; 32],
        ledgers_hash: [u8; 32],
    }

    impl HandoverSetup {
        /// Creates a 3-endorser old cohort and 3-endorser new cohort.
        fn new() -> Self {
            let (old_sks, old_vks) = sorted_key_pairs(3);
            let (new_sks, new_vks) = sorted_key_pairs(3);
            let old_config = CohortConfig::try_from_keys(old_vks.clone()).unwrap();
            let instance_id = old_config.config_id();
            let ledgers_hash = compute_ledgers_hash(&[(
                0,
                &LedgerBlock {
                    entry: [0xAA; 32],
                    index: 42,
                    hash_chain_tail: [0xBB; 32],
                },
            )]);
            let verifier = Verifier::new(old_config);
            Self {
                verifier,
                old_sks,
                old_vks,
                new_sks,
                new_vks,
                instance_id,
                ledgers_hash,
            }
        }

        fn old_config_id(&self) -> [u8; 32] {
            self.verifier.trusted_config().config_id()
        }

        fn new_config_id(&self) -> [u8; 32] {
            let cfg = CohortConfig::try_from_keys(self.new_vks.clone()).unwrap();
            cfg.config_id()
        }

        /// Signs finalization receipts for the given endorsers (by index).
        /// Uses the setup's own instance_id and ledgers_hash.
        fn sign_finalization_receipts(&self, signers: &[usize]) -> Vec<EndorserFinalization> {
            let message = receipts::build_finalize_message(
                &self.instance_id,
                &self.old_config_id(),
                &self.new_config_id(),
                &self.ledgers_hash,
            );
            self.sign_finalization_receipts_with_message(signers, &message)
        }

        /// Signs finalization receipts with a custom message (for mismatch tests).
        fn sign_finalization_receipts_with_message(
            &self,
            signers: &[usize],
            message: &[u8],
        ) -> Vec<EndorserFinalization> {
            self.old_vks
                .iter()
                .enumerate()
                .map(|(i, vk)| EndorserData {
                    endorser_key: *vk,
                    maybe_receipt: if signers.contains(&i) {
                        Some(self.old_sks[i].sign(message))
                    } else {
                        None
                    },
                })
                .collect()
        }

        /// Signs activation receipts for the given endorsers (by index).
        fn sign_activation_receipts(&self, signers: &[usize]) -> Vec<EndorserActivation> {
            let message = receipts::build_activate_from_prev_message(
                &self.instance_id,
                &self.old_config_id(),
                &self.new_config_id(),
                &self.ledgers_hash,
            );
            self.sign_activation_receipts_with_message(signers, &message)
        }

        /// Signs activation receipts with a custom message.
        fn sign_activation_receipts_with_message(
            &self,
            signers: &[usize],
            message: &[u8],
        ) -> Vec<EndorserActivation> {
            self.new_vks
                .iter()
                .enumerate()
                .map(|(i, vk)| EndorserData {
                    endorser_key: *vk,
                    maybe_receipt: if signers.contains(&i) {
                        Some(self.new_sks[i].sign(message))
                    } else {
                        None
                    },
                })
                .collect()
        }

        /// Constructs a valid CohortHandover with
        /// the given signer indices having just-quorum (2 of 3).
        fn valid_handover(&self) -> CohortHandover {
            let fin_entries = self.sign_finalization_receipts(&[0, 1]);
            let act_entries = self.sign_activation_receipts(&[0, 1]);
            CohortHandover::try_new(fin_entries, act_entries, self.ledgers_hash).unwrap()
        }
    }

    // -----------------------------------------------------------------------
    // Handover tests
    // -----------------------------------------------------------------------

    #[test]
    fn handover_happy_path_minimum_quorum() {
        let mut setup = HandoverSetup::new();
        let handover = setup.valid_handover();

        let result = setup.verifier.apply_handover(handover);
        assert!(result.is_ok());

        // After handover, trusted config should be the new cohort.
        assert!(setup
            .verifier
            .trusted_config()
            .keys()
            .eq(setup.new_vks.iter()));
        // Instance ID should be preserved.
        assert_eq!(setup.verifier.instance_id(), &setup.instance_id);
    }

    #[test]
    fn handover_fails_finalization_extra_endorser() {
        let mut setup = HandoverSetup::new();
        // Create a finalization with 4 endorsers (1 extra) — all the old
        // keys plus one more. The config IDs won't match the trusted config.
        let extra_sk = SigningKey::random(&mut rand_core::OsRng);
        let extra_vk = *extra_sk.verifying_key();
        let mut extended_sks = setup.old_sks.clone();
        let mut extended_vks = setup.old_vks.clone();
        extended_sks.push(extra_sk);
        extended_vks.push(extra_vk);
        // Sort both in lockstep by verifying key SEC1 bytes.
        let mut pairs: Vec<_> = extended_sks
            .into_iter()
            .zip(extended_vks.into_iter())
            .collect();
        pairs.sort_by(|a, b| {
            a.1.to_sec1_bytes()
                .as_ref()
                .cmp(b.1.to_sec1_bytes().as_ref())
        });

        // Build a finalization message using the extended config's ID.
        let extended_config = CohortConfig::try_from_keys(pairs.iter().map(|(_, vk)| *vk)).unwrap();
        let message = receipts::build_finalize_message(
            &setup.instance_id,
            &extended_config.config_id(),
            &setup.new_config_id(),
            &setup.ledgers_hash,
        );

        // All 4 endorsers sign valid receipts.
        let fin_entries: Vec<EndorserFinalization> = pairs
            .iter()
            .map(|(sk, vk)| EndorserData {
                endorser_key: *vk,
                maybe_receipt: Some(sk.sign(&message)),
            })
            .collect();
        let act_entries = setup.sign_activation_receipts(&[0, 1]);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        let result = setup.verifier.apply_handover(handover);
        // The config ID check fires before signature verification.
        assert!(matches!(
            result,
            Err(HandoverError::FinalizationConfigMismatch)
        ));
    }

    #[test]
    fn apply_handover_rejects_invalid_handover() {
        let mut setup = HandoverSetup::new();
        // Config IDs match (correct keys, correct order), but no endorsers
        // actually signed — all receipts are None.
        let make_handover = || {
            let fin_entries: Vec<EndorserFinalization> = setup
                .old_vks
                .iter()
                .map(|vk| EndorserData {
                    endorser_key: *vk,
                    maybe_receipt: None,
                })
                .collect();
            let act_entries = setup.sign_activation_receipts(&[0, 1]);
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap()
        };

        // The handover is internally invalid (no finalization quorum).
        assert!(make_handover().verify(&setup.instance_id).is_err());

        // apply_handover delegates to verify and also rejects it.
        let result = setup.verifier.apply_handover(make_handover());
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // verify_read_latest tests
    // -----------------------------------------------------------------------

    /// A test setup for ledger receipt verification scenarios.
    struct LedgerSetup {
        verifier: Verifier,
        sks: Vec<SigningKey>,
        block: LedgerBlock,
        nonce: u64,
        ledger_id: u32,
    }

    impl LedgerSetup {
        /// Creates a 3-endorser cohort with a reference ledger block.
        fn new() -> Self {
            let (sks, vks) = sorted_key_pairs(3);
            let config = CohortConfig::try_from_keys(vks).unwrap();
            let verifier = Verifier::new(config);
            Self {
                verifier,
                sks,
                block: LedgerBlock {
                    entry: [0xAA; 32],
                    index: 42,
                    hash_chain_tail: [0xBB; 32],
                },
                nonce: 12345,
                ledger_id: 7,
            }
        }

        /// Signs read_latest receipts for the given endorsers (by index).
        fn sign_read_latest_receipts(
            &self,
            signers: &[usize],
            instance_id: &[u8; 32],
            block: &LedgerBlock,
            nonce: u64,
            ledger_id: u32,
        ) -> LedgerReceipts {
            let receipts = signers
                .iter()
                .map(|&i| {
                    let message = receipts::build_tip_receipt_message(
                        instance_id,
                        ledger_id,
                        &block.entry,
                        block.index,
                        &block.hash_chain_tail,
                        nonce,
                    );
                    LedgerReceipt {
                        key_index: i,
                        block: block.clone(),
                        signature: self.sks[i].sign(&message),
                    }
                })
                .collect::<Vec<_>>();
            LedgerReceipts::new(receipts)
        }

        /// Signs append_entry receipts for the given endorsers (by index).
        fn sign_append_receipts(
            &self,
            signers: &[usize],
            instance_id: &[u8; 32],
            block: &LedgerBlock,
            ledger_id: u32,
        ) -> LedgerReceipts {
            let receipts = signers
                .iter()
                .map(|&i| {
                    let message = receipts::build_entry_receipt_message(
                        instance_id,
                        ledger_id,
                        &block.entry,
                        block.index,
                        &block.hash_chain_tail,
                    );
                    LedgerReceipt {
                        key_index: i,
                        block: block.clone(),
                        signature: self.sks[i].sign(&message),
                    }
                })
                .collect::<Vec<_>>();
            LedgerReceipts::new(receipts)
        }

        /// Signs read_latest receipts using the setup's default values.
        fn sign_good_read_latest_receipts(&self, signers: &[usize]) -> LedgerReceipts {
            self.sign_read_latest_receipts(
                signers,
                self.verifier.instance_id(),
                &self.block,
                self.nonce,
                self.ledger_id,
            )
        }

        /// Signs append_entry receipts using the setup's default values.
        fn sign_good_append_receipts(&self, signers: &[usize]) -> LedgerReceipts {
            self.sign_append_receipts(
                signers,
                self.verifier.instance_id(),
                &self.block,
                self.ledger_id,
            )
        }
    }

    #[test]
    fn read_latest_happy_path_minimum_quorum() {
        let setup = LedgerSetup::new();
        let receipts = setup.sign_good_read_latest_receipts(&[0, 1]);
        let result = setup
            .verifier
            .verify_read_latest(&receipts, setup.nonce, setup.ledger_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), setup.block);
    }

    #[test]
    fn read_latest_fails_bad_nonce() {
        let setup = LedgerSetup::new();
        let receipts = setup.sign_good_read_latest_receipts(&[0, 1]);
        let wrong_nonce = setup.nonce + 1;
        let result = setup
            .verifier
            .verify_read_latest(&receipts, wrong_nonce, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn read_latest_fails_bad_ledger_id() {
        let setup = LedgerSetup::new();
        let receipts = setup.sign_good_read_latest_receipts(&[0, 1]);
        let wrong_ledger_id = setup.ledger_id + 1;
        let result = setup
            .verifier
            .verify_read_latest(&receipts, setup.nonce, wrong_ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn read_latest_fails_bad_entry() {
        let setup = LedgerSetup::new();
        let mut bad_block = setup.block.clone();
        bad_block.entry = [0xFF; 32];
        let good_receipts = setup.sign_good_read_latest_receipts(&[0]);
        let bad_receipts = setup.sign_read_latest_receipts(
            &[1],
            setup.verifier.instance_id(),
            &bad_block,
            setup.nonce,
            setup.ledger_id,
        );
        // Combine: first receipt (reference) is good, second has different entry.
        let combined = LedgerReceipts::new(
            good_receipts
                .iter()
                .chain(bad_receipts.iter())
                .map(|r| LedgerReceipt {
                    key_index: r.key_index,
                    block: r.block.clone(),
                    signature: r.signature,
                })
                .collect::<Vec<_>>(),
        );
        let result = setup
            .verifier
            .verify_read_latest(&combined, setup.nonce, setup.ledger_id);
        // Only 1 of 3 matches the reference → quorum not met.
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn read_latest_fails_bad_index() {
        let setup = LedgerSetup::new();
        let mut bad_block = setup.block.clone();
        bad_block.index = 999;
        let good_receipts = setup.sign_good_read_latest_receipts(&[0]);
        let bad_receipts = setup.sign_read_latest_receipts(
            &[1],
            setup.verifier.instance_id(),
            &bad_block,
            setup.nonce,
            setup.ledger_id,
        );
        let combined = LedgerReceipts::new(
            good_receipts
                .iter()
                .chain(bad_receipts.iter())
                .map(|r| LedgerReceipt {
                    key_index: r.key_index,
                    block: r.block.clone(),
                    signature: r.signature,
                })
                .collect::<Vec<_>>(),
        );
        let result = setup
            .verifier
            .verify_read_latest(&combined, setup.nonce, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn read_latest_fails_bad_hash_chain_tail() {
        let setup = LedgerSetup::new();
        let mut bad_block = setup.block.clone();
        bad_block.hash_chain_tail = [0xCC; 32];
        let good_receipts = setup.sign_good_read_latest_receipts(&[0]);
        let bad_receipts = setup.sign_read_latest_receipts(
            &[1],
            setup.verifier.instance_id(),
            &bad_block,
            setup.nonce,
            setup.ledger_id,
        );
        let combined = LedgerReceipts::new(
            good_receipts
                .iter()
                .chain(bad_receipts.iter())
                .map(|r| LedgerReceipt {
                    key_index: r.key_index,
                    block: r.block.clone(),
                    signature: r.signature,
                })
                .collect::<Vec<_>>(),
        );
        let result = setup
            .verifier
            .verify_read_latest(&combined, setup.nonce, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn read_latest_fails_bad_instance_id() {
        let setup = LedgerSetup::new();
        let wrong_instance_id = [0xFF; 32];
        let receipts = setup.sign_read_latest_receipts(
            &[0, 1],
            &wrong_instance_id,
            &setup.block,
            setup.nonce,
            setup.ledger_id,
        );
        let result = setup
            .verifier
            .verify_read_latest(&receipts, setup.nonce, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    // -----------------------------------------------------------------------
    // verify_append tests
    // -----------------------------------------------------------------------

    #[test]
    fn append_happy_path_minimum_quorum() {
        let setup = LedgerSetup::new();
        let receipts = setup.sign_good_append_receipts(&[0, 1]);
        let result = setup
            .verifier
            .verify_append(&receipts, setup.block.index, setup.ledger_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), setup.block);
    }

    #[test]
    fn append_fails_bad_ledger_id() {
        let setup = LedgerSetup::new();
        let receipts = setup.sign_good_append_receipts(&[0, 1]);
        let wrong_ledger_id = setup.ledger_id + 1;
        let result = setup
            .verifier
            .verify_append(&receipts, setup.block.index, wrong_ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn append_fails_bad_entry() {
        let setup = LedgerSetup::new();
        let mut bad_block = setup.block.clone();
        bad_block.entry = [0xFF; 32];
        let good_receipts = setup.sign_good_append_receipts(&[0]);
        let bad_receipts = setup.sign_append_receipts(
            &[1],
            setup.verifier.instance_id(),
            &bad_block,
            setup.ledger_id,
        );
        let combined = LedgerReceipts::new(
            good_receipts
                .iter()
                .chain(bad_receipts.iter())
                .map(|r| LedgerReceipt {
                    key_index: r.key_index,
                    block: r.block.clone(),
                    signature: r.signature,
                })
                .collect::<Vec<_>>(),
        );
        let result = setup
            .verifier
            .verify_append(&combined, setup.block.index, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn append_fails_bad_index() {
        let setup = LedgerSetup::new();
        let mut bad_block = setup.block.clone();
        bad_block.index = 999;
        let good_receipts = setup.sign_good_append_receipts(&[0]);
        let bad_receipts = setup.sign_append_receipts(
            &[1],
            setup.verifier.instance_id(),
            &bad_block,
            setup.ledger_id,
        );
        let combined = LedgerReceipts::new(
            good_receipts
                .iter()
                .chain(bad_receipts.iter())
                .map(|r| LedgerReceipt {
                    key_index: r.key_index,
                    block: r.block.clone(),
                    signature: r.signature,
                })
                .collect::<Vec<_>>(),
        );
        let result = setup
            .verifier
            .verify_append(&combined, setup.block.index, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn append_fails_bad_hash_chain_tail() {
        let setup = LedgerSetup::new();
        let mut bad_block = setup.block.clone();
        bad_block.hash_chain_tail = [0xCC; 32];
        let good_receipts = setup.sign_good_append_receipts(&[0]);
        let bad_receipts = setup.sign_append_receipts(
            &[1],
            setup.verifier.instance_id(),
            &bad_block,
            setup.ledger_id,
        );
        let combined = LedgerReceipts::new(
            good_receipts
                .iter()
                .chain(bad_receipts.iter())
                .map(|r| LedgerReceipt {
                    key_index: r.key_index,
                    block: r.block.clone(),
                    signature: r.signature,
                })
                .collect::<Vec<_>>(),
        );
        let result = setup
            .verifier
            .verify_append(&combined, setup.block.index, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn append_fails_bad_instance_id() {
        let setup = LedgerSetup::new();
        let wrong_instance_id = [0xFF; 32];
        let receipts =
            setup.sign_append_receipts(&[0, 1], &wrong_instance_id, &setup.block, setup.ledger_id);
        let result = setup
            .verifier
            .verify_append(&receipts, setup.block.index, setup.ledger_id);
        assert!(matches!(result, Err(VerifyError::QuorumNotMet(_))));
    }

    #[test]
    fn append_fails_wrong_expected_index() {
        let setup = LedgerSetup::new();
        let receipts = setup.sign_good_append_receipts(&[0, 1]);
        let wrong_index = setup.block.index + 1;
        let result = setup
            .verifier
            .verify_append(&receipts, wrong_index, setup.ledger_id);
        assert!(matches!(
            result,
            Err(VerifyError::UnexpectedIndex { expected, actual })
                if expected == wrong_index && actual == setup.block.index
        ));
    }
}
