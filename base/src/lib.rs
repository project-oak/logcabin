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

//! Shared definitions for the LogCabin endorser and verifier.
//!
//! This crate contains types and functions whose representations are currently
//! shared by both ends of the protocol.

#![no_std]

extern crate alloc;

pub mod receipts;

use alloc::vec::Vec;
use core::convert::Infallible;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Cohort Data
// ---------------------------------------------------------------------------

/// Per-endorser entry: a verifying key plus an optional attached datum.
///
/// The type parameter `R` is the receipt type — typically a signature.
#[derive(Clone)]
pub struct EndorserData<R> {
    /// Verifying key of the endorser.
    pub endorser_key: VerifyingKey,
    /// Optional attached data. `None` for endorsers that did not produce
    /// a receipt (e.g., because they crashed).
    pub maybe_receipt: Option<R>,
}

/// A validated collection of per-endorser entries in strict ascending
/// SEC1-lexicographic key order.
///
/// In LogCabin, there's a few situations where we need all endorser
/// verifying keys (to match cohort config and compute required quorum), but
/// only some endorsers produced attached data (e.g. finalization receipts).
/// Additionally, keys must be unique and each attached datum must be signed
/// by that endorser's key and no other.
///
/// While there's a few ways this can be achieved, the structure chosen is a
/// list of pairs (mandatory key, optional receipt), in strict  ascending
/// SEC1-lexicographic order by key. This way, checking key uniqueness and that
/// each key is used at most once becomes natural and trivial.
///
/// CohortData represents the full list of endorsers in a cohort, where each
/// endorser carries an optional attached datum — typically a receipt (signature).
/// Not all endorsers may have produced a receipt (e.g., an endorser that
/// crashed before finalizing), so the attachment is `Option<R>`.
///
/// The key-ordering invariant is established at construction via
/// [`try_new`](CohortData::try_new) and cannot be violated afterward.
/// It enables canonical config ID derivation (SHA-256 of the concatenated
/// SEC1 keys) and O(log n) key lookups.
#[derive(Clone)]
pub struct CohortData<R> {
    entries: Vec<EndorserData<R>>,
}

impl<R> CohortData<R> {
    /// Creates a new `CohortData` from an iterator of endorser entries.
    ///
    /// Returns `Err(InvalidConfigError)` if the collection is empty or if
    /// the endorser keys are not in strict ascending SEC1-lexicographic
    /// order (which also implies no duplicates).
    pub fn try_new(
        entries: impl IntoIterator<Item = EndorserData<R>>,
    ) -> Result<Self, InvalidConfigError> {
        let entries: Vec<EndorserData<R>> = entries.into_iter().collect();
        if entries.is_empty() {
            return Err(InvalidConfigError);
        }
        for window in entries.windows(2) {
            if window[0].endorser_key.to_sec1_bytes().as_ref()
                >= window[1].endorser_key.to_sec1_bytes().as_ref()
            {
                return Err(InvalidConfigError);
            }
        }
        Ok(Self { entries })
    }

    /// Returns the endorser entries.
    pub fn endorsers(&self) -> &[EndorserData<R>] {
        &self.entries
    }

    /// Returns an iterator over the endorser verifying keys.
    pub fn keys(&self) -> impl Iterator<Item = &VerifyingKey> + '_ {
        self.entries.iter().map(|e| &e.endorser_key)
    }

    /// Returns the number of endorsers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the collection contains the given key.
    pub fn contains(&self, key: &VerifyingKey) -> bool {
        let target = key.to_sec1_bytes();
        self.entries
            .binary_search_by(|e| e.endorser_key.to_sec1_bytes().as_ref().cmp(target.as_ref()))
            .is_ok()
    }

    /// Returns the config ID: SHA-256 of the concatenated SEC1 bytes.
    pub fn config_id(&self) -> [u8; 32] {
        compute_config_id(self.keys())
    }

    /// Extracts the endorser keys, discarding any attached data.
    ///
    /// The resulting [`CohortConfig`] preserves the sorted-key invariant
    /// without re-validation.
    pub fn into_config(self) -> CohortConfig {
        CohortData {
            entries: self
                .entries
                .into_iter()
                .map(|e| EndorserData {
                    endorser_key: e.endorser_key,
                    maybe_receipt: None,
                })
                .collect(),
        }
    }
}

/// A validated cohort configuration: a sorted set of endorser verifying keys.
///
/// A CohortConfig is made only of a list of unique, sorted verifying keys.
/// It's an edge case of [`CohortData`] where no endorser has any attached data.
/// [`Infallible`] means `Option<Infallible>` can only be `None`.
pub type CohortConfig = CohortData<Infallible>;

impl CohortConfig {
    /// Creates a new [`CohortConfig`] from an iterator of keys.
    ///
    /// Returns `Err(InvalidConfigError)` if the iterator is empty or if the
    /// keys are not in strict ascending SEC1-lexicographic order (which also
    /// implies no duplicates).
    pub fn try_from_keys(
        keys: impl IntoIterator<Item = VerifyingKey>,
    ) -> Result<Self, InvalidConfigError> {
        CohortData::try_new(keys.into_iter().map(|k| EndorserData {
            endorser_key: k,
            maybe_receipt: None,
        }))
    }
}

/// Finalization data from a single endorser in the outgoing cohort.
pub type EndorserFinalization = EndorserData<Signature>;

/// Finalization receipts from the outgoing cohort: a validated collection of
/// endorser finalization entries in strict ascending SEC1-lexicographic key
/// order.
pub type CohortFinalization = CohortData<Signature>;

/// Error returned when constructing a [`CohortData`] with no entries or
/// with keys that are not in strict ascending SEC1-lexicographic order.
#[derive(Debug)]
pub struct InvalidConfigError;

/// Computes the config ID: SHA-256 of the concatenated SEC1 bytes of the
/// provided verifying keys.
pub fn compute_config_id<'a>(keys: impl Iterator<Item = &'a VerifyingKey>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for key in keys {
        hasher.update(&key.to_sec1_bytes());
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Ledger block
// ---------------------------------------------------------------------------

/// A ledger block: the entry, index, and hash chain tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerBlock {
    /// Entry contents (32 bytes).
    pub entry: [u8; 32],
    /// Index of the entry in the ledger.
    pub index: u64,
    /// Hash chain tail (32 bytes).
    pub hash_chain_tail: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p256::ecdsa::SigningKey;

    /// Generates `n` random verifying keys sorted in SEC1-lexicographic order.
    fn sorted_keys(n: usize) -> Vec<VerifyingKey> {
        sorted_keys_from(
            (0..n)
                .map(|_| *SigningKey::random(&mut rand_core::OsRng).verifying_key())
                .collect(),
        )
    }

    fn sorted_keys_from(mut keys: Vec<VerifyingKey>) -> Vec<VerifyingKey> {
        keys.sort_by(|a, b| a.to_sec1_bytes().as_ref().cmp(b.to_sec1_bytes().as_ref()));
        keys
    }

    #[test]
    fn try_from_keys_accepts_sorted_keys() {
        let keys = sorted_keys(3);
        let config = CohortConfig::try_from_keys(keys.clone()).unwrap();
        assert!(config.keys().eq(keys.iter()));
    }

    #[test]
    fn try_from_keys_rejects_unsorted_keys() {
        let keys = sorted_keys(3);
        // Reverse to get descending order.
        let reversed: Vec<VerifyingKey> = keys.into_iter().rev().collect();
        assert!(CohortConfig::try_from_keys(reversed).is_err());
    }

    #[test]
    fn try_from_keys_rejects_empty() {
        assert!(CohortConfig::try_from_keys(core::iter::empty()).is_err());
    }

    #[test]
    fn compute_config_id_golden() {
        // Deterministic keys from known scalars.
        let sk_a = SigningKey::from_slice(&[0x01; 32]).unwrap();
        let sk_b = SigningKey::from_slice(&[0x02; 32]).unwrap();
        let keys = sorted_keys_from(vec![*sk_a.verifying_key(), *sk_b.verifying_key()]);
        let config = CohortConfig::try_from_keys(keys).unwrap();
        #[rustfmt::skip]
        let expected = [
            109, 104, 212, 208, 226, 191, 70, 40,
            166,   3, 218,  74, 180, 152, 35, 194,
             87, 173,  12,  60,  49, 140, 51, 146,
             42, 167, 193, 229,  63,  52, 128, 188,
        ];
        assert_eq!(config.config_id(), expected);
    }

    #[test]
    fn try_from_keys_rejects_duplicate_keys() {
        let key = *SigningKey::random(&mut rand_core::OsRng).verifying_key();
        assert!(CohortConfig::try_from_keys(vec![key, key]).is_err());
    }

    // -----------------------------------------------------------------------
    // CohortData::try_new — ordering invariant tests
    // -----------------------------------------------------------------------

    /// Helper: wraps keys into `EndorserData` entries with `None` receipts.
    fn entries_from_keys(keys: Vec<VerifyingKey>) -> Vec<EndorserData<()>> {
        keys.into_iter()
            .map(|k| EndorserData {
                endorser_key: k,
                maybe_receipt: None,
            })
            .collect()
    }

    #[test]
    fn cohort_data_rejects_empty() {
        assert!(CohortData::<()>::try_new(Vec::new()).is_err());
    }

    #[test]
    fn cohort_data_rejects_duplicate_keys() {
        let key = *SigningKey::random(&mut rand_core::OsRng).verifying_key();
        assert!(CohortData::try_new(vec![
            EndorserData {
                endorser_key: key,
                maybe_receipt: None::<()>,
            },
            EndorserData {
                endorser_key: key,
                maybe_receipt: None::<()>,
            },
        ])
        .is_err());
    }

    #[test]
    fn cohort_data_rejects_unsorted_keys() {
        let keys = sorted_keys(3);
        let reversed: Vec<VerifyingKey> = keys.into_iter().rev().collect();
        assert!(CohortData::try_new(entries_from_keys(reversed)).is_err());
    }

    #[test]
    fn cohort_data_accepts_sorted_unique_keys() {
        let keys = sorted_keys(2);
        let entries = entries_from_keys(keys.clone());
        let data = CohortData::try_new(entries).unwrap();
        assert!(data.keys().eq(keys.iter()));
    }
}
