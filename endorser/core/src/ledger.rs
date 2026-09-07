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

//! Ledger types: tail blocks and signed ledger blocks.

use alloc::collections::BTreeMap;

use p256::ecdsa::Signature;

use logcabin_base::{LedgerBlock, Sha256Digest};
use sha2::{Digest, Sha256};

/// A snapshot of a ledger's state, with both receipts signed by the endorser.
///
/// Returned by both [`Endorser::append_entry`] and [`Endorser::read_latest`].
/// The signing is performed by the Endorser, not by this type.
// TODO: b/476380752 - Merge with base::LedgerReceipt.
#[derive(Debug)]
pub struct SignedLedgerBlock {
    /// The ledger block (entry, index, hash_chain_tail).
    pub block: LedgerBlock,
    /// Entry receipt (nonce-free). Proves the entry is committed at this index.
    /// This is a timeless proof of commitment, stored by the coordinator.
    pub entry_receipt: Signature,
    /// Tip receipt (nonce-bound). Proves the ledger tip is at this state,
    /// bound to the client-supplied nonce for freshness.
    pub tip_receipt: Signature,
}

impl core::ops::Deref for SignedLedgerBlock {
    type Target = LedgerBlock;
    fn deref(&self) -> &LedgerBlock {
        &self.block
    }
}

/// Ledger store: maps ledger ID to the current ledger block.
#[derive(Clone)]
pub struct Ledgers(BTreeMap<u32, LedgerBlock>);

impl Ledgers {
    /// Creates a new, empty ledger store.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Computes a deterministic SHA-256 hash of the full ledger state.
    ///
    /// Format hashed:
    ///   `num_ledgers (4 bytes, BE) || ledger items...`
    ///
    /// Each ledger item (in ascending `ledger_id` order):
    ///   `ledger_id (u32 BE) || entry (32 bytes) || index (u64 BE) ||
    ///    hash_chain_tail (32 bytes)`
    pub fn hash(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(&(self.0.len() as u32).to_be_bytes());
        for (ledger_id, block) in &self.0 {
            hasher.update(&ledger_id.to_be_bytes());
            hasher.update(&block.entry);
            hasher.update(&block.index.to_be_bytes());
            hasher.update(&block.hash_chain_tail);
        }
        hasher.finalize().into()
    }
}

impl core::ops::Deref for Ledgers {
    type Target = BTreeMap<u32, LedgerBlock>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for Ledgers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::iter::FromIterator<(u32, LedgerBlock)> for Ledgers {
    fn from_iter<I: IntoIterator<Item = (u32, LedgerBlock)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}
