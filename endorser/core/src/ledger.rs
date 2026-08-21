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

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

use logcabin_base::receipts;
use logcabin_base::{ConfigId, LedgerBlock, Sha256Digest};
use sha2::{Digest, Sha256};

/// A snapshot of a ledger's tail block, signed by the endorser.
///
/// The signature covers the ledger state and a client-supplied nonce
/// to prevent replay attacks.
// TODO: b/476380752 - Merge with base::LedgerReceipt.
#[derive(Debug)]
pub struct SignedLedgerBlock {
    /// The ledger block that was signed.
    pub block: LedgerBlock,
    /// Client-supplied nonce included in the signature.
    pub nonce: u64,
    /// ECDSA P-256 signature (RAW R || S) over the `read_latest` receipt
    /// message (see [`receipts::build_read_latest_message`]).
    pub signature: Signature,
}

impl SignedLedgerBlock {
    /// Creates a new signed ledger block by signing the current ledger state.
    pub(crate) fn new(
        block: &LedgerBlock,
        nonce: u64,
        ledger_id: u32,
        instance_id: &ConfigId,
        signing_key: &SigningKey,
    ) -> Self {
        let message = receipts::build_read_latest_message(
            instance_id,
            ledger_id,
            &block.entry,
            block.index,
            &block.hash_chain_tail,
            nonce,
        );

        Self {
            block: block.clone(),
            nonce,
            signature: signing_key.sign(&message),
        }
    }
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
