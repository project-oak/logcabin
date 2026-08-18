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

//! Ledger receipt types for the verifier.
//!
//! These types wrap endorser signatures alongside the ledger block they
//! cover, indexed by the endorser's position in the [`CohortConfig`].

use alloc::vec::Vec;
use core::ops::Deref;
use logcabin_base::LedgerBlock;
use p256::ecdsa::Signature;

/// A single endorser's signed receipt for a ledger operation.
///
/// The endorser is identified by its positional index in the [`CohortConfig`],
/// enabling O(1) key lookup during verification.
///
/// A LedgerReceipt is verified against the [`CohortConfig`] of the endorser
/// that originated it. A verifier knows in advance which config it trusts.
///
/// Design note: A natural approach would have been to have the verifying key
/// instead of its index in the config. However, this requires the verifier to
/// look up each key in its trusted config, more expensive uniqueness checks,
/// and moving more data (33 bytes per key per endorser) for each request. Key
/// indices allow the same checks in O(n_endorsers) time without hash tables.
pub struct LedgerReceipt {
    /// Index of the endorser's key within the [`CohortConfig`].
    pub key_index: usize,
    /// The ledger block this receipt covers.
    pub block: LedgerBlock,
    /// ECDSA P-256 signature over the receipt message.
    pub signature: Signature,
}

impl Deref for LedgerReceipt {
    type Target = LedgerBlock;

    fn deref(&self) -> &LedgerBlock {
        &self.block
    }
}

/// A collection of endorser receipts for a ledger operation.
///
/// Each receipt references an endorser by its positional index in the
/// [`CohortConfig`], enabling O(1) key lookup during verification.
///
/// **Note:** This type does not validate key index uniqueness or bounds.
/// Those checks are performed by [`Verifier::verify_read_latest`], which
/// has access to the [`CohortConfig`] and can safely allocate a bitmap
/// for deduplication.
pub struct LedgerReceipts {
    receipts: Vec<LedgerReceipt>,
}

impl LedgerReceipts {
    /// Creates a new `LedgerReceipts`.
    ///
    /// No validation is performed here; key index uniqueness and bounds
    /// are checked at verification time.
    pub fn new(receipts: impl IntoIterator<Item = LedgerReceipt>) -> Self {
        Self {
            receipts: receipts.into_iter().collect(),
        }
    }
}

impl Deref for LedgerReceipts {
    type Target = [LedgerReceipt];

    fn deref(&self) -> &[LedgerReceipt] {
        &self.receipts
    }
}
