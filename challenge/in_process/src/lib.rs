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

//! In-process harness for the LogCabin split-view challenge.
//!
//! Implement [`Falsifier`] and pass it to [`run`]. See `challenge/README.md`
//! for rules and details.

#![forbid(unsafe_code)]

mod harness;
pub mod util;

pub use harness::{cohort_config, evaluate_split, new_sorted_endorsers, run};

use std::num::NonZeroUsize;

use logcabin_base::{EntryContents, LedgerBlock};
use logcabin_endorser_core::{Endorser, Uninitialized};
use logcabin_verifier::{CohortHandover, HandoverError, LedgerReceipts, VerifyError};

/// Cohort size used unless a [`Falsifier`] overrides it (2-of-3 quorum).
pub const DEFAULT_COHORT_SIZE: NonZeroUsize = NonZeroUsize::new(3).unwrap();

/// An attempt to produce two conflicting views accepted by [`Verifier`](logcabin_verifier::Verifier).
pub trait Falsifier {
    /// Size of the initial cohort, defaulting to [`DEFAULT_COHORT_SIZE`]. Successor
    /// cohorts you build yourself can be any size.
    fn cohort_size(&self) -> NonZeroUsize {
        DEFAULT_COHORT_SIZE
    }

    /// Given a fresh uninitialized cohort (sorted by SEC1 verifying key so
    /// `endorsers[i]` has `key_index == i`), returns two views to verify.
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View);
}

/// A ledger view to be verified by a [`Verifier`](logcabin_verifier::Verifier).
#[derive(Debug)]
pub struct View {
    /// Handovers to apply in order from the initial cohort config.
    pub handovers: Vec<CohortHandover>,
    /// Receipts to verify against the resulting cohort config.
    pub receipts: LedgerReceipts,
    /// Target ledger ID.
    pub ledger_id: u32,
    /// Verification method and parameters.
    pub verification: Verification,
}

/// Which [`Verifier`](logcabin_verifier::Verifier) method to invoke on a [`View`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// [`Verifier::verify_read_latest`](logcabin_verifier::Verifier::verify_read_latest).
    ReadLatest { nonce: u64 },
    /// [`Verifier::verify_append`](logcabin_verifier::Verifier::verify_append).
    Append { entry: EntryContents, nonce: u64 },
    /// [`Verifier::verify_entry`](logcabin_verifier::Verifier::verify_entry).
    Entry { requested_index: u64 },
}

/// Result of running a [`Falsifier`]. Only [`SplitViewAchieved`](Outcome::SplitViewAchieved) is a win.
#[derive(Debug)]
pub enum Outcome {
    /// Both views verified at the same index on the same ledger but differ.
    SplitViewAchieved {
        ledger_id: u32,
        block_a: LedgerBlock,
        block_b: LedgerBlock,
    },
    /// A handover in `which` view's chain failed at `position`.
    HandoverRejected {
        which: WhichView,
        position: usize,
        error: HandoverError,
    },
    /// Receipt verification failed for `which` view.
    ViewRejected {
        which: WhichView,
        error: VerifyError,
    },
    /// Both views verified, but they are mutually consistent.
    NotAFork { reason: NotAForkReason },
    /// Both views verified and returned the exact same block.
    ViewsAgree,
    /// `Falsifier::attempt` panicked, with the panic message if it was a string.
    Panicked { message: String },
}

impl Outcome {
    /// Returns true if this outcome is [`Outcome::SplitViewAchieved`].
    pub fn is_split_view(&self) -> bool {
        matches!(self, Outcome::SplitViewAchieved { .. })
    }
}

/// Identifies one of the two submitted views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhichView {
    A,
    B,
}

/// Why two verified views do not contradict each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAForkReason {
    /// The views target different ledgers.
    DifferentLedger,
    /// The blocks sit at different indices, so they make no competing claim.
    DifferentIndex,
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_endorser_core::Active;
    use logcabin_verifier::{LedgerReceipt, Verifier};

    const LEDGER: u32 = 0;

    /// Activates a single-endorser instance, appends `entry` at index 1, and returns the verified block.
    fn committed_block(entry: EntryContents, nonce: u64) -> LedgerBlock {
        let endorsers = new_sorted_endorsers(1);
        let config = cohort_config(&endorsers).expect("a one-key config is well formed");
        let verifier = Verifier::new(config.clone());

        let mut endorser: Endorser<Active> = endorsers
            .into_iter()
            .next()
            .expect("exactly one endorser")
            .activate(config, None)
            .unwrap_or_else(|_| panic!("activation must succeed"));

        endorser
            .append_entry(LEDGER, entry, 1, 0x1111)
            .expect("appending to the fresh default ledger must succeed");

        let read = endorser
            .read_latest(LEDGER, nonce)
            .expect("the default ledger exists");

        let receipts = LedgerReceipts::new([LedgerReceipt {
            key_index: 0,
            block: read.block.clone(),
            signature: read.read_receipt,
        }]);

        verifier
            .verify_read_latest(&receipts, nonce, LEDGER)
            .expect("a sole endorser is its own quorum")
    }

    #[test]
    fn a_genuine_fork_is_reported_as_a_split_view() {
        let block_a = committed_block([0x01; 32], 0x2222);
        let block_b = committed_block([0x02; 32], 0x3333);

        assert_eq!(block_a.index, block_b.index, "both must sit at index 1");
        assert_ne!(block_a.entry, block_b.entry, "the entries must differ");

        let outcome = evaluate_split(LEDGER, block_a, LEDGER, block_b);
        assert!(
            outcome.is_split_view(),
            "a real fork must be reported as a win, got {outcome:?}"
        );
    }

    #[test]
    fn independent_instances_that_agree_are_not_a_split_view() {
        let block_a = committed_block([0x01; 32], 0x2222);
        let block_b = committed_block([0x01; 32], 0x3333);

        let outcome = evaluate_split(LEDGER, block_a, LEDGER, block_b);
        assert!(matches!(outcome, Outcome::ViewsAgree), "{outcome:?}");
    }
}
