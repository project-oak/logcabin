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

//! Harness execution and win-condition evaluation.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

use logcabin_base::{CohortConfig, InvalidConfigError, LedgerBlock};
use logcabin_endorser_core::{Endorser, Uninitialized};
use logcabin_verifier::Verifier;

use crate::{Falsifier, NotAForkReason, Outcome, Verification, View, WhichView};

/// Builds a [`CohortConfig`] from `endorsers` (must be sorted by SEC1 key bytes).
pub fn cohort_config<S>(endorsers: &[Endorser<S>]) -> Result<CohortConfig, InvalidConfigError> {
    CohortConfig::try_from_keys(endorsers.iter().map(|e| *e.verifying_key()))
}

/// Creates `n` endorsers sorted by SEC1 verifying key so array index equals `key_index`.
pub fn new_sorted_endorsers(n: usize) -> Vec<Endorser<Uninitialized>> {
    let mut endorsers: Vec<Endorser<Uninitialized>> = (0..n).map(|_| Endorser::new()).collect();
    endorsers.sort_by(|a, b| {
        a.verifying_key()
            .to_sec1_bytes()
            .as_ref()
            .cmp(b.verifying_key().to_sec1_bytes().as_ref())
    });
    endorsers
}

/// Runs `falsifier` against a fresh cohort of [`Falsifier::cohort_size`] endorsers.
///
/// Each returned [`View`] is verified on its own [`Verifier`] initialized from
/// the initial cohort config and evolved via [`Verifier::apply_handover`].
pub fn run<F: Falsifier>(falsifier: F) -> Outcome {
    let endorsers = new_sorted_endorsers(falsifier.cohort_size().get());
    let genesis = cohort_config(&endorsers).expect("harness-built cohort is always valid");

    let (view_a, view_b) = match catch_unwind(AssertUnwindSafe(|| falsifier.attempt(endorsers))) {
        Ok(views) => views,
        Err(payload) => {
            return Outcome::Panicked {
                message: panic_message(payload.as_ref()),
            }
        }
    };

    let ledger_a = view_a.ledger_id;
    let ledger_b = view_b.ledger_id;

    let block_a = match resolve_block(&genesis, view_a, WhichView::A) {
        Ok(block) => block,
        Err(outcome) => return outcome,
    };
    let block_b = match resolve_block(&genesis, view_b, WhichView::B) {
        Ok(block) => block,
        Err(outcome) => return outcome,
    };

    evaluate_split(ledger_a, block_a, ledger_b, block_b)
}

/// Initializes a [`Verifier`] from `genesis`, applies `view.handovers`, and verifies `view.receipts`.
///
/// If verification passes, returns the resolved [`LedgerBlock`]. If verification
/// fails, returns [`Outcome::ViewRejected`] (or [`Outcome::HandoverRejected`] if a handover fails).
fn resolve_block(
    genesis: &CohortConfig,
    view: View,
    which: WhichView,
) -> Result<LedgerBlock, Outcome> {
    let View {
        handovers,
        receipts,
        ledger_id,
        verification,
    } = view;

    let mut verifier = Verifier::new(genesis.clone());
    for (position, handover) in handovers.into_iter().enumerate() {
        verifier
            .apply_handover(handover)
            .map_err(|error| Outcome::HandoverRejected {
                which,
                position,
                error,
            })?;
    }

    match &verification {
        Verification::ReadLatest { nonce } => {
            verifier.verify_read_latest(&receipts, *nonce, ledger_id)
        }
        Verification::Append { entry, nonce } => {
            verifier.verify_append(&receipts, entry, *nonce, ledger_id)
        }
        Verification::Entry { requested_index } => {
            verifier.verify_entry(&receipts, *requested_index, ledger_id)
        }
    }
    .map_err(|error| Outcome::ViewRejected { which, error })
}

/// Compares two verified blocks on the same ledger for a contradiction.
///
/// Two blocks contradict each other only if they sit at the same index and
/// differ. Bring both views to a common index to compare them; the timeless
/// [`Verification::Entry`] can request any index a cohort holds.
pub fn evaluate_split(
    ledger_a: u32,
    block_a: LedgerBlock,
    ledger_b: u32,
    block_b: LedgerBlock,
) -> Outcome {
    if ledger_a != ledger_b {
        return Outcome::NotAFork {
            reason: NotAForkReason::DifferentLedger,
        };
    }

    if block_a.index != block_b.index {
        return Outcome::NotAFork {
            reason: NotAForkReason::DifferentIndex,
        };
    }

    if block_a.entry == block_b.entry && block_a.hash_chain_tail == block_b.hash_chain_tail {
        return Outcome::ViewsAgree;
    }

    Outcome::SplitViewAchieved {
        ledger_id: ledger_a,
        block_a,
        block_b,
    }
}

/// Best-effort rendering of a [`catch_unwind`] payload.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_verifier::LedgerReceipts;
    use std::num::NonZeroUsize;

    fn empty_views() -> (View, View) {
        let view = || View {
            handovers: Vec::new(),
            receipts: LedgerReceipts::new([]),
            ledger_id: 0,
            verification: Verification::ReadLatest { nonce: 1 },
        };
        (view(), view())
    }

    #[test]
    fn sorted_endorsers_match_their_config_positions() {
        let endorsers = new_sorted_endorsers(5);
        let config = cohort_config(&endorsers).expect("sorted endorsers form a valid config");

        assert_eq!(config.len(), 5);
        for (i, endorser) in endorsers.iter().enumerate() {
            assert_eq!(
                config.endorsers()[i].endorser_key,
                *endorser.verifying_key(),
                "endorser {i} must sit at key_index {i}"
            );
        }
    }

    #[test]
    fn a_panicking_falsifier_is_caught() {
        struct Panics;
        impl Falsifier for Panics {
            fn attempt(self, _: Vec<Endorser<Uninitialized>>) -> (View, View) {
                panic!("deliberate");
            }
        }

        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = run(Panics);
        std::panic::set_hook(previous);

        match outcome {
            Outcome::Panicked { message } => assert_eq!(message, "deliberate"),
            other => panic!("expected a caught panic, got {other:?}"),
        }
    }

    #[test]
    fn the_first_failing_view_is_the_one_reported() {
        struct Empty;
        impl Falsifier for Empty {
            fn attempt(self, _: Vec<Endorser<Uninitialized>>) -> (View, View) {
                empty_views()
            }
        }

        let outcome = run(Empty);
        assert!(
            matches!(
                outcome,
                Outcome::ViewRejected {
                    which: WhichView::A,
                    ..
                }
            ),
            "{outcome:?}"
        );
    }

    #[test]
    fn the_default_cohort_size_is_three() {
        struct Default_;
        impl Falsifier for Default_ {
            fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
                assert_eq!(endorsers.len(), 3);
                empty_views()
            }
        }

        let _ = run(Default_);
    }

    #[test]
    fn a_falsifier_can_override_the_cohort_size() {
        struct Sized(NonZeroUsize);
        impl Falsifier for Sized {
            fn cohort_size(&self) -> NonZeroUsize {
                self.0
            }
            fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
                assert_eq!(endorsers.len(), self.0.get());
                empty_views()
            }
        }

        for n in [1, 2, 7] {
            let _ = run(Sized(NonZeroUsize::new(n).expect("n is not zero")));
        }
    }

    fn block(entry: u8, index: u64, tail: u8) -> LedgerBlock {
        LedgerBlock {
            entry: [entry; 32],
            index,
            hash_chain_tail: [tail; 32],
        }
    }

    #[test]
    fn identical_blocks_agree() {
        let outcome = evaluate_split(0, block(1, 5, 9), 0, block(1, 5, 9));
        assert!(matches!(outcome, Outcome::ViewsAgree), "{outcome:?}");
    }

    #[test]
    fn different_ledger_is_not_a_fork() {
        let outcome = evaluate_split(0, block(1, 5, 9), 1, block(2, 5, 8));
        assert!(
            matches!(
                outcome,
                Outcome::NotAFork {
                    reason: NotAForkReason::DifferentLedger
                }
            ),
            "{outcome:?}"
        );
    }

    #[test]
    fn different_indices_are_not_a_fork() {
        // Adjacent indices are treated no differently from distant ones.
        for other in [block(2, 6, 8), block(2, 7, 8)] {
            let outcome = evaluate_split(0, block(1, 5, 9), 0, other);
            assert!(
                matches!(
                    outcome,
                    Outcome::NotAFork {
                        reason: NotAForkReason::DifferentIndex
                    }
                ),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn different_entry_is_a_fork() {
        let outcome = evaluate_split(0, block(1, 5, 9), 0, block(2, 5, 9));
        assert!(outcome.is_split_view(), "{outcome:?}");
    }

    #[test]
    fn same_entry_but_different_tail_is_a_fork() {
        let outcome = evaluate_split(0, block(1, 5, 9), 0, block(1, 5, 8));
        assert!(outcome.is_split_view(), "{outcome:?}");
    }

    #[test]
    fn split_view_reports_the_shared_ledger_and_blocks() {
        let outcome = evaluate_split(7, block(1, 5, 9), 7, block(2, 5, 9));
        match outcome {
            Outcome::SplitViewAchieved {
                ledger_id,
                block_a,
                block_b,
            } => {
                assert_eq!(ledger_id, 7);
                assert_eq!(block_a.index, 5);
                assert_eq!(block_b.index, 5);
            }
            other => panic!("expected a split view, got {other:?}"),
        }
    }
}
