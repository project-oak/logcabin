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

//! Attempts to fork the cohort lineage by finalizing a majority of a 5-endorser
//! cohort toward successor `P` and the remaining minority toward successor `Q`.
//!
//! Also shows a non-default [`Falsifier::cohort_size`]: the initial cohort is 5
//! (a 3-of-5 quorum) while both successor cohorts are 3.
//!
//! Fails with [`HandoverError::FinalizationQuorumNotMet`](logcabin_verifier::HandoverError::FinalizationQuorumNotMet):
//! [`Endorser::finalize`](logcabin_endorser_core::Endorser::finalize) consumes
//! `self`, so each endorser signs at most one finalization receipt and at most
//! one successor can gather a strict majority.

use std::num::NonZeroUsize;

use logcabin_base::{EndorserData, EndorserFinalization};
use logcabin_challenge::util::{
    all_indices, must_activate_all, must_activate_all_with_takeover, must_append_to,
    must_handover_from, must_read_latest_from, must_takeover_from,
};
use logcabin_challenge::{cohort_config, new_sorted_endorsers, Falsifier, Verification, View};
use logcabin_endorser_core::{Active, Endorser, Uninitialized};

pub const LEDGER: u32 = 0;

/// Initial cohort size, deliberately different from `DEFAULT_COHORT_SIZE`.
const COHORT_SIZE: usize = 5;
/// Size of each successor cohort; successors need not match the initial size.
const SUCCESSOR_SIZE: usize = 3;
/// Endorsers `[0, FOR_P)` finalize toward `P`, the rest toward `Q`.
const FOR_P: usize = 3;

pub struct DivergentHandover;

impl Falsifier for DivergentHandover {
    fn cohort_size(&self) -> NonZeroUsize {
        const { NonZeroUsize::new(COHORT_SIZE).unwrap() }
    }

    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let config = cohort_config(&endorsers).expect("the handed-in cohort is well formed");
        let instance_id = config.config_id();
        let successor_all = all_indices(SUCCESSOR_SIZE);
        let mut active = must_activate_all(endorsers, &config);

        must_append_to(
            &mut active,
            &all_indices(COHORT_SIZE),
            LEDGER,
            [0xAA; 32],
            1,
            0x1111,
        );

        let p_endorsers = new_sorted_endorsers(SUCCESSOR_SIZE);
        let p_config = cohort_config(&p_endorsers).expect("freshly sorted endorsers are valid");
        let q_endorsers = new_sorted_endorsers(SUCCESSOR_SIZE);
        let q_config = cohort_config(&q_endorsers).expect("freshly sorted endorsers are valid");

        // Finalize the first FOR_P endorsers toward P and the remainder toward Q.
        let finalized: Vec<_> = active
            .into_iter()
            .enumerate()
            .map(|(i, e): (usize, Endorser<Active>)| {
                e.finalize(if i < FOR_P { &p_config } else { &q_config })
            })
            .collect();

        // Each successor only sees the receipts of the endorsers that chose it.
        let entries = |toward_p: bool| -> Vec<EndorserFinalization> {
            finalized
                .iter()
                .enumerate()
                .map(|(i, e)| EndorserData {
                    endorser_key: *e.verifying_key(),
                    maybe_receipt: ((i < FOR_P) == toward_p).then(|| *e.finalization_receipt()),
                })
                .collect()
        };
        let p_entries = entries(true);
        let q_entries = entries(false);

        let ledgers = finalized[0].ledgers().clone();
        let ledgers_hash = ledgers.hash();

        let p_takeover = must_takeover_from(instance_id, &p_entries, &ledgers);
        let p_active = must_activate_all_with_takeover(p_endorsers, &p_config, &p_takeover);
        let p_handover = must_handover_from(&p_entries, &p_active, ledgers_hash);

        // Q lacks a finalization quorum so takeover activation fails; activate fresh instead.
        let q_takeover = must_takeover_from(instance_id, &q_entries, &ledgers);
        let q_active: Vec<Endorser<Active>> = q_endorsers
            .into_iter()
            .map(|e| {
                let e = match e.activate(q_config.clone(), Some(q_takeover.clone())) {
                    Ok(_) => panic!("a minority takeover must never activate an endorser"),
                    Err(error) => error.reclaim_endorser(),
                };
                e.activate(q_config.clone(), None)
                    .unwrap_or_else(|_| panic!("starting a fresh instance must succeed"))
            })
            .collect();
        let q_handover = must_handover_from(&q_entries, &q_active, ledgers_hash);

        let nonce_a = 0xAAAA;
        let from_p = must_read_latest_from(&p_active, &successor_all, LEDGER, nonce_a);
        let nonce_b = 0xBBBB;
        let from_q = must_read_latest_from(&q_active, &successor_all, LEDGER, nonce_b);

        (
            View {
                handovers: vec![p_handover],
                receipts: from_p.read,
                ledger_id: LEDGER,
                verification: Verification::ReadLatest { nonce: nonce_a },
            },
            View {
                handovers: vec![q_handover],
                receipts: from_q.read,
                ledger_id: LEDGER,
                verification: Verification::ReadLatest { nonce: nonce_b },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::{run, Outcome, WhichView};
    use logcabin_verifier::HandoverError;

    #[test]
    fn only_one_successor_can_gather_a_finalization_quorum() {
        let outcome = run(DivergentHandover);
        match outcome {
            Outcome::HandoverRejected {
                which: WhichView::B,
                position: 0,
                error: HandoverError::FinalizationQuorumNotMet(quorum),
            } => {
                assert_eq!(quorum.valid, COHORT_SIZE - FOR_P);
                assert_eq!(quorum.required, FOR_P);
            }
            other => panic!("expected view B's handover to be rejected, got {other:?}"),
        }
    }
}
