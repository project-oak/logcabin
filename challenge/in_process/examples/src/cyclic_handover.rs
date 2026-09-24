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

//! Attempt: cyclic cohort handover `C1 -> C2 -> C1` (`H021` / `H100`).
//!
//! `CohortHandover::verify` (`verifier/rust/src/handover.rs:174`) does not
//! explicitly prohibit cyclic cohort transitions (`C1 -> C2 -> C1`). This
//! example tests two ways an attacker might try to exploit a return cycle back
//! to `C1`:
//!
//! 1. [`CyclicHandoverGenesisReplay`]: Reusing `C1`'s original genesis
//!    `activation_receipt`s (`"activate_new_instance"`) as takeover activation
//!    receipts for `C2 -> C1`. Stopped by domain separation in
//!    `CohortHandover::verify` (`"activate"` vs `"activate_new_instance"`,
//!    yielding `valid: 0, required: 2`).
//! 2. [`CyclicHandoverHeldBackEndorser`]: Activating only a 2-of-3 quorum
//!    (`[e0, e1]`) of `C1` at genesis while holding back `e2` as
//!    `Endorser<Uninitialized>` until `C2` finalizes back toward `C1`. `e2`
//!    genuinely activates from `C2`'s takeover and produces 1 valid
//!    `"activate"` receipt for `C2 -> C1` (`valid: 1`), but because `e0` and
//!    `e1` were linearly consumed at genesis, at most $N - M < M$ endorsers
//!    remain available for the return cycle (`valid: 1, required: 2`).

use logcabin_base::EndorserData;
use logcabin_challenge::util::{
    finalize_all_toward, must_activate_all, must_append_to, must_hand_over_to_fresh_cohort,
    must_handover_from, must_takeover_from,
};
use logcabin_challenge::{cohort_config, new_sorted_endorsers, Falsifier, Verification, View};
use logcabin_endorser_core::{Active, Endorser, Finalized, Uninitialized};
use logcabin_verifier::{CohortHandover, EndorserActivation, LedgerReceipt, LedgerReceipts};

const LEDGER: u32 = 0;

/// Replays `C1`'s genesis activation receipts in a cyclic `C1 -> C2 -> C1` handover.
pub struct CyclicHandoverGenesisReplay;

impl Falsifier for CyclicHandoverGenesisReplay {
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let c1_config = cohort_config(&endorsers).expect("valid genesis config");
        let instance_id = c1_config.config_id();

        let mut c1 = must_activate_all(endorsers, &c1_config);

        let c1_genesis_activations: Vec<EndorserActivation> = c1
            .iter()
            .map(|e| EndorserData {
                endorser_key: *e.verifying_key(),
                maybe_receipt: Some(*e.activation_receipt()),
            })
            .collect();

        let append_a = must_append_to(&mut c1, &[0, 1], LEDGER, [0xAA; 32], 1, 0x1001);

        let view_a = View {
            handovers: Vec::new(),
            receipts: append_a.append,
            ledger_id: LEDGER,
            verification: Verification::Append {
                entry: [0xAA; 32],
                nonce: 0x1001,
            },
        };

        let succession = must_hand_over_to_fresh_cohort(c1, instance_id, 3);
        let c2_finalization = finalize_all_toward(succession.successor, &c1_config);

        let handover_c2_to_c1 = CohortHandover::try_new(
            c2_finalization.entries,
            c1_genesis_activations,
            c2_finalization.ledgers.hash(),
        )
        .expect("keys are in strict SEC1 order");

        let view_b = View {
            handovers: vec![succession.handover, handover_c2_to_c1],
            receipts: append_a.entry,
            ledger_id: LEDGER,
            verification: Verification::Entry { requested_index: 1 },
        };

        (view_a, view_b)
    }
}

/// Holds back `e2` (`Endorser<Uninitialized>`) at genesis so it can genuinely
/// activate via takeover for the return cycle `C2 -> C1` (`valid: 1, required: 2`).
pub struct CyclicHandoverHeldBackEndorser;

impl Falsifier for CyclicHandoverHeldBackEndorser {
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let c1_config = cohort_config(&endorsers).expect("valid genesis config");
        let instance_id = c1_config.config_id();

        let mut iter = endorsers.into_iter();
        let e0_uninit = iter.next().unwrap();
        let e1_uninit = iter.next().unwrap();
        let e2_uninit = iter.next().unwrap();
        let e2_key = *e2_uninit.verifying_key();

        let mut e0: Endorser<Active> = e0_uninit
            .activate(c1_config.clone(), None)
            .expect("e0 genesis activate");
        let mut e1: Endorser<Active> = e1_uninit
            .activate(c1_config.clone(), None)
            .expect("e1 genesis activate");

        let e0_genesis_act = EndorserData {
            endorser_key: *e0.verifying_key(),
            maybe_receipt: Some(*e0.activation_receipt()),
        };
        let e1_genesis_act = EndorserData {
            endorser_key: *e1.verifying_key(),
            maybe_receipt: Some(*e1.activation_receipt()),
        };

        let r0 = e0.append_entry(LEDGER, [0xAA; 32], 1, 0x2001).unwrap();
        let r1 = e1.append_entry(LEDGER, [0xAA; 32], 1, 0x2001).unwrap();
        let view_a_receipts = LedgerReceipts::new([
            LedgerReceipt {
                key_index: 0,
                block: r0.block.clone(),
                signature: r0.entry_receipt,
            },
            LedgerReceipt {
                key_index: 1,
                block: r1.block.clone(),
                signature: r1.entry_receipt,
            },
        ]);
        let view_b_receipts = LedgerReceipts::new([
            LedgerReceipt {
                key_index: 0,
                block: r0.block,
                signature: r0.entry_receipt,
            },
            LedgerReceipt {
                key_index: 1,
                block: r1.block,
                signature: r1.entry_receipt,
            },
        ]);

        let view_a = View {
            handovers: Vec::new(),
            receipts: view_a_receipts,
            ledger_id: LEDGER,
            verification: Verification::Entry { requested_index: 1 },
        };

        let c2_uninit = new_sorted_endorsers(3);
        let c2_config = cohort_config(&c2_uninit).unwrap();
        let e0_fin: Endorser<Finalized> = e0.finalize(&c2_config);
        let e1_fin: Endorser<Finalized> = e1.finalize(&c2_config);
        let c1_to_c2_entries = vec![
            EndorserData {
                endorser_key: *e0_fin.verifying_key(),
                maybe_receipt: Some(*e0_fin.finalization_receipt()),
            },
            EndorserData {
                endorser_key: *e1_fin.verifying_key(),
                maybe_receipt: Some(*e1_fin.finalization_receipt()),
            },
            EndorserData {
                endorser_key: e2_key,
                maybe_receipt: None,
            },
        ];
        let ledgers_at_c1_fin = e0_fin.ledgers().clone();
        let takeover_c1_to_c2 =
            must_takeover_from(instance_id, &c1_to_c2_entries, &ledgers_at_c1_fin);
        let c2_active: Vec<Endorser<Active>> = c2_uninit
            .into_iter()
            .map(|e| {
                e.activate(c2_config.clone(), Some(takeover_c1_to_c2.clone()))
                    .unwrap()
            })
            .collect();
        let handover_c1_to_c2 =
            must_handover_from(&c1_to_c2_entries, &c2_active, ledgers_at_c1_fin.hash());

        let c2_finalization = finalize_all_toward(c2_active, &c1_config);
        let takeover_c2_to_c1 = must_takeover_from(
            instance_id,
            &c2_finalization.entries,
            &c2_finalization.ledgers,
        );

        let e2_active = e2_uninit
            .activate(c1_config, Some(takeover_c2_to_c1))
            .expect("e2 genuinely activates from C2 takeover");
        let e2_takeover_act = EndorserData {
            endorser_key: *e2_active.verifying_key(),
            maybe_receipt: Some(*e2_active.activation_receipt()),
        };

        let handover_c2_to_c1 = CohortHandover::try_new(
            c2_finalization.entries,
            vec![e0_genesis_act, e1_genesis_act, e2_takeover_act],
            c2_finalization.ledgers.hash(),
        )
        .unwrap();

        let view_b = View {
            handovers: vec![handover_c1_to_c2, handover_c2_to_c1],
            receipts: view_b_receipts,
            ledger_id: LEDGER,
            verification: Verification::Entry { requested_index: 1 },
        };

        (view_a, view_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::{run, Outcome, WhichView};
    use logcabin_verifier::{HandoverError, QuorumError};

    #[test]
    fn cyclic_handover_genesis_replay_rejected() {
        let outcome = run(CyclicHandoverGenesisReplay);
        assert!(
            matches!(
                outcome,
                Outcome::HandoverRejected {
                    which: WhichView::B,
                    position: 1,
                    error: HandoverError::ActivationQuorumNotMet(QuorumError {
                        valid: 0,
                        required: 2,
                    }),
                }
            ),
            "unexpected outcome: {outcome:?}"
        );
    }

    #[test]
    fn cyclic_handover_held_back_endorser_rejected() {
        let outcome = run(CyclicHandoverHeldBackEndorser);
        assert!(
            matches!(
                outcome,
                Outcome::HandoverRejected {
                    which: WhichView::B,
                    position: 1,
                    error: HandoverError::ActivationQuorumNotMet(QuorumError {
                        valid: 1,
                        required: 2,
                    }),
                }
            ),
            "unexpected outcome: {outcome:?}"
        );
    }
}
