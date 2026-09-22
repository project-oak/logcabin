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

//! Hands over to a challenger-created cohort and appends a new entry.
//!
//! Fails with [`NotAForkReason::DifferentIndex`](logcabin_challenge::NotAForkReason::DifferentIndex):
//! the verifier performs no attestation check, so the handover is accepted, but
//! finalization pins the inherited ledger state at index 1, and the new block
//! lands at index 2 rather than competing at index 1.

use logcabin_challenge::util::{
    all_indices, must_activate_all, must_append_to, must_hand_over_to_fresh_cohort,
    must_read_latest_from,
};
use logcabin_challenge::{cohort_config, Falsifier, Verification, View};
use logcabin_endorser_core::{Endorser, Uninitialized};

pub const LEDGER: u32 = 0;

pub struct RogueCohort;

impl Falsifier for RogueCohort {
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let config = cohort_config(&endorsers).expect("the handed-in cohort is well formed");
        let instance_id = config.config_id();
        let n = endorsers.len();
        let all = all_indices(n);
        let mut active = must_activate_all(endorsers, &config);

        must_append_to(&mut active, &all, LEDGER, [0xAA; 32], 1, 0x1111);

        let nonce_a = 0x7777;
        let honest = must_read_latest_from(&active, &all, LEDGER, nonce_a);

        let mut succession = must_hand_over_to_fresh_cohort(active, instance_id, n);

        must_append_to(
            &mut succession.successor,
            &all,
            LEDGER,
            [0xBB; 32],
            2,
            0x8888,
        );

        let nonce_b = 0x9999;
        let rogue = must_read_latest_from(&succession.successor, &all, LEDGER, nonce_b);

        (
            View {
                handovers: Vec::new(),
                receipts: honest.read,
                ledger_id: LEDGER,
                verification: Verification::ReadLatest { nonce: nonce_a },
            },
            View {
                handovers: vec![succession.handover],
                receipts: rogue.read,
                ledger_id: LEDGER,
                verification: Verification::ReadLatest { nonce: nonce_b },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::{run, NotAForkReason, Outcome};

    #[test]
    fn a_rogue_cohort_can_only_extend_the_chain() {
        let outcome = run(RogueCohort);
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
