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

//! Compares a view from the initial cohort with a view from its successor cohort
//! after handover.
//!
//! Yields [`Outcome::ViewsAgree`](logcabin_challenge::Outcome::ViewsAgree):
//! [`Verifier::apply_handover`](logcabin_verifier::Verifier::apply_handover)
//! requires a finalization quorum over the inherited ledger state hash, so the
//! successor cohort preserves committed state.

use logcabin_challenge::util::{
    all_indices, must_activate_all, must_append_to, must_create_ledger_on,
    must_hand_over_to_fresh_cohort, must_read_latest_from,
};
use logcabin_challenge::{cohort_config, Falsifier, Verification, View};
use logcabin_endorser_core::{Endorser, Uninitialized};

pub const LEDGER: u32 = 42;

pub struct CrossCohortFork;

impl Falsifier for CrossCohortFork {
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let config = cohort_config(&endorsers).expect("the handed-in cohort is well formed");
        let instance_id = config.config_id();
        let n = endorsers.len();
        let all = all_indices(n);
        let mut active = must_activate_all(endorsers, &config);

        must_create_ledger_on(&mut active, LEDGER);
        must_append_to(&mut active, &all, LEDGER, [0xAA; 32], 1, 0x1111);

        let nonce_a = 0x5555;
        let from_genesis = must_read_latest_from(&active, &all, LEDGER, nonce_a);

        let succession = must_hand_over_to_fresh_cohort(active, instance_id, n);

        let nonce_b = 0x6666;
        let from_successor = must_read_latest_from(&succession.successor, &all, LEDGER, nonce_b);

        (
            View {
                handovers: Vec::new(),
                receipts: from_genesis.read,
                ledger_id: LEDGER,
                verification: Verification::ReadLatest { nonce: nonce_a },
            },
            View {
                handovers: vec![succession.handover],
                receipts: from_successor.read,
                ledger_id: LEDGER,
                verification: Verification::ReadLatest { nonce: nonce_b },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::{run, Outcome};

    #[test]
    fn a_successor_cohort_inherits_committed_state() {
        let outcome = run(CrossCohortFork);
        assert!(matches!(outcome, Outcome::ViewsAgree), "{outcome:?}");
    }
}
