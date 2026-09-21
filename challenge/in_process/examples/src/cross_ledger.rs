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

//! Appends different entries to two distinct ledgers at index 1.
//!
//! Fails with [`NotAForkReason::DifferentLedger`](logcabin_challenge::NotAForkReason::DifferentLedger):
//! ledgers are independent, and receipt signatures commit to `ledger_id`.

use logcabin_challenge::util::{
    all_indices, must_activate_all, must_append_to, must_create_ledger_on, must_read_latest_from,
};
use logcabin_challenge::{cohort_config, Falsifier, Verification, View};
use logcabin_endorser_core::{Endorser, Uninitialized};

pub const LEDGER_A: u32 = 7;
pub const LEDGER_B: u32 = 9;

pub struct CrossLedger;

impl Falsifier for CrossLedger {
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let config = cohort_config(&endorsers).expect("the handed-in cohort is well formed");
        let all = all_indices(endorsers.len());
        let mut active = must_activate_all(endorsers, &config);

        must_create_ledger_on(&mut active, LEDGER_A);
        must_create_ledger_on(&mut active, LEDGER_B);

        must_append_to(&mut active, &all, LEDGER_A, [0xAA; 32], 1, 0x1111);
        must_append_to(&mut active, &all, LEDGER_B, [0xBB; 32], 1, 0x2222);

        let nonce_a = 0xCCCC;
        let from_a = must_read_latest_from(&active, &all, LEDGER_A, nonce_a);
        let nonce_b = 0xDDDD;
        let from_b = must_read_latest_from(&active, &all, LEDGER_B, nonce_b);

        (
            View {
                handovers: Vec::new(),
                receipts: from_a.read,
                ledger_id: LEDGER_A,
                verification: Verification::ReadLatest { nonce: nonce_a },
            },
            View {
                handovers: Vec::new(),
                receipts: from_b.read,
                ledger_id: LEDGER_B,
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
    fn different_ledgers_are_not_a_fork() {
        let outcome = run(CrossLedger);
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
}
