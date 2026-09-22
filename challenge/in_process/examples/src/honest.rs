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

//! End-to-end baseline: appends one entry across the cohort, then reads it back
//! two ways - a nonce-bound `read_latest` and a nonce-free `entry` lookup -
//! yielding [`Outcome::ViewsAgree`](logcabin_challenge::Outcome::ViewsAgree).

use logcabin_challenge::util::{
    all_indices, must_activate_all, must_append_to, must_read_latest_from,
};
use logcabin_challenge::{cohort_config, Falsifier, Verification, View};
use logcabin_endorser_core::{Endorser, Uninitialized};

pub const LEDGER: u32 = 0;

pub struct Honest;

impl Falsifier for Honest {
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let config = cohort_config(&endorsers).expect("the handed-in cohort is well formed");
        let n = endorsers.len();
        let all = all_indices(n);
        let mut active = must_activate_all(endorsers, &config);

        must_append_to(&mut active, &all, LEDGER, [0xAA; 32], 1, 0x1111);

        let first = must_read_latest_from(&active, &all, LEDGER, 0x2222);
        let second = must_read_latest_from(&active, &all, LEDGER, 0x3333);

        (
            View {
                handovers: Vec::new(),
                receipts: first.read,
                ledger_id: LEDGER,
                verification: Verification::ReadLatest { nonce: 0x2222 },
            },
            View {
                handovers: Vec::new(),
                receipts: second.entry,
                ledger_id: LEDGER,
                verification: Verification::Entry { requested_index: 1 },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::{run, Outcome};

    #[test]
    fn honest_views_agree() {
        let outcome = run(Honest);
        assert!(matches!(outcome, Outcome::ViewsAgree), "{outcome:?}");
    }
}
