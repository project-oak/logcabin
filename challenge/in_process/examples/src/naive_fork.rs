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

//! Appends `0xAA` to endorsers `[0, 1]` and `0xBB` to endorser `[2]` at index 1.
//!
//! Fails with [`VerifyError::QuorumNotMet`](logcabin_verifier::VerifyError::QuorumNotMet):
//! any two strict majorities of a cohort intersect, and each endorser signs at
//! most one entry per `(ledger_id, index)`.

use logcabin_challenge::util::{must_activate_all, must_append_to};
use logcabin_challenge::{cohort_config, Falsifier, Verification, View};
use logcabin_endorser_core::{Endorser, Uninitialized};

pub const LEDGER: u32 = 0;

pub struct NaiveFork;

impl Falsifier for NaiveFork {
    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let config = cohort_config(&endorsers).expect("the handed-in cohort is well formed");
        let mut active = must_activate_all(endorsers, &config);

        let nonce = 0x4444;
        let majority = must_append_to(&mut active, &[0, 1], LEDGER, [0xAA; 32], 1, nonce);
        let minority = must_append_to(&mut active, &[2], LEDGER, [0xBB; 32], 1, nonce);

        (
            View {
                handovers: Vec::new(),
                receipts: majority.append,
                ledger_id: LEDGER,
                verification: Verification::Append {
                    entry: [0xAA; 32],
                    nonce,
                },
            },
            View {
                handovers: Vec::new(),
                receipts: minority.append,
                ledger_id: LEDGER,
                verification: Verification::Append {
                    entry: [0xBB; 32],
                    nonce,
                },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::{run, Outcome, WhichView};
    use logcabin_verifier::VerifyError;

    #[test]
    fn the_minority_faction_cannot_reach_a_quorum() {
        let outcome = run(NaiveFork);
        match outcome {
            Outcome::ViewRejected {
                which: WhichView::B,
                error: VerifyError::QuorumNotMet(quorum),
            } => {
                assert_eq!(quorum.valid, 1);
                assert_eq!(quorum.required, 2);
            }
            other => panic!("expected view B to miss quorum, got {other:?}"),
        }
    }
}
