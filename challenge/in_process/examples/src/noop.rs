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

//! Minimal example returning empty receipts; rejected with [`VerifyError::NoReceipts`].

use logcabin_challenge::{Falsifier, Verification, View};
use logcabin_endorser_core::{Endorser, Uninitialized};
use logcabin_verifier::LedgerReceipts;

pub struct Noop;

impl Falsifier for Noop {
    fn attempt(self, _endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let empty = || View {
            handovers: Vec::new(),
            receipts: LedgerReceipts::new([]),
            ledger_id: 0,
            verification: Verification::ReadLatest { nonce: 1 },
        };
        (empty(), empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::{run, Outcome, WhichView};
    use logcabin_verifier::VerifyError;

    #[test]
    fn empty_views_are_rejected() {
        let outcome = run(Noop);
        assert!(
            matches!(
                outcome,
                Outcome::ViewRejected {
                    which: WhichView::A,
                    error: VerifyError::NoReceipts,
                }
            ),
            "{outcome:?}"
        );
    }
}
