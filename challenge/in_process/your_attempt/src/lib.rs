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

//! Starter crate for a split-view challenge attempt.
//!
//! Implement [`YourAttempt::attempt`], remove `#[ignore]` from the test below,
//! and run `just challenge`. Helpers are in [`logcabin_challenge::util`].
//!
//! The initial cohort is 3 endorsers unless you override [`Falsifier::cohort_size`].

#![forbid(unsafe_code)]

use logcabin_challenge::{Falsifier, View};
use logcabin_endorser_core::{Endorser, Uninitialized};

pub struct YourAttempt;

impl Falsifier for YourAttempt {
    fn attempt(self, _endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        unimplemented!("build two conflicting-but-verifiable views")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logcabin_challenge::run;

    #[test]
    #[ignore = "implement YourAttempt::attempt, then remove this attribute"]
    fn your_attempt_wins() {
        let outcome = run(YourAttempt);
        assert!(outcome.is_split_view(), "{outcome:?}");
    }
}
