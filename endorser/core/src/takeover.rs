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

//! Cohort takeover: structures for the case where a cohort activates by
//! taking an instance identity over from a presvious, finalized cohort.

use p256::ecdsa::signature::Verifier;

use crate::ledger::Ledgers;
use logcabin_base::{receipts, CohortConfig, CohortFinalization, ConfigId, EndorserFinalization};

/// Complete takeover data from a previous cohort, needed to activate a new
/// endorser via reconfiguration.
///
/// Combines finalization receipts from the previous cohort with the instance
/// ID and ledger state. The endorser finalization entries are guaranteed to
/// have keys in strict ascending SEC1-lexicographic order.
///
/// Construct via [`CohortTakeOver::new`].
///
/// Used as an argument to [`Endorser::activate`](crate::Endorser::activate):
/// when `Some(CohortTakeOver)` is provided the endorser adopts the finalized
/// state; when `None` the endorser starts a fresh instance.
#[derive(Clone)]
pub struct CohortTakeOver {
    /// The instance_id inherited from the previous cohort. Exactly 32 bytes.
    pub(crate) instance_id: ConfigId,
    /// Finalization receipts from each endorser in the previous cohort.
    /// Keys are in strict ascending SEC1-lexicographic order.
    cohort_finalization: CohortFinalization,
    /// The complete state of all ledgers at finalization.
    pub(crate) ledgers: Ledgers,
}

impl CohortTakeOver {
    /// Creates a new `CohortTakeOver` from a pre-validated
    /// [`CohortFinalization`] (which guarantees endorser keys are in strict
    /// ascending SEC1-lexicographic order), an instance ID, and ledger state.
    pub fn new(
        instance_id: ConfigId,
        cohort_finalization: CohortFinalization,
        ledgers: Ledgers,
    ) -> Self {
        Self {
            instance_id,
            cohort_finalization,
            ledgers,
        }
    }

    /// Returns the endorser finalization entries.
    pub fn endorser_finalizations(&self) -> &[EndorserFinalization] {
        self.cohort_finalization.endorsers()
    }

    /// Returns the config ID of the finalized (previous) cohort.
    pub fn prev_config_id(&self) -> ConfigId {
        self.cohort_finalization.config_id()
    }

    /// Decomposes the takeover into its parts: instance ID, previous cohort
    /// finalization, and ledger state.
    pub fn into_parts(self) -> (ConfigId, CohortFinalization, Ledgers) {
        (self.instance_id, self.cohort_finalization, self.ledgers)
    }

    /// Verifies the finalization receipts in favour of `new_cohort_config`.
    ///
    /// Reconstructs the expected finalization message and verifies each receipt
    /// signature against the corresponding endorser's verifying key. A receipt
    /// is counted as valid only if it cryptographically verifies.
    ///
    /// Returns `true` if a strict majority of receipts are valid.
    pub fn verify(&self, new_cohort_config: &CohortConfig) -> bool {
        let expected_message = receipts::build_finalize_message(
            &self.instance_id,
            &self.prev_config_id(),
            &new_cohort_config.config_id(),
            &self.ledgers.hash(),
        );

        let valid_count =
            self.cohort_finalization
                .endorsers()
                .iter()
                .filter(|entry| {
                    entry.maybe_receipt.as_ref().is_some_and(|sig| {
                        entry.endorser_key.verify(&expected_message, sig).is_ok()
                    })
                })
                .count();

        valid_count * 2 > self.cohort_finalization.len()
    }
}
