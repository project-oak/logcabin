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

//! Lifecycle integration tests for the endorser core crate.
//!
//! These tests exercise multi-endorser, multi-state workflows through the
//! public API only.

use logcabin_endorser_core::{
    CohortConfig, CohortFinalization, CohortTakeOver, Endorser, EndorserData, Uninitialized,
};
use p256::ecdsa::VerifyingKey;

/// Builds a `CohortConfig` from an unsorted list of verifying keys by
/// sorting them into canonical SEC1-lexicographic order.
fn sorted_config(mut keys: Vec<VerifyingKey>) -> CohortConfig {
    keys.sort_by(|a, b| a.to_sec1_bytes().as_ref().cmp(b.to_sec1_bytes().as_ref()));
    CohortConfig::try_from_keys(keys).unwrap()
}

/// Returns a non-zero nonce for testing.
fn nonce() -> u64 {
    0xDEAD_BEEF_CAFE_BABEu64
}

/// Creates `n` new endorsers and returns them with their verifying keys.
fn create_endorsers(n: usize) -> Vec<Endorser<Uninitialized>> {
    (0..n).map(|_| Endorser::new()).collect()
}

/// Test - successful handover: cohort 1 (3 endorsers) → cohort 2 (2 endorsers).
///
/// 1. Create and activate cohort 1 as a new instance.
/// 2. Perform some ledger operations (create + append).
/// 3. Finalize all endorsers in cohort 1, targeting cohort 2's config.
/// 4. Activate cohort 2 endorsers from previous cohort.
/// 5. Verify the new cohort can operate on the handed-over ledgers.
#[test]
fn cohort_handover_success() {
    // -----------------------------------------------------------------------
    // Step 1: Create and activate Cohort 1 (3 endorsers, new instance).
    // -----------------------------------------------------------------------
    let cohort_1_endorsers = create_endorsers(3);
    let cohort_1_vks: Vec<_> = cohort_1_endorsers
        .iter()
        .map(|e| *e.verifying_key())
        .collect();
    let cohort_1_config = sorted_config(cohort_1_vks.clone());

    let mut cohort_1_active: Vec<_> = cohort_1_endorsers
        .into_iter()
        .map(|e| e.activate(cohort_1_config.clone(), None).unwrap())
        .collect();

    // -----------------------------------------------------------------------
    // Step 2: Perform ledger operations on all endorsers (consistent state).
    // -----------------------------------------------------------------------
    let entry_a = [0xAAu8; 32];
    let entry_b = [0xBBu8; 32];

    for endorser in &mut cohort_1_active {
        // Create a second ledger (ledger 0 was created during activation).
        endorser.create_ledger(1).unwrap();

        // Append two entries to ledger 1.
        endorser.append_entry(1, entry_a, 1, nonce()).unwrap();
        endorser.append_entry(1, entry_b, 2, nonce()).unwrap();
    }

    // Verify all endorsers agree on ledger state.
    for endorser in &cohort_1_active {
        let block = endorser.read_latest(1, 42).unwrap();
        assert_eq!(block.entry, entry_b);
        assert_eq!(block.index, 2);
    }

    // -----------------------------------------------------------------------
    // Step 3: Create Cohort 2 (2 endorsers) and finalize Cohort 1.
    // -----------------------------------------------------------------------
    let cohort_2_endorsers = create_endorsers(2);
    let cohort_2_vks: Vec<_> = cohort_2_endorsers
        .iter()
        .map(|e| *e.verifying_key())
        .collect();
    let cohort_2_config = sorted_config(cohort_2_vks.clone());

    // Finalize all endorsers in cohort 1. Each returns a finalized endorser
    // with the receipt + ledger snapshot. All snapshots should be identical.
    let finalized_endorsers: Vec<_> = cohort_1_active
        .into_iter()
        .map(|e| e.finalize(&cohort_2_config))
        .collect();

    // Check: all endorsers returned the same ledger state.
    let reference_ledgers = finalized_endorsers[0].ledgers();
    for finalized in &finalized_endorsers[1..] {
        assert_eq!(
            finalized.ledgers().len(),
            reference_ledgers.len(),
            "all endorsers must have the same number of ledgers"
        );
        for (ledger_id, block) in reference_ledgers.iter() {
            let other_block = finalized
                .ledgers()
                .get(ledger_id)
                .expect("ledger must exist in all endorsers");
            assert_eq!(block.entry, other_block.entry);
            assert_eq!(block.index, other_block.index);
            assert_eq!(block.hash_chain_tail, other_block.hash_chain_tail);
        }
    }

    // -----------------------------------------------------------------------
    // Step 4: Build the CohortFinalization and activate Cohort 2.
    // -----------------------------------------------------------------------

    // The instance_id is the config_id of cohort 1 (since it was a new
    // instance). We compute it from the public keys.
    let instance_id = cohort_1_config.config_id();

    // Build the CohortFinalization from all finalized endorsers.
    let mut endorser_finalizations: Vec<_> = finalized_endorsers
        .iter()
        .map(|e| EndorserData {
            endorser_key: *e.verifying_key(),
            maybe_receipt: Some(*e.finalization_receipt()),
        })
        .collect();
    endorser_finalizations.sort_by(|a, b| {
        a.endorser_key
            .to_sec1_bytes()
            .as_ref()
            .cmp(b.endorser_key.to_sec1_bytes().as_ref())
    });

    // Use the ledger snapshot from the first endorser (all are identical).
    let handed_over_ledgers = finalized_endorsers[0].ledgers().clone();

    let cohort_takeover = CohortTakeOver::new(
        instance_id,
        CohortFinalization::try_new(endorser_finalizations).unwrap(),
        handed_over_ledgers,
    );

    // Activate all cohort 2 endorsers via cohort takeover.
    let mut cohort_2_active: Vec<_> = cohort_2_endorsers
        .into_iter()
        .map(|e| {
            e.activate(cohort_2_config.clone(), Some(cohort_takeover.clone()))
                .expect("cohort 2 endorser should activate via cohort takeover")
        })
        .collect();

    // -----------------------------------------------------------------------
    // Step 5: Verify Cohort 2 can operate on handed-over ledgers.
    // -----------------------------------------------------------------------
    for active in &cohort_2_active {
        let block_0 = active.read_latest(0, 100).unwrap();
        assert_eq!(block_0.index, 0, "ledger 0 should have index 0");

        let block_1 = active.read_latest(1, 100).unwrap();
        assert_eq!(
            block_1.entry, entry_b,
            "ledger 1 should have the last appended entry"
        );
        assert_eq!(block_1.index, 2, "ledger 1 should have index 2");

        assert_eq!(active.ledger_count(), 2, "should have 2 ledgers: 0 and 1");
    }

    // Each endorser can continue appending to handed-over ledgers.
    let entry_c = [0xCCu8; 32];
    for active in &mut cohort_2_active {
        active
            .append_entry(1, entry_c, 3, nonce())
            .expect("should be able to append to handed-over ledger");

        let block_after = active.read_latest(1, 200).unwrap();
        assert_eq!(block_after.entry, entry_c);
        assert_eq!(block_after.index, 3);

        active.create_ledger(99).unwrap();
        assert_eq!(active.ledger_count(), 3, "should have 3 ledgers: 0, 1, 99");
    }
}
