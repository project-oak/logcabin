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

//! Protocol integration tests exercising the endorser core and verifier
//! together.
//!
//! These tests create endorser cohorts, perform ledger operations, and verify
//! the resulting receipts through the verifier — validating the end-to-end
//! protocol contract.
//!
//! In an actual deployment, verifier and endorser never talk directly to each
//! other - a verifier interacts with a LogCabin service via a coordinator,
//! through protobuf services. These tests cut away all the middleware to test
//! the raw protocol.

use logcabin_base::{CohortConfig, EndorserData};
use logcabin_endorser_core::{Active, CohortFinalization, CohortTakeOver, Endorser, Uninitialized};
use logcabin_verifier::{CohortHandover, LedgerReceipt, LedgerReceipts, Verifier};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates `n` new endorsers, sorted by public key, and their cohort config.
///
/// Sorting endorsers by SEC1-compressed key ensures that each endorser's
/// positional index matches its key index in the config.
fn create_endorsers(n: usize) -> (Vec<Endorser<Uninitialized>>, CohortConfig) {
    let mut endorsers: Vec<_> = (0..n).map(|_| Endorser::new()).collect();
    endorsers.sort_by(|a, b| {
        a.verifying_key()
            .to_sec1_bytes()
            .as_ref()
            .cmp(b.verifying_key().to_sec1_bytes().as_ref())
    });
    let config = CohortConfig::try_from_keys(endorsers.iter().map(|e| *e.verifying_key())).unwrap();
    (endorsers, config)
}

/// Collects read_latest receipts from all endorsers into a `LedgerReceipts`.
fn read_latest_from_cohort(
    endorsers: &[Endorser<Active>],
    ledger_id: u32,
    nonce: u64,
) -> LedgerReceipts {
    let receipts: Vec<_> = endorsers
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let signed = e.read_latest(ledger_id, nonce).unwrap();
            LedgerReceipt {
                key_index: i, // Endorsers have the same order as config keys.
                block: signed.block.clone(),
                signature: signed.signature,
            }
        })
        .collect();
    LedgerReceipts::new(receipts)
}

/// Collects append_entry receipts from all endorsers into a `LedgerReceipts`.
///
/// Calls `append_entry` on each endorser and wraps the returned signature
/// with the resulting block (obtained via a subsequent `read_latest`).
fn append_to_cohort(
    endorsers: &mut [Endorser<Active>],
    ledger_id: u32,
    entry: [u8; 32],
    expected_index: u64,
) -> LedgerReceipts {
    let receipts: Vec<_> = endorsers
        .iter_mut()
        .enumerate()
        .map(|(i, e)| {
            let signature = e.append_entry(ledger_id, entry, expected_index).unwrap();
            // Read back the block to get the full state after append.
            // TODO: b/476380752 - Review what append_entry returns to avoid
            // requiring read-after-write.
            let signed = e.read_latest(ledger_id, 0).unwrap();
            LedgerReceipt {
                key_index: i, // Endorsers have the same order as config keys.
                block: signed.block.clone(),
                signature,
            }
        })
        .collect();
    LedgerReceipts::new(receipts)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TODO: b/476380752 - Add numerous integration tests here.

/// Creates an initial cohort, appends an entry, verifies the append, then
/// reads the latest entry and verifies the read.
#[test]
fn verify_with_initial_cohort() {
    // Create and activate a 3-endorser cohort.
    let (endorsers, config) = create_endorsers(3);

    let mut active: Vec<_> = endorsers
        .into_iter()
        .map(|e| e.activate(config.clone(), None).unwrap())
        .collect();

    let verifier = Verifier::new(config.clone());
    let ledger_id = 0;

    // Append an entry and verify.
    let entry = [0xAAu8; 32];
    let append_receipts = append_to_cohort(&mut active, ledger_id, entry, 1);
    let append_block = verifier
        .verify_append(&append_receipts, 1, ledger_id)
        .expect("append verification should succeed");
    assert_eq!(append_block.entry, entry);
    assert_eq!(append_block.index, 1);

    // Read latest and verify.
    let nonce = 42;
    let read_receipts = read_latest_from_cohort(&active, ledger_id, nonce);
    let read_block = verifier
        .verify_read_latest(&read_receipts, nonce, ledger_id)
        .expect("read_latest verification should succeed");
    assert_eq!(read_block.entry, entry);
    assert_eq!(read_block.index, 1);
}

/// Creates cohort 1, appends an entry, hands over to cohort 2, evolves the
/// verifier, then verifies read_latest from the new cohort.
#[test]
fn verify_after_handover() {
    // -----------------------------------------------------------------------
    // Step 1: Create and activate Cohort 1 (3 endorsers).
    // -----------------------------------------------------------------------
    let (c1_endorsers, c1_config) = create_endorsers(3);

    let mut c1_active: Vec<_> = c1_endorsers
        .into_iter()
        .map(|e| e.activate(c1_config.clone(), None).unwrap())
        .collect();

    let mut verifier = Verifier::new(c1_config.clone());

    // -----------------------------------------------------------------------
    // Step 2: Append an entry on all endorsers.
    // -----------------------------------------------------------------------
    let entry = [0xBBu8; 32];
    let _ = append_to_cohort(&mut c1_active, 0, entry, 1);

    // -----------------------------------------------------------------------
    // Step 3: Finalize cohort 1, activate cohort 2.
    // -----------------------------------------------------------------------
    let (c2_endorsers, c2_config) = create_endorsers(2);

    // Finalize all cohort 1 endorsers.
    let finalized: Vec<_> = c1_active
        .into_iter()
        .map(|e| e.finalize(&c2_config))
        .collect();

    let instance_id = c1_config.config_id();
    let endorser_finalizations: Vec<_> = finalized
        .iter()
        .map(|e| EndorserData {
            endorser_key: *e.verifying_key(),
            maybe_receipt: Some(*e.finalization_receipt()),
        })
        .collect();

    let handed_over_ledgers = finalized[0].ledgers();
    let cohort_takeover = CohortTakeOver::new(
        instance_id,
        CohortFinalization::try_new(endorser_finalizations.clone()).unwrap(),
        handed_over_ledgers.clone(),
    );

    // Activate cohort 2 endorsers.
    let c2_active: Vec<_> = c2_endorsers
        .into_iter()
        .map(|e| {
            e.activate(c2_config.clone(), Some(cohort_takeover.clone()))
                .unwrap()
        })
        .collect();

    // -----------------------------------------------------------------------
    // Step 4: Evolve the verifier via handover.
    // -----------------------------------------------------------------------
    let ledgers_hash = handed_over_ledgers.hash();

    // Build verifier-side activation entries.
    let v_act_entries: Vec<_> = c2_active
        .iter()
        .map(|e| EndorserData {
            endorser_key: *e.verifying_key(),
            maybe_receipt: Some(*e.activation_receipt()),
        })
        .collect();

    // Build a CohortHandover bundling finalization, activation, and ledgers hash.
    let handover =
        CohortHandover::try_new(endorser_finalizations.clone(), v_act_entries, ledgers_hash)
            .unwrap();

    verifier
        .apply_handover(handover)
        .expect("handover should succeed");

    // Verify the verifier now trusts cohort 2.
    assert!(verifier.trusted_config().keys().eq(c2_config.keys()));

    // -----------------------------------------------------------------------
    // Step 5: Verify read_latest from cohort 2.
    // -----------------------------------------------------------------------
    let nonce = 99;
    let read_receipts = read_latest_from_cohort(&c2_active, 0, nonce);
    let read_block = verifier
        .verify_read_latest(&read_receipts, nonce, 0)
        .expect("read_latest from new cohort should verify");
    assert_eq!(read_block.entry, entry);
    assert_eq!(read_block.index, 1);
}
