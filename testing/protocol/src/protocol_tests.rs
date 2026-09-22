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

use logcabin_base::{CohortConfig, CohortFinalization, EndorserData, EntryContents};
use logcabin_endorser_core::{Active, CohortTakeOver, Endorser, Uninitialized};
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

/// Returns a non-zero nonce for testing.
fn nonce() -> u64 {
    0xDEAD_BEEF_CAFE_BABEu64
}

/// Both receipt collections produced by a `read_latest` across a cohort.
///
/// An endorser returns two receipts per read: a nonce-bound read receipt
/// (prefix `"read_latest"`) proving freshness, and a nonce-free entry receipt
/// (prefix `"entry"`) that the coordinator may store and serve later.
struct CohortReadReceipts {
    /// Nonce-bound receipts, verified with [`Verifier::verify_read_latest`].
    read: LedgerReceipts,
    /// Timeless receipts, verified with [`Verifier::verify_entry`].
    entry: LedgerReceipts,
}

/// Both receipt collections produced by an `append_entry` across a cohort.
///
/// An endorser returns two receipts per append: a nonce-bound append receipt
/// (prefix `"append_entry"`) proving the operation was performed, and a
/// nonce-free entry receipt (prefix `"entry"`) that the coordinator may store
/// and serve later.
struct CohortAppendReceipts {
    /// Nonce-bound receipts, verified with [`Verifier::verify_append`].
    append: LedgerReceipts,
    /// Timeless receipts, verified with [`Verifier::verify_entry`].
    entry: LedgerReceipts,
}

/// Calls `read_latest` on every endorser, collecting both receipt sets.
fn read_latest_from_cohort(
    endorsers: &[Endorser<Active>],
    ledger_id: u32,
    nonce: u64,
) -> CohortReadReceipts {
    let results: Vec<_> = endorsers
        .iter()
        .map(|e| e.read_latest(ledger_id, nonce).unwrap())
        .collect();

    // Endorsers have the same order as config keys, so the positional index
    // is the key index.
    let read_receipts =
        LedgerReceipts::new(results.iter().enumerate().map(|(i, r)| LedgerReceipt {
            key_index: i,
            block: r.block.clone(),
            signature: r.read_receipt,
        }));
    let entry_receipts =
        LedgerReceipts::new(results.iter().enumerate().map(|(i, r)| LedgerReceipt {
            key_index: i,
            block: r.block.clone(),
            signature: r.entry_receipt,
        }));

    CohortReadReceipts {
        read: read_receipts,
        entry: entry_receipts,
    }
}

/// Calls `append_entry` on every endorser, collecting both receipt sets.
fn append_to_cohort(
    endorsers: &mut [Endorser<Active>],
    ledger_id: u32,
    entry: EntryContents,
    expected_index: u64,
    nonce: u64,
) -> CohortAppendReceipts {
    let results: Vec<_> = endorsers
        .iter_mut()
        .map(|e| {
            e.append_entry(ledger_id, entry, expected_index, nonce)
                .unwrap()
        })
        .collect();

    // Endorsers have the same order as config keys, so the positional index
    // is the key index.
    let append_receipts =
        LedgerReceipts::new(results.iter().enumerate().map(|(i, r)| LedgerReceipt {
            key_index: i,
            block: r.block.clone(),
            signature: r.append_receipt,
        }));
    let entry_receipts =
        LedgerReceipts::new(results.iter().enumerate().map(|(i, r)| LedgerReceipt {
            key_index: i,
            block: r.block.clone(),
            signature: r.entry_receipt,
        }));

    CohortAppendReceipts {
        append: append_receipts,
        entry: entry_receipts,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Creates an initial cohort, appends an entry, then reads it back, verifying
/// every receipt set the protocol produces.
///
/// An append yields two receipt sets (nonce-bound append, timeless entry) and
/// so does a read (nonce-bound read, timeless entry). This test verifies all
/// four independently and asserts they describe the same ledger block.
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

    // ----------------------------------------------------------------------
    // Append an entry; verify both receipt sets it produces.
    // ----------------------------------------------------------------------
    let entry = [0xAAu8; 32];
    let append_nonce = nonce();
    let appended = append_to_cohort(&mut active, ledger_id, entry, 1, append_nonce);

    let append_block = verifier
        .verify_append(&appended.append, &entry, append_nonce, ledger_id)
        .expect("nonce-bound append receipts should verify");
    let append_entry_block = verifier
        .verify_entry(&appended.entry, 1, ledger_id)
        .expect("timeless entry receipts from append should verify");

    assert_eq!(append_block.entry, entry);
    assert_eq!(append_block.index, 1);
    assert_eq!(
        append_block, append_entry_block,
        "both receipt sets from the append must describe the same block"
    );

    // ----------------------------------------------------------------------
    // Read the entry back; verify both receipt sets it produces.
    // ----------------------------------------------------------------------
    let read_nonce = 42;
    let read = read_latest_from_cohort(&active, ledger_id, read_nonce);

    let read_block = verifier
        .verify_read_latest(&read.read, read_nonce, ledger_id)
        .expect("nonce-bound read receipts should verify");
    let read_entry_block = verifier
        .verify_entry(&read.entry, 1, ledger_id)
        .expect("timeless entry receipts from read should verify");

    assert_eq!(
        read_block, read_entry_block,
        "both receipt sets from the read must describe the same block"
    );

    // ----------------------------------------------------------------------
    // All four receipt sets must agree on the ledger state.
    // ----------------------------------------------------------------------
    assert_eq!(
        append_block, read_block,
        "append and read receipts must describe the same block"
    );
}

/// Exercises the nonce-bound receipt from append_entry: appends with a nonce,
/// collects the nonce-bound receipts, and verifies they are accepted by
/// verify_append but rejected by verify_read_latest.
///
/// This is the core security property: a coordinator cannot substitute a
/// read_latest call for an append_entry call, because the signed prefixes
/// differ ("append_entry" vs "read_latest").
#[test]
fn verify_append_receipt_prefix_separation() {
    let (endorsers, config) = create_endorsers(3);
    let mut active: Vec<_> = endorsers
        .into_iter()
        .map(|e| e.activate(config.clone(), None).unwrap())
        .collect();

    let verifier = Verifier::new(config.clone());
    let ledger_id = 0;
    let entry = [0xBBu8; 32];
    let append_nonce: u64 = 0x1234_5678_9ABC_DEF0;

    let appended = append_to_cohort(&mut active, ledger_id, entry, 1, append_nonce);

    // 1. The append receipts should verify with verify_append.
    let block = verifier
        .verify_append(&appended.append, &entry, append_nonce, ledger_id)
        .expect("append receipt should verify with verify_append");
    assert_eq!(block.entry, entry);
    assert_eq!(block.index, 1);

    // 2. The same receipts must NOT verify as read_latest receipts.
    //    This is the key security property: different prefixes prevent substitution.
    assert!(
        verifier
            .verify_read_latest(&appended.append, append_nonce, ledger_id)
            .is_err(),
        "append receipt must not verify as read_latest (different prefix)"
    );

    // 3. Nor may they be replayed as timeless entry receipts.
    assert!(
        verifier
            .verify_entry(&appended.append, 1, ledger_id)
            .is_err(),
        "append receipt must not verify as an entry receipt (different prefix)"
    );

    // 4. A different nonce should also fail.
    let wrong_nonce: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    assert!(
        verifier
            .verify_append(&appended.append, &entry, wrong_nonce, ledger_id)
            .is_err(),
        "append receipt should not verify with a different nonce"
    );

    // 5. A different entry must be rejected, even with the right nonce. This
    //    is what stops a coordinator from appending a value other than the
    //    one the client requested.
    let other_entry = [0xCCu8; 32];
    assert!(
        verifier
            .verify_append(&appended.append, &other_entry, append_nonce, ledger_id)
            .is_err(),
        "append receipt should not verify against an entry the client never requested"
    );
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
    let _ = append_to_cohort(&mut c1_active, 0, entry, 1, nonce());

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
    // Step 5: Verify read_latest from cohort 2, both receipt sets.
    // -----------------------------------------------------------------------
    let read_nonce = 99;
    let read = read_latest_from_cohort(&c2_active, 0, read_nonce);

    let read_block = verifier
        .verify_read_latest(&read.read, read_nonce, 0)
        .expect("read_latest from new cohort should verify");
    let read_entry_block = verifier
        .verify_entry(&read.entry, 1, 0)
        .expect("entry receipts from new cohort should verify");

    assert_eq!(read_block.entry, entry);
    assert_eq!(read_block.index, 1);
    assert_eq!(
        read_block, read_entry_block,
        "both receipt sets from the new cohort must describe the same block"
    );
}
