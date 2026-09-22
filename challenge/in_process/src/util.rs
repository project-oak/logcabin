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

//! Optional helper functions for driving endorsers in challenge attempts.
//!
//! Every fallible helper comes in two flavours: `foo` forwards the endorser's
//! error so an attempt can inspect it and try something else, and `must_foo`
//! panics on failure for the common case where the call is expected to succeed.
//!
//! All helpers assume and preserve SEC1 verifying-key order so that slice
//! indices match `key_index` in [`CohortConfig`].

use logcabin_base::{
    CohortConfig, CohortFinalization, ConfigId, EndorserData, EndorserFinalization, EntryContents,
    InvalidConfigError, Sha256Digest,
};
use logcabin_endorser_core::{
    ActivationError, Active, AppendEntryError, CohortTakeOver, CreateLedgerError, Endorser,
    Finalized, LedgerNotFoundError, Ledgers, Uninitialized,
};
use logcabin_verifier::{CohortHandover, LedgerReceipt, LedgerReceipts};

use crate::{cohort_config, new_sorted_endorsers};

/// Receipts collected from a `read_latest` call across a subset of endorsers.
#[derive(Debug)]
pub struct ReadReceipts {
    /// Nonce-bound `"read_latest"` receipts for [`Verification::ReadLatest`](crate::Verification::ReadLatest).
    pub read: LedgerReceipts,
    /// Nonce-free `"entry"` receipts for [`Verification::Entry`](crate::Verification::Entry).
    pub entry: LedgerReceipts,
}

/// Receipts collected from an `append_entry` call across a subset of endorsers.
#[derive(Debug)]
pub struct AppendReceipts {
    /// Nonce-bound `"append_entry"` receipts for [`Verification::Append`](crate::Verification::Append).
    pub append: LedgerReceipts,
    /// Nonce-free `"entry"` receipts for [`Verification::Entry`](crate::Verification::Entry).
    pub entry: LedgerReceipts,
}

/// Output of finalizing a cohort toward a successor config.
pub struct Finalization {
    pub finalized: Vec<Endorser<Finalized>>,
    pub entries: Vec<EndorserFinalization>,
    pub ledgers: Ledgers,
}

/// Result of handing over to a newly created cohort via [`hand_over_to_fresh_cohort`].
pub struct Succession {
    pub successor: Vec<Endorser<Active>>,
    pub handover: CohortHandover,
}

/// Error from [`hand_over_to_fresh_cohort`].
#[derive(Debug)]
pub enum SuccessionError {
    /// A cohort config, takeover or handover was malformed.
    InvalidConfig(InvalidConfigError),
    /// A successor endorser refused to activate from the takeover.
    Activation(ActivationError),
}

/// Activates all endorsers as an initial cohort (`takeover = None`).
///
/// On failure the remaining endorsers are dropped; only the offending one is
/// recoverable, via [`ActivationError::reclaim_endorser`].
pub fn activate_all(
    endorsers: Vec<Endorser<Uninitialized>>,
    config: &CohortConfig,
) -> Result<Vec<Endorser<Active>>, ActivationError> {
    endorsers
        .into_iter()
        .map(|e| e.activate(config.clone(), None))
        .collect()
}

/// [`activate_all`], panicking on failure.
pub fn must_activate_all(
    endorsers: Vec<Endorser<Uninitialized>>,
    config: &CohortConfig,
) -> Vec<Endorser<Active>> {
    activate_all(endorsers, config).expect("activation of a genesis cohort must succeed")
}

/// Activates all endorsers using `takeover` from a predecessor cohort.
pub fn activate_all_with_takeover(
    endorsers: Vec<Endorser<Uninitialized>>,
    config: &CohortConfig,
    takeover: &CohortTakeOver,
) -> Result<Vec<Endorser<Active>>, ActivationError> {
    endorsers
        .into_iter()
        .map(|e| e.activate(config.clone(), Some(takeover.clone())))
        .collect()
}

/// [`activate_all_with_takeover`], panicking on failure.
pub fn must_activate_all_with_takeover(
    endorsers: Vec<Endorser<Uninitialized>>,
    config: &CohortConfig,
    takeover: &CohortTakeOver,
) -> Vec<Endorser<Active>> {
    activate_all_with_takeover(endorsers, config, takeover)
        .expect("takeover activation must succeed")
}

/// Creates `ledger_id` on every endorser in `endorsers`.
///
/// Stops at the first failure, leaving earlier endorsers with the new ledger.
pub fn create_ledger_on(
    endorsers: &mut [Endorser<Active>],
    ledger_id: u32,
) -> Result<(), CreateLedgerError> {
    for endorser in endorsers.iter_mut() {
        endorser.create_ledger(ledger_id)?;
    }
    Ok(())
}

/// [`create_ledger_on`], panicking on failure.
pub fn must_create_ledger_on(endorsers: &mut [Endorser<Active>], ledger_id: u32) {
    create_ledger_on(endorsers, ledger_id).expect("ledger must not already exist");
}

/// Calls `read_latest` on the endorsers at `key_indices`.
pub fn read_latest_from(
    endorsers: &[Endorser<Active>],
    key_indices: &[usize],
    ledger_id: u32,
    nonce: u64,
) -> Result<ReadReceipts, LedgerNotFoundError> {
    let results: Vec<_> = key_indices
        .iter()
        .map(|&i| Ok((i, endorsers[i].read_latest(ledger_id, nonce)?)))
        .collect::<Result<_, LedgerNotFoundError>>()?;

    Ok(ReadReceipts {
        read: LedgerReceipts::new(results.iter().map(|(i, r)| LedgerReceipt {
            key_index: *i,
            block: r.block.clone(),
            signature: r.read_receipt,
        })),
        entry: LedgerReceipts::new(results.iter().map(|(i, r)| LedgerReceipt {
            key_index: *i,
            block: r.block.clone(),
            signature: r.entry_receipt,
        })),
    })
}

/// [`read_latest_from`], panicking on failure.
pub fn must_read_latest_from(
    endorsers: &[Endorser<Active>],
    key_indices: &[usize],
    ledger_id: u32,
    nonce: u64,
) -> ReadReceipts {
    read_latest_from(endorsers, key_indices, ledger_id, nonce).expect("ledger must exist")
}

/// Calls `append_entry` on the endorsers at `key_indices`.
///
/// Stops at the first failure, leaving earlier endorsers with the entry
/// appended.
pub fn append_to(
    endorsers: &mut [Endorser<Active>],
    key_indices: &[usize],
    ledger_id: u32,
    entry: EntryContents,
    expected_index: u64,
    nonce: u64,
) -> Result<AppendReceipts, AppendEntryError> {
    let mut results = Vec::with_capacity(key_indices.len());
    for &i in key_indices {
        let result = endorsers[i].append_entry(ledger_id, entry, expected_index, nonce)?;
        results.push((i, result));
    }

    Ok(AppendReceipts {
        append: LedgerReceipts::new(results.iter().map(|(i, r)| LedgerReceipt {
            key_index: *i,
            block: r.block.clone(),
            signature: r.append_receipt,
        })),
        entry: LedgerReceipts::new(results.iter().map(|(i, r)| LedgerReceipt {
            key_index: *i,
            block: r.block.clone(),
            signature: r.entry_receipt,
        })),
    })
}

/// [`append_to`], panicking on failure.
pub fn must_append_to(
    endorsers: &mut [Endorser<Active>],
    key_indices: &[usize],
    ledger_id: u32,
    entry: EntryContents,
    expected_index: u64,
    nonce: u64,
) -> AppendReceipts {
    append_to(
        endorsers,
        key_indices,
        ledger_id,
        entry,
        expected_index,
        nonce,
    )
    .expect("append must succeed")
}

/// Returns `(0..n).collect()`.
pub fn all_indices(n: usize) -> Vec<usize> {
    (0..n).collect()
}

/// Finalizes all endorsers in `active` toward `next`.
///
/// # Panics
///
/// If `active` is empty, since there would be no ledger state to hand forward.
pub fn finalize_all_toward(active: Vec<Endorser<Active>>, next: &CohortConfig) -> Finalization {
    assert!(!active.is_empty(), "cannot finalize an empty cohort");

    let finalized: Vec<Endorser<Finalized>> =
        active.into_iter().map(|e| e.finalize(next)).collect();

    let entries: Vec<EndorserFinalization> = finalized
        .iter()
        .map(|e| EndorserData {
            endorser_key: *e.verifying_key(),
            maybe_receipt: Some(*e.finalization_receipt()),
        })
        .collect();

    let ledgers = finalized[0].ledgers().clone();

    Finalization {
        finalized,
        entries,
        ledgers,
    }
}

/// Builds a [`CohortTakeOver`] for activating a successor cohort.
pub fn takeover_from(
    instance_id: ConfigId,
    entries: &[EndorserFinalization],
    ledgers: &Ledgers,
) -> Result<CohortTakeOver, InvalidConfigError> {
    Ok(CohortTakeOver::new(
        instance_id,
        CohortFinalization::try_new(entries.to_vec())?,
        ledgers.clone(),
    ))
}

/// [`takeover_from`], panicking on failure.
pub fn must_takeover_from(
    instance_id: ConfigId,
    entries: &[EndorserFinalization],
    ledgers: &Ledgers,
) -> CohortTakeOver {
    takeover_from(instance_id, entries, ledgers).expect("entries are in key order")
}

/// Builds a [`CohortHandover`] for evolving a [`Verifier`](logcabin_verifier::Verifier).
pub fn handover_from(
    entries: &[EndorserFinalization],
    successor: &[Endorser<Active>],
    ledgers_hash: Sha256Digest,
) -> Result<CohortHandover, InvalidConfigError> {
    let activations: Vec<_> = successor
        .iter()
        .map(|e| EndorserData {
            endorser_key: *e.verifying_key(),
            maybe_receipt: Some(*e.activation_receipt()),
        })
        .collect();

    CohortHandover::try_new(entries.to_vec(), activations, ledgers_hash)
}

/// [`handover_from`], panicking on failure.
pub fn must_handover_from(
    entries: &[EndorserFinalization],
    successor: &[Endorser<Active>],
    ledgers_hash: Sha256Digest,
) -> CohortHandover {
    handover_from(entries, successor, ledgers_hash).expect("entries are in key order")
}

/// Finalizes `active` and hands over to a fresh cohort of `size` endorsers.
pub fn hand_over_to_fresh_cohort(
    active: Vec<Endorser<Active>>,
    instance_id: ConfigId,
    size: usize,
) -> Result<Succession, SuccessionError> {
    let successor = new_sorted_endorsers(size);
    let next_config = cohort_config(&successor).map_err(SuccessionError::InvalidConfig)?;

    let finalization = finalize_all_toward(active, &next_config);
    let takeover = takeover_from(instance_id, &finalization.entries, &finalization.ledgers)
        .map_err(SuccessionError::InvalidConfig)?;
    let successor = activate_all_with_takeover(successor, &next_config, &takeover)
        .map_err(SuccessionError::Activation)?;
    let handover = handover_from(
        &finalization.entries,
        &successor,
        finalization.ledgers.hash(),
    )
    .map_err(SuccessionError::InvalidConfig)?;

    Ok(Succession {
        successor,
        handover,
    })
}

/// [`hand_over_to_fresh_cohort`], panicking on failure.
pub fn must_hand_over_to_fresh_cohort(
    active: Vec<Endorser<Active>>,
    instance_id: ConfigId,
    size: usize,
) -> Succession {
    hand_over_to_fresh_cohort(active, instance_id, size).expect("handover to a fresh cohort")
}
