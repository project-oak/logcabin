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

//! Receipt message builders.
//!
//! Each function constructs the byte message that is signed by an endorser
//! to produce a receipt. The verifier reconstructs the same message to
//! verify the signature.

use alloc::vec::Vec;
use crate::{ConfigId, EntryContents, Sha256Digest};

/// Builds the activation receipt message for a new instance.
///
/// Format: `"activate" || instance_id (32 bytes)`
pub fn build_activate_new_instance_message(instance_id: &ConfigId) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"activate");
    message.extend_from_slice(instance_id);
    message
}

/// Builds the activation receipt message for activation from a previous cohort.
///
/// Format:
///   `"activate" || instance_id (32 bytes) || prev_config_id (32 bytes) ||
///    new_config_id (32 bytes) || ledgers_hash (32 bytes)`
///
/// `ledgers_hash` is a SHA-256 hash of the serialized endorser ledger state
pub fn build_activate_from_prev_message(
    instance_id: &ConfigId,
    prev_config_id: &ConfigId,
    new_config_id: &ConfigId,
    ledgers_hash: &Sha256Digest,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"activate");
    message.extend_from_slice(instance_id);
    message.extend_from_slice(prev_config_id);
    message.extend_from_slice(new_config_id);
    message.extend_from_slice(ledgers_hash);
    message
}

/// Builds the create-ledger receipt message.
///
/// Format: `"create_ledger" || instance_id (32 bytes) || ledger_id (4 bytes, BE)`
pub fn build_create_ledger_message(instance_id: &ConfigId, ledger_id: u32) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"create_ledger");
    message.extend_from_slice(instance_id);
    message.extend_from_slice(&ledger_id.to_be_bytes());
    message
}

/// Builds the append-entry receipt message.
///
/// Format:
///   `"append_entry" || instance_id (32 bytes) || ledger_id (4 bytes, BE) ||
///    entry (32 bytes) || index (8 bytes, BE) || hash_chain_tail (32 bytes)`
pub fn build_append_entry_message(
    instance_id: &ConfigId,
    ledger_id: u32,
    entry: &EntryContents,
    index: u64,
    hash_chain_tail: &Sha256Digest,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"append_entry");
    message.extend_from_slice(instance_id);
    message.extend_from_slice(&ledger_id.to_be_bytes());
    message.extend_from_slice(entry);
    message.extend_from_slice(&index.to_be_bytes());
    message.extend_from_slice(hash_chain_tail);
    message
}

/// Builds the read-latest receipt message.
///
/// Format:
///   `"read_latest" || instance_id (32 bytes) || ledger_id (4 bytes, BE) ||
///    entry (32 bytes) || index (8 bytes, BE) || hash_chain_tail (32 bytes) ||
///    nonce (8 bytes, BE)`
pub fn build_read_latest_message(
    instance_id: &ConfigId,
    ledger_id: u32,
    entry: &EntryContents,
    index: u64,
    hash_chain_tail: &Sha256Digest,
    nonce: u64,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"read_latest");
    message.extend_from_slice(instance_id);
    message.extend_from_slice(&ledger_id.to_be_bytes());
    message.extend_from_slice(entry);
    message.extend_from_slice(&index.to_be_bytes());
    message.extend_from_slice(hash_chain_tail);
    message.extend_from_slice(&nonce.to_be_bytes());
    message
}

/// Builds the finalize receipt message.
///
/// Format:
///   `"finalize" || instance_id (32 bytes) || cohort_config_id (32 bytes) ||
///    next_cohort_config_id (32 bytes) || ledgers_hash (32 bytes)`
pub fn build_finalize_message(
    instance_id: &ConfigId,
    cohort_config_id: &ConfigId,
    next_cohort_config_id: &ConfigId,
    ledgers_hash: &Sha256Digest,
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"finalize");
    message.extend_from_slice(instance_id);
    message.extend_from_slice(cohort_config_id);
    message.extend_from_slice(next_cohort_config_id);
    message.extend_from_slice(ledgers_hash);
    message
}
