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

//! Protocol buffer conversion and validation helpers for the Endorser service.
//!
//! This module handles both directions:
//! - **Parsing**: Validating and converting incoming proto messages into core types.
//! - **Building**: Converting service types into proto messages mostly via `From` impls.

use alloc::format;
use alloc::vec::Vec;
use endorser_micro_rpc_service::logcabin::proto::{
    endorser::State as EndorserStateProto, verifying_key::Key as VerifyingKeyProtoOneOf,
    ActiveState as ActiveStateProto, CohortConfig as CohortConfigProto,
    CohortTakeOver as CohortTakeOverProto, Endorser as EndorserProto,
    EndorserFinalization as EndorserFinalizationProto, FinalizedState as FinalizedStateProto,
    Ledger as LedgerProto, UninitializedState as UninitializedStateProto,
    VerifyingKey as VerifyingKeyProto,
};
use logcabin_endorser_core::{
    Active, CohortConfig, CohortFinalization, CohortTakeOver, EndorserData, EndorserFinalization,
    Finalized, InvalidConfigError, LedgerBlock, Ledgers, Uninitialized,
};
use micro_rpc::{Status, StatusCode};

use crate::{BoundEndorser, MAX_COHORT_SIZE, MAX_LEDGERS};

// ---------------------------------------------------------------------------
// From impls: service types --> proto
// ---------------------------------------------------------------------------

/// Builds an `EndorserProto` with only the common fields (alias, verifying key,
/// vk_signature) and no state-specific metadata. Used by `list_endorsers`
/// where state is intentionally omitted.
pub(crate) fn endorser_proto_without_state<S>(bound: &BoundEndorser<S>) -> EndorserProto {
    EndorserProto {
        alias: bound.endorser.alias(),
        verifying_key: Some(VerifyingKeyProto {
            key: Some(VerifyingKeyProtoOneOf::Ecdsa(
                bound.endorser.verifying_key().to_sec1_bytes().to_vec(),
            )),
        }),
        verifying_key_signature: bound.vk_signature.clone(),
        state: None,
    }
}

impl From<&BoundEndorser<Uninitialized>> for EndorserProto {
    fn from(bound: &BoundEndorser<Uninitialized>) -> Self {
        let mut proto = endorser_proto_without_state(bound);
        proto.state = Some(EndorserStateProto::Uninitialized(
            UninitializedStateProto {},
        ));
        proto
    }
}

impl From<&BoundEndorser<Active>> for EndorserProto {
    fn from(bound: &BoundEndorser<Active>) -> Self {
        let mut proto = endorser_proto_without_state(bound);
        proto.state = Some(EndorserStateProto::Active(ActiveStateProto {
            instance_id: bound.endorser.instance_id().to_vec(),
            activation_receipt: bound.endorser.activation_receipt().to_bytes().to_vec(),
        }));
        proto
    }
}

impl From<&BoundEndorser<Finalized>> for EndorserProto {
    fn from(bound: &BoundEndorser<Finalized>) -> Self {
        let mut proto = endorser_proto_without_state(bound);
        proto.state = Some(EndorserStateProto::Finalized(FinalizedStateProto {
            instance_id: bound.endorser.instance_id().to_vec(),
            activation_receipt: bound.endorser.activation_receipt().to_bytes().to_vec(),
            finalization_receipt: bound.endorser.finalization_receipt().to_bytes().to_vec(),
        }));
        proto
    }
}

/// Parses a proto `VerifyingKey` into a `p256::ecdsa::VerifyingKey`.
///
/// Returns `InvalidArgument` if the key is missing or contains invalid
/// SEC1 bytes. `context` is included in error messages to identify which
/// field failed validation.
pub fn parse_verifying_key(
    vk_proto: Option<VerifyingKeyProto>,
    context: &str,
) -> Result<p256::ecdsa::VerifyingKey, Status> {
    let vk_proto = vk_proto.ok_or_else(|| {
        Status::new_with_message(StatusCode::InvalidArgument, format!("{context} is missing"))
    })?;
    let key_bytes = match vk_proto.key {
        Some(VerifyingKeyProtoOneOf::Ecdsa(bytes)) => bytes,
        None => {
            return Err(Status::new_with_message(
                StatusCode::InvalidArgument,
                format!("{context} has no key set"),
            ));
        }
    };
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|err| {
        Status::new_with_message(
            StatusCode::InvalidArgument,
            format!("{context}: invalid SEC1 key: {err}"),
        )
    })
}

/// Validates and parses a proto `CohortConfig` into a core [`CohortConfig`].
///
/// Returns `InvalidArgument` if the config is missing, empty, contains
/// malformed keys, or keys are not in strict ascending SEC1-lexicographic
/// order. `field_name` is used in error messages to identify which config
/// field failed validation.
pub fn parse_cohort_config(
    config_proto: Option<CohortConfigProto>,
    field_name: &str,
) -> Result<CohortConfig, Status> {
    let config_proto = config_proto.ok_or_else(|| {
        Status::new_with_message(StatusCode::InvalidArgument, format!("missing {field_name}"))
    })?;
    if config_proto.endorser_keys.is_empty() {
        return Err(Status::new_with_message(
            StatusCode::InvalidArgument,
            format!("{field_name} must not be empty"),
        ));
    }
    if config_proto.endorser_keys.len() > MAX_COHORT_SIZE {
        return Err(Status::new_with_message(
            StatusCode::InvalidArgument,
            format!(
                "{field_name} has too many keys ({}, max {MAX_COHORT_SIZE})",
                config_proto.endorser_keys.len()
            ),
        ));
    }
    let keys = config_proto
        .endorser_keys
        .into_iter()
        .enumerate()
        .map(|(i, vk_proto)| {
            parse_verifying_key(Some(vk_proto), &format!("{field_name} key at index {i}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    CohortConfig::try_from_keys(keys).map_err(|_: InvalidConfigError| {
        Status::new_with_message(
            StatusCode::InvalidArgument,
            format!("{field_name} keys are not in strict ascending SEC1-lexicographic order"),
        )
    })
}

/// Validates and parses a proto `Ledger` into a `(ledger_id, LedgerBlock)`
/// tuple.
///
/// Returns `InvalidArgument` if the tail block is missing, or if `entry`
/// or `hash_chain_tail` are not exactly 32 bytes.
pub fn parse_ledger_proto(ledger: LedgerProto) -> Result<(u32, LedgerBlock), Status> {
    let ledger_id = ledger.ledger_id;
    let tail = ledger.tail.ok_or_else(|| {
        Status::new_with_message(
            StatusCode::InvalidArgument,
            format!("ledger {ledger_id} has no tail block"),
        )
    })?;
    let entry: [u8; 32] = tail.entry.try_into().map_err(|_| {
        Status::new_with_message(
            StatusCode::InvalidArgument,
            format!("ledger {ledger_id} entry must be exactly 32 bytes"),
        )
    })?;
    let hash_chain_tail: [u8; 32] = tail.hash_chain_tail.try_into().map_err(|_| {
        Status::new_with_message(
            StatusCode::InvalidArgument,
            format!("ledger {ledger_id} hash_chain_tail must be exactly 32 bytes"),
        )
    })?;
    Ok((
        ledger_id,
        LedgerBlock {
            entry,
            index: tail.index,
            hash_chain_tail,
        },
    ))
}

/// Validates and parses a single `EndorserFinalization` proto entry into a
/// core [`EndorserFinalization`].
///
/// `index` is the position of this entry in the endorser finalizations list,
/// used in error messages.
///
/// Returns `InvalidArgument` if the endorser key is missing, malformed,
/// or if the receipt signature bytes are invalid.
pub fn parse_endorser_finalization_proto(
    index: usize,
    proto: EndorserFinalizationProto,
) -> Result<EndorserFinalization, Status> {
    let endorser_key = parse_verifying_key(
        proto.endorser_key,
        &format!("endorser finalization at index {index}"),
    )?;
    let maybe_receipt = proto
        .receipt
        .map(|sig_bytes| {
            p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|err| {
                Status::new_with_message(
                    StatusCode::InvalidArgument,
                    format!(
                        "endorser finalization at index {index}: invalid receipt signature: {err}"
                    ),
                )
            })
        })
        .transpose()?;
    Ok(EndorserData {
        endorser_key,
        maybe_receipt,
    })
}

/// Validates and parses an optional proto `CohortTakeOver` into a core
/// [`CohortTakeOver`].
///
/// If the input is `Some`, validates all fields (`instance_id`,
/// `cohort_finalization.endorser_finalizations`, `ledgers`) and returns
/// `Ok(Some(CohortTakeOver {...}))`.
///
/// If the input is `None`, returns `Ok(None)`.
///
/// Returns `Err(InvalidArgument)` if any field is malformed, or if endorser
/// finalization keys are not in strict ascending SEC1-lexicographic order.
pub fn parse_cohort_takeover_proto(
    cohort_takeover: Option<CohortTakeOverProto>,
) -> Result<Option<CohortTakeOver>, Status> {
    let cohort_takeover = match cohort_takeover {
        None => return Ok(None),
        Some(ct) => ct,
    };

    // instance_id must be exactly 32 bytes.
    let instance_id: [u8; 32] = cohort_takeover.instance_id.try_into().map_err(|_| {
        Status::new_with_message(
            StatusCode::InvalidArgument,
            format!("instance_id must be exactly 32 bytes"),
        )
    })?;

    // Extract endorser finalizations from the nested CohortFinalization.
    let finalization_proto = cohort_takeover.cohort_finalization.unwrap_or_default();

    // Parse endorser finalizations: each entry provides an endorser key
    // and an optional finalization receipt signature.
    let endorser_finalizations = finalization_proto
        .endorser_finalizations
        .into_iter()
        .enumerate()
        .map(|(i, f)| parse_endorser_finalization_proto(i, f))
        .collect::<Result<Vec<_>, _>>()?;

    if cohort_takeover.ledgers.len() > MAX_LEDGERS {
        return Err(Status::new_with_message(
            StatusCode::InvalidArgument,
            format!(
                "too many ledgers in cohort takeover ({}, max {})",
                cohort_takeover.ledgers.len(),
                MAX_LEDGERS
            ),
        ));
    }

    let ledgers: Ledgers = cohort_takeover
        .ledgers
        .into_iter()
        .map(parse_ledger_proto)
        .collect::<Result<_, _>>()?;

    let cohort_finalization =
        CohortFinalization::try_new(endorser_finalizations).map_err(|_: InvalidConfigError| {
            Status::new_with_message(
                StatusCode::InvalidArgument,
                format!(
                    "endorser finalization keys are not in strict ascending SEC1-lexicographic order"
                ),
            )
        })?;

    Ok(Some(CohortTakeOver::new(
        instance_id,
        cohort_finalization,
        ledgers,
    )))
}
