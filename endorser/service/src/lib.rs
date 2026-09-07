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

//! This module provides the implementation for the EndorserService RPC service.

#![no_std]

extern crate alloc;

mod proto_mapping;

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use endorser_micro_rpc_service::logcabin::proto::{
    verifying_key::Key as VerifyingKeyProtoOneOf, ActivateEndorserRequest,
    ActivateEndorserResponse, AppendEntryRequest, AppendEntryResponse, CreateEndorserRequest,
    CreateLedgerRequest, CreateLedgerResponse, Endorser as EndorserProto,
    EndorserService as EndorserServiceProto, FinalizeEndorserRequest, FinalizeEndorserResponse,
    GetEndorserRequest, GetEvidenceRequest, GetEvidenceResponse, Ledger as LedgerProto,
    LedgerBlock as LedgerBlockProto, ListEndorsersRequest, ListEndorsersResponse,
    ReadLatestRequest, ReadLatestResponse, VerifyingKey as VerifyingKeyProto,
};
#[cfg(test)]
use endorser_micro_rpc_service::logcabin::proto::{
    CohortConfig as CohortConfigProto, CohortFinalization as CohortFinalizationProto,
    CohortTakeOver as CohortTakeOverProto, EndorserFinalization as EndorserFinalizationProto,
};

use logcabin_endorser_core::{
    ActivationError, Active, AppendEntryError, CreateLedgerError, Endorser, Finalized,
    LedgerNotFoundError, Uninitialized,
};
use micro_rpc::{Status, StatusCode};
use oak_attestation_types::attester::Attester;
use oak_crypto::signer::Signer;

// ---------------------------------------------------------------------------
// Defence-in-depth constraints
//
// These operational limits prevent a buggy coordinator from sending
// excessively large payloads that could exhaust enclave memory.
// ---------------------------------------------------------------------------

/// Maximum number of endorsers (across all states) managed by this service.
pub const MAX_ENDORSERS: usize = 100;

/// Maximum number of finalized endorsers kept for receipt recovery.
/// When this limit is reached, the oldest finalized endorser is evicted.
pub const MAX_FINALIZED_ENDORSERS: usize = 16;

/// Maximum number of ledgers per endorser.
pub const MAX_LEDGERS: usize = 100;

/// Maximum number of endorser keys in a single cohort config.
pub const MAX_COHORT_SIZE: usize = 200;

/// An endorser paired with its attestation binding signature.
///
/// The `vk_signature` covers the endorser's verifying key, signed by the app's
/// Signer from Oak Restricted Kernel. It binds the endorser's key to the TEE
/// attestation evidence chain. This is not part of the core protocol.
pub(crate) struct BoundEndorser<S> {
    pub(crate) endorser: Endorser<S>,
    pub(crate) vk_signature: Vec<u8>,
}

impl<S> BoundEndorser<S> {
    fn new(endorser: Endorser<S>, vk_signature: Vec<u8>) -> Self {
        Self {
            endorser,
            vk_signature,
        }
    }
}

impl<S> Deref for BoundEndorser<S> {
    type Target = Endorser<S>;
    fn deref(&self) -> &Endorser<S> {
        &self.endorser
    }
}

impl<S> DerefMut for BoundEndorser<S> {
    fn deref_mut(&mut self) -> &mut Endorser<S> {
        &mut self.endorser
    }
}

pub struct EndorserService<A: Attester, S: Signer> {
    // An InstanceAttester is used to get the Attestation Evidence from Oak
    // Restricted Kernel.
    attester: A,

    // An InstanceSigner can sign things using the private session key made
    // by Oak Restricted Kernel, which is bound to the Attestation Evidence.
    // This is a service-wide signer (using a service-wide key) - not to be
    // confused with each endorser's signer.
    signer: S,

    // Endorsers in Uninitialized state.
    uninitialized_endorsers: Vec<BoundEndorser<Uninitialized>>,

    // Active endorsers.
    active_endorsers: Vec<BoundEndorser<Active>>,

    // Recently finalized endorsers, kept for receipt recovery.
    // Bounded to MAX_FINALIZED_ENDORSERS; oldest entries are evicted first.
    finalized_endorsers: VecDeque<BoundEndorser<Finalized>>,
}

impl<A: Attester, S: Signer> EndorserService<A, S> {
    pub fn new(attester: A, signer: S) -> anyhow::Result<Self> {
        Ok(Self {
            attester,
            signer,
            uninitialized_endorsers: Vec::new(),
            active_endorsers: Vec::new(),
            finalized_endorsers: VecDeque::new(),
        })
    }

    /// Returns a mutable reference to an active endorser by alias, along with
    /// its position in the active endorsers vector.
    ///
    /// Returns `NotFound` if the alias doesn't exist at all, or
    /// `FailedPrecondition` if it exists in a different state.
    fn get_active_endorser_mut(
        &mut self,
        alias: u64,
    ) -> Result<(usize, &mut BoundEndorser<Active>), Status> {
        self.active_endorsers
            .find_by_alias_mut(alias)
            .ok_or_else(|| {
                if self
                    .uninitialized_endorsers
                    .iter()
                    .any(|e| e.alias() == alias)
                {
                    return wrong_state_status(alias, "active", "uninitialized");
                }
                if self.finalized_endorsers.iter().any(|e| e.alias() == alias) {
                    return wrong_state_status(alias, "active", "finalized");
                }
                not_found_status(alias)
            })
    }

    /// Returns a reference to an uninitialized endorser by alias, along with
    /// its position in the uninitialized endorsers vector.
    ///
    /// Returns `NotFound` if the alias doesn't exist at all, or
    /// `FailedPrecondition` if it exists in a different state.
    fn get_uninitialized_endorser(
        &self,
        alias: u64,
    ) -> Result<(usize, &BoundEndorser<Uninitialized>), Status> {
        self.uninitialized_endorsers
            .find_by_alias(alias)
            .ok_or_else(|| {
                if self.active_endorsers.iter().any(|e| e.alias() == alias) {
                    return wrong_state_status(alias, "uninitialized", "active");
                }
                if self.finalized_endorsers.iter().any(|e| e.alias() == alias) {
                    return wrong_state_status(alias, "uninitialized", "finalized");
                }
                not_found_status(alias)
            })
    }
}

// EndorserServiceProto RPC implementations.
//
// EndorserServiceProto is a trait generated by prost. We provide an implementation for each RPC
// method in the proto service.
impl<A: Attester, S: Signer> EndorserServiceProto for EndorserService<A, S> {
    fn get_evidence(
        &mut self,
        _request: GetEvidenceRequest,
    ) -> Result<GetEvidenceResponse, Status> {
        let evidence = self.attester.quote().map_err(|err| {
            micro_rpc::Status::new_with_message(
                micro_rpc::StatusCode::Internal,
                format!("failed to get evidence: {err}"),
            )
        })?;
        Ok(GetEvidenceResponse {
            evidence: Some(evidence),
        })
    }

    fn create_endorser(
        &mut self,
        _request: CreateEndorserRequest,
    ) -> Result<EndorserProto, Status> {
        let total_endorsers = self.uninitialized_endorsers.len()
            + self.active_endorsers.len()
            + self.finalized_endorsers.len();
        if total_endorsers >= MAX_ENDORSERS {
            return Err(Status::new_with_message(
                StatusCode::FailedPrecondition,
                format!("Maximum number of endorsers ({}) exceeded", MAX_ENDORSERS),
            ));
        }

        let endorser = Endorser::new();
        let vk_bytes = endorser.verifying_key().to_sec1_bytes();

        // Bind the verifying key to the attestation evidence, using
        // the app's session signing key from InstanceSigner.
        let vk_signature = self.signer.sign(&vk_bytes);

        let bound = BoundEndorser::new(endorser, vk_signature);
        let proto = EndorserProto::from(&bound);
        self.uninitialized_endorsers.push(bound);
        Ok(proto)
    }

    fn list_endorsers(
        &mut self,
        request: ListEndorsersRequest,
    ) -> Result<ListEndorsersResponse, Status> {
        let mut endorsers: Vec<EndorserProto> = self
            .uninitialized_endorsers
            .iter()
            .map(proto_mapping::endorser_proto_without_state)
            .chain(
                self.active_endorsers
                    .iter()
                    .map(proto_mapping::endorser_proto_without_state),
            )
            .collect();

        if request.include_finalized {
            endorsers.extend(
                self.finalized_endorsers
                    .iter()
                    .map(proto_mapping::endorser_proto_without_state),
            );
        }

        Ok(ListEndorsersResponse { endorsers })
    }

    fn get_endorser(&mut self, request: GetEndorserRequest) -> Result<EndorserProto, Status> {
        let alias = request.endorser_alias;

        if let Some(bound) = self
            .uninitialized_endorsers
            .iter()
            .find(|e| e.alias() == alias)
        {
            return Ok(bound.into());
        }
        if let Some(bound) = self.active_endorsers.iter().find(|e| e.alias() == alias) {
            return Ok(bound.into());
        }
        if let Some(bound) = self.finalized_endorsers.iter().find(|e| e.alias() == alias) {
            return Ok(bound.into());
        }

        Err(not_found_status(alias))
    }

    fn activate_endorser(
        &mut self,
        request: ActivateEndorserRequest,
    ) -> Result<ActivateEndorserResponse, Status> {
        let alias = request.endorser_alias;

        // Parse the cohort config verifying keys from proto SEC1 bytes.
        let new_config = proto_mapping::parse_cohort_config(request.new_config, "new_config")?;

        // Validate cohort takeover fields (if present) before making modifications.
        let maybe_takeover =
            proto_mapping::parse_cohort_takeover_proto(request.prev_cohort_takeover)?;

        // Find the uninitialized endorser by alias. Returns
        // FailedPrecondition if found in active/finalized, NotFound otherwise.
        let (position, _) = self.get_uninitialized_endorser(alias)?;

        // Extract and transition to Active. swap_remove is O(1): swaps the
        // last item into `position`. On failure, we put it back.
        // NOTE: from this point there must be no return-on-error ("?")
        // statements, until the endorser has been placed back in.
        let bound: BoundEndorser<Uninitialized> =
            self.uninitialized_endorsers.swap_remove(position);
        let vk_signature = bound.vk_signature;

        let active_endorser = bound
            .endorser
            .activate(new_config, maybe_takeover)
            .map_err(|err: ActivationError| {
                let reason = err.to_string();
                self.uninitialized_endorsers.push(BoundEndorser::new(
                    err.reclaim_endorser(),
                    vk_signature.clone(),
                ));
                let last_ix = self.uninitialized_endorsers.len() - 1;
                self.uninitialized_endorsers.swap(position, last_ix);
                Status::new_with_message(StatusCode::InvalidArgument, reason)
            })?;
        let activation_receipt = active_endorser.activation_receipt().to_bytes().to_vec();
        self.active_endorsers
            .push(BoundEndorser::new(active_endorser, vk_signature));

        Ok(ActivateEndorserResponse { activation_receipt })
    }

    fn create_ledger(
        &mut self,
        request: CreateLedgerRequest,
    ) -> Result<CreateLedgerResponse, Status> {
        let (_, endorser) = self.get_active_endorser_mut(request.endorser_alias)?;

        if endorser.ledger_count() >= MAX_LEDGERS {
            return Err(Status::new_with_message(
                StatusCode::FailedPrecondition,
                format!("maximum number of ledgers ({MAX_LEDGERS}) exceeded"),
            ));
        }

        let sig = endorser
            .create_ledger(request.ledger_id)
            .map_err(|err| match err {
                CreateLedgerError::AlreadyExists { ledger_id } => Status::new_with_message(
                    StatusCode::FailedPrecondition,
                    format!("ledger with id {ledger_id} already exists"),
                ),
            })?;

        Ok(CreateLedgerResponse {
            create_ledger_receipt: sig.to_bytes().to_vec(),
        })
    }

    fn append_entry(&mut self, request: AppendEntryRequest) -> Result<AppendEntryResponse, Status> {
        let (_, endorser) = self.get_active_endorser_mut(request.endorser_alias)?;

        // Validate entry size (must be exactly 32 bytes).
        let entry: [u8; 32] = request.entry.try_into().map_err(|_| {
            Status::new_with_message(
                StatusCode::InvalidArgument,
                format!("entry must be exactly 32 bytes"),
            )
        })?;

        // Nonce 0 is the proto3 default — reject it to detect missing fields.
        if request.nonce == 0 {
            return Err(Status::new_with_message(
                StatusCode::InvalidArgument,
                format!("nonce must not be zero"),
            ));
        }

        let result = endorser
            .append_entry(request.ledger_id, entry, request.expected_index, request.nonce)
            .map_err(|err| match err {
                AppendEntryError::LedgerNotFound(err) => Status::new_with_message(
                    StatusCode::NotFound,
                    format!("ledger with id {} not found", err.ledger_id),
                ),
                AppendEntryError::WrongIndex { expected, actual } => Status::new_with_message(
                    StatusCode::FailedPrecondition,
                    format!("expected index {expected} does not match next index {actual}"),
                ),
            })?;

        Ok(AppendEntryResponse {
            block: Some(LedgerBlockProto {
                entry: result.block.entry.to_vec(),
                index: result.block.index,
                hash_chain_tail: result.block.hash_chain_tail.to_vec(),
            }),
            entry_receipt: result.entry_receipt.to_bytes().to_vec(),
            tip_receipt: result.tip_receipt.to_bytes().to_vec(),
        })
    }

    fn read_latest(&mut self, request: ReadLatestRequest) -> Result<ReadLatestResponse, Status> {
        let (_, endorser) = self.get_active_endorser_mut(request.endorser_alias)?;

        // Nonce 0 is the proto3 default — reject it to detect missing fields.
        if request.nonce == 0 {
            return Err(Status::new_with_message(
                StatusCode::InvalidArgument,
                format!("nonce must not be zero"),
            ));
        }

        let result = endorser
            .read_latest(request.ledger_id, request.nonce)
            .map_err(|err: LedgerNotFoundError| {
                Status::new_with_message(
                    StatusCode::NotFound,
                    format!("ledger with id {} not found", err.ledger_id),
                )
            })?;

        Ok(ReadLatestResponse {
            block: Some(LedgerBlockProto {
                entry: result.block.entry.to_vec(),
                index: result.block.index,
                hash_chain_tail: result.block.hash_chain_tail.to_vec(),
            }),
            entry_receipt: result.entry_receipt.to_bytes().to_vec(),
            tip_receipt: result.tip_receipt.to_bytes().to_vec(),
        })
    }

    fn finalize_endorser(
        &mut self,
        request: FinalizeEndorserRequest,
    ) -> Result<FinalizeEndorserResponse, Status> {
        let alias = request.endorser_alias;

        let next_config =
            proto_mapping::parse_cohort_config(request.next_cohort_config, "next_cohort_config")?;

        // Find the active endorser and get its position for removal.
        let (position, _) = self.get_active_endorser_mut(alias)?;
        let bound: BoundEndorser<Active> = self.active_endorsers.swap_remove(position);

        // Finalize: produces the receipt and erases the signing key.
        let finalized = bound.endorser.finalize(&next_config);

        let endorser_key_proto = VerifyingKeyProto {
            key: Some(VerifyingKeyProtoOneOf::Ecdsa(
                finalized.verifying_key().to_sec1_bytes().to_vec(),
            )),
        };

        // Convert ledger state to proto format, in ascending ledger_id order.
        let ledgers_proto = finalized
            .ledgers()
            .iter()
            .map(|(ledger_id, block)| LedgerProto {
                ledger_id: *ledger_id,
                tail: Some(LedgerBlockProto {
                    entry: block.entry.to_vec(),
                    index: block.index,
                    hash_chain_tail: block.hash_chain_tail.to_vec(),
                }),
            })
            .collect();

        let response = FinalizeEndorserResponse {
            endorser_key: Some(endorser_key_proto),
            ledgers: ledgers_proto,
            finalization_receipt: finalized.finalization_receipt().to_bytes().to_vec(),
        };

        // Retain the finalized endorser for receipt recovery, evicting the
        // oldest if the queue is full.
        if self.finalized_endorsers.len() >= MAX_FINALIZED_ENDORSERS {
            self.finalized_endorsers.pop_front();
        }
        self.finalized_endorsers
            .push_back(BoundEndorser::new(finalized, bound.vk_signature));

        Ok(response)
    }
}

/// Extension trait for finding bound endorsers by alias in a slice.
trait EndorserSlice<S> {
    /// Finds a bound endorser by alias, returning its position and a reference.
    fn find_by_alias(&self, alias: u64) -> Option<(usize, &BoundEndorser<S>)>;

    /// Finds a bound endorser by alias, returning its position and a mutable
    /// reference.
    fn find_by_alias_mut(&mut self, alias: u64) -> Option<(usize, &mut BoundEndorser<S>)>;
}

impl<S> EndorserSlice<S> for [BoundEndorser<S>] {
    fn find_by_alias(&self, alias: u64) -> Option<(usize, &BoundEndorser<S>)> {
        self.iter().enumerate().find(|(_, e)| e.alias() == alias)
    }

    fn find_by_alias_mut(&mut self, alias: u64) -> Option<(usize, &mut BoundEndorser<S>)> {
        self.iter_mut()
            .enumerate()
            .find(|(_, e)| e.alias() == alias)
    }
}

/// Builds a `FailedPrecondition` status for an endorser found in the wrong state.
fn wrong_state_status(alias: u64, expected: &str, actual: &str) -> Status {
    Status::new_with_message(
        StatusCode::FailedPrecondition,
        format!("endorser {alias}: expected {expected} state, but is {actual}"),
    )
}

/// Builds a `NotFound` status for an endorser alias that doesn't exist.
fn not_found_status(alias: u64) -> Status {
    Status::new_with_message(
        StatusCode::NotFound,
        format!("endorser with alias {alias} not found"),
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use p256::ecdsa::signature::Verifier;

    use super::*;
    use endorser_micro_rpc_service::logcabin::proto::endorser::State as EndorserStateProto;

    pub struct MockAttester;

    impl MockAttester {
        pub fn create() -> anyhow::Result<Self> {
            Ok(Self)
        }
    }

    impl Attester for MockAttester {
        fn extend(&mut self, _encoded_event: &[u8]) -> anyhow::Result<()> {
            Ok(())
        }

        fn quote(&self) -> anyhow::Result<oak_proto_rust::oak::attestation::v1::Evidence> {
            Ok(oak_proto_rust::oak::attestation::v1::Evidence::default())
        }
    }

    #[test]
    fn create_endorser_enforces_max_endorser_limit() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();

        for _ in 0..MAX_ENDORSERS {
            service.create_endorser(CreateEndorserRequest {}).unwrap();
        }

        let status = service.create_endorser(CreateEndorserRequest {});
        assert!(status.is_err());
        assert_eq!(status.unwrap_err().code, StatusCode::FailedPrecondition);
    }

    #[test]
    fn create_endorser_public_key_bound_to_service_key() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let verifying_key = *signer.verifying_key();
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();
        let endorser: EndorserProto = service.create_endorser(CreateEndorserRequest {}).unwrap();

        let Some(VerifyingKeyProtoOneOf::Ecdsa(vk_bytes)) = endorser.verifying_key.unwrap().key
        else {
            panic!("expected ECDSA verifying key");
        };

        let vk_signature = p256::ecdsa::Signature::from_slice(&endorser.verifying_key_signature)
            .expect("CreateEndorser did not return a valid public key signature");

        // Verify that vk_signature, made using service.signer, binds vk_bytes.
        verifying_key
            .verify(&vk_bytes, &vk_signature)
            .expect("CreateEndorser returned a signature which does not verify the public key");
    }

    #[test]
    fn list_endorsers_returns_uninitialized_and_active_without_state() {
        let (mut service, active_alias) = create_active_service();

        // Create a second (uninitialized) endorser.
        let uninit = service.create_endorser(CreateEndorserRequest {}).unwrap();

        let resp = service
            .list_endorsers(ListEndorsersRequest {
                include_finalized: false,
            })
            .unwrap();

        // Should have 2 endorsers (1 active + 1 uninitialized); order is
        // uninitialized first, then active.
        assert_eq!(resp.endorsers.len(), 2);
        assert_eq!(resp.endorsers[0].alias, uninit.alias);
        assert_eq!(resp.endorsers[1].alias, active_alias);

        // State must not be populated (per proto contract).
        for e in &resp.endorsers {
            assert!(e.state.is_none(), "ListEndorsers must not populate state");
            assert!(e.verifying_key.is_some());
            assert!(!e.verifying_key_signature.is_empty());
        }
    }

    #[test]
    fn list_endorsers_includes_finalized_when_requested() {
        let (mut service, alias) = create_active_service();

        // Finalize the active endorser.
        let next_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        service
            .finalize_endorser(FinalizeEndorserRequest {
                endorser_alias: alias,
                next_cohort_config: Some(cohort_config_from_bytes(std::vec![next_key])),
            })
            .unwrap();

        // Without include_finalized: should be empty (no active/uninit left).
        let resp = service
            .list_endorsers(ListEndorsersRequest {
                include_finalized: false,
            })
            .unwrap();
        assert_eq!(resp.endorsers.len(), 0);

        // With include_finalized: should include the finalized endorser.
        let resp = service
            .list_endorsers(ListEndorsersRequest {
                include_finalized: true,
            })
            .unwrap();
        assert_eq!(resp.endorsers.len(), 1);
        assert_eq!(resp.endorsers[0].alias, alias);
        assert!(
            resp.endorsers[0].state.is_none(),
            "ListEndorsers must not populate state even for finalized"
        );
    }

    #[test]
    fn get_endorser_uninitialized_populates_state_metadata() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();
        let created = service.create_endorser(CreateEndorserRequest {}).unwrap();

        let endorser = service
            .get_endorser(GetEndorserRequest {
                endorser_alias: created.alias,
            })
            .unwrap();

        assert_eq!(endorser.alias, created.alias);
        assert!(endorser.verifying_key.is_some());
        assert!(!endorser.verifying_key_signature.is_empty());
        assert!(
            matches!(endorser.state, Some(EndorserStateProto::Uninitialized(_))),
            "expected UninitializedState, got {:?}",
            endorser.state
        );
    }

    #[test]
    fn get_endorser_active_populates_state_metadata() {
        let (mut service, alias) = create_active_service();

        let endorser = service
            .get_endorser(GetEndorserRequest {
                endorser_alias: alias,
            })
            .unwrap();

        assert_eq!(endorser.alias, alias);
        let Some(EndorserStateProto::Active(active_state)) = endorser.state else {
            panic!("expected ActiveState, got {:?}", endorser.state);
        };
        assert_eq!(active_state.instance_id.len(), 32);
        assert_eq!(active_state.activation_receipt.len(), 64);
    }

    #[test]
    fn get_endorser_finalized_populates_state_metadata() {
        let (mut service, alias) = create_active_service();

        // Finalize the active endorser.
        let next_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        service
            .finalize_endorser(FinalizeEndorserRequest {
                endorser_alias: alias,
                next_cohort_config: Some(cohort_config_from_bytes(std::vec![next_key])),
            })
            .unwrap();

        let endorser = service
            .get_endorser(GetEndorserRequest {
                endorser_alias: alias,
            })
            .unwrap();

        assert_eq!(endorser.alias, alias);
        let Some(EndorserStateProto::Finalized(finalized_state)) = endorser.state else {
            panic!("expected FinalizedState, got {:?}", endorser.state);
        };
        assert_eq!(finalized_state.instance_id.len(), 32);
        assert_eq!(finalized_state.activation_receipt.len(), 64);
        assert_eq!(finalized_state.finalization_receipt.len(), 64);
    }

    #[test]
    fn get_endorser_not_found() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();

        let err = service
            .get_endorser(GetEndorserRequest {
                endorser_alias: 0xDEADBEEF,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::NotFound);
    }

    #[test]
    fn activate_new_instance_failure_preserves_uninitialized() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();

        // 1. Create 3 endorsers.
        let mut aliases = Vec::new();
        for _ in 0..3 {
            let res = service.create_endorser(CreateEndorserRequest {}).unwrap();
            aliases.push(res.alias);
        }

        // Check the uninitialized list directly to ensure they are in order.
        assert_eq!(service.uninitialized_endorsers.len(), 3);
        assert_eq!(service.uninitialized_endorsers[0].alias(), aliases[0]);
        assert_eq!(service.uninitialized_endorsers[1].alias(), aliases[1]);
        assert_eq!(service.uninitialized_endorsers[2].alias(), aliases[2]);

        // 2. Try to activate the one in the middle (index 1) with a config
        // that does not contain its verifying key (uses a random unrelated key).
        let unrelated_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        let bad_cohort_config = CohortConfigProto {
            endorser_keys: std::vec![VerifyingKeyProto {
                key: Some(VerifyingKeyProtoOneOf::Ecdsa(unrelated_key)),
            }],
        };
        let req = ActivateEndorserRequest {
            endorser_alias: aliases[1],
            new_config: Some(bad_cohort_config),
            prev_cohort_takeover: None,
        };

        // Assert that activation fails because the endorser's key is not in the config.
        let status = service.activate_endorser(req).unwrap_err();
        assert_eq!(status.code, StatusCode::InvalidArgument);

        // 3. Verify that the order is preserved.
        assert_eq!(service.uninitialized_endorsers.len(), 3);
        assert_eq!(service.uninitialized_endorsers[0].alias(), aliases[0]);
        assert_eq!(service.uninitialized_endorsers[1].alias(), aliases[1]);
        assert_eq!(service.uninitialized_endorsers[2].alias(), aliases[2]);
    }

    #[test]
    fn activate_from_prev_bad_instance_id_preserves_uninitialized() {
        let (mut service, aliases) = create_service_with_3_uninitialized();
        let target = aliases[1];

        let valid_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        let req = ActivateEndorserRequest {
            endorser_alias: target,
            new_config: Some(cohort_config_from_bytes(std::vec![valid_key.clone()])),
            prev_cohort_takeover: Some(CohortTakeOverProto {
                instance_id: std::vec![0xAB; 16], // wrong length (not 32)
                ledgers: std::vec![],
                cohort_finalization: Some(CohortFinalizationProto {
                    endorser_finalizations: std::vec![EndorserFinalizationProto {
                        endorser_key: Some(VerifyingKeyProto {
                            key: Some(VerifyingKeyProtoOneOf::Ecdsa(valid_key)),
                        }),
                        receipt: None,
                    }],
                }),
            }),
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
        assert_uninitialized_aliases(&service, &aliases);
    }

    #[test]
    fn activate_from_prev_bad_endorser_key_preserves_uninitialized() {
        let (mut service, aliases) = create_service_with_3_uninitialized();
        let target = aliases[1];

        let valid_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        let req = ActivateEndorserRequest {
            endorser_alias: target,
            new_config: Some(cohort_config_from_bytes(std::vec![valid_key])),
            prev_cohort_takeover: Some(CohortTakeOverProto {
                instance_id: std::vec![0xAB; 32],
                ledgers: std::vec![],
                cohort_finalization: Some(CohortFinalizationProto {
                    endorser_finalizations: std::vec![EndorserFinalizationProto {
                        endorser_key: Some(VerifyingKeyProto {
                            // Malformed SEC1 key (wrong length).
                            key: Some(VerifyingKeyProtoOneOf::Ecdsa(std::vec![0xFF; 10])),
                        }),
                        receipt: None,
                    }],
                }),
            }),
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
        assert_uninitialized_aliases(&service, &aliases);
    }

    #[test]
    fn activate_from_prev_bad_ledger_entry_preserves_uninitialized() {
        let (mut service, aliases) = create_service_with_3_uninitialized();
        let target = aliases[1];

        let valid_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        let req = ActivateEndorserRequest {
            endorser_alias: target,
            new_config: Some(cohort_config_from_bytes(std::vec![valid_key.clone()])),
            prev_cohort_takeover: Some(CohortTakeOverProto {
                instance_id: std::vec![0xAB; 32],
                ledgers: std::vec![LedgerProto {
                    ledger_id: 0,
                    tail: Some(LedgerBlockProto {
                        entry: std::vec![0xAB; 16], // wrong length (not 32)
                        index: 0,
                        hash_chain_tail: std::vec![0u8; 32],
                    }),
                }],
                cohort_finalization: Some(CohortFinalizationProto {
                    endorser_finalizations: std::vec![EndorserFinalizationProto {
                        endorser_key: Some(VerifyingKeyProto {
                            key: Some(VerifyingKeyProtoOneOf::Ecdsa(valid_key)),
                        }),
                        receipt: None,
                    }],
                }),
            }),
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
        assert_uninitialized_aliases(&service, &aliases);
    }

    #[test]
    fn activate_endorser_not_found() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();

        let valid_key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        let req = ActivateEndorserRequest {
            endorser_alias: 12345, // random unknown alias
            new_config: Some(cohort_config_from_bytes(std::vec![valid_key])),
            prev_cohort_takeover: None,
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::NotFound);
    }

    #[test]
    fn activate_endorser_already_activated() {
        let (mut service, alias) = create_active_service();

        // Get the active endorser's key.
        let vk_bytes = {
            let active = &service.active_endorsers[0];
            active.verifying_key().to_sec1_bytes().to_vec()
        };

        let req = ActivateEndorserRequest {
            endorser_alias: alias,
            new_config: Some(CohortConfigProto {
                endorser_keys: std::vec![VerifyingKeyProto {
                    key: Some(VerifyingKeyProtoOneOf::Ecdsa(vk_bytes)),
                }],
            }),
            prev_cohort_takeover: None,
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::FailedPrecondition);
    }

    #[test]
    fn activate_endorser_missing_new_config() {
        let (mut service, aliases) = create_service_with_3_uninitialized();
        let target = aliases[1];

        let req = ActivateEndorserRequest {
            endorser_alias: target,
            new_config: None,
            prev_cohort_takeover: None,
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
        assert!(err.message.contains("missing new_config"));
        assert_uninitialized_aliases(&service, &aliases);
    }

    #[test]
    fn activate_endorser_empty_new_config() {
        let (mut service, aliases) = create_service_with_3_uninitialized();
        let target = aliases[1];

        let req = ActivateEndorserRequest {
            endorser_alias: target,
            new_config: Some(CohortConfigProto {
                endorser_keys: std::vec![],
            }),
            prev_cohort_takeover: None,
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
        assert!(err.message.contains("new_config must not be empty"));
        assert_uninitialized_aliases(&service, &aliases);
    }

    #[test]
    fn activate_endorser_invalid_config_order() {
        let (mut service, aliases) = create_service_with_3_uninitialized();
        let target = aliases[1];

        let k1 = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();
        let k2 = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng)
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        // Sort descending (which is incorrect for strict ascending order).
        let mut sorted = std::vec![k1, k2];
        sorted.sort_by(|a, b| b.cmp(a));

        let req = ActivateEndorserRequest {
            endorser_alias: target,
            new_config: Some(cohort_config_from_bytes(sorted)),
            prev_cohort_takeover: None,
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
        assert!(err
            .message
            .contains("keys are not in strict ascending SEC1-lexicographic order"));
        assert_uninitialized_aliases(&service, &aliases);
    }

    #[test]
    fn activate_from_prev_too_many_ledgers() {
        let (mut service, aliases) = create_service_with_3_uninitialized();
        let target = aliases[1];

        let vk_bytes = service.uninitialized_endorsers[1]
            .verifying_key()
            .to_sec1_bytes()
            .to_vec();

        // Generate MAX_LEDGERS + 1 ledger entries.
        let mut ledgers = std::vec![];
        for i in 0..=(MAX_LEDGERS as u32) {
            ledgers.push(LedgerProto {
                ledger_id: i,
                tail: Some(LedgerBlockProto {
                    entry: std::vec![0xAA; 32],
                    index: 0,
                    hash_chain_tail: std::vec![0u8; 32],
                }),
            });
        }

        let req = ActivateEndorserRequest {
            endorser_alias: target,
            new_config: Some(cohort_config_from_bytes(std::vec![vk_bytes.clone()])),
            prev_cohort_takeover: Some(CohortTakeOverProto {
                instance_id: std::vec![0xAB; 32],
                ledgers,
                cohort_finalization: Some(CohortFinalizationProto {
                    endorser_finalizations: std::vec![EndorserFinalizationProto {
                        endorser_key: Some(VerifyingKeyProto {
                            key: Some(VerifyingKeyProtoOneOf::Ecdsa(vk_bytes)),
                        }),
                        receipt: None,
                    }],
                }),
            }),
        };

        let err = service.activate_endorser(req).unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
        assert!(err.message.contains("too many ledgers in cohort takeover"));
        assert_uninitialized_aliases(&service, &aliases);
    }

    #[test]
    fn create_ledger_fails_when_max_ledgers_exceeded() {
        let (mut service, alias) = create_active_service();

        // activate already created ledger 0, so we can create
        // MAX_LEDGERS - 1 more before hitting the cap.
        for i in 1..MAX_LEDGERS {
            service
                .create_ledger(CreateLedgerRequest {
                    endorser_alias: alias,
                    ledger_id: i as u32,
                })
                .unwrap();
        }

        let err = service
            .create_ledger(CreateLedgerRequest {
                endorser_alias: alias,
                ledger_id: MAX_LEDGERS as u32,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::FailedPrecondition);
    }

    #[test]
    fn append_entry_happy_path() {
        let (mut service, alias) = create_active_service();
        service
            .create_ledger(CreateLedgerRequest {
                endorser_alias: alias,
                ledger_id: 1,
            })
            .unwrap();

        let resp = service
            .append_entry(AppendEntryRequest {
                endorser_alias: alias,
                ledger_id: 1,
                entry: std::vec![0xAB; 32],
                expected_index: 1,
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            })
            .unwrap();

        // Receipts should be valid ECDSA P-256 RAW (R || S) signatures.
        assert_eq!(resp.entry_receipt.len(), 64);
        p256::ecdsa::Signature::from_slice(&resp.entry_receipt)
            .expect("entry_receipt must be a valid ECDSA P-256 signature");
        assert_eq!(resp.tip_receipt.len(), 64);
        p256::ecdsa::Signature::from_slice(&resp.tip_receipt)
            .expect("tip_receipt must be a valid ECDSA P-256 signature");

        let block = resp.block.expect("block must be present");
        assert_eq!(block.index, 1);
        assert_eq!(block.entry, std::vec![0xAB; 32]);
    }

    #[test]
    fn append_entry_endorser_not_activated() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();
        let endorser = service.create_endorser(CreateEndorserRequest {}).unwrap();

        let err = service
            .append_entry(AppendEntryRequest {
                endorser_alias: endorser.alias,
                ledger_id: 0,
                entry: std::vec![0xAB; 32],
                expected_index: 1,
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::FailedPrecondition);
    }

    #[test]
    fn append_entry_endorser_not_found() {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();

        let err = service
            .append_entry(AppendEntryRequest {
                endorser_alias: 0xDEAD,
                ledger_id: 0,
                entry: std::vec![0xAB; 32],
                expected_index: 1,
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::NotFound);
    }

    #[test]
    fn append_entry_invalid_entry_size() {
        let (mut service, alias) = create_active_service();
        service
            .create_ledger(CreateLedgerRequest {
                endorser_alias: alias,
                ledger_id: 1,
            })
            .unwrap();

        // Entry too short (16 bytes).
        let err = service
            .append_entry(AppendEntryRequest {
                endorser_alias: alias,
                ledger_id: 1,
                entry: std::vec![0xAB; 16],
                expected_index: 1,
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);

        // Entry too long (64 bytes).
        let err = service
            .append_entry(AppendEntryRequest {
                endorser_alias: alias,
                ledger_id: 1,
                entry: std::vec![0xAB; 64],
                expected_index: 1,
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
    }

    #[test]
    fn append_entry_rejects_zero_nonce() {
        let (mut service, alias) = create_active_service();
        service
            .create_ledger(CreateLedgerRequest {
                endorser_alias: alias,
                ledger_id: 1,
            })
            .unwrap();

        let err = service
            .append_entry(AppendEntryRequest {
                endorser_alias: alias,
                ledger_id: 1,
                entry: std::vec![0xAB; 32],
                expected_index: 1,
                nonce: 0,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
    }

    #[test]
    fn append_entry_wrong_index() {
        let (mut service, alias) = create_active_service();
        service
            .create_ledger(CreateLedgerRequest {
                endorser_alias: alias,
                ledger_id: 1,
            })
            .unwrap();

        let err = service
            .append_entry(AppendEntryRequest {
                endorser_alias: alias,
                ledger_id: 1,
                entry: std::vec![0xAB; 32],
                expected_index: 99, // should be 1
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::FailedPrecondition);
    }

    #[test]
    fn append_entry_ledger_not_found() {
        let (mut service, alias) = create_active_service();

        let err = service
            .append_entry(AppendEntryRequest {
                endorser_alias: alias,
                ledger_id: 99, // doesn't exist
                entry: std::vec![0xAB; 32],
                expected_index: 1,
                nonce: 0xDEAD_BEEF_CAFE_BABE,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::NotFound);
    }

    #[test]
    fn read_latest_happy_path() {
        let (mut service, alias) = create_active_service();
        service
            .create_ledger(CreateLedgerRequest {
                endorser_alias: alias,
                ledger_id: 1,
            })
            .unwrap();

        let resp = service
            .read_latest(ReadLatestRequest {
                endorser_alias: alias,
                ledger_id: 1,
                nonce: 0x0102030405060708,
            })
            .unwrap();

        let block = resp.block.unwrap();
        // Initial state: entry and hash_chain_tail should be 32 zero bytes.
        assert_eq!(block.entry, std::vec![0u8; 32]);
        assert_eq!(block.hash_chain_tail, std::vec![0u8; 32]);
        assert_eq!(block.index, 0);

        // Receipts should be valid ECDSA P-256 RAW (R || S) signatures.
        assert_eq!(resp.entry_receipt.len(), 64);
        p256::ecdsa::Signature::from_slice(&resp.entry_receipt)
            .expect("entry_receipt must be a valid ECDSA P-256 signature");
        assert_eq!(resp.tip_receipt.len(), 64);
        p256::ecdsa::Signature::from_slice(&resp.tip_receipt)
            .expect("tip_receipt must be a valid ECDSA P-256 signature");
    }

    #[test]
    fn read_latest_ledger_not_found() {
        let (mut service, alias) = create_active_service();

        let err = service
            .read_latest(ReadLatestRequest {
                endorser_alias: alias,
                ledger_id: 99,
                nonce: 42,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::NotFound);
    }

    #[test]
    fn read_latest_rejects_zero_nonce() {
        let (mut service, alias) = create_active_service();
        service
            .create_ledger(CreateLedgerRequest {
                endorser_alias: alias,
                ledger_id: 1,
            })
            .unwrap();

        let err = service
            .read_latest(ReadLatestRequest {
                endorser_alias: alias,
                ledger_id: 1,
                nonce: 0,
            })
            .unwrap_err();
        assert_eq!(err.code, StatusCode::InvalidArgument);
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Creates a service with one endorser that is already activated.
    /// Returns `(service, endorser_alias)`.
    fn create_active_service() -> (EndorserService<MockAttester, p256::ecdsa::SigningKey>, u64) {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();
        let endorser = service.create_endorser(CreateEndorserRequest {}).unwrap();

        // Extract the verifying key bytes to build the cohort config.
        let Some(VerifyingKeyProtoOneOf::Ecdsa(vk_bytes)) = endorser.verifying_key.unwrap().key
        else {
            panic!("expected ECDSA verifying key");
        };

        let cohort = CohortConfigProto {
            endorser_keys: std::vec![VerifyingKeyProto {
                key: Some(VerifyingKeyProtoOneOf::Ecdsa(vk_bytes)),
            }],
        };
        service
            .activate_endorser(ActivateEndorserRequest {
                endorser_alias: endorser.alias,
                new_config: Some(cohort),
                prev_cohort_takeover: None,
            })
            .unwrap();

        (service, endorser.alias)
    }

    /// Helper: creates a service with 3 uninitialized endorsers and returns
    /// their aliases. Targets the middle endorser (index 1) for init.
    fn create_service_with_3_uninitialized() -> (
        EndorserService<MockAttester, p256::ecdsa::SigningKey>,
        Vec<u64>,
    ) {
        let signer = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let mut service = EndorserService::new(MockAttester::create().unwrap(), signer).unwrap();
        let mut aliases = Vec::new();
        for _ in 0..3 {
            let res = service.create_endorser(CreateEndorserRequest {}).unwrap();
            aliases.push(res.alias);
        }
        (service, aliases)
    }

    /// Helper: builds a valid CohortConfigProto from raw SEC1 key bytes.
    fn cohort_config_from_bytes(keys: Vec<Vec<u8>>) -> CohortConfigProto {
        CohortConfigProto {
            endorser_keys: keys
                .into_iter()
                .map(|k| VerifyingKeyProto {
                    key: Some(VerifyingKeyProtoOneOf::Ecdsa(k)),
                })
                .collect(),
        }
    }

    /// Asserts that uninitialized endorser aliases match exactly.
    fn assert_uninitialized_aliases(
        service: &EndorserService<MockAttester, p256::ecdsa::SigningKey>,
        expected: &[u64],
    ) {
        assert_eq!(service.uninitialized_endorsers.len(), expected.len());
        for (i, alias) in expected.iter().enumerate() {
            assert_eq!(
                service.uninitialized_endorsers[i].alias(),
                *alias,
                "uninitialized endorser at index {i} has wrong alias"
            );
        }
    }
}
