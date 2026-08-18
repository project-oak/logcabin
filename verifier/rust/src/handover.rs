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

//! Cohort finalization, activation, and handover types.
//!
//! These types represent the data exchanged during a cohort handover:
//! finalization receipts from the outgoing cohort and activation receipts
//! from the incoming cohort.

use core::ops::Deref;
use logcabin_base::{
    receipts, CohortConfig, CohortData, CohortFinalization, EndorserData, EndorserFinalization,
    InvalidConfigError,
};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::Signature;

// ---------------------------------------------------------------------------
// Cohort activation data
//
// Note that endorsers themselves don't verify other endorsers' activation.
// Thus, cohort activation data is relevant only to the end verifier.
// ---------------------------------------------------------------------------

/// Activation receipt from a single endorser in the incoming cohort.
pub type EndorserActivation = EndorserData<Signature>;

/// Cohort activation data: receipts from the incoming cohort confirming
/// they have adopted the handed-over state.
pub struct CohortActivation {
    /// Activation data from each endorser, in strict ascending
    /// SEC1-lexicographic order of their keys.
    endorser_data: CohortData<Signature>,
}

impl CohortActivation {
    /// Creates a new `CohortActivation`.
    ///
    /// Returns `Err` if the endorser keys are not in strict ascending
    /// SEC1-lexicographic order.
    pub fn try_new(
        endorser_activations: impl IntoIterator<Item = EndorserActivation>,
    ) -> Result<Self, InvalidConfigError> {
        let endorser_data = CohortData::try_new(endorser_activations)?;
        Ok(Self { endorser_data })
    }

    /// Returns the config ID of the new (activated) cohort.
    ///
    /// Computed as the SHA-256 hash of the concatenated SEC1-encoded
    /// endorser verifying keys, in their canonical order.
    pub(crate) fn new_config_id(&self) -> [u8; 32] {
        self.endorser_data.config_id()
    }
}

impl Deref for CohortActivation {
    type Target = [EndorserActivation];

    fn deref(&self) -> &[EndorserActivation] {
        self.endorser_data.endorsers()
    }
}

impl From<CohortActivation> for CohortConfig {
    fn from(activation: CohortActivation) -> Self {
        activation.endorser_data.into_config()
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Quorum was not met: not enough valid signatures.
#[derive(Debug)]
pub struct QuorumError {
    /// Number of valid signatures received.
    pub valid: usize,
    /// Number of valid signatures required.
    pub required: usize,
}

/// Error returned by [`CohortHandover::verify`] and
/// [`Verifier::apply_handover`](crate::Verifier::apply_handover).
#[derive(Debug)]
pub enum HandoverError {
    /// The finalization's endorser keys do not match the verifier's trusted
    /// config. Only returned by
    /// [`Verifier::apply_handover`](crate::Verifier::apply_handover), never
    /// by [`CohortHandover::verify`].
    FinalizationConfigMismatch,
    /// Not enough valid finalization receipts from the outgoing cohort.
    FinalizationQuorumNotMet(QuorumError),
    /// Not enough valid activation receipts from the incoming cohort.
    ActivationQuorumNotMet(QuorumError),
}

// ---------------------------------------------------------------------------
// Cohort handover bundle
// ---------------------------------------------------------------------------

/// A complete cohort handover: bundles finalization receipts from the outgoing
/// cohort, activation receipts from the incoming cohort, and the ledgers hash
/// that both sides must agree on.
///
/// The verifier uses this to verify and evolve its trusted config. The
/// instance ID is not included because the verifier already knows it.
pub struct CohortHandover {
    /// Finalization receipts from the outgoing cohort.
    pub finalization: CohortFinalization,
    /// Activation receipts from the incoming cohort.
    pub activation: CohortActivation,
    /// SHA-256 hash of the serialized ledger state at finalization.
    pub ledgers_hash: [u8; 32],
}

impl CohortHandover {
    /// Creates a new `CohortHandover`.
    ///
    /// Returns `Err(InvalidConfigError)` if the finalization or activation
    /// endorser keys are not in strict ascending SEC1-lexicographic order.
    pub fn try_new(
        finalization_entries: impl IntoIterator<Item = EndorserFinalization>,
        activation_entries: impl IntoIterator<Item = EndorserActivation>,
        ledgers_hash: [u8; 32],
    ) -> Result<Self, InvalidConfigError> {
        let finalization = CohortData::try_new(finalization_entries)?;
        let activation = CohortActivation::try_new(activation_entries)?;
        Ok(Self {
            finalization,
            activation,
            ledgers_hash,
        })
    }

    /// Verifies the handover's internal validity for a given instance_id.
    ///
    /// Derives the previous cohort's config ID from the finalization
    /// endorser keys and checks:
    /// 1. A strict majority of the outgoing cohort signed valid
    ///    finalization receipts.
    /// 2. A strict majority of the incoming cohort signed valid
    ///    activation receipts.
    ///
    /// This validates the handover's internal consistency. It does NOT
    /// check whether the finalization cohort matches the currently trusted
    /// cohort — that is the caller's responsibility (e.g.,
    /// [`Verifier::apply_handover`](crate::Verifier::apply_handover)).
    ///
    /// On success, consumes the handover and returns the new
    /// [`CohortConfig`].
    pub fn verify(self, instance_id: &[u8; 32]) -> Result<CohortConfig, HandoverError> {
        let prev_config_id = self.finalization.config_id();
        let new_config_id = self.activation.new_config_id();

        // Step 1: Verify finalization receipts from the outgoing cohort.
        let finalize_message = receipts::build_finalize_message(
            instance_id,
            &prev_config_id,
            &new_config_id,
            &self.ledgers_hash,
        );

        let finalization_valid_count =
            self.finalization
                .endorsers()
                .iter()
                .filter(|entry| {
                    entry.maybe_receipt.as_ref().is_some_and(|sig| {
                        entry.endorser_key.verify(&finalize_message, sig).is_ok()
                    })
                })
                .count();

        let finalization_total = self.finalization.len();
        if finalization_valid_count * 2 <= finalization_total {
            return Err(HandoverError::FinalizationQuorumNotMet(QuorumError {
                valid: finalization_valid_count,
                required: finalization_total / 2 + 1,
            }));
        }

        // Step 2: Verify activation receipts from the incoming cohort.
        let activate_message = receipts::build_activate_from_prev_message(
            instance_id,
            &prev_config_id,
            &new_config_id,
            &self.ledgers_hash,
        );

        let activation_valid_count =
            self.activation
                .iter()
                .filter(|entry| {
                    entry.maybe_receipt.as_ref().is_some_and(|sig| {
                        entry.endorser_key.verify(&activate_message, sig).is_ok()
                    })
                })
                .count();

        let activation_total = self.activation.len();
        if activation_valid_count * 2 <= activation_total {
            return Err(HandoverError::ActivationQuorumNotMet(QuorumError {
                valid: activation_valid_count,
                required: activation_total / 2 + 1,
            }));
        }

        // Both quorums met.
        Ok(self.activation.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use logcabin_base::receipts;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{SigningKey, VerifyingKey};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Generates `n` signing keys with their verifying keys sorted in
    /// SEC1-lexicographic order. Returns `(signing_keys, verifying_keys)`.
    fn sorted_key_pairs(n: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
        let mut pairs: Vec<(SigningKey, VerifyingKey)> = (0..n)
            .map(|_| {
                let sk = SigningKey::random(&mut rand_core::OsRng);
                let vk = *sk.verifying_key();
                (sk, vk)
            })
            .collect();
        pairs.sort_by(|a, b| {
            a.1.to_sec1_bytes()
                .as_ref()
                .cmp(b.1.to_sec1_bytes().as_ref())
        });
        pairs.into_iter().unzip()
    }

    /// A test setup for handover verification scenarios (no Verifier needed).
    struct HandoverSetup {
        old_sks: Vec<SigningKey>,
        old_vks: Vec<VerifyingKey>,
        new_sks: Vec<SigningKey>,
        new_vks: Vec<VerifyingKey>,
        instance_id: [u8; 32],
        ledgers_hash: [u8; 32],
    }

    impl HandoverSetup {
        /// Creates a 3-endorser old cohort and 3-endorser new cohort.
        fn new() -> Self {
            let (old_sks, old_vks) = sorted_key_pairs(3);
            let (new_sks, new_vks) = sorted_key_pairs(3);
            let old_config = CohortConfig::try_from_keys(old_vks.clone()).unwrap();
            let instance_id = old_config.config_id();
            let ledgers_hash = {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(&(1u32).to_be_bytes());
                hasher.update(&(0u32).to_be_bytes());
                hasher.update(&[0xAA; 32]);
                hasher.update(&42u64.to_be_bytes());
                hasher.update(&[0xBB; 32]);
                hasher.finalize().into()
            };
            Self {
                old_sks,
                old_vks,
                new_sks,
                new_vks,
                instance_id,
                ledgers_hash,
            }
        }

        fn old_config_id(&self) -> [u8; 32] {
            CohortConfig::try_from_keys(self.old_vks.clone())
                .unwrap()
                .config_id()
        }

        fn new_config_id(&self) -> [u8; 32] {
            CohortConfig::try_from_keys(self.new_vks.clone())
                .unwrap()
                .config_id()
        }

        /// Signs finalization receipts for the given endorsers (by index).
        fn sign_finalization_receipts(&self, signers: &[usize]) -> Vec<EndorserFinalization> {
            let message = receipts::build_finalize_message(
                &self.instance_id,
                &self.old_config_id(),
                &self.new_config_id(),
                &self.ledgers_hash,
            );
            self.sign_finalization_receipts_with_message(signers, &message)
        }

        /// Signs finalization receipts with a custom message (for mismatch tests).
        fn sign_finalization_receipts_with_message(
            &self,
            signers: &[usize],
            message: &[u8],
        ) -> Vec<EndorserFinalization> {
            self.old_vks
                .iter()
                .enumerate()
                .map(|(i, vk)| EndorserData {
                    endorser_key: *vk,
                    maybe_receipt: if signers.contains(&i) {
                        Some(self.old_sks[i].sign(message))
                    } else {
                        None
                    },
                })
                .collect()
        }

        /// Signs activation receipts for the given endorsers (by index).
        fn sign_activation_receipts(&self, signers: &[usize]) -> Vec<EndorserActivation> {
            let message = receipts::build_activate_from_prev_message(
                &self.instance_id,
                &self.old_config_id(),
                &self.new_config_id(),
                &self.ledgers_hash,
            );
            self.sign_activation_receipts_with_message(signers, &message)
        }

        /// Signs activation receipts with a custom message.
        fn sign_activation_receipts_with_message(
            &self,
            signers: &[usize],
            message: &[u8],
        ) -> Vec<EndorserActivation> {
            self.new_vks
                .iter()
                .enumerate()
                .map(|(i, vk)| EndorserData {
                    endorser_key: *vk,
                    maybe_receipt: if signers.contains(&i) {
                        Some(self.new_sks[i].sign(message))
                    } else {
                        None
                    },
                })
                .collect()
        }

        /// Constructs a valid CohortHandover with just-quorum (2 of 3).
        fn valid_handover(&self) -> CohortHandover {
            let fin_entries = self.sign_finalization_receipts(&[0, 1]);
            let act_entries = self.sign_activation_receipts(&[0, 1]);
            CohortHandover::try_new(fin_entries, act_entries, self.ledgers_hash).unwrap()
        }
    }

    // -----------------------------------------------------------------------
    // CohortHandover::verify tests
    // -----------------------------------------------------------------------

    #[test]
    fn verify_happy_path() {
        let setup = HandoverSetup::new();
        let handover = setup.valid_handover();
        let new_config = handover.verify(&setup.instance_id).unwrap();
        assert!(new_config.keys().eq(setup.new_vks.iter()));
    }

    #[test]
    fn verify_fails_finalization_different_instance_id() {
        let setup = HandoverSetup::new();
        let wrong_instance_id = [0xFF; 32];
        let message = receipts::build_finalize_message(
            &wrong_instance_id,
            &setup.old_config_id(),
            &setup.new_config_id(),
            &setup.ledgers_hash,
        );
        let fin_entries = setup.sign_finalization_receipts_with_message(&[0, 1], &message);
        let act_entries = setup.sign_activation_receipts(&[0, 1]);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        let result = handover.verify(&setup.instance_id);
        assert!(matches!(
            result,
            Err(HandoverError::FinalizationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_finalization_different_prev_config() {
        let setup = HandoverSetup::new();
        let wrong_prev_config_id = [0xFF; 32];
        let message = receipts::build_finalize_message(
            &setup.instance_id,
            &wrong_prev_config_id,
            &setup.new_config_id(),
            &setup.ledgers_hash,
        );
        let fin_entries = setup.sign_finalization_receipts_with_message(&[0, 1], &message);
        let act_entries = setup.sign_activation_receipts(&[0, 1]);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        // Endorsers signed with the wrong prev_config_id. verify() reconstructs
        // the message using finalization.config_id() (the real one), so signatures
        // won't match → quorum not met.
        let result = handover.verify(&setup.instance_id);
        assert!(matches!(
            result,
            Err(HandoverError::FinalizationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_finalization_different_new_config() {
        let setup = HandoverSetup::new();
        let wrong_new_config_id = [0xCC; 32];
        let message = receipts::build_finalize_message(
            &setup.instance_id,
            &setup.old_config_id(),
            &wrong_new_config_id,
            &setup.ledgers_hash,
        );
        let fin_entries = setup.sign_finalization_receipts_with_message(&[0, 1], &message);
        let act_entries = setup.sign_activation_receipts(&[0, 1]);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        // verify() reconstructs the finalize message using activation.new_config_id(),
        // so the signatures won't match.
        let result = handover.verify(&setup.instance_id);
        assert!(matches!(
            result,
            Err(HandoverError::FinalizationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_finalization_ledgers_hash_mismatch() {
        let setup = HandoverSetup::new();
        let wrong_ledgers_hash = [0xDD; 32];
        let fin_message = receipts::build_finalize_message(
            &setup.instance_id,
            &setup.old_config_id(),
            &setup.new_config_id(),
            &wrong_ledgers_hash,
        );
        let fin_entries = setup.sign_finalization_receipts_with_message(&[0, 1], &fin_message);
        let act_entries = setup.sign_activation_receipts(&[0, 1]);
        // Handover carries the wrong hash.
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, wrong_ledgers_hash).unwrap();

        let result = handover.verify(&setup.instance_id);
        // Finalization signatures match (they signed over wrong_ledgers_hash),
        // but the activation message is built with wrong_ledgers_hash (from
        // handover.ledgers_hash), so the activation signatures won't match.
        assert!(matches!(
            result,
            Err(HandoverError::ActivationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_activation_ledgers_hash_mismatch() {
        let setup = HandoverSetup::new();
        let wrong_ledgers_hash = [0xDD; 32];
        let fin_entries = setup.sign_finalization_receipts(&[0, 1]);
        let act_message = receipts::build_activate_from_prev_message(
            &setup.instance_id,
            &setup.old_config_id(),
            &setup.new_config_id(),
            &wrong_ledgers_hash,
        );
        let act_entries = setup.sign_activation_receipts_with_message(&[0, 1], &act_message);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        let result = handover.verify(&setup.instance_id);
        // verify() builds the activation message using handover.ledgers_hash,
        // which is correct. The activation receipts signed the wrong hash.
        assert!(matches!(
            result,
            Err(HandoverError::ActivationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_activation_different_instance_id() {
        let setup = HandoverSetup::new();
        let wrong_instance_id = [0xEE; 32];
        let fin_entries = setup.sign_finalization_receipts(&[0, 1]);
        let act_message = receipts::build_activate_from_prev_message(
            &wrong_instance_id,
            &setup.old_config_id(),
            &setup.new_config_id(),
            &setup.ledgers_hash,
        );
        let act_entries = setup.sign_activation_receipts_with_message(&[0, 1], &act_message);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        let result = handover.verify(&setup.instance_id);
        assert!(matches!(
            result,
            Err(HandoverError::ActivationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_activation_different_prev_config() {
        let setup = HandoverSetup::new();
        let wrong_prev_config_id = [0xAA; 32];
        let fin_entries = setup.sign_finalization_receipts(&[0, 1]);
        let act_message = receipts::build_activate_from_prev_message(
            &setup.instance_id,
            &wrong_prev_config_id,
            &setup.new_config_id(),
            &setup.ledgers_hash,
        );
        let act_entries = setup.sign_activation_receipts_with_message(&[0, 1], &act_message);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        // verify() builds the activation message using finalization.config_id(),
        // which is the real prev_config. The activation receipts signed a different one.
        let result = handover.verify(&setup.instance_id);
        assert!(matches!(
            result,
            Err(HandoverError::ActivationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_activation_extra_endorser_in_prev_config() {
        let setup = HandoverSetup::new();
        let extra_sk = SigningKey::random(&mut rand_core::OsRng);
        let extra_vk = *extra_sk.verifying_key();
        let mut extended_old_vks = setup.old_vks.clone();
        extended_old_vks.push(extra_vk);
        extended_old_vks.sort_by(|a, b| a.to_sec1_bytes().as_ref().cmp(b.to_sec1_bytes().as_ref()));
        let extended_prev_config = CohortConfig::try_from_keys(extended_old_vks).unwrap();

        let fin_entries = setup.sign_finalization_receipts(&[0, 1]);
        let act_message = receipts::build_activate_from_prev_message(
            &setup.instance_id,
            &extended_prev_config.config_id(),
            &setup.new_config_id(),
            &setup.ledgers_hash,
        );
        let act_entries = setup.sign_activation_receipts_with_message(&[0, 1], &act_message);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        let result = handover.verify(&setup.instance_id);
        assert!(matches!(
            result,
            Err(HandoverError::ActivationQuorumNotMet(_))
        ));
    }

    #[test]
    fn verify_fails_activation_different_new_config() {
        let setup = HandoverSetup::new();
        let wrong_new_config_id = [0xBB; 32];
        let fin_entries = setup.sign_finalization_receipts(&[0, 1]);
        let act_message = receipts::build_activate_from_prev_message(
            &setup.instance_id,
            &setup.old_config_id(),
            &wrong_new_config_id,
            &setup.ledgers_hash,
        );
        let act_entries = setup.sign_activation_receipts_with_message(&[0, 1], &act_message);
        let handover =
            CohortHandover::try_new(fin_entries, act_entries, setup.ledgers_hash).unwrap();

        // verify() derives new_config_id from the activation keys.
        // The signatures used a different new_config_id, so they won't verify.
        let result = handover.verify(&setup.instance_id);
        assert!(matches!(
            result,
            Err(HandoverError::ActivationQuorumNotMet(_))
        ));
    }
}
