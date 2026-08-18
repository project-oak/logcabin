# Endorser Service

The endorser service crate implements the `EndorserService` interface defined
in `endorser_service.proto` as a MicroRPC service. It wraps the core LogCabin
endorser protocol (from `endorser/core`) and runs inside an Oak Restricted
Kernel enclave application.

Responsibilities:

- **RPC handling**: implements the service RPCs, parsing and validating proto
  messages, routing to the core protocol crate, and translating responses back
  to protos and status codes.
- **Attestation binding**: exposes the TEE attestation evidence and binds the
  core LogCabin protocol to Oak Restricted Kernel attestation by signing each
  endorser's verifying key with the enclave's session key, tying endorser
  identities to the TEE evidence chain.
- **Endorser multiplexing**: hosts multiple independent endorsers in a single
  service instance, possibly but not necessarily part of the same LogCabin
  cohort or instance. Tracks endorsers across all lifecycle states
  (uninitialized, active, finalized).
- **Crash recovery**: allows retrieval of activation and finalization receipts
  via `GetEndorser`, and retains a bounded queue of recently finalized
  endorsers so that receipts lost to coordinator crashes can be recovered.
- **Defence-in-depth constraints**: enforces limits on the number of endorsers,
  ledgers, and cohort size to keep memory and CPU use bounded.
