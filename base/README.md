# Base

Shared definitions used by both the core endorser (`endorser/core`) and the Rust
verifier (`verifier/rust`).

## Why this crate exists

A verifying client and an endorser never talk directly to each other — they
communicate through a coordinator service. Nevertheless, they share some
concepts which, at the moment, have equal representations on both ends:

- **`CohortConfig`**: both sides must derive the same config ID from a key set.
- **`LedgerBlock`**: the entry, index, and hash chain tail of a ledger.
- **Receipt message builders**: the wire format of signed messages must be
  byte-identical on both sides for signature verification to succeed.

## Design philosophy

**Reuse is not a goal in itself.** We only share code here as long as it is
convenient and does not constrain either consumer.

The endorser and verifier run in very different contexts:

- The **endorser enclave app** runs in a TEE on Oak Restricted Kernel. It is
  strictly `no_std` and runs on specific hardware.
- The **verifying client** may run on server infrastructure or on end-user
  devices across a variety of platforms (e.g., Linux, Android). It may
  eventually be implemented in languages other than Rust (e.g., Python).

Because of these differences, the bar to split a type or function out of this
crate, giving each consumer its own copy tailored to its needs, should be **very
low**. If a shared definition starts requiring feature flags, conditional
compilation, or compromises to satisfy both sides, it should be duplicated
rather than forced to fit.
