# Oak Log Cabin

A split-view resistant, tamper-evident ledger system.

By [Ernesto Ocampo](https://github.com/ernoc) · Licensed under the
[Apache License 2.0](LICENSE).

A set of append-only logs whose integrity is collectively endorsed by a quorum
of endorsers, each running in a Trusted Execution Environment (TEE). The
protocol is inspired by [Nimble](https://github.com/microsoft/Nimble)
([paper](https://www.usenix.org/system/files/osdi23-angel.pdf)), with some
[key differences](endorser/core/README.md).

## Security Claims

It is impossible for anyone — service administrators, infrastructure operators,
or external attackers — to create two different views of a ledger that would
both be accepted as valid by relying parties. The only exceptions are
physical-access attacks capable of extracting secrets directly from TEE memory —
where TEE guarantees themselves are broken.

## Architecture

```
                        untrusted
 ┌──────────┐       ┌─────────────┐       ┌──────────────────────────────────┐
 │          │       │             │       │    Endorser (host - untrusted)   │
 │ Verifier │◄─────►│ Coordinator │◄─────►│                                  │
 │          │       │             │       │   ┌──────────────────────────┐   │
 └──────────┘       └──────┬──────┘       │   │          TEE VM          │   │
                           │              │   │                          │   │
                    ┌──────┴──────┐       │   │   ┌──────────────────┐   │   │
                    │    Store    │       │   │   │ Endorser Enclave │   │   │
                    └─────────────┘       │   │   │  App - trusted   │   │   │
                                          │   │   └──────────────────┘   │   │
                                          │   └──────────────────────────┘   │
                                          └──────────────────────────────────┘
```

- **Verifier** — a client-side library that validates endorser receipts against
  a trusted cohort configuration. It verifies quorum, signature validity, and
  ledger state consistency.
- **Coordinator** — an untrusted orchestration layer that routes requests
  between verifiers and endorsers, manages cohort lifecycles (activation,
  finalization, handover), and stores ledger data. _Not yet part of this
  repository._
- **Endorser** — a TEE-hosted enclave application that maintains ledger state
  and produces signed receipts. Each endorser's signing key is bound to the
  TEE's DICE attestation chain, so relying parties can verify that signatures
  were produced by a measured enclave binary.

## Endorser

Each endorser follows a strict lifecycle driven by the coordinator:

1. **Create** — the endorser is instantiated with a fresh signing key.
2. **Activate** — the endorser joins a cohort by verifying finalization receipts
   from the previous cohort (quorum check) and adopting handed-over state.
3. **Append / Read** — entries are appended to ledgers and clients can read the
   latest state, each operation producing a signed receipt.
4. **Finalize** — the endorser is sealed and its finalization receipts are used
   to activate the next cohort.

```
┌──────────────────────────────────┐
│              TEE VM              │
│                                  │
│   ┌──────────────────────────┐   │
│   │   LogCabin Enclave App   │   │
│   │        on Oak RK         │   │
│   │                          │   │
│   │   ┌──────────────────┐   │   │
│   │   │   LogCabin Svc   │   │   │
│   │   │   (micro RPC)    │   │   │
│   │   └──────────────────┘   │   │
│   └──────────────────────────┘   │
└──────────────────────────────────┘
```

## Verifier (Rust)

The verifier is a client-side library that checks endorser receipts against a
trusted cohort configuration. It is a critical part of the protocol's
correctness. If the verifier accepts a receipt, the client can be confident that
a quorum of endorsers agreed on the ledger state.

The verifier also processes cohort handovers to transfer its own trust from one
cohort to the next. It verifies that both the outgoing and incoming cohorts
reached quorum for the transition.

## Crate Structure

```
base/             Shared protocol primitives (CohortConfig, LedgerBlock, receipts)
verifier/rust/    Client-side receipt verification library
endorser/
├── core/         Protocol state machine (no_std, no I/O, pure logic)
├── service/      micro RPC service layer (attestation, endorser multiplexing, RPC handlers)
└── enclave_app/  TEE binary entry point
testing/
├── protocol/     Integration tests exercising endorser and verifier together
└── host_server/  gRPC testing server for local QEMU-based development
```

- `base` contains shared types and receipt message builders used by both the
  endorser and verifier.
- `verifier/rust` verifies endorser receipts against a trusted cohort
  configuration.
- `endorser/core` contains the endorser protocol with no I/O or platform
  dependencies.
- `endorser/service` wraps it as a micro RPC service and binds it to TEE
  attestation.
- `endorser/enclave_app` wires everything together and runs on
  [Oak Restricted Kernel](https://github.com/project-oak/oak).

See each crate's README for details.

## Developing LogCabin

### Prerequisites

- **Nix** — the development environment is fully managed via a Nix flake.
- **Bazel** — the primary build system (provided by the Nix dev shell).

### Quick Start

To verify that everything is working, build and launch the testing gRPC server
on a local QEMU VM:

```
just run-testing-host-server
```

See [testing/host_server/](testing/host_server/README.md) for details.

### Suggested Tools

If using VS Code or Antigravity, install the **direnv** and **Rust Analyzer**
extensions, then run:

```
just regen-rust-project
```

## Disclaimer

This is not an officially supported Google product. This project is not eligible
for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).
