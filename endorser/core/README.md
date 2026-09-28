# Endorser Core

The core crate implements the endorser state machine: a `no_std`-compatible
library that manages append-only ledgers, signs receipts with ECDSA P-256, and
enforces lifecycle transitions at compile time via the typestate pattern.
Features:

- **Typestate lifecycle**: `Uninitialized → Active → Finalized`, with
  state-specific data and methods enforced by the type system.
- **Append-only ledgers**: each ledger tracks an entry, a monotonic index, and a
  SHA-256 hash chain tail.
- **Signed receipts**: activation, ledger creation, entry append, read, and
  finalization operations each produce a verifiable ECDSA P-256 signature over a
  structured message.
- **Cohort handover**: supports reconfiguration by verifying finalization
  receipts from the previous cohort (quorum check) and adopting the handed-over
  ledger state.
- **Key hygiene**: the signing key is heap-allocated (`Box<SigningKey>`) and
  moved (not copied) across state transitions; `ZeroizeOnDrop` securely erases
  it when the endorser is finalized.
- **`no_std` compatible**: relies only on `core` and `alloc`, suitable for
  deployment inside Oak's Restricted Kernel.

The crate implements the protocol specified in
[docs/protocol.md](../../docs/protocol.md), which also summarizes how LogCabin
differs from [Nimble](https://github.com/microsoft/Nimble)
([§13](../../docs/protocol.md#13-differences-from-nimble)).

## Cohort handover

The endorser hands an instance over to a new cohort in two phases — finalize,
then activate — rather than Nimble's three. Because the coordinator brings a
majority of the outgoing cohort to one identical state before finalizing, an
incoming endorser only has to verify that a majority finalized for exactly that
state and for its own config before adopting it: the endorser needs no
initialize phase and no logic to reconcile divergent states, and it receives the
ledger tails only once. See
[docs/two_phase_handover.md](../../docs/two_phase_handover.md) for the design,
the safety argument, and a comparison with Nimble.

## Unconditional appends

Clients append _unconditionally_: they send only an entry and a nonce, never the
index it should land at — the coordinator resolves the `expected_index` that
endorsers check. `AppendEntry` and `ReadLatest` each sign two receipts over the
same block: a timeless entry receipt (prefix `"entry"`), which the coordinator
stores to serve `ReadByIndex`, and a nonce-bound receipt (`"append_entry"` or
`"read_latest"`) that proves to the client that the operation was freshly
executed. See
[docs/unconditional_appends.md](../../docs/unconditional_appends.md) for the
design and security analysis.
