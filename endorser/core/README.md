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

The protocol is inspired by [Nimble](https://github.com/microsoft/Nimble) with
some key differences:

- **2-phase reconfiguration** rather than 3: initialize and activate are folded
  into activate, significantly simplifying the protocol.
- **Linearization at reconfiguration is enforced by the coordinator**, rather
  than by the endorsers, reducing the TCB.
- **Activation does not require every endorser's ledgers**, which drastically
  reduces the amount of data transferred during reconfiguration as the number of
  ledgers scales up. Furthermore, activation does not need an "Appends" (A)
  parameter.

## Simpler reconfigurations

### Nimble's 3-phase protocol

Nimble reconfigures endorsers in three sequential phases:

1. **Finalize** — each old endorser freezes its state, returns its ledger tails
   and a signed finalization receipt, and erases its signing key.
2. **Initialize** — each new endorser receives the target state M (the `max_cut`
   of the finalized states), stores it, and returns a signed commitment. This is
   a one-shot operation: once initialized, the endorser cannot be re-initialized
   with a different state.
3. **Activate** — each new endorser verifies that (a) a quorum of old endorsers
   finalized, and (b) a quorum of new endorsers initialized with the same M.
   Additionally, for each old endorser in the finalization quorum, the new
   endorser receives an Append (A) parameter: a mapping from each ledger ID to a
   sequence of entries that, if appended to that old endorser's finalized state,
   would arrive at the new endorser's initialized state M. It then transitions
   to Active and begins serving.

The Append parameter handles the case where old endorsers in the finalization
quorum had different states when they finalized. This can happen if some
endorsers are still processing requests while the coordinator is finalizing
others. As a result, endorsers in the finalization quorum sign finalization
receipts for different states. The coordinator computes the "max cut" across all
of ledgers and feeds that as the initial state M for the new endorsers. As some
finalized endorsers may not have all ledgers up to date with the max cut, the
Append parameter bridges this gap, letting each new endorser verify that their
starting state (M) is reachable from the finalized state of each old endorser by
replaying the provided entries.

The 2 phase activation (initialize + activate) serves as a linearization point:
it safely brings all new endorsers to a consistent state.

Endorsers will refuse to activate if they can't verify that a majority of
endorsers in their own cohort have initialized for their own config. If this
quorum can't be reached, the cohort fails to activate and the condition is
detected immediately.

When the number of ledgers scales up, this can have a significant impact on the
amount of data moved between cohorts for reconfiguration. Initializing and
activating an endorser requires delivering _to each new endorser_, the data
_from each ledger_, _from each old endorser_. Plus, the appends argument.

The cohort is effectively unable to process requests (downtime):

- from the moment a majority of old endorsers finalized
- through the whole initialization phase
- until the moment a majority of endorsers have activated

### LogCabin's 2-phase protocol

LogCabin folds Initialize and Activate into a single step:

1. **Finalize** — same as Nimble: old endorsers freeze, sign, and erase.
2. **Activate** — each new endorser receives the finalization receipts from the
   old cohort and the target ledger state. It independently verifies that a
   strict majority of the old cohort signed valid finalization receipts for the
   new config and the given ledger state, then adopts that state and goes live.
   Endorsers sign an activation receipt equivalent to the original
   initialization receipt.

Here, a majority of old endorsers must finalize for _the exact state_. The
coordinator must ensure that endorsers stop processing requests _before_
starting to finalize any of them. This moves the linearization point to before
the handover officially starts, and moves all the protocol complexity and code
away from the trusted endorser, into the untrusted coordinator.

Crucially, it reduces by an order of magnitude the amount of data transferred
for activation: new endorsers only get 1 state, not _1 state per old endorser_.
This enables scaling up the number of endorsers, which can be critical for
reliability.

The property that all new endorsers start from a valid and consistent state is
achieved trivially: most old endorsers must have agreed on exactly that state.
There is no need for an Appends argument.

Regarding downtime, it's similar to original Nimble with a slight improvement:

- Linearization phase (purely coordinator-driven): instance can only process
  read requests
- Finalization: downtime starts when a majority of endorsers have finalized
- Activation: downtime ends with a majority of endorsers have activated.

### Why 2 phases are still safe

In this version of the protocol, upon activation, endorsers will verify that a
majority of old endorsers have finalized in favour of the same new config, and
each new endorser will verify that _it_ is in that new config. So, all new
endorsers agree on what new config the previous cohort finalized _for_.

However, during activation they will _not_ verify that other endorsers in their
own cohort are activating from the same _previous_ config - or activating at
all. I explain here why that does not affect safety - it only affects the time
when the error condition is detected.

Consider 2 different cohorts `c_old_1` and `c_old_2`. When activating cohort
`c_new`, some new endorsers could be given finalization receipts
`c_old_1 --> c_new` and others `c_old_2 --> c_new`. However, by induction, if
cohorts 1 and 2 are both able to produce quorum finalization receipts, then they
must have had different instance IDs. This is because:

- The instance ID of a brand new cohort (no handover) is the hash of its
  verification keys
- A cohort can pass its instance ID to 1 and only 1 subsequent cohort.

Correct LogCabin and Nimble code enforce this rule. Clearly, wrong/bad endorser
code can be run that does not adhere to this rule and create a split - but that
is a) already true in original Nimble and b) detectable in the
finalization/activation trail if the TEE endorser attestations are kept.

Because some members of `c_new` have adopted a different instance ID, and given
that the receipts for entry append and tip (read latest) cover the instance ID, these
endorsers can't participate in a majority quorum for these operations. If there
is no such majority (e.g. because there are 3 different partitions), then the
instance is rendered permanently unusable. This condition is not detected at
activation time, but can easily be verified and detected by a coordinator
running read_latest immediately after handover.

### Operational differences

|                     | Nimble (3-phase)                                                                 | LogCabin (2-phase)                                                                                                      |
| ------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Data transfer**   | O(new_endorsers × old_endorsers × n_ledgers)                                     | O(new_endorsers × (old_endorsers + n_ledgers))                                                                          |
| **Downtime**        | `finalize + initialize + activate` RTTs                                          | Coordinator-driven linearization (pause writes, bring a majority of endorsers up to speed) + `finalize + activate` RTTs |
| **Endorser states** | 4 (`Uninitialized → Initialized → Active → Finalized`)                           | 3 (`Uninitialized → Active → Finalized`)                                                                                |
| **TCB size**        | Larger (linearization logic, computing max cut, processing appends, extra state) | Smaller (LogCabin core is ~500 lines of Rust excluding comments and tests)                                              |

## Unconditional appends

In the original Nimble protocol, every append requires the client to supply an
`expected_height` — the index at which the client expects its entry to land. The
endorser rejects the append if the prediction doesn't match. This creates a
time-of-check-to-time-of-use (TOCTOU) race when the client is remote from the
coordinator infrastructure: between discovering the current height and
submitting the append, other clients may have advanced the height.

LogCabin addresses this by separating `expected_index` from the client-facing
API. The coordinator — which already serialises appends and knows the current
height — resolves `expected_index` internally before forwarding to endorsers.
The client supplies only the entry and a random nonce.

The endorser's `AppendEntry` operation accepts a nonce and atomically produces
two receipts over the same post-append state:

- An **entry receipt** (nonce-free), proving the entry is committed at a
  specific index. This receipt is stored by the coordinator and served via
  `ReadByIndex`.
- A **tip receipt** (nonce-bound), proving the ledger tip is at this state
  right now. This receipt is ephemeral — the client uses it to verify that the
  coordinator actually forwarded the request (preventing replay), then discards
  it.

The `ReadLatest` operation also produces both receipt types. This allows a
coordinator to recover an entry receipt that was lost (e.g., after a crash
between the endorser response and the coordinator persisting it to storage).

See [`docs/unconditional_appends.md`](../../docs/unconditional_appends.md) for
the full design and security analysis.

### Receipt terminology

LogCabin uses two receipt types, named for what they prove rather than the
operation that produced them:

| Receipt | Prefix     | Nonce? | Purpose                                                          |
| ------- | ---------- | ------ | ---------------------------------------------------------------- |
| Entry   | `"entry"`  | No     | Proves an entry exists at a specific index. Timeless and stored. |
| Tip     | `"tip"`    | Yes    | Proves the ledger tip is here right now. Ephemeral.              |

This replaces the original Nimble naming:
- `"append_entry"` → `"entry"` (the receipt is about the entry, not the
  operation)
- `"read_latest"` → `"tip"` (the receipt is about the current tip, not the
  read operation)

Both receipt types share the same base fields (`instance_id`, `ledger_id`,
`entry`, `index`, `hash_chain_tail`). The tip receipt appends the nonce.

### Differences from Nimble (operations)

|                     | Nimble                                                     | LogCabin                                                                                   |
| ------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| **Append**          | Client must supply `expected_height`                       | `expected_index` resolved by coordinator; client supplies nonce                             |
| **Atomic append + read** | Described in the paper; not in the reference implementation | Integrated at the endorser level (both `AppendEntry` and `ReadLatest` produce entry + tip receipts) |
| **Receipt prefixes** | N/A (Nimble uses opaque hashes for signing)                | `"entry"` (nonce-free, stored) and `"tip"` (nonce-bound, ephemeral)                         |
