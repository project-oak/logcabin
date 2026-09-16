<!--
  Copyright 2026 The LogCabin Authors

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# Unconditional Appends

## Introduction

The [Nimble](https://github.com/microsoft/Nimble) protocol provides a
tamper-proof append-only ledger backed by a cohort of endorsers running inside
trusted execution environments (TEEs). Clients append entries, and endorsers
sign receipts that cryptographically prove each entry's position in a hash
chain.

In the original protocol, every append operation requires the client to supply
an `expected_height` — the index at which the client expects its entry to land.
The endorser verifies this prediction against its current state and rejects the
append if the index doesn't match. This serves as an implicit form of replay
protection: a receipt at a specific index can only be produced once.

This design works well when the client and coordinator are co-located or when
contention is low. However, in distributed deployments where the client may be
far from the coordinator infrastructure (e.g., a mobile device or a remote
service), this creates a practical challenge.

## The Challenge: Conditional Appends Under Contention

To append an entry, a remote client must:

1. Query the coordinator for the current ledger height
2. Submit the append with `expected_height = height + 1`

Between steps 1 and 2, other clients may have appended entries, advancing the
height. The client's `expected_height` is now stale, and the append is rejected.
The client must retry — querying again, racing again, in a loop.

This time-of-check-to-time-of-use (TOCTOU) race worsens under contention: with N
concurrent clients, the expected number of retries grows, and throughput
degrades.

The Nimble paper recognises a related concern and proposes an
`append_with_read_latest` operation that atomically combines an append with a
read of the current ledger state. This is a valuable insight: it means the
endorser can produce a freshness proof (a _read_ receipt bound to a
client-supplied nonce) alongside the append receipt, in a single atomic step.

LogCabin builds on this idea by observing that `expected_height` resolution can
be moved entirely to the coordinator layer, eliminating the TOCTOU for remote
clients while preserving the endorser-level safety properties.

## Three-Layer Architecture

The key insight is that `expected_index` and the client's nonce serve orthogonal
purposes at different trust boundaries:

```
 Client (remote)              Coordinator (untrusted)           Endorser (TEE)
 ─────────────────           ────────────────────────           ──────────────────
 Append(entry, nonce)  ────►  resolve expected_index     ────►  AppendEntry(
                              from own storage                    entry,
                                                                  expected_index,
                              fan out to all endorsers            nonce)

                       ◄────  append_receipt (with nonce) ◄────  entry_receipt
                              block (entry, index, tail)         append_receipt
                                                                block
                              coordinator stores
                              entry_receipt for
                              later ReadByIndex
```

**`expected_index`** is an internal consistency mechanism between the
coordinator and endorsers. The coordinator serialises appends and knows the
current height. It resolves the correct `expected_index` before forwarding to
endorsers. The client never needs to know or supply it.

**`nonce`** is a client-facing replay protection mechanism. The coordinator is
untrusted — it could silently drop a request and replay an old response. The
client-supplied nonce, signed into the append receipt by the endorser, lets the
client verify that the coordinator actually forwarded and executed the append.
This holds only if the client draws each nonce freshly at random; see
[Anti-replay](#anti-replay--and-the-clients-nonce-obligation) for why a reused
or predictable nonce silently forfeits the guarantee.

The coordinator returns the **append receipt** and **block** to the client. The
entry receipt is primarily for the coordinator's own storage (to serve future
`ReadByIndex` requests) — returning it to the client is optional, as the append
receipt already covers the same ledger state and additionally proves freshness
and that an append operation was performed.

## Three Receipt Types

Each append atomically produces two receipts; `read_latest` produces a third
kind. They are named for what they prove:

### Entry receipt (prefix: `"entry"`)

Proves that an entry exists at a specific position in the hash chain.
Nonce-free.

```
"entry" || instance_id || ledger_id || entry || index || hash_chain_tail
```

This receipt is **timeless**: it describes a permanent fact about the ledger.
The coordinator stores it and serves it via a `ReadByIndex` operation. Because
it contains no per-request metadata, it can be freely shared without leaking
information about the original appending client.

### Append receipt (prefix: `"append_entry"`)

Proves that an append operation was performed, producing the given state.
Nonce-bound.

```
"append_entry" || instance_id || ledger_id || entry || index || hash_chain_tail || nonce
```

This receipt is **ephemeral**: it proves to the client that an `append_entry`
call was actually executed by the endorser, not merely a `read_latest`. The
client verifies it to confirm its operation was performed, and can then discard
it.

### Read-latest receipt (prefix: `"read_latest"`)

Proves that the ledger was at a specific state when queried. Nonce-bound.

```
"read_latest" || instance_id || ledger_id || entry || index || hash_chain_tail || nonce
```

This receipt is also **ephemeral**. It proves freshness for a `read_latest`
call. The distinct prefix ensures it cannot be confused with an append receipt.

## Security Analysis

### Threat model

The coordinator is untrusted. It controls which requests reach the endorsers,
the order of requests, the contents of requests, and what gets returned to the
client. It cannot forge endorser signatures (no access to TEE signing keys) or
alter signed receipt contents.

### Anti-replay — and the client's nonce obligation

The nonce-bound receipt is bound to the client's nonce, so a coordinator cannot
replay a receipt issued for a _different_ nonce.

> [!IMPORTANT] This guarantee is conditional. Clients **must** draw each nonce
> independently at random from a large space (the full 64-bit range, from a
> CSPRNG). Nonce uniqueness and unpredictability are load-bearing: the
> anti-replay property above is void without them.

**Why uniqueness is required.** The signed append message is

```
"append_entry" || instance_id || ledger_id || entry || index || hash_chain_tail || nonce
```

Every field except `index` and `hash_chain_tail` is chosen by the client. So if
a client ever reuses the same `(ledger_id, entry, nonce)` triple, the receipt
from the first append is a _valid receipt for the second request_:

1. Client appends `E` with nonce `N`. Endorsers advance the ledger to index `i`
   and sign a receipt over `… || E || i || T || N`. The coordinator keeps a
   copy.
2. Later the client appends `E` again, reusing nonce `N`.
3. The coordinator never forwards the request. It replays the stored receipt.
4. The client reconstructs the expected message from its own `(E, N)` — which is
   byte-identical to step 1 — so verification **passes**.

The client concludes its second append committed. It never did; the ledger still
sits at index `i`. The replayed receipt does carry the stale `index` and
`hash_chain_tail`, but `verify_append` deliberately does not check the index —
clients are expected to append unconditionally and not track indices — so a
client following the intended pattern has nothing to compare against.

Note the attack needs the _entry_ to repeat as well, since `entry` is in the
signed message. It is therefore most dangerous for idempotent-looking payloads
such as heartbeats, status records, or any fixed sentinel value — precisely the
cases where a client is most tempted to reuse a nonce.

### Operation attestation via distinct prefixes

The nonce-bound receipts use operation-specific prefixes: `"append_entry"` for
appends and `"read_latest"` for reads. This prevents a coordinator from
substituting one operation for the other. Without distinct prefixes, a
coordinator could silently drop a client's append and instead call `read_latest`
with the client's nonce — if the ledger already holds the same payload, the
returned receipt would verify, and the client would incorrectly conclude its
append committed.

With distinct prefixes, the client verifies the nonce-bound receipt against the
expected `"append_entry"` prefix. A receipt signed with the `"read_latest"`
prefix will fail verification for an intended append operation, and vice-versa,
regardless of whether the ledger state matches.

### No nonce leakage

The entry receipt is nonce-free. Stored entry receipts — served via
`ReadByIndex` — contain no per-request metadata. The nonce-bound receipts are
ephemeral and never stored.

## Relationship to the Nimble Paper

The Nimble paper's `append_with_read_latest` is the conceptual foundation of
this design. The paper identifies the key mechanism: atomically producing a read
receipt (with a nonce for freshness) alongside an append, in a single endorser
operation.

LogCabin extends this by moving `expected_index` resolution to the coordinator
layer. In the original protocol, even `append_with_read_latest` requires the
client to supply `expected_height`. In LogCabin's design, the coordinator —
which already serialises appends and knows the current height — resolves the
index internally, exposing only `(entry, nonce)` to the client.

The result is a single round-trip unconditional append for remote clients, with
the same endorser-level safety guarantees as the original protocol.
