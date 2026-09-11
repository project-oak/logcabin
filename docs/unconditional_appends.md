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

                       ◄────  tip_receipt (with nonce)  ◄────  entry_receipt
                              block (entry, index, tail)        tip_receipt
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
client-supplied nonce, signed into the tip receipt by the endorser, lets the
client verify that the coordinator actually forwarded the request.

The coordinator returns the **tip receipt** and **block** to the client. The
entry receipt is primarily for the coordinator's own storage (to serve future
`ReadByIndex` requests) — returning it to the client is optional, as the tip
receipt already covers the same ledger state and additionally proves freshness.

## Two Receipt Types

Each append atomically produces two receipts, named for what they prove:

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

### Tip receipt (prefix: `"tip"`)

Proves that the ledger tip is at a specific state at a specific moment.
Nonce-bound.

```
"tip" || instance_id || ledger_id || entry || index || hash_chain_tail || nonce
```

This receipt is **ephemeral**: it proves freshness to the client that supplied
the nonce and is discarded after verification. The same format is produced by
both append and standalone read-latest operations.

## Security Analysis

### Threat model

The coordinator is untrusted. It controls which requests reach the endorsers,
the order of requests, and what gets returned to the client. It cannot forge
endorser signatures (no access to TEE signing keys) or alter signed receipt
contents.

### Anti-replay

The tip receipt is bound to the client's nonce. A malicious coordinator cannot
replay a previous tip receipt because it would be bound to a different nonce,
which the client would detect.

### No nonce leakage

The entry receipt is nonce-free. Stored entry receipts — served via
`ReadByIndex` — contain no per-request metadata. The tip receipt is ephemeral
and never stored.

### Residual risk: nonce collision

The strongest remaining attack requires the coordinator to have stored a
previous request with the **exact same 32-byte payload AND 64-bit nonce**. For K
prior appends of the same payload:

| Prior appends of same payload (K) | Collision probability (K / 2⁶⁴) |
| --------------------------------- | ------------------------------- |
| 1                                 | 5.42 × 10⁻²⁰                    |
| 10⁶                               | 5.42 × 10⁻¹⁴                    |
| 10⁹                               | 5.42 × 10⁻¹¹                    |
| 4.29 × 10⁹ (2³²)                  | 2.33 × 10⁻¹⁰                    |

In practice, most payloads are unique (hashes of attestation evidence, firmware
digests, etc.), making K very small.

### Verifier-side defense: monotonic index check

Even this residual risk is eliminated by a simple verifier-side check: track the
highest index seen per ledger and reject any receipt with an index not strictly
greater than the last seen. A replayed receipt necessarily refers to a past
index that the verifier has already observed, so the check catches it. Combined
with the nonce, the only receipt that could pass both checks would be one at a
never-before-seen index with a matching nonce — which is a genuinely new
receipt, not a replay.

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
