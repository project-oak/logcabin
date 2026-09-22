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

# The LogCabin Split-View Challenge

LogCabin claims that **nobody — not service administrators, infrastructure
operators, or external attackers — can produce two different views of a ledger
that are both accepted as valid by relying parties.**

This directory is an invitation to prove that claim wrong. Run everything with:

```bash
just challenge
```

Needs Nix, Bazel, and a [Project Oak](https://github.com/project-oak/oak)
checkout at `../oak` — see [prerequisites](../README.md#prerequisites).

A first run should report the three targets passing, followed by
`your_attempt` as `1 ignored`: the worked examples all pass, and the starter
attempt stays skipped until you implement it.

## What You're Attacking

- A **ledger** is a hash chain of blocks. A block is `(entry, index,
  hash_chain_tail)`, where the tail commits to everything before it.
- **Endorsers** are TEE state machines that hold ledgers and sign **receipts**
  over blocks. A **cohort** is the set of endorsers a verifier trusts.
- A **`Verifier`** accepts a block only when a **strict majority** of its cohort
  signed that same block; cohorts can be replaced through **handovers**.
- A **view** is just a block some verifier was convinced of.

So splitting the view means convincing two verifiers of two *different* blocks
at the same index of the same ledger.

## Winning & Rules

You **win** (`Outcome::SplitViewAchieved`) if you return two
[`View`](in_process/src/lib.rs)s of the **same `ledger_id` and `index`** but 
differ in `entry` or `hash_chain_tail`.

- **In scope:** Anything reachable through the endorser Rust API. Own, mutate, or
  drop endorsers; send conflicting requests to different subsets; pick any
  nonces; chain handovers across cohorts (including cohorts built from endorsers
  you created yourself — the verifier performs no attestation checks); forge or
  replay receipts.
- **Out of scope:** Extracting signing keys from process memory (`unsafe` Rust,
  `/proc/self/mem`, `ptrace`, core dumps). Endorsers model TEE enclaves whose
  private keys are isolated from the host. Every challenge crate enforces
  `#![forbid(unsafe_code)]`.

Tip: If your two views end up at different indices, bring them to a common one: the
timeless `Verification::Entry` can request any index a cohort still holds, and a
live cohort can always be advanced with another append.

## In-Process Challenge (`in_process/`)

This is **not a realistic production environment** — as a challenger, you get
far more control than any real-world attacker or untrusted coordinator would
ever have. There is no network, no gRPC serving layer, and no coordinator
sitting in between: you hold the `Endorser` state machines directly in memory
and drive them with plain Rust function calls.

That is intentional: **the service layer provides zero security guarantees.**
All split-view resistance comes from the core endorser state machine and the
verifier's quorum rules. A future `over_grpc/` challenge will expose the
network layer for any-language testing.

### How It Works

```
harness                        you                            harness
─────────                      ────                           ─────────
create N endorsers  ────────►  activate, append, read,
(sorted by SEC1)               finalize, hand over …

                               return (view_a, view_b) ─────►  per view:
                                 each with its own               Verifier::new(init_cfg)
                                 handover chain                  apply its handovers
                                                                 verify its receipts
                                                                 compare the two blocks
```

Implement [`Falsifier`](in_process/src/lib.rs):

```rust
pub trait Falsifier {
    /// Defaults to DEFAULT_COHORT_SIZE (3).
    fn cohort_size(&self) -> NonZeroUsize { DEFAULT_COHORT_SIZE }

    fn attempt(self, endorsers: Vec<Endorser<Uninitialized>>) -> (View, View);
}

pub struct View {
    pub handovers: Vec<CohortHandover>,
    pub receipts: LedgerReceipts,
    pub ledger_id: u32,
    pub verification: Verification,
}

pub enum Verification {
    ReadLatest { nonce: u64 },
    Append { entry: EntryContents, nonce: u64 },
    Entry { requested_index: u64 },
}
```

Key properties:

- **Independent handover chains:** Each view carries its own `handovers`, so the
  two views don't have to be verified on the same cohort. For example, View A
  can be verified on Cohort 1 while View B is verified on Cohort 2 after a
  handover, testing whether a new cohort can endorse a different value at an
  index the previous cohort already committed (see
  [`cross_cohort_fork`](in_process/examples/src/cross_cohort_fork.rs)).
- **Independent verifications & nonces:** Each view specifies its own
  `Verification` (`ReadLatest`, `Append`, or timeless `Entry`) and its own
  nonce. The two views don't need to use the same verification type — for
  example, you win if you prove that a `ReadLatest` and an `Append` (or `Entry`)
  verification accept different blocks at the same ledger and index.
- **Your choice of cohort size:** Override `cohort_size` if your attempt needs a
  specific shape (see
  [`divergent_handover`](in_process/examples/src/divergent_handover.rs)). Only the initial cohort
  is affected — successor cohorts you build yourself can be any size.
- **Verification:** The harness constructs both `Verifier`s itself from
  the initial config and evolves them strictly via `apply_handover`. You can
  still instantiate your own `Verifier` inside `attempt` to pre-check your views.

> [!IMPORTANT]
> Endorsers are handed to you sorted by SEC1 verifying-key bytes, where
> `endorsers[i]` corresponds to `key_index == i` in the verifier's config. Keep
> them in that order when building `LedgerReceipt`s.

### Getting started

[`in_process/your_attempt/`](in_process/your_attempt/) is a starter package with
everything already wired up. Fill in `attempt()`, remove the `#[ignore]` from
its test, and run `just challenge`.

A complete (if useless) attempt is only this much code — it hands back two empty
views, which the verifier rejects:

```rust
pub struct Noop;

impl Falsifier for Noop {
    fn attempt(self, _endorsers: Vec<Endorser<Uninitialized>>) -> (View, View) {
        let empty = || View {
            handovers: Vec::new(),
            receipts: LedgerReceipts::new([]),
            ledger_id: 0,
            verification: Verification::ReadLatest { nonce: 1 },
        };
        (empty(), empty())
    }
}
```

[`logcabin_challenge::util`](in_process/src/util.rs) contains optional
helpers for driving endorsers - they use the same API you have. Each fallible
helper comes in two flavours: `foo` returns a `Result` you can inspect, and
`must_foo` panics on failure.

### Examples

Seven worked attempts live in
[`in_process/examples/src/`](in_process/examples/src/). All of them fail — each
asserts the exact outcome it produces, so they double as regression tests.

| Example | Attack Idea | Result |
|---|---|---|
| [`noop`](in_process/examples/src/noop.rs) | Minimal template returning empty receipts. | `ViewRejected(NoReceipts)` |
| [`honest`](in_process/examples/src/honest.rs) | End-to-end smoke test: append once, then read it back via `ReadLatest` and via `Entry`. | `ViewsAgree` |
| [`cross_ledger`](in_process/examples/src/cross_ledger.rs) | Append different entries to two ledgers at the same index. | `NotAFork(DifferentLedger)` |
| [`naive_fork`](in_process/examples/src/naive_fork.rs) | Append `X` to 2 endorsers and `Y` to the 3rd. | `ViewRejected(QuorumNotMet)` |
| [`cross_cohort_fork`](in_process/examples/src/cross_cohort_fork.rs) | Compare cohort `N` against cohort `N+1` after handover. | `ViewsAgree` |
| [`divergent_handover`](in_process/examples/src/divergent_handover.rs) | On a non-default 5-endorser cohort, finalize 3 endorsers toward successor `P` and 2 toward `Q`. | `HandoverRejected(FinalizationQuorumNotMet)` |
| [`rogue_cohort`](in_process/examples/src/rogue_cohort.rs) | Hand over to a challenger-created cohort and append. | `NotAFork(DifferentIndex)` |

Activation creates ledger `0` only; `cross_ledger` and `cross_cohort_fork` show
how to create and use other ledger IDs.

To verify that the harness can detect split views, the unit tests in
[`in_process/src/lib.rs`](in_process/src/lib.rs) construct a genuine fork across
two independent single-endorser instances and assert that `evaluate_split()`
reports `Outcome::SplitViewAchieved`.

## Submitting

1. Implement `attempt()` in [`in_process/your_attempt/`](in_process/your_attempt/)
   and remove the `#[ignore]` from its test.
2. Run `just challenge`.
3. **If you found a genuine break**, do not open a public issue — follow
   [`SECURITY.md`](../SECURITY.md) so we can coordinate disclosure.
4. **Otherwise**, send us the attempt: see [`CONTRIBUTING.md`](../CONTRIBUTING.md)
   for the CLA and pull request process. Even failed but interesting attempts are
   valuable regression tests!
