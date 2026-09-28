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

# Two-Phase Handover

A handover transfers an instance from its active cohort to a new one; see
[protocol.md §6.5](protocol.md#65-cohort-handover) for the message flow.
LogCabin's handover is a simplification of Nimble's reconfiguration, with these
key differences:

- **2-phase reconfiguration** rather than 3: initialize and activate are folded
  into activate, significantly simplifying the protocol.
- **Linearization at reconfiguration is enforced by the coordinator**, rather
  than by the endorsers, reducing the TCB.
- **Activation does not require every endorser's ledgers**, which drastically
  reduces the amount of data transferred during reconfiguration as the number of
  ledgers scales up. Furthermore, activation does not need an "Appends" (A)
  parameter.

## Nimble's 3-phase protocol

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
_from each ledger_, _from each old endorser_ that finalized at a distinct state.
Plus, the appends argument.

The cohort is effectively unable to process requests (downtime):

- from the moment a majority of old endorsers finalized
- through the whole initialization phase
- until the moment a majority of endorsers have activated

## LogCabin's 2-phase protocol

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

Crucially, it reduces the amount of data transferred for activation: new
endorsers receive the ledger tails exactly once, rather than up to _1 + n_old_
times ([details](#operational-differences)). This enables scaling up the number
of endorsers, which can be critical for reliability.

The property that all new endorsers start from a valid and consistent state is
achieved trivially: most old endorsers must have agreed on exactly that state.
There is no need for an Appends argument.

Regarding downtime, it's similar to original Nimble with a slight improvement:

- Linearization phase (purely coordinator-driven): instance can only process
  read requests
- Finalization: downtime starts when a majority of endorsers have finalized
- Activation: downtime ends with a majority of endorsers have activated.

## Why 2 phases are still safe

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
that the receipts for entry append and read latest cover the instance ID, these
endorsers can't participate in a majority quorum for these operations. If there
is no such majority (e.g. because there are 3 different partitions), then the
instance is rendered permanently unusable. This condition is not detected at
activation time, but can easily be verified and detected by a coordinator
running read_latest immediately after handover.

## Operational differences

|                                                                                                                      | Nimble (3-phase)                                                                                               | LogCabin (2-phase)                                                                                                      |
| -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Finalization data** (worst case)                                                                                   | (1 + n_old) × n_ledgers ledger tails + n_old finalization receipts + n_old public keys + bridging block hashes | n_ledgers ledger tails + n_old finalization receipts + n_old public keys                                                |
| **Handover data transfer** (worst case): finalization data + the new cohort's public keys, sent to each new endorser | O(n_new × (n_old × n_ledgers + n_new))                                                                         | O(n_new × (n_ledgers + n_old + n_new))                                                                                  |
| **Downtime**                                                                                                         | `finalize + initialize + activate` RTTs                                                                        | Coordinator-driven linearization (pause writes, bring a majority of endorsers up to speed) + `finalize + activate` RTTs |
| **Endorser states**                                                                                                  | 4 (`Uninitialized → Initialized → Active → Finalized`)                                                         | 3 (`Uninitialized → Active → Finalized`)                                                                                |
| **TCB size**                                                                                                         | Larger (linearization logic, computing max cut, processing appends, extra state)                               | Smaller (LogCabin core is ~500 lines of Rust excluding comments and tests)                                              |

> [!NOTE]
>
> **Nimble's finalization data** is at its largest when every old endorser
> finalizes at a different state. Nimble de-duplicates equal finalized states,
> so the ledger tails of endorsers that finalized at the same state are only
> sent once, and the number of bridging block hashes depends on how many entries
> apart the old endorsers' finalized states are.
