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

//! Reference attempts for the LogCabin split-view challenge.
//!
//! Each module implements an attack idea and asserts the exact
//! [`Outcome`](logcabin_challenge::Outcome) it produces.

#![forbid(unsafe_code)]

pub mod cross_cohort_fork;
pub mod cross_ledger;
pub mod divergent_handover;
pub mod honest;
pub mod naive_fork;
pub mod noop;
pub mod rogue_cohort;
