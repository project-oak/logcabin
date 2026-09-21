#
# Copyright 2026 The LogCabin Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Worked examples for the in-process split-view challenge.

Kept in a crate of its own so that `#![forbid(unsafe_code)]` and this fixed
dependency set apply to participant code and nothing else.
"""

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//challenge:__subpackages__"],
    licenses = ["notice"],
)

rust_library(
    name = "examples",
    srcs = [
        "src/cross_cohort_fork.rs",
        "src/cross_ledger.rs",
        "src/divergent_handover.rs",
        "src/honest.rs",
        "src/lib.rs",
        "src/naive_fork.rs",
        "src/noop.rs",
        "src/rogue_cohort.rs",
    ],
    crate_name = "logcabin_challenge_examples",
    deps = [
        "//base",
        "//challenge/in_process",
        "//endorser/core",
        "//verifier/rust:verifier",
    ],
)

rust_test(
    name = "tests",
    size = "small",
    crate = ":examples",
)
