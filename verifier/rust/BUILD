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
This package provides the LogCabin receipt verifier library.
"""

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

rust_library(
    name = "verifier",
    srcs = [
        "src/handover.rs",
        "src/ledger_receipts.rs",
        "src/lib.rs",
    ],
    crate_name = "logcabin_verifier",
    deps = [
        "//base",
        "@oak_crates_index//:p256",
    ],
)

rust_test(
    name = "tests",
    size = "small",
    crate = ":verifier",
    deps = [
        "@oak_crates_index//:p256",
        "@oak_crates_index//:rand_core",
        "@oak_crates_index//:sha2",
    ],
)
