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
Starter package for a new challenge attempt. Edit src/lib.rs; nothing here
needs changing. The deps are deliberately wider than the empty body uses, so
an attempt can reach for any of them without touching this file.
"""

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = ["//challenge:__subpackages__"],
    licenses = ["notice"],
)

rust_library(
    name = "your_attempt",
    srcs = ["src/lib.rs"],
    crate_name = "logcabin_challenge_your_attempt",
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
    crate = ":your_attempt",
)
