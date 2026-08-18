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
Protocol integration tests exercising the endorser and verifier together.
"""

load("@rules_rust//rust:defs.bzl", "rust_test")

package(
    licenses = ["notice"],
)

rust_test(
    name = "protocol_tests",
    size = "small",
    srcs = ["src/protocol_tests.rs"],
    deps = [
        "//base",
        "//endorser/core",
        "//verifier/rust:verifier",
    ],
)
