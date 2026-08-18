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
This package provides the enclave app implementation for a TEE running the
endorser server. An enclave app is a small, no_std binary that runs on Oak
Restricted Kernel and uses Oak Restricted kernel SDK.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")

package(
    licenses = ["notice"],
)

rust_binary(
    name = "enclave_app",
    srcs = ["src/main.rs"],
    crate_name = "logcabin_endorser_enclave_app",
    platform = "@oak//:x86_64-unknown-none",
    rustc_flags = [
        "--codegen=link-arg=-Wl,-zmax-page-size=0x200000",
        # DO NOT enable soft-float here. It is only intended for the No-AVX
        # toolchain variant in Oak. See @oak//bazel/rust/README.md for details.
    ],
    deps = [
        "//endorser/service",
        "//endorser/service:endorser_micro_rpc_service",
        "@oak//oak_restricted_kernel_sdk",
        "@oak_crates_index//:log",
    ],
)
