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
This package provides the definition and implementation of EndorserService,
which is the service exposed by the LogCabin TEE endorser servers.
"""

load("@com_google_protobuf//bazel:proto_library.bzl", "proto_library")
load("@oak//micro_rpc_build:build_defs.bzl", "rust_micro_rpc_service")
load("@oak//oak_grpc_utils:build_defs.bzl", "rust_tonic_grpc_service")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(
    default_visibility = [
        "//endorser/enclave_app:__pkg__",
        "//testing/host_server:__pkg__",
    ],
    licenses = ["notice"],
)

proto_library(
    name = "endorser_service_proto",
    srcs = [
        "endorser_entities.proto",
        "endorser_service.proto",
    ],
    deps = [
        "@oak//proto/attestation:evidence_proto",
        "@oak//proto/micro_rpc:options_proto",
    ],
)

rust_micro_rpc_service(
    name = "endorser_micro_rpc_service",
    srcs = [":endorser_service_proto"],
    extern_paths = {
        ".oak.attestation.v1": "::oak_proto_rust::oak::attestation::v1",
    },
    deps = [
        "@oak//oak_proto_rust",
    ],
)

rust_tonic_grpc_service(
    name = "endorser_grpc_service",
    srcs = [":endorser_service_proto"],
    extern_paths = {
        ".oak.attestation.v1": "::oak_proto_rust::oak::attestation::v1",
    },
    deps = [
        "@oak//oak_proto_rust",
    ],
)

# Build with:
# bazel build //endorser/service --platforms=@oak//:x86_64-unknown-none
rust_library(
    name = "service",
    srcs = [
        "src/lib.rs",
        "src/proto_mapping.rs",
    ],
    crate_name = "logcabin_endorser_service",
    deps = [
        ":endorser_micro_rpc_service",
        "//endorser/core",
        "@oak//micro_rpc",
        "@oak//oak_attestation_types",
        "@oak//oak_crypto",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:log",
        "@oak_crates_index//:p256",
    ],
)

rust_test(
    name = "tests",
    size = "small",
    srcs = [
        "src/lib.rs",
        "src/proto_mapping.rs",
    ],
    deps = [
        ":endorser_micro_rpc_service",
        "//endorser/core",
        "@oak//micro_rpc",
        "@oak//oak_attestation_types",
        "@oak//oak_crypto",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:log",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:rand_core",
    ],
)
