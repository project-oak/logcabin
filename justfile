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

# This file is conceptually similar to a Makefile, but uses the `just` tool, which has a more reasonable syntax.
#
# See:
#
# - https://github.com/casey/just
# - https://just.systems/man/en/

# Import justfile.local, if it exists, so that developers can create their own
# justfile commands that might not be generally useful enough to commit to the
# project.
import? "justfile.local"

default:
    @just --list

# --- Dev workflow ---

[doc("Regenerate rust-project.json for rust-analyzer.")]
regen-rust-project:
    bazel run @rules_rust//tools/rust_analyzer:gen_rust_project

[doc("Format all files in the repository.")]
format-all:
    #!/bin/bash
    rustfmt --edition 2021 $(find . -name "*.rs" -not -path "./bazel-*")
    buildifier $(find . -name "BUILD" -o -name "*.bzl" | grep -v bazel-)
    for proto in $(find . -type f -name '*.proto' -not -path './bazel-*' -not -path './.*'); do
        buf format -w "$proto"
    done

preupload: format-all test-all
    echo "Preupload passed; remember to use jj squash && jj cr"

# --- Shared helpers ---

# Resolve the absolute path to the Oak repository from Bazel module metadata.
[private]
oak-repo-path:
    #!/bin/bash
    set -euo pipefail
    oak_rel=$(bazel mod show_repo oak 2>/dev/null | grep 'path =' | sed 's/.*path = "\(.*\)".*/\1/')
    cd "$oak_rel" && pwd

# Build Oak Restricted Kernel artifacts (stage0, kernel, orchestrator, launcher)
# inside the Oak repository using its own justfile.
[private]
oak-rk-artifacts:
    #!/bin/bash
    set -euo pipefail
    oak_path=$(just oak-repo-path)
    echo "Building Oak Restricted Kernel artifacts in: $oak_path"
    cd "$oak_path"
    nix develop --command just run oak-restricted-kernel-launcher-artifacts

# --- Build recipes ---

export-enclave-app out_path:
    bazel build //endorser/enclave_app
    cp --force --preserve=timestamps --no-preserve=mode $(bazel cquery //endorser/enclave_app --output files) "{{out_path}}"

# --- Test recipes ---

test-all:
    bazel test //...:all

# --- Run recipes ---

[doc("""
Run the endorser enclave app on QEMU via the Oak Restricted Kernel.

Builds all required Oak artifacts (stage0, restricted kernel, orchestrator,
launcher) in the Oak repo first, then builds the endorser enclave app locally
and launches QEMU. To enable logging, prefix your command with RUST_LOG=debug.
""")]
run-enclave-app-on-qemu:
    #!/bin/bash
    set -euo pipefail

    oak_path=$(just oak-repo-path)

    if [ ! -f "$oak_path/artifacts/binaries/oak_restricted_kernel_launcher" ]; then
        echo "Stage0 launcher not found. Building Oak Restricted Kernel artifacts..."
        just oak-rk-artifacts
    fi

    chmod +x "$oak_path/artifacts/binaries/oak_restricted_kernel_launcher"
    bazel build //endorser/enclave_app
    RUST_LOG=DEBUG "$oak_path/artifacts/binaries/oak_restricted_kernel_launcher" \
        --bios-binary="$oak_path/artifacts/binaries/stage0_bin" \
        --kernel="$oak_path/artifacts/binaries/oak_restricted_kernel_wrapper_virtio_console_channel_bin" \
        --vmm-binary=$(which qemu-system-x86_64) \
        --app-binary=$(bazel cquery //endorser/enclave_app --output files) \
        --initrd="$oak_path/artifacts/binaries/oak_orchestrator" \
        --memory-size=256M

[doc("""
Run the testing host server that bridges gRPC to the enclave app.
""")]
run-testing-host-server:
    #!/bin/bash
    set -euo pipefail

    oak_path=$(just oak-repo-path)

    if [ ! -f "$oak_path/artifacts/binaries/oak_restricted_kernel_launcher" ]; then
        echo "Stage0 launcher not found. Building Oak Restricted Kernel artifacts..."
        just oak-rk-artifacts
    fi

    bazel build //endorser/enclave_app

    RUST_LOG=DEBUG bazel run //testing/host_server -- \
        --bios-binary="$oak_path/artifacts/binaries/stage0_bin" \
        --kernel="$oak_path/artifacts/binaries/oak_restricted_kernel_wrapper_virtio_console_channel_bin" \
        --app-binary=$(realpath $(bazel cquery //endorser/enclave_app --output files)) \
        --vmm-binary=$(which qemu-system-x86_64) \
        --initrd="$oak_path/artifacts/binaries/oak_orchestrator" \
        --memory-size=256M

invoke-grpc-local method request:
    grpcurl \
        -plaintext \
        -import-path . \
        -import-path $(just oak-repo-path) \
        -proto endorser/service/endorser_service.proto \
        -d '{{request}}' \
        '[::1]:50051' \
        logcabin.proto.EndorserService/{{method}}
