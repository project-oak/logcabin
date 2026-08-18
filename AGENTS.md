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

# Agent Instructions (AGENTS.md)

Welcome! This file provides critical architectural context, environment information, and instructions for AI coding agents working on the Oak Log Cabin project.

---

## 🌲 The Oak Repository Dependency

The Oak repository (`project-oak/oak`) is a major external dependency of this project. It contains core libraries, schemas, and runtime binaries (such as Stage 0, Restricted Kernel, the Orchestrator, and the Launcher) that this project depends on and integrates with.

### 🔍 How to Find the Oak Repository Path
Because developers may checkout or cache the Oak repository in different locations, **never assume a hardcoded absolute path to Oak**.
Instead, dynamically resolve the absolute path on the host by executing:

```bash
just oak-repo-path
```

### 📋 Using Oak Code & Examples
Whenever prompt instructions, issue descriptions, or task requirements refer to patterns, code, tests, or examples from the Oak repository (e.g., remote attestation logic, serialization formats):
1. **Locate the repository** using `just oak-repo-path`.
2. **Read the corresponding files or directory structures** within that resolved directory.
3. Do not try to guess or search online before checking the local Oak repository checkout.

Specifically, when implementing **cryptographic functionalities**, always reference the Oak repository first. For example, before creating logic to sign a payload, locate the signing and key-provisioning implementations designed specifically for the Oak Restricted Kernel (e.g., searching for `InstanceSigner`).

---

## 🛠️ Environment and Build System

This project uses a deterministic Nix-based development environment and Bazel for builds.

### Nix Dev Shell
The development environment is fully managed via Nix.
- Before running bazel commands, or formatting tools, ensure you are operating within the Nix devShell.
- To run a command under the Nix shell, use `nix develop --command $command`.
- If using tools that execute commands, always verify if they run with Nix available.

### Bazel & Just
- **Bazel** is the primary build tool for compiling Rust targets, enclave applications, and protobuf files.
- **Just** is used as a user-friendly command runner (analogous to `make`). Use the commands defined in the `justfile` for common development workflows.
- This project does NOT use Cargo.

---

## 📐 Key Design Patterns

### `no_std` Compatibility
The entire enclave app, including `endorser/core`, `endorser/service`, and `endorser/enclave_app` is designed for  restricted execution environments (specifically Oak's Restricted Kernel) and must remain **`no_std` compatible**.
- Do not import standard library components (`std::*`) inside the core crate.
- Rely on `core::*` and `alloc::*` for memory and primitive management.

---

## 📝 Copyright Notice

All source files must contain a copyright notice in the correct format for that file type.

Here is an example of the notice format (from the top-level `BUILD` file):

```starlark
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
```
