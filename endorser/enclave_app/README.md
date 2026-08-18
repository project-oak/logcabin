# Enclave App

This crate defines the enclave application binary that runs inside a Trusted
Execution Environment (TEE) on the Oak Restricted Kernel. It serves as the
TEE app entry points, sets up attestation evidence and starts the micro RPC
server for the LogCabin service.
