# Host Testing gRPC Server

A testing helper that launches the endorser enclave app in a VM and exposes
it as a gRPC server. It's thin shim that relays gRPC requests to the enclave's
micro RPC service and translates the responses back. Its purpose is to make it
easy to exercise the full enclave stack from standard gRPC tooling.

```
┌──────────────────────────────────────┐
│            Host Machine              │
│                   │                  │
│                   │ gRPC             │
│                   ▼                  │
│   ┌──────────────────────────────┐   │
│   │    Testing gRPC Server       │   │
│   └───────────────┬──────────────┘   │
│                   │ microRPC         │
│   ┌───────────────│──────────────┐   │
│   │       VM      │              │   │
│   │               │              │   │
│   │   ┌───────────▼──────────┐   │   │
│   │   │      Enclave App     │   │   │
│   │   │                      │   │   │
│   │   │  ┌────────────────┐  │   │   │
│   │   │  │  LogCabin Svc  │  │   │   │
│   │   │  └────────────────┘  │   │   │
│   │   └──────────────────────┘   │   │
│   └──────────────────────────────┘   │
└──────────────────────────────────────┘
```

You can launch this gRPC server on a local **QEMU** VM with:

```
just run-testing-host-server
```