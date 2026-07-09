# quic-affinity

`quic-affinity` is a Linux worker-affinity layer for QUIC servers.

It routes incoming QUIC packets to the worker process that owns the connection, even when the client address or port changes because of NAT rebinding or connection migration. The project is intended to be QUIC-stack neutral: NGINX, quiche, quic-go, MsQuic, ngtcp2, and custom servers should be able to integrate without each project writing its own eBPF routing layer.

## Problem

QUIC connections are identified by connection IDs, not by the UDP 4-tuple. On Linux, a multi-process UDP server often uses `SO_REUSEPORT` to distribute packets across workers. The default kernel distribution does not understand QUIC connection IDs, so a client address or port change can cause packets for an existing QUIC connection to arrive at a different worker.

That worker usually does not own the connection state. Common outcomes are packet loss, user-space forwarding between workers, or incorrect stateless reset behavior.

## Goals

- Route QUIC packets by Destination Connection ID (DCID) before they reach user space.
- Support multiple independent QUIC server implementations.
- Provide stronger general-purpose capabilities than implementation-specific features such as NGINX `quic_bpf`.
- Support connection migration and NAT rebinding without steady-state cross-process forwarding.
- Provide observable routing behavior through counters and diagnostics.
- Offer both stateful CID registration and low-state routable CID profiles.

## Non-Goals

- This is not a QUIC implementation.
- This is not an HTTP/3 reverse proxy.
- This does not replace external load balancers for cross-machine routing.
- This does not make the first client Initial packet server-routable; that packet uses a client-generated DCID and still needs fallback routing.

## Architecture

```text
UDP packet
  -> Linux SO_REUSEPORT eBPF program
  -> parse QUIC header
  -> extract DCID
  -> route by CID map or routable CID profile
  -> select owning worker socket
```

The planned project components are:

- `bpf/`: `BPF_PROG_TYPE_SK_REUSEPORT` dataplane for packet parsing and socket selection.
- `qaffd/`: user-space control-plane daemon for worker registration, CID map management, lifecycle cleanup, and metrics.
- `libqaffinity/`: stable C ABI for QUIC servers.
- `bindings/`: language bindings for Rust, Go, and C++.
- `examples/`: integration examples for common QUIC stacks.
- `tests/`: migration and NAT rebinding test scenarios.

## Routing Modes

### Stateful CID Registry

The QUIC server registers every server-generated CID with `quic-affinity`.

This mode works with opaque CIDs and is the most compatible option. It has the best privacy properties but requires lifecycle management for active CIDs.

### Routable CID

The QUIC server uses a CID profile that encodes enough routing information for the eBPF program to select a worker without per-CID state.

This mode is better for very high connection counts, but requires the server to adopt a compatible CID format and key/config rotation policy.

## Initial MVP

1. Fixed-length DCID parser for QUIC v1 long and short headers.
2. `SO_REUSEPORT_EBPF` program that routes by a BPF CID-to-worker map.
3. C ABI for worker registration, CID registration, and CID retirement.
4. One integration example using a real QUIC stack.
5. NAT rebinding test: same QUIC connection, changed source port, same worker.
6. Basic counters for CID hits, fallback, parse errors, and selected workers.

## Documentation

The design bootstrap document is in [docs/bootstrap.md](docs/bootstrap.md).

## Status

Pre-implementation bootstrap. APIs, CID profiles, and repository layout are expected to evolve.

