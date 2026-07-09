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

## Build

Requirements:

- Linux
- C compiler
- CMake
- clang with BPF target support
- libbpf development headers

Build and test:

```sh
cmake -B build -S .
cmake --build build
ctest --test-dir build --output-on-failure
```

The build currently produces:

- `build/libqaffinity.a`
- `build/qaffd`
- `build/qaffctl`
- `build/qaff_minimal_control`
- `build/qaff_minimal_registry`
- `build/qaff_reuseport.bpf.o`
- `build/test_quic_parser`

Example parser check:

```sh
build/qaffctl parse c30000000108deadbeefaabbccdd0411223344
```

Expected output:

```text
parse=ok
header=long
version=0x00000001
dcid_len=8
dcid=deadbeefaabbccdd
```

## Current Implementation Status

Implemented:

- Public C headers for parser, registry, worker socket, and BPF loader APIs.
- QUIC DCID parser for long headers and configured-length short headers.
- CID key format shared between user space and BPF.
- libbpf-backed map creation and CID registration helpers.
- libbpf object loader that can reuse `qaffinity` maps and attach the reuseport program to a socket.
- `sk_reuseport` eBPF source that routes long-header and configured-length short-header packets by registered DCID.
- Stats read API for dataplane counters.
- Minimal `qaffd` control plane with Unix socket fd passing for worker registration.
- Parser unit test, privileged reuseport smoke test, and CLI parser command.

Not implemented yet:

- Real QUIC stack integration.
- Graceful reload, worker lifecycle cleanup, and map pinning.
- Routable CID profile.

## Privileged Smoke Test

`reuseport_smoke` creates a multi-worker UDP `SO_REUSEPORT` group, loads the eBPF object, attaches it to the group, registers a CID to one worker, and sends both long-header and short-header QUIC-like packets from explicitly different source ports. It runs the scenario for both IPv4 and IPv6. The expected result is that all packets arrive at the registered worker.

This test needs the kernel capabilities required to create BPF maps and load/attach BPF programs. On systems with `kernel.unprivileged_bpf_disabled=2`, it will be skipped unless run with suitable privileges.

CTest runs the smoke test through `tests/run_reuseport_smoke.sh`. If passwordless `sudo -n setcap` is available, the wrapper restores the test binary capabilities after rebuilds:

```sh
cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep
```

```sh
ctest --test-dir build --output-on-failure -R reuseport_smoke
```

## Control Plane

`qaffd` is the initial privileged control-plane daemon. It loads the BPF object, creates maps, attaches the reuseport program after the first worker socket is registered, and accepts control requests over a Unix domain socket.

Current control operations:

- register worker socket using `SCM_RIGHTS`
- unregister worker socket
- register CID
- retire CID
- read stats
- health check
- read config
- list registered workers
- stop daemon

Example:

```sh
sudo -n setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep build/qaffd
build/qaffd --socket /tmp/qaffd.sock --bpf build/qaff_reuseport.bpf.o --short-cid-len 8 --fallback-worker 0
```

`--fallback-worker` selects the worker socket used when the incoming packet cannot be parsed or its DCID is not registered yet. This is the expected path for the first client Initial, because that DCID is client-generated.

Inspect and stop it with `qaffctl`:

```sh
build/qaffctl stats /tmp/qaffd.sock
build/qaffctl health /tmp/qaffd.sock
build/qaffctl config /tmp/qaffd.sock   # includes short_cid_len, attached, worker_count, fallback_worker_id
build/qaffctl workers /tmp/qaffd.sock
build/qaffctl unregister-worker /tmp/qaffd.sock 2
build/qaffctl stop /tmp/qaffd.sock
```

The `qaffd_control` test starts `qaffd`, registers IPv4 and IPv6 reuseport workers through the control API, registers a CID, verifies hit and fallback routing, unregisters workers, and verifies stale-CID fallback with `worker_missing` accounting.

## Examples

- `qaff_minimal_registry`: embedded mode. The process creates maps, loads BPF, attaches the program, registers workers, and registers CIDs directly.
- `qaff_minimal_control`: daemon-controlled mode. `qaffd` owns BPF setup; the worker-side example creates UDP workers and registers worker sockets/CIDs through the Unix socket control API.
- `qaff_quiche_control_probe`: optional quiche FFI integration probe. It creates a real quiche server connection, registers quiche source CIDs through `qaffd`, and validates the CID lifecycle hook points.
- `qaff_quiche_udp_smoke`: optional real UDP quiche smoke. It sends real quiche packets through Linux UDP sockets, registers the server CID through `qaffd`, switches the client source port, and verifies a dataplane CID hit.

### Optional quiche Probe

The quiche probe is built only when quiche FFI artifacts exist under `third_party/quiche`.

```sh
mkdir -p third_party
git clone --depth 1 https://github.com/cloudflare/quiche.git third_party/quiche
cargo build --manifest-path third_party/quiche/quiche/Cargo.toml \
  --target-dir third_party/quiche/target \
  --features ffi
cmake -B build -S .
cmake --build build
ctest --test-dir build --output-on-failure -R 'quiche_control_probe|quiche_udp_smoke'
```

`third_party/` is ignored by Git. The control probe verifies that server-issued CIDs from a real QUIC stack can be registered through the `qaffd` control plane. The UDP smoke verifies an actual packet path where the first Initial falls back, the server SCID is registered, and a later packet from a different client source port produces a CID-map hit.

## Documentation

- Design bootstrap: [docs/bootstrap.md](docs/bootstrap.md)
- Integration contract: [docs/integration-contract.md](docs/integration-contract.md)
- Control plane plan: [docs/control-plane.md](docs/control-plane.md)
- Implementation plan: [docs/implementation-plan.md](docs/implementation-plan.md)

## Status

MVP implementation in progress. APIs, CID profiles, and repository layout are expected to evolve.
