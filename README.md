# quic-affinity

`quic-affinity` is a Linux worker-affinity layer for QUIC servers.

It makes `SO_REUSEPORT` understand QUIC connection IDs. When a client's IP
address or UDP source port changes because of NAT rebinding or connection
migration, packets can still reach the worker process that owns the QUIC
connection state.

The project is QUIC-stack neutral. It is designed so NGINX, quiche, quic-go,
MsQuic, ngtcp2, and custom servers can share one Linux dataplane and control
plane instead of each stack carrying its own reuseport eBPF router.

## Why

Linux `SO_REUSEPORT` normally distributes UDP packets without understanding
QUIC connection IDs. That is fine for the first packet of a new connection, but
it is not enough for established QUIC connections:

- QUIC connection identity lives in the Destination Connection ID (DCID), not
  the UDP 4-tuple.
- NAT rebinding can change the client source port while the QUIC connection is
  still the same connection.
- QUIC connection migration can change the client address.
- A packet delivered to the wrong worker usually means packet loss,
  cross-process forwarding, or incorrect stateless reset behavior.

`quic-affinity` routes packets by DCID before they reach user space.

## Design

```text
UDP packet
  -> Linux SO_REUSEPORT eBPF program
  -> parse QUIC header
  -> extract Destination Connection ID
  -> route by CID map or routable CID profile
  -> select owning worker socket
```

Main components:

- `bpf/qaff_reuseport.bpf.c`: `BPF_PROG_TYPE_SK_REUSEPORT` dataplane.
- `qaffd`: privileged control-plane daemon for BPF setup, worker registration,
  CID lifecycle, cleanup, restart recovery, authorization, and audit logs.
- `qaffctl`: diagnostic and management CLI.
- `include/quic_affinity/`: public C API.
- `examples/`: minimal embedded/control-plane examples and optional quiche
  probes.
- `packaging/systemd/`: systemd, tmpfiles, sysusers, and environment templates.

## Routing Modes

### Stateful CID Registry

The QUIC server registers each server-issued CID with `qaffd` or directly with
`libqaffinity`.

This mode works with opaque CIDs and is the most compatible choice. It has good
privacy properties because the CID does not need to reveal routing information.
The cost is maintaining per-CID state and retiring CIDs at the right time.

### Routable CID Profile

The QUIC server uses a CID format that embeds a worker ID plus validation data.
The eBPF program can route these CIDs without a per-CID map entry.

This mode is useful for very high connection counts and restart recovery. It
requires the QUIC server to adopt the profile format and manage key/config
rotation. Profile v2 is the recommended profile: it adds a config ID, worker
generation, nonce, and a 32-bit BPF-friendly keyed tag. The tag is a routing
integrity check, not a cryptographic MAC.

The exact profile formats are documented in [docs/cid-profile.md](docs/cid-profile.md).

## First Packet Behavior

The first client Initial normally uses a client-generated DCID. The server has
not issued a routable or registered CID yet, so that packet must use fallback
routing. After the server creates its own Source Connection ID and registers it
or uses a routable profile, later packets can be steered to the owning worker
even if the client's address or port changes.

## Compared With NGINX `quic_bpf`

`quic-affinity` is intended to be a more general Linux facility:

- It is QUIC-stack neutral rather than tied to one server.
- It supports both exact CID registration and low-state routable CIDs.
- It has a standalone control plane with Unix-socket fd passing.
- It handles worker lifecycle cleanup through leased registrations, pidfd when
  available, and optional heartbeats.
- It validates pinned BPF map schemas before reuse.
- It exposes counters, worker state, CID-index health, and audit logs.

## Build

Requirements:

- Linux with `SO_REUSEPORT` eBPF support
- CMake 3.20+
- C11 compiler
- clang with BPF target support
- libbpf development headers

Build:

```sh
cmake -B build -S .
cmake --build build
```

Run tests:

```sh
ctest --test-dir build --output-on-failure
```

Some tests load and attach eBPF programs. They need the kernel capabilities
required for BPF and may be skipped on hosts without writable bpffs or suitable
privileges.

If passwordless `sudo -n setcap` is available, the test wrappers can restore
capabilities after rebuilds:

```sh
sudo -n setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep build/qaffd
sudo -n setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource+ep build/test_reuseport_smoke
```

Install into `/usr`:

```sh
cmake --install build --prefix /usr
```

Stage a package root:

```sh
DESTDIR=/tmp/qaff-root cmake --install build --prefix /usr
```

## Quick Start With `qaffd`

Start a daemon for one listener:

```sh
build/qaffd \
  --socket /tmp/qaffd.sock \
  --bpf build/qaff_reuseport.bpf.o \
  --short-cid-len 8 \
  --fallback-worker 0
```

Register workers and CIDs from a QUIC server through the control API:

```c
int cfd = qaff_control_connect("/tmp/qaffd.sock");
qaff_control_register_worker_lease(cfd, worker_id, udp_socket_fd);
qaff_control_register_cid(cfd, worker_id, server_cid, server_cid_len);
```

Inspect the listener:

```sh
build/qaffctl health /tmp/qaffd.sock
build/qaffctl config /tmp/qaffd.sock
build/qaffctl workers /tmp/qaffd.sock
build/qaffctl stats /tmp/qaffd.sock
build/qaffctl cids /tmp/qaffd.sock --count
```

New integrations should prefer leased worker registration. If the control
connection closes unexpectedly, `qaffd` unregisters the worker, closes its
duplicated socket fd, and retires CIDs owned by that worker.

## Routable CID Profile v2

Create a listener-local 16-byte key as 32 hex digits:

```sh
install -m 0600 -D /dev/stdin /etc/quic-affinity/profile-v2.key <<EOF
707172737475767778797a7b7c7d7e7f
EOF
```

Start `qaffd` with profile v2 enabled:

```sh
build/qaffd \
  --socket /tmp/qaffd.sock \
  --bpf build/qaff_reuseport.bpf.o \
  --short-cid-len 12 \
  --cid-profile-v2-key-file /etc/quic-affinity/profile-v2.key \
  --cid-profile-v2-config-id 7
```

The exact CID map has priority. On a map miss, the BPF program validates the v2
profile key tag, config ID, and worker generation. If all checks pass, it
selects the embedded worker ID.

## Security Model

`qaffd` is the preferred deployment model because it centralizes privileged BPF
operations and exposes a narrow Unix-socket control API.

Current hardening:

- Control socket defaults to mode `0600`.
- Group access is opt-in with `--socket-mode 0660 --socket-gid GID`.
- World-accessible control sockets are rejected.
- Worker mutation is authorized by recorded Unix peer credentials or an
  explicit management UID/GID.
- Leased workers are cleaned up on control-fd close; pidfd monitoring is used
  when the kernel supports it.
- Optional worker heartbeat timeout can clean up stuck leased workers.
- Pinned map schemas are validated before reuse.
- Pin roots must be directories and must not be group/other writable.
- Audit logs record worker/CID lifecycle events and denied mutations without
  printing CID bytes or profile keys.

## Restart Recovery

For production-style deployments, run with a bpffs pin root and state snapshot:

```sh
build/qaffd \
  --socket /run/quic-affinity/example.sock \
  --bpf /usr/libexec/quic-affinity/qaff_reuseport.bpf.o \
  --short-cid-len 8 \
  --pin-root /sys/fs/bpf/quic-affinity/listeners/example \
  --state-path /var/lib/quic-affinity/example.state
```

Pinned maps allow the dataplane state to survive a `qaffd` restart. The state
snapshot lets `qaffd` rebuild its user-space ownership index and worker
generation metadata.

## Examples

- `qaff_minimal_registry`: embedded mode. One process creates maps, loads BPF,
  attaches the program, registers workers, and registers CIDs directly.
- `qaff_minimal_control`: daemon-controlled mode. `qaffd` owns BPF setup while a
  worker process registers leased worker sockets and CIDs through the Unix
  socket API.
- `qaff_quiche_control_probe`: optional quiche FFI probe that validates the CID
  lifecycle hook points against a real quiche server connection.
- `qaff_quiche_udp_smoke`: optional real UDP quiche smoke that changes the
  client source port and verifies a dataplane CID-map hit.

The quiche examples are built only when quiche FFI artifacts exist under
`third_party/quiche`. `third_party/` is ignored by Git and is not part of the
main project distribution.

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

## Documentation

- Bootstrap/design notes: [docs/bootstrap.md](docs/bootstrap.md)
- Integration contract: [docs/integration-contract.md](docs/integration-contract.md)
- Control plane: [docs/control-plane.md](docs/control-plane.md)
- CID profile: [docs/cid-profile.md](docs/cid-profile.md)
- Implementation plan: [docs/implementation-plan.md](docs/implementation-plan.md)

## Current Status

Implemented:

- Public C API for parser, worker socket registration, CID registration,
  routable CID profiles, control client, and BPF loader.
- QUIC DCID parsing for long headers and configured-length short headers.
- IPv4 and IPv6 reuseport dataplane tests.
- Stateful CID routing and profile v1/v2 routing.
- `qaffd` control plane with fd passing, map pinning, restart recovery,
  worker cleanup, authorization, audit logs, and observability.
- `qaffctl` diagnostics for health, config, stats, workers, and CID counts.
- systemd deployment templates.

Not implemented yet:

- Distro-native `.deb`/`.rpm` packages.
- Direct pinned-map inspection by `qaffctl`.
- Language bindings beyond C.

APIs may still change before a 1.0 release.

## License

The main `quic-affinity` project is licensed under the MIT License. See
[LICENSE](LICENSE).

Optional third-party code downloaded into `third_party/` is not tracked in this
repository and remains under its own upstream license. The BPF object declares
`Dual BSD/GPL` so the kernel treats the loaded program as GPL-compatible for BPF
helper availability; that loader string does not change the MIT license of the
user-space project.
