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
- `qaff-agent`: zero-source-change socket discovery and lifecycle wrapper for
  existing UDP `SO_REUSEPORT` workers.
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

### Passive Affinity

Passive affinity is an opt-in black-box mode for applications that cannot
provide CID lifecycle hooks. Worker sockets can be registered by the
application or discovered without source changes by `qaff-agent`. With
`--passive-affinity --egress-cgroup PATH`, a cgroup v2 egress program observes
server QUIC long headers, maps the sending socket cookie to a registered
worker, and learns the visible server SCID as a high-confidence passive route.

The egress learner cannot read encrypted `NEW_CONNECTION_ID` frames in QUIC
short-header packets. Explicit CID registration or a routable CID profile
therefore remains the stronger production contract. Routing priority is:

```text
exact CID registration > routable CID profile > passive CID > fallback
```

Passive entries use bounded LRU storage, monotonic TTLs, generation checks,
periodic cleanup, and immediate worker-unregister purging. Low-confidence
routing remains disabled by the default minimum confidence.

## First Packet Behavior

The first client Initial normally uses a client-generated DCID. The server has
not issued a routable or registered CID yet, so that packet must use fallback
routing. `--fallback-mode kernel` preserves Linux's normal reuseport 4-tuple
hash for this traffic and avoids concentrating new connections on one worker.
The legacy-compatible default is `fixed`, controlled by `--fallback-worker`.
After the server creates its own Source Connection ID and registers it, uses a
routable profile, or exposes it to passive egress learning, later packets can
be steered to the owning worker even if the client's address or port changes.

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

The BPF build derives the libbpf target name and architecture-specific system
include directory from the CMake toolchain. Cross builds can override them with
`-DQAFF_BPF_TARGET_ARCH=arm64` and
`-DQAFF_BPF_SYSTEM_INCLUDE_DIR=/path/to/sysroot/usr/include/aarch64-linux-gnu`.
The clang target is selected as `bpfel` or `bpfeb` from the target byte order;
unusual toolchains can override it with `-DQAFF_BPF_CLANG_TARGET=bpfeb`.
When `QAFF_BUILD_BPF=ON`, a missing clang BPF backend or missing `asm` headers is
a configuration error rather than a silently incomplete build.

For a library-only build that does not compile BPF, daemons, tools, examples,
or tests:

```sh
cmake -B build-library -S . \
  -DBUILD_TESTING=OFF \
  -DQAFF_BUILD_BPF=OFF \
  -DQAFF_BUILD_DAEMON=OFF \
  -DQAFF_BUILD_TOOLS=OFF \
  -DQAFF_BUILD_EXAMPLES=OFF
cmake --build build-library
```

`BUILD_TESTING`, `QAFF_BUILD_BPF`, `QAFF_BUILD_DAEMON`, `QAFF_BUILD_TOOLS`,
`QAFF_BUILD_EXAMPLES`, `QAFF_BUILD_QUICHE_EXAMPLES`, and
`QAFF_BUILD_FUZZERS` are independent build switches. Fuzzers are disabled by
default and require Clang with libFuzzer support. BPF-dependent tests are not
registered when BPF is disabled.

Run tests:

```sh
ctest --test-dir build --output-on-failure
```

CI runs warning-free native x86_64 and arm64 release builds, the full available
test suite on both architectures, and
AddressSanitizer/UndefinedBehaviorSanitizer unit tests on Ubuntu 24.04. The
arm64 job also verifies that CMake selects the arm64 libbpf target
automatically.

Some tests load and attach eBPF programs. They need the kernel capabilities
required for BPF and may be skipped on hosts without writable bpffs or suitable
privileges.

Passive egress learning additionally requires cgroup v2. Supplying
`--egress-cgroup` is an explicit request: `qaffd` fails startup if the path
cannot be opened or the cgroup egress program cannot be attached.

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

Installed CMake consumers can use:

```cmake
find_package(quic-affinity CONFIG REQUIRED)
target_link_libraries(my_server PRIVATE quic-affinity::qaffinity)
```

The installation also provides `quic-affinity.pc` for pkg-config consumers.

Maintainers can find the private daemon transport design in
[`docs/control-protocol.md`](docs/control-protocol.md).
The restart snapshot format and durability guarantees are documented in
[`docs/state-store.md`](docs/state-store.md).
Worker lifecycle and generation semantics are documented in
[`docs/worker-registry.md`](docs/worker-registry.md).
The daemon's in-memory CID ownership index and invariants are documented in
[`docs/cid-index.md`](docs/cid-index.md).
Maintainer fuzzing targets and corpus handling are documented in
[`docs/fuzzing.md`](docs/fuzzing.md).

## Quick Start With `qaffd`

Start a daemon for one listener:

```sh
build/qaffd \
  --socket /tmp/qaffd.sock \
  --bpf build/qaff_reuseport.bpf.o \
  --short-cid-len 8 \
  --fallback-mode kernel
```

Register workers and CIDs from a QUIC server through the control API:

```c
int lease_fd = qaff_control_connect("/tmp/qaffd.sock");
qaff_control_register_worker_lease(lease_fd, worker_id, udp_socket_fd);

int operation_fd = qaff_control_connect("/tmp/qaffd.sock");
qaff_control_register_cid(operation_fd, worker_id,
                          server_cid, server_cid_len);
close(operation_fd);

/* Keep lease_fd open; only send WORKER_HEARTBEAT on this connection. */
```

Inspect the listener:

```sh
build/qaffctl health /tmp/qaffd.sock
build/qaffctl config /tmp/qaffd.sock
build/qaffctl workers /tmp/qaffd.sock
build/qaffctl stats /tmp/qaffd.sock
build/qaffctl cids /tmp/qaffd.sock --count
```

Enable passive egress learning for workers in the root cgroup:

```sh
build/qaffd \
  --socket /tmp/qaffd.sock \
  --bpf build/qaff_reuseport.bpf.o \
  --short-cid-len 8 \
  --passive-affinity \
  --egress-cgroup /sys/fs/cgroup
```

New integrations should prefer leased worker registration. If the control
connection closes unexpectedly, `qaffd` unregisters the worker, closes its
duplicated socket fd, and retires CIDs owned by that worker.

## Zero-Source-Change Onboarding

`qaff-agent` can launch an existing server and register its bound UDP
`SO_REUSEPORT` socket without changing application code:

```sh
build/qaff-agent run \
  --socket /tmp/qaffd.sock \
  --worker-id 0 \
  --address 0.0.0.0 \
  --port 4433 \
  -- /path/to/existing-quic-server --listen 0.0.0.0:4433
```

Start one agent per worker with a unique worker ID. The agent waits for the
target to bind, duplicates the matching socket with `pidfd_getfd`, registers a
leased worker with qaffd, sends optional heartbeats, restores the registration
after qaffd restarts, and removes the lease when the real target exits. It also
checks the target's socket cookie periodically; if the application closes or
replaces the listener, the agent revokes the old lease, releases its duplicate,
and discovers and registers the replacement.
File-descriptor aliases of one socket are deduplicated by socket cookie;
multiple distinct matching sockets in one worker are rejected as ambiguous.
`qaffctl workers` reports both the registering agent PID and its target PID.

`--socket-check-ms` controls the identity-check interval and defaults to 250ms.
A shorter interval reduces the maximum stale-routing window but scans the
target's `/proc/<pid>/fd` directory more often.

For a hard startup traffic gate, configure
`--readiness-command /path/to/hook`. The agent synchronously invokes the hook
with `not-ready` before spawning a `run` target, invokes it with `ready` only
after qaffd acknowledges the worker lease, and returns to `not-ready` before
revoking a stale socket, while restoring a lost qaffd connection, or exiting.
The hook should idempotently update the load balancer or service-discovery
state and must exit zero. The agent never announces readiness unless the
`ready` transition succeeds. Any hook failure is fatal; because an external
system cannot be forced into `not-ready`, a failed withdrawal must be treated
as a traffic-control incident. `--readiness-timeout-ms` defaults to 5000ms.

An already-running process can be onboarded with:

```sh
sudo build/qaff-agent watch \
  --socket /tmp/qaffd.sock \
  --pid 12345 \
  --worker-id 0 \
  --address 0.0.0.0 \
  --port 4433
```

`run` makes the agent the target's parent and normally satisfies Linux ptrace
access checks without an extra capability. `watch` usually requires
`CAP_SYS_PTRACE` (or an equivalent ptrace policy) and access to the target's
`/proc/<pid>/fd` directory. Both modes require Linux `pidfd_open` and
`pidfd_getfd`; security policies such as seccomp can still deny those syscalls.
The supplied `qaff-agent@.service` is a privileged `watch` template using
`/etc/quic-affinity/agents/<agent-id>.env`.

The address must exactly match `getsockname()` on the socket: use `0.0.0.0` or
`::` for wildcard binds. The target must expose exactly one distinct matching
UDP `SO_REUSEPORT` socket and remain in the foreground in `run` mode. Start
qaffd before qaff-agent. If qaffd uses `--allow-worker-uid` or
`--allow-worker-gid`, configure the agent's identity—not merely the target
process identity—as the allowed registration identity. qaffd, qaff-agent, and
the target should share the relevant network namespace; the target must also
be inside the cgroup observed by passive egress learning.

Keep the listener out of load-balancer/service discovery until every expected
agent appears in `qaffctl workers` and `attached=1` appears in `qaffctl config`.
Otherwise the application can send its first long-header response before its
socket-cookie mapping exists, so passive learning may miss that server SCID.
`watch` protects new traffic after registration; it cannot reconstruct server
CIDs that were visible only before the agent started.

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
  --pin-root /sys/fs/bpf/quic-affinity/listeners/example \
  --state-path /var/lib/quic-affinity/example.state \
  --cid-profile-v2-key-file /etc/quic-affinity/profile-v2.key \
  --cid-profile-v2-config-id 7
```

The exact CID map has priority. On a map miss, the BPF program validates the v2
profile key tag, config ID, and worker generation. If all checks pass, it
selects the embedded worker ID. qaffd rejects profile v2 unless both the pinned
map root and durable state snapshot are configured; otherwise a daemon restart
could reuse a generation and reactivate a stale CID.

## Security Model

`qaffd` is the preferred deployment model because it centralizes privileged BPF
operations and exposes a narrow Unix-socket control API.

Current hardening:

- Control socket defaults to mode `0600`.
- Group access requires `--socket-mode 0660 --socket-gid GID` and an explicit
  management identity with `--allow-admin-uid` and/or `--allow-admin-gid`.
- World-accessible control sockets are rejected.
- Worker admission (`--allow-worker-*`) and management authority
  (`--allow-admin-*`) are configured independently.
- Worker mutation is authorized by recorded Unix peer credentials or the
  explicit management identity.
- A per-socket-path lock prevents a second qaffd instance from displacing the
  active control socket.
- Incomplete control requests are handled non-blockingly and closed after a
  one-second deadline; at most 128 incomplete clients are retained.
- Leased workers are cleaned up on control-fd close; pidfd monitoring is used
  when the kernel supports it.
- Optional worker heartbeat timeout can clean up stuck leased workers.
- Pinned map schemas are validated before reuse.
- Pin roots must be directories and must not be group/other writable.
- Audit logs record worker/CID lifecycle events and denied mutations without
  printing CID bytes or profile keys.
- Passive affinity is disabled unless explicitly requested.
- Passive routing defaults to high-confidence entries; ingress-only low
  confidence routing requires an explicit policy change.
- Passive entries are bounded by an LRU map, expire by monotonic TTL, and are
  purged when their worker is unregistered.

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
snapshot preserves registered workers and generation tombstones so reusing a
worker ID cannot reactivate a stale profile-v2 or passive CID. CID ownership is
rebuilt from the pinned CID map into the daemon's hash index.

Pinned map schemas are validated strictly and incompatible maps fail startup.
During pre-1.0 upgrades that add statistics slots, stop `qaffd`, unpin only the
listener's `qaff_stats` map, and restart so it can be recreated. CID ownership,
worker, and passive routing maps do not need to be discarded for a stats-only
schema change.

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
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Code of conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Current Status

Implemented:

- Public C API for parser, worker socket registration, CID registration,
  routable CID profiles, control client, and BPF loader.
- QUIC DCID parsing for long headers and configured-length short headers.
- IPv4 and IPv6 reuseport dataplane tests.
- Stateful CID routing and profile v1/v2 routing.
- `qaffd` control plane with fd passing, map pinning, restart recovery,
  worker cleanup, authorization, audit logs, and observability.
- Zero-source-change worker onboarding and real-process lifecycle tracking with
  `qaff-agent`.
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
