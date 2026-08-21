# Integration Contract

This document defines the expected contract between a QUIC server and `quic-affinity`.

The contract is intentionally QUIC-stack neutral. A server can be built on quiche, quic-go, MsQuic, ngtcp2, a custom QUIC implementation, or a proxy runtime.

## Model

`quic-affinity` owns the Linux packet selection layer for a `SO_REUSEPORT` UDP socket group.

The QUIC server owns:

- socket creation
- QUIC connection state
- server-generated connection IDs
- CID retirement decisions
- worker lifecycle

`quic-affinity` owns:

- BPF map creation or reuse
- worker socket registration
- DCID-to-worker registration
- eBPF object loading
- `SO_ATTACH_REUSEPORT_EBPF` attachment
- dataplane counters

## Required Socket Shape

All worker sockets for one listener must:

- use UDP
- bind the same address and port
- set `SO_REUSEPORT` before bind
- belong to one Linux reuseport group
- use stable worker IDs for the lifetime of registered CIDs
- use separate `qaffd` instances for IPv4 and IPv6 listeners; IPv6 worker sockets must set `IPV6_V6ONLY`

The worker ID used in `qaff_register_worker_socket()` is also the key used by the eBPF program to select a socket from the reuseport sockarray. Registration atomically claims the socket cookie for that worker so embedded passive-egress learning works without a daemon-side map update. The same socket cannot be registered under another worker ID until its current worker is unregistered; conflicts fail with `EEXIST`.

When using `qaffd`, worker registration is validated at the fd boundary. The daemon rejects non-UDP sockets, sockets without `SO_REUSEPORT`, IPv6 sockets that are not `IPV6_V6ONLY`, and sockets whose local address or port does not match the first accepted worker for that listener. This keeps one `qaffd` process scoped to one UDP reuseport listener group.

Do not intentionally mix unrelated processes into the same address, port, and reuseport group. `quic-affinity` is a selector for the listener group it is attached to, not a global packet router.

## Listener Configuration

QUIC short headers do not carry a DCID length. The listener must provide a fixed server CID length:

```c
struct qaff_options options;
qaff_options_init(&options);
options.short_cid_len = 8;
```

For the stateful CID registry mode, every server-issued CID routed by `quic-affinity` must use this configured length once 1-RTT short headers are expected.

For routable CID profile v2, set `short_cid_len` to
`QAFF_CID_PROFILE_V2_LEN`, enable `cid_profile_v2_enabled`, set
`cid_profile_v2_config_id`, and copy the 16-byte listener key into
`cid_profile_v1_key`. The dataplane checks the CID map first; on map miss, it
validates the profile tag, config ID, and worker generation before routing to
the embedded worker ID. Profile v1 remains available for compatibility.

Zero-length server CIDs are incompatible with CID-based worker affinity.

## Startup Sequence

The expected startup sequence is:

1. Create all UDP worker sockets with `SO_REUSEPORT`.
2. Bind each worker socket to the listener address and port.
3. Call `qaff_options_init()`.
4. Set `short_cid_len`.
5. Call `qaff_open()`.
6. Register each worker socket with `qaff_register_worker_socket()`.
7. Load the BPF object with `qaff_bpf_object_open()`.
8. Attach the BPF program with `qaff_attach_reuseport_bpf()` on one socket in the group.
9. Start accepting packets.

The BPF program applies to the reuseport group after attachment.
Worker registration populates both the reuseport sockarray and the
socket-cookie reverse map. Call `qaff_unregister_worker_socket()` before
reusing a socket under another worker ID.

## qaffd Startup Sequence

When using `qaffd`, the privileged daemon owns BPF setup:

1. Start `qaffd` with a Unix socket path, BPF object path, `short_cid_len`,
   optional fallback mode/worker, optional profile key/config arguments,
   optional socket permission arguments, and optional restart-recovery paths.
2. Each worker creates and binds its UDP `SO_REUSEPORT` socket.
3. Each worker passes its socket fd to `qaffd` with `REGISTER_WORKER_LEASE` and keeps that control connection open for the worker lifetime.
4. `qaffd` registers the socket in the sockarray and attaches BPF on first worker registration.
5. Workers register and retire opaque server-issued CIDs through the control API, or issue profile CIDs when the listener key is enabled.
6. Drained workers unregister their socket after their CIDs have been retired.

If the leased control connection closes unexpectedly, `qaffd` treats the worker as dead, unregisters it, closes qaffd's duplicated worker socket fd, and bulk-retires that worker's CIDs. `--worker-heartbeat-timeout-ms` also lets `qaffd` remove leased workers that keep the connection open but stop sending `WORKER_HEARTBEAT` messages; `0` disables heartbeat timeouts. The older one-shot `REGISTER_WORKER` operation remains available for compatibility, but it cannot detect worker process death on its own because fd passing gives `qaffd` a separate reference to the UDP socket.

`qaffd` records the registering process' Unix peer credentials and exposes them through `qaffctl workers`. For leased workers it also opens a pidfd when supported; pidfd readability is treated as worker death and triggers the same unregister cleanup as lease close. Existing worker IDs, worker CID registration, CID retirement, and worker unregistration can be mutated only by the original worker process or by the configured management identity. Deployments use `--allow-worker-uid` and `--allow-worker-gid` to restrict worker admission, and the independent `--allow-admin-uid` and `--allow-admin-gid` options to grant management authority. Group-accessible control sockets require an explicit management identity.

The current MVP supports one listener per `qaffd` process.

### Optional Passive Egress Learning

Passive affinity is opt-in. Add both arguments:

```sh
qaffd --passive-affinity --egress-cgroup /sys/fs/cgroup ...
```

`--egress-cgroup` must name a cgroup v2 directory containing the worker
processes whose UDP sends should be observed. qaffd treats an explicit attach
request as required configuration and fails startup if the directory cannot be
opened or the BPF link cannot be attached.

The black-box learner sees only server SCIDs carried in visible QUIC long
headers. It cannot parse encrypted short-header frames such as
`NEW_CONNECTION_ID`. Learned entries use a longer egress TTL and are refreshed
when another visible long-header packet carries the same SCID or when a valid
ingress hit reaches the latter half of its TTL. qaffd scans the passive map
every 30 seconds by default; use
`--passive-scan-interval-ms` to tune that control-plane cost.

For restart recovery, use both:

```sh
qaffd --pin-root /sys/fs/bpf/quic-affinity/listeners/<listener-id> \
      --state-path /var/lib/quic-affinity/<listener-id>.state
```

`--pin-root` must point to a writable bpffs directory. `--state-path` must point to a normal filesystem path, not bpffs. If `--state-path` is set, `--pin-root` is required.

On restart, `qaffd` reloads worker IDs and generation tombstones from `--state-path`, reconciles pinned worker generations, and rebuilds CID ownership from the pinned `qaff_cids` map.

Pinned map schema mismatches fail startup rather than silently reinterpreting
data. For a pre-1.0 upgrade that only expands `QAFF_STAT_MAX`, stop qaffd and
unpin the listener's `qaff_stats` map before restarting; qaffd recreates that
map while preserving the routing maps.

Stats and shutdown are available through `qaffctl`:

```sh
qaffctl health /tmp/qaffd.sock
qaffctl config /tmp/qaffd.sock
qaffctl cids /tmp/qaffd.sock --count
qaffctl workers /tmp/qaffd.sock
qaffctl unregister-worker /tmp/qaffd.sock 2
qaffctl stats /tmp/qaffd.sock
qaffctl stop /tmp/qaffd.sock
```

The CID count command reports aggregate counts and consistency status only. It does not print CID bytes by default.

The repository includes `qaff_minimal_control` as a small worker-side example for this mode. It creates UDP reuseport sockets, passes them to `qaffd`, and registers a sample server CID.

## quiche Integration Probe

If quiche FFI is built under `third_party/quiche`, the optional `qaff_quiche_control_probe` target is enabled.

The probe:

1. Creates a real quiche server-side connection with `quiche_accept()`.
2. Reads the connection source CID with `quiche_conn_source_id()`.
3. Registers that source CID through `qaffd`.
4. Generates and parses a routable CID profile v1 CID for the registered worker.
5. Registers the profile CID through `qaffd`.
6. Calls `quiche_conn_new_scid()` to provision an additional server CID.
7. Registers the additional CID through `qaffd`.
8. Drains `quiche_conn_retired_scid_iter()` and calls `RETIRE_CID` for any retired source CIDs.

This is not a complete QUIC server. It is the first integration checkpoint for CID lifecycle hooks.

## quiche UDP Smoke

If quiche FFI is available, `qaff_quiche_udp_smoke` runs a real UDP packet loop:

1. Starts with workers registered through `qaffd`.
2. Creates a real quiche client connection.
3. Sends the first client Initial through a UDP socket.
4. Receives that packet on the fallback worker.
5. Creates a real quiche server connection and registers its server SCID through `qaffd`.
6. Sends the server response to the client.
7. Sends the next client packet from a different UDP source port.
8. Verifies the dataplane sees at least one CID-map hit and one fallback.

This validates the core migration-affinity path with a real QUIC stack, while remaining smaller than a full HTTP/3 server.

## CID Registration

When the QUIC stack creates or advertises a server-side CID, it must register that CID before packets using it are expected to arrive:

```c
qaff_register_cid(ctx, cid, cid_len, worker_id);
```

CID ownership is exclusive and immutable while the entry is live. Repeating
the registration for the same worker is idempotent. A different worker cannot
claim the CID until the current owner retires it; that attempt fails with
`EEXIST`.

Register:

- the server SCID chosen for the handshake
- server CIDs sent in `NEW_CONNECTION_ID`
- Retry SCIDs if Retry is used and the next Initial should be routable

The first client Initial DCID is client-generated and cannot be pre-registered by the server. It will use fallback routing.

## CID Retirement

When a CID is no longer valid, the server should retire it:

```c
qaff_retire_cid(ctx, cid, cid_len);
```

Retirement should be conservative. A CID should remain registered while delayed packets using that CID might still arrive.

## Worker Lifecycle

Workers must use stable worker IDs while any registered CID can still route to them. In daemon-controlled mode:

1. Register the worker socket before registering CIDs for that worker.
2. Stop assigning new connections to a draining worker.
3. Retire or let expire CIDs owned by that worker where the QUIC stack can do so cleanly.
4. Call `UNREGISTER_WORKER` after the worker is drained.

`qaffd` rejects new CID registrations for unregistered worker IDs. It keeps a daemon-side reverse index from worker ID to CID for CIDs registered through the control API, and bulk-retires those CIDs during worker unregistration.
It also rejects replacing an active worker's socket with `EBUSY` while that
worker owns exact CIDs. Unregister the drained worker first if the worker ID
must be reused with a different socket.

## Packet Routing Semantics

The dataplane behavior is:

1. Confirm the packet is UDP.
2. Skip the UDP header.
3. Parse the QUIC DCID.
4. Prefer an exact CID registration.
5. On an exact miss, validate an enabled routable CID profile.
6. On a profile miss, consult the passive CID table when passive mode is
   enabled.
7. Reject passive entries below the configured confidence, past their monotonic
   expiry, or tied to an old worker generation.
8. If no route is selected, use the configured fixed-worker or kernel-default
   fallback policy.

The resulting priority is:

```text
exact CID registration > routable CID profile > passive CID > fallback
```

Fixed fallback:

```text
worker_id = qaff_options.fallback_worker_id
```

The default is `0`. In daemon-controlled mode this is set with `qaffd --fallback-worker ID` and can be inspected with `qaffctl config`.

`qaffd --fallback-mode kernel` skips explicit socket selection on a fallback,
so Linux applies its normal SO_REUSEPORT 4-tuple hash. This is recommended for
black-box onboarding because first Initial packets remain distributed across
the application's worker group. `fixed` remains the compatibility default.

An application that cannot pass its own socket can be started through
`qaff-agent run`, or an existing PID can be registered through
`qaff-agent watch`. The agent matches one exact bound address/port, duplicates
the UDP `SO_REUSEPORT` fd through pidfd, and owns the qaffd lease for the real
worker lifetime. It also reconnects and restores registration after qaffd
restarts. While the target remains alive, it periodically verifies the exact
socket cookie and revokes and replaces the lease if the listener changes. The
check interval is configured with `--socket-check-ms`; detection is polling, so
it defines the maximum expected stale-registration window. This changes no
application source code.

## IPv4 and IPv6

`sk_reuseport_md->data` starts at the UDP header for both IPv4 and IPv6. The eBPF dataplane skips the fixed 8-byte UDP header before parsing QUIC.

The dataplane records IPv4 and IPv6 counters separately.

## Capabilities

Loading and attaching eBPF usually requires privileges such as:

```text
cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource
```

The cgroup egress learner also requires cgroup v2 and permission to attach a
`BPF_PROG_TYPE_CGROUP_SKB` program to the configured cgroup.

Development tests can use file capabilities on the test executable. Production deployments should prefer a small privileged control-plane process and keep business workers unprivileged where possible.

## Error Semantics

The dataplane does not send stateless resets.

If routing fails, the MVP behavior is fallback selection. Future policies may allow drop-on-error or configurable fallback behavior.

If a CID still points at an unavailable worker, routing is treated as a worker-missing condition rather than a stateless reset trigger. In daemon-controlled mode, normal `UNREGISTER_WORKER` cleanup should remove the worker's CIDs before this path is needed.

The application should read dataplane counters through `qaff_read_stats()` and alert on unexpected increases in:

- `parse_error`
- `fallback`
- `worker_missing`
- `zero_length_cid`
- `passive_reject_expired`
- `passive_egress_parse_miss`
- `passive_egress_socket_cookie_miss`
- `passive_egress_map_update_error`

## Minimal API Surface

```c
void qaff_options_init(struct qaff_options *options);
int qaff_open(const struct qaff_options *options, struct qaff_context **out);
void qaff_close(struct qaff_context *ctx);

int qaff_register_worker_socket(struct qaff_context *ctx,
                                uint32_t worker_id,
                                int socket_fd);

int qaff_unregister_worker_socket(struct qaff_context *ctx,
                                  uint32_t worker_id);

int qaff_register_cid(struct qaff_context *ctx,
                      const uint8_t *cid,
                      size_t cid_len,
                      uint32_t worker_id);

int qaff_retire_cid(struct qaff_context *ctx,
                    const uint8_t *cid,
                    size_t cid_len);

int qaff_bpf_object_open(struct qaff_context *ctx,
                         const char *object_path,
                         struct qaff_bpf_object **out);

int qaff_attach_reuseport_bpf(const struct qaff_bpf_object *object,
                              int socket_fd);
```
