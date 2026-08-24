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

For the routable CID profile, set `short_cid_len` to
`QAFF_CID_PROFILE_LEN`, enable `cid_profile_enabled`, and copy the 16-byte
listener key into `cid_profile_key`. The dataplane checks the CID map first; on
map miss, it validates the two-byte profile magic, tag, and worker generation before routing to
the embedded worker ID. qaffd requires both `--pin-root` and `--state-path`
whenever the profile is enabled, so allocated generations and tombstones survive
restart. Embedded users are responsible for an equivalent durable generation
allocator.

Zero-length server CIDs are incompatible with CID-based worker affinity.

## Startup Sequence

The expected startup sequence is:

1. Create all UDP worker sockets with `SO_REUSEPORT`.
2. Bind each worker socket to the listener address and port.
3. Call `qaff_options_init()`.
4. Set `short_cid_len`.
5. Call `qaff_open()`.
6. Publish the validated configuration with `qaff_apply_config()`.
7. Register each worker socket. Profile integrations must use
   `qaff_register_worker_socket_generation()` with a durable generation;
   other integrations may use `qaff_register_worker_socket()`.
8. Load the BPF object with `qaff_bpf_object_open()`.
9. Attach the BPF program with `qaff_attach_reuseport_bpf()` on one socket in
   the group. This explicit call replaces any reuseport BPF program already
   owned by that group.
10. Start accepting packets.

The BPF program applies to the reuseport group after attachment.
Worker registration populates both the reuseport sockarray and the
socket-cookie reverse map. A live worker ID cannot be replaced with a different
socket. `qaff_unregister_worker_socket()` withdraws its generation, purges its
exact and passive CIDs, and removes the socket mappings before the ID can be
reused. Embedded mutation calls are serialized per context; do not let multiple
embedded contexts independently own the same pinned lifecycle maps.

## qaffd Startup Sequence

When using `qaffd`, the privileged daemon owns BPF setup:

1. Start `qaffd` with a Unix socket path, BPF object path, `short_cid_len`, and
   `--reuseport-bpf-policy replace`, plus any fallback, profile, socket
   permission, and restart-recovery arguments.
2. Each worker creates and binds its UDP `SO_REUSEPORT` socket.
3. Each worker passes its socket fd to `qaffd` with `REGISTER_WORKER_LEASE` and keeps that control connection open for the worker lifetime.
4. `qaffd` registers the socket in the sockarray and attaches BPF on first worker registration.
5. Workers register and retire opaque server-issued CIDs through the control API, or issue profile CIDs when the listener key is enabled.
6. Drained workers unregister their socket after their CIDs have been retired.

If the leased control connection closes unexpectedly, `qaffd` treats the worker as dead, unregisters it, closes qaffd's duplicated worker socket fd, and bulk-retires that worker's CIDs. `--worker-heartbeat-timeout-ms` also lets `qaffd` remove leased workers that keep the connection open but stop sending `WORKER_HEARTBEAT` messages; `0` disables heartbeat timeouts. The older one-shot `REGISTER_WORKER` operation remains available for compatibility, but it cannot detect worker process death on its own because fd passing gives `qaffd` a separate reference to the UDP socket.

Confirmed liveness loss fails closed even if the durable tombstone write
fails: qaffd withdraws the worker generation/socket and closes ownership FDs,
then retries the snapshot once per second. `qaffctl health` remains failed with
`state_persistence_degraded=1` until a retry succeeds. An explicit management
`UNREGISTER_WORKER` remains transactional and leaves live routing intact when
its pre-commit tombstone write fails.

Once a tombstone is committed, any incomplete BPF cleanup is retried at a
one-second interval. The affected worker ID returns `EBUSY` on registration
until cleanup completes; this quarantine is required because retry cleanup is
keyed by worker ID and must never delete a replacement worker's state.
`worker_cleanup_degraded` and `worker_cleanup_pending_count` expose this state,
and health remains failed while either is nonzero. A daemon restart performs
the same tombstone reconciliation before opening the control socket.

Failed registrations follow the same quarantine rule when their BPF rollback
is incomplete. A new generation is first persisted as a tombstone and only
changed to a worker record after all BPF and local registration stages succeed;
restart therefore purges, rather than recovers, a pre-commit BPF route. Cleanup
for a new worker removes all worker-keyed residue. For a recovered exact-socket
claim, cleanup only re-withdraws the attempted live generation and socket; it
does not delete the old CID or cookie ownership that the recovery record still
needs. Registrations for a cleanup-pending ID return `EBUSY` until the retry
succeeds.

After qaffd restarts, persisted workers begin in a recovery quarantine rather
than being considered live. Their live BPF generation is zero and their
sockarray entry is absent until the exact socket cookie reclaims the worker ID.
This makes old
exact/profile/passive routes and fixed fallback fail closed during the control
plane recovery window. The default claim deadline is 5000 ms and can be tuned
with `--worker-recovery-timeout-ms`; an unclaimed record is tombstoned and
purged when the deadline expires. Native invasive integrations and
`qaff-agent` must reconnect and repeat their leased registration.

The agent also tolerates daemon/agent startup reordering and a socket rotation
that overlaps qaffd downtime. It remains not-ready and retries registration
while the target process still owns the discovered socket. If that socket
changes during the retry window, the agent abandons the stale duplicate and
restarts discovery instead of exiting or registering the wrong cookie.
Authorization, invalid-configuration, and socket-cookie conflict errors remain
terminal so deployment mistakes are reported instead of retried forever.

`qaffd` records the registering process' Unix peer credentials and exposes them through `qaffctl workers`. For leased workers it also opens a pidfd when supported; pidfd readability is treated as worker death and triggers the same unregister cleanup as lease close. Existing worker IDs, worker CID registration, CID retirement, and worker unregistration can be mutated only by the original worker process or by the configured management identity. Deployments use `--allow-worker-uid` and `--allow-worker-gid` to restrict worker admission, and the independent `--allow-admin-uid` and `--allow-admin-gid` options to grant management authority. Group-accessible control sockets require an explicit management identity.

The current MVP supports one listener per `qaffd` process.

## Integration-mode lifecycle matrix

Both integration modes use the same worker-generation state machine; they
differ only in who observes the application socket and holds the lease.

| Lifecycle event | Invasive integration | Non-invasive `qaff-agent` / passive learning | Dataplane invariant |
| --- | --- | --- | --- |
| Initial registration | Application passes its UDP fd with `REGISTER_WORKER_LEASE` | Agent duplicates the exact target fd and registers the lease | Worker generation and sockarray entry become live together |
| CID ownership | Application registers exact CIDs or emits profile CIDs | Egress observer learns server SCIDs into the passive map | Every route stores or embeds the live worker generation |
| Process/lease exit | qaffd observes lease close or pidfd readability | Agent lease closes after target exit | Generation/socket withdraw first; exact and passive entries are then purged |
| Socket rotation | Application drains, unregisters, and registers the replacement | Agent marks not-ready, revokes, rediscovers, and re-registers | Replacement receives the next generation; old CIDs cannot reactivate |
| qaffd restart | Application reconnects and repeats leased registration | Agent automatically reconnects | Restored worker is quarantined until the exact cookie claims it |
| Same-socket recovery | Existing generation is restored | Existing generation is restored | Existing exact and passive connection affinity resumes |
| Missing/different recovery socket | Claim cannot reactivate the recovered record | Agent retries while the old record is quarantined | Recovery timeout tombstones old state; replacement then advances generation |

The egress learner is attached only after pinned maps and durable state have
been reconciled. While a worker is quarantined its generation is zero, so
egress packets cannot create passive ownership for an unclaimed worker even if
the reverse socket-cookie entry is still retained for claim authentication.

Linux replaces a reuseport group's current BPF program during attach and does
not expose a query or no-replace operation for this attachment type. The
required `--reuseport-bpf-policy replace` argument makes qaffd's ownership
decision explicit. A listener group must not be managed by another reuseport
BPF controller at the same time.

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

`--pin-root` must point to a writable bpffs directory. `--state-path` must point
to a normal filesystem path, not bpffs. They are one persistence unit and must
be configured together.

On restart, `qaffd` reloads worker IDs and generation tombstones from
`--state-path`, validates pinned worker generations against that authoritative
snapshot, removes exact CID entries whose generation is no longer live, and
rebuilds ownership from the remaining `qaff_cids` entries. A map-only worker or
a generation mismatch fails startup rather than being promoted into durable
state.
An unregistration tombstone is committed before live routing is removed. Failed
snapshot commits leave routing unchanged; after a committed interruption,
startup removes residual pinned entries before opening the control socket.

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
4. Generates and parses a generation-bound routable CID profile for the registered worker.
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
the registration for the same worker generation is idempotent. Each exact map
entry stores both worker ID and generation, and BPF rejects it as soon as that
generation is withdrawn. A replacement worker cannot reactivate or claim the
CID until the current owner retires it; that attempt fails with `EEXIST`.

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

Workers must use stable worker IDs while any registered CID can still route to them:

1. Register the worker socket before registering CIDs for that worker.
2. Stop assigning new connections to a draining worker.
3. Retire or let expire CIDs owned by that worker where the QUIC stack can do so cleanly.
4. Call `qaff_unregister_worker_socket()` or `UNREGISTER_WORKER` after the
   worker is drained.

Both integration modes reject CID registrations for unregistered worker IDs,
reject replacing an active worker's socket with `EBUSY`, and bulk-retire exact
and passive CIDs during worker unregistration. qaffd uses its daemon-side CID
index; the embedded control path scans its maps while mutations on that context
are locked. Unregister the drained worker first if the worker ID must be reused
with a different socket.

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

This priority is fail closed. A higher-priority route that is present but
invalid is not treated as a miss and reinterpreted by a lower-priority route.
For example, an exact entry with an old worker generation and a profile-shaped
CID with an invalid tag both go directly to fallback even if the same CID also
exists in the passive map. This prevents stale or attacker-controlled bytes
from changing routing identity by falling through to a different mechanism.

### Routing decision matrix

The following matrix is the normative dataplane oracle. "Socket available"
means `bpf_sk_select_reuseport()` succeeded for the selected worker.

| Parsed DCID state | Exact route | Profile result | Passive result | Socket available | Decision | Required counter |
| --- | --- | --- | --- | --- | --- | --- |
| Parse error or zero-length long-header DCID | Not evaluated | Not evaluated | Not evaluated | N/A | Fallback | `parse_error` or `zero_length_cid` |
| Valid | Live generation | Not evaluated | Not evaluated | Yes | Exact worker | `cid_map_hit` |
| Valid | Live generation | Not evaluated | Not evaluated | No | Fallback | `cid_map_hit`, `worker_missing` |
| Valid | Missing/zero/stale generation | Not evaluated | Not evaluated | N/A | Fallback | `cid_map_reject_generation` |
| Valid | Miss | Valid, live generation | Not evaluated | Yes | Profile worker | `cid_profile_hit` |
| Valid | Miss | Valid, live generation | Not evaluated | No | Fallback | `cid_profile_hit`, `worker_missing` |
| Valid | Miss | Invalid tag/config/generation | Not evaluated | N/A | Fallback | `cid_profile_reject` |
| Valid | Miss | Not a profile CID | Live and policy-valid | Yes | Passive worker | `passive_hit` |
| Valid | Miss | Not a profile CID | Live and policy-valid | No | Fallback | `passive_hit`, `worker_missing` |
| Valid | Miss | Not a profile CID | Below confidence | N/A | Fallback | `passive_reject_confidence` |
| Valid | Miss | Not a profile CID | Expired | N/A | Fallback | `passive_reject_expired` |
| Valid | Miss | Not a profile CID | Missing/zero/stale generation | N/A | Fallback | `passive_reject_generation` |
| Valid | Miss | Not a profile CID | Miss or disabled | N/A | Fallback | `passive_miss` when enabled |

Every fallback decision increments `fallback` in addition to the row-specific
counter. The fallback policy then has its own terminal matrix:

| Fallback mode | Fixed worker socket | Result |
| --- | --- | --- |
| `kernel` | N/A | Return `SK_PASS`; Linux applies the reuseport hash |
| `fixed` | Available | Select the configured fallback worker |
| `fixed` | Missing | Increment `worker_missing` and return `SK_DROP` |

The same DCID decision applies to QUIC v1 Initial, 0-RTT, Handshake, and Retry
long headers. A 1-RTT short header uses the configured fixed short-DCID length.
The privileged reuseport smoke test executes all five packet classes for both
IPv4 and IPv6, both fallback modes, route hits, each passive rejection state,
missing target sockets, stale exact/profile generations, and missing fixed
fallback sockets. Its collision cases also enforce the no-lower-priority
reinterpretation rule above.

Fixed fallback:

```text
worker_id = qaff_options.fallback_worker_id
```

The default is `0`. In daemon-controlled mode this is set with
`qaffd --fallback-worker ID`; valid IDs are `0..4095`. The fixed fallback must
register before any non-fallback worker. If it later disappears, qaffd rejects
new non-fallback registrations until it returns. `qaffctl health` fails and
prints `fallback_available=0` while the fixed fallback is absent; `qaffctl
config` exposes the same state. Kernel fallback is always reported available.
If the fixed fallback selection fails in the dataplane, the packet is dropped
and `worker_missing` increments. Existing exact/profile routes to other live
workers continue to operate, while unknown traffic and new Initials fail
closed until the fallback returns.

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

An arbitrary unmodified application cannot be paused safely between `bind()`
and its first response. To make startup ordering deterministic, configure
`--readiness-command PATH` and make that hook remove/add the worker from the
external traffic source. qaff-agent calls `PATH not-ready` before spawning a
`run` target and `PATH ready` only after qaffd acknowledges registration. It
returns to `not-ready` before stale-socket revocation and at shutdown. Hook
transitions are synchronous and bounded by `--readiness-timeout-ms`. Readiness
is never announced after a failed `ready` transition. A failed `not-ready`
transition is fatal and must raise an operational alert: qaff-agent cannot
guarantee that an external traffic system honored a failed command. In `watch`
mode this protects future traffic but cannot recover responses sent before the
agent started.

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
- `passive_egress_conflict`
- `passive_egress_fragmented`
- `passive_egress_reject_version`
- `passive_egress_reject_type`
- `passive_egress_short_header`

## Minimal API Surface

```c
void qaff_options_init(struct qaff_options *options);
int qaff_open(const struct qaff_options *options, struct qaff_context **out);
int qaff_apply_config(struct qaff_context *ctx);
void qaff_close(struct qaff_context *ctx);

int qaff_register_worker_socket(struct qaff_context *ctx,
                                uint32_t worker_id,
                                int socket_fd);

int qaff_register_worker_socket_generation(struct qaff_context *ctx,
                                           uint32_t worker_id,
                                           int socket_fd,
                                           uint32_t generation);

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
