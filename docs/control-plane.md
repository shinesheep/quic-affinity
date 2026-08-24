# Control Plane Plan

The MVP currently lets an application create maps, load the BPF object, attach the program, and register workers/CIDs in-process.

The next step is a small control plane that can own privileged BPF operations while QUIC workers stay mostly unprivileged.

## Goals

- Keep BPF privileges out of business workers where possible.
- Make map and program state inspectable by `qaffctl`.
- Support worker restart and graceful reload.
- Support multiple listeners.
- Preserve current library-first integration path.

## Current MVP

The repository currently includes a minimal `qaffd` with these operations:

- `REGISTER_WORKER`
- `REGISTER_WORKER_LEASE`
- `WORKER_HEARTBEAT`
- `UNREGISTER_WORKER`
- `REGISTER_CID`
- `RETIRE_CID`
- `READ_STATS`
- `HEALTH`
- `CONFIG`
- `WORKERS`
- `CIDS`
- `STOP`

Worker registration uses Unix-domain `SCM_RIGHTS` fd passing. `qaffd` attaches the BPF program to the reuseport group when the first worker socket is registered. `REGISTER_WORKER_LEASE` keeps the worker's control connection open as a liveness lease; if that connection is closed by worker crash or exit, `qaffd` automatically unregisters the worker. For leased workers, `qaffd` also opens a pidfd when supported and unregisters the worker if the registering process exits. `WORKER_HEARTBEAT` refreshes the lease on that same control connection, and `--worker-heartbeat-timeout-ms` can remove stuck leased workers that stop heartbeating. Keep the lease connection dedicated to heartbeats; use separate short-lived connections for other operations. `qaffd` records Unix peer credentials for worker registration and can restrict registration with `--allow-worker-uid` and `--allow-worker-gid`. Management authority is configured separately with `--allow-admin-uid` and `--allow-admin-gid`. Existing worker IDs, worker CID registration, CID retirement, and worker unregistration can be mutated only by the original live worker process or by that management identity. Worker unregistration retires CIDs owned by that worker, removes the worker ID from the reuseport sockarray, and closes qaffd's duplicated socket fd.

`qaff-agent` supplies the same leased registration for applications that cannot
call the control API. In `run` mode it launches the application, discovers the
matching bound UDP socket through pidfd, and ties the lease to the child
lifetime. In `watch` mode it monitors an existing PID; this normally needs
`CAP_SYS_PTRACE`. qaffd sees the agent as the registering peer, while the agent
is responsible for tracking the real worker PID. The agent retains its
duplicated worker fd and automatically restores the leased registration after
a qaffd disconnect or restart.

The listener config includes `short_cid_len`, `fallback_mode`,
`fallback_worker_id`, `fallback_available`, and optional routable CID profile
settings. Fallback is used for unregistered opaque CIDs, invalid profile CIDs,
parse failures, and the first client Initial before the server has issued a
routable CID. `fixed` selects `fallback_worker_id`; that worker must register
before non-fallback workers, health fails while it is absent, and fallback
packets are dropped rather than hashed to another worker. `kernel` leaves
selection to Linux's native reuseport hash and is always available.
Profile v2 adds a config ID, worker generation, and a 32-bit keyed tag.

qaffd requires `--reuseport-bpf-policy replace` at startup. Linux attach
replaces any reuseport BPF program already owned by the group and offers no
query/no-replace operation, so this argument records an explicit ownership
decision instead of silently taking over another controller's program.

In daemon-controlled mode, `REGISTER_CID` is accepted only for currently
registered worker IDs. Each BPF entry records the worker's current generation,
so withdrawal immediately invalidates stale exact CIDs even if cleanup is
interrupted. `qaffd` keeps a CID owner index so `UNREGISTER_WORKER` can
bulk-retire CIDs owned by the removed worker. The QUIC stack should still drain
and retire CIDs first when possible, so delayed packets are less likely to fall
back. Profile-routed CIDs do not consume CID map entries. For profile v2, qaffd
increments a per-worker generation on replacement and BPF rejects stale CIDs
whose generation no longer matches.

The control socket defaults to `0600`. Deployments that need group access must use `--socket-mode 0660 --socket-gid GID` and configure an explicit management UID and/or GID with `--allow-admin-uid` or `--allow-admin-gid`; world permissions are rejected. Worker admission options never implicitly grant daemon-management authority.

qaffd holds an advisory lock at `<socket-path>.lock` before opening BPF state, so
a duplicate instance fails without unlinking the active socket. New control
connections are non-blocking and limited to 128 pending clients. Ordinary
connections can carry sequential request/response transactions; every
transaction must complete within one second. A leased registration transfers
that connection into the worker-liveness set and it must remain dedicated to
heartbeats.

`WORKERS` responses carry at most 64 entries per wire message. The request's
`worker_id` is an inclusive cursor, and the response's `worker_id` is the next
cursor or `UINT32_MAX` when the list is complete. The public control helpers
fetch these pages automatically and support all 4096 worker IDs. A list is
weakly consistent if workers register or unregister while pages are read.

The current MVP supports one listener per `qaffd` process. Multi-listener management remains future work.

`qaffctl` can currently inspect and stop a running daemon:

```sh
qaffctl health /tmp/qaffd.sock
qaffctl config /tmp/qaffd.sock
qaffctl workers /tmp/qaffd.sock
qaffctl unregister-worker /tmp/qaffd.sock 2
qaffctl stats /tmp/qaffd.sock
qaffctl stop /tmp/qaffd.sock
```

`examples/minimal_control` demonstrates the worker-side flow against `qaffd`.

## Process Model

```text
qaffd
  -> creates or opens pinned maps
  -> loads qaff_reuseport.bpf.o
  -> attaches BPF to listener reuseport groups
  -> exposes a local control API

worker process
  -> creates/binds UDP socket
  -> registers worker socket with qaffd or libqaffinity, or is discovered by
     qaff-agent without source changes
  -> registers server-issued CIDs
  -> retires CIDs
  -> unregisters worker socket when drained

qaffctl
  -> reads pinned maps or asks qaffd
  -> prints workers, CIDs, listener config, stats
```

## Pinning Layout

Recommended default root:

```text
/sys/fs/bpf/quic-affinity/
```

Per listener:

```text
/sys/fs/bpf/quic-affinity/listeners/<listener-id>/
  qaff_cids
  qaff_workers
  qaff_stats
  qaff_config
```

`listener-id` should be deterministic and safe for file names. A practical MVP format:

```text
udp-<family>-<address>-<port>
```

Examples:

```text
udp-ipv4-127.0.0.1-4433
udp-ipv6-__1-4433
```

## API Paths

Two integration paths should coexist.

### Embedded Library

The application links `libqaffinity`, creates maps, loads BPF, attaches, and registers CIDs directly.

This is easiest for early adopters and tests, but requires the application process to have BPF privileges.

### Daemon-Controlled

`qaffd` owns BPF privileges. Workers connect over a Unix domain socket.
The socket transport is a private implementation detail shared by qaffd and
libqaffinity; integrations should use `quic_affinity/control.h` rather than
copying the daemon's C message layout. Install the daemon, CLI, and library from
the same build.

Initial request types:

```text
REGISTER_WORKER(listener_id, worker_id, socket_fd)
REGISTER_WORKER_LEASE(listener_id, worker_id, socket_fd)
WORKER_HEARTBEAT(listener_id, worker_id)
REGISTER_CID(listener_id, worker_id, cid)
RETIRE_CID(listener_id, cid)
READ_STATS(listener_id)
UNREGISTER_WORKER(listener_id, worker_id)
```

Worker socket registration needs `SCM_RIGHTS` fd passing. New integrations should prefer `REGISTER_WORKER_LEASE` and keep the control fd open for the lifetime of the worker. If heartbeat timeout is enabled, the worker must periodically send `WORKER_HEARTBEAT` on the lease fd. Do not send CID or management operations over the lease connection; open a separate short-lived control connection for those operations. The one-shot `REGISTER_WORKER` path remains for compatibility, but it cannot detect worker process death because `qaffd` owns a duplicated socket fd after registration.

Live worker IDs cannot be implicitly replaced or have their lease transferred:
another registration for the ID fails with `EBUSY`, even when it passes the
same socket. Close the old lease or explicitly unregister the worker, wait for
withdrawal, and then register the next lifecycle. The sole exception is a
restart-recovery claim authenticated by the retained exact socket cookie.
During a new leased registration, qaffd reserves the worker until its reply is
delivered, so concurrent registration attempts cannot overwrite pending
ownership. If reply delivery fails, rollback applies only to that reservation.

## Graceful Reload

During reload:

1. New workers join the same listener.
2. New workers register their sockets.
3. New connections can be assigned to new worker IDs.
4. Old CIDs remain mapped to the old worker ID and generation while old
   connections drain.
5. Retired CIDs are removed.
6. Old workers are removed after their active CIDs expire.

The control plane must still drain before reusing a worker ID. If reuse races
with cleanup, generation validation prevents old CIDs from selecting the new
socket.
Profile-v2 generations do not wrap: after generation 255, that worker ID is
exhausted for the listener and registration fails instead of making generation
1—and potentially stale CIDs—valid again.

Unregistration commits the worker's durable generation tombstone before it
mutates live CID and worker maps. If that commit fails, the registered worker
and all routing entries remain intact. Post-commit cleanup is idempotent, and
restart recovery honors the tombstone over residual pinned map entries left by
an interruption.

The current daemon maintains a daemon-side CID owner index for CIDs registered
through the control API. This enables bulk CID cleanup during
`UNREGISTER_WORKER`; across restarts, the index is rebuilt from generation-valid
entries in the pinned `qaff_cids` map.

## Restart Recovery

`qaffd --pin-root PATH` opens existing pinned maps from bpffs or creates and
pins new maps under `PATH`. The pin root must not be writable by group or other
users. Existing pinned maps are schema-checked for type, key size, value size,
and max entries before reuse. `qaffd --state-path PATH` persists the
daemon-side worker list and every allocated worker generation, including
generations of unregistered workers, in a regular filesystem snapshot. Keeping
those generation tombstones prevents stale exact, profile-v2, and passive CIDs
from becoming valid when a worker ID is reused after restart. CID ownership is
recovered only from pinned `qaff_cids` entries whose generation matches the
durable registered worker; a zero live generation is accepted only as residue
of an earlier recovery quarantine and remains unroutable until exact-socket
reclaim.

On daemon restart:

1. `qaffd` opens pinned maps from `--pin-root`.
2. It reloads worker IDs and generation tombstones from `--state-path`, then
   reconciles live generations from the pinned generation map. Tombstones take
   precedence and trigger cleanup of any interrupted-unregistration residue.
3. It removes generation-stale exact entries and rebuilds ownership from the
   remaining pinned CID map into a hash index.
4. Before accepting control traffic, it quarantines every restored worker by
   setting its live generation to zero and removing it from the worker
   sockarray. Exact, profile, and passive routes therefore cannot select an
   unclaimed process after restart.
5. `qaff-agent` or an invasive integration notices the control disconnect and
   re-registers its socket. When the pinned socket-cookie map proves it is the
   exact same socket, qaffd restores the prior generation, preserving exact and
   passive connection affinity. A different socket cannot claim the worker ID
   during this recovery window.
6. A worker that does not reclaim the exact socket within
   `--worker-recovery-timeout-ms` (default 5000 ms) is tombstoned and its exact,
   passive, sockarray, and reverse-cookie state is removed. A replacement
   socket can then register with the next generation.

`qaffctl config` reports both `worker_count` (durable worker records, including
quarantined records) and `recovering_worker_count`. `qaffctl workers` marks
these records with `recovering=1`. A quarantined fixed fallback is reported as
unavailable, so health stays failed until that exact socket reclaims its ID.
The cgroup egress learner is attached after state/map reconciliation and cannot
learn for quarantined workers because their live generation is zero.

The state snapshot is atomically replaced and synced, but is not stored in bpffs. Use a normal persistent location such as `/var/lib/quic-affinity/<listener-id>.state`.
If `--state-path` is configured, `--pin-root` must also be configured.
If CID profile v2 is enabled, both options are mandatory; qaffd rejects an
ephemeral generation configuration before opening BPF state.
During pre-release development, qaffd accepts only the current snapshot format
and rejects older or ambiguous records instead of attempting migration.

## qaffctl MVP

Initial commands:

```sh
qaffctl stats LISTENER_ID
qaffctl health LISTENER_ID
qaffctl config LISTENER_ID
qaffctl cids LISTENER_ID --count
qaffctl workers LISTENER_ID
qaffctl unregister-worker LISTENER_ID WORKER_ID
qaffctl stop LISTENER_ID
```

Future commands:

```sh
qaffctl listeners
qaffctl cids LISTENER_ID --limit 20
```

`qaffctl health`, `qaffctl config`, and `qaffctl cids --count` expose `cid_map_count`, `cid_owner_count`, and `cid_index_mismatch`. Health returns a nonzero status when a fixed fallback worker is absent, durable state persistence is degraded, or post-tombstone BPF cleanup remains pending. Persistence and worker cleanup failures are retried once per second. `state_persistence_degraded`, `state_persistence_error_count`, and `state_persistence_retry_count` expose snapshot health; `worker_cleanup_degraded`, `worker_cleanup_pending_count`, `worker_cleanup_error_count`, and `worker_cleanup_retry_count` expose cleanup quarantine and cumulative process-local activity. `qaffctl workers` reports worker IDs, lease state, pidfd availability, peer pid/uid/gid when available, registration age, and last-seen age. CID bytes and profile keys are not printed by default. `qaffd` emits audit records to stderr for worker lifecycle, CID lifecycle, fallback availability transitions, persistence and cleanup health transitions, and denied mutations. `qaffctl` currently talks to `qaffd` over the daemon Unix socket. Direct pinned-map inspection remains future work.

## Open Decisions

- Whether qaffd should create worker sockets itself or accept worker socket fds.
- How to represent CID keys in CLI output without leaking sensitive routing material by default.
- Whether to ship distro-native packages or keep only CMake install plus systemd templates.
