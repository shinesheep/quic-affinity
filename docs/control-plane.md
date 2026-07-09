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
- `UNREGISTER_WORKER`
- `REGISTER_CID`
- `RETIRE_CID`
- `READ_STATS`
- `HEALTH`
- `CONFIG`
- `WORKERS`
- `CIDS`
- `STOP`

Worker registration uses Unix-domain `SCM_RIGHTS` fd passing. `qaffd` attaches the BPF program to the reuseport group when the first worker socket is registered. Worker unregistration retires CIDs owned by that worker, removes the worker ID from the reuseport sockarray, and closes qaffd's duplicated socket fd.

The listener config includes `short_cid_len` and `fallback_worker_id`. Fallback is used for unregistered CIDs, parse failures, and the first client Initial before the server has issued a routable CID.

In daemon-controlled mode, `REGISTER_CID` is accepted only for currently registered worker IDs. `qaffd` keeps a CID owner index so `UNREGISTER_WORKER` can bulk-retire CIDs owned by the removed worker. The QUIC stack should still drain and retire CIDs first when possible, so delayed packets are less likely to fall back.

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
  -> registers worker socket with qaffd or libqaffinity
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

Initial request types:

```text
REGISTER_WORKER(listener_id, worker_id, socket_fd)
REGISTER_CID(listener_id, worker_id, cid)
RETIRE_CID(listener_id, cid)
READ_STATS(listener_id)
UNREGISTER_WORKER(listener_id, worker_id)
```

Worker socket registration needs `SCM_RIGHTS` fd passing.

## Graceful Reload

During reload:

1. New workers join the same listener.
2. New workers register their sockets.
3. New connections can be assigned to new worker IDs.
4. Old CIDs remain mapped to old worker IDs while old connections drain.
5. Retired CIDs are removed.
6. Old workers are removed after their active CIDs expire.

The control plane must avoid reusing a worker ID while CIDs still point to the old socket.

The current daemon maintains a daemon-side CID owner index for CIDs registered through the control API. This enables bulk CID cleanup during `UNREGISTER_WORKER`; across restarts, the index is rebuilt from the pinned `qaff_cids` map.

## Restart Recovery

`qaffd --pin-root PATH` opens existing pinned maps from bpffs or creates and pins new maps under `PATH`. `qaffd --state-path PATH` persists the daemon-side worker list in a regular filesystem snapshot. CID ownership is recovered from the pinned `qaff_cids` map.

On daemon restart:

1. `qaffd` opens pinned maps from `--pin-root`.
2. It reloads worker IDs from `--state-path`.
3. It rebuilds CID ownership by iterating the pinned CID map.
4. Existing socket-group BPF attachment can continue using the pinned maps while worker sockets remain open.
5. New control operations, including `UNREGISTER_WORKER`, operate on the recovered map and owner state.

The state snapshot is not stored in bpffs. Use a normal persistent location such as `/var/lib/quic-affinity/<listener-id>.state`.
If `--state-path` is configured, `--pin-root` must also be configured.

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

`qaffctl health`, `qaffctl config`, and `qaffctl cids --count` expose `cid_map_count`, `cid_owner_count`, and `cid_index_mismatch`. CID bytes are not printed by default. `qaffctl` currently talks to `qaffd` over the daemon Unix socket. Direct pinned-map inspection remains future work.

## Open Decisions

- Whether qaffd should create worker sockets itself or accept worker socket fds.
- How to represent CID keys in CLI output without leaking sensitive routing material by default.
- Whether to ship distro-native packages or keep only CMake install plus systemd templates.
