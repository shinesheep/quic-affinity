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
- `STOP`

Worker registration uses Unix-domain `SCM_RIGHTS` fd passing. `qaffd` attaches the BPF program to the reuseport group when the first worker socket is registered. Worker unregistration removes the worker ID from the reuseport sockarray and closes qaffd's duplicated socket fd.

The listener config includes `short_cid_len` and `fallback_worker_id`. Fallback is used for unregistered CIDs, parse failures, and the first client Initial before the server has issued a routable CID.

In daemon-controlled mode, `REGISTER_CID` is accepted only for currently registered worker IDs. Existing CIDs are not automatically retired when a worker is unregistered; if packets still use those CIDs, the dataplane records `worker_missing` and falls back. The QUIC stack should retire its CIDs before removing a drained worker.

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
  cids
  workers
  stats
  config
  program
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

The current daemon has explicit worker unregistration but does not yet maintain a daemon-side CID owner index. It cannot bulk-retire all CIDs for a worker, so integrations should retire CIDs as part of the worker drain path before calling `UNREGISTER_WORKER`.

## qaffctl MVP

Initial commands:

```sh
qaffctl stats LISTENER_ID
qaffctl health LISTENER_ID
qaffctl config LISTENER_ID
qaffctl workers LISTENER_ID
qaffctl unregister-worker LISTENER_ID WORKER_ID
qaffctl stop LISTENER_ID
```

Future commands:

```sh
qaffctl listeners
qaffctl cids LISTENER_ID --limit 20
```

Before map pinning exists, `qaffctl` talks to `qaffd` over the daemon Unix socket.

## Open Decisions

- Whether qaffd should create worker sockets itself or accept worker socket fds.
- Whether map pinning should be optional in embedded mode.
- How to represent CID keys in CLI output without leaking sensitive routing material by default.
