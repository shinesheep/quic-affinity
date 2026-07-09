# Control Plane Plan

The MVP currently lets an application create maps, load the BPF object, attach the program, and register workers/CIDs in-process.

The next step is a small control plane that can own privileged BPF operations while QUIC workers stay mostly unprivileged.

## Goals

- Keep BPF privileges out of business workers where possible.
- Make map and program state inspectable by `qaffctl`.
- Support worker restart and graceful reload.
- Support multiple listeners.
- Preserve current library-first integration path.

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

## qaffctl MVP

Initial commands:

```sh
qaffctl listeners
qaffctl stats LISTENER_ID
qaffctl workers LISTENER_ID
qaffctl cids LISTENER_ID --limit 20
```

Before qaffd exists, `qaffctl` can inspect pinned maps directly.

## Open Decisions

- Whether qaffd should create worker sockets itself or accept worker socket fds.
- Whether fallback worker should be configurable through `qaff_config`.
- Whether map pinning should be optional in embedded mode.
- How to represent CID keys in CLI output without leaking sensitive routing material by default.

