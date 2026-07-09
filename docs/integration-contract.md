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

The worker ID used in `qaff_register_worker_socket()` is also the key used by the eBPF program to select a socket from the reuseport sockarray.

## Listener Configuration

QUIC short headers do not carry a DCID length. The listener must provide a fixed server CID length:

```c
struct qaff_options options;
qaff_options_init(&options);
options.short_cid_len = 8;
```

For the stateful CID registry mode, every server-issued CID routed by `quic-affinity` must use this configured length once 1-RTT short headers are expected.

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

## qaffd Startup Sequence

When using `qaffd`, the privileged daemon owns BPF setup:

1. Start `qaffd` with a Unix socket path, BPF object path, and `short_cid_len`.
2. Each worker creates and binds its UDP `SO_REUSEPORT` socket.
3. Each worker passes its socket fd to `qaffd` with `REGISTER_WORKER`.
4. `qaffd` registers the socket in the sockarray and attaches BPF on first worker registration.
5. Workers register and retire server-issued CIDs through the control API.

The current MVP supports one listener per `qaffd` process.

## CID Registration

When the QUIC stack creates or advertises a server-side CID, it must register that CID before packets using it are expected to arrive:

```c
qaff_register_cid(ctx, cid, cid_len, worker_id);
```

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

## Packet Routing Semantics

The dataplane behavior is:

1. Confirm the packet is UDP.
2. Skip the UDP header.
3. Parse the QUIC DCID.
4. Lookup the DCID in the CID map.
5. If found, select the registered worker socket.
6. If not found or parsing fails, select the fallback worker.

Current fallback worker:

```text
worker_id = 0
```

This is an MVP behavior and will become configurable.

## IPv4 and IPv6

`sk_reuseport_md->data` starts at the UDP header for both IPv4 and IPv6. The eBPF dataplane skips the fixed 8-byte UDP header before parsing QUIC.

The dataplane records IPv4 and IPv6 counters separately.

## Capabilities

Loading and attaching eBPF usually requires privileges such as:

```text
cap_bpf,cap_net_admin,cap_perfmon,cap_sys_resource
```

Development tests can use file capabilities on the test executable. Production deployments should prefer a small privileged control-plane process and keep business workers unprivileged where possible.

## Error Semantics

The dataplane does not send stateless resets.

If routing fails, the MVP behavior is fallback selection. Future policies may allow drop-on-error or configurable fallback behavior.

The application should read dataplane counters through `qaff_read_stats()` and alert on unexpected increases in:

- `parse_error`
- `fallback`
- `worker_missing`
- `zero_length_cid`

## Minimal API Surface

```c
void qaff_options_init(struct qaff_options *options);
int qaff_open(const struct qaff_options *options, struct qaff_context **out);
void qaff_close(struct qaff_context *ctx);

int qaff_register_worker_socket(struct qaff_context *ctx,
                                uint32_t worker_id,
                                int socket_fd);

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
