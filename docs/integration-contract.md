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

1. Start `qaffd` with a Unix socket path, BPF object path, `short_cid_len`, and optional `fallback_worker_id`.
2. Each worker creates and binds its UDP `SO_REUSEPORT` socket.
3. Each worker passes its socket fd to `qaffd` with `REGISTER_WORKER`.
4. `qaffd` registers the socket in the sockarray and attaches BPF on first worker registration.
5. Workers register and retire server-issued CIDs through the control API.

The current MVP supports one listener per `qaffd` process.

Stats and shutdown are available through `qaffctl`:

```sh
qaffctl health /tmp/qaffd.sock
qaffctl config /tmp/qaffd.sock
qaffctl workers /tmp/qaffd.sock
qaffctl stats /tmp/qaffd.sock
qaffctl stop /tmp/qaffd.sock
```

The repository includes `qaff_minimal_control` as a small worker-side example for this mode. It creates UDP reuseport sockets, passes them to `qaffd`, and registers a sample server CID.

## quiche Integration Probe

If quiche FFI is built under `third_party/quiche`, the optional `qaff_quiche_control_probe` target is enabled.

The probe:

1. Creates a real quiche server-side connection with `quiche_accept()`.
2. Reads the connection source CID with `quiche_conn_source_id()`.
3. Registers that source CID through `qaffd`.
4. Calls `quiche_conn_new_scid()` to provision an additional server CID.
5. Registers the additional CID through `qaffd`.
6. Drains `quiche_conn_retired_scid_iter()` and calls `RETIRE_CID` for any retired source CIDs.

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

Fallback worker:

```text
worker_id = qaff_options.fallback_worker_id
```

The default is `0`. In daemon-controlled mode this is set with `qaffd --fallback-worker ID` and can be inspected with `qaffctl config`.

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
