# Passive Affinity Mode

This document describes a best-effort black-box mode for `quic-affinity`.

The normal integration model remains the preferred production model: the QUIC
server registers worker sockets and server-issued CIDs explicitly, or issues a
routable CID profile. Passive affinity is for deployments where the customer
program cannot or will not integrate a library or CID lifecycle hooks.

Passive affinity tries to recover useful QUIC worker affinity by observing
packets and learning CID ownership outside the application. It is similar in
spirit to connection tracking, but it is not equivalent to application-owned
QUIC state.

## Goals

- Improve affinity for NAT rebinding and connection migration without changing
  the customer program.
- Keep packets for a learned QUIC CID on the same reuseport worker socket.
- Support CPU-oriented deployments when each worker socket is serviced by a
  CPU-pinned thread or process.
- Fail conservatively when ownership cannot be learned with enough confidence.
- Expose enough counters to make black-box behavior debuggable.

## Non-Goals

- It does not provide the same correctness guarantee as explicit CID
  registration.
- It does not directly schedule packets onto a CPU. It selects a socket in a
  `SO_REUSEPORT` group. CPU affinity is achieved only when the deployment maps
  one worker socket to one CPU-pinned worker.
- It does not infer application-level connection migration, connection
  handoff, or CID retirement with full accuracy.
- It does not support zero-length server CIDs.

## Deployment Shape

Passive mode still needs a listener socket group that can be selected by
`SO_REUSEPORT` eBPF:

```text
UDP packet
  -> Linux SO_REUSEPORT eBPF program
  -> parse QUIC DCID
  -> consult passive CID table
  -> select learned worker socket or fallback selection
```

For CPU affinity, use this shape:

```text
worker 0: UDP reuseport socket 0, thread/process pinned to CPU 0
worker 1: UDP reuseport socket 1, thread/process pinned to CPU 1
worker N: UDP reuseport socket N, thread/process pinned to CPU N
```

If multiple threads race on the same UDP socket, passive mode can only keep a
CID on that socket. It cannot control which thread reads the datagram.

## Recommended Black-Box Design

The best black-box design combines ingress routing with egress learning.

### Ingress Path

The existing reuseport eBPF program observes inbound UDP packets before user
space receives them.

For each packet:

1. Parse the QUIC DCID.
2. Look up the DCID in the passive CID table.
3. If the entry is valid, select the recorded worker socket.
4. If the entry is missing or invalid, use fallback selection.
5. Optionally create a low-confidence candidate from tuple-to-worker state.

The passive CID table is:

```text
CID -> {
  worker_id,
  worker_generation,
  confidence,
  source,
  expires_at_ns
}
```

### Egress Path

An egress observer watches packets sent by worker sockets. This can be
implemented with a TC egress program, cgroup skb hook, or another deployment
appropriate BPF hook.

For each outbound QUIC packet:

1. Identify the sending socket or worker.
2. Parse server Source Connection ID where the packet format exposes it.
3. Learn that this server CID belongs to the sending worker.
4. Install or refresh a high-confidence passive CID entry.

This is stronger than ingress-only learning because the server worker that sent
the CID is usually the worker that owns the connection state. When the client
later sends that CID as a DCID, the ingress path can route it back to the same
worker even if the client address or UDP port changed.

The initial implementation uses an optional cgroup skb egress program. Start
`qaffd` with `--egress-cgroup PATH` where `PATH` is a cgroup v2 directory. The
egress learner currently parses QUIC long headers and learns the server Source
Connection ID from visible Initial/Handshake packets. It does not parse
encrypted short-header frames such as `NEW_CONNECTION_ID`; those remain outside
the black-box dataplane's reliable visibility.

### Socket-to-Worker Mapping

Passive mode still needs a way to map kernel-observed sockets to worker IDs.
Acceptable options include:

- An embedded integration calls `qaff_register_worker_socket()`, which updates
  both the reuseport sockarray and the socket-cookie reverse map.
- qaffd receives worker socket fds through the existing control API, but the
  application does not register CIDs.
- `qaff-agent run` launches an existing application, discovers its socket, and
  owns a leased registration for the child lifetime.
- `qaff-agent watch` discovers a socket in an existing PID. This uses strict
  protocol, `SO_REUSEPORT`, bound-address, port, and unique socket-cookie
  validation, but usually requires `CAP_SYS_PTRACE`.

Without a reliable socket-to-worker mapping, passive mode cannot safely select
from the reuseport sockarray.

Traffic readiness must be gated on all expected agents being registered. If a
worker sends its first long-header response before qaff-agent installs the
socket-cookie mapping, the egress learner cannot retroactively recover that
SCID. Likewise, attaching `watch` to an already-busy process cannot reconstruct
CIDs that were visible only in earlier packets.

## Fallback Selection

Fallback selection is used for:

- first client Initial packets
- unknown CIDs
- parse failures
- zero-length CIDs
- expired or rejected passive entries
- worker-missing conditions

Implemented fallback policies:

```text
fixed worker        --fallback-mode fixed; route to --fallback-worker
kernel default      --fallback-mode kernel; use Linux reuseport selection
```

For black-box deployments, `kernel default` is usually safer than `fixed
worker`. A fixed worker is simple but can overload one worker and can place new
connections far from where the application would naturally handle them.

## Ingress-Only Mode

Ingress-only mode is simpler but weaker.

It can learn:

```text
4-tuple -> selected worker
CID -> selected worker
```

This helps when the original address/port flow was routed correctly and later
packets expose the same server CID. It can preserve affinity after NAT rebinding
if the CID was learned before the rebinding.

The main weakness is first-learn correctness. If the initial worker selection
was wrong, ingress-only mode may convert a transient miss into a persistent
wrong route.

Ingress-only mode should therefore mark entries as low confidence unless they
are observed repeatedly or correlated with stable tuple ownership.

## Confidence Model

Passive entries should not all be treated equally.

Suggested levels:

```text
high       learned from egress server SCID on a known worker socket
medium     learned from stable ingress tuple-to-worker correlation
low        learned from a single ingress observation after fallback selection
rejected   known unsafe, expired, or worker generation mismatch
```

Ingress routing should prefer high and medium entries. Low-confidence entries
can be used only when the operator explicitly enables aggressive mode, or after
they are promoted by repeated successful observations.

## Expiration and Cleanup

Because the application does not provide CID retirement events, passive mode
must expire entries. Valid ingress hits use a sliding lifetime: the dataplane
refreshes an entry only after it enters the latter half of its TTL. This keeps
active long-lived connections routable without writing the map on every
packet.

Recommended cleanup:

- Use an LRU hash map or userspace-managed hash table with bounded size.
- Refresh active entries and remove stale entries.
- Use shorter TTL for low-confidence entries.
- Use longer TTL for egress-learned high-confidence entries.
- Drop all entries for a worker when that worker socket is unregistered.
- Use a listener or worker epoch to reject entries learned before a worker
  replacement.

Example defaults:

```text
low confidence TTL      30 seconds
medium confidence TTL   5 minutes
high confidence TTL     15 minutes
egress-learned TTL      60 minutes
cleanup scan interval   30 seconds
max entries             1,048,576 with LRU eviction
```

These are the implemented policy defaults, not QUIC protocol rules.

## Safety Risks

### Wrong Learning

The largest risk is learning the wrong owner:

```text
CID X -> worker 1
```

when the real connection state is on worker 0. If the system keeps routing CID
X to worker 1, the connection may see persistent packet loss.

Mitigations:

- Prefer egress-learned entries.
- Keep ingress-only entries low confidence.
- Expire low-confidence entries quickly.
- Count repeated fallback and worker-missing events.
- Provide an operator switch to disable aggressive low-confidence routing.

### Map Pollution

UDP packets can be spoofed. An attacker can send many random CIDs and force
state allocation.

Mitigations:

- Bound passive tables.
- Use LRU eviction.
- Rate-limit learning from unknown sources.
- Avoid installing high-confidence entries from ingress-only observations.
- Track per-source or per-prefix pressure counters where practical.

### Worker Replacement

If worker ID 2 dies and a new worker reuses ID 2, old passive CID entries may
route stale packets to the replacement worker.

Mitigations:

- Maintain worker epochs or generations.
- Store the generation in each passive entry.
- Reject entries whose generation no longer matches the worker table.
- Flush all entries for a worker on unregister.

### CID Retirement Blindness

Without application hooks, passive mode does not know exactly when a CID was
retired.

Mitigations:

- TTL-based cleanup.
- Egress refresh on active use.
- Conservative maximum lifetime.
- Operator-visible stale-entry counters.

### QUIC Parsing Ambiguity

QUIC short headers do not carry DCID length. Passive mode still needs a
listener-level `short_cid_len` or another configured parsing profile.

Mitigations:

- Require explicit `short_cid_len`.
- Count parse errors and zero-length CIDs.
- Do not enable passive routing when CID length is unknown.

## Stability Risks

- Extra BPF map lookups add per-packet overhead.
- Egress observation adds another dataplane hook and must be kept verifier
  friendly.
- Cross-CPU routing can increase cache misses if packets arrive on one CPU but
  wake a worker on another CPU.
- Aggressive learning can make transient fallback mistakes last longer.
- Large passive tables can cause memory pressure or noisy eviction behavior.

Passive mode should therefore be opt-in and ship with conservative defaults.

## Observability

Current counters include:

```text
passive_hit
passive_miss
passive_reject_confidence
passive_reject_generation
passive_reject_expired
passive_egress_learn
passive_egress_parse_miss
passive_egress_not_udp
passive_egress_zero_length_scid
passive_egress_too_long_scid
passive_egress_socket_cookie_hit
passive_egress_socket_cookie_miss
passive_egress_map_update_error
```

`qaffctl config` and `qaffctl health` expose:

- passive mode enabled/disabled
- table size and capacity
- cleanup scan interval
- expiry and worker-purge totals
- cleanup errors
- top-level health status without printing CID bytes by default

## Recommended Rollout

1. Start with egress learning and the default high-confidence threshold.
2. Monitor passive hit/miss, expiry, cookie-miss, and map-update-error counters.
3. Validate worker-unregister purging and generation rejection during reloads.
4. Tune the cleanup interval only after measuring table size and scan cost.
5. Add ingress-only learning only behind a separate feature flag.
6. Keep low-confidence ingress routing disabled until rate limits and pressure
   controls are in place.

## Product Positioning

Passive affinity should be documented as:

```text
best effort, zero application CID hooks, useful for migration/rebinding
optimization when the deployment can expose worker sockets
```

It should not be described as:

```text
fully correct QUIC affinity without application cooperation
```

The practical guarantee hierarchy is:

```text
strong       explicit CID registration or routable CID profile
medium       egress + ingress passive learning
weak         ingress-only passive learning
none         plain Linux reuseport/RSS
```
