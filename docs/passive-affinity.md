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
  confidence,
  learned_at,
  last_seen,
  source,
  generation_or_epoch
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

- qaffd receives worker socket fds through the existing control API, but the
  application does not register CIDs.
- A launcher or supervisor creates the reuseport sockets, registers them with
  qaffd, and then starts the customer program with inherited sockets.
- A deployment-specific agent discovers sockets and registers only those that
  safely match the listener. This is the least preferred option and requires
  strict validation.

Without a reliable socket-to-worker mapping, passive mode cannot safely select
from the reuseport sockarray.

## Fallback Selection

Fallback selection is used for:

- first client Initial packets
- unknown CIDs
- parse failures
- zero-length CIDs
- expired or rejected passive entries
- worker-missing conditions

Possible fallback policies:

```text
fixed worker        route all unknown packets to one worker
kernel default      let Linux reuseport choose normally
tuple hash          hash client/server 4-tuple to a worker
CPU/RSS hint        choose a worker associated with the receiving CPU
```

For black-box deployments, `tuple hash` or `kernel default` are usually safer
than `fixed worker`. A fixed worker is simple but can overload one worker and
can place new connections far from where the application would naturally handle
them.

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
must expire entries.

Recommended cleanup:

- Use an LRU hash map or userspace-managed hash table with bounded size.
- Track `last_seen` and remove stale entries.
- Use shorter TTL for low-confidence entries.
- Use longer TTL for egress-learned high-confidence entries.
- Drop all entries for a worker when that worker socket is unregistered.
- Use a listener or worker epoch to reject entries learned before a worker
  replacement.

Example defaults:

```text
low confidence TTL      10-30 seconds
medium confidence TTL   2-5 minutes
high confidence TTL     10-30 minutes
max entries             deployment sized, bounded by memory budget
```

These values are policy defaults, not protocol rules.

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

Add counters for:

```text
passive_ingress_hit_high
passive_ingress_hit_medium
passive_ingress_hit_low
passive_ingress_miss
passive_egress_learn
passive_ingress_learn
passive_promote
passive_expire
passive_evict
passive_reject_generation
passive_reject_parse
passive_reject_pressure
passive_worker_missing
passive_rebinding_hit
```

`qaffctl` should expose:

- passive mode enabled/disabled
- table size and capacity
- hit rate by confidence
- eviction and expiration rates
- worker generation mismatch count
- rebinding hit count
- top-level health status without printing CID bytes by default

## Recommended Rollout

1. Implement passive table metadata in userspace first, with bounded cleanup and
   counters.
2. Add ingress-only passive learning behind an explicit feature flag.
3. Keep low-confidence routing disabled by default; observe miss and candidate
   rates first.
4. Add egress learning and promote egress-learned entries to high confidence.
5. Enable routing only for high-confidence entries by default.
6. Add aggressive mode for operators that accept best-effort behavior.
7. Add worker epoch handling before recommending passive mode for reloads or
   long-running production listeners.

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
