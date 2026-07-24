# Passive Affinity Next Steps

This document tracks the next work items for passive affinity after the initial
passive routing substrate, qaffd control operations, socket-cookie mapping, and
cgroup egress learner have landed.

## 1. Productionize Egress Learner Boundaries

Status: implemented in README, the integration contract, detailed passive-mode
documentation, and egress-specific counters.

The current egress learner intentionally learns only visible QUIC long-header
Source Connection IDs. That is the right first scope, but the product boundary
needs to be explicit everywhere operators read about the feature.

Tasks:

- Document the long-header-only learning scope in `README.md` and
  `docs/integration-contract.md`.
- Explain that encrypted short-header frames such as `NEW_CONNECTION_ID` are
  not parsed by the black-box dataplane.
- Add more egress-specific counters:
  - parse miss
  - non-UDP
  - zero-length SCID
  - too-long SCID
  - socket-cookie hit
  - socket-cookie miss
- Keep the existing routing priority explicit:

```text
exact CID registration > routable CID profile > passive CID > fallback
```

## 2. Add Passive Entry Lifecycle Management

Status: implemented with monotonic TTLs, periodic qaffd cleanup, dataplane
expiry rejection, and worker-unregister purging.

The passive map remains bounded by LRU behavior. qaffd also assigns monotonic
TTLs by confidence and source, periodically removes expired entries, and
purges all entries owned by an unregistered worker.

Tasks:

- Make qaffd periodically scan `qaff_passive_cids`.
- Use `expires_at_ns` or equivalent metadata for cleanup decisions.
- Apply shorter lifetimes to low-confidence entries.
- Apply longer lifetimes to egress-learned high-confidence entries.
- Remove all passive entries for a worker when the worker unregisters.
- Add counters for passive expiry and eviction where practical.

## 3. Improve Passive Map Observability

Status: implemented in qaffd/qaffctl config and health output.

Operators can now inspect passive entry count and capacity, cleanup interval,
expiry and worker-purge totals, legacy expiry initialization, and cleanup
errors without exposing CID bytes.

Tasks:

- Add passive entry count to qaffd/qaffctl health or config output.
- Expose passive table capacity.
- Expose passive hit/miss/reject counters clearly in `qaffctl stats`.
- Expose generation-reject counts.
- Keep CID bytes hidden by default.

Potential CLI output:

```text
passive_entry_count=N
passive_entry_capacity=N
passive_egress_learn=N
passive_hit=N
passive_miss=N
passive_reject_generation=N
```

## 4. Verify Worker Restart and Stale Passive Entries

Status: implemented in `tests/test_qaffd_restart.c`.

Passive entries include worker generation, and the dataplane rejects entries
whose generation no longer matches. This needs focused coverage.

Tasks:

- Register worker 2.
- Learn or register a passive CID for worker 2.
- Unregister worker 2.
- Re-register worker 2, forcing generation change.
- Send a packet with the old passive CID.
- Verify it does not route to the replacement worker.
- Verify `passive_reject_generation` increments and the packet falls back.

This should be the next implementation task because it validates the main stale
state safety mechanism.

## 5. Add Real QUIC Egress Learning Smoke

Status: implemented by `quiche_passive_egress_smoke`, which runs
`qaff_quiche_udp_smoke --passive-egress` with qaffd egress learning enabled.

The current egress learning smoke uses QUIC-like long-header packets. The next
proof point should use a real QUIC stack.

Tasks:

- Extend the existing quiche UDP smoke or add a separate quiche passive smoke.
- Start qaffd with:

```text
--passive-affinity --egress-cgroup /sys/fs/cgroup
```

- Let the server send a real long-header packet with its SCID.
- Verify the egress learner records that SCID as passive ownership.
- Have the client send a later packet using that CID from a changed source port.
- Verify it reaches the original worker.
- Verify passive egress learn and passive hit counters increase.

This is the key demonstration that black-box passive affinity improves NAT
rebinding or migration behavior without explicit CID registration.

## 6. Complete Deployment and Packaging Support

Status: implemented in the systemd environment template, service unit,
packaging smoke, README, and integration contract.

The systemd templates and packaging smoke should know about passive affinity
and optional egress attach.

Tasks:

- Update `packaging/systemd/qaffd.env.example` with optional variables:

```text
QAFF_EGRESS_CGROUP=/sys/fs/cgroup
QAFF_EXTRA_ARGS=--passive-affinity --egress-cgroup /sys/fs/cgroup
```

- Update packaging smoke expectations.
- Document cgroup v2 requirement.
- Document required BPF capabilities for cgroup attach.
- Explain that qaffd startup fails if `--egress-cgroup` is explicitly supplied
  but attach fails.

## 7. Define Passive Affinity Safety Policy

Status: conservative baseline implemented and documented. Per-source learning
rate limits remain a future hardening item if ingress-only learning is added.

Passive affinity must remain opt-in and conservative by default.

Tasks:

- Keep passive affinity disabled unless explicitly configured.
- Keep low-confidence passive routing disabled by default.
- Define pressure handling for passive maps.
- Consider learning rate limits.
- Consider per-source or per-prefix pressure counters for ingress learning if
  ingress-only learning is added later.
- Document that ingress-only learning is weaker than egress learning and should
  be treated as aggressive mode.

## Suggested Order

1. Worker restart and stale passive entry test.
2. Real quiche egress learning smoke.
3. Passive entry lifecycle cleanup.
4. Passive table observability.
5. Deployment and packaging updates.
6. Expanded egress counters.
7. Broader safety policy and ingress-only learning decisions.
