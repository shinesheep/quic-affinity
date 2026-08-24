# qaffd State Store

qaffd persists worker registration generations when `--state-path` is set.
The snapshot is an internal restart mechanism, not a public interchange format.
Before the first compatibility baseline, qaffd accepts only the current format.
CID profile v2 requires `--state-path` together with `--pin-root`; qaffd rejects
v2 at startup if either persistence component is absent.

## Format

The file is canonical UTF-8-compatible ASCII text ending in newlines:

```text
qaffd-state
worker 7 3
generation 12 9
```

`worker` records restore a registered worker generation. `generation` records
preserve the last generation of an unregistered worker, preventing stale
passive entries from becoming valid after an ID is reused. Each worker ID may
appear once. IDs and generations are unsigned canonical decimal numbers;
generation zero and values above `QAFF_WORKER_GENERATION_MAX` are rejected.

## Durability and validation

Snapshots are written to a mode-0600 temporary file in the destination
directory, fully written and fsynced, atomically renamed, and followed by a
parent directory fsync. Failed writes remove the temporary file.

Failures before `rename` leave the previous snapshot intact. A parent-directory
sync failure occurs after the new snapshot becomes visible, so the state-store
API reports `QAFFD_STATE_STORE_SAVE_COMMITTED_UNSYNCED` instead of a generic
pre-commit error. qaffd keeps the new in-memory/BPF state, emits a
`state_persistence_degraded` audit event, and avoids rolling back into a state
that disagrees with the visible snapshot. Durability across a power loss is not
guaranteed when this warning occurs.

Worker unregistration uses the generation tombstone as its transaction commit
point. qaffd writes the prospective tombstone before withdrawing the worker
generation and socket, then removes exact CIDs, passive entries, and
socket-cookie ownership. A pre-commit snapshot failure therefore leaves all
live routing unchanged for an explicit management unregistration. When qaffd
has independently confirmed loss of worker liveness through lease close,
pidfd, heartbeat timeout, failed leased-registration reply, or recovery
timeout, it instead fails closed: generation/socket withdrawal and local FD
cleanup proceed even if the tombstone cannot be written. qaffd then retries
the current snapshot at a one-second interval and reports degraded persistence
health until it succeeds. After commit, generation/socket withdrawal happens
first so a later cleanup error cannot leave the worker routable. Cleanup is
idempotent. If socket-map, reverse-cookie, exact-CID, or passive-CID cleanup
fails after the tombstone commit, qaffd quarantines that worker ID and retries
the complete cleanup. The fair retry queue advances by at most one worker per
second, bounding expensive full-map scans. The ID cannot be registered again
until cleanup succeeds, preventing an old retry from deleting a replacement
worker's state. If qaffd stops during that phase, startup treats the durable
tombstone as authoritative and removes residual pinned BPF state before
accepting control connections.
Pre-commit failures emit `worker_unregistration_commit_failed`; failures in
the retryable post-commit cleanup emit `worker_unregistration_incomplete` with
the failing stage. `qaffctl health` fails while
`state_persistence_degraded=1`; `qaffctl config` also exposes cumulative
`state_persistence_error_count` and `state_persistence_retry_count` values for
the current daemon process. Post-tombstone cleanup health is exposed separately
through `worker_cleanup_degraded`, `worker_cleanup_pending_count`,
`worker_cleanup_error_count`, and `worker_cleanup_retry_count`; health fails
while any cleanup remains pending.

Registration uses the inverse transaction boundary: local registry and durable
state are not committed until all BPF insertion stages succeed. If rollback of
a failed insertion is itself incomplete, the same retry queue quarantines the
worker ID. New registrations use full dataplane cleanup. A failed claim of a
recovered worker uses route withdrawal only, preserving the durable record,
exact/passive CIDs, and reverse-cookie ownership needed for another claim.

Loading uses `O_NOFOLLOW` and accepts only a private regular file owned by the
daemon user, with no group/world permissions and exactly one hard link. Parsing
is transactional: truncated lines,
embedded NUL bytes, unknown or duplicate records, trailing fields, and invalid
ranges fail before any caller state is changed. A missing snapshot is treated
as an empty initial state.

The implementation and deterministic fault tests for interrupted/short writes,
zero-progress writes, file and directory sync failures, rename failures, and
temporary-file cleanup are in `qaffd/state_store.c` and
`tests/test_qaffd_state_store.c`.
