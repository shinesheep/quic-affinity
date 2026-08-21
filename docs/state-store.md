# qaffd State Store

qaffd persists worker registration generations when `--state-path` is set.
The snapshot is an internal restart mechanism, not a public interchange format.
Before the first compatibility baseline, qaffd accepts only the current format.

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
directory, flushed and fsynced, atomically renamed, and followed by a parent
directory fsync. Failed writes remove the temporary file.

Loading uses `O_NOFOLLOW` and accepts only a private regular file owned by the
daemon user, with no group/world permissions and exactly one hard link. Parsing
is transactional: truncated lines,
embedded NUL bytes, unknown or duplicate records, trailing fields, and invalid
ranges fail before any caller state is changed. A missing snapshot is treated
as an empty initial state.

The implementation and deterministic fault tests are in `qaffd/state_store.c`
and `tests/test_qaffd_state_store.c`.
