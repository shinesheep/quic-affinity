# qaffd CID Ownership Index

The CID ownership index is qaffd's process-local ownership mirror of the BPF
CID map. The BPF value stores worker ID plus generation, while the index maps
each canonical `qaff_cid_key` to its authorized worker ID and supports constant-time
average lookup, insertion, reassignment, and removal. qaffd uses it to authorize
CID retirement, retire every CID owned by a departing worker, recover ownership
after restart, and report BPF/userspace consistency.

Restart recovery accepts only entries whose worker ID is present in durable
state and whose stored generation equals that durable worker generation. The
pinned live generation must either match or be zero from a previous recovery
quarantine. Stale or malformed exact entries are removed before the control
socket opens. Runtime consistency checks compare the index owner, BPF owner,
and generation together.

The index combines a dense entry array with an open-addressed hash table. Hash
slots store one-based array positions; zero denotes an unused slot and
`SIZE_MAX` denotes a tombstone. Removing a non-tail entry moves the last dense
entry into its position and updates that entry's hash slot. This keeps worker
retirement linear in the number of tracked CIDs without leaving holes.

CID registration prepares the process-local ownership entry before publishing
the BPF route, so allocation failure cannot occur after the dataplane mutation.
A failed BPF insertion removes that provisional entry. Retirement treats an
already-absent BPF key as success and removes the ownership entry, making retry
self-healing after a partial delete. Worker teardown first retires indexed CIDs
and then sweeps the BPF map for matching map-only residue; the index is an
authorization and acceleration structure, not the cleanup source of truth.

Keys must be canonical: `len` cannot exceed `QAFF_MAX_CID_LEN`, and bytes after
`len` must be zero. `qaff_cid_key_from_bytes()` produces this representation.
The module validates canonical form on mutation, bounds allocation arithmetic,
and never returns positions that cannot be represented by `ptrdiff_t`.

`qaffd_cid_index_check()` verifies the relationship between the dense array and
hash table. Deterministic lifecycle, resizing, tombstone reuse, relocation, and
randomized model tests live in `tests/test_qaffd_cid_index.c`. The implementation
is in `qaffd/cid_index.c`; BPF map updates and transaction compensation remain
in `qaffd/main.c`.
