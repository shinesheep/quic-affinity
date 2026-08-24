# qaffd Worker Registry

The worker registry centralizes qaffd's process-local lifecycle metadata while
qaffd remains responsible for socket, pidfd, BPF map, and persistence side
effects.

Each record tracks the worker socket, lease and pidfd handles, socket cookie,
registration and liveness times, generation, supervised PID, and peer
credentials. Registry operations provide initialization, counting, generation
allocation, registration commit, heartbeat refresh, full snapshot/restore, and
clear-with-generation-tombstone semantics.

The registry never wraps a generation: attempting to advance
`QAFF_WORKER_GENERATION_MAX` fails with `EOVERFLOW`. Clearing a worker resets its
live metadata and descriptors but intentionally preserves its generation so a
stale passive routing entry cannot become valid when the worker ID is reused.

Records restored after qaffd restart have no live worker fd and are therefore
reported as recovering. Startup withdraws their BPF generation and sockarray
entry while retaining enough cookie ownership to authenticate an exact-socket
claim. A same-socket claim restores the prior generation; expiry of the
recovery deadline clears the record while preserving its generation tombstone,
so a replacement socket advances to the next generation.

New leased registrations have a process-local pending-reply reservation. Until
the success reply is delivered, the worker cannot be registered again and its
new pidfd is not allowed to race reply completion by expiring the registration.
Live worker IDs otherwise reject every re-registration with `EBUSY`; callers
must explicitly finish the old lifecycle before starting the next one. This
keeps lease, pidfd, worker fd, and BPF ownership single-valued.

The implementation is in `qaffd/worker_registry.c`; deterministic lifecycle,
rollback, bounds, and exhaustion tests are in
`tests/test_qaffd_worker_registry.c`.
