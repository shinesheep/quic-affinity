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

The implementation is in `qaffd/worker_registry.c`; deterministic lifecycle,
rollback, bounds, and exhaustion tests are in
`tests/test_qaffd_worker_registry.c`.
