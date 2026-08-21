#ifndef QAFFD_STATE_STORE_H
#define QAFFD_STATE_STORE_H

#include <stddef.h>
#include <stdint.h>

int qaffd_state_store_save(const char *path, const int *worker_registered,
                           const uint32_t *worker_generations,
                           size_t worker_capacity);

int qaffd_state_store_load(const char *path, int *worker_registered,
                           uint64_t *worker_registered_at_ms,
                           uint64_t *worker_last_seen_ms,
                           uint32_t *worker_generations, size_t worker_capacity,
                           uint64_t loaded_at_ms);

#endif
