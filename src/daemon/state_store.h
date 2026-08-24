#ifndef QAFFD_STATE_STORE_H
#define QAFFD_STATE_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct qaffd_state_store_io {
  void *context;
  ssize_t (*write_fn)(void *context, int fd, const void *data, size_t len);
  int (*fsync_fn)(void *context, int fd);
  int (*rename_fn)(void *context, const char *old_path, const char *new_path);
};

enum qaffd_state_store_save_result {
  /* No new snapshot was committed. */
  QAFFD_STATE_STORE_SAVE_ERROR = -1,
  /* The new snapshot was committed and its directory entry was synced. */
  QAFFD_STATE_STORE_SAVE_OK = 0,
  /* The new snapshot is visible, but its directory entry may not be durable. */
  QAFFD_STATE_STORE_SAVE_COMMITTED_UNSYNCED = 1,
};

/*
 * Returns a qaffd_state_store_save_result; errors and warnings preserve errno.
 */
int qaffd_state_store_save(const char *path, const int *worker_registered,
                           const uint32_t *worker_generations,
                           size_t worker_capacity);

/* Internal test seam for deterministic filesystem fault injection. */
int qaffd_state_store_save_with_io(const char *path,
                                   const int *worker_registered,
                                   const uint32_t *worker_generations,
                                   size_t worker_capacity,
                                   const struct qaffd_state_store_io *io);

int qaffd_state_store_load(const char *path, int *worker_registered,
                           uint64_t *worker_registered_at_ms,
                           uint64_t *worker_last_seen_ms,
                           uint32_t *worker_generations, size_t worker_capacity,
                           uint64_t loaded_at_ms);

#endif
