#ifndef QAFFD_CLEANUP_RETRY_H
#define QAFFD_CLEANUP_RETRY_H

#include <stddef.h>
#include <stdint.h>

typedef int (*qaffd_cleanup_retry_fn)(void *opaque, uint32_t worker_id);

/*
 * In-memory coordinator for durable-tombstone cleanup. One worker is retried
 * per interval in round-robin order so full-map cleanup cannot multiply into
 * an unbounded event-loop stall.
 */
struct qaffd_cleanup_retry {
  uint8_t *pending;
  size_t capacity;
  uint64_t retry_interval_ms;
  uint64_t retry_at_ms;
  uint64_t error_count;
  uint64_t retry_count;
  uint32_t pending_count;
  uint32_t next_worker_id;
};

int qaffd_cleanup_retry_init(struct qaffd_cleanup_retry *retry,
                             uint8_t *pending,
                             size_t capacity,
                             uint64_t retry_interval_ms);

int qaffd_cleanup_retry_is_pending(const struct qaffd_cleanup_retry *retry,
                                   uint32_t worker_id);

int qaffd_cleanup_retry_mark_failed(struct qaffd_cleanup_retry *retry,
                                    uint32_t worker_id,
                                    uint64_t now_ms);

int qaffd_cleanup_retry_poll_timeout(const struct qaffd_cleanup_retry *retry,
                                     uint64_t now_ms);

int qaffd_cleanup_retry_run_due(struct qaffd_cleanup_retry *retry,
                                uint64_t now_ms,
                                qaffd_cleanup_retry_fn cleanup_fn,
                                void *opaque);

#endif
