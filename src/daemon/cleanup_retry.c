#include "cleanup_retry.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

int qaffd_cleanup_retry_init(struct qaffd_cleanup_retry *retry,
                             uint8_t *pending,
                             size_t capacity,
                             uint64_t retry_interval_ms) {
  if (retry == NULL || pending == NULL || capacity == 0 ||
      capacity > UINT32_MAX || retry_interval_ms == 0) {
    errno = EINVAL;
    return -1;
  }
  memset(retry, 0, sizeof(*retry));
  memset(pending, 0, capacity);
  retry->pending = pending;
  retry->capacity = capacity;
  retry->retry_interval_ms = retry_interval_ms;
  return 0;
}

int qaffd_cleanup_retry_is_pending(const struct qaffd_cleanup_retry *retry,
                                   uint32_t worker_id) {
  return retry != NULL && retry->pending != NULL &&
         worker_id < retry->capacity && retry->pending[worker_id] != 0;
}

int qaffd_cleanup_retry_mark_failed(struct qaffd_cleanup_retry *retry,
                                    uint32_t worker_id,
                                    uint64_t now_ms) {
  if (retry == NULL || retry->pending == NULL ||
      worker_id >= retry->capacity) {
    errno = EINVAL;
    return -1;
  }
  int queue_was_empty = retry->pending_count == 0;
  if (!retry->pending[worker_id]) {
    retry->pending[worker_id] = 1;
    retry->pending_count++;
  }
  retry->error_count++;
  if (queue_was_empty || retry->retry_at_ms == 0) {
    retry->retry_at_ms = now_ms + retry->retry_interval_ms;
  }
  return 0;
}

int qaffd_cleanup_retry_clear(struct qaffd_cleanup_retry *retry,
                              uint32_t worker_id) {
  if (retry == NULL || retry->pending == NULL ||
      worker_id >= retry->capacity) {
    errno = EINVAL;
    return -1;
  }
  if (retry->pending[worker_id]) {
    retry->pending[worker_id] = 0;
    retry->pending_count--;
  }
  if (retry->pending_count == 0) {
    retry->retry_at_ms = 0;
  }
  return 0;
}

int qaffd_cleanup_retry_poll_timeout(const struct qaffd_cleanup_retry *retry,
                                     uint64_t now_ms) {
  if (retry == NULL || retry->pending_count == 0) {
    return -1;
  }
  if (now_ms >= retry->retry_at_ms) {
    return 0;
  }
  uint64_t remaining = retry->retry_at_ms - now_ms;
  return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

int qaffd_cleanup_retry_run_due(struct qaffd_cleanup_retry *retry,
                                uint64_t now_ms,
                                qaffd_cleanup_retry_fn cleanup_fn,
                                void *opaque) {
  if (retry == NULL || retry->pending == NULL || cleanup_fn == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (retry->pending_count == 0 || now_ms < retry->retry_at_ms) {
    return 0;
  }

  uint32_t attempted_worker_id = UINT32_MAX;
  for (size_t offset = 0; offset < retry->capacity; offset++) {
    uint32_t worker_id =
        (uint32_t)((retry->next_worker_id + offset) % retry->capacity);
    if (!retry->pending[worker_id]) {
      continue;
    }
    attempted_worker_id = worker_id;
    break;
  }

  if (attempted_worker_id == UINT32_MAX) {
    errno = EIO;
    return -1;
  }
  retry->next_worker_id =
      attempted_worker_id + 1u < retry->capacity
          ? attempted_worker_id + 1u
          : 0;
  retry->retry_count++;
  int cleanup_rc = cleanup_fn(opaque, attempted_worker_id);
  int cleanup_errno = errno ? errno : EIO;
  if (cleanup_rc == 0) {
    (void)qaffd_cleanup_retry_clear(retry, attempted_worker_id);
  } else {
    retry->error_count++;
  }

  if (retry->pending_count != 0) {
    retry->retry_at_ms = now_ms + retry->retry_interval_ms;
  }
  if (cleanup_rc != 0) {
    errno = cleanup_errno;
    return -1;
  }
  return 0;
}
