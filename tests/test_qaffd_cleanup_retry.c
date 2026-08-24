#include "cleanup_retry.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct cleanup_fixture {
  unsigned int calls[4];
  unsigned int failures_remaining[4];
};

static int check(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "check failed: %s\n", message);
    return -1;
  }
  return 0;
}

static int cleanup_worker(void *opaque, uint32_t worker_id) {
  struct cleanup_fixture *fixture = opaque;
  fixture->calls[worker_id]++;
  if (fixture->failures_remaining[worker_id] > 0) {
    fixture->failures_remaining[worker_id]--;
    errno = EAGAIN;
    return -1;
  }
  return 0;
}

int main(void) {
  uint8_t pending[4];
  struct qaffd_cleanup_retry retry;
  if (qaffd_cleanup_retry_init(&retry, pending, 4, 1000) != 0) {
    perror("qaffd_cleanup_retry_init");
    return 1;
  }

  if (qaffd_cleanup_retry_mark_failed(&retry, 1, 100) != 0 ||
      qaffd_cleanup_retry_mark_failed(&retry, 3, 900) != 0 ||
      qaffd_cleanup_retry_mark_failed(&retry, 1, 950) != 0 ||
      check(retry.pending_count == 2, "pending IDs are deduplicated") != 0 ||
      check(retry.error_count == 3, "initial failures are counted") != 0 ||
      check(qaffd_cleanup_retry_is_pending(&retry, 1),
            "marked worker is pending") != 0 ||
      check(qaffd_cleanup_retry_poll_timeout(&retry, 100) == 1000,
            "new failures do not postpone existing retries") != 0) {
    return 1;
  }
  errno = 0;
  if (qaffd_cleanup_retry_mark_failed(&retry, 4, 100) == 0 ||
      check(errno == EINVAL, "out-of-range worker is rejected") != 0) {
    return 1;
  }

  struct cleanup_fixture fixture;
  memset(&fixture, 0, sizeof(fixture));
  fixture.failures_remaining[1] = 1;
  if (qaffd_cleanup_retry_run_due(&retry,
                                  1099,
                                  cleanup_worker,
                                  &fixture) != 0 ||
      check(fixture.calls[1] == 0 && fixture.calls[3] == 0,
            "cleanup does not run before deadline") != 0) {
    return 1;
  }
  if (qaffd_cleanup_retry_run_due(&retry,
                                  1100,
                                  cleanup_worker,
                                  &fixture) == 0 ||
      check(retry.pending_count == 2, "failed worker remains queued") != 0 ||
      check(qaffd_cleanup_retry_is_pending(&retry, 1),
            "failed worker remains pending") != 0 ||
      check(qaffd_cleanup_retry_is_pending(&retry, 3),
            "one worker is attempted per interval") != 0 ||
      check(retry.retry_count == 1 && retry.error_count == 4,
            "retry attempts and failures are counted") != 0 ||
      check(qaffd_cleanup_retry_poll_timeout(&retry, 1100) == 1000,
            "failed retry is rate limited") != 0) {
    return 1;
  }
  if (qaffd_cleanup_retry_run_due(&retry,
                                  2100,
                                  cleanup_worker,
                                  &fixture) != 0 ||
      check(retry.pending_count == 1,
            "round-robin retry clears another worker") != 0 ||
      check(!qaffd_cleanup_retry_is_pending(&retry, 3),
            "successful worker leaves quarantine") != 0 ||
      check(retry.retry_count == 2,
            "successful retry is counted") != 0 ||
      check(qaffd_cleanup_retry_run_due(&retry,
                                        3100,
                                        cleanup_worker,
                                        &fixture) == 0,
            "failed worker is retried after fair rotation") != 0 ||
      check(retry.pending_count == 0 && retry.retry_at_ms == 0,
            "transient failure recovers") != 0 ||
      check(retry.retry_count == 3,
            "recovery attempt is counted") != 0 ||
      check(qaffd_cleanup_retry_poll_timeout(&retry, 2100) == -1,
            "healthy queue has no deadline") != 0) {
    return 1;
  }

  if (qaffd_cleanup_retry_mark_failed(&retry, 0, 0) != 0) {
    return 1;
  }
  retry.retry_at_ms = (uint64_t)INT_MAX + 5000u;
  if (check(qaffd_cleanup_retry_poll_timeout(&retry, 0) == INT_MAX,
            "large deadline is clamped") != 0) {
    return 1;
  }
  if (qaffd_cleanup_retry_clear(&retry, 0) != 0 ||
      check(retry.pending_count == 0 && retry.retry_at_ms == 0,
            "explicit completion cancels pending retry") != 0) {
    return 1;
  }

  puts("qaffd cleanup retry tests passed");
  return 0;
}
