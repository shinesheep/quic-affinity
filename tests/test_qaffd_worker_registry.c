#include "worker_registry.h"

#include "quic_affinity/types.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPACITY 4u

struct fixture {
  int worker_fds[CAPACITY];
  int lease_fds[CAPACITY];
  int pidfds[CAPACITY];
  uint64_t cookies[CAPACITY];
  int registered[CAPACITY];
  uint64_t registered_at[CAPACITY];
  uint64_t last_seen[CAPACITY];
  uint32_t generations[CAPACITY];
  uint32_t target_pids[CAPACITY];
  struct qaffd_peer_cred creds[CAPACITY];
  struct qaffd_worker_registry registry;
};

static int expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "worker registry test failed: %s\n", message);
    return -1;
  }
  return 0;
}

static int fixture_init(struct fixture *fixture) {
  memset(fixture, 0, sizeof(*fixture));
  fixture->registry = (struct qaffd_worker_registry){
      .capacity = CAPACITY,
      .worker_fds = fixture->worker_fds,
      .lease_fds = fixture->lease_fds,
      .pidfds = fixture->pidfds,
      .socket_cookies = fixture->cookies,
      .registered = fixture->registered,
      .registered_at_ms = fixture->registered_at,
      .last_seen_ms = fixture->last_seen,
      .generations = fixture->generations,
      .target_pids = fixture->target_pids,
      .creds = fixture->creds,
  };
  return qaffd_worker_registry_init(&fixture->registry);
}

static int test_lifecycle(void) {
  struct fixture fixture;
  if (fixture_init(&fixture) != 0 ||
      expect(fixture.worker_fds[0] == -1 && fixture.lease_fds[0] == -1 &&
                 fixture.pidfds[0] == -1,
             "initial descriptors are invalid") != 0) {
    return -1;
  }
  struct qaffd_peer_cred cred = {.valid = 1, .pid = 10, .uid = 20, .gid = 30};
  if (qaffd_worker_registry_register(&fixture.registry, 2, 40, 50, 3, 60, 70,
                                     &cred) != 0 ||
      expect(qaffd_worker_registry_count(&fixture.registry) == 1,
             "registration changes count") != 0 ||
      expect(fixture.registered[2] && fixture.worker_fds[2] == 40 &&
                 fixture.cookies[2] == 50 && fixture.generations[2] == 3 &&
                 fixture.target_pids[2] == 60 && fixture.last_seen[2] == 70 &&
                 fixture.creds[2].uid == 20,
             "registration metadata is committed") != 0) {
    return -1;
  }
  if (qaffd_worker_registry_heartbeat(&fixture.registry, 2, 80) != 0 ||
      expect(fixture.last_seen[2] == 80, "heartbeat refreshes liveness") != 0) {
    return -1;
  }

  fixture.lease_fds[2] = 90;
  fixture.pidfds[2] = 91;
  struct qaffd_worker_record snapshot;
  if (qaffd_worker_registry_snapshot(&fixture.registry, 2, &snapshot) != 0 ||
      qaffd_worker_registry_clear(&fixture.registry, 2) != 0 ||
      expect(!fixture.registered[2] && fixture.generations[2] == 3 &&
                 fixture.worker_fds[2] == -1 && fixture.lease_fds[2] == -1,
             "clear preserves generation tombstone") != 0 ||
      qaffd_worker_registry_restore(&fixture.registry, 2, &snapshot) != 0 ||
      expect(fixture.registered[2] && fixture.lease_fds[2] == 90 &&
                 fixture.pidfds[2] == 91 && fixture.last_seen[2] == 80,
             "snapshot restores the full record") != 0) {
    return -1;
  }
  return 0;
}

static int test_generation_and_bounds(void) {
  uint32_t next = 0;
  if (qaffd_worker_registry_next_generation(0, &next) != 0 ||
      expect(next == QAFF_WORKER_GENERATION_DEFAULT,
             "first generation uses default") != 0 ||
      qaffd_worker_registry_next_generation(7, &next) != 0 ||
      expect(next == 8, "generation increments") != 0) {
    return -1;
  }
  errno = 0;
  if (expect(qaffd_worker_registry_next_generation(QAFF_WORKER_GENERATION_MAX,
                                                   &next) == -1 &&
                 errno == EOVERFLOW,
             "generation exhaustion does not wrap") != 0) {
    return -1;
  }

  struct fixture fixture;
  if (fixture_init(&fixture) != 0) {
    return -1;
  }
  errno = 0;
  return expect(qaffd_worker_registry_register(&fixture.registry, CAPACITY, 1,
                                               0, 1, 0, 1, NULL) == -1 &&
                    errno == EINVAL,
                "out-of-range worker is rejected");
}

int main(void) {
  if (test_lifecycle() != 0 || test_generation_and_bounds() != 0) {
    return 1;
  }
  puts("qaffd worker registry tests passed");
  return 0;
}
