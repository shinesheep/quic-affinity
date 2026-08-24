#ifndef QAFFD_WORKER_REGISTRY_H
#define QAFFD_WORKER_REGISTRY_H

#include "authorization.h"

#include <stddef.h>
#include <stdint.h>

struct qaffd_worker_record {
  int worker_fd;
  int lease_fd;
  int pidfd;
  uint64_t socket_cookie;
  int registered;
  uint64_t registered_at_ms;
  uint64_t last_seen_ms;
  uint32_t generation;
  uint32_t target_pid;
  struct qaffd_peer_cred cred;
};

struct qaffd_worker_registry {
  size_t capacity;
  int *worker_fds;
  int *lease_fds;
  int *pidfds;
  uint64_t *socket_cookies;
  int *registered;
  uint64_t *registered_at_ms;
  uint64_t *last_seen_ms;
  uint32_t *generations;
  uint32_t *target_pids;
  struct qaffd_peer_cred *creds;
};

int qaffd_worker_registry_init(struct qaffd_worker_registry *registry);
uint32_t
qaffd_worker_registry_count(const struct qaffd_worker_registry *registry);
int qaffd_worker_registry_next_generation(uint32_t previous, uint32_t *next);
int qaffd_worker_registry_snapshot(const struct qaffd_worker_registry *registry,
                                   uint32_t worker_id,
                                   struct qaffd_worker_record *record);
int qaffd_worker_registry_restore(struct qaffd_worker_registry *registry,
                                  uint32_t worker_id,
                                  const struct qaffd_worker_record *record);
int qaffd_worker_registry_register(struct qaffd_worker_registry *registry,
                                   uint32_t worker_id, int worker_fd,
                                   uint64_t socket_cookie, uint32_t generation,
                                   uint32_t target_pid, uint64_t now_ms,
                                   const struct qaffd_peer_cred *cred);
int qaffd_worker_registry_clear(struct qaffd_worker_registry *registry,
                                uint32_t worker_id);
int qaffd_worker_registry_heartbeat(struct qaffd_worker_registry *registry,
                                    uint32_t worker_id, uint64_t now_ms);

#endif
