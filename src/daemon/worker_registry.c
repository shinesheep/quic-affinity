#include "worker_registry.h"

#include "quic_affinity/types.h"

#include <errno.h>
#include <string.h>

static int registry_valid(const struct qaffd_worker_registry *registry) {
  return registry != NULL && registry->capacity > 0 &&
         registry->capacity <= UINT32_MAX && registry->worker_fds != NULL &&
         registry->lease_fds != NULL && registry->pidfds != NULL &&
         registry->socket_cookies != NULL && registry->registered != NULL &&
         registry->registered_at_ms != NULL && registry->last_seen_ms != NULL &&
         registry->generations != NULL && registry->target_pids != NULL &&
         registry->creds != NULL;
}

static int worker_valid(const struct qaffd_worker_registry *registry,
                        uint32_t worker_id) {
  if (!registry_valid(registry) || worker_id >= registry->capacity) {
    errno = EINVAL;
    return 0;
  }
  return 1;
}

int qaffd_worker_registry_init(struct qaffd_worker_registry *registry) {
  if (!registry_valid(registry)) {
    errno = EINVAL;
    return -1;
  }
  for (size_t i = 0; i < registry->capacity; i++) {
    registry->worker_fds[i] = -1;
    registry->lease_fds[i] = -1;
    registry->pidfds[i] = -1;
    registry->socket_cookies[i] = 0;
    registry->registered[i] = 0;
    registry->registered_at_ms[i] = 0;
    registry->last_seen_ms[i] = 0;
    registry->generations[i] = 0;
    registry->target_pids[i] = 0;
    memset(&registry->creds[i], 0, sizeof(registry->creds[i]));
  }
  return 0;
}

uint32_t
qaffd_worker_registry_count(const struct qaffd_worker_registry *registry) {
  if (!registry_valid(registry)) {
    return 0;
  }
  uint32_t count = 0;
  for (size_t i = 0; i < registry->capacity; i++) {
    if (registry->registered[i]) {
      count++;
    }
  }
  return count;
}

int qaffd_worker_registry_next_generation(uint32_t previous, uint32_t *next) {
  if (next == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (previous == 0) {
    *next = QAFF_WORKER_GENERATION_DEFAULT;
    return 0;
  }
  if (previous >= QAFF_WORKER_GENERATION_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  *next = previous + 1;
  return 0;
}

int qaffd_worker_registry_snapshot(const struct qaffd_worker_registry *registry,
                                   uint32_t worker_id,
                                   struct qaffd_worker_record *record) {
  if (!worker_valid(registry, worker_id) || record == NULL) {
    errno = EINVAL;
    return -1;
  }
  *record = (struct qaffd_worker_record){
      .worker_fd = registry->worker_fds[worker_id],
      .lease_fd = registry->lease_fds[worker_id],
      .pidfd = registry->pidfds[worker_id],
      .socket_cookie = registry->socket_cookies[worker_id],
      .registered = registry->registered[worker_id],
      .registered_at_ms = registry->registered_at_ms[worker_id],
      .last_seen_ms = registry->last_seen_ms[worker_id],
      .generation = registry->generations[worker_id],
      .target_pid = registry->target_pids[worker_id],
      .cred = registry->creds[worker_id],
  };
  return 0;
}

int qaffd_worker_registry_restore(struct qaffd_worker_registry *registry,
                                  uint32_t worker_id,
                                  const struct qaffd_worker_record *record) {
  if (!worker_valid(registry, worker_id) || record == NULL) {
    errno = EINVAL;
    return -1;
  }
  registry->worker_fds[worker_id] = record->worker_fd;
  registry->lease_fds[worker_id] = record->lease_fd;
  registry->pidfds[worker_id] = record->pidfd;
  registry->socket_cookies[worker_id] = record->socket_cookie;
  registry->registered[worker_id] = record->registered;
  registry->registered_at_ms[worker_id] = record->registered_at_ms;
  registry->last_seen_ms[worker_id] = record->last_seen_ms;
  registry->generations[worker_id] = record->generation;
  registry->target_pids[worker_id] = record->target_pid;
  registry->creds[worker_id] = record->cred;
  return 0;
}

int qaffd_worker_registry_register(struct qaffd_worker_registry *registry,
                                   uint32_t worker_id, int worker_fd,
                                   uint64_t socket_cookie, uint32_t generation,
                                   uint32_t target_pid, uint64_t now_ms,
                                   const struct qaffd_peer_cred *cred) {
  if (!worker_valid(registry, worker_id) || worker_fd < 0 || generation == 0 ||
      generation > QAFF_WORKER_GENERATION_MAX) {
    errno = EINVAL;
    return -1;
  }
  registry->worker_fds[worker_id] = worker_fd;
  registry->pidfds[worker_id] = -1;
  registry->socket_cookies[worker_id] = socket_cookie;
  registry->registered[worker_id] = 1;
  registry->registered_at_ms[worker_id] = now_ms;
  registry->last_seen_ms[worker_id] = now_ms;
  registry->generations[worker_id] = generation;
  registry->target_pids[worker_id] = target_pid;
  registry->creds[worker_id] =
      cred != NULL ? *cred : (struct qaffd_peer_cred){0};
  return 0;
}

int qaffd_worker_registry_clear(struct qaffd_worker_registry *registry,
                                uint32_t worker_id) {
  if (!worker_valid(registry, worker_id)) {
    return -1;
  }
  registry->worker_fds[worker_id] = -1;
  registry->lease_fds[worker_id] = -1;
  registry->pidfds[worker_id] = -1;
  registry->socket_cookies[worker_id] = 0;
  registry->registered[worker_id] = 0;
  registry->registered_at_ms[worker_id] = 0;
  registry->last_seen_ms[worker_id] = 0;
  registry->target_pids[worker_id] = 0;
  memset(&registry->creds[worker_id], 0, sizeof(registry->creds[worker_id]));
  return 0;
}

int qaffd_worker_registry_heartbeat(struct qaffd_worker_registry *registry,
                                    uint32_t worker_id, uint64_t now_ms) {
  if (!worker_valid(registry, worker_id) || !registry->registered[worker_id]) {
    errno = ENOENT;
    return -1;
  }
  registry->last_seen_ms[worker_id] = now_ms;
  return 0;
}
