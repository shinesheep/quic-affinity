#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"
#include "control_protocol.h"
#include "authorization.h"
#include "cid_index.h"
#include "cleanup_retry.h"
#include "qaffinity_internal.h"
#include "state_store.h"
#include "worker_registry.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>

#define QAFFD_MAX_WORKERS QAFF_WORKER_CAPACITY
#define QAFFD_MAX_PENDING_CLIENTS 128
#define QAFFD_MAX_POLLFDS \
  (QAFFD_MAX_WORKERS * 2 + QAFFD_MAX_PENDING_CLIENTS + 1)
#define QAFFD_CONTROL_DEADLINE_MS 1000u
#define QAFFD_PASSIVE_SCAN_INTERVAL_MS_DEFAULT 30000u
#define QAFFD_WORKER_RECOVERY_TIMEOUT_MS_DEFAULT 5000u
#define QAFFD_STATE_PERSISTENCE_RETRY_MS 1000u
#define QAFFD_WORKER_CLEANUP_RETRY_MS 1000u
#define QAFFD_PASSIVE_CLEANUP_RETRY_MS 1000u

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

#ifndef SYS_pidfd_open
#if defined(__NR_pidfd_open)
#define SYS_pidfd_open __NR_pidfd_open
#elif defined(__x86_64__)
#define SYS_pidfd_open 434
#endif
#endif

enum qaffd_poll_source {
  QAFFD_POLL_SERVER = 0,
  QAFFD_POLL_WORKER_LEASE = 1,
  QAFFD_POLL_WORKER_PIDFD = 2,
  QAFFD_POLL_CLIENT = 3,
};

enum qaffd_client_stage {
  QAFFD_CLIENT_READING = 0,
  QAFFD_CLIENT_WRITING = 1,
};

struct qaffd_client {
  int fd;
  int received_fd;
  int lease_worker_id;
  enum qaffd_client_stage stage;
  uint64_t deadline_ms;
  struct qaff_control_msg request;
  struct qaff_control_msg reply;
  uint8_t reply_packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t reply_len;
};

struct qaffd_options {
  const char *socket_path;
  const char *bpf_object_path;
  const char *egress_cgroup_path;
  const char *pin_root;
  const char *state_path;
  uint8_t short_cid_len;
  uint8_t cid_profile_enabled;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t fallback_mode;
  uint8_t cid_profile_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
  uint64_t worker_heartbeat_timeout_ms;
  uint64_t worker_recovery_timeout_ms;
  uint64_t passive_scan_interval_ms;
  int reuseport_bpf_replace_allowed;
  int allow_worker_uid_set;
  int allow_worker_gid_set;
  int allow_admin_uid_set;
  int allow_admin_gid_set;
  int socket_gid_set;
  uint32_t allow_worker_uid;
  uint32_t allow_worker_gid;
  uint32_t allow_admin_uid;
  uint32_t allow_admin_gid;
  uint32_t socket_gid;
  mode_t socket_mode;
};

struct qaffd_worker_snapshot {
  struct qaffd_worker_record worker;
  int listener_locked;
  struct sockaddr_storage listener_addr;
};

enum qaffd_worker_cleanup_action {
  QAFFD_WORKER_CLEANUP_NONE = 0,
  QAFFD_WORKER_CLEANUP_TOMBSTONE = 1,
  QAFFD_WORKER_CLEANUP_RECOVERY_WITHDRAW = 2,
};

struct qaffd_state {
  struct qaff_context *ctx;
  struct qaff_bpf_object *bpf;
  int instance_lock_fd;
  int worker_fds[QAFFD_MAX_WORKERS];
  int worker_lease_fds[QAFFD_MAX_WORKERS];
  int worker_pending_lease_fds[QAFFD_MAX_WORKERS];
  int worker_pidfds[QAFFD_MAX_WORKERS];
  uint64_t worker_socket_cookies[QAFFD_MAX_WORKERS];
  int worker_registered[QAFFD_MAX_WORKERS];
  uint64_t worker_registered_at_ms[QAFFD_MAX_WORKERS];
  uint64_t worker_last_seen_ms[QAFFD_MAX_WORKERS];
  uint32_t worker_generations[QAFFD_MAX_WORKERS];
  uint32_t worker_target_pids[QAFFD_MAX_WORKERS];
  struct qaffd_peer_cred worker_creds[QAFFD_MAX_WORKERS];
  struct qaffd_worker_registry worker_registry;
  struct qaffd_cid_index cid_index;
  const char *pin_root;
  const char *state_path;
  uint8_t short_cid_len;
  uint8_t cid_profile_enabled;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t fallback_mode;
  uint8_t cid_profile_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
  uint64_t worker_heartbeat_timeout_ms;
  uint64_t worker_recovery_timeout_ms;
  uint64_t passive_scan_interval_ms;
  uint64_t passive_last_scan_ms;
  uint64_t passive_expired_count;
  uint64_t passive_worker_purged_count;
  uint64_t passive_expiry_initialized_count;
  uint64_t passive_cleanup_error_count;
  uint64_t passive_cleanup_retry_count;
  uint64_t passive_cleanup_retry_at_ms;
  uint8_t passive_cleanup_degraded;
  uint8_t state_persistence_degraded;
  uint64_t state_persistence_error_count;
  uint64_t state_persistence_retry_count;
  uint64_t state_persistence_retry_at_ms;
  uint8_t worker_cleanup_pending[QAFFD_MAX_WORKERS];
  uint8_t worker_cleanup_actions[QAFFD_MAX_WORKERS];
  struct qaffd_cleanup_retry worker_cleanup_retry;
  int allow_worker_uid_set;
  int allow_worker_gid_set;
  int allow_admin_uid_set;
  int allow_admin_gid_set;
  int socket_gid_set;
  uint32_t allow_worker_uid;
  uint32_t allow_worker_gid;
  uint32_t allow_admin_uid;
  uint32_t allow_admin_gid;
  uint32_t socket_gid;
  mode_t socket_mode;
  int attached;
  int egress_attached;
  int stop;
  int listener_locked;
  struct sockaddr_storage listener_addr;
};

struct qaffd_cid_consistency {
  uint64_t map_count;
  uint64_t owner_count;
  uint64_t mismatch_count;
};

struct qaffd_passive_table_info {
  uint64_t entry_count;
  uint64_t entry_capacity;
};

static volatile sig_atomic_t g_stop_requested = 0;

static void audit_event(const char *event,
                        const struct qaffd_peer_cred *peer,
                        const char *fmt,
                        ...) {
  fprintf(stderr, "audit event=%s", event);
  if (peer != NULL && peer->valid) {
    fprintf(stderr,
            " peer_pid=%u peer_uid=%u peer_gid=%u",
            peer->pid,
            peer->uid,
            peer->gid);
  }
  if (fmt != NULL && fmt[0] != '\0') {
    fputc(' ', stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
  }
  fputc('\n', stderr);
}

static void handle_signal(int signo) {
  (void)signo;
  g_stop_requested = 1;
}

static int install_signal_handlers(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handle_signal;
  if (sigemptyset(&action.sa_mask) != 0) {
    return -1;
  }
  if (sigaction(SIGTERM, &action, NULL) != 0) {
    return -1;
  }
  if (sigaction(SIGINT, &action, NULL) != 0) {
    return -1;
  }
  return 0;
}

static uint64_t now_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static uint64_t elapsed_ms(uint64_t now, uint64_t then) {
  if (then == 0 || now < then) {
    return 0;
  }
  return now - then;
}

static struct qaffd_auth_rule worker_auth_rule(
    const struct qaffd_state *state) {
  return (struct qaffd_auth_rule){
    .uid_set = state->allow_worker_uid_set,
    .gid_set = state->allow_worker_gid_set,
    .uid = state->allow_worker_uid,
    .gid = state->allow_worker_gid,
  };
}

static struct qaffd_auth_rule admin_auth_rule(
    const struct qaffd_state *state) {
  return (struct qaffd_auth_rule){
    .uid_set = state->allow_admin_uid_set,
    .gid_set = state->allow_admin_gid_set,
    .uid = state->allow_admin_uid,
    .gid = state->allow_admin_gid,
  };
}

static int validate_worker_peer(const struct qaffd_state *state,
                                const struct qaffd_peer_cred *peer) {
  struct qaffd_auth_rule rule = worker_auth_rule(state);
  return qaffd_auth_worker_registration(&rule, peer);
}

static int peer_matches_configured_admin(const struct qaffd_state *state,
                                         const struct qaffd_peer_cred *peer) {
  struct qaffd_auth_rule rule = admin_auth_rule(state);
  return qaffd_auth_rule_matches(&rule, peer);
}

static int peer_matches_worker(const struct qaffd_state *state,
                               uint32_t worker_id,
                               const struct qaffd_peer_cred *peer) {
  if (worker_id >= QAFFD_MAX_WORKERS || peer == NULL || !peer->valid) {
    return 0;
  }

  return qaffd_auth_same_peer(&state->worker_creds[worker_id], peer);
}

static int authorize_worker_mutation(const struct qaffd_state *state,
                                     uint32_t worker_id,
                                     const struct qaffd_peer_cred *peer) {
  if (worker_id >= QAFFD_MAX_WORKERS ||
      !state->worker_registered[worker_id]) {
    errno = ENOENT;
    return -1;
  }
  if (peer_matches_configured_admin(state, peer) ||
      peer_matches_worker(state, worker_id, peer)) {
    return 0;
  }
  audit_event("worker_mutation_denied",
              peer,
              "worker_id=%u reason=unauthorized",
              worker_id);
  errno = EACCES;
  return -1;
}

static int authorize_daemon_mutation(const struct qaffd_state *state,
                                     const struct qaffd_peer_cred *peer) {
  struct qaffd_auth_rule rule = admin_auth_rule(state);
  if (qaffd_auth_daemon_mutation(&rule, (uint32_t)geteuid(), peer) == 0) {
    return 0;
  }
  audit_event("daemon_mutation_denied", peer, "reason=unauthorized");
  errno = EACCES;
  return -1;
}

static int open_pidfd_for_peer(const struct qaffd_peer_cred *peer) {
  if (peer == NULL || !peer->valid || peer->pid == 0) {
    errno = EINVAL;
    return -1;
  }
#ifdef SYS_pidfd_open
  int fd = (int)syscall(SYS_pidfd_open, (pid_t)peer->pid, 0);
  if (fd < 0) {
    return -1;
  }
  return fd;
#else
  errno = ENOSYS;
  return -1;
#endif
}

static int worker_is_recovering(const struct qaffd_state *state,
                                uint32_t worker_id) {
  return worker_id < QAFFD_MAX_WORKERS &&
         state->worker_registered[worker_id] &&
         state->worker_fds[worker_id] < 0;
}

static int worker_has_pending_lease(const struct qaffd_state *state,
                                    uint32_t worker_id) {
  return worker_id < QAFFD_MAX_WORKERS &&
         state->worker_pending_lease_fds[worker_id] >= 0;
}

static uint32_t worker_count(const struct qaffd_state *state) {
  return qaffd_worker_registry_count(&state->worker_registry);
}

static uint32_t recovering_worker_count(const struct qaffd_state *state) {
  uint32_t count = 0;
  for (uint32_t worker_id = 0; worker_id < QAFFD_MAX_WORKERS; worker_id++) {
    if (worker_is_recovering(state, worker_id)) {
      count++;
    }
  }
  return count;
}

static int worker_is_tombstoned(const struct qaffd_state *state,
                                uint32_t worker_id) {
  return worker_id < QAFFD_MAX_WORKERS &&
         !state->worker_registered[worker_id] &&
         state->worker_generations[worker_id] != 0;
}

static int next_worker_generation(uint32_t previous, uint32_t *next) {
  return qaffd_worker_registry_next_generation(previous, next);
}

static int copy_config_path(char *dst, size_t dst_len, const char *src) {
  if (dst_len == 0) {
    return 0;
  }
  dst[0] = '\0';
  if (src == NULL) {
    return 0;
  }
  size_t len = strlen(src);
  if (len >= dst_len) {
    len = dst_len - 1;
  }
  memcpy(dst, src, len);
  dst[len] = '\0';
  return 0;
}

static uint16_t sockaddr_port(const struct sockaddr_storage *addr) {
  if (addr->ss_family == AF_INET) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    return in->sin_port;
  }
  if (addr->ss_family == AF_INET6) {
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
    return in6->sin6_port;
  }
  return 0;
}

static int sockaddr_listener_equal(const struct sockaddr_storage *left,
                                   const struct sockaddr_storage *right) {
  if (left->ss_family != right->ss_family ||
      sockaddr_port(left) != sockaddr_port(right)) {
    return 0;
  }

  if (left->ss_family == AF_INET) {
    const struct sockaddr_in *a = (const struct sockaddr_in *)left;
    const struct sockaddr_in *b = (const struct sockaddr_in *)right;
    return a->sin_addr.s_addr == b->sin_addr.s_addr;
  }

  if (left->ss_family == AF_INET6) {
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)left;
    const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)right;
    return memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0 &&
           a->sin6_scope_id == b->sin6_scope_id;
  }

  return 0;
}

static int validate_worker_socket(const struct qaffd_state *state,
                                  int socket_fd,
                                  struct sockaddr_storage *local_addr) {
  int type = 0;
  socklen_t opt_len = sizeof(type);
  if (getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &type, &opt_len) != 0) {
    return -1;
  }
  if (type != SOCK_DGRAM) {
    errno = EPROTOTYPE;
    return -1;
  }

#ifdef SO_PROTOCOL
  int protocol = 0;
  opt_len = sizeof(protocol);
  if (getsockopt(socket_fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &opt_len) != 0) {
    return -1;
  }
  if (protocol != IPPROTO_UDP) {
    errno = EPROTOTYPE;
    return -1;
  }
#endif

  int reuseport = 0;
  opt_len = sizeof(reuseport);
  if (getsockopt(socket_fd,
                 SOL_SOCKET,
                 SO_REUSEPORT,
                 &reuseport,
                 &opt_len) != 0) {
    return -1;
  }
  if (!reuseport) {
    errno = EINVAL;
    return -1;
  }

  socklen_t addr_len = sizeof(*local_addr);
  memset(local_addr, 0, sizeof(*local_addr));
  if (getsockname(socket_fd, (struct sockaddr *)local_addr, &addr_len) != 0) {
    return -1;
  }
  if (local_addr->ss_family != AF_INET && local_addr->ss_family != AF_INET6) {
    errno = EAFNOSUPPORT;
    return -1;
  }
  if (sockaddr_port(local_addr) == 0) {
    errno = EINVAL;
    return -1;
  }

  if (local_addr->ss_family == AF_INET6) {
    int v6only = 0;
    opt_len = sizeof(v6only);
    if (getsockopt(socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &opt_len) != 0) {
      return -1;
    }
    if (!v6only) {
      errno = EINVAL;
      return -1;
    }
  }

  if (state->listener_locked &&
      !sockaddr_listener_equal(&state->listener_addr, local_addr)) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int read_socket_cookie(int socket_fd, uint64_t *out) {
  uint64_t cookie = 0;
  socklen_t opt_len = sizeof(cookie);
  if (getsockopt(socket_fd, SOL_SOCKET, SO_COOKIE, &cookie, &opt_len) != 0) {
    return -1;
  }
  if (opt_len != sizeof(cookie) || cookie == 0) {
    errno = EINVAL;
    return -1;
  }
  *out = cookie;
  return 0;
}

static int register_socket_cookie(struct qaffd_state *state,
                                  uint32_t worker_id,
                                  int socket_fd,
                                  uint64_t *out_cookie) {
  uint64_t cookie = 0;
  if (read_socket_cookie(socket_fd, &cookie) != 0) {
    return -1;
  }
  int map_fd = qaff_get_socket_worker_map_fd(state->ctx);
  if (bpf_map_update_elem(map_fd,
                          &cookie,
                          &worker_id,
                          BPF_NOEXIST) != 0) {
    if (errno != EEXIST) {
      return -1;
    }
    uint32_t existing_worker_id = UINT32_MAX;
    if (bpf_map_lookup_elem(map_fd, &cookie, &existing_worker_id) != 0) {
      return -1;
    }
    if (existing_worker_id != worker_id) {
      errno = EEXIST;
      return -1;
    }
  }
  *out_cookie = cookie;
  return 0;
}

static int is_same_registered_socket(const struct qaffd_state *state,
                                     uint32_t worker_id,
                                     int socket_fd) {
  if (!state->worker_registered[worker_id] ||
      state->worker_generations[worker_id] == 0) {
    return 0;
  }

  uint64_t cookie = 0;
  if (read_socket_cookie(socket_fd, &cookie) != 0) {
    return -1;
  }
  uint32_t mapped_worker = UINT32_MAX;
  if (bpf_map_lookup_elem(qaff_get_socket_worker_map_fd(state->ctx),
                          &cookie,
                          &mapped_worker) != 0) {
    if (errno == ENOENT) {
      return 0;
    }
    return -1;
  }
  return mapped_worker == worker_id;
}

static void unregister_socket_cookie(struct qaffd_state *state,
                                     uint64_t cookie) {
  if (cookie == 0 || state->ctx == NULL) {
    return;
  }
  bpf_map_delete_elem(qaff_get_socket_worker_map_fd(state->ctx), &cookie);
}

static int read_cid_consistency(const struct qaffd_state *state,
                                struct qaffd_cid_consistency *out);
static int read_passive_table_info(const struct qaffd_state *state,
                                   struct qaffd_passive_table_info *out);

static void fill_config_reply(const struct qaffd_state *state,
                              struct qaff_control_msg *reply) {
  reply->config.short_cid_len = state->short_cid_len;
  reply->config.cid_profile_enabled = state->cid_profile_enabled;
  reply->config.passive_affinity_enabled = state->passive_affinity_enabled;
  reply->config.passive_min_confidence = state->passive_min_confidence;
  reply->config.egress_attached = state->egress_attached ? 1 : 0;
  reply->config.fallback_mode = state->fallback_mode;
  reply->config.fallback_available =
      state->fallback_mode == QAFF_FALLBACK_MODE_KERNEL ||
      (state->fallback_worker_id < QAFFD_MAX_WORKERS &&
       state->worker_registered[state->fallback_worker_id] &&
       !worker_is_recovering(state, state->fallback_worker_id));
  reply->config.state_persistence_degraded =
      state->state_persistence_degraded;
  reply->config.worker_cleanup_degraded =
      state->worker_cleanup_retry.pending_count != 0;
  reply->config.passive_cleanup_degraded =
      state->passive_cleanup_degraded;
  reply->config.attached = state->attached ? 1 : 0;
  reply->config.worker_count = worker_count(state);
  reply->config.recovering_worker_count = recovering_worker_count(state);
  reply->config.fallback_worker_id = state->fallback_worker_id;
  reply->config.worker_cleanup_pending_count =
      state->worker_cleanup_retry.pending_count;
  reply->config.passive_expired_count = state->passive_expired_count;
  reply->config.passive_worker_purged_count =
      state->passive_worker_purged_count;
  reply->config.passive_expiry_initialized_count =
      state->passive_expiry_initialized_count;
  reply->config.passive_cleanup_error_count =
      state->passive_cleanup_error_count;
  reply->config.passive_cleanup_retry_count =
      state->passive_cleanup_retry_count;
  reply->config.state_persistence_error_count =
      state->state_persistence_error_count;
  reply->config.state_persistence_retry_count =
      state->state_persistence_retry_count;
  reply->config.worker_cleanup_error_count =
      state->worker_cleanup_retry.error_count;
  reply->config.worker_cleanup_retry_count =
      state->worker_cleanup_retry.retry_count;
  reply->config.passive_scan_interval_ms =
      state->passive_scan_interval_ms;
  reply->config.worker_recovery_timeout_ms =
      state->worker_recovery_timeout_ms;
  copy_config_path(reply->config.pin_root,
                   sizeof(reply->config.pin_root),
                   state->pin_root);
  copy_config_path(reply->config.state_path,
                   sizeof(reply->config.state_path),
                   state->state_path);

  struct qaffd_cid_consistency consistency;
  if (read_cid_consistency(state, &consistency) == 0) {
    reply->config.cid_map_count = consistency.map_count;
    reply->config.cid_owner_count = consistency.owner_count;
    reply->config.cid_index_mismatch = consistency.mismatch_count;
  } else {
    reply->config.cid_consistency_degraded = 1;
  }

  struct qaffd_passive_table_info passive;
  if (read_passive_table_info(state, &passive) == 0) {
    reply->config.passive_entry_count = passive.entry_count;
    reply->config.passive_entry_capacity = passive.entry_capacity;
  }
}

static void fill_workers_reply(const struct qaffd_state *state,
                               uint32_t cursor,
                               struct qaff_control_msg *reply) {
  uint32_t written = 0;
  uint64_t now = now_ms();

  reply->worker_id = UINT32_MAX;
  for (uint32_t i = cursor; i < QAFFD_MAX_WORKERS; i++) {
    int cleanup_pending = qaffd_cleanup_retry_is_pending(
        &state->worker_cleanup_retry,
        i);
    if (!state->worker_registered[i] && !cleanup_pending) {
      continue;
    }
    if (written == QAFF_CONTROL_PAGE_WORKERS) {
      reply->worker_id = i;
      break;
    }
    reply->workers[written] = i;
    reply->worker_infos[written].worker_id = i;
    reply->worker_infos[written].flags =
        state->worker_lease_fds[i] >= 0 ? QAFF_CONTROL_WORKER_FLAG_LEASED : 0;
    if (cleanup_pending) {
      reply->worker_infos[written].flags |=
          QAFF_CONTROL_WORKER_FLAG_CLEANUP_PENDING;
    }
    if (worker_is_recovering(state, i)) {
      reply->worker_infos[written].flags |=
          QAFF_CONTROL_WORKER_FLAG_RECOVERING;
    }
    if (state->worker_creds[i].valid) {
      reply->worker_infos[written].flags |= QAFF_CONTROL_WORKER_FLAG_CRED;
      reply->worker_infos[written].pid = state->worker_creds[i].pid;
      reply->worker_infos[written].uid = state->worker_creds[i].uid;
      reply->worker_infos[written].gid = state->worker_creds[i].gid;
    }
    reply->worker_infos[written].target_pid =
        state->worker_target_pids[i];
    if (state->worker_pidfds[i] >= 0) {
      reply->worker_infos[written].flags |= QAFF_CONTROL_WORKER_FLAG_PIDFD;
    }
    if (state->worker_registered[i]) {
      reply->worker_infos[written].registered_ms_ago =
          elapsed_ms(now, state->worker_registered_at_ms[i]);
      reply->worker_infos[written].last_seen_ms_ago =
          elapsed_ms(now, state->worker_last_seen_ms[i]);
    }
    written++;
  }

  reply->workers_len = written;
}

static void usage(FILE *out) {
  fprintf(out,
          "Usage: qaffd --socket PATH --bpf PATH --short-cid-len N "
          "--reuseport-bpf-policy replace "
          "[--fallback-worker ID] [--fallback-mode fixed|kernel] "
          "[--pin-root PATH --state-path PATH] "
          "[--egress-cgroup PATH] "
          "[--cid-profile-key HEX32 | --cid-profile-key-file PATH] "
          "[--passive-affinity] [--passive-min-confidence N] "
          "[--passive-scan-interval-ms N] "
          "[--worker-heartbeat-timeout-ms N] "
          "[--worker-recovery-timeout-ms N] [--allow-worker-uid UID] "
          "[--allow-worker-gid GID] [--allow-admin-uid UID] "
          "[--allow-admin-gid GID] [--socket-mode OCTAL] "
          "[--socket-gid GID]\n");
}

static int profile_key_hex_value(int c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static int parse_fixed_hex(const char *hex, uint8_t *out, size_t out_len) {
  size_t digits = 0;
  for (const char *p = hex; *p; p++) {
    if (*p == ':' || *p == '-' || isspace((unsigned char)*p)) {
      continue;
    }
    if (profile_key_hex_value((unsigned char)*p) < 0) {
      return -1;
    }
    digits++;
  }
  if (digits != out_len * 2) {
    return -1;
  }

  size_t index = 0;
  int high = -1;
  for (const char *p = hex; *p; p++) {
    if (*p == ':' || *p == '-' || isspace((unsigned char)*p)) {
      continue;
    }
    int v = profile_key_hex_value((unsigned char)*p);
    if (high < 0) {
      high = v;
    } else {
      out[index++] = (uint8_t)((high << 4) | v);
      high = -1;
    }
  }
  return index == out_len ? 0 : -1;
}

static int read_profile_key_file(const char *path,
                                 uint8_t *out,
                                 size_t out_len) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  if (S_ISREG(st.st_mode) && (st.st_mode & 0077) != 0) {
    close(fd);
    errno = EACCES;
    return -1;
  }
  char buf[256];
  if (S_ISREG(st.st_mode) && st.st_size >= (off_t)sizeof(buf)) {
    close(fd);
    errno = EINVAL;
    return -1;
  }

  ssize_t got = read(fd, buf, sizeof(buf) - 1);
  if (got < 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  if (close(fd) != 0) {
    return -1;
  }
  if (got == 0) {
    errno = EINVAL;
    return -1;
  }
  buf[got] = '\0';

  if (parse_fixed_hex(buf, out, out_len) != 0) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

static int parse_args(int argc, char **argv, struct qaffd_options *options) {
  memset(options, 0, sizeof(*options));
  options->socket_mode = 0600;
  options->passive_min_confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  options->passive_scan_interval_ms =
      QAFFD_PASSIVE_SCAN_INTERVAL_MS_DEFAULT;
  options->worker_recovery_timeout_ms =
      QAFFD_WORKER_RECOVERY_TIMEOUT_MS_DEFAULT;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
      options->socket_path = argv[++i];
    } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
      options->bpf_object_path = argv[++i];
    } else if (strcmp(argv[i], "--egress-cgroup") == 0 && i + 1 < argc) {
      options->egress_cgroup_path = argv[++i];
    } else if (strcmp(argv[i], "--pin-root") == 0 && i + 1 < argc) {
      options->pin_root = argv[++i];
    } else if (strcmp(argv[i], "--state-path") == 0 && i + 1 < argc) {
      options->state_path = argv[++i];
    } else if (strcmp(argv[i], "--reuseport-bpf-policy") == 0 &&
               i + 1 < argc) {
      if (strcmp(argv[++i], "replace") != 0) {
        return -1;
      }
      options->reuseport_bpf_replace_allowed = 1;
    } else if (strcmp(argv[i], "--short-cid-len") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > QAFF_MAX_CID_LEN) {
        return -1;
      }
      options->short_cid_len = (uint8_t)value;
    } else if (strcmp(argv[i], "--fallback-worker") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT32_MAX) {
        return -1;
      }
      options->fallback_worker_id = (uint32_t)value;
    } else if (strcmp(argv[i], "--fallback-mode") == 0 && i + 1 < argc) {
      const char *mode = argv[++i];
      if (strcmp(mode, "fixed") == 0) {
        options->fallback_mode = QAFF_FALLBACK_MODE_FIXED;
      } else if (strcmp(mode, "kernel") == 0) {
        options->fallback_mode = QAFF_FALLBACK_MODE_KERNEL;
      } else {
        return -1;
      }
    } else if (strcmp(argv[i], "--cid-profile-key") == 0 && i + 1 < argc) {
      if (parse_fixed_hex(argv[++i],
                          options->cid_profile_key,
                          sizeof(options->cid_profile_key)) != 0) {
        return -1;
      }
      options->cid_profile_enabled = 1;
    } else if (strcmp(argv[i], "--cid-profile-key-file") == 0 &&
               i + 1 < argc) {
      if (read_profile_key_file(argv[++i],
                                options->cid_profile_key,
                                sizeof(options->cid_profile_key)) != 0) {
        return -1;
      }
      options->cid_profile_enabled = 1;
    } else if (strcmp(argv[i], "--passive-affinity") == 0) {
      options->passive_affinity_enabled = 1;
    } else if (strcmp(argv[i], "--passive-min-confidence") == 0 &&
               i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] ||
          *end != '\0' ||
          value < QAFF_PASSIVE_CONFIDENCE_LOW ||
          value > QAFF_PASSIVE_CONFIDENCE_HIGH) {
        return -1;
      }
      options->passive_min_confidence = (uint8_t)value;
    } else if (strcmp(argv[i], "--passive-scan-interval-ms") == 0 &&
               i + 1 < argc) {
      char *end = NULL;
      unsigned long long value = strtoull(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value == 0 ||
          value > INT_MAX) {
        return -1;
      }
      options->passive_scan_interval_ms = (uint64_t)value;
    } else if (strcmp(argv[i], "--worker-heartbeat-timeout-ms") == 0 &&
               i + 1 < argc) {
      char *end = NULL;
      unsigned long long value = strtoull(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0') {
        return -1;
      }
      options->worker_heartbeat_timeout_ms = (uint64_t)value;
    } else if (strcmp(argv[i], "--worker-recovery-timeout-ms") == 0 &&
               i + 1 < argc) {
      char *end = NULL;
      unsigned long long value = strtoull(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value == 0 ||
          value > INT_MAX) {
        return -1;
      }
      options->worker_recovery_timeout_ms = (uint64_t)value;
    } else if (strcmp(argv[i], "--allow-worker-uid") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT32_MAX) {
        return -1;
      }
      options->allow_worker_uid_set = 1;
      options->allow_worker_uid = (uint32_t)value;
    } else if (strcmp(argv[i], "--allow-worker-gid") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT32_MAX) {
        return -1;
      }
      options->allow_worker_gid_set = 1;
      options->allow_worker_gid = (uint32_t)value;
    } else if (strcmp(argv[i], "--allow-admin-uid") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT32_MAX) {
        return -1;
      }
      options->allow_admin_uid_set = 1;
      options->allow_admin_uid = (uint32_t)value;
    } else if (strcmp(argv[i], "--allow-admin-gid") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT32_MAX) {
        return -1;
      }
      options->allow_admin_gid_set = 1;
      options->allow_admin_gid = (uint32_t)value;
    } else if (strcmp(argv[i], "--socket-mode") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 8);
      if (end == argv[i] || *end != '\0' || value > 0770) {
        return -1;
      }
      options->socket_mode = (mode_t)value;
    } else if (strcmp(argv[i], "--socket-gid") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT32_MAX) {
        return -1;
      }
      options->socket_gid_set = 1;
      options->socket_gid = (uint32_t)value;
    } else {
      return -1;
    }
  }

  if (options->socket_path == NULL ||
      options->bpf_object_path == NULL ||
      options->short_cid_len == 0) {
    return -1;
  }
  if (!options->reuseport_bpf_replace_allowed) {
    fprintf(stderr,
            "qaffd: --reuseport-bpf-policy replace is required because "
            "Linux attach replaces the current group program\n");
    return -1;
  }
  if (options->fallback_worker_id >= QAFFD_MAX_WORKERS) {
    fprintf(stderr, "qaffd: --fallback-worker must be less than %u\n",
            QAFFD_MAX_WORKERS);
    return -1;
  }
  if ((options->pin_root == NULL) != (options->state_path == NULL)) {
    fprintf(stderr,
            "qaffd: --pin-root and --state-path must be configured together\n");
    return -1;
  }
  if (options->cid_profile_enabled &&
      (options->pin_root == NULL || options->state_path == NULL)) {
    fprintf(stderr,
            "qaffd: CID profile requires --pin-root and --state-path\n");
    return -1;
  }
  if (options->cid_profile_enabled &&
      options->short_cid_len != QAFF_CID_PROFILE_LEN) {
    return -1;
  }
  if ((options->socket_mode & 0007) != 0) {
    return -1;
  }
  if ((options->socket_mode & 0070) != 0 && !options->socket_gid_set) {
    return -1;
  }
  if ((options->socket_mode & 0070) != 0 &&
      !options->allow_admin_uid_set &&
      !options->allow_admin_gid_set) {
    return -1;
  }

  return 0;
}

static int recv_request(int fd, struct qaff_control_msg *msg, int *received_fd) {
  *received_fd = -1;

  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  struct iovec iov;
  iov.iov_base = packet;
  iov.iov_len = sizeof(packet);

  int rights[4];
  char control[CMSG_SPACE(sizeof(rights))];
  memset(control, 0, sizeof(control));

  struct msghdr hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  hdr.msg_control = control;
  hdr.msg_controllen = sizeof(control);

  ssize_t got;
  do {
    got = recvmsg(fd, &hdr, 0);
  } while (got < 0 && errno == EINTR);

  if (got < 0) {
    return -1;
  }
  if (got == 0) {
    errno = ECONNRESET;
    return -1;
  }
  int invalid_rights = 0;
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS &&
        cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
      size_t rights_len = cmsg->cmsg_len - CMSG_LEN(0);
      size_t rights_count = rights_len / sizeof(int);
      const int *received = (const int *)CMSG_DATA(cmsg);
      for (size_t i = 0; i < rights_count; i++) {
        if (*received_fd < 0 && !invalid_rights) {
          *received_fd = received[i];
        } else {
          close(received[i]);
          invalid_rights = 1;
        }
      }
    }
  }
  if ((hdr.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 || invalid_rights) {
    if (*received_fd >= 0) {
      close(*received_fd);
      *received_fd = -1;
    }
    errno = EPROTO;
    return -1;
  }
  return qaff_control_decode_request(packet, (size_t)got, msg);
}

static void reply_init(struct qaff_control_msg *reply,
                       const struct qaff_control_msg *request) {
  memset(reply, 0, sizeof(*reply));
  reply->op = request->op;
}

static int read_cid_consistency(const struct qaffd_state *state,
                                struct qaffd_cid_consistency *out) {
  memset(out, 0, sizeof(*out));
  out->owner_count = qaffd_cid_index_size(&state->cid_index);

  int map_fd = qaff_get_cid_map_fd(state->ctx);
  if (map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_cid_key key;
  struct qaff_cid_key next_key;
  struct qaff_cid_key *previous = NULL;

  while (bpf_map_get_next_key(map_fd, previous, &next_key) == 0) {
    struct qaff_cid_value value;
    out->map_count++;
    if (bpf_map_lookup_elem(map_fd, &next_key, &value) != 0) {
      out->mismatch_count++;
      key = next_key;
      previous = &key;
      continue;
    }

    ptrdiff_t position = qaffd_cid_index_find(&state->cid_index, &next_key);
    const struct qaffd_cid_entry *entry =
        position < 0 ? NULL
                     : qaffd_cid_index_entry(&state->cid_index,
                                             (size_t)position);
    if (entry == NULL ||
        value.worker_id >= QAFFD_MAX_WORKERS ||
        entry->worker_id != value.worker_id ||
        value.worker_generation == 0 ||
        !state->worker_registered[value.worker_id] ||
        state->worker_generations[value.worker_id] !=
            value.worker_generation) {
      out->mismatch_count++;
    }

    key = next_key;
    previous = &key;
  }

  if (errno != ENOENT) {
    return -1;
  }

  for (size_t i = 0; i < qaffd_cid_index_size(&state->cid_index); i++) {
    const struct qaffd_cid_entry *entry =
        qaffd_cid_index_entry(&state->cid_index, i);
    struct qaff_cid_value value;
    if (entry == NULL ||
        bpf_map_lookup_elem(map_fd, &entry->key, &value) != 0 ||
        value.worker_id != entry->worker_id ||
        value.worker_id >= QAFFD_MAX_WORKERS ||
        value.worker_generation == 0 ||
        !state->worker_registered[value.worker_id] ||
        state->worker_generations[value.worker_id] !=
            value.worker_generation) {
      out->mismatch_count++;
    }
  }

  return 0;
}

static int read_passive_table_info(const struct qaffd_state *state,
                                   struct qaffd_passive_table_info *out) {
  memset(out, 0, sizeof(*out));

  int map_fd = qaff_get_passive_cid_map_fd(state->ctx);
  if (map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  struct bpf_map_info map_info;
  memset(&map_info, 0, sizeof(map_info));
  uint32_t map_info_len = sizeof(map_info);
  if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len) != 0) {
    return -1;
  }
  out->entry_capacity = map_info.max_entries;

  struct qaff_cid_key key;
  struct qaff_cid_key next_key;
  struct qaff_cid_key *previous = NULL;
  while (out->entry_count < out->entry_capacity &&
         bpf_map_get_next_key(map_fd, previous, &next_key) == 0) {
    out->entry_count++;
    key = next_key;
    previous = &key;
  }
  if (out->entry_count == out->entry_capacity) {
    return 0;
  }
  return errno == ENOENT ? 0 : -1;
}

static int retire_worker_cids(struct qaffd_state *state, uint32_t worker_id) {
  int retire_tombstones = worker_id == UINT32_MAX;
  size_t i = 0;
  while (i < qaffd_cid_index_size(&state->cid_index)) {
    struct qaffd_cid_entry *entry =
        qaffd_cid_index_entry_mut(&state->cid_index, i);
    if (entry == NULL) {
      errno = EIO;
      return -1;
    }
    int should_retire = retire_tombstones
                            ? worker_is_tombstoned(state, entry->worker_id)
                            : entry->worker_id == worker_id;
    if (!should_retire) {
      i++;
      continue;
    }

    if (qaff_retire_cid(state->ctx,
                        entry->key.bytes,
                        entry->key.len) != 0 &&
        errno != ENOENT) {
      return -1;
    }
    if (qaffd_cid_index_remove_at(&state->cid_index, i) != 0) {
      return -1;
    }
  }

  /*
   * The ownership index is an acceleration structure, not the cleanup source
   * of truth. Sweep the map as well so legacy, externally inserted, or failed-
   * rollback residue cannot survive worker teardown.
   */
  int map_fd = qaff_get_cid_map_fd(state->ctx);
  if (map_fd < 0) {
    errno = EINVAL;
    return -1;
  }
  struct bpf_map_info map_info;
  memset(&map_info, 0, sizeof(map_info));
  uint32_t map_info_len = sizeof(map_info);
  if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len) != 0) {
    return -1;
  }
  struct qaff_cid_key current;
  if (bpf_map_get_next_key(map_fd, NULL, &current) != 0) {
    return errno == ENOENT ? 0 : -1;
  }
  for (uint32_t inspected = 0; inspected < map_info.max_entries; inspected++) {
    struct qaff_cid_key next;
    int has_next = bpf_map_get_next_key(map_fd, &current, &next) == 0;
    if (!has_next && errno != ENOENT) {
      return -1;
    }

    struct qaff_cid_value value;
    if (bpf_map_lookup_elem(map_fd, &current, &value) == 0) {
      int should_retire = retire_tombstones
                              ? worker_is_tombstoned(state, value.worker_id)
                              : value.worker_id == worker_id;
      if (should_retire &&
          bpf_map_delete_elem(map_fd, &current) != 0 && errno != ENOENT) {
        return -1;
      }
    } else if (errno != ENOENT) {
      return -1;
    }

    if (!has_next) {
      break;
    }
    current = next;
  }

  return 0;
}

static uint64_t passive_default_ttl_ns(
    const struct qaff_passive_cid_value *value) {
  if (value->source == QAFF_PASSIVE_SOURCE_EGRESS) {
    return QAFF_PASSIVE_TTL_EGRESS_NS;
  }
  if (value->confidence == QAFF_PASSIVE_CONFIDENCE_LOW) {
    return QAFF_PASSIVE_TTL_LOW_NS;
  }
  if (value->confidence == QAFF_PASSIVE_CONFIDENCE_MEDIUM) {
    return QAFF_PASSIVE_TTL_MEDIUM_NS;
  }
  return QAFF_PASSIVE_TTL_HIGH_NS;
}

static int passive_value_should_delete(const struct qaffd_state *state,
                                       const struct qaff_passive_cid_value *value,
                                       uint64_t monotonic_now_ns,
                                       int purge_worker,
                                       uint32_t worker_id) {
  if (purge_worker) {
    return worker_id == UINT32_MAX
               ? worker_is_tombstoned(state, value->worker_id)
               : value->worker_id == worker_id;
  }
  return value->expires_at_ns != 0 &&
         value->expires_at_ns <= monotonic_now_ns;
}

static int restore_passive_value(int map_fd,
                                 const struct qaff_cid_key *key,
                                 const struct qaff_passive_cid_value *value) {
  if (bpf_map_update_elem(map_fd, key, value, BPF_NOEXIST) == 0 ||
      errno == EEXIST) {
    return 0;
  }
  return -1;
}

static int cleanup_passive_cids(struct qaffd_state *state,
                                uint64_t monotonic_now_ns,
                                int purge_worker,
                                uint32_t worker_id) {
  int map_fd = qaff_get_passive_cid_map_fd(state->ctx);
  if (map_fd < 0 || monotonic_now_ns == 0) {
    errno = EINVAL;
    return -1;
  }

  struct bpf_map_info map_info;
  memset(&map_info, 0, sizeof(map_info));
  uint32_t map_info_len = sizeof(map_info);
  if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len) != 0) {
    return -1;
  }

  struct qaff_cid_key current;
  if (bpf_map_get_next_key(map_fd, NULL, &current) != 0) {
    return errno == ENOENT ? 0 : -1;
  }

  for (uint32_t inspected = 0; inspected < map_info.max_entries; inspected++) {
    struct qaff_cid_key next;
    int has_next = bpf_map_get_next_key(map_fd, &current, &next) == 0;
    if (!has_next && errno != ENOENT) {
      return -1;
    }

    struct qaff_passive_cid_value value;
    if (bpf_map_lookup_elem(map_fd, &current, &value) == 0) {
      int should_delete = passive_value_should_delete(state,
                                                       &value,
                                                       monotonic_now_ns,
                                                       purge_worker,
                                                       worker_id);
      int should_initialize =
          !purge_worker && value.expires_at_ns == 0;
      if (should_delete || should_initialize) {
        /*
         * Atomically take the current value, then re-evaluate it. A dataplane
         * refresh or a concurrent owner change between lookup and deletion
         * must not be discarded by this userspace scan.
         */
        struct qaff_passive_cid_value removed;
        if (bpf_map_lookup_and_delete_elem(map_fd, &current, &removed) != 0) {
          if (errno != ENOENT) {
            return -1;
          }
        } else if (passive_value_should_delete(state,
                                               &removed,
                                               monotonic_now_ns,
                                               purge_worker,
                                               worker_id)) {
          if (purge_worker) {
            state->passive_worker_purged_count++;
          } else {
            state->passive_expired_count++;
          }
        } else if (!purge_worker && removed.expires_at_ns == 0) {
          removed.expires_at_ns =
              monotonic_now_ns + passive_default_ttl_ns(&removed);
          if (bpf_map_update_elem(map_fd,
                                  &current,
                                  &removed,
                                  BPF_NOEXIST) == 0) {
            state->passive_expiry_initialized_count++;
          } else if (errno != EEXIST) {
            return -1;
          }
        } else if (restore_passive_value(map_fd, &current, &removed) != 0) {
          return -1;
        }
      }
    } else if (errno != ENOENT) {
      return -1;
    }

    if (!has_next) {
      break;
    }
    current = next;
  }

  return 0;
}

static void mark_state_persistence_degraded(struct qaffd_state *state,
                                            const char *stage,
                                            int error) {
  state->state_persistence_degraded = 1;
  state->state_persistence_error_count++;
  state->state_persistence_retry_at_ms =
      now_ms() + QAFFD_STATE_PERSISTENCE_RETRY_MS;
  audit_event("state_persistence_degraded",
              NULL,
              "stage=%s errno=%d error_count=%llu retry_ms=%u",
              stage,
              error,
              (unsigned long long)state->state_persistence_error_count,
              QAFFD_STATE_PERSISTENCE_RETRY_MS);
}

static int save_state(struct qaffd_state *state) {
  int result = qaffd_state_store_save(state->state_path,
                                      state->worker_registered,
                                      state->worker_generations,
                                      QAFFD_MAX_WORKERS);
  if (result == QAFFD_STATE_STORE_SAVE_COMMITTED_UNSYNCED) {
    int saved_errno = errno ? errno : EIO;
    mark_state_persistence_degraded(state,
                                    "parent_directory_sync",
                                    saved_errno);
    errno = saved_errno;
    return 0;
  }
  if (result != 0) {
    int saved_errno = errno ? errno : EIO;
    mark_state_persistence_degraded(state, "snapshot_write", saved_errno);
    errno = saved_errno;
    return -1;
  }
  if (state->state_persistence_degraded) {
    audit_event("state_persistence_recovered",
                NULL,
                "error_count=%llu retry_count=%llu",
                (unsigned long long)state->state_persistence_error_count,
                (unsigned long long)state->state_persistence_retry_count);
  }
  state->state_persistence_degraded = 0;
  state->state_persistence_retry_at_ms = 0;
  return result;
}

static void retry_state_persistence_if_due(struct qaffd_state *state) {
  if (!state->state_persistence_degraded ||
      now_ms() < state->state_persistence_retry_at_ms) {
    return;
  }
  state->state_persistence_retry_count++;
  (void)save_state(state);
}

static int load_state(struct qaffd_state *state) {
  return qaffd_state_store_load(state->state_path,
                                state->worker_registered,
                                state->worker_registered_at_ms,
                                state->worker_last_seen_ms,
                                state->worker_generations,
                                QAFFD_MAX_WORKERS,
                                now_ms());
}

static int validate_workers_against_generation_map(
    const struct qaffd_state *state) {
  int map_fd = qaff_get_worker_generation_map_fd(state->ctx);
  if (map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  for (uint32_t worker_id = 0; worker_id < QAFFD_MAX_WORKERS; worker_id++) {
    uint32_t generation = 0;
    if (bpf_map_lookup_elem(map_fd, &worker_id, &generation) != 0) {
      return -1;
    }
    if (generation == 0) {
      continue;
    }
    if (generation > QAFF_WORKER_GENERATION_MAX) {
      errno = EINVAL;
      return -1;
    }
    if (worker_is_tombstoned(state, worker_id)) {
      continue;
    }
    if (!state->worker_registered[worker_id] ||
        state->worker_generations[worker_id] != generation) {
      fprintf(stderr,
              "qaffd: pinned worker generation disagrees with durable state "
              "worker_id=%u map_generation=%u state_registered=%u "
              "state_generation=%u\n",
              worker_id,
              generation,
              state->worker_registered[worker_id] ? 1u : 0u,
              state->worker_generations[worker_id]);
      errno = EUCLEAN;
      return -1;
    }
  }
  return 0;
}

static int recover_cids_from_map(struct qaffd_state *state) {
  int map_fd = qaff_get_cid_map_fd(state->ctx);
  int generation_map_fd = qaff_get_worker_generation_map_fd(state->ctx);
  if (map_fd < 0 || generation_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  struct bpf_map_info info;
  memset(&info, 0, sizeof(info));
  uint32_t info_len = sizeof(info);
  if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) != 0) {
    return -1;
  }

  struct qaff_cid_key current;
  if (bpf_map_get_next_key(map_fd, NULL, &current) != 0) {
    return errno == ENOENT ? 0 : -1;
  }
  for (uint32_t inspected = 0; inspected < info.max_entries; inspected++) {
    struct qaff_cid_key next;
    int has_next = bpf_map_get_next_key(map_fd, &current, &next) == 0;
    if (!has_next && errno != ENOENT) {
      return -1;
    }

    struct qaff_cid_value value;
    int valid = bpf_map_lookup_elem(map_fd, &current, &value) == 0;
    if (!valid && errno != ENOENT) {
      return -1;
    }
    if (valid) {
      uint32_t live_generation = 0;
      if (value.worker_id < QAFFD_MAX_WORKERS &&
          bpf_map_lookup_elem(generation_map_fd,
                              &value.worker_id,
                              &live_generation) != 0) {
        return -1;
      }
      valid = value.worker_id < QAFFD_MAX_WORKERS &&
              value.worker_generation != 0 &&
              state->worker_registered[value.worker_id] &&
              state->worker_generations[value.worker_id] ==
                  value.worker_generation &&
              (live_generation == 0 ||
               live_generation == value.worker_generation);
    }
    if (!valid) {
      if (bpf_map_delete_elem(map_fd, &current) != 0 && errno != ENOENT) {
        return -1;
      }
    } else if (qaffd_cid_index_put(&state->cid_index,
                                    &current,
                                    value.worker_id) != 0) {
      return -1;
    }

    if (!has_next) {
      return 0;
    }
    current = next;
  }
  errno = EAGAIN;
  return -1;
}

static int reconcile_worker_tombstones(struct qaffd_state *state) {
  int have_tombstones = 0;
  for (uint32_t worker_id = 0; worker_id < QAFFD_MAX_WORKERS; worker_id++) {
    if (worker_is_tombstoned(state, worker_id)) {
      have_tombstones = 1;
    }
  }

  if (!have_tombstones) {
    return 0;
  }
  if (retire_worker_cids(state, UINT32_MAX) != 0) {
    return -1;
  }
  if (cleanup_passive_cids(state, now_ns(), 1, UINT32_MAX) != 0) {
    state->passive_cleanup_error_count++;
    return -1;
  }

  for (uint32_t worker_id = 0; worker_id < QAFFD_MAX_WORKERS; worker_id++) {
    if (!worker_is_tombstoned(state, worker_id)) {
      continue;
    }
    if (qaff_unregister_worker_socket_only(state->ctx, worker_id) != 0 &&
        errno != ENOENT) {
      return -1;
    }
  }
  return 0;
}

static int withdraw_worker_route(struct qaffd_state *state,
                                 uint32_t worker_id) {
  int generation_map_fd = qaff_get_worker_generation_map_fd(state->ctx);
  int worker_map_fd = qaff_get_worker_sock_map_fd(state->ctx);
  if (generation_map_fd < 0 || worker_map_fd < 0 ||
      worker_id >= QAFFD_MAX_WORKERS) {
    errno = EINVAL;
    return -1;
  }

  uint32_t zero = 0;
  if (bpf_map_update_elem(generation_map_fd,
                          &worker_id,
                          &zero,
                          BPF_ANY) != 0 ||
      (bpf_map_delete_elem(worker_map_fd, &worker_id) != 0 &&
       errno != ENOENT)) {
    return -1;
  }
  return 0;
}

static int quarantine_recovered_workers(struct qaffd_state *state) {
  uint64_t quarantined_at = now_ms();
  for (uint32_t worker_id = 0; worker_id < QAFFD_MAX_WORKERS; worker_id++) {
    if (!worker_is_recovering(state, worker_id)) {
      continue;
    }

    if (withdraw_worker_route(state, worker_id) != 0) {
      return -1;
    }
    state->worker_registered_at_ms[worker_id] = quarantined_at;
    state->worker_last_seen_ms[worker_id] = quarantined_at;
    audit_event("worker_recovery_quarantined",
                NULL,
                "worker_id=%u generation=%u timeout_ms=%llu",
                worker_id,
                state->worker_generations[worker_id],
                (unsigned long long)state->worker_recovery_timeout_ms);
  }
  return 0;
}

static void snapshot_worker(const struct qaffd_state *state,
                            uint32_t worker_id,
                            struct qaffd_worker_snapshot *snapshot) {
  qaffd_worker_registry_snapshot(&state->worker_registry,
                                 worker_id,
                                 &snapshot->worker);
  snapshot->listener_locked = state->listener_locked;
  snapshot->listener_addr = state->listener_addr;
}

static void restore_worker(struct qaffd_state *state,
                           uint32_t worker_id,
                           const struct qaffd_worker_snapshot *snapshot) {
  qaffd_worker_registry_restore(&state->worker_registry,
                                worker_id,
                                &snapshot->worker);
  state->listener_locked = snapshot->listener_locked;
  state->listener_addr = snapshot->listener_addr;
}

static const char *worker_cleanup_action_name(uint8_t action) {
  switch (action) {
    case QAFFD_WORKER_CLEANUP_TOMBSTONE:
      return "tombstone";
    case QAFFD_WORKER_CLEANUP_RECOVERY_WITHDRAW:
      return "recovery_withdraw";
    default:
      return "none";
  }
}

static void defer_worker_cleanup(struct qaffd_state *state,
                                 uint32_t worker_id,
                                 uint8_t action,
                                 const struct qaffd_peer_cred *peer,
                                 const char *reason,
                                 int error) {
  if (action == QAFFD_WORKER_CLEANUP_TOMBSTONE ||
      state->worker_cleanup_actions[worker_id] == QAFFD_WORKER_CLEANUP_NONE) {
    state->worker_cleanup_actions[worker_id] = action;
  }
  (void)qaffd_cleanup_retry_mark_failed(&state->worker_cleanup_retry,
                                        worker_id,
                                        now_ms());
  audit_event("worker_cleanup_degraded",
              peer,
              "worker_id=%u action=%s reason=%s pending_count=%u errno=%d "
              "retry_ms=%u",
              worker_id,
              worker_cleanup_action_name(
                  state->worker_cleanup_actions[worker_id]),
              reason,
              state->worker_cleanup_retry.pending_count,
              error ? error : EIO,
              QAFFD_WORKER_CLEANUP_RETRY_MS);
}

static int rollback_worker_maps(
    struct qaffd_state *state,
    uint32_t worker_id,
    const struct qaffd_worker_snapshot *snapshot,
    uint64_t new_socket_cookie,
    int same_socket) {
  int recovered_same_socket = snapshot->worker.registered &&
                              snapshot->worker.worker_fd < 0 && same_socket;
  if (new_socket_cookie != 0 &&
      new_socket_cookie != snapshot->worker.socket_cookie &&
      !recovered_same_socket) {
    unregister_socket_cookie(state, new_socket_cookie);
  }

  if (!snapshot->worker.registered) {
    if (qaff_unregister_worker_socket_only(state->ctx, worker_id) != 0 &&
        errno != ENOENT) {
      return -1;
    }
    return 0;
  }
  if (snapshot->worker.worker_fd >= 0) {
    return qaff_register_worker_socket_generation(state->ctx,
                                                  worker_id,
                                                  snapshot->worker.worker_fd,
                                                  snapshot->worker.generation);
  }
  if (recovered_same_socket) {
    return withdraw_worker_route(state, worker_id);
  }

  if (qaff_unregister_worker_socket_only(state->ctx, worker_id) != 0 &&
      errno != ENOENT) {
    return -1;
  }
  errno = ESTALE;
  return -1;
}

static void rollback_registration_maps_or_defer(
    struct qaffd_state *state,
    uint32_t worker_id,
    const struct qaffd_worker_snapshot *snapshot,
    uint64_t new_socket_cookie,
    int same_socket,
    const struct qaffd_peer_cred *peer,
    const char *stage) {
  if (rollback_worker_maps(state,
                           worker_id,
                           snapshot,
                           new_socket_cookie,
                           same_socket) == 0) {
    return;
  }

  int rollback_errno = errno ? errno : EIO;
  uint8_t action = QAFFD_WORKER_CLEANUP_NONE;
  if (!snapshot->worker.registered) {
    action = QAFFD_WORKER_CLEANUP_TOMBSTONE;
  } else if (snapshot->worker.worker_fd < 0 && same_socket) {
    action = QAFFD_WORKER_CLEANUP_RECOVERY_WITHDRAW;
  }
  if (action != QAFFD_WORKER_CLEANUP_NONE) {
    defer_worker_cleanup(state,
                         worker_id,
                         action,
                         peer,
                         "registration_rollback",
                         rollback_errno);
  }
  audit_event("worker_registration_rollback_failed",
              peer,
              "worker_id=%u stage=%s action=%s errno=%d",
              worker_id,
              stage,
              action == QAFFD_WORKER_CLEANUP_NONE
                  ? "unrecoverable"
                  : worker_cleanup_action_name(action),
              rollback_errno);
}

static void reset_empty_listener_after_registration_failure(
    struct qaffd_state *state) {
  if (worker_count(state) != 0) {
    return;
  }
  state->attached = 0;
  state->listener_locked = 0;
  memset(&state->listener_addr, 0, sizeof(state->listener_addr));
}

static int handle_register_worker(struct qaffd_state *state,
                                  const struct qaff_control_msg *request,
                                  int socket_fd,
                                  const struct qaffd_peer_cred *peer,
                                  int enable_pidfd) {
  if (socket_fd < 0 || request->worker_id >= QAFFD_MAX_WORKERS) {
    errno = EINVAL;
    return -1;
  }
  if (validate_worker_peer(state, peer) != 0) {
    return -1;
  }
  if (qaffd_cleanup_retry_is_pending(&state->worker_cleanup_retry,
                                     request->worker_id)) {
    audit_event("worker_registration_rejected",
                peer,
                "worker_id=%u reason=cleanup_pending",
                request->worker_id);
    errno = EBUSY;
    return -1;
  }
  if (worker_has_pending_lease(state, request->worker_id)) {
    audit_event("worker_registration_rejected",
                peer,
                "worker_id=%u reason=lease_reply_pending",
                request->worker_id);
    errno = EBUSY;
    return -1;
  }
  if (state->fallback_mode == QAFF_FALLBACK_MODE_FIXED &&
      request->worker_id != state->fallback_worker_id &&
      (!state->worker_registered[state->fallback_worker_id] ||
       worker_is_recovering(state, state->fallback_worker_id))) {
    audit_event("worker_registration_rejected",
                peer,
                "worker_id=%u reason=fixed_fallback_unavailable "
                "fallback_worker_id=%u",
                request->worker_id,
                state->fallback_worker_id);
    errno = EHOSTDOWN;
    return -1;
  }
  int recovered_worker = worker_is_recovering(state, request->worker_id);
  if (state->worker_registered[request->worker_id] && !recovered_worker) {
    if (authorize_worker_mutation(state, request->worker_id, peer) != 0) {
      return -1;
    }
    audit_event("worker_registration_rejected",
                peer,
                "worker_id=%u reason=worker_already_live",
                request->worker_id);
    errno = EBUSY;
    return -1;
  }

  struct sockaddr_storage local_addr;
  if (validate_worker_socket(state, socket_fd, &local_addr) != 0) {
    return -1;
  }

  int same_socket =
      is_same_registered_socket(state, request->worker_id, socket_fd);
  if (same_socket < 0) {
    return -1;
  }
  if (recovered_worker && !same_socket) {
    audit_event("worker_registration_rejected",
                peer,
                "worker_id=%u reason=recovery_socket_mismatch",
                request->worker_id);
    errno = EBUSY;
    return -1;
  }

  /*
   * Attach before inserting the socket into a newly-created sockarray. After
   * an unpinned qaffd restart, the live reuseport socket can still be held by
   * the old program's sockarray; replacing the program releases that reference
   * and avoids BPF_MAP_UPDATE_ELEM returning EBUSY.
   */
  if (!state->attached) {
    if (qaff_attach_reuseport_bpf(state->bpf, socket_fd) != 0) {
      return -1;
    }
    state->attached = 1;
  }

  uint32_t generation = state->worker_generations[request->worker_id];
  uint32_t previous_generation = generation;
  if (!same_socket &&
      next_worker_generation(state->worker_generations[request->worker_id],
                             &generation) != 0) {
    reset_empty_listener_after_registration_failure(state);
    return -1;
  }
  if (!same_socket) {
    /*
     * Persist the allocated generation as a tombstone before publishing it to
     * BPF. If qaffd exits before the final worker record is committed, startup
     * must clean the pinned route rather than recover an uncommitted worker.
     */
    state->worker_generations[request->worker_id] = generation;
    if (save_state(state) != 0) {
      int saved_errno = errno ? errno : EIO;
      state->worker_generations[request->worker_id] = previous_generation;
      audit_event("worker_registration_intent_failed",
                  peer,
                  "worker_id=%u generation=%u errno=%d",
                  request->worker_id,
                  generation,
                  saved_errno);
      reset_empty_listener_after_registration_failure(state);
      errno = saved_errno;
      return -1;
    }
  }
  struct qaffd_worker_snapshot snapshot;
  snapshot_worker(state, request->worker_id, &snapshot);
  if (qaff_register_worker_socket_generation(state->ctx,
                                             request->worker_id,
                                             socket_fd,
                                             generation) != 0) {
    int saved_errno = errno ? errno : EIO;
    rollback_registration_maps_or_defer(state,
                                        request->worker_id,
                                        &snapshot,
                                        0,
                                        same_socket,
                                        peer,
                                        "worker_maps");
    reset_empty_listener_after_registration_failure(state);
    errno = saved_errno;
    return -1;
  }

  uint64_t socket_cookie = 0;
  if (register_socket_cookie(state,
                             request->worker_id,
                             socket_fd,
                             &socket_cookie) != 0) {
    int saved_errno = errno ? errno : EIO;
    rollback_registration_maps_or_defer(state,
                                        request->worker_id,
                                        &snapshot,
                                        0,
                                        same_socket,
                                        peer,
                                        "socket_cookie");
    reset_empty_listener_after_registration_failure(state);
    errno = saved_errno;
    return -1;
  }

  uint64_t now = now_ms();
  if (qaffd_worker_registry_register(&state->worker_registry,
                                     request->worker_id,
                                     socket_fd,
                                     socket_cookie,
                                     generation,
                                     enable_pidfd ? request->target_pid : 0,
                                     now,
                                     peer) != 0) {
    int saved_errno = errno ? errno : EIO;
    rollback_registration_maps_or_defer(state,
                                        request->worker_id,
                                        &snapshot,
                                        socket_cookie,
                                        same_socket,
                                        peer,
                                        "registry");
    reset_empty_listener_after_registration_failure(state);
    errno = saved_errno;
    return -1;
  }
  if (enable_pidfd) {
    int pidfd = open_pidfd_for_peer(peer);
    if (pidfd >= 0) {
      state->worker_pidfds[request->worker_id] = pidfd;
    }
  }

  if (!state->listener_locked) {
    state->listener_addr = local_addr;
    state->listener_locked = 1;
  }

  if (save_state(state) != 0) {
    int saved_errno = errno ? errno : EIO;
    int new_pidfd = state->worker_pidfds[request->worker_id];
    restore_worker(state, request->worker_id, &snapshot);
    if (new_pidfd >= 0) {
      close(new_pidfd);
    }
    if (save_state(state) != 0) {
      audit_event("worker_registration_rollback_failed",
                  peer,
                  "worker_id=%u stage=state_restore errno=%d",
                  request->worker_id,
                  errno);
    }
    rollback_registration_maps_or_defer(state,
                                        request->worker_id,
                                        &snapshot,
                                        socket_cookie,
                                        same_socket,
                                        peer,
                                        "state_persist");
    reset_empty_listener_after_registration_failure(state);
    errno = saved_errno;
    return -1;
  }

  if (snapshot.worker.worker_fd >= 0 &&
      snapshot.worker.worker_fd != socket_fd) {
    close(snapshot.worker.worker_fd);
  }
  if (snapshot.worker.pidfd >= 0 &&
      snapshot.worker.pidfd != state->worker_pidfds[request->worker_id]) {
    close(snapshot.worker.pidfd);
  }
  if (snapshot.worker.socket_cookie != socket_cookie) {
    unregister_socket_cookie(state, snapshot.worker.socket_cookie);
  }
  if (!enable_pidfd && state->worker_lease_fds[request->worker_id] >= 0) {
    close(state->worker_lease_fds[request->worker_id]);
    state->worker_lease_fds[request->worker_id] = -1;
  }
  audit_event("worker_registered",
              peer,
              "worker_id=%u generation=%u leased=%u same_socket=%u "
              "target_pid=%u",
              request->worker_id,
              generation,
              enable_pidfd ? 1u : 0u,
              same_socket ? 1u : 0u,
              state->worker_target_pids[request->worker_id]);
  if (state->fallback_mode == QAFF_FALLBACK_MODE_FIXED &&
      request->worker_id == state->fallback_worker_id) {
    audit_event("fixed_fallback_available",
                peer,
                "worker_id=%u",
                request->worker_id);
  }
  return 0;
}

static int cleanup_worker_dataplane(
    struct qaffd_state *state,
    uint32_t worker_id,
    const struct qaffd_peer_cred *peer,
    const char *failure_event) {
  int cleanup_errno = 0;
  if (qaff_unregister_worker_socket_only(state->ctx, worker_id) != 0 &&
      errno != ENOENT) {
    cleanup_errno = errno ? errno : EIO;
    audit_event(failure_event,
                peer,
                "worker_id=%u stage=worker_maps errno=%d",
                worker_id,
                cleanup_errno);
  }
  if (retire_worker_cids(state, worker_id) != 0) {
    int stage_errno = errno ? errno : EIO;
    if (cleanup_errno == 0) {
      cleanup_errno = stage_errno;
    }
    audit_event(failure_event,
                peer,
                "worker_id=%u stage=exact_cids errno=%d",
                worker_id,
                stage_errno);
  }
  if (cleanup_passive_cids(state, now_ns(), 1, worker_id) != 0) {
    int stage_errno = errno ? errno : EIO;
    if (cleanup_errno == 0) {
      cleanup_errno = stage_errno;
    }
    state->passive_cleanup_error_count++;
    audit_event(failure_event,
                peer,
                "worker_id=%u stage=passive_cids errno=%d",
                worker_id,
                stage_errno);
  }

  if (cleanup_errno != 0) {
    errno = cleanup_errno;
    return -1;
  }
  return 0;
}

static int finalize_worker_unregistration(
    struct qaffd_state *state,
    uint32_t worker_id,
    const struct qaffd_peer_cred *peer) {
  int cleanup_rc = cleanup_worker_dataplane(
      state,
      worker_id,
      peer,
      "worker_unregistration_incomplete");
  int cleanup_errno = errno;

  if (state->worker_fds[worker_id] >= 0) {
    close(state->worker_fds[worker_id]);
  }
  unregister_socket_cookie(state, state->worker_socket_cookies[worker_id]);
  if (state->worker_lease_fds[worker_id] >= 0) {
    close(state->worker_lease_fds[worker_id]);
  }
  if (state->worker_pidfds[worker_id] >= 0) {
    close(state->worker_pidfds[worker_id]);
  }
  qaffd_worker_registry_clear(&state->worker_registry, worker_id);
  if (worker_count(state) == 0) {
    state->attached = 0;
    state->listener_locked = 0;
    memset(&state->listener_addr, 0, sizeof(state->listener_addr));
  }
  audit_event("worker_unregistered",
              peer,
              "worker_id=%u",
              worker_id);
  if (state->fallback_mode == QAFF_FALLBACK_MODE_FIXED &&
      worker_id == state->fallback_worker_id) {
    audit_event("fixed_fallback_unavailable",
                peer,
                "worker_id=%u remaining_workers=%u",
                worker_id,
                worker_count(state));
  }
  if (cleanup_rc != 0) {
    defer_worker_cleanup(state,
                         worker_id,
                         QAFFD_WORKER_CLEANUP_TOMBSTONE,
                         peer,
                         "unregistration",
                         cleanup_errno);
    errno = cleanup_errno;
    return -1;
  }
  if (qaffd_cleanup_retry_is_pending(&state->worker_cleanup_retry,
                                     worker_id)) {
    audit_event("worker_cleanup_superseded",
                peer,
                "worker_id=%u old_action=%s reason=unregistration_complete",
                worker_id,
                worker_cleanup_action_name(
                    state->worker_cleanup_actions[worker_id]));
    (void)qaffd_cleanup_retry_clear(&state->worker_cleanup_retry, worker_id);
    state->worker_cleanup_actions[worker_id] = QAFFD_WORKER_CLEANUP_NONE;
  }
  return 0;
}

static int retry_worker_cleanup_one(void *opaque, uint32_t worker_id) {
  struct qaffd_state *state = opaque;
  uint8_t action = state->worker_cleanup_actions[worker_id];
  int cleanup_rc;
  if (action == QAFFD_WORKER_CLEANUP_RECOVERY_WITHDRAW) {
    cleanup_rc = withdraw_worker_route(state, worker_id);
    if (cleanup_rc != 0) {
      audit_event("worker_cleanup_retry_failed",
                  NULL,
                  "worker_id=%u action=recovery_withdraw errno=%d",
                  worker_id,
                  errno ? errno : EIO);
    }
  } else if (action == QAFFD_WORKER_CLEANUP_TOMBSTONE) {
    cleanup_rc = cleanup_worker_dataplane(state,
                                          worker_id,
                                          NULL,
                                          "worker_cleanup_retry_failed");
  } else {
    audit_event("worker_cleanup_retry_failed",
                NULL,
                "worker_id=%u action=none errno=%d",
                worker_id,
                EINVAL);
    errno = EINVAL;
    return -1;
  }
  if (cleanup_rc != 0) {
    return -1;
  }
  audit_event("worker_cleanup_recovered",
              NULL,
              "worker_id=%u action=%s remaining_before=%u",
              worker_id,
              worker_cleanup_action_name(action),
              state->worker_cleanup_retry.pending_count);
  state->worker_cleanup_actions[worker_id] = QAFFD_WORKER_CLEANUP_NONE;
  return 0;
}

static int retry_worker_cleanups_if_due(struct qaffd_state *state) {
  return qaffd_cleanup_retry_run_due(&state->worker_cleanup_retry,
                                     now_ms(),
                                     retry_worker_cleanup_one,
                                     state);
}

static int unregister_worker_authorized(struct qaffd_state *state,
                                        uint32_t worker_id,
                                        const struct qaffd_peer_cred *peer) {
  /*
   * The durable tombstone is the transaction commit point. Temporarily expose
   * the prospective registry state only to the synchronous snapshot writer;
   * live in-memory and BPF routing remain unchanged if persistence fails.
   */
  int was_registered = state->worker_registered[worker_id];
  state->worker_registered[worker_id] = 0;
  int persist_rc = save_state(state);
  int persist_errno = errno;
  state->worker_registered[worker_id] = was_registered;
  if (persist_rc != 0) {
    audit_event("worker_unregistration_commit_failed",
                peer,
                "worker_id=%u stage=state_persist errno=%d",
                worker_id,
                persist_errno ? persist_errno : EIO);
    errno = persist_errno ? persist_errno : EIO;
    return -1;
  }

  return finalize_worker_unregistration(state, worker_id, peer);
}

static int handle_unregister_worker(struct qaffd_state *state,
                                    const struct qaff_control_msg *request,
                                    const struct qaffd_peer_cred *peer) {
  if (authorize_worker_mutation(state, request->worker_id, peer) != 0) {
    return -1;
  }
  return unregister_worker_authorized(state, request->worker_id, peer);
}

static int handle_register_cid(struct qaffd_state *state,
                               const struct qaff_control_msg *request,
                               const struct qaffd_peer_cred *peer) {
  if (authorize_worker_mutation(state, request->worker_id, peer) != 0) {
    return -1;
  }

  struct qaff_cid_key key;
  if (qaff_cid_key_from_bytes(request->cid, request->cid_len, &key) !=
      QAFF_PARSE_OK) {
    errno = EINVAL;
    return -1;
  }

  ptrdiff_t existing_position =
      qaffd_cid_index_find(&state->cid_index, &key);
  const struct qaffd_cid_entry *existing_entry =
      existing_position < 0
          ? NULL
          : qaffd_cid_index_entry(&state->cid_index,
                                  (size_t)existing_position);
  if (existing_entry != NULL &&
      existing_entry->worker_id != request->worker_id) {
    errno = EEXIST;
    return -1;
  }

  int index_inserted = existing_entry == NULL;
  if (index_inserted &&
      qaffd_cid_index_put(&state->cid_index,
                          &key,
                          request->worker_id) != 0) {
    return -1;
  }

  if (qaff_register_cid(state->ctx,
                        request->cid,
                        request->cid_len,
                        request->worker_id) != 0) {
    int saved_errno = errno ? errno : EIO;
    if (index_inserted &&
        qaffd_cid_index_remove(&state->cid_index, &key) != 0) {
      audit_event("cid_registration_rollback_failed",
                  peer,
                  "worker_id=%u stage=ownership_index errno=%d",
                  request->worker_id,
                  errno ? errno : EIO);
    }
    errno = saved_errno;
    return -1;
  }

  audit_event("cid_registered",
              peer,
              "worker_id=%u cid_len=%u",
              request->worker_id,
              request->cid_len);
  return 0;
}

static int handle_retire_cid(struct qaffd_state *state,
                             const struct qaff_control_msg *request,
                             const struct qaffd_peer_cred *peer) {
  struct qaff_cid_key key;
  if (qaff_cid_key_from_bytes(request->cid, request->cid_len, &key) !=
      QAFF_PARSE_OK) {
    errno = EINVAL;
    return -1;
  }

  ptrdiff_t position = qaffd_cid_index_find(&state->cid_index, &key);
  const struct qaffd_cid_entry *entry =
      position < 0
          ? NULL
          : qaffd_cid_index_entry(&state->cid_index, (size_t)position);
  if (entry == NULL) {
    errno = ENOENT;
    return -1;
  }
  if (authorize_worker_mutation(state, entry->worker_id, peer) != 0) {
    return -1;
  }
  uint32_t owner_worker_id = entry->worker_id;

  if (qaff_retire_cid(state->ctx, request->cid, request->cid_len) != 0 &&
      errno != ENOENT) {
    return -1;
  }

  if (qaffd_cid_index_remove(&state->cid_index, &key) != 0) {
    return -1;
  }
  audit_event("cid_retired",
              peer,
              "worker_id=%u cid_len=%u",
              owner_worker_id,
              request->cid_len);
  return 0;
}

static int validate_passive_request(const struct qaffd_state *state,
                                    struct qaff_passive_cid_value *value) {
  if (value->worker_id >= QAFFD_MAX_WORKERS ||
      !state->worker_registered[value->worker_id]) {
    errno = ENOENT;
    return -1;
  }
  if (value->confidence < QAFF_PASSIVE_CONFIDENCE_LOW ||
      value->confidence > QAFF_PASSIVE_CONFIDENCE_HIGH) {
    errno = EINVAL;
    return -1;
  }
  if (value->source != QAFF_PASSIVE_SOURCE_INGRESS &&
      value->source != QAFF_PASSIVE_SOURCE_EGRESS) {
    errno = EINVAL;
    return -1;
  }
  if (value->flags != 0) {
    errno = EINVAL;
    return -1;
  }

  uint32_t current_generation = state->worker_generations[value->worker_id];
  if (current_generation == 0) {
    errno = EINVAL;
    return -1;
  }
  if (value->worker_generation != 0 &&
      value->worker_generation != current_generation) {
    errno = EINVAL;
    return -1;
  }
  value->worker_generation = current_generation;
  uint64_t monotonic_now_ns = now_ns();
  if (monotonic_now_ns == 0) {
    errno = EIO;
    return -1;
  }
  uint64_t default_expiry =
      monotonic_now_ns + passive_default_ttl_ns(value);
  if (value->expires_at_ns != 0 &&
      value->expires_at_ns <= monotonic_now_ns) {
    errno = EINVAL;
    return -1;
  }
  if (value->expires_at_ns == 0 ||
      value->expires_at_ns > default_expiry) {
    value->expires_at_ns = default_expiry;
  }
  return 0;
}

static int handle_register_passive_cid(struct qaffd_state *state,
                                       const struct qaff_control_msg *request,
                                       const struct qaffd_peer_cred *peer) {
  if (authorize_daemon_mutation(state, peer) != 0) {
    return -1;
  }

  struct qaff_passive_cid_value value = request->passive_value;
  if (value.worker_id != request->worker_id) {
    errno = EINVAL;
    return -1;
  }
  if (validate_passive_request(state, &value) != 0) {
    return -1;
  }

  if (qaff_register_passive_cid(state->ctx,
                                request->cid,
                                request->cid_len,
                                &value) != 0) {
    return -1;
  }

  audit_event("passive_cid_registered",
              peer,
              "worker_id=%u confidence=%u source=%u cid_len=%u",
              value.worker_id,
              value.confidence,
              value.source,
              request->cid_len);
  return 0;
}

static int handle_retire_passive_cid(struct qaffd_state *state,
                                     const struct qaff_control_msg *request,
                                     const struct qaffd_peer_cred *peer) {
  if (authorize_daemon_mutation(state, peer) != 0) {
    return -1;
  }

  if (qaff_retire_passive_cid(state->ctx,
                              request->cid,
                              request->cid_len) != 0) {
    return -1;
  }

  audit_event("passive_cid_retired",
              peer,
              "cid_len=%u",
              request->cid_len);
  return 0;
}

static void install_worker_lease(struct qaffd_state *state,
                                 uint32_t worker_id,
                                 int lease_fd) {
  if (state->worker_lease_fds[worker_id] >= 0) {
    close(state->worker_lease_fds[worker_id]);
  }
  state->worker_lease_fds[worker_id] = lease_fd;
}

static int unregister_worker_liveness(struct qaffd_state *state,
                                      uint32_t worker_id,
                                      const char *reason) {
  if (worker_id >= QAFFD_MAX_WORKERS ||
      !state->worker_registered[worker_id]) {
    errno = ENOENT;
    return -1;
  }
  int rc = unregister_worker_authorized(state, worker_id, NULL);
  int saved_errno = errno;
  if (rc == 0 || !state->worker_registered[worker_id]) {
    errno = saved_errno;
    return rc;
  }

  /*
   * This path is used only after qaffd has confirmed loss of liveness. A
   * failed tombstone write must not leave an ownerless worker routable. The
   * failed save has already scheduled a rate-limited retry; withdraw the live
   * generation and socket now, then let that retry persist the tombstone.
   */
  audit_event("worker_liveness_fail_closed",
              NULL,
              "worker_id=%u generation=%u reason=%s errno=%d",
              worker_id,
              state->worker_generations[worker_id],
              reason,
              saved_errno ? saved_errno : EIO);
  if (finalize_worker_unregistration(state, worker_id, NULL) != 0) {
    audit_event("worker_liveness_withdrawal_incomplete",
                NULL,
                "worker_id=%u errno=%d",
                worker_id,
                errno ? errno : EIO);
  }
  errno = saved_errno ? saved_errno : EIO;
  return -1;
}

static int handle_worker_lease_event(struct qaffd_state *state,
                                     uint32_t worker_id,
                                     int lease_fd) {
  struct qaff_control_msg request;
  int received_fd = -1;
  if (recv_request(lease_fd, &request, &received_fd) != 0) {
    if (received_fd >= 0) {
      close(received_fd);
    }
    return unregister_worker_liveness(state, worker_id, "lease_read");
  }
  if (received_fd >= 0) {
    close(received_fd);
  }

  struct qaff_control_msg reply;
  reply_init(&reply, &request);
  if (request.op != QAFF_CONTROL_WORKER_HEARTBEAT ||
      request.worker_id != worker_id ||
      !state->worker_registered[worker_id] ||
      state->worker_lease_fds[worker_id] != lease_fd) {
    reply.status = EPROTO;
  } else {
    qaffd_worker_registry_heartbeat(&state->worker_registry,
                                    worker_id,
                                    now_ms());
  }

  uint8_t reply_packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t reply_len;
  if (qaff_control_encode_reply(&reply,
                                reply_packet,
                                sizeof(reply_packet),
                                &reply_len) != 0) {
    return unregister_worker_liveness(state, worker_id, "lease_reply_encode");
  }
  ssize_t written;
  do {
    written = send(lease_fd, reply_packet, reply_len, MSG_NOSIGNAL);
  } while (written < 0 && errno == EINTR);
  if (written < 0 || (size_t)written != reply_len) {
    return unregister_worker_liveness(state, worker_id, "lease_reply_write");
  }
  if (reply.status != 0) {
    int saved_errno = reply.status;
    unregister_worker_liveness(state, worker_id, "lease_protocol");
    errno = saved_errno;
    return -1;
  }

  return 0;
}

static void process_request(struct qaffd_state *state,
                            int client_fd,
                            const struct qaff_control_msg *request,
                            int *received_fd,
                            struct qaff_control_msg *reply,
                            int *lease_worker_id) {
  struct qaffd_peer_cred peer_cred;
  memset(&peer_cred, 0, sizeof(peer_cred));
  *lease_worker_id = -1;
  reply_init(reply, request);

  int requires_fd = request->op == QAFF_CONTROL_REGISTER_WORKER ||
                    request->op == QAFF_CONTROL_REGISTER_WORKER_LEASE;
  if (requires_fd != (*received_fd >= 0)) {
    reply->status = EPROTO;
    return;
  }

  switch (request->op) {
    case QAFF_CONTROL_REGISTER_WORKER:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_register_worker(state,
                                 request,
                                 *received_fd,
                                 &peer_cred,
                                 0) != 0) {
        reply->status = errno ? errno : EIO;
      } else {
        *received_fd = -1;
      }
      break;
    case QAFF_CONTROL_REGISTER_WORKER_LEASE:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_register_worker(state,
                                 request,
                                 *received_fd,
                                 &peer_cred,
                                 1) != 0) {
        reply->status = errno ? errno : EIO;
      } else {
        *lease_worker_id = (int)request->worker_id;
        state->worker_pending_lease_fds[request->worker_id] = client_fd;
        *received_fd = -1;
      }
      break;
    case QAFF_CONTROL_UNREGISTER_WORKER:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_unregister_worker(state, request, &peer_cred) != 0) {
        reply->status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_REGISTER_CID:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_register_cid(state, request, &peer_cred) != 0) {
        reply->status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_RETIRE_CID:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_retire_cid(state, request, &peer_cred) != 0) {
        reply->status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_REGISTER_PASSIVE_CID:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_register_passive_cid(state, request, &peer_cred) != 0) {
        reply->status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_RETIRE_PASSIVE_CID:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_retire_passive_cid(state, request, &peer_cred) != 0) {
        reply->status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_READ_STATS:
      if (qaff_read_stats(state->ctx, &reply->stats) != 0) {
        reply->status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_HEALTH:
      fill_config_reply(state, reply);
      if (!reply->config.fallback_available) {
        reply->status = EHOSTDOWN;
      } else if (reply->config.state_persistence_degraded ||
                 reply->config.worker_cleanup_degraded ||
                 reply->config.passive_cleanup_degraded ||
                 reply->config.cid_consistency_degraded ||
                 reply->config.cid_index_mismatch != 0) {
        reply->status = EUCLEAN;
      }
      break;
    case QAFF_CONTROL_CONFIG:
      fill_config_reply(state, reply);
      break;
    case QAFF_CONTROL_WORKERS:
      if (request->worker_id >= QAFFD_MAX_WORKERS) {
        reply->status = EINVAL;
      } else {
        if (request->worker_id == 0) {
          fill_config_reply(state, reply);
        } else {
          reply->config.worker_count = worker_count(state);
        }
        fill_workers_reply(state, request->worker_id, reply);
      }
      break;
    case QAFF_CONTROL_CIDS:
      fill_config_reply(state, reply);
      break;
    case QAFF_CONTROL_STOP:
      if (qaffd_get_peer_cred(client_fd, &peer_cred) != 0 ||
          authorize_daemon_mutation(state, &peer_cred) != 0) {
        reply->status = errno ? errno : EIO;
      } else {
        state->stop = 1;
      }
      break;
  default:
    reply->status = ENOSYS;
    break;
  }
}

static void init_client(struct qaffd_client *client) {
  memset(client, 0, sizeof(*client));
  client->fd = -1;
  client->received_fd = -1;
  client->lease_worker_id = -1;
  client->stage = QAFFD_CLIENT_READING;
}

static void drop_client(struct qaffd_state *state,
                        struct qaffd_client *client) {
  if (client->lease_worker_id >= 0) {
    uint32_t worker_id = (uint32_t)client->lease_worker_id;
    if (state->worker_pending_lease_fds[worker_id] == client->fd) {
      state->worker_pending_lease_fds[worker_id] = -1;
      (void)unregister_worker_liveness(state,
                                       worker_id,
                                       "lease_registration_reply");
    }
  }
  if (client->received_fd >= 0) {
    close(client->received_fd);
  }
  if (client->fd >= 0) {
    close(client->fd);
  }
  init_client(client);
}

static int receive_client_request(struct qaffd_client *client) {
  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  struct iovec iov = {
    .iov_base = packet,
    .iov_len = sizeof(packet),
  };
  int rights[4];
  char control[CMSG_SPACE(sizeof(rights))];
  memset(control, 0, sizeof(control));
  struct msghdr hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  hdr.msg_control = control;
  hdr.msg_controllen = sizeof(control);

  ssize_t got;
  do {
    got = recvmsg(client->fd, &hdr, MSG_DONTWAIT);
  } while (got < 0 && errno == EINTR);
  if (got < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
  if (got == 0) {
    errno = ECONNRESET;
    return -1;
  }

  int invalid_rights = 0;
  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
      continue;
    }
    size_t rights_len = cmsg->cmsg_len - CMSG_LEN(0);
    size_t rights_count = rights_len / sizeof(int);
    const int *received = (const int *)CMSG_DATA(cmsg);
    for (size_t i = 0; i < rights_count; i++) {
      if (client->received_fd < 0 && !invalid_rights) {
        client->received_fd = received[i];
      } else {
        close(received[i]);
        invalid_rights = 1;
      }
    }
  }
  if ((hdr.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0 || invalid_rights) {
    errno = EPROTO;
    return -1;
  }
  if (qaff_control_decode_request(packet,
                                  (size_t)got,
                                  &client->request) != 0) {
    return -1;
  }
  return 1;
}

static int write_client_reply(struct qaffd_client *client) {
  ssize_t written;
  do {
    written = send(client->fd,
                   client->reply_packet,
                   client->reply_len,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
  } while (written < 0 && errno == EINTR);
  if (written < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return -1;
  }
  if ((size_t)written != client->reply_len) {
    errno = EIO;
    return -1;
  }
  return 1;
}

static int service_client(struct qaffd_state *state,
                          struct qaffd_client *client) {
  if (client->stage == QAFFD_CLIENT_READING) {
    int rc = receive_client_request(client);
    if (rc <= 0) {
      return rc;
    }
    process_request(state,
                    client->fd,
                    &client->request,
                    &client->received_fd,
                    &client->reply,
                    &client->lease_worker_id);
    if (client->received_fd >= 0) {
      close(client->received_fd);
      client->received_fd = -1;
    }
    if (qaff_control_encode_reply(&client->reply,
                                  client->reply_packet,
                                  sizeof(client->reply_packet),
                                  &client->reply_len) != 0) {
      return -1;
    }
    client->stage = QAFFD_CLIENT_WRITING;
  }
  return write_client_reply(client);
}

static void complete_client(struct qaffd_state *state,
                            struct qaffd_client *client) {
  if (client->lease_worker_id >= 0) {
    uint32_t worker_id = (uint32_t)client->lease_worker_id;
    if (state->worker_pending_lease_fds[worker_id] == client->fd) {
      state->worker_pending_lease_fds[worker_id] = -1;
      if (state->worker_registered[worker_id]) {
        install_worker_lease(state, worker_id, client->fd);
        client->fd = -1;
      }
    }
    client->lease_worker_id = -1;
    drop_client(state, client);
    return;
  }

  memset(&client->request, 0, sizeof(client->request));
  memset(&client->reply, 0, sizeof(client->reply));
  client->reply_len = 0;
  client->stage = QAFFD_CLIENT_READING;
  client->deadline_ms = now_ms() + QAFFD_CONTROL_DEADLINE_MS;
}

static int make_server_socket(const struct qaffd_state *state,
                              const char *path) {
  int fd = socket(AF_UNIX,
                  SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
                  0);
  if (fd < 0) {
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(path) >= sizeof(addr.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(addr.sun_path, path);

  struct stat existing;
  if (lstat(path, &existing) == 0) {
    if (!S_ISSOCK(existing.st_mode) || existing.st_uid != geteuid()) {
      close(fd);
      errno = EEXIST;
      return -1;
    }
    if (unlink(path) != 0) {
      int saved_errno = errno;
      close(fd);
      errno = saved_errno;
      return -1;
    }
  } else if (errno != ENOENT) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  if (state->socket_gid_set &&
      chown(path, (uid_t)-1, (gid_t)state->socket_gid) != 0) {
    int saved_errno = errno;
    close(fd);
    unlink(path);
    errno = saved_errno;
    return -1;
  }

  if (chmod(path, state->socket_mode) != 0) {
    int saved_errno = errno;
    close(fd);
    unlink(path);
    errno = saved_errno;
    return -1;
  }

  if (listen(fd, 64) != 0) {
    int saved_errno = errno;
    close(fd);
    unlink(path);
    errno = saved_errno;
    return -1;
  }

  return fd;
}

static int acquire_instance_lock(const char *socket_path) {
  char lock_path[PATH_MAX];
  int n = snprintf(lock_path, sizeof(lock_path), "%s.lock", socket_path);
  if (n < 0 || (size_t)n >= sizeof(lock_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  int fd = open(lock_path,
                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                0600);
  if (fd < 0) {
    return -1;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  if (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
      st.st_uid != geteuid() || (st.st_mode & 0077) != 0) {
    close(fd);
    errno = EINVAL;
    return -1;
  }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    int saved_errno = errno == EWOULDBLOCK ? EADDRINUSE : errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}

static int attach_egress_cgroup_if_configured(struct qaff_bpf_object *bpf,
                                              const char *path) {
  if (path == NULL) {
    return 0;
  }

  int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_attach_cgroup_egress_bpf(bpf, fd);
  int saved_errno = errno;
  close(fd);
  if (rc != 0) {
    errno = saved_errno ? saved_errno : EIO;
    return -1;
  }
  return 0;
}

static int accept_client(int server_fd) {
  int fd;
  do {
    fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
  } while (fd < 0 && errno == EINTR && !g_stop_requested);
  return fd;
}

static nfds_t build_pollfds(const struct qaffd_state *state,
                            const struct qaffd_client *clients,
                            int server_fd,
                            struct pollfd *fds,
                            uint32_t *worker_ids,
                            enum qaffd_poll_source *sources,
                            nfds_t cap) {
  nfds_t count = 0;
  if (cap == 0) {
    return 0;
  }

  fds[count].fd = server_fd;
  fds[count].events = POLLIN;
  fds[count].revents = 0;
  worker_ids[count] = UINT32_MAX;
  sources[count] = QAFFD_POLL_SERVER;
  count++;

  for (uint32_t i = 0; i < QAFFD_MAX_WORKERS && count < cap; i++) {
    if (state->worker_lease_fds[i] >= 0 &&
        !worker_has_pending_lease(state, i)) {
      fds[count].fd = state->worker_lease_fds[i];
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      worker_ids[count] = i;
      sources[count] = QAFFD_POLL_WORKER_LEASE;
      count++;
    }
    if (state->worker_pidfds[i] >= 0 &&
        !worker_has_pending_lease(state, i) && count < cap) {
      fds[count].fd = state->worker_pidfds[i];
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      worker_ids[count] = i;
      sources[count] = QAFFD_POLL_WORKER_PIDFD;
      count++;
    }
  }

  for (uint32_t i = 0;
       i < QAFFD_MAX_PENDING_CLIENTS && count < cap;
       i++) {
    if (clients[i].fd < 0) {
      continue;
    }
    fds[count].fd = clients[i].fd;
    fds[count].events = clients[i].stage == QAFFD_CLIENT_READING
                            ? POLLIN
                            : POLLOUT;
    fds[count].revents = 0;
    worker_ids[count] = i;
    sources[count] = QAFFD_POLL_CLIENT;
    count++;
  }

  return count;
}

static int expire_worker_heartbeat_timeouts(struct qaffd_state *state) {
  if (state->worker_heartbeat_timeout_ms == 0) {
    return 0;
  }

  uint64_t now = now_ms();
  int rc = 0;
  for (uint32_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state->worker_lease_fds[i] < 0 || !state->worker_registered[i] ||
        worker_has_pending_lease(state, i)) {
      continue;
    }
    if (elapsed_ms(now, state->worker_last_seen_ms[i]) <
        state->worker_heartbeat_timeout_ms) {
      continue;
    }
    if (unregister_worker_liveness(state, i, "heartbeat_timeout") != 0 &&
        errno != ENOENT) {
      rc = -1;
    }
  }
  return rc;
}

static int expire_recovered_workers(struct qaffd_state *state) {
  uint64_t now = now_ms();
  int rc = 0;
  for (uint32_t worker_id = 0;
       worker_id < QAFFD_MAX_WORKERS;
       worker_id++) {
    if (!worker_is_recovering(state, worker_id) ||
        elapsed_ms(now, state->worker_registered_at_ms[worker_id]) <
            state->worker_recovery_timeout_ms) {
      continue;
    }
    audit_event("worker_recovery_expired",
                NULL,
                "worker_id=%u generation=%u",
                worker_id,
                state->worker_generations[worker_id]);
    if (unregister_worker_liveness(state,
                                   worker_id,
                                   "recovery_timeout") != 0 &&
        errno != ENOENT) {
      rc = -1;
    }
  }
  return rc;
}

static int expire_passive_cids_if_due(struct qaffd_state *state) {
  if (!state->passive_affinity_enabled ||
      state->passive_scan_interval_ms == 0) {
    return 0;
  }

  uint64_t monotonic_now_ms = now_ms();
  if (state->passive_cleanup_degraded) {
    if (monotonic_now_ms < state->passive_cleanup_retry_at_ms) {
      return 0;
    }
    state->passive_cleanup_retry_count++;
  } else if (state->passive_last_scan_ms != 0 &&
      elapsed_ms(monotonic_now_ms, state->passive_last_scan_ms) <
          state->passive_scan_interval_ms) {
    return 0;
  }

  state->passive_last_scan_ms = monotonic_now_ms;
  if (cleanup_passive_cids(state, now_ns(), 0, 0) != 0) {
    int saved_errno = errno ? errno : EIO;
    state->passive_cleanup_degraded = 1;
    state->passive_cleanup_error_count++;
    state->passive_cleanup_retry_at_ms =
        monotonic_now_ms + QAFFD_PASSIVE_CLEANUP_RETRY_MS;
    audit_event("passive_cleanup_degraded",
                NULL,
                "errno=%d error_count=%llu retry_ms=%u",
                saved_errno,
                (unsigned long long)state->passive_cleanup_error_count,
                QAFFD_PASSIVE_CLEANUP_RETRY_MS);
    errno = saved_errno;
    return -1;
  }
  if (state->passive_cleanup_degraded) {
    audit_event("passive_cleanup_recovered",
                NULL,
                "error_count=%llu retry_count=%llu",
                (unsigned long long)state->passive_cleanup_error_count,
                (unsigned long long)state->passive_cleanup_retry_count);
  }
  state->passive_cleanup_degraded = 0;
  state->passive_cleanup_retry_at_ms = 0;
  return 0;
}

static int worker_heartbeat_poll_timeout(const struct qaffd_state *state) {
  if (state->worker_heartbeat_timeout_ms == 0) {
    return -1;
  }

  uint64_t now = now_ms();
  uint64_t min_remaining = UINT64_MAX;
  for (uint32_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state->worker_lease_fds[i] < 0 || !state->worker_registered[i] ||
        worker_has_pending_lease(state, i)) {
      continue;
    }
    uint64_t age = elapsed_ms(now, state->worker_last_seen_ms[i]);
    if (age >= state->worker_heartbeat_timeout_ms) {
      return 0;
    }
    uint64_t remaining = state->worker_heartbeat_timeout_ms - age;
    if (remaining < min_remaining) {
      min_remaining = remaining;
    }
  }

  if (min_remaining == UINT64_MAX) {
    return -1;
  }
  if (min_remaining > (uint64_t)INT_MAX) {
    return INT_MAX;
  }
  return (int)min_remaining;
}

static int worker_recovery_poll_timeout(const struct qaffd_state *state) {
  uint64_t now = now_ms();
  uint64_t min_remaining = UINT64_MAX;
  for (uint32_t worker_id = 0;
       worker_id < QAFFD_MAX_WORKERS;
       worker_id++) {
    if (!worker_is_recovering(state, worker_id)) {
      continue;
    }
    uint64_t age =
        elapsed_ms(now, state->worker_registered_at_ms[worker_id]);
    if (age >= state->worker_recovery_timeout_ms) {
      return 0;
    }
    uint64_t remaining = state->worker_recovery_timeout_ms - age;
    if (remaining < min_remaining) {
      min_remaining = remaining;
    }
  }
  if (min_remaining == UINT64_MAX) {
    return -1;
  }
  return min_remaining > (uint64_t)INT_MAX ? INT_MAX : (int)min_remaining;
}

static int state_persistence_poll_timeout(const struct qaffd_state *state) {
  if (!state->state_persistence_degraded) {
    return -1;
  }
  uint64_t now = now_ms();
  if (now >= state->state_persistence_retry_at_ms) {
    return 0;
  }
  uint64_t remaining = state->state_persistence_retry_at_ms - now;
  return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

static int worker_cleanup_poll_timeout(const struct qaffd_state *state) {
  return qaffd_cleanup_retry_poll_timeout(&state->worker_cleanup_retry,
                                          now_ms());
}

static int passive_cleanup_poll_timeout(const struct qaffd_state *state) {
  if (!state->passive_affinity_enabled ||
      state->passive_scan_interval_ms == 0 ||
      state->passive_last_scan_ms == 0) {
    return state->passive_affinity_enabled ? 0 : -1;
  }

  uint64_t now = now_ms();
  if (state->passive_cleanup_degraded) {
    if (now >= state->passive_cleanup_retry_at_ms) {
      return 0;
    }
    uint64_t retry_remaining = state->passive_cleanup_retry_at_ms - now;
    return retry_remaining > (uint64_t)INT_MAX
               ? INT_MAX
               : (int)retry_remaining;
  }

  uint64_t age = elapsed_ms(now, state->passive_last_scan_ms);
  if (age >= state->passive_scan_interval_ms) {
    return 0;
  }
  uint64_t remaining = state->passive_scan_interval_ms - age;
  return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

static int add_pending_client(struct qaffd_client *clients, int fd) {
  for (size_t i = 0; i < QAFFD_MAX_PENDING_CLIENTS; i++) {
    if (clients[i].fd >= 0) {
      continue;
    }
    init_client(&clients[i]);
    clients[i].fd = fd;
    uint64_t accepted_at = now_ms();
    clients[i].deadline_ms = accepted_at + QAFFD_CONTROL_DEADLINE_MS;
    return 0;
  }
  errno = EMFILE;
  return -1;
}

static void expire_pending_clients(struct qaffd_state *state,
                                   struct qaffd_client *clients) {
  uint64_t now = now_ms();
  for (size_t i = 0; i < QAFFD_MAX_PENDING_CLIENTS; i++) {
    if (clients[i].fd >= 0 && now >= clients[i].deadline_ms) {
      audit_event("control_client_timeout", NULL, "fd=%d", clients[i].fd);
      drop_client(state, &clients[i]);
    }
  }
}

static int pending_client_poll_timeout(const struct qaffd_client *clients) {
  uint64_t now = now_ms();
  uint64_t min_remaining = UINT64_MAX;
  for (size_t i = 0; i < QAFFD_MAX_PENDING_CLIENTS; i++) {
    if (clients[i].fd < 0) {
      continue;
    }
    if (now >= clients[i].deadline_ms) {
      return 0;
    }
    uint64_t remaining = clients[i].deadline_ms - now;
    if (remaining < min_remaining) {
      min_remaining = remaining;
    }
  }
  if (min_remaining == UINT64_MAX) {
    return -1;
  }
  return min_remaining > (uint64_t)INT_MAX ? INT_MAX : (int)min_remaining;
}

static int earlier_poll_timeout(int left, int right) {
  if (left < 0) {
    return right;
  }
  if (right < 0) {
    return left;
  }
  return left < right ? left : right;
}

int main(int argc, char **argv) {
  struct qaffd_options daemon_options;
  if (parse_args(argc, argv, &daemon_options) != 0) {
    usage(stderr);
    return 2;
  }

  signal(SIGPIPE, SIG_IGN);
  if (install_signal_handlers() != 0) {
    perror("sigaction");
    return 1;
  }

  struct qaffd_state state;
  memset(&state, 0, sizeof(state));
  state.instance_lock_fd = -1;
  state.pin_root = daemon_options.pin_root;
  state.state_path = daemon_options.state_path;
  state.short_cid_len = daemon_options.short_cid_len;
  state.cid_profile_enabled = daemon_options.cid_profile_enabled;
  state.passive_affinity_enabled = daemon_options.passive_affinity_enabled;
  state.passive_min_confidence = daemon_options.passive_min_confidence;
  state.fallback_mode = daemon_options.fallback_mode;
  memcpy(state.cid_profile_key,
         daemon_options.cid_profile_key,
         sizeof(state.cid_profile_key));
  state.fallback_worker_id = daemon_options.fallback_worker_id;
  state.worker_heartbeat_timeout_ms =
      daemon_options.worker_heartbeat_timeout_ms;
  state.worker_recovery_timeout_ms =
      daemon_options.worker_recovery_timeout_ms;
  state.passive_scan_interval_ms =
      daemon_options.passive_scan_interval_ms;
  state.allow_worker_uid_set = daemon_options.allow_worker_uid_set;
  state.allow_worker_gid_set = daemon_options.allow_worker_gid_set;
  state.allow_admin_uid_set = daemon_options.allow_admin_uid_set;
  state.allow_admin_gid_set = daemon_options.allow_admin_gid_set;
  state.allow_worker_uid = daemon_options.allow_worker_uid;
  state.allow_worker_gid = daemon_options.allow_worker_gid;
  state.allow_admin_uid = daemon_options.allow_admin_uid;
  state.allow_admin_gid = daemon_options.allow_admin_gid;
  state.socket_gid_set = daemon_options.socket_gid_set;
  state.socket_gid = daemon_options.socket_gid;
  state.socket_mode = daemon_options.socket_mode;
  state.worker_registry = (struct qaffd_worker_registry){
    .capacity = QAFFD_MAX_WORKERS,
    .worker_fds = state.worker_fds,
    .lease_fds = state.worker_lease_fds,
    .pidfds = state.worker_pidfds,
    .socket_cookies = state.worker_socket_cookies,
    .registered = state.worker_registered,
    .registered_at_ms = state.worker_registered_at_ms,
    .last_seen_ms = state.worker_last_seen_ms,
    .generations = state.worker_generations,
    .target_pids = state.worker_target_pids,
    .creds = state.worker_creds,
  };
  if (qaffd_worker_registry_init(&state.worker_registry) != 0) {
    perror("qaffd_worker_registry_init");
    return 1;
  }
  if (qaffd_cleanup_retry_init(&state.worker_cleanup_retry,
                               state.worker_cleanup_pending,
                               QAFFD_MAX_WORKERS,
                               QAFFD_WORKER_CLEANUP_RETRY_MS) != 0) {
    perror("qaffd_cleanup_retry_init");
    return 1;
  }
  for (uint32_t worker_id = 0;
       worker_id < QAFFD_MAX_WORKERS;
       worker_id++) {
    state.worker_pending_lease_fds[worker_id] = -1;
  }

  state.instance_lock_fd = acquire_instance_lock(daemon_options.socket_path);
  if (state.instance_lock_fd < 0) {
    perror("acquire_instance_lock");
    return 1;
  }

  struct qaff_options options;
  qaff_options_init(&options);
  options.pin_root = daemon_options.pin_root;
  options.short_cid_len = daemon_options.short_cid_len;
  options.cid_profile_enabled = daemon_options.cid_profile_enabled;
  options.passive_affinity_enabled = daemon_options.passive_affinity_enabled;
  options.passive_min_confidence = daemon_options.passive_min_confidence;
  options.fallback_mode = daemon_options.fallback_mode;
  memcpy(options.cid_profile_key,
         daemon_options.cid_profile_key,
         sizeof(options.cid_profile_key));
  options.fallback_worker_id = daemon_options.fallback_worker_id;

  if (qaff_open(&options, &state.ctx) != 0) {
    perror("qaff_open");
    close(state.instance_lock_fd);
    return 1;
  }

  if (qaff_bpf_object_open(state.ctx,
                           daemon_options.bpf_object_path,
                           &state.bpf) != 0) {
    perror("qaff_bpf_object_open");
    qaff_close(state.ctx);
    close(state.instance_lock_fd);
    return 1;
  }

  if (load_state(&state) != 0) {
    perror("load_state");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    qaffd_cid_index_destroy(&state.cid_index);
    close(state.instance_lock_fd);
    return 1;
  }
  if (validate_workers_against_generation_map(&state) != 0) {
    perror("validate_workers_against_generation_map");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    qaffd_cid_index_destroy(&state.cid_index);
    close(state.instance_lock_fd);
    return 1;
  }
  if (recover_cids_from_map(&state) != 0) {
    perror("recover_cids_from_map");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    qaffd_cid_index_destroy(&state.cid_index);
    close(state.instance_lock_fd);
    return 1;
  }
  if (reconcile_worker_tombstones(&state) != 0) {
    perror("reconcile_worker_tombstones");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    qaffd_cid_index_destroy(&state.cid_index);
    close(state.instance_lock_fd);
    return 1;
  }
  if (attach_egress_cgroup_if_configured(
          state.bpf,
          daemon_options.egress_cgroup_path) != 0) {
    perror("attach_egress_cgroup");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    qaffd_cid_index_destroy(&state.cid_index);
    close(state.instance_lock_fd);
    return 1;
  }
  state.egress_attached = daemon_options.egress_cgroup_path != NULL;

  int server_fd = make_server_socket(&state, daemon_options.socket_path);
  if (server_fd < 0) {
    perror("make_server_socket");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    qaffd_cid_index_destroy(&state.cid_index);
    close(state.instance_lock_fd);
    return 1;
  }
  if (quarantine_recovered_workers(&state) != 0) {
    perror("quarantine_recovered_workers");
    close(server_fd);
    unlink(daemon_options.socket_path);
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    qaffd_cid_index_destroy(&state.cid_index);
    close(state.instance_lock_fd);
    return 1;
  }

  struct qaffd_client clients[QAFFD_MAX_PENDING_CLIENTS];
  for (size_t i = 0; i < QAFFD_MAX_PENDING_CLIENTS; i++) {
    init_client(&clients[i]);
  }
  struct pollfd pollfds[QAFFD_MAX_POLLFDS];
  uint32_t poll_worker_ids[QAFFD_MAX_POLLFDS];
  enum qaffd_poll_source poll_sources[QAFFD_MAX_POLLFDS];

  while (!state.stop && !g_stop_requested) {
    retry_state_persistence_if_due(&state);
    if (retry_worker_cleanups_if_due(&state) != 0) {
      perror("retry_worker_cleanups");
    }
    if (expire_recovered_workers(&state) != 0) {
      perror("expire_recovered_workers");
    }
    if (expire_worker_heartbeat_timeouts(&state) != 0) {
      perror("expire_worker_heartbeat_timeouts");
    }
    if (expire_passive_cids_if_due(&state) != 0) {
      perror("expire_passive_cids");
    }
    expire_pending_clients(&state, clients);

    nfds_t pollfds_len = build_pollfds(&state,
                                       clients,
                                       server_fd,
                                       pollfds,
                                       poll_worker_ids,
                                       poll_sources,
                                       QAFFD_MAX_POLLFDS);
    int poll_timeout = earlier_poll_timeout(
        worker_recovery_poll_timeout(&state),
        worker_heartbeat_poll_timeout(&state));
    poll_timeout = earlier_poll_timeout(
        poll_timeout,
        passive_cleanup_poll_timeout(&state));
    poll_timeout = earlier_poll_timeout(
        poll_timeout,
        pending_client_poll_timeout(clients));
    poll_timeout = earlier_poll_timeout(
        poll_timeout,
        state_persistence_poll_timeout(&state));
    poll_timeout = earlier_poll_timeout(
        poll_timeout,
        worker_cleanup_poll_timeout(&state));
    int poll_rc;
    do {
      poll_rc = poll(pollfds, pollfds_len, poll_timeout);
    } while (poll_rc < 0 && errno == EINTR && !g_stop_requested);

    if (poll_rc == 0) {
      continue;
    }

    if (poll_rc < 0) {
      if (g_stop_requested) {
        break;
      }
      perror("poll");
      break;
    }

    if (pollfds[0].revents & POLLIN) {
      for (size_t accepted = 0;
           accepted < QAFFD_MAX_PENDING_CLIENTS;
           accepted++) {
        int client_fd = accept_client(server_fd);
        if (client_fd < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
          }
          if (g_stop_requested) {
            break;
          }
          perror("accept");
          break;
        }
        if (add_pending_client(clients, client_fd) != 0) {
          audit_event("control_client_rejected",
                      NULL,
                      "reason=capacity fd=%d",
                      client_fd);
          close(client_fd);
          break;
        }
      }
    }

    for (nfds_t i = 1; i < pollfds_len; i++) {
      if ((pollfds[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0) {
        continue;
      }

      uint32_t worker_id = poll_worker_ids[i];
      if (poll_sources[i] == QAFFD_POLL_CLIENT) {
        if (worker_id >= QAFFD_MAX_PENDING_CLIENTS ||
            clients[worker_id].fd != pollfds[i].fd) {
          continue;
        }
        int expected = clients[worker_id].stage == QAFFD_CLIENT_READING
                           ? POLLIN
                           : POLLOUT;
        if ((pollfds[i].revents & expected) != 0) {
          int rc = service_client(&state, &clients[worker_id]);
          if (rc > 0) {
            complete_client(&state, &clients[worker_id]);
          } else if (rc < 0) {
            drop_client(&state, &clients[worker_id]);
          }
        } else {
          drop_client(&state, &clients[worker_id]);
        }
        continue;
      }
      if (worker_id >= QAFFD_MAX_WORKERS) {
        continue;
      }

      if (poll_sources[i] == QAFFD_POLL_WORKER_LEASE &&
          state.worker_lease_fds[worker_id] == pollfds[i].fd &&
          (pollfds[i].revents & POLLIN)) {
        if (handle_worker_lease_event(&state, worker_id, pollfds[i].fd) != 0 &&
            errno != ENOENT) {
          perror("handle_worker_lease_event");
        }
      } else if (poll_sources[i] == QAFFD_POLL_WORKER_LEASE &&
                 state.worker_lease_fds[worker_id] == pollfds[i].fd &&
                 unregister_worker_liveness(&state,
                                            worker_id,
                                            "lease_closed") != 0 &&
                 errno != ENOENT) {
        perror("unregister_worker_lease");
      } else if (poll_sources[i] == QAFFD_POLL_WORKER_PIDFD &&
                 state.worker_pidfds[worker_id] == pollfds[i].fd &&
                 unregister_worker_liveness(&state,
                                            worker_id,
                                            "pidfd_exit") != 0 &&
                 errno != ENOENT) {
        perror("unregister_worker_pidfd");
      }
    }
  }

  close(server_fd);
  unlink(daemon_options.socket_path);
  for (size_t i = 0; i < QAFFD_MAX_PENDING_CLIENTS; i++) {
    if (clients[i].fd >= 0) {
      drop_client(&state, &clients[i]);
    }
  }
  for (size_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state.worker_fds[i] >= 0) {
      close(state.worker_fds[i]);
    }
    if (state.worker_lease_fds[i] >= 0) {
      close(state.worker_lease_fds[i]);
    }
    if (state.worker_pidfds[i] >= 0) {
      close(state.worker_pidfds[i]);
    }
  }
  qaffd_cid_index_destroy(&state.cid_index);
  qaff_bpf_object_close(state.bpf);
  qaff_close(state.ctx);
  close(state.instance_lock_fd);
  return 0;
}
