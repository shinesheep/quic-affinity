#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"
#include "control_protocol.h"
#include "authorization.h"
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

#define QAFFD_MAX_WORKERS 4096
#define QAFFD_MAX_PENDING_CLIENTS 128
#define QAFFD_MAX_POLLFDS \
  (QAFFD_MAX_WORKERS * 2 + QAFFD_MAX_PENDING_CLIENTS + 1)
#define QAFFD_CONTROL_DEADLINE_MS 1000u
#define QAFFD_PASSIVE_SCAN_INTERVAL_MS_DEFAULT 30000u

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

struct qaffd_cid_entry {
  struct qaff_cid_key key;
  uint32_t worker_id;
};

struct qaffd_options {
  const char *socket_path;
  const char *bpf_object_path;
  const char *egress_cgroup_path;
  const char *pin_root;
  const char *state_path;
  uint8_t short_cid_len;
  uint8_t cid_profile_v1_enabled;
  uint8_t cid_profile_v2_enabled;
  uint8_t cid_profile_v2_config_id;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t fallback_mode;
  uint8_t cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
  uint64_t worker_heartbeat_timeout_ms;
  uint64_t passive_scan_interval_ms;
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

struct qaffd_state {
  struct qaff_context *ctx;
  struct qaff_bpf_object *bpf;
  int instance_lock_fd;
  int worker_fds[QAFFD_MAX_WORKERS];
  int worker_lease_fds[QAFFD_MAX_WORKERS];
  int worker_pidfds[QAFFD_MAX_WORKERS];
  uint64_t worker_socket_cookies[QAFFD_MAX_WORKERS];
  int worker_registered[QAFFD_MAX_WORKERS];
  uint64_t worker_registered_at_ms[QAFFD_MAX_WORKERS];
  uint64_t worker_last_seen_ms[QAFFD_MAX_WORKERS];
  uint32_t worker_generations[QAFFD_MAX_WORKERS];
  uint32_t worker_target_pids[QAFFD_MAX_WORKERS];
  struct qaffd_peer_cred worker_creds[QAFFD_MAX_WORKERS];
  struct qaffd_worker_registry worker_registry;
  struct qaffd_cid_entry *cid_entries;
  size_t cid_entries_len;
  size_t cid_entries_cap;
  size_t *cid_index_slots;
  size_t cid_index_cap;
  size_t cid_index_used;
  size_t cid_index_tombstones;
  const char *pin_root;
  const char *state_path;
  uint8_t short_cid_len;
  uint8_t cid_profile_v1_enabled;
  uint8_t cid_profile_v2_enabled;
  uint8_t cid_profile_v2_config_id;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t fallback_mode;
  uint8_t cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
  uint64_t worker_heartbeat_timeout_ms;
  uint64_t passive_scan_interval_ms;
  uint64_t passive_last_scan_ms;
  uint64_t passive_expired_count;
  uint64_t passive_worker_purged_count;
  uint64_t passive_expiry_initialized_count;
  uint64_t passive_cleanup_error_count;
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

static uint32_t worker_count(const struct qaffd_state *state) {
  return qaffd_worker_registry_count(&state->worker_registry);
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
  if (bpf_map_update_elem(qaff_get_socket_worker_map_fd(state->ctx),
                          &cookie,
                          &worker_id,
                          BPF_ANY) != 0) {
    return -1;
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
  reply->config.cid_profile_v1_enabled = state->cid_profile_v1_enabled;
  reply->config.cid_profile_v2_enabled = state->cid_profile_v2_enabled;
  reply->config.cid_profile_v2_config_id = state->cid_profile_v2_config_id;
  reply->config.passive_affinity_enabled = state->passive_affinity_enabled;
  reply->config.passive_min_confidence = state->passive_min_confidence;
  reply->config.egress_attached = state->egress_attached ? 1 : 0;
  reply->config.fallback_mode = state->fallback_mode;
  reply->config.attached = state->attached ? 1 : 0;
  reply->config.worker_count = worker_count(state);
  reply->config.fallback_worker_id = state->fallback_worker_id;
  reply->config.passive_expired_count = state->passive_expired_count;
  reply->config.passive_worker_purged_count =
      state->passive_worker_purged_count;
  reply->config.passive_expiry_initialized_count =
      state->passive_expiry_initialized_count;
  reply->config.passive_cleanup_error_count =
      state->passive_cleanup_error_count;
  reply->config.passive_scan_interval_ms =
      state->passive_scan_interval_ms;
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
    if (!state->worker_registered[i]) {
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
    reply->worker_infos[written].registered_ms_ago =
        elapsed_ms(now, state->worker_registered_at_ms[i]);
    reply->worker_infos[written].last_seen_ms_ago =
        elapsed_ms(now, state->worker_last_seen_ms[i]);
    written++;
  }

  reply->workers_len = written;
}

static void usage(FILE *out) {
  fprintf(out,
          "Usage: qaffd --socket PATH --bpf PATH --short-cid-len N "
          "[--fallback-worker ID] [--fallback-mode fixed|kernel] "
          "[--pin-root PATH] [--state-path PATH] "
          "[--egress-cgroup PATH] "
          "[--cid-profile-v1-key HEX32 | --cid-profile-v1-key-file PATH] "
          "[--cid-profile-v2-key HEX32 | --cid-profile-v2-key-file PATH] "
          "[--cid-profile-v2-config-id ID] "
          "[--passive-affinity] [--passive-min-confidence N] "
          "[--passive-scan-interval-ms N] "
          "[--worker-heartbeat-timeout-ms N] [--allow-worker-uid UID] "
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
    } else if (strcmp(argv[i], "--cid-profile-v1-key") == 0 && i + 1 < argc) {
      if (parse_fixed_hex(argv[++i],
                          options->cid_profile_v1_key,
                          sizeof(options->cid_profile_v1_key)) != 0) {
        return -1;
      }
      options->cid_profile_v1_enabled = 1;
    } else if (strcmp(argv[i], "--cid-profile-v1-key-file") == 0 &&
               i + 1 < argc) {
      if (read_profile_key_file(argv[++i],
                                options->cid_profile_v1_key,
                                sizeof(options->cid_profile_v1_key)) != 0) {
        return -1;
      }
      options->cid_profile_v1_enabled = 1;
    } else if (strcmp(argv[i], "--cid-profile-v2-key") == 0 && i + 1 < argc) {
      if (parse_fixed_hex(argv[++i],
                          options->cid_profile_v1_key,
                          sizeof(options->cid_profile_v1_key)) != 0) {
        return -1;
      }
      options->cid_profile_v2_enabled = 1;
    } else if (strcmp(argv[i], "--cid-profile-v2-key-file") == 0 &&
               i + 1 < argc) {
      if (read_profile_key_file(argv[++i],
                                options->cid_profile_v1_key,
                                sizeof(options->cid_profile_v1_key)) != 0) {
        return -1;
      }
      options->cid_profile_v2_enabled = 1;
    } else if (strcmp(argv[i], "--cid-profile-v2-config-id") == 0 &&
               i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT8_MAX) {
        return -1;
      }
      options->cid_profile_v2_config_id = (uint8_t)value;
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
  if (options->state_path != NULL && options->pin_root == NULL) {
    return -1;
  }
  if (options->cid_profile_v2_enabled &&
      options->short_cid_len != QAFF_CID_PROFILE_V2_LEN) {
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

static int cid_key_equal(const struct qaff_cid_key *a,
                         const struct qaff_cid_key *b) {
  return a->len == b->len &&
         memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

#define QAFFD_CID_INDEX_EMPTY 0u
#define QAFFD_CID_INDEX_TOMBSTONE SIZE_MAX

static uint64_t cid_key_hash(const struct qaff_cid_key *key) {
  uint64_t hash = 1469598103934665603ULL;
  hash ^= key->len;
  hash *= 1099511628211ULL;
  for (size_t i = 0; i < sizeof(key->bytes); i++) {
    hash ^= key->bytes[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static size_t cid_index_slot_for(const struct qaffd_state *state,
                                 const struct qaff_cid_key *key,
                                 int *found) {
  size_t mask = state->cid_index_cap - 1;
  size_t slot = (size_t)cid_key_hash(key) & mask;
  size_t first_tombstone = SIZE_MAX;

  for (size_t probed = 0; probed < state->cid_index_cap; probed++) {
    size_t value = state->cid_index_slots[slot];
    if (value == QAFFD_CID_INDEX_EMPTY) {
      *found = 0;
      return first_tombstone != SIZE_MAX ? first_tombstone : slot;
    }
    if (value == QAFFD_CID_INDEX_TOMBSTONE) {
      if (first_tombstone == SIZE_MAX) {
        first_tombstone = slot;
      }
    } else {
      size_t index = value - 1;
      if (index < state->cid_entries_len &&
          cid_key_equal(&state->cid_entries[index].key, key)) {
        *found = 1;
        return slot;
      }
    }
    slot = (slot + 1) & mask;
  }

  *found = 0;
  return first_tombstone;
}

static int cid_index_rehash(struct qaffd_state *state, size_t new_cap) {
  size_t *old_slots = state->cid_index_slots;
  size_t old_cap = state->cid_index_cap;
  size_t old_used = state->cid_index_used;
  size_t old_tombstones = state->cid_index_tombstones;

  size_t *new_slots = calloc(new_cap, sizeof(*new_slots));
  if (new_slots == NULL) {
    return -1;
  }

  state->cid_index_slots = new_slots;
  state->cid_index_cap = new_cap;
  state->cid_index_used = 0;
  state->cid_index_tombstones = 0;

  for (size_t i = 0; i < state->cid_entries_len; i++) {
    int found = 0;
    size_t slot = cid_index_slot_for(state, &state->cid_entries[i].key, &found);
    if (found || slot == SIZE_MAX) {
      free(new_slots);
      state->cid_index_slots = old_slots;
      state->cid_index_cap = old_cap;
      state->cid_index_used = old_used;
      state->cid_index_tombstones = old_tombstones;
      errno = EINVAL;
      return -1;
    }
    state->cid_index_slots[slot] = i + 1;
    state->cid_index_used++;
  }

  free(old_slots);
  return 0;
}

static int cid_index_prepare_insert(struct qaffd_state *state) {
  if (state->cid_index_cap == 0) {
    return cid_index_rehash(state, 16);
  }

  size_t occupied = state->cid_index_used + state->cid_index_tombstones;
  size_t threshold = state->cid_index_cap / 2 + state->cid_index_cap / 4;
  if (occupied + 1 < threshold) {
    return 0;
  }

  size_t next_cap = state->cid_index_cap;
  if (state->cid_index_tombstones <= state->cid_index_used) {
    if (next_cap > SIZE_MAX / 2) {
      errno = ENOMEM;
      return -1;
    }
    next_cap *= 2;
  }
  return cid_index_rehash(state, next_cap);
}

static ssize_t find_cid_entry(const struct qaffd_state *state,
                              const struct qaff_cid_key *key) {
  if (state->cid_index_cap == 0) {
    return -1;
  }
  int found = 0;
  size_t slot = cid_index_slot_for(state, key, &found);
  if (!found || slot == SIZE_MAX) {
    return -1;
  }
  return (ssize_t)(state->cid_index_slots[slot] - 1);
}

static int remember_cid(struct qaffd_state *state,
                        const struct qaff_cid_key *key,
                        uint32_t worker_id) {
  ssize_t index = find_cid_entry(state, key);
  if (index >= 0) {
    state->cid_entries[index].worker_id = worker_id;
    return 0;
  }

  if (cid_index_prepare_insert(state) != 0) {
    return -1;
  }

  if (state->cid_entries_len == state->cid_entries_cap) {
    const size_t max_cap = SIZE_MAX / sizeof(*state->cid_entries);
    if (state->cid_entries_cap > max_cap / 2) {
      errno = ENOMEM;
      return -1;
    }
    size_t next_cap = state->cid_entries_cap == 0
                        ? 1024
                        : state->cid_entries_cap * 2;
    struct qaffd_cid_entry *next =
        realloc(state->cid_entries, next_cap * sizeof(*next));
    if (next == NULL) {
      return -1;
    }
    state->cid_entries = next;
    state->cid_entries_cap = next_cap;
  }

  size_t new_index = state->cid_entries_len;
  state->cid_entries[new_index].key = *key;
  state->cid_entries[new_index].worker_id = worker_id;
  state->cid_entries_len++;

  int found = 0;
  size_t slot = cid_index_slot_for(state, key, &found);
  if (found || slot == SIZE_MAX) {
    state->cid_entries_len--;
    errno = EINVAL;
    return -1;
  }
  if (state->cid_index_slots[slot] == QAFFD_CID_INDEX_TOMBSTONE) {
    state->cid_index_tombstones--;
  }
  state->cid_index_slots[slot] = new_index + 1;
  state->cid_index_used++;
  return 0;
}

static int forget_cid_at(struct qaffd_state *state, size_t index) {
  if (index >= state->cid_entries_len || state->cid_index_cap == 0) {
    errno = EINVAL;
    return -1;
  }

  int found = 0;
  size_t removed_slot =
      cid_index_slot_for(state, &state->cid_entries[index].key, &found);
  if (!found || removed_slot == SIZE_MAX) {
    errno = EIO;
    return -1;
  }

  size_t last = state->cid_entries_len - 1;
  size_t moved_slot = SIZE_MAX;
  if (index != last) {
    int moved_found = 0;
    moved_slot =
        cid_index_slot_for(state, &state->cid_entries[last].key, &moved_found);
    if (!moved_found || moved_slot == SIZE_MAX) {
      errno = EIO;
      return -1;
    }
  }

  state->cid_index_slots[removed_slot] = QAFFD_CID_INDEX_TOMBSTONE;
  state->cid_index_used--;
  state->cid_index_tombstones++;
  if (index != last) {
    state->cid_entries[index] = state->cid_entries[last];
    state->cid_index_slots[moved_slot] = index + 1;
  }
  state->cid_entries_len--;
  return 0;
}

static int forget_cid(struct qaffd_state *state,
                      const struct qaff_cid_key *key) {
  ssize_t index = find_cid_entry(state, key);
  if (index < 0) {
    errno = ENOENT;
    return -1;
  }
  return forget_cid_at(state, (size_t)index);
}

static int read_cid_consistency(const struct qaffd_state *state,
                                struct qaffd_cid_consistency *out) {
  memset(out, 0, sizeof(*out));
  out->owner_count = state->cid_entries_len;

  int map_fd = qaff_get_cid_map_fd(state->ctx);
  if (map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_cid_key key;
  struct qaff_cid_key next_key;
  struct qaff_cid_key *previous = NULL;

  while (bpf_map_get_next_key(map_fd, previous, &next_key) == 0) {
    uint32_t worker_id = 0;
    out->map_count++;
    if (bpf_map_lookup_elem(map_fd, &next_key, &worker_id) != 0) {
      out->mismatch_count++;
      key = next_key;
      previous = &key;
      continue;
    }

    ssize_t index = find_cid_entry(state, &next_key);
    if (index < 0 ||
        state->cid_entries[index].worker_id != worker_id) {
      out->mismatch_count++;
    }

    key = next_key;
    previous = &key;
  }

  if (errno != ENOENT) {
    return -1;
  }

  for (size_t i = 0; i < state->cid_entries_len; i++) {
    uint32_t worker_id = 0;
    if (bpf_map_lookup_elem(map_fd,
                            &state->cid_entries[i].key,
                            &worker_id) != 0 ||
        worker_id != state->cid_entries[i].worker_id) {
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
  size_t i = 0;
  while (i < state->cid_entries_len) {
    struct qaffd_cid_entry *entry = &state->cid_entries[i];
    if (entry->worker_id != worker_id) {
      i++;
      continue;
    }

    if (qaff_retire_cid(state->ctx,
                        entry->key.bytes,
                        entry->key.len) != 0 &&
        errno != ENOENT) {
      return -1;
    }
    if (forget_cid_at(state, i) != 0) {
      return -1;
    }
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
      int should_delete = purge_worker && value.worker_id == worker_id;
      if (!purge_worker && value.expires_at_ns != 0 &&
          value.expires_at_ns <= monotonic_now_ns) {
        should_delete = 1;
      }

      if (should_delete) {
        if (bpf_map_delete_elem(map_fd, &current) != 0 && errno != ENOENT) {
          return -1;
        }
        if (purge_worker) {
          state->passive_worker_purged_count++;
        } else {
          state->passive_expired_count++;
        }
      } else if (!purge_worker && value.expires_at_ns == 0) {
        value.expires_at_ns =
            monotonic_now_ns + passive_default_ttl_ns(&value);
        if (bpf_map_update_elem(map_fd, &current, &value, BPF_EXIST) != 0 &&
            errno != ENOENT) {
          return -1;
        }
        state->passive_expiry_initialized_count++;
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

static int save_state(const struct qaffd_state *state) {
  return qaffd_state_store_save(state->state_path,
                                state->worker_registered,
                                state->worker_generations,
                                QAFFD_MAX_WORKERS);
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

static int recover_workers_from_generation_map(struct qaffd_state *state) {
  int map_fd = qaff_get_worker_generation_map_fd(state->ctx);
  if (map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  uint64_t recovered_at = now_ms();
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
    state->worker_registered[worker_id] = 1;
    state->worker_generations[worker_id] = generation;
    if (state->worker_registered_at_ms[worker_id] == 0) {
      state->worker_registered_at_ms[worker_id] = recovered_at;
      state->worker_last_seen_ms[worker_id] = recovered_at;
    }
  }
  return 0;
}

static int recover_cids_from_map(struct qaffd_state *state) {
  int map_fd = qaff_get_cid_map_fd(state->ctx);
  if (map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_cid_key key;
  struct qaff_cid_key next_key;
  struct qaff_cid_key *previous = NULL;

  while (bpf_map_get_next_key(map_fd, previous, &next_key) == 0) {
    uint32_t worker_id = 0;
    if (bpf_map_lookup_elem(map_fd, &next_key, &worker_id) != 0) {
      key = next_key;
      previous = &key;
      continue;
    }
    if (worker_id >= QAFFD_MAX_WORKERS) {
      errno = EINVAL;
      return -1;
    }
    if (remember_cid(state, &next_key, worker_id) != 0) {
      return -1;
    }
    state->worker_registered[worker_id] = 1;
    if (state->worker_generations[worker_id] == 0) {
      state->worker_generations[worker_id] = QAFF_WORKER_GENERATION_DEFAULT;
    }
    if (state->worker_registered_at_ms[worker_id] == 0) {
      uint64_t recovered_at = now_ms();
      state->worker_registered_at_ms[worker_id] = recovered_at;
      state->worker_last_seen_ms[worker_id] = recovered_at;
    }

    key = next_key;
    previous = &key;
  }

  if (errno != ENOENT) {
    return -1;
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

static int rollback_worker_maps(
    struct qaffd_state *state,
    uint32_t worker_id,
    const struct qaffd_worker_snapshot *snapshot,
    uint64_t new_socket_cookie,
    int same_socket) {
  if (new_socket_cookie != 0 &&
      new_socket_cookie != snapshot->worker.socket_cookie) {
    unregister_socket_cookie(state, new_socket_cookie);
  }

  if (!snapshot->worker.registered) {
    if (qaff_unregister_worker_socket(state->ctx, worker_id) != 0 &&
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
  if (same_socket) {
    return 0;
  }

  if (qaff_unregister_worker_socket(state->ctx, worker_id) != 0 &&
      errno != ENOENT) {
    return -1;
  }
  errno = ESTALE;
  return -1;
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
  int recovered_worker =
      state->worker_registered[request->worker_id] &&
      state->worker_fds[request->worker_id] < 0 &&
      !state->worker_creds[request->worker_id].valid;
  if (state->worker_registered[request->worker_id] && !recovered_worker &&
      authorize_worker_mutation(state, request->worker_id, peer) != 0) {
    return -1;
  }

  struct sockaddr_storage local_addr;
  if (validate_worker_socket(state, socket_fd, &local_addr) != 0) {
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

  int same_socket =
      is_same_registered_socket(state, request->worker_id, socket_fd);
  if (same_socket < 0) {
    return -1;
  }
  uint32_t generation = state->worker_generations[request->worker_id];
  if (!same_socket &&
      next_worker_generation(state->worker_generations[request->worker_id],
                             &generation) != 0) {
    return -1;
  }
  struct qaffd_worker_snapshot snapshot;
  snapshot_worker(state, request->worker_id, &snapshot);
  if (qaff_register_worker_socket_generation(state->ctx,
                                             request->worker_id,
                                             socket_fd,
                                             generation) != 0) {
    return -1;
  }

  uint64_t socket_cookie = 0;
  if (register_socket_cookie(state,
                             request->worker_id,
                             socket_fd,
                             &socket_cookie) != 0) {
    int saved_errno = errno ? errno : EIO;
    if (rollback_worker_maps(state,
                             request->worker_id,
                             &snapshot,
                             0,
                             same_socket) != 0) {
      audit_event("worker_registration_rollback_failed",
                  peer,
                  "worker_id=%u stage=socket_cookie errno=%d",
                  request->worker_id,
                  errno);
    }
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
    if (rollback_worker_maps(state,
                             request->worker_id,
                             &snapshot,
                             socket_cookie,
                             same_socket) != 0) {
      audit_event("worker_registration_rollback_failed",
                  peer,
                  "worker_id=%u stage=state_persist errno=%d",
                  request->worker_id,
                  errno);
    }
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
  return 0;
}

static int unregister_worker_authorized(struct qaffd_state *state,
                                        uint32_t worker_id,
                                        const struct qaffd_peer_cred *peer) {
  if (retire_worker_cids(state, worker_id) != 0) {
    return -1;
  }
  if (cleanup_passive_cids(state, now_ns(), 1, worker_id) != 0) {
    state->passive_cleanup_error_count++;
    return -1;
  }

  if (qaff_unregister_worker_socket(state->ctx, worker_id) != 0 &&
      errno != ENOENT) {
    return -1;
  }

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
  if (save_state(state) != 0) {
    return -1;
  }
  audit_event("worker_unregistered",
              peer,
              "worker_id=%u",
              worker_id);
  return 0;
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

  if (qaff_register_cid(state->ctx,
                        request->cid,
                        request->cid_len,
                        request->worker_id) != 0) {
    return -1;
  }

  if (remember_cid(state, &key, request->worker_id) != 0) {
    int saved_errno = errno ? errno : ENOMEM;
    qaff_retire_cid(state->ctx, request->cid, request->cid_len);
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

  ssize_t index = find_cid_entry(state, &key);
  if (index < 0) {
    errno = ENOENT;
    return -1;
  }
  if (authorize_worker_mutation(state,
                                state->cid_entries[index].worker_id,
                                peer) != 0) {
    return -1;
  }
  uint32_t owner_worker_id = state->cid_entries[index].worker_id;

  if (qaff_retire_cid(state->ctx, request->cid, request->cid_len) != 0) {
    return -1;
  }

  if (forget_cid(state, &key) != 0) {
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

static int unregister_worker_id(struct qaffd_state *state, uint32_t worker_id) {
  if (worker_id >= QAFFD_MAX_WORKERS ||
      !state->worker_registered[worker_id]) {
    errno = ENOENT;
    return -1;
  }
  return unregister_worker_authorized(state, worker_id, NULL);
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
    return unregister_worker_id(state, worker_id);
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
    return unregister_worker_id(state, worker_id);
  }
  ssize_t written;
  do {
    written = send(lease_fd, reply_packet, reply_len, MSG_NOSIGNAL);
  } while (written < 0 && errno == EINTR);
  if (written < 0 || (size_t)written != reply_len) {
    return unregister_worker_id(state, worker_id);
  }
  if (reply.status != 0) {
    int saved_errno = reply.status;
    unregister_worker_id(state, worker_id);
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
    if (unregister_worker_id(state,
                             (uint32_t)client->lease_worker_id) != 0 &&
        errno != ENOENT) {
      perror("rollback_worker_lease");
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
    install_worker_lease(state,
                         (uint32_t)client->lease_worker_id,
                         client->fd);
    client->fd = -1;
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
    if (state->worker_lease_fds[i] >= 0) {
      fds[count].fd = state->worker_lease_fds[i];
      fds[count].events = POLLIN;
      fds[count].revents = 0;
      worker_ids[count] = i;
      sources[count] = QAFFD_POLL_WORKER_LEASE;
      count++;
    }
    if (state->worker_pidfds[i] >= 0 && count < cap) {
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
    if (state->worker_lease_fds[i] < 0 || !state->worker_registered[i]) {
      continue;
    }
    if (elapsed_ms(now, state->worker_last_seen_ms[i]) <
        state->worker_heartbeat_timeout_ms) {
      continue;
    }
    if (unregister_worker_id(state, i) != 0 && errno != ENOENT) {
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
  if (state->passive_last_scan_ms != 0 &&
      elapsed_ms(monotonic_now_ms, state->passive_last_scan_ms) <
          state->passive_scan_interval_ms) {
    return 0;
  }

  state->passive_last_scan_ms = monotonic_now_ms;
  if (cleanup_passive_cids(state, now_ns(), 0, 0) != 0) {
    state->passive_cleanup_error_count++;
    return -1;
  }
  return 0;
}

static int worker_heartbeat_poll_timeout(const struct qaffd_state *state) {
  if (state->worker_heartbeat_timeout_ms == 0) {
    return -1;
  }

  uint64_t now = now_ms();
  uint64_t min_remaining = UINT64_MAX;
  for (uint32_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state->worker_lease_fds[i] < 0 || !state->worker_registered[i]) {
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

static int passive_cleanup_poll_timeout(const struct qaffd_state *state) {
  if (!state->passive_affinity_enabled ||
      state->passive_scan_interval_ms == 0 ||
      state->passive_last_scan_ms == 0) {
    return state->passive_affinity_enabled ? 0 : -1;
  }

  uint64_t age = elapsed_ms(now_ms(), state->passive_last_scan_ms);
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
  state.cid_profile_v1_enabled = daemon_options.cid_profile_v1_enabled;
  state.cid_profile_v2_enabled = daemon_options.cid_profile_v2_enabled;
  state.cid_profile_v2_config_id = daemon_options.cid_profile_v2_config_id;
  state.passive_affinity_enabled = daemon_options.passive_affinity_enabled;
  state.passive_min_confidence = daemon_options.passive_min_confidence;
  state.fallback_mode = daemon_options.fallback_mode;
  memcpy(state.cid_profile_v1_key,
         daemon_options.cid_profile_v1_key,
         sizeof(state.cid_profile_v1_key));
  state.fallback_worker_id = daemon_options.fallback_worker_id;
  state.worker_heartbeat_timeout_ms =
      daemon_options.worker_heartbeat_timeout_ms;
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

  state.instance_lock_fd = acquire_instance_lock(daemon_options.socket_path);
  if (state.instance_lock_fd < 0) {
    perror("acquire_instance_lock");
    return 1;
  }

  struct qaff_options options;
  qaff_options_init(&options);
  options.pin_root = daemon_options.pin_root;
  options.short_cid_len = daemon_options.short_cid_len;
  options.cid_profile_v1_enabled = daemon_options.cid_profile_v1_enabled;
  options.cid_profile_v2_enabled = daemon_options.cid_profile_v2_enabled;
  options.cid_profile_v2_config_id = daemon_options.cid_profile_v2_config_id;
  options.passive_affinity_enabled = daemon_options.passive_affinity_enabled;
  options.passive_min_confidence = daemon_options.passive_min_confidence;
  options.fallback_mode = daemon_options.fallback_mode;
  memcpy(options.cid_profile_v1_key,
         daemon_options.cid_profile_v1_key,
         sizeof(options.cid_profile_v1_key));
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

  if (attach_egress_cgroup_if_configured(
          state.bpf,
          daemon_options.egress_cgroup_path) != 0) {
    perror("attach_egress_cgroup");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    close(state.instance_lock_fd);
    return 1;
  }
  state.egress_attached = daemon_options.egress_cgroup_path != NULL;

  if (load_state(&state) != 0) {
    perror("load_state");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    free(state.cid_entries);
    free(state.cid_index_slots);
    close(state.instance_lock_fd);
    return 1;
  }
  if (recover_workers_from_generation_map(&state) != 0) {
    perror("recover_workers_from_generation_map");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    free(state.cid_entries);
    free(state.cid_index_slots);
    close(state.instance_lock_fd);
    return 1;
  }
  if (recover_cids_from_map(&state) != 0) {
    perror("recover_cids_from_map");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    free(state.cid_entries);
    free(state.cid_index_slots);
    close(state.instance_lock_fd);
    return 1;
  }

  int server_fd = make_server_socket(&state, daemon_options.socket_path);
  if (server_fd < 0) {
    perror("make_server_socket");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    free(state.cid_entries);
    free(state.cid_index_slots);
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
        worker_heartbeat_poll_timeout(&state),
        passive_cleanup_poll_timeout(&state));
    poll_timeout = earlier_poll_timeout(
        poll_timeout,
        pending_client_poll_timeout(clients));
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
                 unregister_worker_id(&state, worker_id) != 0 &&
                 errno != ENOENT) {
        perror("unregister_worker_lease");
      } else if (poll_sources[i] == QAFFD_POLL_WORKER_PIDFD &&
                 state.worker_pidfds[worker_id] == pollfds[i].fd &&
                 unregister_worker_id(&state, worker_id) != 0 &&
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
  free(state.cid_entries);
  free(state.cid_index_slots);
  qaff_bpf_object_close(state.bpf);
  qaff_close(state.ctx);
  close(state.instance_lock_fd);
  return 0;
}
