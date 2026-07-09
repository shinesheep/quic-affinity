#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"

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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>

#define QAFFD_MAX_WORKERS 4096

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
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
};

struct qaffd_cid_entry {
  struct qaff_cid_key key;
  uint32_t worker_id;
};

struct qaffd_options {
  const char *socket_path;
  const char *bpf_object_path;
  const char *pin_root;
  const char *state_path;
  uint8_t short_cid_len;
  uint8_t cid_profile_v1_enabled;
  uint8_t cid_profile_v2_enabled;
  uint8_t cid_profile_v2_config_id;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
  uint64_t worker_heartbeat_timeout_ms;
  int allow_worker_uid_set;
  int allow_worker_gid_set;
  int socket_gid_set;
  uint32_t allow_worker_uid;
  uint32_t allow_worker_gid;
  uint32_t socket_gid;
  mode_t socket_mode;
};

struct qaffd_peer_cred {
  int valid;
  uint32_t pid;
  uint32_t uid;
  uint32_t gid;
};

struct qaffd_state {
  struct qaff_context *ctx;
  struct qaff_bpf_object *bpf;
  int worker_fds[QAFFD_MAX_WORKERS];
  int worker_lease_fds[QAFFD_MAX_WORKERS];
  int worker_pidfds[QAFFD_MAX_WORKERS];
  int worker_registered[QAFFD_MAX_WORKERS];
  uint64_t worker_registered_at_ms[QAFFD_MAX_WORKERS];
  uint64_t worker_last_seen_ms[QAFFD_MAX_WORKERS];
  uint32_t worker_generations[QAFFD_MAX_WORKERS];
  struct qaffd_peer_cred worker_creds[QAFFD_MAX_WORKERS];
  struct qaffd_cid_entry *cid_entries;
  size_t cid_entries_len;
  size_t cid_entries_cap;
  const char *pin_root;
  const char *state_path;
  uint8_t short_cid_len;
  uint8_t cid_profile_v1_enabled;
  uint8_t cid_profile_v2_enabled;
  uint8_t cid_profile_v2_config_id;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
  uint64_t worker_heartbeat_timeout_ms;
  int allow_worker_uid_set;
  int allow_worker_gid_set;
  int socket_gid_set;
  uint32_t allow_worker_uid;
  uint32_t allow_worker_gid;
  uint32_t socket_gid;
  mode_t socket_mode;
  int attached;
  int stop;
  int listener_locked;
  struct sockaddr_storage listener_addr;
};

struct qaffd_cid_consistency {
  uint64_t map_count;
  uint64_t owner_count;
  uint64_t mismatch_count;
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

static uint64_t elapsed_ms(uint64_t now, uint64_t then) {
  if (then == 0 || now < then) {
    return 0;
  }
  return now - then;
}

static int get_peer_cred(int fd, struct qaffd_peer_cred *out) {
  memset(out, 0, sizeof(*out));
#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    return -1;
  }
  if (cred.pid < 0 || cred.uid > UINT32_MAX || cred.gid > UINT32_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  out->valid = 1;
  out->pid = (uint32_t)cred.pid;
  out->uid = (uint32_t)cred.uid;
  out->gid = (uint32_t)cred.gid;
#else
  (void)fd;
#endif
  return 0;
}

static int validate_worker_peer(const struct qaffd_state *state,
                                const struct qaffd_peer_cred *peer) {
  if (!state->allow_worker_uid_set && !state->allow_worker_gid_set) {
    return 0;
  }
  if (peer == NULL || !peer->valid) {
    errno = EACCES;
    return -1;
  }
  if (state->allow_worker_uid_set && peer->uid != state->allow_worker_uid) {
    errno = EACCES;
    return -1;
  }
  if (state->allow_worker_gid_set && peer->gid != state->allow_worker_gid) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

static int peer_matches_configured_admin(const struct qaffd_state *state,
                                         const struct qaffd_peer_cred *peer) {
  if (!state->allow_worker_uid_set && !state->allow_worker_gid_set) {
    return 0;
  }
  return validate_worker_peer(state, peer) == 0;
}

static int peer_matches_worker(const struct qaffd_state *state,
                               uint32_t worker_id,
                               const struct qaffd_peer_cred *peer) {
  if (worker_id >= QAFFD_MAX_WORKERS || peer == NULL || !peer->valid) {
    return 0;
  }

  const struct qaffd_peer_cred *worker = &state->worker_creds[worker_id];
  return worker->valid &&
         worker->pid == peer->pid &&
         worker->uid == peer->uid &&
         worker->gid == peer->gid;
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
  if (!state->allow_worker_uid_set && !state->allow_worker_gid_set) {
    return 0;
  }
  if (peer_matches_configured_admin(state, peer)) {
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
  uint32_t count = 0;
  for (size_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state->worker_registered[i]) {
      count++;
    }
  }
  return count;
}

static uint32_t next_worker_generation(uint32_t previous) {
  if (previous == 0 || previous >= QAFF_WORKER_GENERATION_MAX) {
    return QAFF_WORKER_GENERATION_DEFAULT;
  }
  return previous + 1;
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

static int read_cid_consistency(const struct qaffd_state *state,
                                struct qaffd_cid_consistency *out);

static void fill_config_reply(const struct qaffd_state *state,
                              struct qaff_control_msg *reply) {
  reply->config.short_cid_len = state->short_cid_len;
  reply->config.cid_profile_v1_enabled = state->cid_profile_v1_enabled;
  reply->config.cid_profile_v2_enabled = state->cid_profile_v2_enabled;
  reply->config.cid_profile_v2_config_id = state->cid_profile_v2_config_id;
  reply->config.passive_affinity_enabled = state->passive_affinity_enabled;
  reply->config.passive_min_confidence = state->passive_min_confidence;
  reply->config.attached = state->attached ? 1 : 0;
  reply->config.worker_count = worker_count(state);
  reply->config.fallback_worker_id = state->fallback_worker_id;
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
}

static void fill_workers_reply(const struct qaffd_state *state,
                               struct qaff_control_msg *reply) {
  uint32_t total = 0;
  uint32_t written = 0;
  uint64_t now = now_ms();

  for (uint32_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (!state->worker_registered[i]) {
      continue;
    }
    if (written < QAFF_CONTROL_MAX_WORKERS) {
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
      if (state->worker_pidfds[i] >= 0) {
        reply->worker_infos[written].flags |= QAFF_CONTROL_WORKER_FLAG_PIDFD;
      }
      reply->worker_infos[written].registered_ms_ago =
          elapsed_ms(now, state->worker_registered_at_ms[i]);
      reply->worker_infos[written].last_seen_ms_ago =
          elapsed_ms(now, state->worker_last_seen_ms[i]);
      written++;
    }
    total++;
  }

  reply->workers_len = written;
  reply->config.worker_count = total;
}

static void usage(FILE *out) {
  fprintf(out,
          "Usage: qaffd --socket PATH --bpf PATH --short-cid-len N "
          "[--fallback-worker ID] [--pin-root PATH] [--state-path PATH] "
          "[--cid-profile-v1-key HEX32 | --cid-profile-v1-key-file PATH] "
          "[--cid-profile-v2-key HEX32 | --cid-profile-v2-key-file PATH] "
          "[--cid-profile-v2-config-id ID] "
          "[--passive-affinity] [--passive-min-confidence N] "
          "[--worker-heartbeat-timeout-ms N] [--allow-worker-uid UID] "
          "[--allow-worker-gid GID] [--socket-mode OCTAL] "
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

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
      options->socket_path = argv[++i];
    } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
      options->bpf_object_path = argv[++i];
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

  return 0;
}

static int read_exact(int fd, void *buf, size_t len) {
  char *p = buf;
  while (len > 0) {
    ssize_t got = read(fd, p, len);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (got == 0) {
      errno = ECONNRESET;
      return -1;
    }
    p += got;
    len -= (size_t)got;
  }
  return 0;
}

static int write_exact(int fd, const void *buf, size_t len) {
  const char *p = buf;
  while (len > 0) {
    ssize_t written = write(fd, p, len);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    p += written;
    len -= (size_t)written;
  }
  return 0;
}

static int recv_request(int fd, struct qaff_control_msg *msg, int *received_fd) {
  *received_fd = -1;

  struct iovec iov;
  iov.iov_base = msg;
  iov.iov_len = sizeof(*msg);

  char control[CMSG_SPACE(sizeof(int))];
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
  if ((size_t)got != sizeof(*msg)) {
    if (read_exact(fd, (char *)msg + got, sizeof(*msg) - (size_t)got) != 0) {
      return -1;
    }
  }

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS &&
        cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
      memcpy(received_fd, CMSG_DATA(cmsg), sizeof(int));
      break;
    }
  }

  return 0;
}

static void reply_init(struct qaff_control_msg *reply,
                       const struct qaff_control_msg *request) {
  memset(reply, 0, sizeof(*reply));
  reply->magic = QAFF_CONTROL_MAGIC;
  reply->version = QAFF_CONTROL_VERSION;
  reply->op = request->op;
}

static int cid_key_equal(const struct qaff_cid_key *a,
                         const struct qaff_cid_key *b) {
  return a->len == b->len &&
         memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

static ssize_t find_cid_entry(const struct qaffd_state *state,
                              const struct qaff_cid_key *key) {
  for (size_t i = 0; i < state->cid_entries_len; i++) {
    if (cid_key_equal(&state->cid_entries[i].key, key)) {
      return (ssize_t)i;
    }
  }
  return -1;
}

static int remember_cid(struct qaffd_state *state,
                        const struct qaff_cid_key *key,
                        uint32_t worker_id) {
  ssize_t index = find_cid_entry(state, key);
  if (index >= 0) {
    state->cid_entries[index].worker_id = worker_id;
    return 0;
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

  state->cid_entries[state->cid_entries_len].key = *key;
  state->cid_entries[state->cid_entries_len].worker_id = worker_id;
  state->cid_entries_len++;
  return 0;
}

static void forget_cid_at(struct qaffd_state *state, size_t index) {
  if (index + 1 < state->cid_entries_len) {
    state->cid_entries[index] = state->cid_entries[state->cid_entries_len - 1];
  }
  state->cid_entries_len--;
}

static void forget_cid(struct qaffd_state *state,
                       const struct qaff_cid_key *key) {
  ssize_t index = find_cid_entry(state, key);
  if (index >= 0) {
    forget_cid_at(state, (size_t)index);
  }
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
    forget_cid_at(state, i);
  }

  return 0;
}

static int hex_value(int c) {
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

static int parse_cid_hex(const char *hex,
                         uint32_t len,
                         struct qaff_cid_key *out) {
  if (len > QAFF_MAX_CID_LEN || strlen(hex) != (size_t)len * 2) {
    errno = EINVAL;
    return -1;
  }

  memset(out, 0, sizeof(*out));
  out->len = (uint8_t)len;
  for (uint32_t i = 0; i < len; i++) {
    int high = hex_value((unsigned char)hex[i * 2]);
    int low = hex_value((unsigned char)hex[i * 2 + 1]);
    if (high < 0 || low < 0) {
      errno = EINVAL;
      return -1;
    }
    out->bytes[i] = (uint8_t)((high << 4) | low);
  }
  return 0;
}

static int save_state(const struct qaffd_state *state) {
  if (state->state_path == NULL) {
    return 0;
  }

  char tmp_path[PATH_MAX];
  int n = snprintf(tmp_path,
                   sizeof(tmp_path),
                   "%s.tmp.%ld",
                   state->state_path,
                   (long)getpid());
  if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  FILE *out = fopen(tmp_path, "w");
  if (out == NULL) {
    return -1;
  }

  int rc = 0;
  if (fprintf(out, "qaffd-state-v2\n") < 0) {
    rc = -1;
  }
  for (uint32_t i = 0; rc == 0 && i < QAFFD_MAX_WORKERS; i++) {
    if (state->worker_registered[i] &&
        fprintf(out,
                "worker %u %u\n",
                i,
                state->worker_generations[i]) < 0) {
      rc = -1;
    }
  }

  if (fclose(out) != 0) {
    rc = -1;
  }
  if (rc != 0) {
    unlink(tmp_path);
    return -1;
  }
  if (rename(tmp_path, state->state_path) != 0) {
    unlink(tmp_path);
    return -1;
  }
  return 0;
}

static int load_state(struct qaffd_state *state) {
  if (state->state_path == NULL) {
    return 0;
  }

  FILE *in = fopen(state->state_path, "r");
  if (in == NULL) {
    if (errno == ENOENT) {
      return 0;
    }
    return -1;
  }

  char line[256];
  if (fgets(line, sizeof(line), in) == NULL ||
      (strcmp(line, "qaffd-state-v1\n") != 0 &&
       strcmp(line, "qaffd-state-v2\n") != 0)) {
    fclose(in);
    errno = EINVAL;
    return -1;
  }

  uint64_t loaded_at = now_ms();
  while (fgets(line, sizeof(line), in) != NULL) {
    uint32_t worker_id = 0;
    uint32_t generation = QAFF_WORKER_GENERATION_DEFAULT;
    if (sscanf(line, "worker %u %u", &worker_id, &generation) >= 1) {
      if (worker_id >= QAFFD_MAX_WORKERS) {
        fclose(in);
        errno = EINVAL;
        return -1;
      }
      if (generation == 0 || generation > QAFF_WORKER_GENERATION_MAX) {
        fclose(in);
        errno = EINVAL;
        return -1;
      }
      state->worker_registered[worker_id] = 1;
      state->worker_generations[worker_id] = generation;
      state->worker_registered_at_ms[worker_id] = loaded_at;
      state->worker_last_seen_ms[worker_id] = loaded_at;
      continue;
    }

    uint32_t cid_len = 0;
    char hex[QAFF_MAX_CID_LEN * 2 + 2];
    if (sscanf(line, "cid %u %u %65s", &worker_id, &cid_len, hex) == 3) {
      struct qaff_cid_key ignored;
      if (worker_id >= QAFFD_MAX_WORKERS ||
          parse_cid_hex(hex, cid_len, &ignored) != 0) {
        fclose(in);
        errno = EINVAL;
        return -1;
      }
      state->worker_registered[worker_id] = 1;
      if (state->worker_generations[worker_id] == 0) {
        state->worker_generations[worker_id] = QAFF_WORKER_GENERATION_DEFAULT;
      }
      state->worker_registered_at_ms[worker_id] = loaded_at;
      state->worker_last_seen_ms[worker_id] = loaded_at;
      continue;
    }

    fclose(in);
    errno = EINVAL;
    return -1;
  }

  if (ferror(in)) {
    fclose(in);
    return -1;
  }
  fclose(in);
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
  if (state->worker_registered[request->worker_id] &&
      authorize_worker_mutation(state, request->worker_id, peer) != 0) {
    return -1;
  }

  struct sockaddr_storage local_addr;
  if (validate_worker_socket(state, socket_fd, &local_addr) != 0) {
    return -1;
  }

  uint32_t generation = next_worker_generation(
      state->worker_generations[request->worker_id]);
  if (qaff_register_worker_socket_generation(state->ctx,
                                             request->worker_id,
                                             socket_fd,
                                             generation) != 0) {
    return -1;
  }

  if (!state->attached) {
    if (qaff_attach_reuseport_bpf(state->bpf, socket_fd) != 0) {
      int saved_errno = errno ? errno : EIO;
      qaff_unregister_worker_socket(state->ctx, request->worker_id);
      errno = saved_errno;
      return -1;
    }
    state->attached = 1;
  }

  if (state->worker_fds[request->worker_id] >= 0) {
    close(state->worker_fds[request->worker_id]);
  }
  if (state->worker_pidfds[request->worker_id] >= 0) {
    close(state->worker_pidfds[request->worker_id]);
    state->worker_pidfds[request->worker_id] = -1;
  }
  state->worker_fds[request->worker_id] = socket_fd;
  state->worker_registered[request->worker_id] = 1;
  state->worker_generations[request->worker_id] = generation;
  uint64_t now = now_ms();
  state->worker_registered_at_ms[request->worker_id] = now;
  state->worker_last_seen_ms[request->worker_id] = now;
  state->worker_creds[request->worker_id] =
      peer != NULL ? *peer : (struct qaffd_peer_cred){0};
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
    return -1;
  }
  audit_event("worker_registered",
              peer,
              "worker_id=%u generation=%u leased=%u",
              request->worker_id,
              generation,
              enable_pidfd ? 1u : 0u);
  return 0;
}

static int unregister_worker_authorized(struct qaffd_state *state,
                                        uint32_t worker_id,
                                        const struct qaffd_peer_cred *peer) {
  if (retire_worker_cids(state, worker_id) != 0) {
    return -1;
  }

  if (qaff_unregister_worker_socket(state->ctx, worker_id) != 0 &&
      errno != ENOENT) {
    return -1;
  }

  if (state->worker_fds[worker_id] >= 0) {
    close(state->worker_fds[worker_id]);
    state->worker_fds[worker_id] = -1;
  }
  if (state->worker_lease_fds[worker_id] >= 0) {
    close(state->worker_lease_fds[worker_id]);
    state->worker_lease_fds[worker_id] = -1;
  }
  if (state->worker_pidfds[worker_id] >= 0) {
    close(state->worker_pidfds[worker_id]);
    state->worker_pidfds[worker_id] = -1;
  }
  state->worker_registered[worker_id] = 0;
  state->worker_registered_at_ms[worker_id] = 0;
  state->worker_last_seen_ms[worker_id] = 0;
  memset(&state->worker_creds[worker_id],
         0,
         sizeof(state->worker_creds[worker_id]));
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

  if (save_state(state) != 0) {
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

  forget_cid(state, &key);
  if (save_state(state) != 0) {
    return -1;
  }
  audit_event("cid_retired",
              peer,
              "worker_id=%u cid_len=%u",
              owner_worker_id,
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
  if (request.magic != QAFF_CONTROL_MAGIC ||
      request.version != QAFF_CONTROL_VERSION ||
      request.op != QAFF_CONTROL_WORKER_HEARTBEAT ||
      request.worker_id != worker_id ||
      !state->worker_registered[worker_id] ||
      state->worker_lease_fds[worker_id] != lease_fd) {
    reply.status = EPROTO;
  } else {
    state->worker_last_seen_ms[worker_id] = now_ms();
  }

  if (write_exact(lease_fd, &reply, sizeof(reply)) != 0) {
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

static int handle_request(struct qaffd_state *state,
                          int client_fd,
                          int *keep_client_fd) {
  struct qaff_control_msg request;
  int received_fd = -1;
  int lease_worker_id = -1;
  struct qaffd_peer_cred peer_cred;
  memset(&peer_cred, 0, sizeof(peer_cred));
  *keep_client_fd = 0;

  if (recv_request(client_fd, &request, &received_fd) != 0) {
    if (received_fd >= 0) {
      close(received_fd);
    }
    if (errno == ECONNRESET) {
      return 0;
    }
    return -1;
  }

  struct qaff_control_msg reply;
  reply_init(&reply, &request);

  if (request.magic != QAFF_CONTROL_MAGIC ||
      request.version != QAFF_CONTROL_VERSION) {
    reply.status = EPROTO;
  } else {
    switch (request.op) {
    case QAFF_CONTROL_REGISTER_WORKER:
      if (get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_register_worker(state,
                                 &request,
                                 received_fd,
                                 &peer_cred,
                                 0) != 0) {
        reply.status = errno ? errno : EIO;
        if (received_fd >= 0) {
          close(received_fd);
        }
      } else {
        received_fd = -1;
      }
      break;
    case QAFF_CONTROL_REGISTER_WORKER_LEASE:
      if (get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_register_worker(state,
                                 &request,
                                 received_fd,
                                 &peer_cred,
                                 1) != 0) {
        reply.status = errno ? errno : EIO;
        if (received_fd >= 0) {
          close(received_fd);
        }
      } else {
        lease_worker_id = (int)request.worker_id;
        received_fd = -1;
      }
      break;
    case QAFF_CONTROL_UNREGISTER_WORKER:
      if (get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_unregister_worker(state, &request, &peer_cred) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_REGISTER_CID:
      if (get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_register_cid(state, &request, &peer_cred) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_RETIRE_CID:
      if (get_peer_cred(client_fd, &peer_cred) != 0 ||
          handle_retire_cid(state, &request, &peer_cred) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_READ_STATS:
      if (qaff_read_stats(state->ctx, &reply.stats) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_HEALTH:
      fill_config_reply(state, &reply);
      break;
    case QAFF_CONTROL_CONFIG:
      fill_config_reply(state, &reply);
      break;
    case QAFF_CONTROL_WORKERS:
      fill_config_reply(state, &reply);
      fill_workers_reply(state, &reply);
      break;
    case QAFF_CONTROL_CIDS:
      fill_config_reply(state, &reply);
      break;
    case QAFF_CONTROL_STOP:
      if (get_peer_cred(client_fd, &peer_cred) != 0 ||
          authorize_daemon_mutation(state, &peer_cred) != 0) {
        reply.status = errno ? errno : EIO;
      } else {
        state->stop = 1;
      }
      break;
    default:
      reply.status = ENOSYS;
      break;
    }
  }

  int rc = write_exact(client_fd, &reply, sizeof(reply));
  if (rc != 0) {
    if (lease_worker_id >= 0) {
      unregister_worker_id(state, (uint32_t)lease_worker_id);
    }
    return -1;
  }

  if (lease_worker_id >= 0) {
    install_worker_lease(state, (uint32_t)lease_worker_id, client_fd);
    *keep_client_fd = 1;
  }

  if (received_fd >= 0) {
    close(received_fd);
  }

  return 0;
}

static int make_server_socket(const struct qaffd_state *state,
                              const char *path) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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

  unlink(path);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  if (state->socket_gid_set &&
      chown(path, (uid_t)-1, (gid_t)state->socket_gid) != 0) {
    close(fd);
    return -1;
  }

  if (chmod(path, state->socket_mode) != 0) {
    close(fd);
    return -1;
  }

  if (listen(fd, 64) != 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static int accept_cloexec(int server_fd) {
  int fd;
  do {
    fd = accept(server_fd, NULL, NULL);
  } while (fd < 0 && errno == EINTR && !g_stop_requested);

  if (fd < 0) {
    return -1;
  }

  int flags = fcntl(fd, F_GETFD, 0);
  if (flags >= 0) {
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
  }
  return fd;
}

static nfds_t build_pollfds(const struct qaffd_state *state,
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
  state.pin_root = daemon_options.pin_root;
  state.state_path = daemon_options.state_path;
  state.short_cid_len = daemon_options.short_cid_len;
  state.cid_profile_v1_enabled = daemon_options.cid_profile_v1_enabled;
  state.cid_profile_v2_enabled = daemon_options.cid_profile_v2_enabled;
  state.cid_profile_v2_config_id = daemon_options.cid_profile_v2_config_id;
  state.passive_affinity_enabled = daemon_options.passive_affinity_enabled;
  state.passive_min_confidence = daemon_options.passive_min_confidence;
  memcpy(state.cid_profile_v1_key,
         daemon_options.cid_profile_v1_key,
         sizeof(state.cid_profile_v1_key));
  state.fallback_worker_id = daemon_options.fallback_worker_id;
  state.worker_heartbeat_timeout_ms =
      daemon_options.worker_heartbeat_timeout_ms;
  state.allow_worker_uid_set = daemon_options.allow_worker_uid_set;
  state.allow_worker_gid_set = daemon_options.allow_worker_gid_set;
  state.allow_worker_uid = daemon_options.allow_worker_uid;
  state.allow_worker_gid = daemon_options.allow_worker_gid;
  state.socket_gid_set = daemon_options.socket_gid_set;
  state.socket_gid = daemon_options.socket_gid;
  state.socket_mode = daemon_options.socket_mode;
  for (size_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    state.worker_fds[i] = -1;
    state.worker_lease_fds[i] = -1;
    state.worker_pidfds[i] = -1;
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
  memcpy(options.cid_profile_v1_key,
         daemon_options.cid_profile_v1_key,
         sizeof(options.cid_profile_v1_key));
  options.fallback_worker_id = daemon_options.fallback_worker_id;

  if (qaff_open(&options, &state.ctx) != 0) {
    perror("qaff_open");
    return 1;
  }

  if (qaff_bpf_object_open(state.ctx,
                           daemon_options.bpf_object_path,
                           &state.bpf) != 0) {
    perror("qaff_bpf_object_open");
    qaff_close(state.ctx);
    return 1;
  }

  if (load_state(&state) != 0) {
    perror("load_state");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    free(state.cid_entries);
    return 1;
  }
  if (recover_cids_from_map(&state) != 0) {
    perror("recover_cids_from_map");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    free(state.cid_entries);
    return 1;
  }
  if (worker_count(&state) > 0) {
    state.attached = 1;
  }

  int server_fd = make_server_socket(&state, daemon_options.socket_path);
  if (server_fd < 0) {
    perror("make_server_socket");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    return 1;
  }

  struct pollfd pollfds[QAFFD_MAX_WORKERS * 2 + 1];
  uint32_t poll_worker_ids[QAFFD_MAX_WORKERS * 2 + 1];
  enum qaffd_poll_source poll_sources[QAFFD_MAX_WORKERS * 2 + 1];

  while (!state.stop && !g_stop_requested) {
    if (expire_worker_heartbeat_timeouts(&state) != 0) {
      perror("expire_worker_heartbeat_timeouts");
    }

    nfds_t pollfds_len = build_pollfds(&state,
                                       server_fd,
                                       pollfds,
                                       poll_worker_ids,
                                       poll_sources,
                                       QAFFD_MAX_WORKERS * 2 + 1);
    int poll_timeout = worker_heartbeat_poll_timeout(&state);
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
      int client_fd = accept_cloexec(server_fd);
      if (client_fd < 0) {
        if (g_stop_requested) {
          break;
        }
        perror("accept");
      } else {
        int keep_client_fd = 0;
        if (handle_request(&state, client_fd, &keep_client_fd) != 0) {
          perror("handle_request");
        }
        if (!keep_client_fd) {
          close(client_fd);
        }
      }
    }

    for (nfds_t i = 1; i < pollfds_len; i++) {
      if ((pollfds[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) == 0) {
        continue;
      }

      uint32_t worker_id = poll_worker_ids[i];
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
  qaff_bpf_object_close(state.bpf);
  qaff_close(state.ctx);
  return 0;
}
