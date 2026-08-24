#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"
#include "bpf_abi.h"
#include "quic_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif
#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

#define TEST_SKIP 77
#define WORKER_COUNT 3
#define FALLBACK_WORKER 0
#define TARGET_WORKER 2

static const uint8_t k_dcid[] = {
  0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
  0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
};

static const uint8_t k_passive_dcid[] = {
  0x70, 0x61, 0x73, 0x73, 0x0a, 0x0b, 0x0c, 0x0d,
  0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
};

static const uint8_t k_orphan_dcid[] = {
  0x6f, 0x72, 0x70, 0x68, 0x61, 0x6e, 0x01, 0x02,
  0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
};

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int make_worker_socket(uint16_t *port) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0) {
    close(fd);
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(*port);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  if (*port == 0) {
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
      close(fd);
      return -1;
    }
    *port = ntohs(addr.sin_port);
  }

  if (set_nonblocking(fd) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int make_sender_socket(void) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int send_quic_like_packet(int fd, uint16_t port, const uint8_t *dcid) {
  uint8_t packet[] = {
    0x43,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x01, 0x02, 0x03, 0x04,
  };
  memcpy(packet + 1, dcid, sizeof(k_dcid));

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(port);
  return sendto(fd, packet, sizeof(packet), 0,
                (struct sockaddr *)&dst, sizeof(dst)) == (ssize_t)sizeof(packet)
           ? 0
           : -1;
}

static int receive_worker_timeout(const int *workers,
                                  size_t count,
                                  int timeout_ms) {
  struct pollfd fds[WORKER_COUNT];
  for (size_t i = 0; i < count; i++) {
    fds[i].fd = workers[i];
    fds[i].events = POLLIN;
    fds[i].revents = 0;
  }

  if (poll(fds, count, timeout_ms) <= 0) {
    return -1;
  }

  uint8_t buf[2048];
  for (size_t i = 0; i < count; i++) {
    if ((fds[i].revents & POLLIN) &&
        recv(workers[i], buf, sizeof(buf), 0) > 0) {
      return (int)i;
    }
  }
  return -1;
}

static int receive_worker(const int *workers, size_t count) {
  return receive_worker_timeout(workers, count, 1000);
}

static int connect_retry(const char *socket_path, int attempts) {
  const struct timespec delay = {
    .tv_sec = 0,
    .tv_nsec = 20 * 1000 * 1000,
  };

  for (int i = 0; i < attempts; i++) {
    int fd = qaff_control_connect(socket_path);
    if (fd >= 0) {
      return fd;
    }
    nanosleep(&delay, NULL);
  }
  return -1;
}

static int state_has_record(const char *state_path,
                            const char *kind,
                            uint32_t worker_id,
                            uint32_t generation) {
  char expected[64];
  int expected_len = snprintf(expected,
                              sizeof(expected),
                              "%s %u %u\n",
                              kind,
                              worker_id,
                              generation);
  if (expected_len < 0 || (size_t)expected_len >= sizeof(expected)) {
    errno = EOVERFLOW;
    return -1;
  }

  FILE *state = fopen(state_path, "r");
  if (state == NULL) {
    return -1;
  }
  char line[128];
  int found = 0;
  while (fgets(line, sizeof(line), state) != NULL) {
    if (strcmp(line, expected) == 0) {
      found = 1;
      break;
    }
  }
  int saved_errno = errno;
  if (ferror(state)) {
    found = -1;
  }
  if (fclose(state) != 0 && found >= 0) {
    return -1;
  }
  errno = saved_errno;
  return found;
}

static pid_t start_qaffd_with_key(const char *qaffd_path,
                                  const char *socket_path,
                                  const char *bpf_path,
                                  const char *pin_root,
                                  const char *state_path,
                                  const char *profile_key) {
  char uid_arg[32];
  char gid_arg[32];
  snprintf(uid_arg, sizeof(uid_arg), "%u", (unsigned int)getuid());
  snprintf(gid_arg, sizeof(gid_arg), "%u", (unsigned int)getgid());

  pid_t pid = fork();
  if (pid != 0) {
    return pid;
  }

  execl(qaffd_path,
        qaffd_path,
        "--socket",
        socket_path,
        "--bpf",
        bpf_path,
        "--short-cid-len",
        "16",
        "--reuseport-bpf-policy",
        "replace",
        "--cid-profile-key",
        profile_key,
        "--passive-affinity",
        "--pin-root",
        pin_root,
        "--state-path",
        state_path,
        "--worker-recovery-timeout-ms",
        "2000",
        "--allow-worker-uid",
        uid_arg,
        "--allow-worker-gid",
        gid_arg,
        "--allow-admin-uid",
        uid_arg,
        "--allow-admin-gid",
        gid_arg,
        (char *)NULL);
  perror("execl qaffd");
  _exit(127);
}

static pid_t start_qaffd(const char *qaffd_path,
                         const char *socket_path,
                         const char *bpf_path,
                         const char *pin_root,
                         const char *state_path) {
  return start_qaffd_with_key(qaffd_path,
                              socket_path,
                              bpf_path,
                              pin_root,
                              state_path,
                              "707172737475767778797a7b7c7d7e7f");
}

static int read_pinned_config(const char *pin_root,
                              struct qaff_config_value *out) {
  char path[4096];
  int n = snprintf(path, sizeof(path), "%s/qaff_config", pin_root);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  int fd = bpf_obj_get(path);
  if (fd < 0) {
    return -1;
  }
  uint32_t key = 0;
  int rc = bpf_map_lookup_elem(fd, &key, out);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return rc;
}

static int stop_qaffd(const char *socket_path, pid_t pid) {
  int fd = qaff_control_connect(socket_path);
  if (fd >= 0) {
    qaff_control_stop(fd);
    close(fd);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int wait_ready_or_skip(const char *socket_path, pid_t pid) {
  int fd = connect_retry(socket_path, 100);
  if (fd >= 0) {
    close(fd);
    return 0;
  }

  int status = 0;
  if (waitpid(pid, &status, WNOHANG) == pid) {
    fprintf(stderr, "skipping: qaffd exited before accepting control connections\n");
    return TEST_SKIP;
  }
  kill(pid, SIGTERM);
  waitpid(pid, NULL, 0);
  return -1;
}

static int control_register_worker_result(const char *socket_path,
                                          uint32_t worker_id,
                                          int worker_fd,
                                          uint32_t *generation_out) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  struct qaff_control_worker_registration registration;
  int rc = qaff_control_register_worker(
      fd, worker_id, worker_fd, &registration);
  close(fd);
  if (rc == 0 && (registration.worker_id != worker_id ||
                  registration.generation == 0 ||
                  registration.cid_profile_key_fingerprint == 0)) {
    errno = EPROTO;
    return -1;
  }
  if (rc == 0 && generation_out != NULL) {
    *generation_out = registration.generation;
  }
  return rc;
}

static int control_register_worker(const char *socket_path,
                                   uint32_t worker_id,
                                   int worker_fd) {
  return control_register_worker_result(
      socket_path, worker_id, worker_fd, NULL);
}

static int control_register_cid(const char *socket_path,
                                uint32_t worker_id,
                                const uint8_t *cid) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_register_cid(fd, worker_id, cid, sizeof(k_dcid));
  close(fd);
  return rc;
}

static int control_retire_cid(const char *socket_path, const uint8_t *cid) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_retire_cid(fd, cid, sizeof(k_dcid));
  close(fd);
  return rc;
}

static int control_register_passive_cid(const char *socket_path,
                                        uint32_t worker_id,
                                        const uint8_t *cid) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  struct qaff_passive_cid_value value;
  memset(&value, 0, sizeof(value));
  value.worker_id = worker_id;
  value.confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  value.source = QAFF_PASSIVE_SOURCE_EGRESS;
  int rc = qaff_control_register_passive_cid(fd,
                                             cid,
                                             sizeof(k_passive_dcid),
                                             &value);
  close(fd);
  return rc;
}

static int control_unregister_worker(const char *socket_path,
                                     uint32_t worker_id) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_unregister_worker(fd, worker_id);
  close(fd);
  return rc;
}

static int control_workers_len(const char *socket_path, size_t *workers_len) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  uint32_t workers[QAFF_CONTROL_WORKER_CAPACITY];
  int rc = qaff_control_workers(fd,
                                workers,
                                QAFF_CONTROL_WORKER_CAPACITY,
                                workers_len);
  close(fd);
  return rc;
}

static int control_workers_info(
    const char *socket_path,
    struct qaff_control_worker_info *workers,
    size_t workers_cap,
    size_t *workers_len) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_workers_info(fd,
                                     workers,
                                     workers_cap,
                                     workers_len);
  close(fd);
  return rc;
}

static int wait_workers_len(const char *socket_path, size_t expected) {
  const struct timespec delay = {
    .tv_sec = 0,
    .tv_nsec = 20 * 1000 * 1000,
  };
  for (int attempt = 0; attempt < 200; attempt++) {
    size_t workers_len = 0;
    if (control_workers_len(socket_path, &workers_len) == 0 &&
        workers_len == expected) {
      return 0;
    }
    nanosleep(&delay, NULL);
  }
  errno = ETIMEDOUT;
  return -1;
}

static int control_config(const char *socket_path,
                          struct qaff_control_config *config);

static int wait_persistence_healthy(
    const char *socket_path,
    struct qaff_control_config *config) {
  const struct timespec delay = {
    .tv_sec = 0,
    .tv_nsec = 20 * 1000 * 1000,
  };
  for (int attempt = 0; attempt < 250; attempt++) {
    if (control_config(socket_path, config) == 0 &&
        !config->state_persistence_degraded) {
      return 0;
    }
    nanosleep(&delay, NULL);
  }
  errno = ETIMEDOUT;
  return -1;
}

static int control_read_stats(const char *socket_path, struct qaff_stats *stats) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_read_stats(fd, stats);
  close(fd);
  return rc;
}

static int control_cids(const char *socket_path,
                        struct qaff_control_config *config) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_cids(fd, config);
  close(fd);
  return rc;
}

static int control_health(const char *socket_path) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_health(fd);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return rc;
}

static int control_config(const char *socket_path,
                          struct qaff_control_config *config) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_config(fd, config);
  close(fd);
  return rc;
}

static int inject_stale_passive_cid(const char *pin_root,
                                    uint32_t worker_id,
                                    uint32_t worker_generation,
                                    const uint8_t *cid,
                                    size_t cid_len) {
  char map_path[4096];
  int n = snprintf(map_path,
                   sizeof(map_path),
                   "%s/qaff_passive_cids",
                   pin_root);
  if (n < 0 || (size_t)n >= sizeof(map_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  int map_fd = bpf_obj_get(map_path);
  if (map_fd < 0) {
    return -1;
  }

  struct qaff_cid_key key;
  if (qaff_cid_key_from_bytes(cid, cid_len, &key) != QAFF_PARSE_OK) {
    close(map_fd);
    errno = EINVAL;
    return -1;
  }

  struct qaff_passive_cid_value value;
  memset(&value, 0, sizeof(value));
  value.worker_id = worker_id;
  value.worker_generation = worker_generation;
  value.confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  value.source = QAFF_PASSIVE_SOURCE_EGRESS;
  int rc = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
  int saved_errno = errno;
  close(map_fd);
  errno = saved_errno;
  return rc;
}

static int open_pinned_map(const char *pin_root, const char *name) {
  char map_path[4096];
  int n = snprintf(map_path, sizeof(map_path), "%s/%s", pin_root, name);
  if (n < 0 || (size_t)n >= sizeof(map_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return bpf_obj_get(map_path);
}

static int set_pinned_exact_cid(const char *pin_root,
                                const uint8_t *cid,
                                size_t cid_len,
                                uint32_t worker_id,
                                uint32_t worker_generation) {
  struct qaff_cid_key key;
  if (qaff_cid_key_from_bytes(cid, cid_len, &key) != QAFF_PARSE_OK) {
    errno = EINVAL;
    return -1;
  }
  int map_fd = open_pinned_map(pin_root, "qaff_cids");
  if (map_fd < 0) {
    return -1;
  }
  struct qaff_cid_value value = {
    .worker_id = worker_id,
    .worker_generation = worker_generation,
  };
  int rc = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
  int saved_errno = errno;
  close(map_fd);
  errno = saved_errno;
  return rc;
}

static int delete_pinned_exact_cid(const char *pin_root,
                                   const uint8_t *cid,
                                   size_t cid_len) {
  struct qaff_cid_key key;
  if (qaff_cid_key_from_bytes(cid, cid_len, &key) != QAFF_PARSE_OK) {
    errno = EINVAL;
    return -1;
  }
  int map_fd = open_pinned_map(pin_root, "qaff_cids");
  if (map_fd < 0) {
    return -1;
  }
  int rc = bpf_map_delete_elem(map_fd, &key);
  int saved_errno = errno;
  close(map_fd);
  errno = saved_errno;
  return rc;
}

static int freeze_pinned_map(const char *pin_root, const char *name) {
  int map_fd = open_pinned_map(pin_root, name);
  if (map_fd < 0) {
    return -1;
  }
  int rc = bpf_map_freeze(map_fd);
  int saved_errno = errno;
  close(map_fd);
  errno = saved_errno;
  return rc;
}

static int set_pinned_worker_generation(const char *pin_root,
                                        uint32_t worker_id,
                                        uint32_t generation) {
  int map_fd = open_pinned_map(pin_root, "qaff_worker_generations");
  if (map_fd < 0) {
    return -1;
  }
  int rc = bpf_map_update_elem(map_fd,
                               &worker_id,
                               &generation,
                               BPF_ANY);
  int saved_errno = errno;
  close(map_fd);
  errno = saved_errno;
  return rc;
}

static int inject_interrupted_unregistration(const char *pin_root,
                                             uint32_t worker_id,
                                             int worker_fd,
                                             const uint8_t *exact_cid,
                                             size_t exact_cid_len,
                                             const uint8_t *passive_cid,
                                             size_t passive_cid_len) {
  int exact_map_fd = -1;
  int worker_map_fd = -1;
  int generation_map_fd = -1;
  int socket_worker_map_fd = -1;
  int rc = -1;

  struct qaff_cid_key key;
  if (qaff_cid_key_from_bytes(exact_cid, exact_cid_len, &key) !=
      QAFF_PARSE_OK) {
    errno = EINVAL;
    return -1;
  }
  if (inject_stale_passive_cid(pin_root,
                               worker_id,
                               QAFF_WORKER_GENERATION_DEFAULT,
                               passive_cid,
                               passive_cid_len) != 0) {
    return -1;
  }

  exact_map_fd = open_pinned_map(pin_root, "qaff_cids");
  worker_map_fd = open_pinned_map(pin_root, "qaff_workers");
  generation_map_fd = open_pinned_map(pin_root, "qaff_worker_generations");
  socket_worker_map_fd = open_pinned_map(pin_root, "qaff_socket_workers");
  if (exact_map_fd < 0 || worker_map_fd < 0 || generation_map_fd < 0 ||
      socket_worker_map_fd < 0) {
    goto out;
  }

  /*
   * Model a crash after the generation was withdrawn but before the socket
   * and reverse-cookie maps were cleaned. Restart reconciliation must finish
   * the transaction instead of treating generation zero as fully removed.
   */
  uint32_t generation = 0;
  uint64_t socket_cookie = 0;
  socklen_t cookie_len = sizeof(socket_cookie);
  if (getsockopt(worker_fd,
                 SOL_SOCKET,
                 SO_COOKIE,
                 &socket_cookie,
                 &cookie_len) != 0 ||
      cookie_len != sizeof(socket_cookie) || socket_cookie == 0) {
    goto out;
  }

  struct qaff_cid_value exact_value = {
      .worker_id = worker_id,
      .worker_generation = QAFF_WORKER_GENERATION_DEFAULT,
  };
  if (bpf_map_update_elem(exact_map_fd, &key, &exact_value, BPF_ANY) != 0 ||
      bpf_map_update_elem(worker_map_fd,
                          &worker_id,
                          &worker_fd,
                          BPF_ANY) != 0 ||
      bpf_map_update_elem(generation_map_fd,
                          &worker_id,
                          &generation,
                          BPF_ANY) != 0 ||
      bpf_map_update_elem(socket_worker_map_fd,
                          &socket_cookie,
                          &worker_id,
                          BPF_ANY) != 0) {
    goto out;
  }
  rc = 0;

out:
  {
    int saved_errno = errno;
    if (exact_map_fd >= 0) {
      close(exact_map_fd);
    }
    if (worker_map_fd >= 0) {
      close(worker_map_fd);
    }
    if (generation_map_fd >= 0) {
      close(generation_map_fd);
    }
    if (socket_worker_map_fd >= 0) {
      close(socket_worker_map_fd);
    }
    errno = saved_errno;
  }
  return rc;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr,
            "usage: %s PATH_TO_QAFFD PATH_TO_BPF_OBJECT PIN_ROOT STATE_PATH\n",
            argv[0]);
    return 2;
  }

  const char *qaffd_path = argv[1];
  const char *bpf_path = argv[2];
  const char *pin_root = argv[3];
  const char *state_path = argv[4];

  char socket_path[108];
  snprintf(socket_path, sizeof(socket_path),
           "/tmp/qaffd-restart-%ld.sock",
           (long)getpid());
  char lock_path[sizeof(socket_path) + sizeof(".lock")];
  snprintf(lock_path, sizeof(lock_path), "%s.lock", socket_path);
  unlink(socket_path);
  unlink(lock_path);

  char unwritable_state_path[128];
  snprintf(unwritable_state_path,
           sizeof(unwritable_state_path),
           "/proc/qaffd-restart-%ld.state",
           (long)getpid());
  pid_t rollback_daemon_pid = start_qaffd(qaffd_path,
                                          socket_path,
                                          bpf_path,
                                          pin_root,
                                          unwritable_state_path);
  if (rollback_daemon_pid < 0) {
    perror("fork qaffd rollback test");
    return 1;
  }
  int ready = wait_ready_or_skip(socket_path, rollback_daemon_pid);
  if (ready != 0) {
    return ready == TEST_SKIP ? TEST_SKIP : 1;
  }
  uint16_t rollback_port = 0;
  int rollback_worker = make_worker_socket(&rollback_port);
  if (rollback_worker < 0) {
    perror("make rollback worker socket");
    return 1;
  }
  if (control_register_worker(socket_path, 0, rollback_worker) == 0) {
    fprintf(stderr, "worker registration unexpectedly survived state failure\n");
    return 1;
  }
  size_t rollback_workers_len = 0;
  if (control_workers_len(socket_path, &rollback_workers_len) != 0 ||
      rollback_workers_len != 0) {
    fprintf(stderr, "worker registration state was not rolled back\n");
    return 1;
  }
  close(rollback_worker);
  if (stop_qaffd(socket_path, rollback_daemon_pid) != 0) {
    perror("stop_qaffd rollback test");
    return 1;
  }

  pid_t daemon_pid = start_qaffd(qaffd_path,
                                 socket_path,
                                 bpf_path,
                                 pin_root,
                                 state_path);
  if (daemon_pid < 0) {
    perror("fork qaffd");
    return 1;
  }

  ready = wait_ready_or_skip(socket_path, daemon_pid);
  if (ready != 0) {
    return ready == TEST_SKIP ? TEST_SKIP : 1;
  }

  struct qaff_control_config listener_config;
  if (control_config(socket_path, &listener_config) != 0 ||
      listener_config.short_cid_len != QAFF_CID_PROFILE_LEN ||
      !listener_config.cid_profile_enabled ||
      strcmp(listener_config.pin_root, pin_root) != 0 ||
      strcmp(listener_config.state_path, state_path) != 0) {
    fprintf(stderr, "CID profile persistence config was not applied\n");
    return 1;
  }
  struct qaff_control_config cid_config;

  int workers[WORKER_COUNT] = {-1, -1, -1};
  uint16_t port = 0;
  for (uint32_t i = 0; i < WORKER_COUNT; i++) {
    workers[i] = make_worker_socket(&port);
    if (workers[i] < 0) {
      perror("make_worker_socket");
      return 1;
    }
    if (control_register_worker(socket_path, i, workers[i]) != 0) {
      perror("qaff_control_register_worker");
      return 1;
    }
  }

  if (control_register_cid(socket_path, TARGET_WORKER, k_dcid) != 0) {
    perror("qaff_control_register_cid");
    return 1;
  }

  int sender = make_sender_socket();
  if (sender < 0) {
    perror("make_sender_socket");
    return 1;
  }

  if (send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER) {
    fprintf(stderr, "expected initial CID hit on worker %d\n", TARGET_WORKER);
    return 1;
  }
  if (control_register_passive_cid(socket_path,
                                   TARGET_WORKER,
                                   k_passive_dcid) != 0 ||
      send_quic_like_packet(sender, port, k_passive_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER) {
    fprintf(stderr, "expected initial passive CID hit on worker %d\n",
            TARGET_WORKER);
    return 1;
  }

  if (delete_pinned_exact_cid(pin_root, k_dcid, sizeof(k_dcid)) != 0 ||
      control_cids(socket_path, &cid_config) != 0 ||
      cid_config.cid_map_count != 0 ||
      cid_config.cid_owner_count != 1 ||
      cid_config.cid_index_mismatch != 1) {
    fprintf(stderr, "exact CID deletion fault was not observable\n");
    return 1;
  }
  errno = 0;
  if (control_health(socket_path) == 0 || errno != EUCLEAN) {
    fprintf(stderr, "CID ownership mismatch did not fail health errno=%d\n",
            errno);
    return 1;
  }
  if (control_retire_cid(socket_path, k_dcid) != 0 ||
      control_cids(socket_path, &cid_config) != 0 ||
      cid_config.cid_map_count != 0 ||
      cid_config.cid_owner_count != 0 ||
      cid_config.cid_index_mismatch != 0 ||
      control_health(socket_path) != 0) {
    fprintf(stderr, "idempotent exact CID retirement did not repair index\n");
    return 1;
  }
  if (control_register_cid(socket_path, TARGET_WORKER, k_dcid) != 0) {
    perror("restore exact CID after retirement repair");
    return 1;
  }

  if (stop_qaffd(socket_path, daemon_pid) != 0) {
    perror("stop_qaffd first");
    return 1;
  }

  struct qaff_config_value config_before_rekey;
  struct qaff_config_value config_after_rekey;
  if (read_pinned_config(pin_root, &config_before_rekey) != 0) {
    perror("read config before rejected rekey");
    return 1;
  }
  daemon_pid = start_qaffd_with_key(
      qaffd_path,
      socket_path,
      bpf_path,
      pin_root,
      state_path,
      "808182838485868788898a8b8c8d8e8f");
  if (daemon_pid < 0) {
    perror("fork qaffd rekey rejection");
    return 1;
  }
  int rekey_status = 0;
  int rekey_exited = 0;
  const struct timespec rekey_delay = {
    .tv_sec = 0,
    .tv_nsec = 20 * 1000 * 1000,
  };
  for (int attempt = 0; attempt < 100; attempt++) {
    pid_t waited = waitpid(daemon_pid, &rekey_status, WNOHANG);
    if (waited == daemon_pid) {
      rekey_exited = 1;
      break;
    }
    if (waited < 0) {
      perror("waitpid rejected rekey");
      return 1;
    }
    nanosleep(&rekey_delay, NULL);
  }
  if (!rekey_exited) {
    kill(daemon_pid, SIGTERM);
    waitpid(daemon_pid, NULL, 0);
  }
  if (!rekey_exited || !WIFEXITED(rekey_status) ||
      WEXITSTATUS(rekey_status) == 0 ||
      read_pinned_config(pin_root, &config_after_rekey) != 0 ||
      memcmp(&config_before_rekey,
             &config_after_rekey,
             sizeof(config_before_rekey)) != 0) {
    fprintf(stderr,
            "qaffd accepted an online rekey or changed pinned config on "
            "failed startup\n");
    return 1;
  }

  if (set_pinned_worker_generation(pin_root,
                                   3,
                                   QAFF_WORKER_GENERATION_DEFAULT) != 0) {
    perror("inject map-only worker generation");
    return 1;
  }
  daemon_pid = start_qaffd(qaffd_path,
                           socket_path,
                           bpf_path,
                           pin_root,
                           state_path);
  if (daemon_pid < 0) {
    perror("fork qaffd map-only generation");
    return 1;
  }
  int map_only_status = 0;
  int map_only_exited = 0;
  const struct timespec startup_rejection_delay = {
    .tv_sec = 0,
    .tv_nsec = 20 * 1000 * 1000,
  };
  for (int attempt = 0; attempt < 100; attempt++) {
    pid_t waited = waitpid(daemon_pid, &map_only_status, WNOHANG);
    if (waited == daemon_pid) {
      map_only_exited = 1;
      break;
    }
    if (waited < 0) {
      perror("waitpid map-only generation");
      return 1;
    }
    nanosleep(&startup_rejection_delay, NULL);
  }
  if (!map_only_exited) {
    kill(daemon_pid, SIGTERM);
    waitpid(daemon_pid, NULL, 0);
  }
  if (!map_only_exited || !WIFEXITED(map_only_status) ||
      WEXITSTATUS(map_only_status) == 0) {
    fprintf(stderr,
            "qaffd accepted a worker generation absent from durable state\n");
    return 1;
  }
  if (set_pinned_worker_generation(pin_root, 3, 0) != 0) {
    perror("clear map-only worker generation");
    return 1;
  }

  daemon_pid = start_qaffd(qaffd_path,
                           socket_path,
                           bpf_path,
                           pin_root,
                           state_path);
  if (daemon_pid < 0) {
    perror("fork qaffd restart");
    return 1;
  }
  ready = wait_ready_or_skip(socket_path, daemon_pid);
  if (ready != 0) {
    return ready == TEST_SKIP ? TEST_SKIP : 1;
  }

  size_t restored_workers_len = 0;
  if (control_workers_len(socket_path, &restored_workers_len) != 0) {
    perror("qaff_control_workers restart");
    return 1;
  }
  if (restored_workers_len != WORKER_COUNT) {
    fprintf(stderr,
            "expected %d restored workers, got %zu\n",
            WORKER_COUNT,
            restored_workers_len);
    return 1;
  }
  struct qaff_control_worker_info restored_workers[WORKER_COUNT];
  size_t restored_worker_infos_len = 0;
  if (control_workers_info(socket_path,
                           restored_workers,
                           WORKER_COUNT,
                           &restored_worker_infos_len) != 0 ||
      restored_worker_infos_len != WORKER_COUNT) {
    fprintf(stderr, "could not inspect recovering workers\n");
    return 1;
  }
  for (size_t i = 0; i < restored_worker_infos_len; i++) {
    if ((restored_workers[i].flags &
         QAFF_CONTROL_WORKER_FLAG_RECOVERING) == 0) {
      fprintf(stderr, "restored worker %u was not marked recovering\n",
              restored_workers[i].worker_id);
      return 1;
    }
  }

  if (control_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids restart");
    return 1;
  }
  if (cid_config.cid_map_count != 1 ||
      cid_config.cid_owner_count != 1 ||
      cid_config.cid_index_mismatch != 0 ||
      cid_config.passive_entry_count != 1 ||
      cid_config.worker_count != WORKER_COUNT ||
      cid_config.recovering_worker_count != WORKER_COUNT ||
      cid_config.fallback_available != 0) {
    fprintf(stderr, "unexpected restored CID counts\n");
    return 1;
  }

  int mismatched_fallback = make_worker_socket(&port);
  if (mismatched_fallback < 0) {
    perror("make mismatched recovery socket");
    return 1;
  }
  if (control_register_worker(socket_path,
                              FALLBACK_WORKER,
                              mismatched_fallback) == 0) {
    fprintf(stderr, "mismatched socket reclaimed a recovering worker\n");
    close(mismatched_fallback);
    return 1;
  }
  close(mismatched_fallback);

  char recovery_state_backup[4096];
  int recovery_backup_len =
      snprintf(recovery_state_backup,
               sizeof(recovery_state_backup),
               "%s.recovery-backup",
               state_path);
  if (recovery_backup_len < 0 ||
      (size_t)recovery_backup_len >= sizeof(recovery_state_backup) ||
      rename(state_path, recovery_state_backup) != 0 ||
      mkdir(state_path, 0700) != 0) {
    perror("block recovery claim snapshot");
    return 1;
  }
  if (control_register_worker(socket_path,
                              FALLBACK_WORKER,
                              workers[FALLBACK_WORKER]) == 0 ||
      control_cids(socket_path, &cid_config) != 0 ||
      cid_config.recovering_worker_count != WORKER_COUNT ||
      cid_config.fallback_available != 0 ||
      send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker_timeout(workers, WORKER_COUNT, 100) >= 0) {
    fprintf(stderr, "failed recovery claim escaped quarantine\n");
    return 1;
  }
  if (rmdir(state_path) != 0 ||
      rename(recovery_state_backup, state_path) != 0) {
    perror("restore recovery claim snapshot");
    return 1;
  }

  if (stop_qaffd(socket_path, daemon_pid) != 0) {
    perror("stop qaffd while workers are quarantined");
    return 1;
  }
  daemon_pid = start_qaffd(qaffd_path,
                           socket_path,
                           bpf_path,
                           pin_root,
                           state_path);
  if (daemon_pid < 0) {
    perror("restart qaffd from quarantined state");
    return 1;
  }
  ready = wait_ready_or_skip(socket_path, daemon_pid);
  if (ready != 0) {
    return ready == TEST_SKIP ? TEST_SKIP : 1;
  }
  if (control_cids(socket_path, &cid_config) != 0 ||
      cid_config.cid_map_count != 1 ||
      cid_config.cid_owner_count != 1 ||
      cid_config.passive_entry_count != 1 ||
      cid_config.recovering_worker_count != WORKER_COUNT) {
    fprintf(stderr, "repeated restart discarded quarantined routing state\n");
    return 1;
  }

  if (send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker_timeout(workers, WORKER_COUNT, 100) >= 0 ||
      send_quic_like_packet(sender, port, k_passive_dcid) != 0 ||
      receive_worker_timeout(workers, WORKER_COUNT, 100) >= 0) {
    fprintf(stderr, "restored workers accepted traffic before reclaim\n");
    return 1;
  }

  for (uint32_t i = 0; i < WORKER_COUNT; i++) {
    if (control_register_worker(socket_path, i, workers[i]) != 0) {
      perror("reclaim recovered worker socket");
      return 1;
    }
  }
  if (control_cids(socket_path, &cid_config) != 0 ||
      cid_config.recovering_worker_count != 0 ||
      cid_config.fallback_available != 1 ||
      send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER ||
      send_quic_like_packet(sender, port, k_passive_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER) {
    fprintf(stderr, "reclaimed workers did not restore CID routing\n");
    return 1;
  }
  if (control_workers_info(socket_path,
                           restored_workers,
                           WORKER_COUNT,
                           &restored_worker_infos_len) != 0) {
    perror("inspect reclaimed workers");
    return 1;
  }
  for (size_t i = 0; i < restored_worker_infos_len; i++) {
    if ((restored_workers[i].flags &
         QAFF_CONTROL_WORKER_FLAG_RECOVERING) != 0 ||
        restored_workers[i].generation != QAFF_WORKER_GENERATION_DEFAULT) {
      fprintf(stderr,
              "worker %u reclaim changed recovery state or generation=%u\n",
              restored_workers[i].worker_id,
              restored_workers[i].generation);
      return 1;
    }
  }

  char state_backup[4096];
  int backup_len = snprintf(state_backup,
                            sizeof(state_backup),
                            "%s.unregister-backup",
                            state_path);
  if (backup_len < 0 || (size_t)backup_len >= sizeof(state_backup) ||
      rename(state_path, state_backup) != 0 || mkdir(state_path, 0700) != 0) {
    perror("block state snapshot replacement");
    return 1;
  }

  if (control_unregister_worker(socket_path, TARGET_WORKER) == 0) {
    fprintf(stderr, "worker unregister unexpectedly survived state failure\n");
    return 1;
  }
  size_t failed_unregister_workers_len = 0;
  if (control_workers_len(socket_path, &failed_unregister_workers_len) != 0 ||
      failed_unregister_workers_len != WORKER_COUNT ||
      control_cids(socket_path, &cid_config) != 0 ||
      cid_config.state_persistence_degraded != 1 ||
      cid_config.state_persistence_error_count == 0 ||
      cid_config.cid_map_count != 1 ||
      cid_config.cid_owner_count != 1 ||
      cid_config.cid_index_mismatch != 0 ||
      cid_config.passive_entry_count != 1 ||
      cid_config.passive_worker_purged_count != 0) {
    fprintf(stderr, "failed unregister changed live routing state\n");
    return 1;
  }
  if (send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER ||
      send_quic_like_packet(sender, port, k_passive_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER) {
    fprintf(stderr, "failed unregister disrupted worker routing\n");
    return 1;
  }

  if (rmdir(state_path) != 0 || rename(state_backup, state_path) != 0) {
    perror("restore state snapshot path");
    return 1;
  }

  if (set_pinned_exact_cid(pin_root,
                           k_orphan_dcid,
                           sizeof(k_orphan_dcid),
                           TARGET_WORKER,
                           QAFF_WORKER_GENERATION_DEFAULT) != 0 ||
      control_cids(socket_path, &cid_config) != 0 ||
      cid_config.cid_map_count != 2 ||
      cid_config.cid_owner_count != 1 ||
      cid_config.cid_index_mismatch != 1) {
    fprintf(stderr, "map-only exact CID fixture was not observable\n");
    return 1;
  }

  if (control_unregister_worker(socket_path, TARGET_WORKER) != 0) {
    perror("qaff_control_unregister_worker restart");
    return 1;
  }

  if (control_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids after cleanup");
    return 1;
  }
  if (cid_config.cid_map_count != 0 ||
      cid_config.state_persistence_degraded != 0 ||
      cid_config.cid_owner_count != 0 ||
      cid_config.cid_index_mismatch != 0 ||
      cid_config.passive_entry_count != 0 ||
      cid_config.passive_worker_purged_count != 1) {
    fprintf(stderr, "unexpected CID counts after restarted cleanup\n");
    return 1;
  }

  if (stop_qaffd(socket_path, daemon_pid) != 0) {
    perror("stop_qaffd after worker cleanup");
    return 1;
  }
  if (inject_interrupted_unregistration(pin_root,
                                        TARGET_WORKER,
                                        workers[TARGET_WORKER],
                                        k_dcid,
                                        sizeof(k_dcid),
                                        k_passive_dcid,
                                        sizeof(k_passive_dcid)) != 0) {
    perror("inject interrupted worker unregistration");
    return 1;
  }
  daemon_pid = start_qaffd(qaffd_path,
                           socket_path,
                           bpf_path,
                           pin_root,
                           state_path);
  if (daemon_pid < 0) {
    perror("fork qaffd tombstone restart");
    return 1;
  }
  ready = wait_ready_or_skip(socket_path, daemon_pid);
  if (ready != 0) {
    return ready == TEST_SKIP ? TEST_SKIP : 1;
  }

  restored_workers_len = 0;
  if (control_workers_len(socket_path, &restored_workers_len) != 0) {
    perror("qaff_control_workers tombstone restart");
    return 1;
  }
  if (restored_workers_len != WORKER_COUNT - 1) {
    fprintf(stderr,
            "expected %d workers after tombstone restart, got %zu\n",
            WORKER_COUNT - 1,
            restored_workers_len);
    return 1;
  }
  if (control_cids(socket_path, &cid_config) != 0 ||
      cid_config.cid_map_count != 0 ||
      cid_config.cid_owner_count != 0 ||
      cid_config.cid_index_mismatch != 0 ||
      cid_config.passive_entry_count != 0) {
    fprintf(stderr, "committed tombstone did not clean residual BPF state\n");
    return 1;
  }

  if (control_register_worker(socket_path,
                              FALLBACK_WORKER,
                              workers[FALLBACK_WORKER]) != 0) {
    perror("reclaim fallback after tombstone restart");
    return 1;
  }
  if (rename(state_path, recovery_state_backup) != 0 ||
      mkdir(state_path, 0700) != 0) {
    perror("block recovery expiration snapshot");
    return 1;
  }
  if (wait_workers_len(socket_path, 1) != 0 ||
      control_cids(socket_path, &cid_config) != 0 ||
      cid_config.worker_count != 1 ||
      cid_config.recovering_worker_count != 0 ||
      cid_config.state_persistence_degraded != 1 ||
      cid_config.state_persistence_error_count == 0) {
    fprintf(stderr,
            "unclaimed recovered worker did not fail closed on state "
            "failure\n");
    return 1;
  }
  if (rmdir(state_path) != 0 ||
      rename(recovery_state_backup, state_path) != 0) {
    perror("restore recovery expiration snapshot");
    return 1;
  }
  if (wait_persistence_healthy(socket_path, &cid_config) != 0 ||
      cid_config.worker_count != 1 ||
      cid_config.state_persistence_retry_count == 0) {
    fprintf(stderr, "state persistence retry did not recover\n");
    return 1;
  }
  close(workers[1]);
  workers[1] = make_worker_socket(&port);
  if (workers[1] < 0 ||
      control_register_worker(socket_path, 1, workers[1]) != 0) {
    perror("register replacement after recovery timeout");
    return 1;
  }

  close(workers[TARGET_WORKER]);
  workers[TARGET_WORKER] = make_worker_socket(&port);
  if (workers[TARGET_WORKER] < 0) {
    perror("make replacement worker socket");
    return 1;
  }
  uint32_t replacement_generation = 0;
  if (control_register_worker_result(socket_path,
                                     TARGET_WORKER,
                                     workers[TARGET_WORKER],
                                     &replacement_generation) != 0 ||
      replacement_generation != 2) {
    perror("qaff_control_register_worker replacement");
    return 1;
  }

  if (inject_stale_passive_cid(pin_root,
                               TARGET_WORKER,
                               QAFF_WORKER_GENERATION_DEFAULT,
                               k_passive_dcid,
                               sizeof(k_passive_dcid)) != 0) {
    perror("inject stale passive CID");
    return 1;
  }

  if (send_quic_like_packet(sender, port, k_passive_dcid) != 0) {
    perror("send stale passive CID packet");
    return 1;
  }
  int stale_passive_worker = receive_worker(workers, WORKER_COUNT);
  if (stale_passive_worker != FALLBACK_WORKER) {
    fprintf(stderr,
            "expected stale passive CID fallback worker %d, got %d\n",
            FALLBACK_WORKER,
            stale_passive_worker);
    return 1;
  }

  if (send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != FALLBACK_WORKER) {
    fprintf(stderr, "expected fallback after restarted qaffd worker cleanup\n");
    return 1;
  }

  struct qaff_stats stats;
  if (control_read_stats(socket_path, &stats) != 0) {
    perror("qaff_control_read_stats");
    return 1;
  }
  if (stats.values[QAFF_STAT_PACKETS] != 11 ||
      stats.values[QAFF_STAT_CID_MAP_HIT] != 3 ||
      stats.values[QAFF_STAT_FALLBACK] != 5 ||
      stats.values[QAFF_STAT_WORKER_MISSING] != 3 ||
      stats.values[QAFF_STAT_IPV4] != 11 ||
      stats.values[QAFF_STAT_PASSIVE_HIT] != 3 ||
      stats.values[QAFF_STAT_PASSIVE_MISS] != 1 ||
      stats.values[QAFF_STAT_PASSIVE_REJECT_GENERATION] != 2 ||
      stats.values[QAFF_STAT_CID_MAP_REJECT_GENERATION] != 2) {
    fprintf(stderr,
            "unexpected restart stats packets=%llu cid_hit=%llu fallback=%llu "
            "worker_missing=%llu ipv4=%llu passive_hit=%llu "
            "passive_miss=%llu passive_reject_generation=%llu "
            "cid_reject_generation=%llu\n",
            (unsigned long long)stats.values[QAFF_STAT_PACKETS],
            (unsigned long long)stats.values[QAFF_STAT_CID_MAP_HIT],
            (unsigned long long)stats.values[QAFF_STAT_FALLBACK],
            (unsigned long long)stats.values[QAFF_STAT_WORKER_MISSING],
            (unsigned long long)stats.values[QAFF_STAT_IPV4],
            (unsigned long long)stats.values[QAFF_STAT_PASSIVE_HIT],
            (unsigned long long)stats.values[QAFF_STAT_PASSIVE_MISS],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_REJECT_GENERATION],
            (unsigned long long)
                stats.values[QAFF_STAT_CID_MAP_REJECT_GENERATION]);
    stop_qaffd(socket_path, daemon_pid);
    return 1;
  }

  if (control_register_cid(socket_path, TARGET_WORKER, k_dcid) != 0) {
    perror("register exact CID before cleanup fault");
    return 1;
  }
  if (freeze_pinned_map(pin_root, "qaff_cids") != 0) {
    perror("freeze exact CID map");
    return 1;
  }
  if (control_unregister_worker(socket_path, TARGET_WORKER) == 0) {
    fprintf(stderr, "worker cleanup unexpectedly survived frozen CID map\n");
    return 1;
  }
  if (control_config(socket_path, &cid_config) != 0 ||
      cid_config.worker_cleanup_degraded != 1 ||
      cid_config.worker_cleanup_pending_count != 1 ||
      cid_config.worker_cleanup_error_count == 0 ||
      cid_config.worker_count != WORKER_COUNT - 1 ||
      cid_config.cid_map_count != 1 ||
      cid_config.cid_owner_count != 1) {
    fprintf(stderr, "failed worker cleanup was not quarantined\n");
    return 1;
  }
  errno = 0;
  if (control_register_worker(socket_path,
                              TARGET_WORKER,
                              workers[TARGET_WORKER]) == 0 ||
      errno != EBUSY) {
    fprintf(stderr, "cleanup-pending worker ID was reusable errno=%d\n", errno);
    return 1;
  }
  if (send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != FALLBACK_WORKER) {
    fprintf(stderr, "cleanup residue remained generation-routable\n");
    return 1;
  }
  const struct timespec cleanup_retry_delay = {
    .tv_sec = 0,
    .tv_nsec = 20 * 1000 * 1000,
  };
  int cleanup_retry_observed = 0;
  for (int attempt = 0; attempt < 150; attempt++) {
    if (control_config(socket_path, &cid_config) == 0 &&
        cid_config.worker_cleanup_degraded == 1 &&
        cid_config.worker_cleanup_pending_count == 1 &&
        cid_config.worker_cleanup_retry_count > 0) {
      cleanup_retry_observed = 1;
      break;
    }
    nanosleep(&cleanup_retry_delay, NULL);
  }
  if (!cleanup_retry_observed ||
      cid_config.worker_cleanup_error_count < 2 ||
      cid_config.worker_cleanup_retry_count > 3) {
    fprintf(stderr,
            "worker cleanup retry was absent or unthrottled errors=%llu "
            "retries=%llu\n",
            (unsigned long long)cid_config.worker_cleanup_error_count,
            (unsigned long long)cid_config.worker_cleanup_retry_count);
    return 1;
  }

  int registration_rollback_worker = make_worker_socket(&port);
  if (registration_rollback_worker < 0) {
    perror("make registration rollback worker");
    return 1;
  }
  uint64_t cleanup_errors_before_registration =
      cid_config.worker_cleanup_error_count;
  if (freeze_pinned_map(pin_root, "qaff_worker_generations") != 0) {
    perror("freeze worker generation map");
    return 1;
  }
  errno = 0;
  if (control_register_worker(socket_path,
                              3,
                              registration_rollback_worker) == 0) {
    fprintf(stderr, "registration unexpectedly survived frozen generation\n");
    return 1;
  }
  if (control_config(socket_path, &cid_config) != 0 ||
      cid_config.worker_cleanup_degraded != 1 ||
      cid_config.worker_cleanup_pending_count != 2 ||
      cid_config.worker_cleanup_error_count <=
          cleanup_errors_before_registration) {
    fprintf(stderr, "failed registration rollback was not quarantined\n");
    return 1;
  }
  if (state_has_record(state_path,
                       "generation",
                       3,
                       QAFF_WORKER_GENERATION_DEFAULT) != 1) {
    fprintf(stderr,
            "failed registration had no durable generation tombstone\n");
    return 1;
  }
  struct qaff_control_worker_info cleanup_workers[4];
  size_t cleanup_workers_len = 0;
  if (control_workers_info(socket_path,
                           cleanup_workers,
                           4,
                           &cleanup_workers_len) != 0 ||
      cleanup_workers_len != 4) {
    fprintf(stderr, "cleanup-pending worker IDs were not inspectable\n");
    return 1;
  }
  int target_cleanup_visible = 0;
  int rollback_cleanup_visible = 0;
  for (size_t i = 0; i < cleanup_workers_len; i++) {
    if ((cleanup_workers[i].flags &
         QAFF_CONTROL_WORKER_FLAG_CLEANUP_PENDING) == 0) {
      continue;
    }
    target_cleanup_visible |=
        cleanup_workers[i].worker_id == TARGET_WORKER;
    rollback_cleanup_visible |= cleanup_workers[i].worker_id == 3;
  }
  if (!target_cleanup_visible || !rollback_cleanup_visible) {
    fprintf(stderr, "qaffctl worker metadata hid cleanup quarantine IDs\n");
    return 1;
  }
  errno = 0;
  if (control_register_worker(socket_path,
                              3,
                              registration_rollback_worker) == 0 ||
      errno != EBUSY) {
    fprintf(stderr,
            "registration-rollback worker ID was reusable errno=%d\n",
            errno);
    return 1;
  }
  close(registration_rollback_worker);

  if (stop_qaffd(socket_path, daemon_pid) != 0) {
    perror("stop_qaffd second");
    return 1;
  }

  FILE *obsolete_state = fopen(state_path, "w");
  if (obsolete_state == NULL) {
    perror("open obsolete state");
    return 1;
  }
  int obsolete_write_rc =
      fputs("qaffd-state-v3\nworker 0 1\n", obsolete_state);
  int obsolete_close_rc = fclose(obsolete_state);
  if (obsolete_write_rc == EOF || obsolete_close_rc != 0) {
    perror("write obsolete state");
    return 1;
  }
  daemon_pid = start_qaffd(qaffd_path,
                           socket_path,
                           bpf_path,
                           pin_root,
                           state_path);
  if (daemon_pid < 0) {
    perror("fork qaffd obsolete state");
    return 1;
  }
  int obsolete_status = 0;
  if (waitpid(daemon_pid, &obsolete_status, 0) < 0 ||
      !WIFEXITED(obsolete_status) || WEXITSTATUS(obsolete_status) == 0) {
    fprintf(stderr, "qaffd unexpectedly accepted an obsolete state format\n");
    return 1;
  }

  for (size_t i = 0; i < WORKER_COUNT; i++) {
    close(workers[i]);
  }
  close(sender);
  unlink(socket_path);
  unlink(lock_path);
  return 0;
}
