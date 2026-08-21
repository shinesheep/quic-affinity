#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"

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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define TEST_SKIP 77
#define WORKER_COUNT 3
#define FALLBACK_WORKER 0
#define TARGET_WORKER 2

static const uint8_t k_dcid[] = {
  0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_passive_dcid[] = {
  0x70, 0x61, 0x73, 0x73, 0x0a, 0x0b, 0x0c, 0x0d,
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
    0, 0, 0, 0, 0, 0, 0, 0,
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

static int receive_worker(const int *workers, size_t count) {
  struct pollfd fds[WORKER_COUNT];
  for (size_t i = 0; i < count; i++) {
    fds[i].fd = workers[i];
    fds[i].events = POLLIN;
    fds[i].revents = 0;
  }

  if (poll(fds, count, 1000) <= 0) {
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

static pid_t start_qaffd(const char *qaffd_path,
                         const char *socket_path,
                         const char *bpf_path,
                         const char *pin_root,
                         const char *state_path) {
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
        "8",
        "--passive-affinity",
        "--pin-root",
        pin_root,
        "--state-path",
        state_path,
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

static int control_register_worker(const char *socket_path,
                                   uint32_t worker_id,
                                   int worker_fd) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_register_worker(fd, worker_id, worker_fd);
  close(fd);
  return rc;
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

  if (stop_qaffd(socket_path, daemon_pid) != 0) {
    perror("stop_qaffd first");
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

  struct qaff_control_config cid_config;
  if (control_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids restart");
    return 1;
  }
  if (cid_config.cid_map_count != 1 ||
      cid_config.cid_owner_count != 1 ||
      cid_config.cid_index_mismatch != 0) {
    fprintf(stderr, "unexpected restored CID counts\n");
    return 1;
  }

  if (send_quic_like_packet(sender, port, k_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER) {
    fprintf(stderr, "expected restarted qaffd CID hit on worker %d\n", TARGET_WORKER);
    return 1;
  }

  if (control_register_passive_cid(socket_path,
                                   TARGET_WORKER,
                                   k_passive_dcid) != 0) {
    perror("qaff_control_register_passive_cid");
    return 1;
  }

  if (send_quic_like_packet(sender, port, k_passive_dcid) != 0 ||
      receive_worker(workers, WORKER_COUNT) != TARGET_WORKER) {
    fprintf(stderr, "expected passive CID hit on worker %d\n", TARGET_WORKER);
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

  close(workers[TARGET_WORKER]);
  workers[TARGET_WORKER] = make_worker_socket(&port);
  if (workers[TARGET_WORKER] < 0) {
    perror("make replacement worker socket");
    return 1;
  }
  if (control_register_worker(socket_path,
                              TARGET_WORKER,
                              workers[TARGET_WORKER]) != 0) {
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
  if (stats.values[QAFF_STAT_PACKETS] != 5 ||
      stats.values[QAFF_STAT_CID_MAP_HIT] != 2 ||
      stats.values[QAFF_STAT_FALLBACK] != 2 ||
      stats.values[QAFF_STAT_WORKER_MISSING] != 0 ||
      stats.values[QAFF_STAT_IPV4] != 5 ||
      stats.values[QAFF_STAT_PASSIVE_HIT] != 1 ||
      stats.values[QAFF_STAT_PASSIVE_MISS] != 1 ||
      stats.values[QAFF_STAT_PASSIVE_REJECT_GENERATION] != 1) {
    fprintf(stderr,
            "unexpected restart stats packets=%llu cid_hit=%llu fallback=%llu "
            "ipv4=%llu passive_hit=%llu passive_miss=%llu "
            "passive_reject_generation=%llu\n",
            (unsigned long long)stats.values[QAFF_STAT_PACKETS],
            (unsigned long long)stats.values[QAFF_STAT_CID_MAP_HIT],
            (unsigned long long)stats.values[QAFF_STAT_FALLBACK],
            (unsigned long long)stats.values[QAFF_STAT_IPV4],
            (unsigned long long)stats.values[QAFF_STAT_PASSIVE_HIT],
            (unsigned long long)stats.values[QAFF_STAT_PASSIVE_MISS],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_REJECT_GENERATION]);
    stop_qaffd(socket_path, daemon_pid);
    return 1;
  }

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
