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

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define TEST_SKIP 77
#define WORKER_COUNT 3
#define FALLBACK_WORKER 0
#define TARGET_WORKER 2

struct test_case {
  int family;
  const char *name;
};

struct sender_socket {
  int fd;
  uint16_t port;
};

static const uint8_t k_dcid[] = {
  0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_unknown_dcid[] = {
  0xba, 0xad, 0xf0, 0x0d, 0x12, 0x34, 0x56, 0x78,
};

static const uint8_t k_second_dcid[] = {
  0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04,
};

static const uint8_t k_passive_dcid[] = {
  0x70, 0x61, 0x73, 0x73, 0x0a, 0x0b, 0x0c, 0x0d,
};

static const uint8_t k_expiring_passive_dcid[] = {
  0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x01, 0x02,
};

static const uint8_t k_purged_passive_dcid[] = {
  0x70, 0x75, 0x72, 0x67, 0x65, 0x64, 0x01, 0x02,
};

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int make_worker_socket(int family, uint16_t *port) {
  int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0) {
    close(fd);
    return -1;
  }

  if (family == AF_INET) {
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
  } else {
    int v6only = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
      close(fd);
      return -1;
    }
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_loopback;
    addr6.sin6_port = htons(*port);
    if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
      close(fd);
      return -1;
    }
    if (*port == 0) {
      socklen_t len = sizeof(addr6);
      if (getsockname(fd, (struct sockaddr *)&addr6, &len) != 0) {
        close(fd);
        return -1;
      }
      *port = ntohs(addr6.sin6_port);
    }
  }

  if (set_nonblocking(fd) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int make_plain_udp_socket(int family) {
  int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  if (family == AF_INET) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      close(fd);
      return -1;
    }
  } else {
    int v6only = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
      close(fd);
      return -1;
    }
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_loopback;
    if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
      close(fd);
      return -1;
    }
  }

  return fd;
}

static int bind_sender_socket(int family, struct sender_socket *sender) {
  sender->fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sender->fd < 0) {
    return -1;
  }

  if (family == AF_INET) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(sender->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      close(sender->fd);
      return -1;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(sender->fd, (struct sockaddr *)&addr, &len) != 0) {
      close(sender->fd);
      return -1;
    }
    sender->port = ntohs(addr.sin_port);
  } else {
    int v6only = 1;
    if (setsockopt(sender->fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
      close(sender->fd);
      return -1;
    }
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_loopback;
    if (bind(sender->fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
      close(sender->fd);
      return -1;
    }
    socklen_t len = sizeof(addr6);
    if (getsockname(sender->fd, (struct sockaddr *)&addr6, &len) != 0) {
      close(sender->fd);
      return -1;
    }
    sender->port = ntohs(addr6.sin6_port);
  }
  return 0;
}

static int send_quic_like_packet(int fd,
                                 int family,
                                 uint16_t port,
                                 int short_header,
                                 const uint8_t *dcid) {
  uint8_t long_packet[] = {
    0xc3, 0x00, 0x00, 0x00, 0x01, 0x08,
    0, 0, 0, 0, 0, 0, 0, 0,
    0x00, 0x01, 0x02, 0x03, 0x04,
  };
  uint8_t short_packet[] = {
    0x43,
    0, 0, 0, 0, 0, 0, 0, 0,
    0x01, 0x02, 0x03, 0x04,
  };
  memcpy(long_packet + 6, dcid, sizeof(k_dcid));
  memcpy(short_packet + 1, dcid, sizeof(k_dcid));

  const uint8_t *packet = short_header ? short_packet : long_packet;
  size_t packet_len = short_header ? sizeof(short_packet) : sizeof(long_packet);

  if (family == AF_INET) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);
    return sendto(fd, packet, packet_len, 0,
                  (struct sockaddr *)&dst, sizeof(dst)) == (ssize_t)packet_len
               ? 0
               : -1;
  }

  struct sockaddr_in6 dst6;
  memset(&dst6, 0, sizeof(dst6));
  dst6.sin6_family = AF_INET6;
  dst6.sin6_addr = in6addr_loopback;
  dst6.sin6_port = htons(port);
  return sendto(fd, packet, packet_len, 0,
                (struct sockaddr *)&dst6, sizeof(dst6)) == (ssize_t)packet_len
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
    if (fds[i].revents & POLLIN) {
      if (recv(workers[i], buf, sizeof(buf), 0) > 0) {
        return (int)i;
      }
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

static uint64_t monotonic_now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static pid_t start_qaffd(const char *qaffd_path,
                         const char *socket_path,
                         const char *bpf_path) {
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
        "--passive-min-confidence",
        "3",
        "--passive-scan-interval-ms",
        "20",
        "--worker-heartbeat-timeout-ms",
        "500",
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

static int control_call_register_worker(const char *socket_path,
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

static int control_call_register_worker_lease(const char *socket_path,
                                              uint32_t worker_id,
                                              int worker_fd,
                                              int *lease_fd) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  if (qaff_control_register_worker_lease(fd, worker_id, worker_fd) != 0) {
    close(fd);
    return -1;
  }
  *lease_fd = fd;
  return 0;
}

static int control_call_worker_heartbeat(int lease_fd, uint32_t worker_id) {
  return qaff_control_worker_heartbeat(lease_fd, worker_id);
}

static int control_call_unregister_worker(const char *socket_path,
                                          uint32_t worker_id) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_unregister_worker(fd, worker_id);
  close(fd);
  return rc;
}

static int control_call_register_cid(const char *socket_path,
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

static int control_call_retire_cid(const char *socket_path, const uint8_t *cid) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_retire_cid(fd, cid, sizeof(k_dcid));
  close(fd);
  return rc;
}

static int control_call_register_passive_cid(const char *socket_path,
                                             uint32_t worker_id,
                                             const uint8_t *cid,
                                             uint8_t confidence,
                                             uint8_t source,
                                             uint64_t expires_after_ms) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  struct qaff_passive_cid_value value;
  memset(&value, 0, sizeof(value));
  value.worker_id = worker_id;
  value.confidence = confidence;
  value.source = source;
  if (expires_after_ms != 0) {
    uint64_t current_ns = monotonic_now_ns();
    if (current_ns == 0) {
      close(fd);
      errno = EIO;
      return -1;
    }
    value.expires_at_ns =
        current_ns + expires_after_ms * 1000000u;
  }
  int rc = qaff_control_register_passive_cid(fd,
                                             cid,
                                             sizeof(k_dcid),
                                             &value);
  close(fd);
  return rc;
}

static int control_call_retire_passive_cid(const char *socket_path,
                                           const uint8_t *cid) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_retire_passive_cid(fd, cid, sizeof(k_dcid));
  close(fd);
  return rc;
}

static int child_attempt_register_cid(const char *socket_path,
                                      uint32_t worker_id,
                                      const uint8_t *cid) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int rc = control_call_register_cid(socket_path, worker_id, cid);
    if (rc == 0) {
      _exit(0);
    }
    _exit(errno == EACCES ? 10 : 11);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 12;
}

static int child_attempt_unregister_worker(const char *socket_path,
                                           uint32_t worker_id) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int rc = control_call_unregister_worker(socket_path, worker_id);
    if (rc == 0) {
      _exit(0);
    }
    _exit(errno == EACCES ? 10 : 11);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 12;
}

static int child_attempt_register_worker(const char *socket_path,
                                         uint32_t worker_id,
                                         int worker_fd) {
  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    int rc = control_call_register_worker(socket_path, worker_id, worker_fd);
    if (rc == 0) {
      _exit(0);
    }
    _exit(errno == EACCES ? 10 : 11);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : 12;
}

static int control_call_read_stats(const char *socket_path,
                                   struct qaff_stats *stats) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_read_stats(fd, stats);
  close(fd);
  return rc;
}

static int control_call_cids(const char *socket_path,
                             struct qaff_control_config *config) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_cids(fd, config);
  close(fd);
  return rc;
}

static int control_call_workers(const char *socket_path,
                                uint32_t *workers,
                                size_t workers_cap,
                                size_t *workers_len) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_workers(fd, workers, workers_cap, workers_len);
  close(fd);
  return rc;
}

static int control_call_workers_info(
    const char *socket_path,
    struct qaff_control_worker_info *workers,
    size_t workers_cap,
    size_t *workers_len) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_workers_info(fd, workers, workers_cap, workers_len);
  close(fd);
  return rc;
}

static int expect_registered_workers(const char *socket_path,
                                     const char *case_name,
                                     const uint32_t *expected,
                                     size_t expected_len) {
  uint32_t registered_workers[QAFF_CONTROL_MAX_WORKERS];
  size_t registered_workers_len = 0;
  if (control_call_workers(socket_path,
                           registered_workers,
                           QAFF_CONTROL_MAX_WORKERS,
                           &registered_workers_len) != 0) {
    perror("qaff_control_workers");
    return -1;
  }
  if (registered_workers_len != expected_len) {
    fprintf(stderr,
            "%s: expected %zu registered workers, got %zu\n",
            case_name,
            expected_len,
            registered_workers_len);
    return -1;
  }
  for (size_t i = 0; i < registered_workers_len; i++) {
    if (registered_workers[i] != expected[i]) {
      fprintf(stderr,
              "%s: expected worker id %u at index %zu, got %u\n",
              case_name,
              expected[i],
              i,
              registered_workers[i]);
      return -1;
    }
  }
  return 0;
}

static int wait_registered_workers_len(const char *socket_path,
                                       size_t expected_len) {
  const struct timespec delay = {
    .tv_sec = 0,
    .tv_nsec = 20 * 1000 * 1000,
  };

  for (int attempt = 0; attempt < 100; attempt++) {
    uint32_t workers[QAFF_CONTROL_MAX_WORKERS];
    size_t workers_len = 0;
    if (control_call_workers(socket_path,
                             workers,
                             QAFF_CONTROL_MAX_WORKERS,
                             &workers_len) == 0 &&
        workers_len == expected_len) {
      return 0;
    }
    nanosleep(&delay, NULL);
  }

  errno = ETIMEDOUT;
  return -1;
}

static int run_case(const char *qaffd_path,
                    const char *bpf_path,
                    const struct test_case *test) {
  char socket_path[108];
  snprintf(socket_path, sizeof(socket_path),
           "/tmp/qaffd-control-%ld-%s.sock",
           (long)getpid(),
           test->name);

  unlink(socket_path);
  pid_t daemon_pid = start_qaffd(qaffd_path, socket_path, bpf_path);
  if (daemon_pid < 0) {
    perror("fork qaffd");
    return 1;
  }

  int ready_fd = connect_retry(socket_path, 100);
  if (ready_fd < 0) {
    int status = 0;
    if (waitpid(daemon_pid, &status, WNOHANG) == daemon_pid) {
      fprintf(stderr, "skipping: qaffd exited before accepting control connections\n");
      return TEST_SKIP;
    }
    kill(daemon_pid, SIGTERM);
    waitpid(daemon_pid, NULL, 0);
    perror("connect qaffd");
    return 1;
  }
  close(ready_fd);

  int lease_fd = -1;
  int leased_worker = -1;
  uint16_t lease_port = 0;
  leased_worker = make_worker_socket(test->family, &lease_port);
  if (leased_worker < 0) {
    perror("make_worker_socket leased_worker");
    return 1;
  }
  if (control_call_register_worker_lease(socket_path,
                                         0,
                                         leased_worker,
                                         &lease_fd) != 0) {
    perror("qaff_control_register_worker_lease");
    return 1;
  }

  const uint32_t leased_workers[] = {0};
  if (expect_registered_workers(socket_path,
                                test->name,
                                leased_workers,
                                sizeof(leased_workers) / sizeof(leased_workers[0])) != 0) {
    return 1;
  }
  if (control_call_worker_heartbeat(lease_fd, 0) != 0) {
    perror("qaff_control_worker_heartbeat");
    return 1;
  }

  struct qaff_control_worker_info worker_infos[QAFF_CONTROL_MAX_WORKERS];
  size_t worker_infos_len = 0;
  if (control_call_workers_info(socket_path,
                                worker_infos,
                                QAFF_CONTROL_MAX_WORKERS,
                                &worker_infos_len) != 0) {
    perror("qaff_control_workers_info");
    return 1;
  }
  if (worker_infos_len != 1 ||
      worker_infos[0].worker_id != 0 ||
      (worker_infos[0].flags & QAFF_CONTROL_WORKER_FLAG_LEASED) == 0 ||
      (worker_infos[0].flags & QAFF_CONTROL_WORKER_FLAG_CRED) == 0 ||
      worker_infos[0].uid != (uint32_t)getuid() ||
      worker_infos[0].gid != (uint32_t)getgid()) {
    fprintf(stderr, "%s: unexpected leased worker info\n", test->name);
    return 1;
  }
  if (control_call_register_cid(socket_path, 0, k_dcid) != 0) {
    perror("qaff_control_register_cid leased");
    return 1;
  }

  struct qaff_control_config cid_config;
  if (control_call_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids leased");
    return 1;
  }
  if (cid_config.cid_map_count != 1 ||
      cid_config.cid_owner_count != 1 ||
      cid_config.cid_index_mismatch != 0) {
    fprintf(stderr, "%s: unexpected leased CID counts\n", test->name);
    return 1;
  }

  close(lease_fd);
  lease_fd = -1;
  close(leased_worker);
  leased_worker = -1;
  if (wait_registered_workers_len(socket_path, 0) != 0) {
    perror("wait lease cleanup");
    return 1;
  }
  if (control_call_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids after lease close");
    return 1;
  }
  if (cid_config.cid_map_count != 0 ||
      cid_config.cid_owner_count != 0 ||
      cid_config.cid_index_mismatch != 0) {
    fprintf(stderr, "%s: leaked CID after worker lease close\n", test->name);
    return 1;
  }

  lease_port = 0;
  leased_worker = make_worker_socket(test->family, &lease_port);
  if (leased_worker < 0) {
    perror("make_worker_socket timeout_worker");
    return 1;
  }
  if (control_call_register_worker_lease(socket_path,
                                         0,
                                         leased_worker,
                                         &lease_fd) != 0) {
    perror("qaff_control_register_worker_lease timeout");
    return 1;
  }
  if (control_call_register_cid(socket_path, 0, k_dcid) != 0) {
    perror("qaff_control_register_cid timeout");
    return 1;
  }
  if (wait_registered_workers_len(socket_path, 0) != 0) {
    perror("wait heartbeat timeout cleanup");
    return 1;
  }
  close(lease_fd);
  lease_fd = -1;
  close(leased_worker);
  leased_worker = -1;
  if (control_call_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids after heartbeat timeout");
    return 1;
  }
  if (cid_config.cid_map_count != 0 ||
      cid_config.cid_owner_count != 0 ||
      cid_config.cid_index_mismatch != 0) {
    fprintf(stderr, "%s: leaked CID after heartbeat timeout\n", test->name);
    return 1;
  }

  int workers[WORKER_COUNT] = {-1, -1, -1};

  int plain_udp = make_plain_udp_socket(test->family);
  if (plain_udp < 0) {
    perror("make_plain_udp_socket");
    return 1;
  }
  if (control_call_register_worker(socket_path, 10, plain_udp) == 0) {
    fprintf(stderr,
            "%s: unexpectedly registered worker without SO_REUSEPORT\n",
            test->name);
    return 1;
  }
  close(plain_udp);

  uint16_t port = 0;
  workers[0] = make_worker_socket(test->family, &port);
  if (workers[0] < 0) {
    perror("make_worker_socket");
    return 1;
  }
  if (control_call_register_worker(socket_path, 0, workers[0]) != 0) {
    perror("qaff_control_register_worker first");
    return 1;
  }

  uint16_t other_port = 0;
  int wrong_listener = make_worker_socket(test->family, &other_port);
  if (wrong_listener < 0) {
    perror("make_worker_socket wrong_listener");
    return 1;
  }
  if (control_call_register_worker(socket_path, 10, wrong_listener) == 0) {
    fprintf(stderr,
            "%s: unexpectedly registered worker bound to another listener\n",
            test->name);
    return 1;
  }
  close(wrong_listener);

  for (uint32_t i = 1; i < WORKER_COUNT; i++) {
    workers[i] = make_worker_socket(test->family, &port);
    if (workers[i] < 0) {
      perror("make_worker_socket");
      return 1;
    }
    if (control_call_register_worker(socket_path, i, workers[i]) != 0) {
      perror("qaff_control_register_worker");
      return 1;
    }
  }

  const uint32_t all_workers[] = {0, 1, 2};
  if (expect_registered_workers(socket_path,
                                test->name,
                                all_workers,
                                sizeof(all_workers) / sizeof(all_workers[0])) != 0) {
    return 1;
  }

  if (child_attempt_register_worker(socket_path, TARGET_WORKER, workers[TARGET_WORKER]) != 10) {
    fprintf(stderr,
            "%s: child process unexpectedly replaced worker %d\n",
            test->name,
            TARGET_WORKER);
    return 1;
  }
  if (child_attempt_register_cid(socket_path, TARGET_WORKER, k_dcid) != 10) {
    fprintf(stderr,
            "%s: child process unexpectedly registered CID for worker %d\n",
            test->name,
            TARGET_WORKER);
    return 1;
  }
  if (child_attempt_unregister_worker(socket_path, TARGET_WORKER) != 10) {
    fprintf(stderr,
            "%s: child process unexpectedly unregistered worker %d\n",
            test->name,
            TARGET_WORKER);
    return 1;
  }

  if (control_call_unregister_worker(socket_path, 1) != 0) {
    perror("qaff_control_unregister_worker");
    return 1;
  }

  const uint32_t after_worker_1_removed[] = {0, 2};
  if (expect_registered_workers(
          socket_path,
          test->name,
          after_worker_1_removed,
          sizeof(after_worker_1_removed) / sizeof(after_worker_1_removed[0])) != 0) {
    return 1;
  }

  if (control_call_register_cid(socket_path, TARGET_WORKER, k_dcid) != 0) {
    perror("qaff_control_register_cid");
    return 1;
  }
  if (control_call_register_cid(socket_path, TARGET_WORKER, k_second_dcid) != 0) {
    perror("qaff_control_register_cid second");
    return 1;
  }

  if (child_attempt_register_cid(socket_path, TARGET_WORKER, k_unknown_dcid) != 10) {
    fprintf(stderr,
            "%s: child process unexpectedly registered second CID for worker %d\n",
            test->name,
            TARGET_WORKER);
    return 1;
  }
  pid_t retire_pid = fork();
  if (retire_pid < 0) {
    perror("fork retire child");
    return 1;
  }
  if (retire_pid == 0) {
    int rc = control_call_retire_cid(socket_path, k_dcid);
    if (rc == 0) {
      _exit(0);
    }
    _exit(errno == EACCES ? 10 : 11);
  }
  int retire_status = 0;
  if (waitpid(retire_pid, &retire_status, 0) < 0 ||
      !WIFEXITED(retire_status) ||
      WEXITSTATUS(retire_status) != 10) {
    fprintf(stderr,
            "%s: child process unexpectedly retired CID for worker %d\n",
            test->name,
            TARGET_WORKER);
    return 1;
  }

  if (control_call_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids");
    return 1;
  }
  if (cid_config.cid_map_count != 2 ||
      cid_config.cid_owner_count != 2 ||
      cid_config.cid_index_mismatch != 0) {
    fprintf(stderr, "%s: unexpected CID counts after registration\n", test->name);
    return 1;
  }

  struct sender_socket senders[2] = {{.fd = -1}, {.fd = -1}};
  if (bind_sender_socket(test->family, &senders[0]) != 0 ||
      bind_sender_socket(test->family, &senders[1]) != 0) {
    perror("bind_sender_socket");
    return 1;
  }
  if (senders[0].port == senders[1].port) {
    fprintf(stderr, "%s: sender ports unexpectedly match\n", test->name);
    return 1;
  }

  for (int i = 0; i < 2; i++) {
    if (send_quic_like_packet(senders[i].fd,
                              test->family,
                              port,
                              i == 1,
                              k_dcid) != 0) {
      perror("send_quic_like_packet");
      return 1;
    }
    int worker = receive_worker(workers, WORKER_COUNT);
    if (worker != TARGET_WORKER) {
      fprintf(stderr, "%s: expected worker %d, got %d\n",
              test->name, TARGET_WORKER, worker);
      return 1;
    }
  }

  if (control_call_register_passive_cid(socket_path,
                                        TARGET_WORKER,
                                        k_passive_dcid,
                                        QAFF_PASSIVE_CONFIDENCE_HIGH,
                                        QAFF_PASSIVE_SOURCE_EGRESS,
                                        0) != 0) {
    perror("qaff_control_register_passive_cid");
    return 1;
  }
  if (send_quic_like_packet(senders[0].fd,
                            test->family,
                            port,
                            0,
                            k_passive_dcid) != 0) {
    perror("send passive packet");
    return 1;
  }
  int passive_worker = receive_worker(workers, WORKER_COUNT);
  if (passive_worker != TARGET_WORKER) {
    fprintf(stderr, "%s: expected passive worker %d, got %d\n",
            test->name, TARGET_WORKER, passive_worker);
    return 1;
  }

  if (control_call_retire_passive_cid(socket_path, k_passive_dcid) != 0) {
    perror("qaff_control_retire_passive_cid");
    return 1;
  }

  if (control_call_register_passive_cid(socket_path,
                                        TARGET_WORKER,
                                        k_expiring_passive_dcid,
                                        QAFF_PASSIVE_CONFIDENCE_LOW,
                                        QAFF_PASSIVE_SOURCE_INGRESS,
                                        40) != 0) {
    perror("qaff_control_register_passive_cid expiring");
    return 1;
  }
  const struct timespec passive_expiry_delay = {
    .tv_sec = 0,
    .tv_nsec = 120 * 1000 * 1000,
  };
  nanosleep(&passive_expiry_delay, NULL);
  if (control_call_retire_passive_cid(socket_path,
                                      k_expiring_passive_dcid) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: expired passive CID was not cleaned up\n", test->name);
    return 1;
  }

  if (control_call_register_passive_cid(socket_path,
                                        TARGET_WORKER,
                                        k_purged_passive_dcid,
                                        QAFF_PASSIVE_CONFIDENCE_HIGH,
                                        QAFF_PASSIVE_SOURCE_EGRESS,
                                        0) != 0) {
    perror("qaff_control_register_passive_cid purge");
    return 1;
  }
  if (send_quic_like_packet(senders[1].fd,
                            test->family,
                            port,
                            0,
                            k_passive_dcid) != 0) {
    perror("send retired passive packet");
    return 1;
  }
  int retired_passive_worker = receive_worker(workers, WORKER_COUNT);
  if (retired_passive_worker != FALLBACK_WORKER) {
    fprintf(stderr, "%s: expected retired passive fallback worker %d, got %d\n",
            test->name, FALLBACK_WORKER, retired_passive_worker);
    return 1;
  }

  if (send_quic_like_packet(senders[0].fd,
                            test->family,
                            port,
                            0,
                            k_unknown_dcid) != 0) {
    perror("send fallback packet");
    return 1;
  }
  int fallback_worker = receive_worker(workers, WORKER_COUNT);
  if (fallback_worker != FALLBACK_WORKER) {
    fprintf(stderr, "%s: expected fallback worker %d, got %d\n",
            test->name, FALLBACK_WORKER, fallback_worker);
    return 1;
  }

  if (control_call_unregister_worker(socket_path, TARGET_WORKER) != 0) {
    perror("qaff_control_unregister_worker target");
    return 1;
  }

  const uint32_t after_target_removed[] = {0};
  if (expect_registered_workers(
          socket_path,
          test->name,
          after_target_removed,
          sizeof(after_target_removed) / sizeof(after_target_removed[0])) != 0) {
    return 1;
  }

  if (control_call_register_cid(socket_path, TARGET_WORKER, k_dcid) == 0) {
    fprintf(stderr,
            "%s: unexpectedly registered CID to unregistered worker\n",
            test->name);
    return 1;
  }
  if (control_call_register_passive_cid(socket_path,
                                        TARGET_WORKER,
                                        k_passive_dcid,
                                        QAFF_PASSIVE_CONFIDENCE_HIGH,
                                        QAFF_PASSIVE_SOURCE_EGRESS,
                                        0) == 0) {
    fprintf(stderr,
            "%s: unexpectedly registered passive CID to unregistered worker\n",
            test->name);
    return 1;
  }
  if (control_call_retire_passive_cid(socket_path,
                                      k_purged_passive_dcid) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: worker passive CID was not purged\n", test->name);
    return 1;
  }

  if (control_call_cids(socket_path, &cid_config) != 0) {
    perror("qaff_control_cids after unregister");
    return 1;
  }
  if (cid_config.cid_map_count != 0 ||
      cid_config.cid_owner_count != 0 ||
      cid_config.cid_index_mismatch != 0 ||
      cid_config.passive_entry_count != 0 ||
      cid_config.passive_entry_capacity != 1024 * 1024 ||
      cid_config.passive_expired_count != 1 ||
      cid_config.passive_worker_purged_count != 1 ||
      cid_config.passive_expiry_initialized_count != 0 ||
      cid_config.passive_cleanup_error_count != 0 ||
      cid_config.passive_scan_interval_ms != 20) {
    fprintf(stderr,
            "%s: unexpected CID counts after worker unregister\n",
            test->name);
    return 1;
  }

  if (send_quic_like_packet(senders[1].fd,
                            test->family,
                            port,
                            1,
                            k_dcid) != 0) {
    perror("send stale worker packet");
    return 1;
  }
  int stale_worker = receive_worker(workers, WORKER_COUNT);
  if (stale_worker != FALLBACK_WORKER) {
    fprintf(stderr, "%s: expected stale CID fallback worker %d, got %d\n",
            test->name, FALLBACK_WORKER, stale_worker);
    return 1;
  }

  if (send_quic_like_packet(senders[0].fd,
                            test->family,
                            port,
                            1,
                            k_second_dcid) != 0) {
    perror("send second stale worker packet");
    return 1;
  }
  int second_stale_worker = receive_worker(workers, WORKER_COUNT);
  if (second_stale_worker != FALLBACK_WORKER) {
    fprintf(stderr, "%s: expected second stale CID fallback worker %d, got %d\n",
            test->name, FALLBACK_WORKER, second_stale_worker);
    return 1;
  }

  struct qaff_stats stats;
  if (control_call_read_stats(socket_path, &stats) != 0) {
    perror("qaff_control_read_stats");
    return 1;
  }

  enum qaff_stat_index family_stat =
      test->family == AF_INET ? QAFF_STAT_IPV4 : QAFF_STAT_IPV6;
  if (stats.values[QAFF_STAT_PACKETS] != 7 ||
      stats.values[QAFF_STAT_CID_MAP_HIT] != 2 ||
      stats.values[QAFF_STAT_FALLBACK] != 4 ||
      stats.values[QAFF_STAT_PARSE_ERROR] != 0 ||
      stats.values[QAFF_STAT_WORKER_MISSING] != 0 ||
      stats.values[family_stat] != 7 ||
      stats.values[QAFF_STAT_PASSIVE_HIT] != 1 ||
      stats.values[QAFF_STAT_PASSIVE_MISS] != 4 ||
      stats.values[QAFF_STAT_PASSIVE_REJECT_CONFIDENCE] != 0 ||
      stats.values[QAFF_STAT_PASSIVE_REJECT_GENERATION] != 0) {
    fprintf(stderr, "%s: unexpected qaffd stats\n", test->name);
    return 1;
  }

  if (stop_qaffd(socket_path, daemon_pid) != 0) {
    perror("stop_qaffd");
    return 1;
  }

  for (size_t i = 0; i < WORKER_COUNT; i++) {
    close(workers[i]);
  }
  close(senders[0].fd);
  close(senders[1].fd);
  unlink(socket_path);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s PATH_TO_QAFFD PATH_TO_BPF_OBJECT\n", argv[0]);
    return 2;
  }

  const struct test_case tests[] = {
    {.family = AF_INET, .name = "ipv4"},
    {.family = AF_INET6, .name = "ipv6"},
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    int rc = run_case(argv[1], argv[2], &tests[i]);
    if (rc != 0) {
      return rc;
    }
  }
  return 0;
}
