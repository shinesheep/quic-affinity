#include "quic_affinity/control.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define WORKER_COUNT 3

static int make_udp_reuseport_socket(uint16_t *port) {
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

  return fd;
}

static int control_connect_once(const char *socket_path) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    perror("qaff_control_connect");
  }
  return fd;
}

static int register_worker(const char *socket_path,
                           uint32_t worker_id,
                           int worker_fd) {
  int control_fd = control_connect_once(socket_path);
  if (control_fd < 0) {
    return -1;
  }
  int rc = qaff_control_register_worker(control_fd, worker_id, worker_fd);
  if (rc != 0) {
    perror("qaff_control_register_worker");
  }
  close(control_fd);
  return rc;
}

static int register_cid(const char *socket_path,
                        uint32_t worker_id,
                        const uint8_t *cid,
                        size_t cid_len) {
  int control_fd = control_connect_once(socket_path);
  if (control_fd < 0) {
    return -1;
  }
  int rc = qaff_control_register_cid(control_fd, worker_id, cid, cid_len);
  if (rc != 0) {
    perror("qaff_control_register_cid");
  }
  close(control_fd);
  return rc;
}

static int read_stats(const char *socket_path) {
  int control_fd = control_connect_once(socket_path);
  if (control_fd < 0) {
    return -1;
  }

  struct qaff_stats stats;
  int rc = qaff_control_read_stats(control_fd, &stats);
  if (rc != 0) {
    perror("qaff_control_read_stats");
    close(control_fd);
    return -1;
  }

  for (uint32_t i = 0; i < QAFF_STAT_MAX; i++) {
    printf("%s=%llu\n",
           qaff_stat_name(i),
           (unsigned long long)stats.values[i]);
  }
  close(control_fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s QAFFD_SOCKET\n", argv[0]);
    return 2;
  }

  const char *socket_path = argv[1];
  int workers[WORKER_COUNT] = {-1, -1, -1};
  uint16_t port = 0;

  for (uint32_t worker_id = 0; worker_id < WORKER_COUNT; worker_id++) {
    workers[worker_id] = make_udp_reuseport_socket(&port);
    if (workers[worker_id] < 0) {
      perror("make_udp_reuseport_socket");
      return 1;
    }
    if (register_worker(socket_path, worker_id, workers[worker_id]) != 0) {
      return 1;
    }
  }

  const uint8_t example_server_cid[] = {
    0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
  };
  const uint32_t owner_worker = 2;
  if (register_cid(socket_path,
                   owner_worker,
                   example_server_cid,
                   sizeof(example_server_cid)) != 0) {
    return 1;
  }

  printf("listener=127.0.0.1:%u\n", port);
  printf("registered example CID to worker=%u through qaffd\n", owner_worker);
  if (read_stats(socket_path) != 0) {
    return 1;
  }

  for (size_t i = 0; i < WORKER_COUNT; i++) {
    close(workers[i]);
  }
  return 0;
}

