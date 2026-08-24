#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define WORKER_COUNT 3
#define TARGET_WORKER 2
#define CONFLICT_WORKER 1
#define FALLBACK_WORKER 0
#define TEST_SKIP 77

static const uint8_t k_client_cid[] = {
  0xc1, 0x1e, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
};

static const uint8_t k_server_cid[] = {
  0x5e, 0x12, 0x51, 0xd0, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_conflict_server_cid[] = {
  0xcf, 0x11, 0xc7, 0x01, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_retry_server_cid[] = {
  0x12, 0xe7, 0x12, 0xd0, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_ipv4_options_server_cid[] = {
  0x14, 0x04, 0x71, 0x05, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_vn_scid[] = {
  0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_0rtt_scid[] = {
  0x00, 0x12, 0x77, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
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

static int make_client_socket(uint16_t *port) {
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
  socklen_t len = sizeof(addr);
  if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
    close(fd);
    return -1;
  }
  *port = ntohs(addr.sin_port);
  return fd;
}

static size_t make_long_packet(uint8_t *packet,
                               size_t packet_len,
                               const uint8_t *dcid,
                               size_t dcid_len,
                               const uint8_t *scid,
                               size_t scid_len) {
  if (packet_len < 1 + 4 + 1 + dcid_len + 1 + scid_len + 4) {
    return 0;
  }

  size_t off = 0;
  packet[off++] = 0xc3;
  packet[off++] = 0x00;
  packet[off++] = 0x00;
  packet[off++] = 0x00;
  packet[off++] = 0x01;
  packet[off++] = (uint8_t)dcid_len;
  memcpy(packet + off, dcid, dcid_len);
  off += dcid_len;
  packet[off++] = (uint8_t)scid_len;
  memcpy(packet + off, scid, scid_len);
  off += scid_len;
  packet[off++] = 0x00;
  packet[off++] = 0x01;
  packet[off++] = 0x02;
  packet[off++] = 0x03;
  return off;
}

static void set_long_header_type_and_version(uint8_t *packet,
                                             uint8_t first,
                                             uint32_t version) {
  packet[0] = first;
  packet[1] = (uint8_t)(version >> 24);
  packet[2] = (uint8_t)(version >> 16);
  packet[3] = (uint8_t)(version >> 8);
  packet[4] = (uint8_t)version;
}

static int send_packet_to_port(int fd,
                               uint16_t port,
                               const uint8_t *packet,
                               size_t packet_len) {
  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(port);
  ssize_t sent = sendto(fd,
                        packet,
                        packet_len,
                        0,
                        (struct sockaddr *)&dst,
                        sizeof(dst));
  return sent == (ssize_t)packet_len ? 0 : -1;
}

static int receive_worker(const int *workers) {
  struct pollfd fds[WORKER_COUNT];
  for (size_t i = 0; i < WORKER_COUNT; i++) {
    fds[i].fd = workers[i];
    fds[i].events = POLLIN;
    fds[i].revents = 0;
  }

  int rc = poll(fds, WORKER_COUNT, 1000);
  if (rc <= 0) {
    return -1;
  }

  uint8_t buf[2048];
  for (size_t i = 0; i < WORKER_COUNT; i++) {
    if (fds[i].revents & POLLIN) {
      if (recv(workers[i], buf, sizeof(buf), 0) > 0) {
        return (int)i;
      }
    }
  }
  return -1;
}

static int register_worker(const char *socket_path,
                           uint32_t worker_id,
                           int worker_fd) {
  int control_fd = qaff_control_connect(socket_path);
  if (control_fd < 0) {
    return -1;
  }
  int rc = qaff_control_register_worker(control_fd, worker_id, worker_fd);
  close(control_fd);
  return rc;
}

static int read_stats(const char *socket_path, struct qaff_stats *stats) {
  int control_fd = qaff_control_connect(socket_path);
  if (control_fd < 0) {
    return -1;
  }
  int rc = qaff_control_read_stats(control_fd, stats);
  close(control_fd);
  return rc;
}

static int register_passive_cid(const char *socket_path,
                                uint32_t worker_id,
                                const uint8_t *cid,
                                size_t cid_len) {
  int control_fd = qaff_control_connect(socket_path);
  if (control_fd < 0) {
    return -1;
  }
  struct qaff_passive_cid_value value;
  memset(&value, 0, sizeof(value));
  value.worker_id = worker_id;
  value.confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  value.source = QAFF_PASSIVE_SOURCE_EGRESS;
  int rc = qaff_control_register_passive_cid(control_fd,
                                             cid,
                                             cid_len,
                                             &value);
  close(control_fd);
  return rc;
}

static int observe_and_route_server_cid(const int *workers,
                                        int client_fd,
                                        uint16_t client_port,
                                        uint16_t listener_port,
                                        uint8_t outbound_first,
                                        uint32_t outbound_version,
                                        const uint8_t *server_cid,
                                        size_t server_cid_len) {
  uint8_t packet[128];
  size_t packet_len = make_long_packet(packet,
                                       sizeof(packet),
                                       k_client_cid,
                                       sizeof(k_client_cid),
                                       server_cid,
                                       server_cid_len);
  if (packet_len == 0) {
    errno = EINVAL;
    return -1;
  }
  set_long_header_type_and_version(packet,
                                   outbound_first,
                                   outbound_version);
  if (send_packet_to_port(workers[TARGET_WORKER],
                          client_port,
                          packet,
                          packet_len) != 0) {
    return -1;
  }

  packet_len = make_long_packet(packet,
                                sizeof(packet),
                                server_cid,
                                server_cid_len,
                                k_client_cid,
                                sizeof(k_client_cid));
  if (packet_len == 0 ||
      send_packet_to_port(client_fd,
                          listener_port,
                          packet,
                          packet_len) != 0) {
    return -1;
  }
  return receive_worker(workers);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s QAFFD_SOCKET\n", argv[0]);
    return 2;
  }

  const char *socket_path = argv[1];
  uint16_t listener_port = 0;
  uint16_t client_port = 0;
  int workers[WORKER_COUNT] = {-1, -1, -1};
  int client_fd = -1;

  for (uint32_t i = 0; i < WORKER_COUNT; i++) {
    workers[i] = make_worker_socket(&listener_port);
    if (workers[i] < 0) {
      perror("make_worker_socket");
      return 1;
    }
    if (register_worker(socket_path, i, workers[i]) != 0) {
      perror("qaff_control_register_worker");
      return 1;
    }
  }

  client_fd = make_client_socket(&client_port);
  if (client_fd < 0) {
    perror("make_client_socket");
    return 1;
  }

  uint8_t packet[128];
  size_t packet_len = make_long_packet(packet,
                                       sizeof(packet),
                                       k_client_cid,
                                       sizeof(k_client_cid),
                                       k_server_cid,
                                       sizeof(k_server_cid));
  if (packet_len == 0) {
    fprintf(stderr, "failed to build server long-header packet\n");
    return 1;
  }
  if (send_packet_to_port(workers[TARGET_WORKER],
                          client_port,
                          packet,
                          packet_len) != 0) {
    perror("send server packet");
    return 1;
  }

  packet_len = make_long_packet(packet,
                                sizeof(packet),
                                k_server_cid,
                                sizeof(k_server_cid),
                                k_client_cid,
                                sizeof(k_client_cid));
  if (packet_len == 0) {
    fprintf(stderr, "failed to build client long-header packet\n");
    return 1;
  }
  if (send_packet_to_port(client_fd, listener_port, packet, packet_len) != 0) {
    perror("send client packet");
    return 1;
  }

  int worker = receive_worker(workers);
  if (worker != TARGET_WORKER) {
    fprintf(stderr,
            "expected egress-learned packet on worker %d, got %d\n",
            TARGET_WORKER,
            worker);
    return 1;
  }

  if (register_passive_cid(socket_path,
                           CONFLICT_WORKER,
                           k_conflict_server_cid,
                           sizeof(k_conflict_server_cid)) != 0) {
    perror("qaff_control_register_passive_cid conflict");
    return 1;
  }
  packet_len = make_long_packet(packet,
                                sizeof(packet),
                                k_client_cid,
                                sizeof(k_client_cid),
                                k_conflict_server_cid,
                                sizeof(k_conflict_server_cid));
  if (packet_len == 0 ||
      send_packet_to_port(workers[TARGET_WORKER],
                          client_port,
                          packet,
                          packet_len) != 0) {
    perror("send conflicting server packet");
    return 1;
  }

  packet_len = make_long_packet(packet,
                                sizeof(packet),
                                k_conflict_server_cid,
                                sizeof(k_conflict_server_cid),
                                k_client_cid,
                                sizeof(k_client_cid));
  if (packet_len == 0 ||
      send_packet_to_port(client_fd, listener_port, packet, packet_len) != 0) {
    perror("send conflicting client packet");
    return 1;
  }
  worker = receive_worker(workers);
  if (worker != CONFLICT_WORKER) {
    fprintf(stderr,
            "egress learning replaced passive owner %d with worker %d\n",
            CONFLICT_WORKER,
            worker);
    return 1;
  }

  worker = observe_and_route_server_cid(workers,
                                        client_fd,
                                        client_port,
                                        listener_port,
                                        0xf3,
                                        1,
                                        k_retry_server_cid,
                                        sizeof(k_retry_server_cid));
  if (worker != TARGET_WORKER) {
    fprintf(stderr, "QUIC v1 Retry SCID was not learned, got worker %d\n",
            worker);
    return 1;
  }

  const uint8_t ip_options[] = {1, 1, 1, 0};
  if (setsockopt(workers[TARGET_WORKER],
                 IPPROTO_IP,
                 IP_OPTIONS,
                 ip_options,
                 sizeof(ip_options)) != 0) {
    perror("setsockopt IP_OPTIONS");
    return 1;
  }
  worker = observe_and_route_server_cid(workers,
                                        client_fd,
                                        client_port,
                                        listener_port,
                                        0xc3,
                                        1,
                                        k_ipv4_options_server_cid,
                                        sizeof(k_ipv4_options_server_cid));
  int options_errno = errno;
  if (setsockopt(workers[TARGET_WORKER],
                 IPPROTO_IP,
                 IP_OPTIONS,
                 NULL,
                 0) != 0) {
    perror("clear IP_OPTIONS");
    return 1;
  }
  errno = options_errno;
  if (worker != TARGET_WORKER) {
    fprintf(stderr, "IPv4-options SCID was not learned, got worker %d\n",
            worker);
    return 1;
  }

  worker = observe_and_route_server_cid(workers,
                                        client_fd,
                                        client_port,
                                        listener_port,
                                        0xc3,
                                        0,
                                        k_vn_scid,
                                        sizeof(k_vn_scid));
  if (worker != FALLBACK_WORKER) {
    fprintf(stderr,
            "Version Negotiation SCID was learned by worker %d\n",
            worker);
    return 1;
  }

  worker = observe_and_route_server_cid(workers,
                                        client_fd,
                                        client_port,
                                        listener_port,
                                        0xd3,
                                        1,
                                        k_0rtt_scid,
                                        sizeof(k_0rtt_scid));
  if (worker != FALLBACK_WORKER) {
    fprintf(stderr, "server 0-RTT SCID was learned by worker %d\n", worker);
    return 1;
  }

  const uint8_t short_packet[] = {
    0x43, 0x52, 0x10, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
  };
  if (send_packet_to_port(workers[TARGET_WORKER],
                          client_port,
                          short_packet,
                          sizeof(short_packet)) != 0) {
    perror("send short-header server packet");
    return 1;
  }

  struct qaff_stats stats;
  if (read_stats(socket_path, &stats) != 0) {
    perror("qaff_control_read_stats");
    return 1;
  }
  if (stats.values[QAFF_STAT_PASSIVE_EGRESS_LEARN] < 3 ||
      stats.values[QAFF_STAT_PASSIVE_HIT] < 4 ||
      stats.values[QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_HIT] < 1 ||
      stats.values[QAFF_STAT_PASSIVE_EGRESS_CONFLICT] < 1 ||
      stats.values[QAFF_STAT_PASSIVE_EGRESS_REJECT_VERSION] < 1 ||
      stats.values[QAFF_STAT_PASSIVE_EGRESS_REJECT_TYPE] < 1 ||
      stats.values[QAFF_STAT_PASSIVE_EGRESS_SHORT_HEADER] < 1 ||
      stats.values[QAFF_STAT_PASSIVE_EGRESS_MAP_UPDATE_ERROR] != 0) {
    fprintf(stderr,
            "unexpected egress stats learn=%llu hit=%llu cookie_hit=%llu conflict=%llu reject_version=%llu reject_type=%llu short_header=%llu update_error=%llu\n",
            (unsigned long long)stats.values[QAFF_STAT_PASSIVE_EGRESS_LEARN],
            (unsigned long long)stats.values[QAFF_STAT_PASSIVE_HIT],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_HIT],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_EGRESS_CONFLICT],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_EGRESS_REJECT_VERSION],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_EGRESS_REJECT_TYPE],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_EGRESS_SHORT_HEADER],
            (unsigned long long)
                stats.values[QAFF_STAT_PASSIVE_EGRESS_MAP_UPDATE_ERROR]);
    return 1;
  }

  close(client_fd);
  for (size_t i = 0; i < WORKER_COUNT; i++) {
    close(workers[i]);
  }
  return 0;
}
