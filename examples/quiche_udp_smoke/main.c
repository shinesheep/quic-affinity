#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <quiche.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define WORKER_COUNT 3
#define CID_LEN 8
#define MAX_DATAGRAM_SIZE 1350

static const uint8_t k_server_scid[CID_LEN] = {
  0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
};

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int make_udp_socket(uint16_t *port, int reuseport) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  if (reuseport) {
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0) {
      close(fd);
      return -1;
    }
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

static int get_sockaddr(int fd, struct sockaddr_storage *addr, socklen_t *len) {
  *len = sizeof(*addr);
  memset(addr, 0, sizeof(*addr));
  return getsockname(fd, (struct sockaddr *)addr, len);
}

static int connect_control(const char *socket_path) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    perror("qaff_control_connect");
  }
  return fd;
}

static int control_register_worker(const char *socket_path,
                                   uint32_t worker_id,
                                   int worker_fd,
                                   int *lease_fd) {
  int fd = connect_control(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_register_worker_lease(fd, worker_id, worker_fd);
  if (rc != 0) {
    perror("qaff_control_register_worker_lease");
    close(fd);
    return rc;
  }
  *lease_fd = fd;
  return 0;
}

static int control_register_cid(const char *socket_path,
                                uint32_t worker_id,
                                const uint8_t *cid,
                                size_t cid_len) {
  int fd = connect_control(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_register_cid(fd, worker_id, cid, cid_len);
  if (rc != 0) {
    perror("qaff_control_register_cid");
  }
  close(fd);
  return rc;
}

static int control_read_stats(const char *socket_path, struct qaff_stats *stats) {
  int fd = connect_control(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_read_stats(fd, stats);
  if (rc != 0) {
    perror("qaff_control_read_stats");
  }
  close(fd);
  return rc;
}

static int control_stop(const char *socket_path) {
  int fd = connect_control(socket_path);
  if (fd < 0) {
    return -1;
  }
  int rc = qaff_control_stop(fd);
  close(fd);
  return rc;
}

static quiche_config *make_client_config(void) {
  quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (config == NULL) {
    return NULL;
  }
  quiche_config_verify_peer(config, false);
  const uint8_t alpn[] = {2, 'h', 'q'};
  quiche_config_set_application_protos(config, alpn, sizeof(alpn));
  quiche_config_set_initial_max_data(config, 1024 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 64 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 64 * 1024);
  quiche_config_set_initial_max_streams_bidi(config, 16);
  quiche_config_set_active_connection_id_limit(config, 4);
  return config;
}

static quiche_config *make_server_config(const char *cert, const char *key) {
  quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (config == NULL) {
    return NULL;
  }
  if (quiche_config_load_cert_chain_from_pem_file(config, cert) != 0 ||
      quiche_config_load_priv_key_from_pem_file(config, key) != 0) {
    quiche_config_free(config);
    return NULL;
  }
  const uint8_t alpn[] = {2, 'h', 'q'};
  quiche_config_set_application_protos(config, alpn, sizeof(alpn));
  quiche_config_set_initial_max_data(config, 1024 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 64 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 64 * 1024);
  quiche_config_set_initial_max_streams_bidi(config, 16);
  quiche_config_set_active_connection_id_limit(config, 4);
  return config;
}

static int flush_conn(int fd, quiche_conn *conn) {
  uint8_t out[MAX_DATAGRAM_SIZE];

  for (;;) {
    quiche_send_info send_info;
    ssize_t written = quiche_conn_send(conn, out, sizeof(out), &send_info);
    if (written == QUICHE_ERR_DONE) {
      return 0;
    }
    if (written < 0) {
      fprintf(stderr, "quiche_conn_send failed: %zd\n", written);
      return -1;
    }
    ssize_t sent = sendto(fd,
                          out,
                          (size_t)written,
                          0,
                          (struct sockaddr *)&send_info.to,
                          send_info.to_len);
    if (sent != written) {
      perror("sendto");
      return -1;
    }
  }
}

static int recv_from_workers(const int *workers,
                             size_t count,
                             uint8_t *buf,
                             size_t buf_len,
                             struct sockaddr_storage *peer,
                             socklen_t *peer_len,
                             int *worker_id) {
  struct pollfd fds[WORKER_COUNT];
  for (size_t i = 0; i < count; i++) {
    fds[i].fd = workers[i];
    fds[i].events = POLLIN;
    fds[i].revents = 0;
  }

  if (poll(fds, count, 1000) <= 0) {
    return -1;
  }

  for (size_t i = 0; i < count; i++) {
    if (fds[i].revents & POLLIN) {
      *peer_len = sizeof(*peer);
      ssize_t got = recvfrom(workers[i],
                             buf,
                             buf_len,
                             0,
                             (struct sockaddr *)peer,
                             peer_len);
      if (got > 0) {
        *worker_id = (int)i;
        return (int)got;
      }
    }
  }

  return -1;
}

static int recv_client_packet(int fd,
                              uint8_t *buf,
                              size_t buf_len,
                              struct sockaddr_storage *peer,
                              socklen_t *peer_len) {
  struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN,
  };
  if (poll(&pfd, 1, 1000) <= 0) {
    return -1;
  }
  *peer_len = sizeof(*peer);
  ssize_t got = recvfrom(fd,
                         buf,
                         buf_len,
                         0,
                         (struct sockaddr *)peer,
                         peer_len);
  return got > 0 ? (int)got : -1;
}

static quiche_conn *accept_server_conn(const char *control_sock,
                                       quiche_config *server_config,
                                       int passive_egress,
                                       const uint8_t *packet,
                                       size_t packet_len,
                                       const struct sockaddr_storage *server_addr,
                                       socklen_t server_addr_len,
                                       const struct sockaddr_storage *peer_addr,
                                       socklen_t peer_addr_len) {
  uint8_t type = 0;
  uint32_t version = 0;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  size_t scid_len = sizeof(scid);
  uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
  size_t dcid_len = sizeof(dcid);
  uint8_t token[256];
  size_t token_len = sizeof(token);

  int rc = quiche_header_info(packet,
                              packet_len,
                              CID_LEN,
                              &version,
                              &type,
                              scid,
                              &scid_len,
                              dcid,
                              &dcid_len,
                              token,
                              &token_len);
  if (rc != 0) {
    fprintf(stderr, "quiche_header_info failed: %d\n", rc);
    return NULL;
  }

  quiche_conn *conn = quiche_accept(k_server_scid,
                                    sizeof(k_server_scid),
                                    dcid,
                                    dcid_len,
                                    (const struct sockaddr *)server_addr,
                                    server_addr_len,
                                    (const struct sockaddr *)peer_addr,
                                    peer_addr_len,
                                    server_config);
  if (conn == NULL) {
    fprintf(stderr, "quiche_accept failed\n");
    return NULL;
  }

  if (!passive_egress &&
      control_register_cid(control_sock, 0, k_server_scid, sizeof(k_server_scid)) != 0) {
    quiche_conn_free(conn);
    return NULL;
  }
  return conn;
}

static int drive_server_packet(quiche_conn **server_conn,
                               const char *control_sock,
                               quiche_config *server_config,
                               int passive_egress,
                               int server_fd,
                               uint8_t *packet,
                               size_t packet_len,
                               const struct sockaddr_storage *server_addr,
                               socklen_t server_addr_len,
                               const struct sockaddr_storage *peer_addr,
                               socklen_t peer_addr_len) {
  if (*server_conn == NULL) {
    *server_conn = accept_server_conn(control_sock,
                                      server_config,
                                      passive_egress,
                                      packet,
                                      packet_len,
                                      server_addr,
                                      server_addr_len,
                                      peer_addr,
                                      peer_addr_len);
    if (*server_conn == NULL) {
      return -1;
    }
  }

  quiche_recv_info recv_info = {
    .from = (struct sockaddr *)peer_addr,
    .from_len = peer_addr_len,
    .to = (struct sockaddr *)server_addr,
    .to_len = server_addr_len,
  };
  ssize_t done = quiche_conn_recv(*server_conn, packet, packet_len, &recv_info);
  if (done < 0) {
    fprintf(stderr, "server quiche_conn_recv failed: %zd\n", done);
    return -1;
  }
  return flush_conn(server_fd, *server_conn);
}

static int drive_client_packet(quiche_conn *client_conn,
                               int client_fd,
                               uint8_t *packet,
                               size_t packet_len,
                               const struct sockaddr_storage *server_addr,
                               socklen_t server_addr_len,
                               const struct sockaddr_storage *client_addr,
                               socklen_t client_addr_len) {
  quiche_recv_info recv_info = {
    .from = (struct sockaddr *)server_addr,
    .from_len = server_addr_len,
    .to = (struct sockaddr *)client_addr,
    .to_len = client_addr_len,
  };
  ssize_t done = quiche_conn_recv(client_conn, packet, packet_len, &recv_info);
  if (done < 0) {
    fprintf(stderr, "client quiche_conn_recv failed: %zd\n", done);
    return -1;
  }
  return flush_conn(client_fd, client_conn);
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "--probe-ready") == 0) {
    int fd = qaff_control_connect(argv[2]);
    if (fd < 0) {
      return 1;
    }
    close(fd);
    return 0;
  }

  int passive_egress = 0;
  const char *control_sock = NULL;
  const char *cert = NULL;
  const char *key = NULL;
  if (argc == 5 && strcmp(argv[1], "--passive-egress") == 0) {
    passive_egress = 1;
    control_sock = argv[2];
    cert = argv[3];
    key = argv[4];
  } else if (argc == 4) {
    control_sock = argv[1];
    cert = argv[2];
    key = argv[3];
  } else {
    fprintf(stderr, "usage: %s [--passive-egress] QAFFD_SOCKET CERT KEY\n", argv[0]);
    return 2;
  }

  int workers[WORKER_COUNT] = {-1, -1, -1};
  int worker_leases[WORKER_COUNT] = {-1, -1, -1};
  uint16_t server_port = 0;
  for (uint32_t i = 0; i < WORKER_COUNT; i++) {
    workers[i] = make_udp_socket(&server_port, 1);
    if (workers[i] < 0) {
      perror("make worker socket");
      return 1;
    }
    if (control_register_worker(control_sock,
                                i,
                                workers[i],
                                &worker_leases[i]) != 0) {
      return 1;
    }
  }

  uint16_t client_port1 = 0;
  int client_fd1 = make_udp_socket(&client_port1, 0);
  uint16_t client_port2 = 0;
  int client_fd2 = make_udp_socket(&client_port2, 0);
  if (client_fd1 < 0 || client_fd2 < 0 || client_port1 == client_port2) {
    perror("make client socket");
    return 1;
  }

  struct sockaddr_storage server_addr;
  socklen_t server_addr_len;
  if (get_sockaddr(workers[0], &server_addr, &server_addr_len) != 0) {
    perror("getsockname server");
    return 1;
  }
  struct sockaddr_in *server4 = (struct sockaddr_in *)&server_addr;
  server4->sin_port = htons(server_port);

  struct sockaddr_storage client_addr1;
  socklen_t client_addr1_len;
  if (get_sockaddr(client_fd1, &client_addr1, &client_addr1_len) != 0) {
    perror("getsockname client");
    return 1;
  }

  quiche_config *client_config = make_client_config();
  quiche_config *server_config = make_server_config(cert, key);
  if (client_config == NULL || server_config == NULL) {
    fprintf(stderr, "failed to create quiche configs\n");
    return 1;
  }

  const uint8_t client_scid[CID_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  };
  quiche_conn *client_conn = quiche_connect("localhost",
                                            client_scid,
                                            sizeof(client_scid),
                                            (struct sockaddr *)&client_addr1,
                                            client_addr1_len,
                                            (struct sockaddr *)&server_addr,
                                            server_addr_len,
                                            client_config);
  if (client_conn == NULL) {
    fprintf(stderr, "quiche_connect failed\n");
    return 1;
  }

  quiche_conn *server_conn = NULL;
  uint8_t buf[65535];

  if (flush_conn(client_fd1, client_conn) != 0) {
    return 1;
  }

  struct sockaddr_storage peer_addr;
  socklen_t peer_addr_len;
  int worker_id = -1;
  int got = recv_from_workers(workers,
                              WORKER_COUNT,
                              buf,
                              sizeof(buf),
                              &peer_addr,
                              &peer_addr_len,
                              &worker_id);
  if (got <= 0 || worker_id != 0) {
    fprintf(stderr, "expected first Initial on fallback worker 0, got %d\n", worker_id);
    return 1;
  }

  if (drive_server_packet(&server_conn,
                          control_sock,
                          server_config,
                          passive_egress,
                          workers[0],
                          buf,
                          (size_t)got,
                          &server_addr,
                          server_addr_len,
                          &peer_addr,
                          peer_addr_len) != 0) {
    return 1;
  }

  struct sockaddr_storage from_server;
  socklen_t from_server_len;
  got = recv_client_packet(client_fd1,
                           buf,
                           sizeof(buf),
                           &from_server,
                           &from_server_len);
  if (got <= 0) {
    fprintf(stderr, "client did not receive server packet\n");
    return 1;
  }
  if (drive_client_packet(client_conn,
                          client_fd2,
                          buf,
                          (size_t)got,
                          &from_server,
                          from_server_len,
                          &client_addr1,
                          client_addr1_len) != 0) {
    return 1;
  }

  got = recv_from_workers(workers,
                          WORKER_COUNT,
                          buf,
                          sizeof(buf),
                          &peer_addr,
                          &peer_addr_len,
                          &worker_id);
  if (got <= 0 || worker_id != 0) {
    fprintf(stderr, "expected migrated client packet on worker 0, got %d\n", worker_id);
    return 1;
  }

  struct qaff_stats stats;
  if (control_read_stats(control_sock, &stats) != 0) {
    return 1;
  }
  if (passive_egress) {
    if (stats.values[QAFF_STAT_PASSIVE_EGRESS_LEARN] < 1 ||
        stats.values[QAFF_STAT_PASSIVE_HIT] < 1 ||
        stats.values[QAFF_STAT_FALLBACK] < 1) {
      fprintf(stderr,
              "expected passive egress learn, passive hit, and fallback, learn=%llu hit=%llu fallback=%llu\n",
              (unsigned long long)stats.values[QAFF_STAT_PASSIVE_EGRESS_LEARN],
              (unsigned long long)stats.values[QAFF_STAT_PASSIVE_HIT],
              (unsigned long long)stats.values[QAFF_STAT_FALLBACK]);
      return 1;
    }
  } else if (stats.values[QAFF_STAT_CID_MAP_HIT] < 1 ||
             stats.values[QAFF_STAT_FALLBACK] < 1) {
    fprintf(stderr,
            "expected at least one CID hit and one fallback, hit=%llu fallback=%llu\n",
            (unsigned long long)stats.values[QAFF_STAT_CID_MAP_HIT],
            (unsigned long long)stats.values[QAFF_STAT_FALLBACK]);
    return 1;
  }

  printf("quiche_udp_smoke=ok\n");
  printf("passive_egress=%u\n", passive_egress ? 1u : 0u);
  printf("client_source_port_before=%u\n", client_port1);
  printf("client_source_port_after=%u\n", client_port2);
  printf("cid_map_hit=%llu\n", (unsigned long long)stats.values[QAFF_STAT_CID_MAP_HIT]);
  printf("fallback=%llu\n", (unsigned long long)stats.values[QAFF_STAT_FALLBACK]);
  printf("passive_egress_learn=%llu\n",
         (unsigned long long)stats.values[QAFF_STAT_PASSIVE_EGRESS_LEARN]);
  printf("passive_hit=%llu\n",
         (unsigned long long)stats.values[QAFF_STAT_PASSIVE_HIT]);

  quiche_conn_free(client_conn);
  if (server_conn != NULL) {
    quiche_conn_free(server_conn);
  }
  quiche_config_free(client_config);
  quiche_config_free(server_config);
  close(client_fd1);
  close(client_fd2);
  for (size_t i = 0; i < WORKER_COUNT; i++) {
    close(worker_leases[i]);
    close(workers[i]);
  }
  control_stop(control_sock);
  return 0;
}
