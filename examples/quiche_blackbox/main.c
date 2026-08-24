#define _POSIX_C_SOURCE 200809L

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
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define CID_LEN 8
#define MAX_DATAGRAM_SIZE 1350
#define RECEIVE_TIMEOUT_MS 5000

static int parse_u16(const char *text, uint16_t *out) {
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 10);
  if (end == text || *end != '\0' || value == 0 || value > UINT16_MAX) {
    errno = EINVAL;
    return -1;
  }
  *out = (uint16_t)value;
  return 0;
}

static int parse_u8(const char *text, uint8_t *out) {
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 10);
  if (end == text || *end != '\0' || value > UINT8_MAX) {
    errno = EINVAL;
    return -1;
  }
  *out = (uint8_t)value;
  return 0;
}

static int hex_value(char c) {
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

static int parse_cid(const char *text, uint8_t cid[CID_LEN]) {
  if (strlen(text) != CID_LEN * 2) {
    errno = EINVAL;
    return -1;
  }
  for (size_t i = 0; i < CID_LEN; i++) {
    int high = hex_value(text[i * 2]);
    int low = hex_value(text[i * 2 + 1]);
    if (high < 0 || low < 0) {
      errno = EINVAL;
      return -1;
    }
    cid[i] = (uint8_t)((high << 4) | low);
  }
  return 0;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int make_udp_socket(uint16_t port, int reuseport) {
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
  addr.sin_port = htons(port);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      set_nonblocking(fd) != 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}

static int socket_address(int fd,
                          struct sockaddr_storage *addr,
                          socklen_t *addr_len) {
  *addr_len = sizeof(*addr);
  memset(addr, 0, sizeof(*addr));
  return getsockname(fd, (struct sockaddr *)addr, addr_len);
}

static int receive_packet(int fd,
                          uint8_t *buf,
                          size_t buf_len,
                          struct sockaddr_storage *peer,
                          socklen_t *peer_len) {
  struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN,
  };
  int rc;
  do {
    rc = poll(&pfd, 1, RECEIVE_TIMEOUT_MS);
  } while (rc < 0 && errno == EINTR);
  if (rc <= 0) {
    if (rc == 0) {
      errno = ETIMEDOUT;
    }
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

static int flush_connection(int fd, quiche_conn *conn) {
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
      return -1;
    }
  }
}

static quiche_config *client_config(void) {
  quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (config == NULL) {
    return NULL;
  }
  quiche_config_verify_peer(config, false);
  const uint8_t alpn[] = {2, 'h', 'q'};
  if (quiche_config_set_application_protos(config, alpn, sizeof(alpn)) != 0) {
    quiche_config_free(config);
    return NULL;
  }
  quiche_config_set_initial_max_data(config, 1024 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 64 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 64 * 1024);
  quiche_config_set_initial_max_streams_bidi(config, 16);
  quiche_config_set_active_connection_id_limit(config, 4);
  return config;
}

static quiche_config *server_config(const char *cert, const char *key) {
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
  if (quiche_config_set_application_protos(config, alpn, sizeof(alpn)) != 0) {
    quiche_config_free(config);
    return NULL;
  }
  quiche_config_set_initial_max_data(config, 1024 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 64 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 64 * 1024);
  quiche_config_set_initial_max_streams_bidi(config, 16);
  quiche_config_set_active_connection_id_limit(config, 4);
  return config;
}

static uint16_t peer_port(const struct sockaddr_storage *addr) {
  const struct sockaddr_in *addr4 = (const struct sockaddr_in *)addr;
  return ntohs(addr4->sin_port);
}

static int run_server(uint8_t worker_id,
                      uint16_t port,
                      const char *cert,
                      const char *key) {
  int fd = make_udp_socket(port, 1);
  if (fd < 0) {
    return -1;
  }
  quiche_config *config = server_config(cert, key);
  if (config == NULL) {
    close(fd);
    errno = EINVAL;
    return -1;
  }

  uint8_t packet[65535];
  struct sockaddr_storage initial_peer;
  socklen_t initial_peer_len;
  int got;
  do {
    got = receive_packet(fd,
                         packet,
                         sizeof(packet),
                         &initial_peer,
                         &initial_peer_len);
    if (got <= 0) {
      quiche_config_free(config);
      close(fd);
      return -1;
    }
  } while ((packet[0] & 0x80u) == 0);

  uint8_t type = 0;
  uint32_t version = 0;
  uint8_t client_scid[QUICHE_MAX_CONN_ID_LEN];
  size_t client_scid_len = sizeof(client_scid);
  uint8_t original_dcid[QUICHE_MAX_CONN_ID_LEN];
  size_t original_dcid_len = sizeof(original_dcid);
  uint8_t token[256];
  size_t token_len = sizeof(token);
  if (quiche_header_info(packet,
                         (size_t)got,
                         CID_LEN,
                         &version,
                         &type,
                         client_scid,
                         &client_scid_len,
                         original_dcid,
                         &original_dcid_len,
                         token,
                         &token_len) != 0) {
    quiche_config_free(config);
    close(fd);
    errno = EPROTO;
    return -1;
  }

  uint64_t pid = (uint64_t)getpid();
  uint8_t server_scid[CID_LEN] = {
    0xd0,
    worker_id,
    0x71,
    0x61,
    0x66,
    0x66,
    (uint8_t)(pid >> 8),
    (uint8_t)pid,
  };
  struct sockaddr_storage local;
  socklen_t local_len;
  if (socket_address(fd, &local, &local_len) != 0) {
    quiche_config_free(config);
    close(fd);
    return -1;
  }
  quiche_conn *conn = quiche_accept(server_scid,
                                    sizeof(server_scid),
                                    original_dcid,
                                    original_dcid_len,
                                    (struct sockaddr *)&local,
                                    local_len,
                                    (struct sockaddr *)&initial_peer,
                                    initial_peer_len,
                                    config);
  if (conn == NULL) {
    quiche_config_free(config);
    close(fd);
    errno = EPROTO;
    return -1;
  }
  quiche_recv_info recv_info = {
    .from = (struct sockaddr *)&initial_peer,
    .from_len = initial_peer_len,
    .to = (struct sockaddr *)&local,
    .to_len = local_len,
  };
  if (quiche_conn_recv(conn, packet, (size_t)got, &recv_info) < 0 ||
      flush_connection(fd, conn) != 0) {
    quiche_conn_free(conn);
    quiche_config_free(config);
    close(fd);
    return -1;
  }

  struct sockaddr_storage migrated_peer;
  socklen_t migrated_peer_len;
  got = receive_packet(fd,
                       packet,
                       sizeof(packet),
                       &migrated_peer,
                       &migrated_peer_len);
  if (got <= 0 || peer_port(&migrated_peer) == peer_port(&initial_peer)) {
    quiche_conn_free(conn);
    quiche_config_free(config);
    close(fd);
    errno = EPROTO;
    return -1;
  }
  recv_info.from = (struct sockaddr *)&migrated_peer;
  recv_info.from_len = migrated_peer_len;
  if (quiche_conn_recv(conn, packet, (size_t)got, &recv_info) < 0) {
    quiche_conn_free(conn);
    quiche_config_free(config);
    close(fd);
    errno = EPROTO;
    return -1;
  }

  printf("blackbox_server=ok\n");
  printf("worker_id=%u\n", worker_id);
  printf("server_scid=");
  for (size_t i = 0; i < sizeof(server_scid); i++) {
    printf("%02x", server_scid[i]);
  }
  printf("\n");
  printf("client_source_port_before=%u\n", peer_port(&initial_peer));
  printf("client_source_port_after=%u\n", peer_port(&migrated_peer));
  fflush(stdout);
  quiche_conn_free(conn);
  quiche_config_free(config);
  close(fd);
  return 0;
}

static int run_probe(uint16_t port, const uint8_t cid[CID_LEN]) {
  int fd = make_udp_socket(0, 0);
  if (fd < 0) {
    return -1;
  }
  uint8_t packet[1 + CID_LEN + 4] = {0x43};
  memcpy(packet + 1, cid, CID_LEN);
  packet[1 + CID_LEN] = 0x01;
  packet[2 + CID_LEN] = 0x02;
  packet[3 + CID_LEN] = 0x03;
  packet[4 + CID_LEN] = 0x04;
  struct sockaddr_in server4;
  memset(&server4, 0, sizeof(server4));
  server4.sin_family = AF_INET;
  server4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  server4.sin_port = htons(port);
  ssize_t sent = sendto(fd,
                        packet,
                        sizeof(packet),
                        0,
                        (struct sockaddr *)&server4,
                        sizeof(server4));
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return sent == (ssize_t)sizeof(packet) ? 0 : -1;
}

static int run_client(uint16_t port) {
  int first_fd = make_udp_socket(0, 0);
  int second_fd = make_udp_socket(0, 0);
  if (first_fd < 0 || second_fd < 0) {
    if (first_fd >= 0) {
      close(first_fd);
    }
    if (second_fd >= 0) {
      close(second_fd);
    }
    return -1;
  }
  struct sockaddr_storage first_addr;
  socklen_t first_addr_len;
  struct sockaddr_storage second_addr;
  socklen_t second_addr_len;
  if (socket_address(first_fd, &first_addr, &first_addr_len) != 0 ||
      socket_address(second_fd, &second_addr, &second_addr_len) != 0) {
    close(first_fd);
    close(second_fd);
    return -1;
  }
  struct sockaddr_in server4;
  memset(&server4, 0, sizeof(server4));
  server4.sin_family = AF_INET;
  server4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  server4.sin_port = htons(port);

  quiche_config *config = client_config();
  if (config == NULL) {
    close(first_fd);
    close(second_fd);
    errno = EINVAL;
    return -1;
  }
  uint64_t pid = (uint64_t)getpid();
  uint8_t client_scid[CID_LEN] = {
    0xc0,
    (uint8_t)(pid >> 8),
    (uint8_t)pid,
    0x71,
    0x61,
    0x66,
    0x66,
    0x01,
  };
  quiche_conn *conn = quiche_connect("localhost",
                                     client_scid,
                                     sizeof(client_scid),
                                     (struct sockaddr *)&first_addr,
                                     first_addr_len,
                                     (struct sockaddr *)&server4,
                                     sizeof(server4),
                                     config);
  if (conn == NULL || flush_connection(first_fd, conn) != 0) {
    if (conn != NULL) {
      quiche_conn_free(conn);
    }
    quiche_config_free(config);
    close(first_fd);
    close(second_fd);
    errno = EPROTO;
    return -1;
  }

  uint8_t packet[65535];
  struct sockaddr_storage from_server;
  socklen_t from_server_len;
  int got = receive_packet(first_fd,
                           packet,
                           sizeof(packet),
                           &from_server,
                           &from_server_len);
  quiche_recv_info recv_info = {
    .from = (struct sockaddr *)&from_server,
    .from_len = from_server_len,
    .to = (struct sockaddr *)&first_addr,
    .to_len = first_addr_len,
  };
  if (got <= 0 ||
      quiche_conn_recv(conn, packet, (size_t)got, &recv_info) < 0 ||
      flush_connection(second_fd, conn) != 0) {
    quiche_conn_free(conn);
    quiche_config_free(config);
    close(first_fd);
    close(second_fd);
    errno = EPROTO;
    return -1;
  }

  printf("blackbox_client=ok\n");
  printf("client_source_port_before=%u\n", peer_port(&first_addr));
  printf("client_source_port_after=%u\n", peer_port(&second_addr));
  quiche_conn_free(conn);
  quiche_config_free(config);
  close(first_fd);
  close(second_fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "client") == 0) {
    uint16_t port;
    if (parse_u16(argv[2], &port) != 0 || run_client(port) != 0) {
      perror("blackbox client");
      return 1;
    }
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "probe") == 0) {
    uint16_t port;
    uint8_t cid[CID_LEN];
    if (parse_u16(argv[2], &port) != 0 ||
        parse_cid(argv[3], cid) != 0 ||
        run_probe(port, cid) != 0) {
      perror("blackbox probe");
      return 1;
    }
    return 0;
  }
  if (argc == 6 && strcmp(argv[1], "server") == 0) {
    uint8_t worker_id;
    uint16_t port;
    if (parse_u8(argv[2], &worker_id) != 0 ||
        parse_u16(argv[3], &port) != 0 ||
        run_server(worker_id, port, argv[4], argv[5]) != 0) {
      perror("blackbox server");
      return 1;
    }
    return 0;
  }
  fprintf(stderr,
          "usage: %s client PORT | probe PORT CID_HEX | "
          "server WORKER_ID PORT CERT KEY\n",
          argv[0]);
  return 2;
}
