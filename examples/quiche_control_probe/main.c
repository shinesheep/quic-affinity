#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <quiche.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define WORKER_ID 2
#define CID_LEN 8

static int make_udp_reuseport_socket(void) {
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
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static int register_worker(const char *socket_path, int worker_fd, int *lease_fd) {
  int control_fd = qaff_control_connect(socket_path);
  if (control_fd < 0) {
    perror("qaff_control_connect");
    return -1;
  }

  int rc = qaff_control_register_worker_lease(control_fd, WORKER_ID, worker_fd);
  if (rc != 0) {
    perror("qaff_control_register_worker_lease");
    close(control_fd);
    return -1;
  }

  printf("registered_worker=%u\n", WORKER_ID);
  *lease_fd = control_fd;
  return 0;
}

static int register_cid(const char *socket_path,
                        const uint8_t *cid,
                        size_t cid_len,
                        const char *label) {
  int control_fd = qaff_control_connect(socket_path);
  if (control_fd < 0) {
    perror("qaff_control_connect");
    return -1;
  }

  int rc = qaff_control_register_cid(control_fd, WORKER_ID, cid, cid_len);
  if (rc != 0) {
    perror("qaff_control_register_cid");
    close(control_fd);
    return -1;
  }

  printf("registered_%s_len=%zu\n", label, cid_len);
  close(control_fd);
  return 0;
}

static void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s QAFFD_SOCKET\n", argv[0]);
    return 2;
  }

  const char *socket_path = argv[1];
  int worker_fd = make_udp_reuseport_socket();
  if (worker_fd < 0) {
    perror("make_udp_reuseport_socket");
    return 1;
  }
  int worker_lease_fd = -1;
  if (register_worker(socket_path, worker_fd, &worker_lease_fd) != 0) {
    close(worker_fd);
    return 1;
  }

  quiche_config *config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (config == NULL) {
    fprintf(stderr, "quiche_config_new failed\n");
    close(worker_lease_fd);
    close(worker_fd);
    return 1;
  }

  const uint8_t alpn[] = {2, 'h', 'q'};
  if (quiche_config_set_application_protos(config, alpn, sizeof(alpn)) != 0) {
    fprintf(stderr, "quiche_config_set_application_protos failed\n");
    quiche_config_free(config);
    close(worker_lease_fd);
    close(worker_fd);
    return 1;
  }

  quiche_config_set_initial_max_data(config, 1024 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_local(config, 64 * 1024);
  quiche_config_set_initial_max_stream_data_bidi_remote(config, 64 * 1024);
  quiche_config_set_initial_max_streams_bidi(config, 16);
  quiche_config_set_active_connection_id_limit(config, 4);

  struct sockaddr_in local;
  memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  local.sin_port = htons(4433);

  struct sockaddr_in peer;
  memset(&peer, 0, sizeof(peer));
  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  peer.sin_port = htons(55555);

  const uint8_t scid[CID_LEN] = {0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd};
  const uint8_t odcid[CID_LEN] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

  quiche_conn *conn = quiche_accept(scid,
                                    sizeof(scid),
                                    odcid,
                                    sizeof(odcid),
                                    (struct sockaddr *)&local,
                                    sizeof(local),
                                    (struct sockaddr *)&peer,
                                    sizeof(peer),
                                    config);
  if (conn == NULL) {
    fprintf(stderr, "quiche_accept failed\n");
    quiche_config_free(config);
    close(worker_lease_fd);
    close(worker_fd);
    return 1;
  }

  const uint8_t *source_id = NULL;
  size_t source_id_len = 0;
  quiche_conn_source_id(conn, &source_id, &source_id_len);
  printf("quiche_source_cid=");
  print_hex(source_id, source_id_len);
  printf("\n");

  if (register_cid(socket_path, source_id, source_id_len, "source_cid") != 0) {
    quiche_conn_free(conn);
    quiche_config_free(config);
    close(worker_lease_fd);
    close(worker_fd);
    return 1;
  }

  const uint8_t extra_scid[CID_LEN] = {0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04};
  const uint8_t reset_token[16] = {
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
  };
  uint64_t scid_seq = 0;
  int new_scid_rc = quiche_conn_new_scid(conn,
                                         extra_scid,
                                         sizeof(extra_scid),
                                         reset_token,
                                         false,
                                         &scid_seq);
  printf("quiche_new_scid_rc=%d\n", new_scid_rc);
  if (new_scid_rc == 0) {
    printf("quiche_new_scid_seq=%llu\n", (unsigned long long)scid_seq);
    if (register_cid(socket_path,
                     extra_scid,
                     sizeof(extra_scid),
                     "new_scid") != 0) {
      quiche_conn_free(conn);
      quiche_config_free(config);
      close(worker_lease_fd);
      close(worker_fd);
      return 1;
    }
  }

  quiche_connection_id_iter *retired = quiche_conn_retired_scid_iter(conn);
  if (retired != NULL) {
    const uint8_t *retired_cid = NULL;
    size_t retired_cid_len = 0;
    while (quiche_connection_id_iter_next(retired,
                                          &retired_cid,
                                          &retired_cid_len)) {
      int control_fd = qaff_control_connect(socket_path);
      if (control_fd >= 0) {
        qaff_control_retire_cid(control_fd, retired_cid, retired_cid_len);
        close(control_fd);
      }
    }
    quiche_connection_id_iter_free(retired);
  }

  quiche_conn_free(conn);
  quiche_config_free(config);
  close(worker_lease_fd);
  close(worker_fd);
  return 0;
}
