#include "quic_affinity/quic_affinity.h"

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

static void print_stats(struct qaff_context *ctx) {
  struct qaff_stats stats;
  if (qaff_read_stats(ctx, &stats) != 0) {
    perror("qaff_read_stats");
    return;
  }

  for (uint32_t i = 0; i < QAFF_STAT_MAX; i++) {
    printf("%s=%llu\n",
           qaff_stat_name(i),
           (unsigned long long)stats.values[i]);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s PATH_TO_QAFF_BPF_OBJECT\n", argv[0]);
    return 2;
  }

  int workers[WORKER_COUNT] = {-1, -1, -1};
  uint16_t port = 0;
  struct qaff_context *ctx = NULL;
  struct qaff_bpf_object *bpf = NULL;

  for (uint32_t worker_id = 0; worker_id < WORKER_COUNT; worker_id++) {
    workers[worker_id] = make_udp_reuseport_socket(&port);
    if (workers[worker_id] < 0) {
      perror("make_udp_reuseport_socket");
      return 1;
    }
  }

  struct qaff_options options;
  qaff_options_init(&options);
  options.short_cid_len = 8;

  if (qaff_open(&options, &ctx) != 0) {
    perror("qaff_open");
    return 1;
  }

  for (uint32_t worker_id = 0; worker_id < WORKER_COUNT; worker_id++) {
    if (qaff_register_worker_socket(ctx, worker_id, workers[worker_id]) != 0) {
      perror("qaff_register_worker_socket");
      return 1;
    }
  }

  if (qaff_bpf_object_open(ctx, argv[1], &bpf) != 0) {
    perror("qaff_bpf_object_open");
    return 1;
  }

  if (qaff_attach_reuseport_bpf(bpf, workers[0]) != 0) {
    perror("qaff_attach_reuseport_bpf");
    return 1;
  }

  /*
   * A real QUIC stack would call qaff_register_cid() whenever it creates
   * a server-issued CID for a connection owned by this worker.
   */
  const uint8_t example_server_cid[] = {
    0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
  };
  const uint32_t owner_worker = 2;
  if (qaff_register_cid(ctx,
                        example_server_cid,
                        sizeof(example_server_cid),
                        owner_worker) != 0) {
    perror("qaff_register_cid");
    return 1;
  }

  printf("listener=127.0.0.1:%u\n", port);
  printf("registered example CID to worker=%u\n", owner_worker);
  print_stats(ctx);

  qaff_retire_cid(ctx, example_server_cid, sizeof(example_server_cid));
  qaff_bpf_object_close(bpf);
  qaff_close(ctx);

  for (size_t i = 0; i < WORKER_COUNT; i++) {
    close(workers[i]);
  }

  return 0;
}

