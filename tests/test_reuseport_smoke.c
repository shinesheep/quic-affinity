#include "quic_affinity/quic_affinity.h"
#include "quic_affinity/cid_profile.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#define TEST_SKIP 77
#define WORKER_COUNT 3
#define FALLBACK_WORKER 0
#define CONFIGURED_FALLBACK_WORKER 1
#define TARGET_WORKER 2

static const uint8_t k_dcid[] = {
  0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
};

static const uint8_t k_unknown_dcid[] = {
  0xba, 0xad, 0xf0, 0x0d, 0x12, 0x34, 0x56, 0x78,
};

static struct qaff_cid_profile_key profile_key(void) {
  struct qaff_cid_profile_key key;
  for (uint8_t i = 0; i < QAFF_CID_PROFILE_KEY_LEN; i++) {
    key.bytes[i] = (uint8_t)(0x70u + i);
  }
  return key;
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

struct test_case {
  int family;
  const char *name;
  uint32_t fallback_worker;
};

struct sender_socket {
  int fd;
  uint16_t port;
};

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
  } else if (family == AF_INET6) {
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
  } else {
    close(fd);
    errno = EAFNOSUPPORT;
    return -1;
  }

  if (set_nonblocking(fd) != 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static int bind_sender_socket(int family, struct sender_socket *sender) {
  memset(sender, 0, sizeof(*sender));
  sender->fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sender->fd < 0) {
    return -1;
  }

  if (family == AF_INET) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(sender->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
      close(sender->fd);
      sender->fd = -1;
      return -1;
    }

    socklen_t len = sizeof(addr);
    if (getsockname(sender->fd, (struct sockaddr *)&addr, &len) != 0) {
      close(sender->fd);
      sender->fd = -1;
      return -1;
    }
    sender->port = ntohs(addr.sin_port);
  } else if (family == AF_INET6) {
    int v6only = 1;
    if (setsockopt(sender->fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
      close(sender->fd);
      sender->fd = -1;
      return -1;
    }

    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_loopback;
    addr6.sin6_port = 0;

    if (bind(sender->fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
      close(sender->fd);
      sender->fd = -1;
      return -1;
    }

    socklen_t len = sizeof(addr6);
    if (getsockname(sender->fd, (struct sockaddr *)&addr6, &len) != 0) {
      close(sender->fd);
      sender->fd = -1;
      return -1;
    }
    sender->port = ntohs(addr6.sin6_port);
  } else {
    close(sender->fd);
    sender->fd = -1;
    errno = EAFNOSUPPORT;
    return -1;
  }

  return 0;
}

static int send_quic_like_packet(int fd,
                                 int family,
                                 uint16_t port,
                                 int short_header,
                                 const uint8_t *dcid) {
  uint8_t long_packet[] = {
    0xc3,
    0x00, 0x00, 0x00, 0x01,
    0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
    0x01, 0x02, 0x03, 0x04,
  };
  uint8_t short_packet[] = {
    0x43,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04,
  };
  memcpy(long_packet + 6, dcid, sizeof(k_dcid));
  memcpy(short_packet + 1, dcid, sizeof(k_dcid));

  const uint8_t *packet = short_header ? short_packet : long_packet;
  size_t packet_len = short_header ? sizeof(short_packet) : sizeof(long_packet);

  ssize_t sent;
  if (family == AF_INET) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);
    sent = sendto(fd,
                  packet,
                  packet_len,
                  0,
                  (struct sockaddr *)&dst,
                  sizeof(dst));
  } else {
    struct sockaddr_in6 dst6;
    memset(&dst6, 0, sizeof(dst6));
    dst6.sin6_family = AF_INET6;
    dst6.sin6_addr = in6addr_loopback;
    dst6.sin6_port = htons(port);
    sent = sendto(fd,
                  packet,
                  packet_len,
                  0,
                  (struct sockaddr *)&dst6,
                  sizeof(dst6));
  }
  int saved_errno = errno;
  errno = saved_errno;
  return sent == (ssize_t)packet_len ? 0 : -1;
}

static void drain_workers(const int *workers, size_t count) {
  uint8_t buf[2048];
  for (size_t i = 0; i < count; i++) {
    while (recv(workers[i], buf, sizeof(buf), 0) > 0) {
    }
  }
}

static int receive_worker(const int *workers, size_t count, int timeout_ms) {
  struct pollfd fds[WORKER_COUNT];
  if (count > WORKER_COUNT) {
    errno = EINVAL;
    return -1;
  }

  for (size_t i = 0; i < count; i++) {
    fds[i].fd = workers[i];
    fds[i].events = POLLIN;
    fds[i].revents = 0;
  }

  int rc = poll(fds, count, timeout_ms);
  if (rc <= 0) {
    return -1;
  }

  uint8_t buf[2048];
  for (size_t i = 0; i < count; i++) {
    if (fds[i].revents & POLLIN) {
      ssize_t got = recv(workers[i], buf, sizeof(buf), 0);
      if (got > 0) {
        return (int)i;
      }
    }
  }

  return -1;
}

static void print_stats(struct qaff_context *ctx) {
  struct qaff_stats stats;
  if (qaff_read_stats(ctx, &stats) != 0) {
    perror("qaff_read_stats");
    return;
  }

  for (uint32_t i = 0; i < QAFF_STAT_MAX; i++) {
    fprintf(stderr, "stat.%s=%llu\n",
            qaff_stat_name(i),
            (unsigned long long)stats.values[i]);
  }
}

static int expect_stat(struct qaff_context *ctx,
                       enum qaff_stat_index index,
                       uint64_t expected) {
  struct qaff_stats stats;
  if (qaff_read_stats(ctx, &stats) != 0) {
    perror("qaff_read_stats");
    return -1;
  }

  if (stats.values[index] != expected) {
    fprintf(stderr,
            "expected stat.%s=%llu, got %llu\n",
            qaff_stat_name(index),
            (unsigned long long)expected,
            (unsigned long long)stats.values[index]);
    print_stats(ctx);
    return -1;
  }

  return 0;
}

static int expect_case_stats(struct qaff_context *ctx,
                             const struct test_case *test) {
  enum qaff_stat_index family_stat =
      test->family == AF_INET ? QAFF_STAT_IPV4 : QAFF_STAT_IPV6;

  if (expect_stat(ctx, QAFF_STAT_PACKETS, 5) != 0 ||
      expect_stat(ctx, QAFF_STAT_CID_MAP_HIT, 2) != 0 ||
      expect_stat(ctx, QAFF_STAT_FALLBACK, 2) != 0 ||
      expect_stat(ctx, QAFF_STAT_PARSE_ERROR, 0) != 0 ||
      expect_stat(ctx, QAFF_STAT_ZERO_LENGTH_CID, 0) != 0 ||
      expect_stat(ctx, QAFF_STAT_WORKER_MISSING, 0) != 0 ||
      expect_stat(ctx, family_stat, 5) != 0 ||
      expect_stat(ctx, QAFF_STAT_NOT_UDP, 0) != 0 ||
      expect_stat(ctx, QAFF_STAT_CID_PROFILE_HIT, 1) != 0 ||
      expect_stat(ctx, QAFF_STAT_CID_PROFILE_REJECT, 1) != 0) {
    fprintf(stderr, "%s: unexpected dataplane stats\n", test->name);
    return -1;
  }

  return 0;
}

static int run_case(const char *object_path, const struct test_case *test) {
  uint16_t port = 0;
  int workers[WORKER_COUNT] = {-1, -1, -1};
  struct sender_socket senders[2] = {
    {.fd = -1, .port = 0},
    {.fd = -1, .port = 0},
  };
  struct qaff_context *ctx = NULL;
  struct qaff_bpf_object *object = NULL;
  struct qaff_cid_profile_key key = profile_key();
  uint8_t profile_cid[QAFF_CID_PROFILE_V1_LEN];
  uint8_t tampered_profile_cid[QAFF_CID_PROFILE_V1_LEN];

  for (size_t i = 0; i < WORKER_COUNT; i++) {
    workers[i] = make_worker_socket(test->family, &port);
    if (workers[i] < 0) {
      perror("make_worker_socket");
      return 1;
    }
  }

  if (bind_sender_socket(test->family, &senders[0]) != 0 ||
      bind_sender_socket(test->family, &senders[1]) != 0) {
    perror("bind_sender_socket");
    return 1;
  }
  if (senders[0].port == senders[1].port) {
    fprintf(stderr, "%s: expected distinct source ports, both are %u\n",
            test->name,
            senders[0].port);
    return 1;
  }

  struct qaff_options options;
  qaff_options_init(&options);
  options.short_cid_len = sizeof(k_dcid);
  options.fallback_worker_id = test->fallback_worker;
  options.cid_profile_v1_enabled = 1;
  memcpy(options.cid_profile_v1_key,
         key.bytes,
         sizeof(options.cid_profile_v1_key));

  if (qaff_cid_profile_v1_generate(&key,
                                   TARGET_WORKER,
                                   0x010203,
                                   profile_cid,
                                   sizeof(profile_cid)) != 0) {
    perror("qaff_cid_profile_v1_generate");
    return 1;
  }
  memcpy(tampered_profile_cid, profile_cid, sizeof(tampered_profile_cid));
  tampered_profile_cid[7] ^= 0x01;

  if (qaff_open(&options, &ctx) != 0) {
    if (errno == EPERM || errno == EACCES) {
      fprintf(stderr, "skipping: BPF map creation requires elevated privileges\n");
      for (size_t i = 0; i < WORKER_COUNT; i++) {
        close(workers[i]);
      }
      return TEST_SKIP;
    }
    perror("qaff_open");
    return 1;
  }

  for (uint32_t i = 0; i < WORKER_COUNT; i++) {
    if (qaff_register_worker_socket(ctx, i, workers[i]) != 0) {
      perror("qaff_register_worker_socket");
      return 1;
    }
  }

  if (qaff_register_cid(ctx, k_dcid, sizeof(k_dcid), TARGET_WORKER) != 0) {
    perror("qaff_register_cid");
    return 1;
  }

  if (qaff_bpf_object_open(ctx, object_path, &object) != 0) {
    if (errno == EPERM || errno == EACCES) {
      fprintf(stderr, "skipping: BPF program load requires elevated privileges\n");
      qaff_close(ctx);
      for (size_t i = 0; i < WORKER_COUNT; i++) {
        close(workers[i]);
      }
      return TEST_SKIP;
    }
    perror("qaff_bpf_object_open");
    return 1;
  }

  if (qaff_attach_reuseport_bpf(object, workers[0]) != 0) {
    if (errno == EPERM || errno == EACCES) {
      fprintf(stderr, "skipping: BPF attach requires elevated privileges\n");
      qaff_bpf_object_close(object);
      qaff_close(ctx);
      for (size_t i = 0; i < WORKER_COUNT; i++) {
        close(workers[i]);
      }
      return TEST_SKIP;
    }
    perror("qaff_attach_reuseport_bpf");
    return 1;
  }

  drain_workers(workers, WORKER_COUNT);

  for (int attempt = 0; attempt < 2; attempt++) {
    if (send_quic_like_packet(senders[attempt].fd,
                              test->family,
                              port,
                              attempt == 1,
                              k_dcid) != 0) {
      perror("send_quic_like_packet");
      return 1;
    }

    int worker = receive_worker(workers, WORKER_COUNT, 1000);
    if (worker != TARGET_WORKER) {
      fprintf(stderr,
              "%s: expected worker %d, got %d on attempt %d\n",
              test->name,
              TARGET_WORKER,
              worker,
              attempt + 1);
      print_stats(ctx);
      return 1;
    }
  }

  if (send_quic_like_packet(senders[0].fd,
                            test->family,
                            port,
                            1,
                            profile_cid) != 0) {
    perror("send profile packet");
    return 1;
  }

  int profile_worker = receive_worker(workers, WORKER_COUNT, 1000);
  if (profile_worker != TARGET_WORKER) {
    fprintf(stderr,
            "%s: expected profile worker %d, got %d\n",
            test->name,
            TARGET_WORKER,
            profile_worker);
    print_stats(ctx);
    return 1;
  }

  if (send_quic_like_packet(senders[1].fd,
                            test->family,
                            port,
                            1,
                            tampered_profile_cid) != 0) {
    perror("send tampered profile packet");
    return 1;
  }

  int tampered_fallback_worker = receive_worker(workers, WORKER_COUNT, 1000);
  if (tampered_fallback_worker != (int)test->fallback_worker) {
    fprintf(stderr,
            "%s: expected tampered profile fallback worker %d, got %d\n",
            test->name,
            (int)test->fallback_worker,
            tampered_fallback_worker);
    print_stats(ctx);
    return 1;
  }

  if (send_quic_like_packet(senders[0].fd,
                            test->family,
                            port,
                            0,
                            k_unknown_dcid) != 0) {
    perror("send_quic_like_packet");
    return 1;
  }

  int fallback_worker = receive_worker(workers, WORKER_COUNT, 1000);
  if (fallback_worker != (int)test->fallback_worker) {
    fprintf(stderr,
            "%s: expected fallback worker %d, got %d\n",
            test->name,
            (int)test->fallback_worker,
            fallback_worker);
    print_stats(ctx);
    return 1;
  }

  if (expect_case_stats(ctx, test) != 0) {
    return 1;
  }

  qaff_bpf_object_close(object);
  qaff_close(ctx);
  for (size_t i = 0; i < sizeof(senders) / sizeof(senders[0]); i++) {
    close(senders[i].fd);
  }
  for (size_t i = 0; i < WORKER_COUNT; i++) {
    close(workers[i]);
  }

  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s PATH_TO_QAFF_BPF_OBJECT\n", argv[0]);
    return 2;
  }

  const struct test_case tests[] = {
    {.family = AF_INET, .name = "ipv4", .fallback_worker = FALLBACK_WORKER},
    {.family = AF_INET6, .name = "ipv6", .fallback_worker = FALLBACK_WORKER},
    {
      .family = AF_INET,
      .name = "ipv4-configured-fallback",
      .fallback_worker = CONFIGURED_FALLBACK_WORKER,
    },
  };

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    int rc = run_case(argv[1], &tests[i]);
    if (rc != 0) {
      return rc;
    }
  }

  return 0;
}
