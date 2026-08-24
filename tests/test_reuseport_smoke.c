#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/cid_profile.h"
#include "quic_affinity/qaffinity.h"
#include "bpf_abi.h"
#include "qaffinity_internal.h"
#include "quic_parser.h"

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
#include <time.h>
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
#define CONFIGURED_FALLBACK_WORKER 1
#define TARGET_WORKER 2

static const uint8_t k_dcid[] = {
    0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
};

static const uint8_t k_unknown_dcid[] = {
    0xba, 0xad, 0xf0, 0x0d, 0x12, 0x34, 0x56, 0x78, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27,
};

static const uint8_t k_passive_dcid[] = {
    QAFF_CID_PROFILE_MAGIC_0, 0x61, 0x73, 0x73,
    0x01, 0x02, 0x03, 0x04, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37,
};

static const uint8_t k_worker_lifecycle_dcid[] = {
    0x6c, 0x69, 0x66, 0x65, 0x01, 0x02, 0x03, 0x04, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47,
};

static struct qaff_cid_profile_key profile_key(void) {
  struct qaff_cid_profile_key key;
  for (uint8_t i = 0; i < QAFF_CID_PROFILE_KEY_LEN; i++) {
    key.bytes[i] = (uint8_t)(0x70u + i);
  }
  return key;
}

static uint64_t monotonic_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
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
  uint8_t fallback_mode;
  uint32_t kernel_probe_packets;
};

struct sender_socket {
  int fd;
  uint16_t port;
};

struct quic_packet_class {
  const char *name;
  uint8_t first_byte;
};

static const struct quic_packet_class k_quic_packet_classes[] = {
    {.name = "Initial", .first_byte = 0xc3},
    {.name = "0-RTT", .first_byte = 0xd3},
    {.name = "Handshake", .first_byte = 0xe3},
    {.name = "Retry", .first_byte = 0xf3},
    {.name = "1-RTT", .first_byte = 0x43},
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
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) !=
        0) {
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
    if (setsockopt(sender->fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
                   sizeof(v6only)) != 0) {
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

static int send_quic_like_packet_type(int fd, int family, uint16_t port,
                                      uint8_t first_byte, const uint8_t *dcid,
                                      size_t dcid_len);

static int send_quic_like_packet(int fd, int family, uint16_t port,
                                 int short_header, const uint8_t *dcid,
                                 size_t dcid_len) {
  uint8_t first_byte = short_header ? 0x43u : 0xc3u;
  return send_quic_like_packet_type(fd, family, port, first_byte, dcid,
                                    dcid_len);
}

static int send_quic_like_packet_type(int fd, int family, uint16_t port,
                                      uint8_t first_byte, const uint8_t *dcid,
                                      size_t dcid_len) {
  int short_header = (first_byte & 0x80u) == 0;
  if (dcid_len > QAFF_MAX_CID_LEN ||
      (short_header && dcid_len != sizeof(k_dcid))) {
    errno = EINVAL;
    return -1;
  }

  uint8_t long_packet[1 + 4 + 1 + QAFF_MAX_CID_LEN + 1 + 4];
  size_t long_packet_len = 0;
  long_packet[long_packet_len++] = first_byte;
  long_packet[long_packet_len++] = 0x00;
  long_packet[long_packet_len++] = 0x00;
  long_packet[long_packet_len++] = 0x00;
  long_packet[long_packet_len++] = 0x01;
  long_packet[long_packet_len++] = (uint8_t)dcid_len;
  memcpy(long_packet + long_packet_len, dcid, dcid_len);
  long_packet_len += dcid_len;
  long_packet[long_packet_len++] = 0x00;
  long_packet[long_packet_len++] = 0x01;
  long_packet[long_packet_len++] = 0x02;
  long_packet[long_packet_len++] = 0x03;
  long_packet[long_packet_len++] = 0x04;

  uint8_t short_packet[1 + sizeof(k_dcid) + 4];
  size_t short_packet_len = 0;
  short_packet[short_packet_len++] = first_byte;
  memcpy(short_packet + short_packet_len, dcid, sizeof(k_dcid));
  short_packet_len += sizeof(k_dcid);
  short_packet[short_packet_len++] = 0x01;
  short_packet[short_packet_len++] = 0x02;
  short_packet[short_packet_len++] = 0x03;
  short_packet[short_packet_len++] = 0x04;

  const uint8_t *packet = short_header ? short_packet : long_packet;
  size_t packet_len = short_header ? short_packet_len : long_packet_len;

  ssize_t sent;
  if (family == AF_INET) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);
    sent =
        sendto(fd, packet, packet_len, 0, (struct sockaddr *)&dst, sizeof(dst));
  } else {
    struct sockaddr_in6 dst6;
    memset(&dst6, 0, sizeof(dst6));
    dst6.sin6_family = AF_INET6;
    dst6.sin6_addr = in6addr_loopback;
    dst6.sin6_port = htons(port);
    sent = sendto(fd, packet, packet_len, 0, (struct sockaddr *)&dst6,
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
  struct pollfd fds[WORKER_COUNT + 1];
  if (count > WORKER_COUNT + 1) {
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
    fprintf(stderr, "stat.%s=%llu\n", qaff_stat_name(i),
            (unsigned long long)stats.values[i]);
  }
}

static int expect_stat(struct qaff_context *ctx, enum qaff_stat_index index,
                       uint64_t expected) {
  struct qaff_stats stats;
  if (qaff_read_stats(ctx, &stats) != 0) {
    perror("qaff_read_stats");
    return -1;
  }

  if (stats.values[index] != expected) {
    fprintf(stderr, "expected stat.%s=%llu, got %llu\n", qaff_stat_name(index),
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
  uint64_t packets = 9u + test->kernel_probe_packets;
  uint64_t fallback = 2u + test->kernel_probe_packets;
  uint64_t passive_miss = 1u + test->kernel_probe_packets;

  if (expect_stat(ctx, QAFF_STAT_PACKETS, packets) != 0 ||
      expect_stat(ctx, QAFF_STAT_CID_MAP_HIT, 5) != 0 ||
      expect_stat(ctx, QAFF_STAT_FALLBACK, fallback) != 0 ||
      expect_stat(ctx, QAFF_STAT_PARSE_ERROR, 0) != 0 ||
      expect_stat(ctx, QAFF_STAT_ZERO_LENGTH_CID, 0) != 0 ||
      expect_stat(ctx, QAFF_STAT_WORKER_MISSING, 0) != 0 ||
      expect_stat(ctx, family_stat, packets) != 0 ||
      expect_stat(ctx, QAFF_STAT_NOT_UDP, 0) != 0 ||
      expect_stat(ctx, QAFF_STAT_CID_PROFILE_HIT, 1) != 0 ||
      expect_stat(ctx, QAFF_STAT_CID_PROFILE_REJECT, 1) != 0 ||
      expect_stat(ctx, QAFF_STAT_PASSIVE_HIT, 1) != 0 ||
      expect_stat(ctx, QAFF_STAT_PASSIVE_MISS, passive_miss) != 0 ||
      expect_stat(ctx, QAFF_STAT_PASSIVE_REJECT_CONFIDENCE, 0) != 0 ||
      expect_stat(ctx, QAFF_STAT_PASSIVE_REJECT_GENERATION, 0) != 0) {
    fprintf(stderr, "%s: unexpected dataplane stats\n", test->name);
    return -1;
  }

  return 0;
}

static int is_expected_fallback_receiver(const struct test_case *test,
                                         int receiver) {
  return receiver >= 0 && (test->fallback_mode == QAFF_FALLBACK_MODE_KERNEL ||
                           receiver == (int)test->fallback_worker);
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
  uint8_t profile_cid[QAFF_CID_PROFILE_LEN];
  uint8_t tampered_profile_cid[QAFF_CID_PROFILE_LEN];

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
            test->name, senders[0].port);
    return 1;
  }

  struct qaff_options options;
  qaff_options_init(&options);
  options.short_cid_len = sizeof(k_dcid);
  options.fallback_worker_id = test->fallback_worker;
  options.fallback_mode = test->fallback_mode;
  options.cid_profile_enabled = 1;
  options.passive_affinity_enabled = 1;
  options.passive_min_confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  memcpy(options.cid_profile_key, key.bytes, sizeof(options.cid_profile_key));

  if (qaff_cid_profile_generate(&key, TARGET_WORKER,
                                QAFF_WORKER_GENERATION_DEFAULT, 0x010203,
                                profile_cid, sizeof(profile_cid)) != 0) {
    perror("qaff_cid_profile_generate");
    return 1;
  }
  memcpy(tampered_profile_cid, profile_cid, sizeof(tampered_profile_cid));
  tampered_profile_cid[7] ^= 0x01;

  if (qaff_open(&options, &ctx) != 0) {
    if (errno == EPERM || errno == EACCES) {
      fprintf(stderr,
              "skipping: BPF map creation requires elevated privileges\n");
      for (size_t i = 0; i < WORKER_COUNT; i++) {
        close(workers[i]);
      }
      return TEST_SKIP;
    }
    perror("qaff_open");
    return 1;
  }
  struct qaff_config_value unpublished_config;
  uint32_t config_key = 0;
  if (bpf_map_lookup_elem(qaff_get_config_map_fd(ctx),
                          &config_key,
                          &unpublished_config) != 0 ||
      unpublished_config.short_cid_len != 0 ||
      unpublished_config.cid_profile_enabled != 0) {
    fprintf(stderr, "%s: qaff_open published configuration prematurely\n",
            test->name);
    return 1;
  }
  if (qaff_apply_config(ctx) != 0) {
    perror("qaff_apply_config");
    return 1;
  }
  errno = 0;
  if (qaff_register_worker_socket(ctx, 0, workers[0]) == 0 ||
      errno != ENOTSUP) {
    fprintf(stderr, "%s: profile accepted implicit worker generation\n",
            test->name);
    return 1;
  }

  struct qaff_passive_cid_value passive_value;
  memset(&passive_value, 0, sizeof(passive_value));
  passive_value.worker_id = TARGET_WORKER;
  passive_value.confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  passive_value.source = QAFF_PASSIVE_SOURCE_EGRESS;
  errno = 0;
  if (qaff_register_cid(ctx, k_dcid, sizeof(k_dcid), TARGET_WORKER) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: exact CID accepted an unregistered worker\n",
            test->name);
    return 1;
  }
  errno = 0;
  if (qaff_register_passive_cid(ctx, k_passive_dcid, sizeof(k_passive_dcid),
                                &passive_value) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: passive CID accepted an unregistered worker\n",
            test->name);
    return 1;
  }
  errno = 0;
  if (qaff_register_worker_socket_generation(
          ctx, QAFF_WORKER_CAPACITY, workers[0],
          QAFF_WORKER_GENERATION_DEFAULT) == 0 ||
      errno != EINVAL) {
    fprintf(stderr, "%s: worker registration accepted an invalid ID\n",
            test->name);
    return 1;
  }

  for (uint32_t i = 0; i < WORKER_COUNT; i++) {
    if (qaff_register_worker_socket_generation(
            ctx, i, workers[i], QAFF_WORKER_GENERATION_DEFAULT) != 0) {
      perror("qaff_register_worker_socket_generation");
      return 1;
    }
  }
  errno = 0;
  if (qaff_register_cid(ctx, k_dcid, sizeof(k_dcid), QAFF_WORKER_CAPACITY) ==
          0 ||
      errno != EINVAL) {
    fprintf(stderr, "%s: exact CID accepted an invalid worker ID\n",
            test->name);
    return 1;
  }
  passive_value.worker_id = QAFF_WORKER_CAPACITY;
  errno = 0;
  if (qaff_register_passive_cid(ctx, k_passive_dcid, sizeof(k_passive_dcid),
                                &passive_value) == 0 ||
      errno != EINVAL) {
    fprintf(stderr, "%s: passive CID accepted an invalid worker ID\n",
            test->name);
    return 1;
  }
  passive_value.worker_id = TARGET_WORKER;
  passive_value.worker_generation = 2;
  errno = 0;
  if (qaff_register_passive_cid(ctx, k_passive_dcid, sizeof(k_passive_dcid),
                                &passive_value) == 0 ||
      errno != EINVAL) {
    fprintf(stderr, "%s: passive CID accepted a stale generation\n",
            test->name);
    return 1;
  }
  passive_value.worker_generation = 0;
  errno = 0;
  if (qaff_unregister_worker_socket(ctx, 100) == 0 || errno != ENOENT) {
    fprintf(stderr, "%s: unregistered worker was removed successfully\n",
            test->name);
    return 1;
  }

  uint64_t target_socket_cookie = 0;
  socklen_t target_cookie_len = sizeof(target_socket_cookie);
  uint32_t cookie_worker_id = UINT32_MAX;
  if (getsockopt(workers[TARGET_WORKER], SOL_SOCKET, SO_COOKIE,
                 &target_socket_cookie, &target_cookie_len) != 0 ||
      target_cookie_len != sizeof(target_socket_cookie) ||
      bpf_map_lookup_elem(qaff_get_socket_worker_map_fd(ctx),
                          &target_socket_cookie, &cookie_worker_id) != 0 ||
      cookie_worker_id != TARGET_WORKER) {
    fprintf(stderr, "worker registration did not install socket-cookie map\n");
    return 1;
  }

  int replacement_worker = make_worker_socket(test->family, &port);
  if (replacement_worker < 0) {
    perror("make replacement worker socket");
    return 1;
  }
  errno = 0;
  if (qaff_register_worker_socket_generation(
          ctx, TARGET_WORKER, replacement_worker,
          QAFF_WORKER_GENERATION_DEFAULT) ==
          0 ||
      errno != EBUSY) {
    fprintf(stderr, "%s: active worker socket was replaced\n", test->name);
    return 1;
  }
  if (bpf_map_delete_elem(qaff_get_socket_worker_map_fd(ctx),
                          &target_socket_cookie) != 0) {
    perror("remove active worker socket-cookie mapping");
    return 1;
  }
  errno = 0;
  if (qaff_register_worker_socket_generation(
          ctx, TARGET_WORKER, replacement_worker,
          QAFF_WORKER_GENERATION_DEFAULT) ==
          0 ||
      errno != EBUSY) {
    fprintf(stderr,
            "%s: active worker with missing cookie mapping was replaced\n",
            test->name);
    return 1;
  }
  if (bpf_map_update_elem(qaff_get_socket_worker_map_fd(ctx),
                          &target_socket_cookie, &cookie_worker_id,
                          BPF_NOEXIST) != 0) {
    perror("restore active worker socket-cookie mapping");
    return 1;
  }
  close(replacement_worker);
  errno = 0;
  if (qaff_register_worker_socket_generation(
          ctx, FALLBACK_WORKER, workers[TARGET_WORKER],
          QAFF_WORKER_GENERATION_DEFAULT) == 0 ||
      errno != EEXIST) {
    fprintf(stderr, "socket was registered under multiple worker IDs\n");
    return 1;
  }

  if (qaff_register_cid(ctx, k_dcid, sizeof(k_dcid), TARGET_WORKER) != 0) {
    perror("qaff_register_cid");
    return 1;
  }
  if (qaff_register_cid(ctx, k_dcid, sizeof(k_dcid), TARGET_WORKER) != 0) {
    perror("qaff_register_cid idempotent");
    return 1;
  }
  errno = 0;
  if (qaff_register_cid(ctx, k_dcid, sizeof(k_dcid), FALLBACK_WORKER) == 0 ||
      errno != EEXIST) {
    fprintf(stderr, "live CID was reassigned to another worker\n");
    return 1;
  }
  passive_value.worker_generation = 0;
  uint64_t passive_registered_ns = monotonic_ns();
  if (passive_registered_ns == 0) {
    perror("clock_gettime");
    return 1;
  }
  passive_value.expires_at_ns = passive_registered_ns + 1000000000u;
  if (qaff_register_passive_cid(ctx, k_passive_dcid, sizeof(k_passive_dcid),
                                &passive_value) != 0) {
    perror("qaff_register_passive_cid");
    return 1;
  }
  if (qaff_register_passive_cid(ctx, k_passive_dcid, sizeof(k_passive_dcid),
                                &passive_value) != 0) {
    perror("qaff_register_passive_cid idempotent");
    return 1;
  }
  struct qaff_passive_cid_value conflicting_passive = passive_value;
  conflicting_passive.worker_id = FALLBACK_WORKER;
  errno = 0;
  if (qaff_register_passive_cid(ctx,
                                k_passive_dcid,
                                sizeof(k_passive_dcid),
                                &conflicting_passive) == 0 ||
      errno != EEXIST) {
    fprintf(stderr, "live passive CID was reassigned to another worker\n");
    return 1;
  }
  if (qaff_register_passive_cid(ctx, tampered_profile_cid,
                                sizeof(tampered_profile_cid),
                                &passive_value) != 0) {
    perror("register passive collision for rejected profile");
    return 1;
  }

  if (qaff_bpf_object_open(ctx, object_path, &object) != 0) {
    if (errno == EPERM || errno == EACCES) {
      fprintf(stderr,
              "skipping: BPF program load requires elevated privileges\n");
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

  for (size_t i = 0;
       i < sizeof(k_quic_packet_classes) / sizeof(k_quic_packet_classes[0]);
       i++) {
    const struct quic_packet_class *packet_class = &k_quic_packet_classes[i];
    if (send_quic_like_packet_type(senders[i % 2].fd, test->family, port,
                                   packet_class->first_byte, k_dcid,
                                   sizeof(k_dcid)) != 0) {
      perror(packet_class->name);
      return 1;
    }

    int worker = receive_worker(workers, WORKER_COUNT, 1000);
    if (worker != TARGET_WORKER) {
      fprintf(stderr, "%s: expected worker %d, got %d for QUIC %s packet\n",
              test->name, TARGET_WORKER, worker, packet_class->name);
      print_stats(ctx);
      return 1;
    }
  }

  if (send_quic_like_packet(senders[0].fd, test->family, port, 0, profile_cid,
                            sizeof(profile_cid)) != 0) {
    perror("send profile packet");
    return 1;
  }

  int profile_worker = receive_worker(workers, WORKER_COUNT, 1000);
  if (profile_worker != TARGET_WORKER) {
    fprintf(stderr, "%s: expected profile worker %d, got %d\n", test->name,
            TARGET_WORKER, profile_worker);
    print_stats(ctx);
    return 1;
  }

  if (send_quic_like_packet(senders[1].fd, test->family, port, 0,
                            tampered_profile_cid,
                            sizeof(tampered_profile_cid)) != 0) {
    perror("send tampered profile packet");
    return 1;
  }

  int tampered_fallback_worker = receive_worker(workers, WORKER_COUNT, 1000);
  if (tampered_fallback_worker < 0 ||
      (test->fallback_mode == QAFF_FALLBACK_MODE_FIXED &&
       tampered_fallback_worker != (int)test->fallback_worker)) {
    fprintf(stderr,
            "%s: expected tampered profile fallback worker %d, got %d\n",
            test->name, (int)test->fallback_worker, tampered_fallback_worker);
    print_stats(ctx);
    return 1;
  }

  if (send_quic_like_packet(senders[0].fd, test->family, port, 0,
                            k_passive_dcid, sizeof(k_passive_dcid)) != 0) {
    perror("send passive packet");
    return 1;
  }

  int passive_worker = receive_worker(workers, WORKER_COUNT, 1000);
  if (passive_worker != TARGET_WORKER) {
    fprintf(stderr, "%s: expected passive worker %d, got %d\n", test->name,
            TARGET_WORKER, passive_worker);
    print_stats(ctx);
    return 1;
  }
  struct qaff_cid_key passive_key;
  struct qaff_passive_cid_value refreshed_passive;
  if (qaff_cid_key_from_bytes(k_passive_dcid, sizeof(k_passive_dcid),
                              &passive_key) != QAFF_PARSE_OK ||
      bpf_map_lookup_elem(qaff_get_passive_cid_map_fd(ctx), &passive_key,
                          &refreshed_passive) != 0) {
    perror("lookup refreshed passive CID");
    return 1;
  }
  if (refreshed_passive.expires_at_ns <
      passive_registered_ns + QAFF_PASSIVE_TTL_EGRESS_NS) {
    fprintf(stderr, "%s: passive CID lifetime was not refreshed\n", test->name);
    return 1;
  }
  if (refreshed_passive.worker_generation != QAFF_WORKER_GENERATION_DEFAULT) {
    fprintf(stderr, "%s: passive CID did not inherit worker generation\n",
            test->name);
    return 1;
  }

  if (send_quic_like_packet(senders[0].fd, test->family, port, 0,
                            k_unknown_dcid, sizeof(k_unknown_dcid)) != 0) {
    perror("send_quic_like_packet");
    return 1;
  }

  int fallback_worker = receive_worker(workers, WORKER_COUNT, 1000);
  if (fallback_worker < 0 || (test->fallback_mode == QAFF_FALLBACK_MODE_FIXED &&
                              fallback_worker != (int)test->fallback_worker)) {
    fprintf(stderr, "%s: expected fallback worker %d, got %d\n", test->name,
            (int)test->fallback_worker, fallback_worker);
    print_stats(ctx);
    return 1;
  }

  if (test->fallback_mode == QAFF_FALLBACK_MODE_KERNEL) {
    uint32_t worker_mask = (1u << (uint32_t)tampered_fallback_worker) |
                           (1u << (uint32_t)fallback_worker);
    for (uint32_t i = 0; i < test->kernel_probe_packets; i++) {
      struct sender_socket probe = {.fd = -1, .port = 0};
      if (bind_sender_socket(test->family, &probe) != 0) {
        perror("bind kernel fallback probe");
        return 1;
      }
      int send_rc =
          send_quic_like_packet(probe.fd, test->family, port, 0, k_unknown_dcid,
                                sizeof(k_unknown_dcid));
      int saved_errno = errno;
      close(probe.fd);
      errno = saved_errno;
      if (send_rc != 0) {
        perror("send kernel fallback probe");
        return 1;
      }
      int selected = receive_worker(workers, WORKER_COUNT, 1000);
      if (selected < 0) {
        fprintf(stderr, "%s: kernel fallback probe was not delivered\n",
                test->name);
        return 1;
      }
      worker_mask |= 1u << (uint32_t)selected;
    }
    if ((worker_mask & (worker_mask - 1u)) == 0) {
      fprintf(stderr, "%s: kernel fallback did not distribute across workers\n",
              test->name);
      print_stats(ctx);
      return 1;
    }
  }

  if (expect_case_stats(ctx, test) != 0) {
    return 1;
  }

  if (qaff_retire_passive_cid(ctx, tampered_profile_cid,
                              sizeof(tampered_profile_cid)) != 0) {
    perror("retire passive collision for rejected profile");
    return 1;
  }

  uint64_t now_ns = monotonic_ns();
  if (now_ns == 0) {
    perror("clock_gettime for passive rejection matrix");
    return 1;
  }
  struct passive_reject_case {
    const char *name;
    enum qaff_stat_index reject_stat;
    struct qaff_passive_cid_value value;
  } passive_reject_cases[] = {
      {
          .name = "missing worker generation",
          .reject_stat = QAFF_STAT_PASSIVE_REJECT_GENERATION,
          .value = refreshed_passive,
      },
      {
          .name = "confidence below policy",
          .reject_stat = QAFF_STAT_PASSIVE_REJECT_CONFIDENCE,
          .value = refreshed_passive,
      },
      {
          .name = "expired monotonic TTL",
          .reject_stat = QAFF_STAT_PASSIVE_REJECT_EXPIRED,
          .value = refreshed_passive,
      },
  };
  passive_reject_cases[0].value.worker_generation = 0;
  passive_reject_cases[1].value.confidence = QAFF_PASSIVE_CONFIDENCE_MEDIUM;
  passive_reject_cases[2].value.expires_at_ns = now_ns - 1;

  for (size_t i = 0;
       i < sizeof(passive_reject_cases) / sizeof(passive_reject_cases[0]);
       i++) {
    const struct passive_reject_case *reject_case = &passive_reject_cases[i];
    struct qaff_stats before_reject;
    struct qaff_stats after_reject;
    if (qaff_read_stats(ctx, &before_reject) != 0 ||
        bpf_map_update_elem(qaff_get_passive_cid_map_fd(ctx), &passive_key,
                            &reject_case->value, BPF_ANY) != 0 ||
        send_quic_like_packet(senders[i % 2].fd, test->family, port, 0,
                              k_passive_dcid, sizeof(k_passive_dcid)) != 0) {
      perror(reject_case->name);
      return 1;
    }
    int receiver = receive_worker(workers, WORKER_COUNT, 1000);
    if (qaff_read_stats(ctx, &after_reject) != 0 ||
        !is_expected_fallback_receiver(test, receiver) ||
        after_reject.values[reject_case->reject_stat] !=
            before_reject.values[reject_case->reject_stat] + 1 ||
        after_reject.values[QAFF_STAT_PASSIVE_HIT] !=
            before_reject.values[QAFF_STAT_PASSIVE_HIT] ||
        after_reject.values[QAFF_STAT_FALLBACK] !=
            before_reject.values[QAFF_STAT_FALLBACK] + 1) {
      fprintf(stderr, "%s: passive rejection case '%s' selected receiver %d\n",
              test->name, reject_case->name, receiver);
      print_stats(ctx);
      return 1;
    }
  }
  passive_value.expires_at_ns = 0;
  if (qaff_retire_passive_cid(ctx,
                              k_passive_dcid,
                              sizeof(k_passive_dcid)) != 0 ||
      qaff_register_passive_cid(ctx, k_passive_dcid, sizeof(k_passive_dcid),
                                &passive_value) != 0) {
    perror("restore passive CID generation");
    return 1;
  }

  if (qaff_register_passive_cid(ctx, k_dcid, sizeof(k_dcid), &passive_value) !=
          0 ||
      qaff_register_passive_cid(ctx, profile_cid, sizeof(profile_cid),
                                &passive_value) != 0) {
    perror("register passive collisions for missing-worker matrix");
    return 1;
  }
  struct missing_route_case {
    const char *name;
    const uint8_t *dcid;
    size_t dcid_len;
    enum qaff_stat_index hit_stat;
  } missing_route_cases[] = {
      {
          .name = "exact",
          .dcid = k_dcid,
          .dcid_len = sizeof(k_dcid),
          .hit_stat = QAFF_STAT_CID_MAP_HIT,
      },
      {
          .name = "profile",
          .dcid = profile_cid,
          .dcid_len = sizeof(profile_cid),
          .hit_stat = QAFF_STAT_CID_PROFILE_HIT,
      },
      {
          .name = "passive",
          .dcid = k_passive_dcid,
          .dcid_len = sizeof(k_passive_dcid),
          .hit_stat = QAFF_STAT_PASSIVE_HIT,
      },
  };
  const enum qaff_stat_index route_hit_stats[] = {
      QAFF_STAT_CID_MAP_HIT,
      QAFF_STAT_CID_PROFILE_HIT,
      QAFF_STAT_PASSIVE_HIT,
  };
  uint32_t target_worker_key = TARGET_WORKER;
  if (bpf_map_delete_elem(qaff_get_worker_sock_map_fd(ctx),
                          &target_worker_key) != 0) {
    perror("remove target socket for missing-worker matrix");
    return 1;
  }
  for (size_t i = 0;
       i < sizeof(missing_route_cases) / sizeof(missing_route_cases[0]); i++) {
    const struct missing_route_case *missing_case = &missing_route_cases[i];
    struct qaff_stats before_missing;
    struct qaff_stats after_missing;
    if (qaff_read_stats(ctx, &before_missing) != 0 ||
        send_quic_like_packet(senders[i % 2].fd, test->family, port, 0,
                              missing_case->dcid,
                              missing_case->dcid_len) != 0) {
      perror(missing_case->name);
      return 1;
    }
    int receiver = receive_worker(workers, WORKER_COUNT, 1000);
    if (qaff_read_stats(ctx, &after_missing) != 0) {
      perror("read missing-worker matrix stats");
      return 1;
    }
    int route_counters_match = 1;
    for (size_t route = 0;
         route < sizeof(route_hit_stats) / sizeof(route_hit_stats[0]);
         route++) {
      uint64_t expected_delta =
          route_hit_stats[route] == missing_case->hit_stat ? 1u : 0u;
      if (after_missing.values[route_hit_stats[route]] !=
          before_missing.values[route_hit_stats[route]] + expected_delta) {
        route_counters_match = 0;
      }
    }
    if (!is_expected_fallback_receiver(test, receiver) ||
        after_missing.values[QAFF_STAT_WORKER_MISSING] !=
            before_missing.values[QAFF_STAT_WORKER_MISSING] + 1 ||
        after_missing.values[QAFF_STAT_FALLBACK] !=
            before_missing.values[QAFF_STAT_FALLBACK] + 1 ||
        !route_counters_match) {
      fprintf(stderr, "%s: missing %s-route socket selected receiver %d\n",
              test->name, missing_case->name, receiver);
      print_stats(ctx);
      return 1;
    }
  }
  if (qaff_register_worker_socket_generation(
          ctx, TARGET_WORKER, workers[TARGET_WORKER],
          QAFF_WORKER_GENERATION_DEFAULT) != 0 ||
      qaff_retire_passive_cid(ctx, k_dcid, sizeof(k_dcid)) != 0 ||
      qaff_retire_passive_cid(ctx, profile_cid, sizeof(profile_cid)) != 0) {
    perror("restore worker after missing-worker matrix");
    return 1;
  }

  if (qaff_retire_cid(ctx, k_dcid, sizeof(k_dcid)) != 0 ||
      qaff_register_cid(ctx, k_dcid, sizeof(k_dcid), FALLBACK_WORKER) != 0) {
    perror("retire and reassign CID");
    return 1;
  }
  if (qaff_register_cid(ctx, k_worker_lifecycle_dcid,
                        sizeof(k_worker_lifecycle_dcid), TARGET_WORKER) != 0) {
    perror("register worker lifecycle CID");
    return 1;
  }
  struct qaff_cid_key lifecycle_key;
  if (qaff_cid_key_from_bytes(k_worker_lifecycle_dcid,
                              sizeof(k_worker_lifecycle_dcid),
                              &lifecycle_key) != QAFF_PARSE_OK) {
    fprintf(stderr, "%s: could not build lifecycle CID key\n", test->name);
    return 1;
  }
  struct qaff_cid_value lifecycle_value;
  if (bpf_map_lookup_elem(qaff_get_cid_map_fd(ctx), &lifecycle_key,
                          &lifecycle_value) != 0 ||
      lifecycle_value.worker_id != TARGET_WORKER ||
      lifecycle_value.worker_generation != QAFF_WORKER_GENERATION_DEFAULT) {
    fprintf(stderr, "%s: exact CID was not generation-bound\n", test->name);
    return 1;
  }
  uint32_t withdrawn_worker = TARGET_WORKER;
  uint32_t withdrawn_generation = 0;
  if (bpf_map_update_elem(qaff_get_worker_generation_map_fd(ctx),
                          &withdrawn_worker, &withdrawn_generation,
                          BPF_ANY) != 0) {
    perror("inject interrupted worker withdrawal");
    return 1;
  }

  int replacement_after_withdrawal = make_worker_socket(test->family, &port);
  if (replacement_after_withdrawal < 0) {
    perror("make replacement after withdrawal");
    return 1;
  }
  struct qaff_options peer_options;
  qaff_options_init(&peer_options);
  peer_options.cid_map_fd = qaff_get_cid_map_fd(ctx);
  peer_options.passive_cid_map_fd = qaff_get_passive_cid_map_fd(ctx);
  peer_options.worker_sock_map_fd = qaff_get_worker_sock_map_fd(ctx);
  peer_options.socket_worker_map_fd = qaff_get_socket_worker_map_fd(ctx);
  peer_options.worker_generation_map_fd =
      qaff_get_worker_generation_map_fd(ctx);
  peer_options.stats_map_fd = qaff_get_stats_map_fd(ctx);
  peer_options.config_map_fd = qaff_get_config_map_fd(ctx);
  peer_options.short_cid_len = options.short_cid_len;
  peer_options.cid_profile_enabled = options.cid_profile_enabled;
  peer_options.passive_affinity_enabled = options.passive_affinity_enabled;
  peer_options.passive_min_confidence = options.passive_min_confidence;
  peer_options.fallback_mode = options.fallback_mode;
  peer_options.fallback_worker_id = options.fallback_worker_id;
  memcpy(peer_options.cid_profile_key, options.cid_profile_key,
         sizeof(peer_options.cid_profile_key));
  struct qaff_context *peer_ctx = NULL;
  if (qaff_open(&peer_options, &peer_ctx) != 0 ||
      qaff_apply_config(peer_ctx) != 0 ||
      qaff_register_worker_socket_generation(
          peer_ctx, TARGET_WORKER, replacement_after_withdrawal, 2) != 0) {
    perror("reuse worker ID from independent context");
    return 1;
  }
  int observed_workers[WORKER_COUNT + 1] = {
      workers[0],
      workers[1],
      workers[2],
      replacement_after_withdrawal,
  };

  errno = 0;
  if (qaff_register_cid(peer_ctx, k_worker_lifecycle_dcid,
                        sizeof(k_worker_lifecycle_dcid), TARGET_WORKER) == 0 ||
      errno != EEXIST) {
    fprintf(stderr, "%s: stale exact CID was silently reactivated\n",
            test->name);
    return 1;
  }

  struct qaff_passive_cid_value profile_collision = passive_value;
  profile_collision.worker_generation = 0;
  profile_collision.expires_at_ns = 0;
  struct qaff_stats before_stale_profile;
  struct qaff_stats after_stale_profile;
  if (qaff_register_passive_cid(peer_ctx, profile_cid, sizeof(profile_cid),
                                &profile_collision) != 0 ||
      qaff_read_stats(ctx, &before_stale_profile) != 0 ||
      send_quic_like_packet(senders[1].fd, test->family, port, 0, profile_cid,
                            sizeof(profile_cid)) != 0) {
    perror("send stale profile after worker reuse");
    return 1;
  }
  int stale_profile_receiver =
      receive_worker(observed_workers, WORKER_COUNT + 1, 1000);
  if (qaff_read_stats(ctx, &after_stale_profile) != 0 ||
      !is_expected_fallback_receiver(test, stale_profile_receiver) ||
      after_stale_profile.values[QAFF_STAT_CID_PROFILE_REJECT] !=
          before_stale_profile.values[QAFF_STAT_CID_PROFILE_REJECT] + 1 ||
      after_stale_profile.values[QAFF_STAT_CID_PROFILE_HIT] !=
          before_stale_profile.values[QAFF_STAT_CID_PROFILE_HIT] ||
      after_stale_profile.values[QAFF_STAT_PASSIVE_HIT] !=
          before_stale_profile.values[QAFF_STAT_PASSIVE_HIT] ||
      after_stale_profile.values[QAFF_STAT_FALLBACK] !=
          before_stale_profile.values[QAFF_STAT_FALLBACK] + 1) {
    fprintf(stderr,
            "%s: stale profile selected receiver %d after worker reuse\n",
            test->name, stale_profile_receiver);
    print_stats(ctx);
    return 1;
  }

  struct qaff_stats before_stale_exact;
  struct qaff_stats after_stale_exact;
  drain_workers(observed_workers, WORKER_COUNT + 1);
  if (qaff_read_stats(ctx, &before_stale_exact) != 0 ||
      send_quic_like_packet(senders[0].fd, test->family, port, 0,
                            k_worker_lifecycle_dcid,
                            sizeof(k_worker_lifecycle_dcid)) != 0) {
    perror("send stale exact CID after worker reuse");
    return 1;
  }
  int stale_exact_receiver =
      receive_worker(observed_workers, WORKER_COUNT + 1, 1000);
  if (qaff_read_stats(ctx, &after_stale_exact) != 0 ||
      stale_exact_receiver < 0 ||
      after_stale_exact.values[QAFF_STAT_CID_MAP_REJECT_GENERATION] !=
          before_stale_exact.values[QAFF_STAT_CID_MAP_REJECT_GENERATION] + 1 ||
      after_stale_exact.values[QAFF_STAT_CID_MAP_HIT] !=
          before_stale_exact.values[QAFF_STAT_CID_MAP_HIT] ||
      after_stale_exact.values[QAFF_STAT_FALLBACK] !=
          before_stale_exact.values[QAFF_STAT_FALLBACK] + 1 ||
      (test->fallback_mode == QAFF_FALLBACK_MODE_FIXED &&
       stale_exact_receiver != (int)test->fallback_worker)) {
    fprintf(stderr,
            "%s: stale exact CID selected receiver %d after worker reuse\n",
            test->name, stale_exact_receiver);
    return 1;
  }

  if (qaff_unregister_worker_socket(ctx, TARGET_WORKER) != 0) {
    perror("qaff_unregister_worker_socket");
    return 1;
  }
  qaff_close(peer_ctx);
  close(replacement_after_withdrawal);
  errno = 0;
  if (bpf_map_lookup_elem(qaff_get_socket_worker_map_fd(ctx),
                          &target_socket_cookie, &cookie_worker_id) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "worker unregister left a socket-cookie mapping\n");
    return 1;
  }
  errno = 0;
  if (bpf_map_lookup_elem(qaff_get_cid_map_fd(ctx), &lifecycle_key,
                          &lifecycle_value) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: worker unregister left an exact CID\n", test->name);
    return 1;
  }
  errno = 0;
  if (bpf_map_lookup_elem(qaff_get_passive_cid_map_fd(ctx), &passive_key,
                          &refreshed_passive) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: worker unregister left a passive CID\n", test->name);
    return 1;
  }
  errno = 0;
  if (qaff_register_cid(ctx, k_worker_lifecycle_dcid,
                        sizeof(k_worker_lifecycle_dcid), TARGET_WORKER) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: removed worker accepted a CID\n", test->name);
    return 1;
  }
  if (qaff_register_worker_socket_generation(ctx, TARGET_WORKER,
                                             workers[TARGET_WORKER], 3) != 0) {
    perror("reuse worker ID with a new generation");
    return 1;
  }
  errno = 0;
  if (qaff_register_worker_socket_generation(
          ctx, TARGET_WORKER, workers[TARGET_WORKER],
          QAFF_WORKER_GENERATION_DEFAULT) ==
          0 ||
      errno != EINVAL) {
    fprintf(stderr, "%s: worker generation regressed during registration\n",
            test->name);
    return 1;
  }
  errno = 0;
  if (bpf_map_lookup_elem(qaff_get_cid_map_fd(ctx), &lifecycle_key,
                          &lifecycle_value) == 0 ||
      errno != ENOENT) {
    fprintf(stderr, "%s: worker ID reuse reactivated an exact CID\n",
            test->name);
    return 1;
  }

  if (test->fallback_mode == QAFF_FALLBACK_MODE_FIXED) {
    drain_workers(workers, WORKER_COUNT);
    if (send_quic_like_packet(senders[0].fd, test->family, port, 0,
                              k_worker_lifecycle_dcid,
                              sizeof(k_worker_lifecycle_dcid)) != 0) {
      perror("send retired lifecycle CID");
      return 1;
    }
    int lifecycle_fallback = receive_worker(workers, WORKER_COUNT, 1000);
    if (lifecycle_fallback != (int)test->fallback_worker) {
      fprintf(stderr, "%s: retired CID reached worker %d after ID reuse\n",
              test->name, lifecycle_fallback);
      return 1;
    }
  }

  if (test->fallback_mode == QAFF_FALLBACK_MODE_FIXED) {
    if (qaff_unregister_worker_socket(ctx, test->fallback_worker) != 0) {
      perror("qaff_unregister_worker_socket fallback");
      return 1;
    }
    struct qaff_stats before_missing_fallback;
    struct qaff_stats after_missing_fallback;
    drain_workers(workers, WORKER_COUNT);
    if (qaff_read_stats(ctx, &before_missing_fallback) != 0 ||
        send_quic_like_packet(senders[0].fd, test->family, port, 0,
                              k_unknown_dcid, sizeof(k_unknown_dcid)) != 0) {
      perror("send missing fallback packet");
      return 1;
    }
    if (receive_worker(workers, WORKER_COUNT, 200) >= 0) {
      fprintf(stderr, "%s: missing fixed fallback failed open\n", test->name);
      return 1;
    }
    if (qaff_read_stats(ctx, &after_missing_fallback) != 0 ||
        after_missing_fallback.values[QAFF_STAT_WORKER_MISSING] !=
            before_missing_fallback.values[QAFF_STAT_WORKER_MISSING] + 1 ||
        after_missing_fallback.values[QAFF_STAT_FALLBACK] !=
            before_missing_fallback.values[QAFF_STAT_FALLBACK] + 1) {
      fprintf(stderr, "%s: missing fixed fallback was not counted\n",
              test->name);
      print_stats(ctx);
      return 1;
    }
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

  struct qaff_options invalid_options;
  struct qaff_context *invalid_context = NULL;
  qaff_options_init(&invalid_options);
  invalid_options.fallback_worker_id = QAFF_WORKER_CAPACITY;
  errno = 0;
  if (qaff_open(&invalid_options, &invalid_context) == 0 || errno != EINVAL) {
    fprintf(stderr, "accepted an out-of-range embedded fallback worker\n");
    qaff_close(invalid_context);
    return 1;
  }
  qaff_options_init(&invalid_options);
  invalid_options.short_cid_len = QAFF_CID_PROFILE_LEN;
  invalid_options.cid_profile_enabled = 1;
  errno = 0;
  if (qaff_open(&invalid_options, &invalid_context) == 0 || errno != EINVAL) {
    fprintf(stderr, "accepted an all-zero CID profile key\n");
    qaff_close(invalid_context);
    return 1;
  }
  qaff_options_init(&invalid_options);
  invalid_options.short_cid_len = 8;
  invalid_options.cid_profile_enabled = 1;
  errno = 0;
  if (qaff_open(&invalid_options, &invalid_context) == 0 || errno != EINVAL) {
    fprintf(stderr, "accepted CID profile with an incompatible CID length\n");
    qaff_close(invalid_context);
    return 1;
  }

  const struct test_case tests[] = {
      {.family = AF_INET, .name = "ipv4", .fallback_worker = FALLBACK_WORKER},
      {.family = AF_INET6, .name = "ipv6", .fallback_worker = FALLBACK_WORKER},
      {
          .family = AF_INET,
          .name = "ipv4-configured-fallback",
          .fallback_worker = CONFIGURED_FALLBACK_WORKER,
      },
      {
          .family = AF_INET,
          .name = "ipv4-kernel-fallback",
          .fallback_worker = FALLBACK_WORKER,
          .fallback_mode = QAFF_FALLBACK_MODE_KERNEL,
          .kernel_probe_packets = 48,
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
