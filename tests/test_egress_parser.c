#include "quic_affinity/quic_affinity.h"

#include <bpf/bpf.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_SKIP 77
#define UDP_HEADER_LEN 8

static const uint8_t k_dcid[] = {
  0xd0, 0xc1, 0xd0, 0xc1, 0x01, 0x02, 0x03, 0x04,
};

static const uint8_t k_scid[] = {
  0x5c, 0x1d, 0x5c, 0x1d, 0x05, 0x06, 0x07, 0x08,
};

static size_t append_udp_quic(uint8_t *packet,
                              size_t capacity,
                              size_t offset,
                              uint8_t first) {
  const size_t required = UDP_HEADER_LEN + 6 + sizeof(k_dcid) + 1 +
                          sizeof(k_scid);
  if (offset > capacity || capacity - offset < required) {
    return 0;
  }

  memset(packet + offset, 0, UDP_HEADER_LEN);
  offset += UDP_HEADER_LEN;
  packet[offset++] = first;
  packet[offset++] = 0;
  packet[offset++] = 0;
  packet[offset++] = 0;
  packet[offset++] = 1;
  packet[offset++] = sizeof(k_dcid);
  memcpy(packet + offset, k_dcid, sizeof(k_dcid));
  offset += sizeof(k_dcid);
  packet[offset++] = sizeof(k_scid);
  memcpy(packet + offset, k_scid, sizeof(k_scid));
  return offset + sizeof(k_scid);
}

static size_t make_ipv6_extension_packet(uint8_t *packet,
                                         size_t capacity,
                                         uint8_t extension_header,
                                         size_t extension_len) {
  if (capacity < 40 + extension_len || extension_len < 2) {
    return 0;
  }
  memset(packet, 0, capacity);
  packet[0] = 0x60;
  packet[6] = extension_header;
  packet[40] = 17;
  if (extension_header == 51) {
    packet[41] = (uint8_t)(extension_len / 4 - 2);
  } else {
    packet[41] = (uint8_t)(extension_len / 8 - 1);
  }
  return append_udp_quic(packet, capacity, 40 + extension_len, 0xc3);
}

static size_t make_ipv6_fragment_packet(uint8_t *packet, size_t capacity) {
  if (capacity < 48) {
    return 0;
  }
  memset(packet, 0, capacity);
  packet[0] = 0x60;
  packet[6] = 44;
  packet[40] = 17;
  return append_udp_quic(packet, capacity, 48, 0xc3);
}

static size_t make_ipv4_fragment_packet(uint8_t *packet, size_t capacity) {
  if (capacity < 20) {
    return 0;
  }
  memset(packet, 0, capacity);
  packet[0] = 0x45;
  packet[6] = 0x20;
  packet[9] = 17;
  return append_udp_quic(packet, capacity, 20, 0xc3);
}

static size_t make_ipv4_short_packet(uint8_t *packet, size_t capacity) {
  if (capacity < 20 + UDP_HEADER_LEN + 9) {
    return 0;
  }
  memset(packet, 0, capacity);
  packet[0] = 0x45;
  packet[9] = 17;
  size_t offset = 20 + UDP_HEADER_LEN;
  packet[offset++] = 0x43;
  memcpy(packet + offset, k_dcid, sizeof(k_dcid));
  return offset + sizeof(k_dcid);
}

static int run_packet(int program_fd, const uint8_t *packet, size_t len) {
  uint8_t frame[14 + 256];
  if (len > sizeof(frame) - 14) {
    errno = E2BIG;
    return -1;
  }
  memset(frame, 0, sizeof(frame));
  if ((packet[0] >> 4) == 6) {
    frame[12] = 0x86;
    frame[13] = 0xdd;
  } else {
    frame[12] = 0x08;
    frame[13] = 0x00;
  }
  memcpy(frame + 14, packet, len);

  struct bpf_test_run_opts opts;
  memset(&opts, 0, sizeof(opts));
  opts.sz = sizeof(opts);
  opts.data_in = frame;
  opts.data_size_in = len + 14;
  opts.repeat = 1;
  if (bpf_prog_test_run_opts(program_fd, &opts) != 0) {
    return -1;
  }
  if (opts.retval != 1) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int expect_delta(const struct qaff_stats *before,
                        const struct qaff_stats *after,
                        enum qaff_stat_index index,
                        uint64_t delta,
                        const char *name) {
  uint64_t actual = after->values[index] - before->values[index];
  if (actual == delta) {
    return 0;
  }
  fprintf(stderr,
          "%s: expected %s delta %llu, got %llu\n",
          name,
          qaff_stat_name(index),
          (unsigned long long)delta,
          (unsigned long long)actual);
  for (uint32_t i = 0; i < QAFF_STAT_MAX; i++) {
    uint64_t observed = after->values[i] - before->values[i];
    if (observed != 0) {
      fprintf(stderr,
              "  %s=%llu\n",
              qaff_stat_name(i),
              (unsigned long long)observed);
    }
  }
  return -1;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s PATH_TO_BPF_OBJECT\n", argv[0]);
    return 2;
  }

  struct qaff_options options;
  qaff_options_init(&options);
  options.short_cid_len = sizeof(k_dcid);
  options.passive_affinity_enabled = 1;

  struct qaff_context *ctx = NULL;
  if (qaff_open(&options, &ctx) != 0) {
    if (errno == EPERM || errno == EACCES) {
      fprintf(stderr, "skipping: BPF map creation is not permitted\n");
      return TEST_SKIP;
    }
    perror("qaff_open");
    return 1;
  }

  struct qaff_bpf_object *object = NULL;
  if (qaff_bpf_object_open(ctx, argv[1], &object) != 0) {
    if (errno == EPERM || errno == EACCES) {
      fprintf(stderr, "skipping: BPF program load is not permitted\n");
      qaff_close(ctx);
      return TEST_SKIP;
    }
    perror("qaff_bpf_object_open");
    qaff_close(ctx);
    return 1;
  }
  int program_fd = qaff_bpf_egress_program_fd(object);
  if (program_fd < 0) {
    fprintf(stderr, "egress program fd is unavailable\n");
    qaff_bpf_object_close(object);
    qaff_close(ctx);
    return 1;
  }

  uint8_t packet[256];
  struct qaff_stats before;
  struct qaff_stats after;
  if (qaff_read_stats(ctx, &before) != 0) {
    perror("qaff_read_stats before");
    return 1;
  }

  size_t len = make_ipv6_extension_packet(packet, sizeof(packet), 0, 8);
  if (len == 0 || run_packet(program_fd, packet, len) != 0) {
    perror("IPv6 hop-by-hop test run");
    return 1;
  }
  len = make_ipv6_extension_packet(packet, sizeof(packet), 51, 12);
  if (len == 0 || run_packet(program_fd, packet, len) != 0) {
    perror("IPv6 AH test run");
    return 1;
  }
  len = make_ipv6_fragment_packet(packet, sizeof(packet));
  if (len == 0 || run_packet(program_fd, packet, len) != 0) {
    perror("IPv6 fragment test run");
    return 1;
  }
  len = make_ipv4_fragment_packet(packet, sizeof(packet));
  if (len == 0 || run_packet(program_fd, packet, len) != 0) {
    perror("IPv4 fragment test run");
    return 1;
  }
  len = make_ipv4_short_packet(packet, sizeof(packet));
  if (len == 0 || run_packet(program_fd, packet, len) != 0) {
    perror("short-header test run");
    return 1;
  }

  if (qaff_read_stats(ctx, &after) != 0 ||
      expect_delta(&before,
                   &after,
                   QAFF_STAT_PASSIVE_EGRESS_NO_WORKER,
                   2,
                   "IPv6 extensions") != 0 ||
      expect_delta(&before,
                   &after,
                   QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_MISS,
                   2,
                   "IPv6 extensions") != 0 ||
      expect_delta(&before,
                   &after,
                   QAFF_STAT_PASSIVE_EGRESS_FRAGMENTED,
                   2,
                   "IP fragments") != 0 ||
      expect_delta(&before,
                   &after,
                   QAFF_STAT_PASSIVE_EGRESS_SHORT_HEADER,
                   1,
                   "short header") != 0 ||
      expect_delta(&before,
                   &after,
                   QAFF_STAT_PASSIVE_EGRESS_PARSE_MISS,
                   0,
                   "supported parser matrix") != 0) {
    return 1;
  }

  qaff_bpf_object_close(object);
  qaff_close(ctx);
  return 0;
}
