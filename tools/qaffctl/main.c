#include "quic_affinity/control.h"
#include "quic_affinity/quic_affinity.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *out) {
  fprintf(out,
          "Usage:\n"
          "  qaffctl version\n"
          "  qaffctl stat-names\n"
          "  qaffctl parse HEX_PACKET [SHORT_CID_LEN]\n"
          "  qaffctl health SOCKET\n"
          "  qaffctl config SOCKET\n"
          "  qaffctl cids SOCKET --count\n"
          "  qaffctl workers SOCKET\n"
          "  qaffctl unregister-worker SOCKET WORKER_ID\n"
          "  qaffctl stats SOCKET\n"
          "  qaffctl stop SOCKET\n");
}

static int hex_value(int c) {
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

static int parse_hex(const char *hex, uint8_t **out, size_t *out_len) {
  size_t digits = 0;
  for (const char *p = hex; *p; p++) {
    if (!isspace((unsigned char)*p) && *p != ':' && *p != '-') {
      if (hex_value((unsigned char)*p) < 0) {
        return -1;
      }
      digits++;
    }
  }

  if ((digits % 2) != 0) {
    return -1;
  }

  uint8_t *buf = calloc(digits / 2, 1);
  if (buf == NULL) {
    return -1;
  }

  size_t index = 0;
  int high = -1;
  for (const char *p = hex; *p; p++) {
    if (isspace((unsigned char)*p) || *p == ':' || *p == '-') {
      continue;
    }
    int v = hex_value((unsigned char)*p);
    if (high < 0) {
      high = v;
    } else {
      buf[index++] = (uint8_t)((high << 4) | v);
      high = -1;
    }
  }

  *out = buf;
  *out_len = index;
  return 0;
}

static void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
}

static int cmd_parse(int argc, char **argv) {
  if (argc < 3 || argc > 4) {
    usage(stderr);
    return 2;
  }

  uint8_t *packet = NULL;
  size_t packet_len = 0;
  if (parse_hex(argv[2], &packet, &packet_len) != 0) {
    fprintf(stderr, "invalid hex packet\n");
    return 2;
  }

  struct qaff_parse_config config = {0};
  if (argc == 4) {
    char *end = NULL;
    unsigned long value = strtoul(argv[3], &end, 10);
    if (end == argv[3] || *end != '\0' || value > QAFF_MAX_CID_LEN) {
      fprintf(stderr, "invalid short CID length\n");
      free(packet);
      return 2;
    }
    config.short_cid_len = (uint8_t)value;
  }

  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, packet_len, &config, &dcid);
  if (rc != QAFF_PARSE_OK) {
    printf("parse=%s\n", qaff_parse_result_str(rc));
    free(packet);
    return 1;
  }

  printf("parse=ok\n");
  printf("header=%s\n", dcid.is_long_header ? "long" : "short");
  if (dcid.is_long_header) {
    printf("version=0x%08x\n", dcid.version);
  }
  printf("dcid_len=%u\n", dcid.len);
  printf("dcid=");
  print_hex(dcid.data, dcid.len);
  printf("\n");

  free(packet);
  return 0;
}

static void print_stats(const struct qaff_stats *stats) {
  for (uint32_t i = 0; i < QAFF_STAT_MAX; i++) {
    printf("%s=%llu\n",
           qaff_stat_name(i),
           (unsigned long long)stats->values[i]);
  }
}

static int cmd_stats(int argc, char **argv) {
  if (argc != 3) {
    usage(stderr);
    return 2;
  }

  int fd = qaff_control_connect(argv[2]);
  if (fd < 0) {
    perror("qaff_control_connect");
    return 1;
  }

  struct qaff_stats stats;
  if (qaff_control_read_stats(fd, &stats) != 0) {
    perror("qaff_control_read_stats");
    close(fd);
    return 1;
  }

  print_stats(&stats);
  close(fd);
  return 0;
}

static int open_control_or_die(const char *socket_path) {
  int fd = qaff_control_connect(socket_path);
  if (fd < 0) {
    perror("qaff_control_connect");
  }
  return fd;
}

static int cmd_health(int argc, char **argv) {
  if (argc != 3) {
    usage(stderr);
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    return 1;
  }

  struct qaff_control_config config;
  if (qaff_control_config(fd, &config) != 0) {
    perror("qaff_control_config");
    close(fd);
    return 1;
  }

  printf("ok=1\n");
  printf("attached=%u\n", config.attached);
  printf("worker_count=%u\n", config.worker_count);
  printf("cid_map_count=%llu\n",
         (unsigned long long)config.cid_map_count);
  printf("cid_owner_count=%llu\n",
         (unsigned long long)config.cid_owner_count);
  printf("cid_index_mismatch=%llu\n",
         (unsigned long long)config.cid_index_mismatch);
  close(fd);
  return 0;
}

static void print_config(const struct qaff_control_config *config) {
  printf("short_cid_len=%u\n", config->short_cid_len);
  printf("attached=%u\n", config->attached);
  printf("worker_count=%u\n", config->worker_count);
  printf("fallback_worker_id=%u\n", config->fallback_worker_id);
  printf("cid_map_count=%llu\n",
         (unsigned long long)config->cid_map_count);
  printf("cid_owner_count=%llu\n",
         (unsigned long long)config->cid_owner_count);
  printf("cid_index_mismatch=%llu\n",
         (unsigned long long)config->cid_index_mismatch);
  printf("pin_root=%s\n", config->pin_root);
  printf("state_path=%s\n", config->state_path);
}

static int cmd_config(int argc, char **argv) {
  if (argc != 3) {
    usage(stderr);
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    return 1;
  }

  struct qaff_control_config config;
  if (qaff_control_config(fd, &config) != 0) {
    perror("qaff_control_config");
    close(fd);
    return 1;
  }

  print_config(&config);
  close(fd);
  return 0;
}

static int cmd_cids(int argc, char **argv) {
  if (argc != 4 || strcmp(argv[3], "--count") != 0) {
    usage(stderr);
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    return 1;
  }

  struct qaff_control_config config;
  if (qaff_control_cids(fd, &config) != 0) {
    perror("qaff_control_cids");
    close(fd);
    return 1;
  }

  printf("cid_map_count=%llu\n",
         (unsigned long long)config.cid_map_count);
  printf("cid_owner_count=%llu\n",
         (unsigned long long)config.cid_owner_count);
  printf("cid_index_mismatch=%llu\n",
         (unsigned long long)config.cid_index_mismatch);
  close(fd);
  return 0;
}

static int cmd_workers(int argc, char **argv) {
  if (argc != 3) {
    usage(stderr);
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    return 1;
  }

  struct qaff_control_worker_info workers[QAFF_CONTROL_MAX_WORKERS];
  size_t workers_len = 0;
  if (qaff_control_workers_info(fd,
                                workers,
                                QAFF_CONTROL_MAX_WORKERS,
                                &workers_len) != 0) {
    perror("qaff_control_workers_info");
    close(fd);
    return 1;
  }

  printf("workers_len=%zu\n", workers_len);
  for (size_t i = 0; i < workers_len && i < QAFF_CONTROL_MAX_WORKERS; i++) {
    printf("worker=%u leased=%u has_cred=%u pid=%u uid=%u gid=%u "
           "registered_ms_ago=%llu last_seen_ms_ago=%llu\n",
           workers[i].worker_id,
           (workers[i].flags & QAFF_CONTROL_WORKER_FLAG_LEASED) ? 1u : 0u,
           (workers[i].flags & QAFF_CONTROL_WORKER_FLAG_CRED) ? 1u : 0u,
           workers[i].pid,
           workers[i].uid,
           workers[i].gid,
           (unsigned long long)workers[i].registered_ms_ago,
           (unsigned long long)workers[i].last_seen_ms_ago);
  }

  close(fd);
  return 0;
}

static int parse_u32_arg(const char *text, uint32_t *out) {
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 10);
  if (end == text || *end != '\0' || value > UINT32_MAX) {
    errno = EINVAL;
    return -1;
  }
  *out = (uint32_t)value;
  return 0;
}

static int cmd_unregister_worker(int argc, char **argv) {
  if (argc != 4) {
    usage(stderr);
    return 2;
  }

  uint32_t worker_id = 0;
  if (parse_u32_arg(argv[3], &worker_id) != 0) {
    fprintf(stderr, "invalid worker id\n");
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    return 1;
  }

  if (qaff_control_unregister_worker(fd, worker_id) != 0) {
    perror("qaff_control_unregister_worker");
    close(fd);
    return 1;
  }

  close(fd);
  return 0;
}

static int cmd_stop(int argc, char **argv) {
  if (argc != 3) {
    usage(stderr);
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    return 1;
  }

  if (qaff_control_stop(fd) != 0) {
    perror("qaff_control_stop");
    close(fd);
    return 1;
  }

  close(fd);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(stderr);
    return 2;
  }

  if (strcmp(argv[1], "version") == 0) {
    printf("qaffctl 0.1.0\n");
    return 0;
  }

  if (strcmp(argv[1], "stat-names") == 0) {
    for (uint32_t i = 0; i < QAFF_STAT_MAX; i++) {
      printf("%u %s\n", i, qaff_stat_name(i));
    }
    return 0;
  }

  if (strcmp(argv[1], "parse") == 0) {
    return cmd_parse(argc, argv);
  }

  if (strcmp(argv[1], "stats") == 0) {
    return cmd_stats(argc, argv);
  }

  if (strcmp(argv[1], "health") == 0) {
    return cmd_health(argc, argv);
  }

  if (strcmp(argv[1], "config") == 0) {
    return cmd_config(argc, argv);
  }

  if (strcmp(argv[1], "cids") == 0) {
    return cmd_cids(argc, argv);
  }

  if (strcmp(argv[1], "workers") == 0) {
    return cmd_workers(argc, argv);
  }

  if (strcmp(argv[1], "unregister-worker") == 0) {
    return cmd_unregister_worker(argc, argv);
  }

  if (strcmp(argv[1], "stop") == 0) {
    return cmd_stop(argc, argv);
  }

  usage(stderr);
  return 2;
}
