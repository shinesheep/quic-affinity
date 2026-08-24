#include "quic_affinity/control.h"
#include "quic_affinity/qaffinity.h"
#include "quic_parser.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef QAFF_PROJECT_VERSION
#define QAFF_PROJECT_VERSION "unknown"
#endif

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
          "  qaffctl register-passive-cid SOCKET WORKER_ID CID_HEX CONFIDENCE SOURCE\n"
          "  qaffctl retire-passive-cid SOCKET CID_HEX\n"
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

  unsigned int healthy = config.fallback_available &&
                         !config.state_persistence_degraded &&
                         !config.worker_cleanup_degraded &&
                         !config.passive_cleanup_degraded &&
                         !config.cid_consistency_degraded &&
                         config.cid_index_mismatch == 0;
  printf("ok=%u\n", healthy);
  printf("fallback_available=%u\n", config.fallback_available);
  printf("state_persistence_degraded=%u\n",
         config.state_persistence_degraded);
  printf("state_persistence_error_count=%llu\n",
         (unsigned long long)config.state_persistence_error_count);
  printf("state_persistence_retry_count=%llu\n",
         (unsigned long long)config.state_persistence_retry_count);
  printf("worker_cleanup_degraded=%u\n", config.worker_cleanup_degraded);
  printf("worker_cleanup_pending_count=%u\n",
         config.worker_cleanup_pending_count);
  printf("worker_cleanup_error_count=%llu\n",
         (unsigned long long)config.worker_cleanup_error_count);
  printf("worker_cleanup_retry_count=%llu\n",
         (unsigned long long)config.worker_cleanup_retry_count);
  printf("passive_cleanup_degraded=%u\n",
         config.passive_cleanup_degraded);
  printf("passive_cleanup_retry_count=%llu\n",
         (unsigned long long)config.passive_cleanup_retry_count);
  printf("cid_consistency_degraded=%u\n",
         config.cid_consistency_degraded);
  printf("attached=%u\n", config.attached);
  printf("worker_count=%u\n", config.worker_count);
  printf("recovering_worker_count=%u\n", config.recovering_worker_count);
  printf("cid_map_count=%llu\n",
         (unsigned long long)config.cid_map_count);
  printf("cid_owner_count=%llu\n",
         (unsigned long long)config.cid_owner_count);
  printf("cid_index_mismatch=%llu\n",
         (unsigned long long)config.cid_index_mismatch);
  printf("passive_entry_count=%llu\n",
         (unsigned long long)config.passive_entry_count);
  printf("passive_entry_capacity=%llu\n",
         (unsigned long long)config.passive_entry_capacity);
  printf("passive_cleanup_error_count=%llu\n",
         (unsigned long long)config.passive_cleanup_error_count);
  close(fd);
  return healthy ? 0 : 1;
}

static void print_config(const struct qaff_control_config *config) {
  printf("short_cid_len=%u\n", config->short_cid_len);
  printf("cid_profile_enabled=%u\n", config->cid_profile_enabled);
  printf("cid_profile_key_fingerprint=%016llx\n",
         (unsigned long long)config->cid_profile_key_fingerprint);
  printf("passive_affinity_enabled=%u\n", config->passive_affinity_enabled);
  printf("passive_min_confidence=%u\n", config->passive_min_confidence);
  printf("egress_attached=%u\n", config->egress_attached);
  printf("attached=%u\n", config->attached);
  printf("worker_count=%u\n", config->worker_count);
  printf("recovering_worker_count=%u\n", config->recovering_worker_count);
  printf("fallback_mode=%s\n",
         config->fallback_mode == QAFF_FALLBACK_MODE_KERNEL
             ? "kernel"
             : "fixed");
  printf("fallback_worker_id=%u\n", config->fallback_worker_id);
  printf("fallback_available=%u\n", config->fallback_available);
  printf("state_persistence_degraded=%u\n",
         config->state_persistence_degraded);
  printf("state_persistence_error_count=%llu\n",
         (unsigned long long)config->state_persistence_error_count);
  printf("state_persistence_retry_count=%llu\n",
         (unsigned long long)config->state_persistence_retry_count);
  printf("worker_cleanup_degraded=%u\n",
         config->worker_cleanup_degraded);
  printf("worker_cleanup_pending_count=%u\n",
         config->worker_cleanup_pending_count);
  printf("worker_cleanup_error_count=%llu\n",
         (unsigned long long)config->worker_cleanup_error_count);
  printf("worker_cleanup_retry_count=%llu\n",
         (unsigned long long)config->worker_cleanup_retry_count);
  printf("cid_consistency_degraded=%u\n",
         config->cid_consistency_degraded);
  printf("cid_map_count=%llu\n",
         (unsigned long long)config->cid_map_count);
  printf("cid_owner_count=%llu\n",
         (unsigned long long)config->cid_owner_count);
  printf("cid_index_mismatch=%llu\n",
         (unsigned long long)config->cid_index_mismatch);
  printf("passive_entry_count=%llu\n",
         (unsigned long long)config->passive_entry_count);
  printf("passive_entry_capacity=%llu\n",
         (unsigned long long)config->passive_entry_capacity);
  printf("passive_expired_count=%llu\n",
         (unsigned long long)config->passive_expired_count);
  printf("passive_worker_purged_count=%llu\n",
         (unsigned long long)config->passive_worker_purged_count);
  printf("passive_expiry_initialized_count=%llu\n",
         (unsigned long long)config->passive_expiry_initialized_count);
  printf("passive_cleanup_error_count=%llu\n",
         (unsigned long long)config->passive_cleanup_error_count);
  printf("passive_cleanup_degraded=%u\n",
         config->passive_cleanup_degraded);
  printf("passive_cleanup_retry_count=%llu\n",
         (unsigned long long)config->passive_cleanup_retry_count);
  printf("passive_scan_interval_ms=%llu\n",
         (unsigned long long)config->passive_scan_interval_ms);
  printf("worker_recovery_timeout_ms=%llu\n",
         (unsigned long long)config->worker_recovery_timeout_ms);
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
  printf("cid_consistency_degraded=%u\n",
         config.cid_consistency_degraded);
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

  struct qaff_control_worker_info workers[QAFF_CONTROL_WORKER_CAPACITY];
  size_t workers_len = 0;
  if (qaff_control_workers_info(fd,
                                workers,
                                QAFF_CONTROL_WORKER_CAPACITY,
                                &workers_len) != 0) {
    perror("qaff_control_workers_info");
    close(fd);
    return 1;
  }

  printf("workers_len=%zu\n", workers_len);
  for (size_t i = 0;
       i < workers_len && i < QAFF_CONTROL_WORKER_CAPACITY;
       i++) {
    printf("worker=%u generation=%u leased=%u recovering=%u cleanup_pending=%u "
           "has_cred=%u pidfd=%u "
           "pid=%u target_pid=%u "
           "uid=%u gid=%u registered_ms_ago=%llu last_seen_ms_ago=%llu\n",
           workers[i].worker_id,
           workers[i].generation,
           (workers[i].flags & QAFF_CONTROL_WORKER_FLAG_LEASED) ? 1u : 0u,
           (workers[i].flags & QAFF_CONTROL_WORKER_FLAG_RECOVERING) ? 1u : 0u,
           (workers[i].flags & QAFF_CONTROL_WORKER_FLAG_CLEANUP_PENDING)
               ? 1u
               : 0u,
           (workers[i].flags & QAFF_CONTROL_WORKER_FLAG_CRED) ? 1u : 0u,
           (workers[i].flags & QAFF_CONTROL_WORKER_FLAG_PIDFD) ? 1u : 0u,
           workers[i].pid,
           workers[i].target_pid,
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

static int parse_passive_confidence(const char *text, uint8_t *out) {
  if (strcmp(text, "low") == 0 || strcmp(text, "1") == 0) {
    *out = QAFF_PASSIVE_CONFIDENCE_LOW;
    return 0;
  }
  if (strcmp(text, "medium") == 0 || strcmp(text, "2") == 0) {
    *out = QAFF_PASSIVE_CONFIDENCE_MEDIUM;
    return 0;
  }
  if (strcmp(text, "high") == 0 || strcmp(text, "3") == 0) {
    *out = QAFF_PASSIVE_CONFIDENCE_HIGH;
    return 0;
  }
  errno = EINVAL;
  return -1;
}

static int parse_passive_source(const char *text, uint8_t *out) {
  if (strcmp(text, "ingress") == 0 || strcmp(text, "1") == 0) {
    *out = QAFF_PASSIVE_SOURCE_INGRESS;
    return 0;
  }
  if (strcmp(text, "egress") == 0 || strcmp(text, "2") == 0) {
    *out = QAFF_PASSIVE_SOURCE_EGRESS;
    return 0;
  }
  errno = EINVAL;
  return -1;
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

static int cmd_register_passive_cid(int argc, char **argv) {
  if (argc != 7) {
    usage(stderr);
    return 2;
  }

  uint32_t worker_id = 0;
  if (parse_u32_arg(argv[3], &worker_id) != 0) {
    fprintf(stderr, "invalid worker id\n");
    return 2;
  }

  uint8_t *cid = NULL;
  size_t cid_len = 0;
  if (parse_hex(argv[4], &cid, &cid_len) != 0 ||
      cid_len == 0 ||
      cid_len > QAFF_MAX_CID_LEN) {
    fprintf(stderr, "invalid CID hex\n");
    free(cid);
    return 2;
  }

  struct qaff_passive_cid_value value;
  memset(&value, 0, sizeof(value));
  value.worker_id = worker_id;
  if (parse_passive_confidence(argv[5], &value.confidence) != 0) {
    fprintf(stderr, "invalid passive confidence\n");
    free(cid);
    return 2;
  }
  if (parse_passive_source(argv[6], &value.source) != 0) {
    fprintf(stderr, "invalid passive source\n");
    free(cid);
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    free(cid);
    return 1;
  }

  if (qaff_control_register_passive_cid(fd, cid, cid_len, &value) != 0) {
    perror("qaff_control_register_passive_cid");
    close(fd);
    free(cid);
    return 1;
  }

  close(fd);
  free(cid);
  return 0;
}

static int cmd_retire_passive_cid(int argc, char **argv) {
  if (argc != 4) {
    usage(stderr);
    return 2;
  }

  uint8_t *cid = NULL;
  size_t cid_len = 0;
  if (parse_hex(argv[3], &cid, &cid_len) != 0 ||
      cid_len == 0 ||
      cid_len > QAFF_MAX_CID_LEN) {
    fprintf(stderr, "invalid CID hex\n");
    free(cid);
    return 2;
  }

  int fd = open_control_or_die(argv[2]);
  if (fd < 0) {
    free(cid);
    return 1;
  }

  if (qaff_control_retire_passive_cid(fd, cid, cid_len) != 0) {
    perror("qaff_control_retire_passive_cid");
    close(fd);
    free(cid);
    return 1;
  }

  close(fd);
  free(cid);
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
    printf("qaffctl %s\n", QAFF_PROJECT_VERSION);
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

  if (strcmp(argv[1], "register-passive-cid") == 0) {
    return cmd_register_passive_cid(argc, argv);
  }

  if (strcmp(argv[1], "retire-passive-cid") == 0) {
    return cmd_retire_passive_cid(argc, argv);
  }

  if (strcmp(argv[1], "stop") == 0) {
    return cmd_stop(argc, argv);
  }

  usage(stderr);
  return 2;
}
