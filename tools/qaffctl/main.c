#include "quic_affinity/quic_affinity.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out) {
  fprintf(out,
          "Usage:\n"
          "  qaffctl version\n"
          "  qaffctl stat-names\n"
          "  qaffctl parse HEX_PACKET [SHORT_CID_LEN]\n");
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

  usage(stderr);
  return 2;
}
