#include "quic_parser.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,         \
              #condition);                                                     \
      return -1;                                                               \
    }                                                                          \
  } while (0)

static int parses_all_long_header_packet_types(void) {
  uint8_t packet[] = {
      0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0xde, 0xad, 0xbe, 0xef,
      0xaa, 0xbb, 0xcc, 0xdd, 0x04, 0x11, 0x22, 0x33, 0x44,
  };

  const uint8_t first_bytes[] = {
      0xc3, /* Initial */
      0xd3, /* 0-RTT */
      0xe3, /* Handshake */
      0xf3, /* Retry */
  };

  for (size_t i = 0; i < sizeof(first_bytes) / sizeof(first_bytes[0]); i++) {
    packet[0] = first_bytes[i];
    struct qaff_parse_config config = {0};
    struct qaff_dcid dcid;
    int rc = qaff_parse_dcid(packet, sizeof(packet), &config, &dcid);

    CHECK(rc == QAFF_PARSE_OK);
    CHECK(dcid.is_long_header == 1);
    CHECK(dcid.version == 1);
    CHECK(dcid.len == 8);
    CHECK(memcmp(dcid.data, "\xde\xad\xbe\xef\xaa\xbb\xcc\xdd", 8) == 0);
  }
  return 0;
}

static int parses_short_header_dcid(void) {
  const uint8_t packet[] = {
      0x43, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
  };

  struct qaff_parse_config config = {.short_cid_len = 4};
  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, sizeof(packet), &config, &dcid);

  CHECK(rc == QAFF_PARSE_OK);
  CHECK(dcid.is_long_header == 0);
  CHECK(dcid.len == 4);
  CHECK(memcmp(dcid.data, "\xde\xad\xbe\xef", 4) == 0);
  return 0;
}

static int rejects_short_header_without_config(void) {
  const uint8_t packet[] = {0x43, 0xde, 0xad, 0xbe, 0xef};

  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, sizeof(packet), NULL, &dcid);

  CHECK(rc == QAFF_PARSE_ERR_SHORT_CID_LEN_REQUIRED);
  return 0;
}

static int rejects_too_long_dcid(void) {
  uint8_t packet[64] = {
      0xc3, 0x00, 0x00, 0x00, 0x01, QAFF_MAX_CID_LEN + 1,
  };

  struct qaff_parse_config config = {0};
  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, sizeof(packet), &config, &dcid);

  CHECK(rc == QAFF_PARSE_ERR_CID_TOO_LONG);
  return 0;
}

int main(void) {
  if (parses_all_long_header_packet_types() != 0 ||
      parses_short_header_dcid() != 0 ||
      rejects_short_header_without_config() != 0 ||
      rejects_too_long_dcid() != 0) {
    return 1;
  }
  return 0;
}
