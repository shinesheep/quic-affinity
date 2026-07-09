#include "quic_affinity/quic_parser.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void parses_long_header_dcid(void) {
  const uint8_t packet[] = {
    0xc3,
    0x00, 0x00, 0x00, 0x01,
    0x08,
    0xde, 0xad, 0xbe, 0xef, 0xaa, 0xbb, 0xcc, 0xdd,
    0x04,
    0x11, 0x22, 0x33, 0x44,
  };

  struct qaff_parse_config config = {0};
  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, sizeof(packet), &config, &dcid);

  assert(rc == QAFF_PARSE_OK);
  assert(dcid.is_long_header == 1);
  assert(dcid.version == 1);
  assert(dcid.len == 8);
  assert(memcmp(dcid.data, "\xde\xad\xbe\xef\xaa\xbb\xcc\xdd", 8) == 0);
}

static void parses_short_header_dcid(void) {
  const uint8_t packet[] = {
    0x43,
    0xde, 0xad, 0xbe, 0xef,
    0x00, 0x01,
  };

  struct qaff_parse_config config = {.short_cid_len = 4};
  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, sizeof(packet), &config, &dcid);

  assert(rc == QAFF_PARSE_OK);
  assert(dcid.is_long_header == 0);
  assert(dcid.len == 4);
  assert(memcmp(dcid.data, "\xde\xad\xbe\xef", 4) == 0);
}

static void rejects_short_header_without_config(void) {
  const uint8_t packet[] = {0x43, 0xde, 0xad, 0xbe, 0xef};

  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, sizeof(packet), NULL, &dcid);

  assert(rc == QAFF_PARSE_ERR_SHORT_CID_LEN_REQUIRED);
}

static void rejects_too_long_dcid(void) {
  uint8_t packet[64] = {
    0xc3,
    0x00, 0x00, 0x00, 0x01,
    QAFF_MAX_CID_LEN + 1,
  };

  struct qaff_parse_config config = {0};
  struct qaff_dcid dcid;
  int rc = qaff_parse_dcid(packet, sizeof(packet), &config, &dcid);

  assert(rc == QAFF_PARSE_ERR_CID_TOO_LONG);
}

int main(void) {
  parses_long_header_dcid();
  parses_short_header_dcid();
  rejects_short_header_without_config();
  rejects_too_long_dcid();
  return 0;
}

