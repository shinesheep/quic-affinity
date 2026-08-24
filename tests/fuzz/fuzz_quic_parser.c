#include "quic_parser.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void verify_parse(const uint8_t *data, size_t size,
                         const struct qaff_parse_config *config) {
  struct qaff_dcid dcid;
  int result = qaff_parse_dcid(data, size, config, &dcid);
  (void)qaff_parse_result_str(result);
  if (result != QAFF_PARSE_OK) {
    return;
  }

  if (dcid.len > QAFF_MAX_CID_LEN || size == 0) {
    abort();
  }
  const int is_long = (data[0] & 0x80) != 0;
  const uint8_t *expected = data + (is_long ? 6 : 1);
  if (dcid.data != expected || dcid.is_long_header != is_long ||
      (size_t)(dcid.data - data) + dcid.len > size ||
      (!is_long && dcid.version != 0)) {
    abort();
  }

  struct qaff_cid_key key;
  if (qaff_cid_key_from_bytes(dcid.data, dcid.len, &key) != QAFF_PARSE_OK ||
      key.len != dcid.len || memcmp(key.bytes, dcid.data, dcid.len) != 0) {
    abort();
  }
  for (size_t i = key.len; i < sizeof(key.bytes); i++) {
    if (key.bytes[i] != 0) {
      abort();
    }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct qaff_parse_config derived = {
      .short_cid_len = size > 1 ? data[1] : 0,
      .allow_zero_length_cid = size > 2 && (data[2] & 1) != 0,
  };
  const struct qaff_parse_config boundaries[] = {
      {.short_cid_len = 1, .allow_zero_length_cid = 0},
      {.short_cid_len = QAFF_MAX_CID_LEN, .allow_zero_length_cid = 1},
      {.short_cid_len = QAFF_MAX_CID_LEN + 1, .allow_zero_length_cid = 1},
  };

  verify_parse(data, size, NULL);
  verify_parse(data, size, &derived);
  for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
    verify_parse(data, size, &boundaries[i]);
  }

  struct qaff_cid_key key;
  int key_result = qaff_cid_key_from_bytes(data, size, &key);
  if (key_result == QAFF_PARSE_OK) {
    if (size > QAFF_MAX_CID_LEN || key.len != size ||
        memcmp(key.bytes, data, size) != 0) {
      abort();
    }
    for (size_t i = size; i < sizeof(key.bytes); i++) {
      if (key.bytes[i] != 0) {
        abort();
      }
    }
  }
  return 0;
}
