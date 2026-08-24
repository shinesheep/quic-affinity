#include "quic_parser.h"

#include <string.h>

static uint32_t qaff_read_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

int qaff_cid_key_from_bytes(const uint8_t *cid,
                            size_t cid_len,
                            struct qaff_cid_key *out) {
  if (cid == NULL || out == NULL) {
    return QAFF_PARSE_ERR_TRUNCATED;
  }
  if (cid_len > QAFF_MAX_CID_LEN) {
    return QAFF_PARSE_ERR_CID_TOO_LONG;
  }

  memset(out, 0, sizeof(*out));
  out->len = (uint8_t)cid_len;
  if (cid_len > 0) {
    memcpy(out->bytes, cid, cid_len);
  }
  return QAFF_PARSE_OK;
}

int qaff_parse_dcid(const uint8_t *packet,
                    size_t packet_len,
                    const struct qaff_parse_config *config,
                    struct qaff_dcid *out) {
  if (packet == NULL || out == NULL || packet_len < 1) {
    return QAFF_PARSE_ERR_TRUNCATED;
  }

  memset(out, 0, sizeof(*out));

  const uint8_t first = packet[0];
  const int is_long = (first & 0x80) != 0;

  if (is_long) {
    if (packet_len < 6) {
      return QAFF_PARSE_ERR_TRUNCATED;
    }

    const uint32_t version = qaff_read_be32(packet + 1);
    const uint8_t dcid_len = packet[5];

    if (dcid_len > QAFF_MAX_CID_LEN) {
      return QAFF_PARSE_ERR_CID_TOO_LONG;
    }
    if (dcid_len == 0 && (config == NULL || !config->allow_zero_length_cid)) {
      return QAFF_PARSE_ERR_ZERO_LENGTH_CID;
    }
    if (packet_len < (size_t)6 + dcid_len) {
      return QAFF_PARSE_ERR_TRUNCATED;
    }

    out->data = packet + 6;
    out->len = dcid_len;
    out->is_long_header = 1;
    out->version = version;
    return QAFF_PARSE_OK;
  }

  if (config == NULL || config->short_cid_len == 0) {
    return QAFF_PARSE_ERR_SHORT_CID_LEN_REQUIRED;
  }
  if (config->short_cid_len > QAFF_MAX_CID_LEN) {
    return QAFF_PARSE_ERR_CID_TOO_LONG;
  }
  if (packet_len < (size_t)1 + config->short_cid_len) {
    return QAFF_PARSE_ERR_TRUNCATED;
  }

  out->data = packet + 1;
  out->len = config->short_cid_len;
  out->is_long_header = 0;
  out->version = 0;
  return QAFF_PARSE_OK;
}

const char *qaff_parse_result_str(int result) {
  switch (result) {
  case QAFF_PARSE_OK:
    return "ok";
  case QAFF_PARSE_ERR_TRUNCATED:
    return "truncated";
  case QAFF_PARSE_ERR_CID_TOO_LONG:
    return "cid-too-long";
  case QAFF_PARSE_ERR_SHORT_CID_LEN_REQUIRED:
    return "short-cid-len-required";
  case QAFF_PARSE_ERR_ZERO_LENGTH_CID:
    return "zero-length-cid";
  default:
    return "unknown";
  }
}
