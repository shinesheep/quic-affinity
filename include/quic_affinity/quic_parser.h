#ifndef QUIC_AFFINITY_QUIC_PARSER_H
#define QUIC_AFFINITY_QUIC_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

enum qaff_parse_result {
  QAFF_PARSE_OK = 0,
  QAFF_PARSE_ERR_TRUNCATED = -1,
  QAFF_PARSE_ERR_CID_TOO_LONG = -2,
  QAFF_PARSE_ERR_SHORT_CID_LEN_REQUIRED = -3,
  QAFF_PARSE_ERR_ZERO_LENGTH_CID = -4,
};

struct qaff_parse_config {
  uint8_t short_cid_len;
  int allow_zero_length_cid;
};

struct qaff_dcid {
  const uint8_t *data;
  uint8_t len;
  int is_long_header;
  uint32_t version;
};

int qaff_parse_dcid(const uint8_t *packet,
                    size_t packet_len,
                    const struct qaff_parse_config *config,
                    struct qaff_dcid *out);

int qaff_cid_key_from_bytes(const uint8_t *cid,
                            size_t cid_len,
                            struct qaff_cid_key *out);

const char *qaff_parse_result_str(int result);

#ifdef __cplusplus
}
#endif

#endif

