#ifndef QUIC_AFFINITY_QUIC_PARSER_H
#define QUIC_AFFINITY_QUIC_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Result codes returned by the QUIC DCID parser. */
enum qaff_parse_result {
  /** Parsing succeeded and qaff_dcid was populated. */
  QAFF_PARSE_OK = 0,
  /** The packet buffer ended before the DCID could be read. */
  QAFF_PARSE_ERR_TRUNCATED = -1,
  /** The packet advertised or configured a CID longer than QAFF_MAX_CID_LEN. */
  QAFF_PARSE_ERR_CID_TOO_LONG = -2,
  /** Short-header parsing requires a configured fixed DCID length. */
  QAFF_PARSE_ERR_SHORT_CID_LEN_REQUIRED = -3,
  /** A zero-length long-header DCID was rejected by policy. */
  QAFF_PARSE_ERR_ZERO_LENGTH_CID = -4,
};

/** Parser options for extracting a Destination Connection ID. */
struct qaff_parse_config {
  /**
   * Fixed DCID length for short-header packets.
   *
   * QUIC short headers do not carry a DCID length on the wire, so listeners
   * must configure the length used by their CID scheme.
   */
  uint8_t short_cid_len;

  /** Allow zero-length long-header DCIDs when non-zero. */
  int allow_zero_length_cid;
};

/** Borrowed view of a parsed Destination Connection ID. */
struct qaff_dcid {
  /** Pointer into the original packet buffer; not owned by the caller. */
  const uint8_t *data;
  /** Number of bytes at data. */
  uint8_t len;
  /** Non-zero for QUIC long-header packets. */
  int is_long_header;
  /** QUIC version from long headers, or 0 for short headers. */
  uint32_t version;
};

/**
 * Extract the QUIC Destination Connection ID from a UDP payload.
 *
 * On success, out->data points into packet. The caller must keep packet alive
 * for as long as it uses the returned view.
 *
 * Returns QAFF_PARSE_OK on success or a negative qaff_parse_result value.
 */
int qaff_parse_dcid(const uint8_t *packet,
                    size_t packet_len,
                    const struct qaff_parse_config *config,
                    struct qaff_dcid *out);

/**
 * Convert raw CID bytes into the fixed qaff_cid_key map-key layout.
 *
 * Returns QAFF_PARSE_OK on success or a negative qaff_parse_result value.
 */
int qaff_cid_key_from_bytes(const uint8_t *cid,
                            size_t cid_len,
                            struct qaff_cid_key *out);

/** Return a stable printable name for a qaff_parse_result value. */
const char *qaff_parse_result_str(int result);

#ifdef __cplusplus
}
#endif

#endif
