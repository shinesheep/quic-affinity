#ifndef QUIC_AFFINITY_CID_PROFILE_H
#define QUIC_AFFINITY_CID_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Listener-local key used to generate and validate routable CID profiles.
 *
 * This key is not a TLS secret and is never sent on the wire. It should still be
 * treated as routing-sensitive material: possession lets an actor mint CIDs
 * that pass profile validation for the listener.
 */
struct qaff_cid_profile_key {
  uint8_t bytes[QAFF_CID_PROFILE_KEY_LEN];
};

/** Decoded fields from an 8-byte routable CID profile v1. */
struct qaff_cid_profile_v1_fields {
  /** Profile version, currently QAFF_CID_PROFILE_V1_VERSION. */
  uint8_t version;
  /** Embedded worker ID; v1 encodes 16 bits. */
  uint32_t worker_id;
  /** Embedded 24-bit nonce. */
  uint32_t nonce;
};

/** Decoded fields from a 12-byte routable CID profile v2. */
struct qaff_cid_profile_v2_fields {
  /** Profile version, currently QAFF_CID_PROFILE_V2_VERSION. */
  uint8_t version;
  /** Listener-selected key/config generation identifier. */
  uint8_t config_id;
  /** Embedded worker ID; v2 encodes 16 bits. */
  uint32_t worker_id;
  /** Worker generation used to reject stale CIDs after worker-ID reuse. */
  uint32_t generation;
  /** Embedded 24-bit nonce. */
  uint32_t nonce;
};

/**
 * Generate an 8-byte routable CID profile v1.
 *
 * worker_id must be below QAFF_WORKER_CAPACITY and nonce must fit in 24 bits.
 * The output buffer must be at least QAFF_CID_PROFILE_V1_LEN bytes.
 *
 * Returns 0 on success or -1 with errno set.
 */
int qaff_cid_profile_v1_generate(const struct qaff_cid_profile_key *key,
                                  uint32_t worker_id,
                                  uint32_t nonce,
                                  uint8_t *out,
                                  size_t out_len);

/**
 * Validate and decode an 8-byte routable CID profile v1.
 *
 * Returns 0 on success or -1 with errno set to EINVAL, EPROTO, or EBADMSG.
 */
int qaff_cid_profile_v1_parse(const struct qaff_cid_profile_key *key,
                               const uint8_t *cid,
                               size_t cid_len,
                               struct qaff_cid_profile_v1_fields *out);

/**
 * Generate a 12-byte routable CID profile v2.
 *
 * config_id must fit in 8 bits, worker_id must be below QAFF_WORKER_CAPACITY,
 * generation in 1..255, and nonce in 24 bits. The output buffer must be at least
 * QAFF_CID_PROFILE_V2_LEN bytes.
 *
 * Returns 0 on success or -1 with errno set.
 */
int qaff_cid_profile_v2_generate(const struct qaff_cid_profile_key *key,
                                  uint32_t config_id,
                                  uint32_t worker_id,
                                  uint32_t generation,
                                  uint32_t nonce,
                                  uint8_t *out,
                                  size_t out_len);

/**
 * Validate and decode a 12-byte routable CID profile v2.
 *
 * The parser checks the profile tag but does not check the worker generation
 * against the live worker map; qaffd/BPF perform that deployment-time check.
 *
 * Returns 0 on success or -1 with errno set to EINVAL, EPROTO, or EBADMSG.
 */
int qaff_cid_profile_v2_parse(const struct qaff_cid_profile_key *key,
                               const uint8_t *cid,
                               size_t cid_len,
                               struct qaff_cid_profile_v2_fields *out);

#ifdef __cplusplus
}
#endif

#endif
