#ifndef QUIC_AFFINITY_CID_PROFILE_H
#define QUIC_AFFINITY_CID_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/types.h"

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

/** Return a non-secret stable fingerprint for configuration verification. */
uint64_t qaff_cid_profile_key_fingerprint(
    const struct qaff_cid_profile_key *key);

/** Decoded fields from a 16-byte routable CID profile. */
struct qaff_cid_profile_fields {
  /** Embedded worker ID; the profile encodes 16 bits. */
  uint32_t worker_id;
  /** Worker generation used to reject stale CIDs after worker-ID reuse. */
  uint32_t generation;
  /** Embedded 24-bit nonce. */
  uint32_t nonce;
};

/**
 * Generate a 16-byte routable CID profile.
 *
 * worker_id must be below QAFF_WORKER_CAPACITY, generation in 1..255, and nonce
 * in 24 bits. The output buffer must be at least QAFF_CID_PROFILE_LEN bytes.
 *
 * Returns 0 on success or -1 with errno set.
 */
int qaff_cid_profile_generate(const struct qaff_cid_profile_key *key,
                              uint32_t worker_id,
                              uint32_t generation,
                              uint32_t nonce,
                              uint8_t *out,
                              size_t out_len);

/**
 * Validate and decode a 16-byte routable CID profile.
 *
 * The parser checks the profile tag but does not check the worker generation
 * against the live worker map; qaffd/BPF perform that deployment-time check.
 *
 * Returns 0 on success or -1 with errno set to EINVAL, EPROTO, or EBADMSG.
 */
int qaff_cid_profile_parse(const struct qaff_cid_profile_key *key,
                           const uint8_t *cid,
                           size_t cid_len,
                           struct qaff_cid_profile_fields *out);

#ifdef __cplusplus
}
#endif

#endif
