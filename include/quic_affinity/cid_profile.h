#ifndef QUIC_AFFINITY_CID_PROFILE_H
#define QUIC_AFFINITY_CID_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

struct qaff_cid_profile_key {
  uint8_t bytes[QAFF_CID_PROFILE_KEY_LEN];
};

struct qaff_cid_profile_v1_fields {
  uint8_t version;
  uint32_t worker_id;
  uint32_t nonce;
};

struct qaff_cid_profile_v2_fields {
  uint8_t version;
  uint8_t config_id;
  uint32_t worker_id;
  uint32_t generation;
  uint32_t nonce;
};

int qaff_cid_profile_v1_generate(const struct qaff_cid_profile_key *key,
                                  uint32_t worker_id,
                                  uint32_t nonce,
                                  uint8_t *out,
                                  size_t out_len);

int qaff_cid_profile_v1_parse(const struct qaff_cid_profile_key *key,
                               const uint8_t *cid,
                               size_t cid_len,
                               struct qaff_cid_profile_v1_fields *out);

int qaff_cid_profile_v2_generate(const struct qaff_cid_profile_key *key,
                                  uint32_t config_id,
                                  uint32_t worker_id,
                                  uint32_t generation,
                                  uint32_t nonce,
                                  uint8_t *out,
                                  size_t out_len);

int qaff_cid_profile_v2_parse(const struct qaff_cid_profile_key *key,
                               const uint8_t *cid,
                               size_t cid_len,
                               struct qaff_cid_profile_v2_fields *out);

#ifdef __cplusplus
}
#endif

#endif
