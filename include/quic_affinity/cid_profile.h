#ifndef QUIC_AFFINITY_CID_PROFILE_H
#define QUIC_AFFINITY_CID_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QAFF_CID_PROFILE_V1_LEN 8u
#define QAFF_CID_PROFILE_KEY_LEN 16u
#define QAFF_CID_PROFILE_V1_VERSION 1u

struct qaff_cid_profile_key {
  uint8_t bytes[QAFF_CID_PROFILE_KEY_LEN];
};

struct qaff_cid_profile_v1_fields {
  uint8_t version;
  uint32_t worker_id;
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

#ifdef __cplusplus
}
#endif

#endif
