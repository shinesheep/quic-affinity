#include "quic_affinity/cid_profile.h"

#include <errno.h>
#include <string.h>

#define QAFF_CID_PROFILE_V1_WORKER_MAX 0xffffu
#define QAFF_CID_PROFILE_V1_NONCE_MAX 0xffffffu

static uint16_t profile_tag(const struct qaff_cid_profile_key *key,
                            const uint8_t *cid_prefix,
                            size_t cid_prefix_len) {
  uint32_t h = 2166136261u;

  for (size_t i = 0; i < QAFF_CID_PROFILE_KEY_LEN; i++) {
    h ^= key->bytes[i];
    h *= 16777619u;
  }
  for (size_t i = 0; i < cid_prefix_len; i++) {
    h ^= cid_prefix[i];
    h *= 16777619u;
  }

  h ^= h >> 16;
  return (uint16_t)h;
}

int qaff_cid_profile_v1_generate(const struct qaff_cid_profile_key *key,
                                  uint32_t worker_id,
                                  uint32_t nonce,
                                  uint8_t *out,
                                  size_t out_len) {
  if (key == NULL || out == NULL ||
      out_len < QAFF_CID_PROFILE_V1_LEN ||
      worker_id > QAFF_CID_PROFILE_V1_WORKER_MAX ||
      nonce > QAFF_CID_PROFILE_V1_NONCE_MAX) {
    errno = EINVAL;
    return -1;
  }

  out[0] = (uint8_t)(QAFF_CID_PROFILE_V1_VERSION << 4);
  out[1] = (uint8_t)(worker_id >> 8);
  out[2] = (uint8_t)worker_id;
  out[3] = (uint8_t)(nonce >> 16);
  out[4] = (uint8_t)(nonce >> 8);
  out[5] = (uint8_t)nonce;

  uint16_t tag = profile_tag(key, out, 6);
  out[6] = (uint8_t)(tag >> 8);
  out[7] = (uint8_t)tag;
  return 0;
}

int qaff_cid_profile_v1_parse(const struct qaff_cid_profile_key *key,
                               const uint8_t *cid,
                               size_t cid_len,
                               struct qaff_cid_profile_v1_fields *out) {
  if (key == NULL || cid == NULL || out == NULL ||
      cid_len != QAFF_CID_PROFILE_V1_LEN) {
    errno = EINVAL;
    return -1;
  }

  uint8_t version = cid[0] >> 4;
  if (version != QAFF_CID_PROFILE_V1_VERSION) {
    errno = EPROTO;
    return -1;
  }

  uint16_t expected_tag = profile_tag(key, cid, 6);
  uint16_t got_tag = (uint16_t)(((uint16_t)cid[6] << 8) | cid[7]);
  if (got_tag != expected_tag) {
    errno = EBADMSG;
    return -1;
  }

  memset(out, 0, sizeof(*out));
  out->version = version;
  out->worker_id = (uint32_t)(((uint32_t)cid[1] << 8) | cid[2]);
  out->nonce = ((uint32_t)cid[3] << 16) |
               ((uint32_t)cid[4] << 8) |
               (uint32_t)cid[5];
  return 0;
}
