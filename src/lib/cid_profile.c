#include "quic_affinity/cid_profile.h"

#include <errno.h>
#include <string.h>

#define QAFF_CID_PROFILE_NONCE_MAX 0xffffffu

uint64_t qaff_cid_profile_key_fingerprint(
    const struct qaff_cid_profile_key *key) {
  if (key == NULL) {
    return 0;
  }
  uint64_t hash = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < QAFF_CID_PROFILE_KEY_LEN; i++) {
    hash ^= key->bytes[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash == 0 ? 1 : hash;
}

static uint64_t load64_le(const uint8_t bytes[8]) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; i++) {
    value |= (uint64_t)bytes[i] << (8u * i);
  }
  return value;
}

static uint64_t rotl64(uint64_t value, unsigned int bits) {
  return (value << bits) | (value >> (64u - bits));
}

static void sip_round(uint64_t *v0, uint64_t *v1,
                      uint64_t *v2, uint64_t *v3) {
  *v0 += *v1;
  *v1 = rotl64(*v1, 13);
  *v1 ^= *v0;
  *v0 = rotl64(*v0, 32);
  *v2 += *v3;
  *v3 = rotl64(*v3, 16);
  *v3 ^= *v2;
  *v0 += *v3;
  *v3 = rotl64(*v3, 21);
  *v3 ^= *v0;
  *v2 += *v1;
  *v1 = rotl64(*v1, 17);
  *v1 ^= *v2;
  *v2 = rotl64(*v2, 32);
}

/* SipHash-2-4 over the fixed eight-byte profile routing prefix. */
static uint64_t profile_tag64(const struct qaff_cid_profile_key *key,
                              const uint8_t cid_prefix[8]) {
  uint64_t k0 = load64_le(key->bytes);
  uint64_t k1 = load64_le(key->bytes + 8);
  uint64_t v0 = UINT64_C(0x736f6d6570736575) ^ k0;
  uint64_t v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
  uint64_t v2 = UINT64_C(0x6c7967656e657261) ^ k0;
  uint64_t v3 = UINT64_C(0x7465646279746573) ^ k1;
  uint64_t message = load64_le(cid_prefix);

  v3 ^= message;
  sip_round(&v0, &v1, &v2, &v3);
  sip_round(&v0, &v1, &v2, &v3);
  v0 ^= message;

  uint64_t final_block = UINT64_C(8) << 56;
  v3 ^= final_block;
  sip_round(&v0, &v1, &v2, &v3);
  sip_round(&v0, &v1, &v2, &v3);
  v0 ^= final_block;
  v2 ^= UINT64_C(0xff);
  for (unsigned int i = 0; i < 4; i++) {
    sip_round(&v0, &v1, &v2, &v3);
  }
  return v0 ^ v1 ^ v2 ^ v3;
}

int qaff_cid_profile_generate(const struct qaff_cid_profile_key *key,
                              uint32_t worker_id,
                              uint32_t generation,
                              uint32_t nonce,
                              uint8_t *out,
                              size_t out_len) {
  if (key == NULL || out == NULL ||
      out_len < QAFF_CID_PROFILE_LEN ||
      worker_id >= QAFF_WORKER_CAPACITY ||
      generation == 0 ||
      generation > QAFF_WORKER_GENERATION_MAX ||
      nonce > QAFF_CID_PROFILE_NONCE_MAX) {
    errno = EINVAL;
    return -1;
  }

  out[0] = QAFF_CID_PROFILE_MAGIC_0;
  out[1] = QAFF_CID_PROFILE_MAGIC_1;
  out[2] = (uint8_t)(worker_id >> 8);
  out[3] = (uint8_t)worker_id;
  out[4] = (uint8_t)generation;
  out[5] = (uint8_t)(nonce >> 16);
  out[6] = (uint8_t)(nonce >> 8);
  out[7] = (uint8_t)nonce;

  uint64_t tag = profile_tag64(key, out);
  for (size_t i = 0; i < 8; i++) {
    out[8 + i] = (uint8_t)(tag >> (56u - 8u * i));
  }
  return 0;
}

int qaff_cid_profile_parse(const struct qaff_cid_profile_key *key,
                           const uint8_t *cid,
                           size_t cid_len,
                           struct qaff_cid_profile_fields *out) {
  if (key == NULL || cid == NULL || out == NULL ||
      cid_len != QAFF_CID_PROFILE_LEN) {
    errno = EINVAL;
    return -1;
  }

  if (cid[0] != QAFF_CID_PROFILE_MAGIC_0 ||
      cid[1] != QAFF_CID_PROFILE_MAGIC_1) {
    errno = EPROTO;
    return -1;
  }

  uint64_t expected_tag = profile_tag64(key, cid);
  uint64_t got_tag = 0;
  for (size_t i = 0; i < 8; i++) {
    got_tag = (got_tag << 8) | cid[8 + i];
  }
  if (got_tag != expected_tag) {
    errno = EBADMSG;
    return -1;
  }

  uint32_t worker_id = ((uint32_t)cid[2] << 8) | (uint32_t)cid[3];
  uint32_t generation = cid[4];
  if (worker_id >= QAFF_WORKER_CAPACITY || generation == 0) {
    errno = EINVAL;
    return -1;
  }

  memset(out, 0, sizeof(*out));
  out->worker_id = worker_id;
  out->generation = generation;
  out->nonce = ((uint32_t)cid[5] << 16) |
               ((uint32_t)cid[6] << 8) |
               (uint32_t)cid[7];
  return 0;
}
