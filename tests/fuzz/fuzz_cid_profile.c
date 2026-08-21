#include "quic_affinity/cid_profile.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static uint32_t input_hash(const uint8_t *data, size_t size) {
  uint32_t hash = UINT32_C(2166136261);
  for (size_t i = 0; i < size; i++) {
    hash ^= data[i];
    hash *= UINT32_C(16777619);
  }
  return hash;
}

static void verify_v1_parse(const struct qaff_cid_profile_key *key,
                            const uint8_t *cid, size_t cid_len) {
  struct qaff_cid_profile_v1_fields fields;
  if (qaff_cid_profile_v1_parse(key, cid, cid_len, &fields) != 0) {
    return;
  }
  if (fields.version != QAFF_CID_PROFILE_V1_VERSION ||
      fields.worker_id > UINT32_C(0xffff) ||
      fields.nonce > UINT32_C(0xffffff)) {
    abort();
  }
  uint8_t regenerated[QAFF_CID_PROFILE_V1_LEN];
  struct qaff_cid_profile_v1_fields round_trip;
  if (qaff_cid_profile_v1_generate(key, fields.worker_id, fields.nonce,
                                   regenerated, sizeof(regenerated)) != 0 ||
      qaff_cid_profile_v1_parse(key, regenerated, sizeof(regenerated),
                                &round_trip) != 0 ||
      round_trip.worker_id != fields.worker_id ||
      round_trip.nonce != fields.nonce) {
    abort();
  }
}

static void verify_v2_parse(const struct qaff_cid_profile_key *key,
                            const uint8_t *cid, size_t cid_len) {
  struct qaff_cid_profile_v2_fields fields;
  if (qaff_cid_profile_v2_parse(key, cid, cid_len, &fields) != 0) {
    return;
  }
  if (fields.version != QAFF_CID_PROFILE_V2_VERSION ||
      fields.worker_id > UINT32_C(0xffff) || fields.generation == 0 ||
      fields.generation > QAFF_WORKER_GENERATION_MAX ||
      fields.nonce > UINT32_C(0xffffff)) {
    abort();
  }
  uint8_t regenerated[QAFF_CID_PROFILE_V2_LEN];
  struct qaff_cid_profile_v2_fields round_trip;
  if (qaff_cid_profile_v2_generate(key, fields.config_id, fields.worker_id,
                                   fields.generation, fields.nonce, regenerated,
                                   sizeof(regenerated)) != 0 ||
      qaff_cid_profile_v2_parse(key, regenerated, sizeof(regenerated),
                                &round_trip) != 0 ||
      round_trip.config_id != fields.config_id ||
      round_trip.worker_id != fields.worker_id ||
      round_trip.generation != fields.generation ||
      round_trip.nonce != fields.nonce) {
    abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct qaff_cid_profile_key key = {0};
  for (size_t i = 0; i < sizeof(key.bytes) && size > 0; i++) {
    key.bytes[i] = data[i % size];
  }

  verify_v1_parse(&key, data, size);
  verify_v2_parse(&key, data, size);

  uint32_t hash = input_hash(data, size);
  uint8_t v1[QAFF_CID_PROFILE_V1_LEN];
  struct qaff_cid_profile_v1_fields v1_fields;
  if (qaff_cid_profile_v1_generate(&key, hash & UINT32_C(0xffff),
                                   hash & UINT32_C(0xffffff), v1,
                                   sizeof(v1)) != 0 ||
      qaff_cid_profile_v1_parse(&key, v1, sizeof(v1), &v1_fields) != 0) {
    abort();
  }

  uint8_t v2[QAFF_CID_PROFILE_V2_LEN];
  struct qaff_cid_profile_v2_fields v2_fields;
  uint32_t generation = hash % QAFF_WORKER_GENERATION_MAX + 1;
  if (qaff_cid_profile_v2_generate(
          &key, hash & UINT32_C(0xff), hash & UINT32_C(0xffff), generation,
          hash & UINT32_C(0xffffff), v2, sizeof(v2)) != 0 ||
      qaff_cid_profile_v2_parse(&key, v2, sizeof(v2), &v2_fields) != 0 ||
      v2_fields.generation != generation) {
    abort();
  }
  return 0;
}
