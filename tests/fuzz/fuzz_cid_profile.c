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

static void verify_profile_parse(const struct qaff_cid_profile_key *key,
                                 const uint8_t *cid, size_t cid_len) {
  struct qaff_cid_profile_fields fields;
  if (qaff_cid_profile_parse(key, cid, cid_len, &fields) != 0) {
    return;
  }
  if (fields.worker_id >= QAFF_WORKER_CAPACITY || fields.generation == 0 ||
      fields.generation > QAFF_WORKER_GENERATION_MAX ||
      fields.nonce > UINT32_C(0xffffff)) {
    abort();
  }
  uint8_t regenerated[QAFF_CID_PROFILE_LEN];
  struct qaff_cid_profile_fields round_trip;
  if (qaff_cid_profile_generate(key, fields.worker_id, fields.generation,
                                fields.nonce, regenerated,
                                sizeof(regenerated)) != 0 ||
      qaff_cid_profile_parse(key, regenerated, sizeof(regenerated),
                             &round_trip) != 0 ||
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

  verify_profile_parse(&key, data, size);

  uint32_t hash = input_hash(data, size);
  uint8_t cid[QAFF_CID_PROFILE_LEN];
  struct qaff_cid_profile_fields fields;
  uint32_t generation = hash % QAFF_WORKER_GENERATION_MAX + 1;
  if (qaff_cid_profile_generate(
          &key, hash % QAFF_WORKER_CAPACITY, generation,
          hash & UINT32_C(0xffffff), cid, sizeof(cid)) != 0 ||
      qaff_cid_profile_parse(&key, cid, sizeof(cid), &fields) != 0 ||
      fields.generation != generation) {
    abort();
  }
  return 0;
}
