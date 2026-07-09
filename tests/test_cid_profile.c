#include "quic_affinity/cid_profile.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

static struct qaff_cid_profile_key test_key(void) {
  struct qaff_cid_profile_key key;
  for (uint8_t i = 0; i < QAFF_CID_PROFILE_KEY_LEN; i++) {
    key.bytes[i] = (uint8_t)(0xa0u + i);
  }
  return key;
}

static void roundtrips_v1_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];

  int rc = qaff_cid_profile_v1_generate(&key, 42, 0x010203, cid, sizeof(cid));
  assert(rc == 0);
  assert((cid[0] >> 4) == QAFF_CID_PROFILE_V1_VERSION);

  struct qaff_cid_profile_v1_fields fields;
  rc = qaff_cid_profile_v1_parse(&key, cid, sizeof(cid), &fields);
  assert(rc == 0);
  assert(fields.version == QAFF_CID_PROFILE_V1_VERSION);
  assert(fields.worker_id == 42);
  assert(fields.nonce == 0x010203);
}

static void rejects_tampered_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];
  assert(qaff_cid_profile_v1_generate(&key, 7, 9, cid, sizeof(cid)) == 0);

  cid[3] ^= 0x40;
  struct qaff_cid_profile_v1_fields fields;
  int rc = qaff_cid_profile_v1_parse(&key, cid, sizeof(cid), &fields);
  assert(rc != 0);
  assert(errno == EBADMSG);
}

static void rejects_wrong_key(void) {
  struct qaff_cid_profile_key key = test_key();
  struct qaff_cid_profile_key wrong_key = test_key();
  wrong_key.bytes[0] ^= 0x55;
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];
  assert(qaff_cid_profile_v1_generate(&key, 7, 9, cid, sizeof(cid)) == 0);

  struct qaff_cid_profile_v1_fields fields;
  int rc = qaff_cid_profile_v1_parse(&wrong_key, cid, sizeof(cid), &fields);
  assert(rc != 0);
  assert(errno == EBADMSG);
}

static void rejects_invalid_bounds(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];

  assert(qaff_cid_profile_v1_generate(&key, 0x10000, 1, cid, sizeof(cid)) != 0);
  assert(errno == EINVAL);
  assert(qaff_cid_profile_v1_generate(&key, 1, 0x1000000, cid, sizeof(cid)) != 0);
  assert(errno == EINVAL);
  assert(qaff_cid_profile_v1_generate(&key, 1, 1, cid, sizeof(cid) - 1) != 0);
  assert(errno == EINVAL);
}

int main(void) {
  roundtrips_v1_cid();
  rejects_tampered_cid();
  rejects_wrong_key();
  rejects_invalid_bounds();
  return 0;
}
