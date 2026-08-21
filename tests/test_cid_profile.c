#include "quic_affinity/cid_profile.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr,                                                          \
              "%s:%d: check failed: %s\n",                                   \
              __FILE__,                                                        \
              __LINE__,                                                        \
              #condition);                                                     \
      return -1;                                                               \
    }                                                                          \
  } while (0)

static struct qaff_cid_profile_key test_key(void) {
  struct qaff_cid_profile_key key;
  for (uint8_t i = 0; i < QAFF_CID_PROFILE_KEY_LEN; i++) {
    key.bytes[i] = (uint8_t)(0xa0u + i);
  }
  return key;
}

static int roundtrips_v1_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];

  int rc = qaff_cid_profile_v1_generate(&key, 42, 0x010203, cid, sizeof(cid));
  CHECK(rc == 0);
  CHECK((cid[0] >> 4) == QAFF_CID_PROFILE_V1_VERSION);

  struct qaff_cid_profile_v1_fields fields;
  rc = qaff_cid_profile_v1_parse(&key, cid, sizeof(cid), &fields);
  CHECK(rc == 0);
  CHECK(fields.version == QAFF_CID_PROFILE_V1_VERSION);
  CHECK(fields.worker_id == 42);
  CHECK(fields.nonce == 0x010203);
  return 0;
}

static int roundtrips_v2_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V2_LEN];

  int rc = qaff_cid_profile_v2_generate(&key,
                                        9,
                                        42,
                                        3,
                                        0x010203,
                                        cid,
                                        sizeof(cid));
  CHECK(rc == 0);
  CHECK((cid[0] >> 4) == QAFF_CID_PROFILE_V2_VERSION);

  struct qaff_cid_profile_v2_fields fields;
  rc = qaff_cid_profile_v2_parse(&key, cid, sizeof(cid), &fields);
  CHECK(rc == 0);
  CHECK(fields.version == QAFF_CID_PROFILE_V2_VERSION);
  CHECK(fields.config_id == 9);
  CHECK(fields.worker_id == 42);
  CHECK(fields.generation == 3);
  CHECK(fields.nonce == 0x010203);
  return 0;
}

static int rejects_tampered_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];
  CHECK(qaff_cid_profile_v1_generate(&key, 7, 9, cid, sizeof(cid)) == 0);

  cid[3] ^= 0x40;
  struct qaff_cid_profile_v1_fields fields;
  int rc = qaff_cid_profile_v1_parse(&key, cid, sizeof(cid), &fields);
  CHECK(rc != 0);
  CHECK(errno == EBADMSG);
  return 0;
}

static int rejects_wrong_key(void) {
  struct qaff_cid_profile_key key = test_key();
  struct qaff_cid_profile_key wrong_key = test_key();
  wrong_key.bytes[0] ^= 0x55;
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];
  CHECK(qaff_cid_profile_v1_generate(&key, 7, 9, cid, sizeof(cid)) == 0);

  struct qaff_cid_profile_v1_fields fields;
  int rc = qaff_cid_profile_v1_parse(&wrong_key, cid, sizeof(cid), &fields);
  CHECK(rc != 0);
  CHECK(errno == EBADMSG);
  return 0;
}

static int rejects_tampered_v2_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V2_LEN];
  CHECK(qaff_cid_profile_v2_generate(&key,
                                     1,
                                     7,
                                     2,
                                     9,
                                     cid,
                                     sizeof(cid)) == 0);

  cid[4] ^= 0x01;
  struct qaff_cid_profile_v2_fields fields;
  int rc = qaff_cid_profile_v2_parse(&key, cid, sizeof(cid), &fields);
  CHECK(rc != 0);
  CHECK(errno == EBADMSG);
  return 0;
}

static int rejects_invalid_bounds(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_V1_LEN];
  uint8_t cid_v2[QAFF_CID_PROFILE_V2_LEN];

  CHECK(qaff_cid_profile_v1_generate(&key, 0x10000, 1, cid, sizeof(cid)) != 0);
  CHECK(errno == EINVAL);
  CHECK(qaff_cid_profile_v1_generate(&key, 1, 0x1000000, cid, sizeof(cid)) != 0);
  CHECK(errno == EINVAL);
  CHECK(qaff_cid_profile_v1_generate(&key, 1, 1, cid, sizeof(cid) - 1) != 0);
  CHECK(errno == EINVAL);
  CHECK(qaff_cid_profile_v2_generate(&key,
                                     0x100,
                                     1,
                                     1,
                                     1,
                                     cid_v2,
                                     sizeof(cid_v2)) != 0);
  CHECK(errno == EINVAL);
  CHECK(qaff_cid_profile_v2_generate(&key,
                                     1,
                                     1,
                                     0,
                                     1,
                                     cid_v2,
                                     sizeof(cid_v2)) != 0);
  CHECK(errno == EINVAL);
  return 0;
}

int main(void) {
  if (roundtrips_v1_cid() != 0 || roundtrips_v2_cid() != 0 ||
      rejects_tampered_cid() != 0 || rejects_tampered_v2_cid() != 0 ||
      rejects_wrong_key() != 0 || rejects_invalid_bounds() != 0) {
    return 1;
  }
  return 0;
}
