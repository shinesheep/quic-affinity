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

static int roundtrips_profile_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_LEN];

  int rc = qaff_cid_profile_generate(&key,
                                     42,
                                     3,
                                     0x010203,
                                     cid,
                                     sizeof(cid));
  CHECK(rc == 0);
  CHECK(cid[0] == QAFF_CID_PROFILE_MARKER);
  CHECK(cid[1] == QAFF_CID_PROFILE_FLAGS_NONE);

  struct qaff_cid_profile_fields fields;
  rc = qaff_cid_profile_parse(&key, cid, sizeof(cid), &fields);
  CHECK(rc == 0);
  CHECK(fields.worker_id == 42);
  CHECK(fields.generation == 3);
  CHECK(fields.nonce == 0x010203);
  return 0;
}

static int rejects_wrong_key(void) {
  struct qaff_cid_profile_key key = test_key();
  struct qaff_cid_profile_key wrong_key = test_key();
  wrong_key.bytes[0] ^= 0x55;
  uint8_t cid[QAFF_CID_PROFILE_LEN];
  CHECK(qaff_cid_profile_generate(&key, 7, 2, 9, cid, sizeof(cid)) == 0);

  struct qaff_cid_profile_fields fields;
  int rc = qaff_cid_profile_parse(&wrong_key, cid, sizeof(cid), &fields);
  CHECK(rc != 0);
  CHECK(errno == EBADMSG);
  return 0;
}

static int rejects_tampered_profile_cid(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_LEN];
  CHECK(qaff_cid_profile_generate(&key, 7, 2, 9, cid, sizeof(cid)) == 0);

  cid[4] ^= 0x01;
  struct qaff_cid_profile_fields fields;
  int rc = qaff_cid_profile_parse(&key, cid, sizeof(cid), &fields);
  CHECK(rc != 0);
  CHECK(errno == EBADMSG);
  return 0;
}

static int rejects_unknown_marker_or_flags(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_LEN];
  struct qaff_cid_profile_fields fields;
  CHECK(qaff_cid_profile_generate(&key, 7, 2, 9, cid, sizeof(cid)) == 0);

  cid[0] ^= 1;
  CHECK(qaff_cid_profile_parse(&key, cid, sizeof(cid), &fields) != 0);
  CHECK(errno == EPROTO);

  CHECK(qaff_cid_profile_generate(&key, 7, 2, 9, cid, sizeof(cid)) == 0);
  cid[1] = 1;
  CHECK(qaff_cid_profile_parse(&key, cid, sizeof(cid), &fields) != 0);
  CHECK(errno == EPROTO);
  return 0;
}

static int rejects_invalid_bounds(void) {
  struct qaff_cid_profile_key key = test_key();
  uint8_t cid[QAFF_CID_PROFILE_LEN];
  CHECK(qaff_cid_profile_generate(&key,
                                  QAFF_WORKER_CAPACITY,
                                  1,
                                  1,
                                  cid,
                                  sizeof(cid)) != 0);
  CHECK(errno == EINVAL);
  CHECK(qaff_cid_profile_generate(&key, 1, 0, 1, cid, sizeof(cid)) != 0);
  CHECK(errno == EINVAL);
  return 0;
}

int main(void) {
  if (roundtrips_profile_cid() != 0 ||
      rejects_tampered_profile_cid() != 0 ||
      rejects_unknown_marker_or_flags() != 0 ||
      rejects_wrong_key() != 0 || rejects_invalid_bounds() != 0) {
    return 1;
  }
  return 0;
}
