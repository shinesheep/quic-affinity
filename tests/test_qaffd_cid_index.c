#include "cid_index.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SCALE_KEYS 8192u
#define MODEL_KEYS 2048u
#define MODEL_OPERATIONS 50000u

static int expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "CID index test failed: %s\n", message);
    return -1;
  }
  return 0;
}

static struct qaff_cid_key make_key(uint64_t value) {
  struct qaff_cid_key key;
  memset(&key, 0, sizeof(key));
  key.len = 8;
  for (size_t i = 0; i < key.len; i++) {
    key.bytes[i] = (uint8_t)(value >> (i * 8));
  }
  return key;
}

static uint64_t next_random(uint64_t *state) {
  uint64_t value = *state;
  value ^= value << 13;
  value ^= value >> 7;
  value ^= value << 17;
  *state = value;
  return value;
}

static int expect_owner(const struct qaffd_cid_index *index,
                        const struct qaff_cid_key *key, uint32_t owner,
                        const char *message) {
  ptrdiff_t position = qaffd_cid_index_find(index, key);
  const struct qaffd_cid_entry *entry =
      position < 0 ? NULL : qaffd_cid_index_entry(index, (size_t)position);
  return expect(entry != NULL && entry->worker_id == owner, message);
}

static int test_lifecycle_and_validation(void) {
  struct qaffd_cid_index index = {0};
  struct qaff_cid_key one = make_key(1);
  struct qaff_cid_key two = make_key(2);
  struct qaff_cid_key three = make_key(3);

  if (qaffd_cid_index_check(&index) != 0 ||
      expect(qaffd_cid_index_size(&index) == 0, "new index is empty") != 0 ||
      expect(qaffd_cid_index_entry(&index, 0) == NULL,
             "empty index has no first entry") != 0 ||
      qaffd_cid_index_put(&index, &one, 10) != 0 ||
      qaffd_cid_index_put(&index, &two, 20) != 0 ||
      qaffd_cid_index_put(&index, &three, 30) != 0 ||
      qaffd_cid_index_put(&index, &one, 10) != 0 ||
      expect(qaffd_cid_index_size(&index) == 3,
             "idempotent insertion does not duplicate the key") != 0 ||
      expect_owner(&index, &one, 10, "idempotent insertion retains owner") !=
          0 ||
      expect(qaffd_cid_index_has_worker(&index, 10),
             "worker ownership can be queried") != 0 ||
      expect(!qaffd_cid_index_has_worker(&index, 99),
             "absent worker ownership is reported") != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }

  errno = 0;
  if (expect(qaffd_cid_index_put(&index, &one, 11) == -1 &&
                 errno == EEXIST,
             "reassigning a live CID is rejected") != 0 ||
      expect_owner(&index, &one, 10,
                   "rejected reassignment preserves owner") != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }
  if (qaffd_cid_index_remove(&index, &one) != 0 ||
      qaffd_cid_index_put(&index, &one, 11) != 0 ||
      expect_owner(&index, &one, 11,
                   "retired CID can be assigned to a new owner") != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }

  ptrdiff_t removed = qaffd_cid_index_find(&index, &two);
  if (expect(removed >= 0, "key selected for removal exists") != 0 ||
      qaffd_cid_index_remove_at(&index, (size_t)removed) != 0 ||
      expect(qaffd_cid_index_find(&index, &two) < 0, "removed key is absent") !=
          0 ||
      expect_owner(&index, &three, 30,
                   "tail relocation updates the hash position") != 0 ||
      qaffd_cid_index_check(&index) != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }

  errno = 0;
  if (expect(qaffd_cid_index_remove(&index, &two) == -1 && errno == ENOENT,
             "removing an absent key reports ENOENT") != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }
  errno = 0;
  if (expect(qaffd_cid_index_remove_at(&index, qaffd_cid_index_size(&index)) ==
                     -1 &&
                 errno == EINVAL,
             "out-of-range removal is rejected") != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }

  struct qaff_cid_key too_long = make_key(4);
  too_long.len = QAFF_MAX_CID_LEN + 1;
  struct qaff_cid_key noncanonical = make_key(5);
  noncanonical.len = 2;
  noncanonical.bytes[2] = 1;
  errno = 0;
  if (expect(qaffd_cid_index_put(&index, &too_long, 1) == -1 && errno == EINVAL,
             "overlong key is rejected") != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }
  errno = 0;
  if (expect(qaffd_cid_index_put(&index, &noncanonical, 1) == -1 &&
                 errno == EINVAL,
             "noncanonical key is rejected") != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }

  qaffd_cid_index_destroy(&index);
  return expect(qaffd_cid_index_size(&index) == 0 &&
                    qaffd_cid_index_check(&index) == 0,
                "destroy resets the index");
}

static int test_growth_and_tombstones(void) {
  struct qaffd_cid_index index = {0};
  for (uint32_t i = 0; i < SCALE_KEYS; i++) {
    struct qaff_cid_key key = make_key(i);
    if (qaffd_cid_index_put(&index, &key, i + 100) != 0) {
      qaffd_cid_index_destroy(&index);
      return -1;
    }
  }
  if (expect(qaffd_cid_index_size(&index) == SCALE_KEYS,
             "scale insertion retains every key") != 0 ||
      qaffd_cid_index_check(&index) != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }

  for (uint32_t i = 1; i < SCALE_KEYS; i += 2) {
    struct qaff_cid_key key = make_key(i);
    if (qaffd_cid_index_remove(&index, &key) != 0) {
      qaffd_cid_index_destroy(&index);
      return -1;
    }
  }
  for (uint32_t i = SCALE_KEYS; i < SCALE_KEYS + SCALE_KEYS / 2; i++) {
    struct qaff_cid_key key = make_key(i);
    if (qaffd_cid_index_put(&index, &key, i + 100) != 0) {
      qaffd_cid_index_destroy(&index);
      return -1;
    }
  }
  if (expect(qaffd_cid_index_size(&index) == SCALE_KEYS,
             "tombstone reuse preserves the expected size") != 0 ||
      qaffd_cid_index_check(&index) != 0) {
    qaffd_cid_index_destroy(&index);
    return -1;
  }

  for (uint32_t i = 0; i < SCALE_KEYS; i += 2) {
    struct qaff_cid_key key = make_key(i);
    if (expect_owner(&index, &key, i + 100,
                     "surviving scale key retains its owner") != 0) {
      qaffd_cid_index_destroy(&index);
      return -1;
    }
  }
  qaffd_cid_index_destroy(&index);
  return 0;
}

static int verify_model(const struct qaffd_cid_index *index,
                        const uint8_t *present, const uint32_t *owners,
                        size_t expected_size) {
  if (qaffd_cid_index_check(index) != 0 ||
      expect(qaffd_cid_index_size(index) == expected_size,
             "model and index sizes agree") != 0) {
    return -1;
  }
  for (uint32_t i = 0; i < MODEL_KEYS; i++) {
    struct qaff_cid_key key = make_key(i);
    ptrdiff_t position = qaffd_cid_index_find(index, &key);
    if (present[i]) {
      if (expect_owner(index, &key, owners[i],
                       "model owner agrees with the index") != 0) {
        return -1;
      }
    } else if (expect(position < 0, "model-absent key is absent") != 0) {
      return -1;
    }
  }
  return 0;
}

static int test_randomized_model(void) {
  struct qaffd_cid_index index = {0};
  uint8_t present[MODEL_KEYS] = {0};
  uint32_t owners[MODEL_KEYS] = {0};
  size_t expected_size = 0;
  uint64_t random_state = UINT64_C(0x6a09e667f3bcc909);

  for (uint32_t operation = 0; operation < MODEL_OPERATIONS; operation++) {
    uint64_t random = next_random(&random_state);
    uint32_t id = (uint32_t)(random % MODEL_KEYS);
    struct qaff_cid_key key = make_key(id);
    if ((random & 3u) != 0) {
      uint32_t owner = (uint32_t)(random >> 32);
      if (present[id] && owners[id] != owner) {
        errno = 0;
        if (expect(qaffd_cid_index_put(&index, &key, owner) == -1 &&
                       errno == EEXIST,
                   "random reassignment is rejected") != 0) {
          qaffd_cid_index_destroy(&index);
          return -1;
        }
      } else if (qaffd_cid_index_put(&index, &key, owner) != 0) {
        qaffd_cid_index_destroy(&index);
        return -1;
      } else if (!present[id]) {
        expected_size++;
        present[id] = 1;
        owners[id] = owner;
      }
    } else if (present[id]) {
      if (qaffd_cid_index_remove(&index, &key) != 0) {
        qaffd_cid_index_destroy(&index);
        return -1;
      }
      present[id] = 0;
      expected_size--;
    } else {
      errno = 0;
      if (expect(qaffd_cid_index_remove(&index, &key) == -1 && errno == ENOENT,
                 "random absent removal reports ENOENT") != 0) {
        qaffd_cid_index_destroy(&index);
        return -1;
      }
    }

    if (operation % 257u == 0 &&
        verify_model(&index, present, owners, expected_size) != 0) {
      qaffd_cid_index_destroy(&index);
      return -1;
    }
  }

  int result = verify_model(&index, present, owners, expected_size);
  qaffd_cid_index_destroy(&index);
  return result;
}

int main(void) {
  if (test_lifecycle_and_validation() != 0 ||
      test_growth_and_tombstones() != 0 || test_randomized_model() != 0) {
    return 1;
  }
  puts("qaffd CID index tests passed");
  return 0;
}
