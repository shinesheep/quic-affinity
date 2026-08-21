#include "cid_index.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define EMPTY 0u
#define TOMBSTONE SIZE_MAX

static int key_valid(const struct qaff_cid_key *key) {
  if (key == NULL || key->len > QAFF_MAX_CID_LEN) {
    return 0;
  }
  for (size_t i = key->len; i < sizeof(key->bytes); i++) {
    if (key->bytes[i] != 0) {
      return 0;
    }
  }
  return 1;
}

static int key_equal(const struct qaff_cid_key *a,
                     const struct qaff_cid_key *b) {
  return a->len == b->len && memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

static uint64_t key_hash(const struct qaff_cid_key *key) {
  uint64_t hash = UINT64_C(1469598103934665603);
  hash ^= key->len;
  hash *= UINT64_C(1099511628211);
  for (size_t i = 0; i < sizeof(key->bytes); i++) {
    hash ^= key->bytes[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static size_t slot_for(const struct qaffd_cid_index *index,
                       const struct qaff_cid_key *key, int *found) {
  size_t mask = index->slots_cap - 1;
  size_t slot = (size_t)key_hash(key) & mask;
  size_t first_tombstone = SIZE_MAX;
  for (size_t probed = 0; probed < index->slots_cap; probed++) {
    size_t value = index->slots[slot];
    if (value == EMPTY) {
      *found = 0;
      return first_tombstone != SIZE_MAX ? first_tombstone : slot;
    }
    if (value == TOMBSTONE) {
      if (first_tombstone == SIZE_MAX) {
        first_tombstone = slot;
      }
    } else {
      size_t position = value - 1;
      if (position < index->entries_len &&
          key_equal(&index->entries[position].key, key)) {
        *found = 1;
        return slot;
      }
    }
    slot = (slot + 1) & mask;
  }
  *found = 0;
  return first_tombstone;
}

static int rehash(struct qaffd_cid_index *index, size_t capacity) {
  if (capacity < 16 || (capacity & (capacity - 1)) != 0 ||
      capacity > SIZE_MAX / sizeof(*index->slots)) {
    errno = ENOMEM;
    return -1;
  }
  size_t *slots = calloc(capacity, sizeof(*slots));
  if (slots == NULL) {
    return -1;
  }
  size_t *old_slots = index->slots;
  size_t old_cap = index->slots_cap;
  size_t old_used = index->slots_used;
  size_t old_tombstones = index->tombstones;
  index->slots = slots;
  index->slots_cap = capacity;
  index->slots_used = 0;
  index->tombstones = 0;
  for (size_t i = 0; i < index->entries_len; i++) {
    int found = 0;
    size_t slot = slot_for(index, &index->entries[i].key, &found);
    if (found || slot == SIZE_MAX) {
      free(slots);
      index->slots = old_slots;
      index->slots_cap = old_cap;
      index->slots_used = old_used;
      index->tombstones = old_tombstones;
      errno = EINVAL;
      return -1;
    }
    index->slots[slot] = i + 1;
    index->slots_used++;
  }
  free(old_slots);
  return 0;
}

static int prepare_insert(struct qaffd_cid_index *index) {
  if (index->slots_cap == 0) {
    return rehash(index, 16);
  }
  size_t occupied = index->slots_used + index->tombstones;
  size_t threshold = index->slots_cap / 2 + index->slots_cap / 4;
  if (occupied + 1 < threshold) {
    return 0;
  }
  size_t capacity = index->slots_cap;
  if (index->tombstones <= index->slots_used) {
    if (capacity > SIZE_MAX / 2) {
      errno = ENOMEM;
      return -1;
    }
    capacity *= 2;
  }
  return rehash(index, capacity);
}

void qaffd_cid_index_destroy(struct qaffd_cid_index *index) {
  if (index == NULL) {
    return;
  }
  free(index->entries);
  free(index->slots);
  memset(index, 0, sizeof(*index));
}

size_t qaffd_cid_index_size(const struct qaffd_cid_index *index) {
  return index == NULL ? 0 : index->entries_len;
}

const struct qaffd_cid_entry *
qaffd_cid_index_entry(const struct qaffd_cid_index *index, size_t position) {
  return index != NULL && position < index->entries_len
             ? &index->entries[position]
             : NULL;
}

struct qaffd_cid_entry *qaffd_cid_index_entry_mut(struct qaffd_cid_index *index,
                                                  size_t position) {
  return index != NULL && position < index->entries_len
             ? &index->entries[position]
             : NULL;
}

ptrdiff_t qaffd_cid_index_find(const struct qaffd_cid_index *index,
                               const struct qaff_cid_key *key) {
  if (index == NULL || !key_valid(key) || index->slots_cap == 0) {
    return -1;
  }
  int found = 0;
  size_t slot = slot_for(index, key, &found);
  return found && slot != SIZE_MAX ? (ptrdiff_t)(index->slots[slot] - 1) : -1;
}

int qaffd_cid_index_put(struct qaffd_cid_index *index,
                        const struct qaff_cid_key *key, uint32_t worker_id) {
  if (index == NULL || !key_valid(key)) {
    errno = EINVAL;
    return -1;
  }
  ptrdiff_t position = qaffd_cid_index_find(index, key);
  if (position >= 0) {
    if (index->entries[position].worker_id == worker_id) {
      return 0;
    }
    errno = EEXIST;
    return -1;
  }
  if (prepare_insert(index) != 0) {
    return -1;
  }
  if (index->entries_len == index->entries_cap) {
    size_t max_cap = SIZE_MAX / sizeof(*index->entries);
    if (max_cap > (size_t)PTRDIFF_MAX) {
      max_cap = (size_t)PTRDIFF_MAX;
    }
    if (index->entries_cap > max_cap / 2) {
      errno = ENOMEM;
      return -1;
    }
    size_t next_cap = index->entries_cap == 0 ? 1024 : index->entries_cap * 2;
    if (next_cap > max_cap) {
      errno = ENOMEM;
      return -1;
    }
    struct qaffd_cid_entry *entries =
        realloc(index->entries, next_cap * sizeof(*entries));
    if (entries == NULL) {
      return -1;
    }
    index->entries = entries;
    index->entries_cap = next_cap;
  }
  size_t new_position = index->entries_len++;
  index->entries[new_position] =
      (struct qaffd_cid_entry){.key = *key, .worker_id = worker_id};
  int found = 0;
  size_t slot = slot_for(index, key, &found);
  if (found || slot == SIZE_MAX) {
    index->entries_len--;
    errno = EINVAL;
    return -1;
  }
  if (index->slots[slot] == TOMBSTONE) {
    index->tombstones--;
  }
  index->slots[slot] = new_position + 1;
  index->slots_used++;
  return 0;
}

int qaffd_cid_index_remove_at(struct qaffd_cid_index *index, size_t position) {
  if (index == NULL || position >= index->entries_len ||
      index->slots_cap == 0) {
    errno = EINVAL;
    return -1;
  }
  int found = 0;
  size_t removed = slot_for(index, &index->entries[position].key, &found);
  if (!found || removed == SIZE_MAX) {
    errno = EIO;
    return -1;
  }
  size_t last = index->entries_len - 1;
  size_t moved = SIZE_MAX;
  if (position != last) {
    int moved_found = 0;
    moved = slot_for(index, &index->entries[last].key, &moved_found);
    if (!moved_found || moved == SIZE_MAX) {
      errno = EIO;
      return -1;
    }
  }
  index->slots[removed] = TOMBSTONE;
  index->slots_used--;
  index->tombstones++;
  if (position != last) {
    index->entries[position] = index->entries[last];
    index->slots[moved] = position + 1;
  }
  index->entries_len--;
  return 0;
}

int qaffd_cid_index_remove(struct qaffd_cid_index *index,
                           const struct qaff_cid_key *key) {
  if (index == NULL || !key_valid(key)) {
    errno = EINVAL;
    return -1;
  }
  ptrdiff_t position = qaffd_cid_index_find(index, key);
  if (position < 0) {
    errno = ENOENT;
    return -1;
  }
  return qaffd_cid_index_remove_at(index, (size_t)position);
}

int qaffd_cid_index_has_worker(const struct qaffd_cid_index *index,
                               uint32_t worker_id) {
  if (index == NULL) {
    return 0;
  }
  for (size_t i = 0; i < index->entries_len; i++) {
    if (index->entries[i].worker_id == worker_id) {
      return 1;
    }
  }
  return 0;
}

int qaffd_cid_index_check(const struct qaffd_cid_index *index) {
  if (index == NULL || index->entries_len > index->entries_cap ||
      (index->entries_cap == 0 && index->entries != NULL) ||
      (index->entries_cap > 0 && index->entries == NULL) ||
      (index->slots_cap == 0 && index->slots != NULL) ||
      (index->slots_cap > 0 &&
       (index->slots == NULL || index->slots_cap < 16 ||
        (index->slots_cap & (index->slots_cap - 1)) != 0)) ||
      index->slots_used != index->entries_len ||
      index->slots_used > index->slots_cap ||
      index->tombstones > index->slots_cap - index->slots_used ||
      (index->entries_len > 0 && index->slots_cap == 0)) {
    errno = EIO;
    return -1;
  }
  size_t live_slots = 0;
  size_t tombstones = 0;
  for (size_t i = 0; i < index->slots_cap; i++) {
    size_t value = index->slots[i];
    if (value == TOMBSTONE) {
      tombstones++;
    } else if (value != EMPTY) {
      if (value - 1 >= index->entries_len) {
        errno = EIO;
        return -1;
      }
      live_slots++;
    }
  }
  if (live_slots != index->slots_used || tombstones != index->tombstones) {
    errno = EIO;
    return -1;
  }
  for (size_t i = 0; i < index->entries_len; i++) {
    if (!key_valid(&index->entries[i].key) ||
        qaffd_cid_index_find(index, &index->entries[i].key) != (ptrdiff_t)i) {
      errno = EIO;
      return -1;
    }
  }
  return 0;
}
