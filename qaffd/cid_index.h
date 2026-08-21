#ifndef QAFFD_CID_INDEX_H
#define QAFFD_CID_INDEX_H

#include "quic_affinity/wire.h"

#include <stddef.h>
#include <stdint.h>

struct qaffd_cid_entry {
  struct qaff_cid_key key;
  uint32_t worker_id;
};

struct qaffd_cid_index {
  struct qaffd_cid_entry *entries;
  size_t entries_len;
  size_t entries_cap;
  size_t *slots;
  size_t slots_cap;
  size_t slots_used;
  size_t tombstones;
};

void qaffd_cid_index_destroy(struct qaffd_cid_index *index);
size_t qaffd_cid_index_size(const struct qaffd_cid_index *index);
const struct qaffd_cid_entry *
qaffd_cid_index_entry(const struct qaffd_cid_index *index, size_t position);
struct qaffd_cid_entry *qaffd_cid_index_entry_mut(struct qaffd_cid_index *index,
                                                  size_t position);
ptrdiff_t qaffd_cid_index_find(const struct qaffd_cid_index *index,
                               const struct qaff_cid_key *key);
int qaffd_cid_index_put(struct qaffd_cid_index *index,
                        const struct qaff_cid_key *key, uint32_t worker_id);
int qaffd_cid_index_remove(struct qaffd_cid_index *index,
                           const struct qaff_cid_key *key);
int qaffd_cid_index_remove_at(struct qaffd_cid_index *index, size_t position);
int qaffd_cid_index_check(const struct qaffd_cid_index *index);

#endif
