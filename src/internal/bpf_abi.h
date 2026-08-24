#ifndef QUIC_AFFINITY_BPF_ABI_H
#define QUIC_AFFINITY_BPF_ABI_H

#include "quic_affinity/types.h"

/** Fixed-size key shared by the qaff_cids and qaff_passive_cids maps. */
struct qaff_cid_key {
#if defined(__KERNEL__) || defined(QAFF_BPF)
  __u8 len;
  __u8 bytes[QAFF_MAX_CID_LEN];
#else
  uint8_t len;
  uint8_t bytes[QAFF_MAX_CID_LEN];
#endif
};

/** Generation-bound value stored in the exact CID routing map. */
struct qaff_cid_value {
#if defined(__KERNEL__) || defined(QAFF_BPF)
  __u32 worker_id;
  __u32 worker_generation;
#else
  uint32_t worker_id;
  uint32_t worker_generation;
#endif
};

/** Runtime value stored at key zero in the qaff_config map. */
struct qaff_config_value {
#if defined(__KERNEL__) || defined(QAFF_BPF)
  __u8 short_cid_len;
  __u8 cid_profile_enabled;
  __u8 passive_affinity_enabled;
  __u8 passive_min_confidence;
  __u8 fallback_mode;
  __u8 reserved[3];
  __u32 fallback_worker_id;
  __u8 cid_profile_key[QAFF_CID_PROFILE_KEY_LEN];
#else
  uint8_t short_cid_len;
  uint8_t cid_profile_enabled;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t fallback_mode;
  uint8_t reserved[3];
  uint32_t fallback_worker_id;
  uint8_t cid_profile_key[QAFF_CID_PROFILE_KEY_LEN];
#endif
};

#endif
