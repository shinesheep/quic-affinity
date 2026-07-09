#ifndef QUIC_AFFINITY_WIRE_H
#define QUIC_AFFINITY_WIRE_H

#if defined(__KERNEL__) || defined(QAFF_BPF)
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define QAFF_MAX_CID_LEN 32

struct qaff_cid_key {
#if defined(__KERNEL__) || defined(QAFF_BPF)
  __u8 len;
  __u8 bytes[QAFF_MAX_CID_LEN];
#else
  uint8_t len;
  uint8_t bytes[QAFF_MAX_CID_LEN];
#endif
};

enum qaff_stat_index {
  QAFF_STAT_PACKETS = 0,
  QAFF_STAT_CID_MAP_HIT = 1,
  QAFF_STAT_FALLBACK = 2,
  QAFF_STAT_PARSE_ERROR = 3,
  QAFF_STAT_ZERO_LENGTH_CID = 4,
  QAFF_STAT_WORKER_MISSING = 5,
  QAFF_STAT_MAX = 6,
};

#endif
