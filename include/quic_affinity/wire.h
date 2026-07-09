#ifndef QUIC_AFFINITY_WIRE_H
#define QUIC_AFFINITY_WIRE_H

#if defined(__KERNEL__) || defined(QAFF_BPF)
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/**
 * Maximum QUIC connection ID length accepted by quic-affinity.
 *
 * The QUIC transport allows CIDs up to 20 bytes, but this ABI keeps room for
 * deployment-specific formats while preserving a fixed-size BPF map key.
 */
#define QAFF_MAX_CID_LEN 32

/** Length, in bytes, of routable CID profile v1. */
#define QAFF_CID_PROFILE_V1_LEN 8u

/** Length, in bytes, of routable CID profile v2. */
#define QAFF_CID_PROFILE_V2_LEN 12u

/** Length, in bytes, of the listener-local routable CID profile key. */
#define QAFF_CID_PROFILE_KEY_LEN 16u

/** Version nibble used by routable CID profile v1. */
#define QAFF_CID_PROFILE_V1_VERSION 1u

/** Version nibble used by routable CID profile v2. */
#define QAFF_CID_PROFILE_V2_VERSION 2u

/** Initial worker generation written when callers do not supply one. */
#define QAFF_WORKER_GENERATION_DEFAULT 1u

/** Highest worker generation encodable in routable CID profile v2. */
#define QAFF_WORKER_GENERATION_MAX 255u

/**
 * Fixed-size BPF map key for a QUIC connection ID.
 *
 * The first len bytes of bytes[] contain the CID and the rest are zero-filled.
 * This exact layout is shared by user space and the eBPF program; changing it
 * changes the qaff_cids map ABI.
 */
struct qaff_cid_key {
#if defined(__KERNEL__) || defined(QAFF_BPF)
  __u8 len;
  __u8 bytes[QAFF_MAX_CID_LEN];
#else
  uint8_t len;
  uint8_t bytes[QAFF_MAX_CID_LEN];
#endif
};

/**
 * Runtime dataplane configuration stored in the qaff_config BPF map.
 *
 * The map has a single entry at key 0. qaff_open() writes this value before the
 * BPF object is loaded. The field layout is part of the BPF/user-space ABI.
 */
struct qaff_config_value {
#if defined(__KERNEL__) || defined(QAFF_BPF)
  __u8 short_cid_len;
  __u8 cid_profile_v1_enabled;
  __u8 cid_profile_v2_enabled;
  __u8 cid_profile_v2_config_id;
  __u32 fallback_worker_id;
  __u8 cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
#else
  uint8_t short_cid_len;
  uint8_t cid_profile_v1_enabled;
  uint8_t cid_profile_v2_enabled;
  uint8_t cid_profile_v2_config_id;
  uint32_t fallback_worker_id;
  uint8_t cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
#endif
};

/** Dataplane counter indexes in the qaff_stats BPF array map. */
enum qaff_stat_index {
  /** All packets seen by the reuseport program. */
  QAFF_STAT_PACKETS = 0,
  /** Packets routed through an exact DCID map hit. */
  QAFF_STAT_CID_MAP_HIT = 1,
  /** Packets sent to the configured fallback worker. */
  QAFF_STAT_FALLBACK = 2,
  /** Packets that could not be parsed as a supported QUIC UDP packet. */
  QAFF_STAT_PARSE_ERROR = 3,
  /** Long-header packets with a zero-length DCID. */
  QAFF_STAT_ZERO_LENGTH_CID = 4,
  /** Packets whose selected worker socket was not registered. */
  QAFF_STAT_WORKER_MISSING = 5,
  /** IPv4 packets seen by the reuseport program. */
  QAFF_STAT_IPV4 = 6,
  /** IPv6 packets seen by the reuseport program. */
  QAFF_STAT_IPV6 = 7,
  /** Non-UDP packets passed to the program. */
  QAFF_STAT_NOT_UDP = 8,
  /** Packets routed by a valid routable CID profile. */
  QAFF_STAT_CID_PROFILE_HIT = 9,
  /** Packets that looked like a profile CID but failed validation. */
  QAFF_STAT_CID_PROFILE_REJECT = 10,
  /** Number of stats slots; always keep this last. */
  QAFF_STAT_MAX = 11,
};

#endif
