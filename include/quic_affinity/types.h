#ifndef QUIC_AFFINITY_TYPES_H
#define QUIC_AFFINITY_TYPES_H

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

/** Number of worker IDs supported by one listener and its BPF maps. */
#define QAFF_WORKER_CAPACITY 4096u

/** Length, in bytes, of the routable CID profile. */
#define QAFF_CID_PROFILE_LEN 16u

/** Length, in bytes, of the listener-local routable CID profile key. */
#define QAFF_CID_PROFILE_KEY_LEN 16u

/** Two-byte magic identifying the routable profile CID namespace. */
#define QAFF_CID_PROFILE_MAGIC_0 0xa5u
#define QAFF_CID_PROFILE_MAGIC_1 0x5au

/** Initial worker generation written when callers do not supply one. */
#define QAFF_WORKER_GENERATION_DEFAULT 1u

/** Highest worker generation encodable in a routable CID profile. */
#define QAFF_WORKER_GENERATION_MAX 255u

/** Passive CID confidence levels used by black-box learning. */
#define QAFF_PASSIVE_CONFIDENCE_LOW 1u
#define QAFF_PASSIVE_CONFIDENCE_MEDIUM 2u
#define QAFF_PASSIVE_CONFIDENCE_HIGH 3u

/** Passive entry learned from inbound traffic only. */
#define QAFF_PASSIVE_SOURCE_INGRESS 1u
/** Passive entry learned from outbound server traffic. */
#define QAFF_PASSIVE_SOURCE_EGRESS 2u

/** Default monotonic lifetimes for passive entries. */
#define QAFF_PASSIVE_TTL_LOW_NS (30ULL * 1000000000ULL)
#define QAFF_PASSIVE_TTL_MEDIUM_NS (5ULL * 60ULL * 1000000000ULL)
#define QAFF_PASSIVE_TTL_HIGH_NS (15ULL * 60ULL * 1000000000ULL)
#define QAFF_PASSIVE_TTL_EGRESS_NS (60ULL * 60ULL * 1000000000ULL)

/** Direct fallback traffic to fallback_worker_id or drop if it is unavailable. */
#define QAFF_FALLBACK_MODE_FIXED 0u
/** Leave fallback traffic to the kernel's native SO_REUSEPORT hash. */
#define QAFF_FALLBACK_MODE_KERNEL 1u

/**
 * Passive CID routing entry.
 *
 * This is used for best-effort black-box affinity. The dataplane routes by this
 * table only when passive routing is enabled and no stronger exact/profile
 * route was selected. expires_at_ns is an absolute CLOCK_MONOTONIC timestamp.
 * The dataplane rejects expired entries and qaffd removes them periodically.
 */
struct qaff_passive_cid_value {
#if defined(__KERNEL__) || defined(QAFF_BPF)
  __u32 worker_id;
  __u32 worker_generation;
  __u8 confidence;
  __u8 source;
  __u16 flags;
  __u64 expires_at_ns;
#else
  uint32_t worker_id;
  uint32_t worker_generation;
  uint8_t confidence;
  uint8_t source;
  uint16_t flags;
  uint64_t expires_at_ns;
#endif
};

/** Dataplane counter indexes in the qaff_stats BPF array map. */
enum qaff_stat_index {
  /** All packets seen by the reuseport program. */
  QAFF_STAT_PACKETS = 0,
  /** Packets routed through an exact DCID map hit. */
  QAFF_STAT_CID_MAP_HIT = 1,
  /** Packets handled by either fixed-worker or kernel-default fallback. */
  QAFF_STAT_FALLBACK = 2,
  /** Packets that could not be parsed as a supported QUIC UDP packet. */
  QAFF_STAT_PARSE_ERROR = 3,
  /** Long-header packets with a zero-length DCID. */
  QAFF_STAT_ZERO_LENGTH_CID = 4,
  /** Packets whose selected worker or fixed fallback was not registered. */
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
  /** Packets routed through a passive CID entry. */
  QAFF_STAT_PASSIVE_HIT = 11,
  /** Passive routing was enabled but no passive CID entry existed. */
  QAFF_STAT_PASSIVE_MISS = 12,
  /** Passive CID entry existed but its confidence was below policy. */
  QAFF_STAT_PASSIVE_REJECT_CONFIDENCE = 13,
  /** Passive CID entry generation did not match the live worker generation. */
  QAFF_STAT_PASSIVE_REJECT_GENERATION = 14,
  /** Egress observer learned a server Source CID. */
  QAFF_STAT_PASSIVE_EGRESS_LEARN = 15,
  /** Egress observer could not map the sending socket to a worker. */
  QAFF_STAT_PASSIVE_EGRESS_NO_WORKER = 16,
  /** Passive entry existed but its monotonic TTL had elapsed. */
  QAFF_STAT_PASSIVE_REJECT_EXPIRED = 17,
  /** Egress observer could not parse a supported QUIC long header. */
  QAFF_STAT_PASSIVE_EGRESS_PARSE_MISS = 18,
  /** Egress observer saw a non-UDP packet. */
  QAFF_STAT_PASSIVE_EGRESS_NOT_UDP = 19,
  /** Egress observer saw a zero-length server SCID. */
  QAFF_STAT_PASSIVE_EGRESS_ZERO_LENGTH_SCID = 20,
  /** Egress observer saw a server SCID longer than the supported maximum. */
  QAFF_STAT_PASSIVE_EGRESS_TOO_LONG_SCID = 21,
  /** Egress observer mapped a sending socket cookie to a worker. */
  QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_HIT = 22,
  /** Egress observer could not map a sending socket cookie to a worker. */
  QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_MISS = 23,
  /** Egress observer failed to update the passive CID map. */
  QAFF_STAT_PASSIVE_EGRESS_MAP_UPDATE_ERROR = 24,
  /** Exact CID entry generation did not match the live worker generation. */
  QAFF_STAT_CID_MAP_REJECT_GENERATION = 25,
  /** Egress learning refused to overwrite another passive CID owner. */
  QAFF_STAT_PASSIVE_EGRESS_CONFLICT = 26,
  /** Egress observer rejected an IPv4 or IPv6 fragment. */
  QAFF_STAT_PASSIVE_EGRESS_FRAGMENTED = 27,
  /** Egress observer rejected Version Negotiation or an unknown version. */
  QAFF_STAT_PASSIVE_EGRESS_REJECT_VERSION = 28,
  /** Egress observer rejected a long-header type unsafe for server learning. */
  QAFF_STAT_PASSIVE_EGRESS_REJECT_TYPE = 29,
  /** Egress observer saw a normal short header with no visible server SCID. */
  QAFF_STAT_PASSIVE_EGRESS_SHORT_HEADER = 30,
  /** Number of stats slots; always keep this last. */
  QAFF_STAT_MAX = 31,
};

#endif
