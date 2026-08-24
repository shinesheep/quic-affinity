#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "qaff_bpf.h"

#define QAFF_ETH_P_IP 0x0008
#define QAFF_ETH_P_IPV6 0xdd86
#define QAFF_IPPROTO_UDP 17
#define QAFF_IPPROTO_HOPOPTS 0
#define QAFF_IPPROTO_ROUTING 43
#define QAFF_IPPROTO_FRAGMENT 44
#define QAFF_IPPROTO_AH 51
#define QAFF_IPPROTO_DSTOPTS 60
#define QAFF_IPPROTO_MH 135
#define QAFF_UDP_HEADER_LEN 8
#define QAFF_QUIC_VERSION_1 0x00000001u
#define QAFF_QUIC_LONG_TYPE_0RTT_V1 1u
#define QAFF_IPV6_MAX_EXTENSION_HEADERS 6

#define QAFF_EGRESS_PARSE_MISS -1
#define QAFF_EGRESS_NOT_UDP -2
#define QAFF_EGRESS_ZERO_LENGTH_SCID -3
#define QAFF_EGRESS_TOO_LONG_SCID -4
#define QAFF_EGRESS_FRAGMENTED -5
#define QAFF_EGRESS_REJECT_VERSION -6
#define QAFF_EGRESS_REJECT_TYPE -7
#define QAFF_EGRESS_SHORT_HEADER -8

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1048576);
  __type(key, struct qaff_cid_key);
  __type(value, struct qaff_cid_value);
} qaff_cids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1048576);
  __type(key, struct qaff_cid_key);
  __type(value, struct qaff_passive_cid_value);
} qaff_passive_cids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(max_entries, QAFF_WORKER_CAPACITY);
  __type(key, __u32);
  __type(value, __u32);
} qaff_workers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, QAFF_WORKER_CAPACITY);
  __type(key, __u64);
  __type(value, __u32);
} qaff_socket_workers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, QAFF_WORKER_CAPACITY);
  __type(key, __u32);
  __type(value, __u32);
} qaff_worker_generations SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, QAFF_STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} qaff_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct qaff_config_value);
} qaff_config SEC(".maps");

static __always_inline void qaff_count(__u32 index) {
  __u64 *value = bpf_map_lookup_elem(&qaff_stats, &index);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline int qaff_drop_stale_egress_learning(
    const struct qaff_cid_key *key,
    const struct qaff_passive_cid_value *learned,
    const __u32 *live_generation) {
  if (*live_generation == learned->worker_generation) {
    return 0;
  }

  struct qaff_passive_cid_value *current =
      bpf_map_lookup_elem(&qaff_passive_cids, key);
  if (current && current->worker_id == learned->worker_id &&
      current->worker_generation == learned->worker_generation) {
    bpf_map_delete_elem(&qaff_passive_cids, key);
  }
  qaff_count(QAFF_STAT_PASSIVE_EGRESS_NO_WORKER);
  return 1;
}

static __always_inline int qaff_copy_dcid(struct qaff_cid_key *key,
                                          void *data,
                                          void *data_end,
                                          __u32 offset,
                                          __u32 len) {
  if (len > QAFF_MAX_CID_LEN) {
    return -1;
  }
  if (data + offset + len > data_end) {
    return -1;
  }

  __builtin_memset(key, 0, sizeof(*key));
  key->len = len;

  for (__u32 i = 0; i < QAFF_MAX_CID_LEN; i++) {
    if (i >= len) {
      break;
    }
    if (data + offset + i + 1 > data_end) {
      return -1;
    }
    key->bytes[i] = *(__u8 *)(data + offset + i);
  }

  return 0;
}

static __always_inline int qaff_copy_skb_cid(struct __sk_buff *skb,
                                             struct qaff_cid_key *key,
                                             __u32 offset,
                                             __u32 len) {
  if (len > QAFF_MAX_CID_LEN) {
    return -1;
  }

  __builtin_memset(key, 0, sizeof(*key));
  key->len = len;
  return bpf_skb_load_bytes(skb, offset, key->bytes, len) == 0 ? 0 : -1;
}

static __always_inline int qaff_extract_dcid(struct sk_reuseport_md *ctx,
                                             struct qaff_cid_key *key) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 payload_offset = QAFF_UDP_HEADER_LEN;

  if (ctx->eth_protocol == QAFF_ETH_P_IP) {
    qaff_count(QAFF_STAT_IPV4);
  } else if (ctx->eth_protocol == QAFF_ETH_P_IPV6) {
    qaff_count(QAFF_STAT_IPV6);
  }

  if (ctx->ip_protocol != QAFF_IPPROTO_UDP) {
    qaff_count(QAFF_STAT_NOT_UDP);
    return -1;
  }

  if (data + payload_offset + 1 > data_end) {
    return -1;
  }

  __u8 first = *(__u8 *)(data + payload_offset);
  if (first & 0x80) {
    if (data + payload_offset + 6 > data_end) {
      return -1;
    }

    __u8 dcid_len = *(__u8 *)(data + payload_offset + 5);
    if (dcid_len == 0) {
      return -2;
    }

    return qaff_copy_dcid(key, data, data_end, payload_offset + 6, dcid_len);
  }

  __u32 config_key = 0;
  struct qaff_config_value *config =
      bpf_map_lookup_elem(&qaff_config, &config_key);
  if (!config || config->short_cid_len == 0) {
    return -3;
  }

  return qaff_copy_dcid(key,
                        data,
                        data_end,
                        payload_offset + 1,
                        config->short_cid_len);
}

static __always_inline __u64 qaff_load64_le(const __u8 *bytes) {
  return (__u64)bytes[0] |
         ((__u64)bytes[1] << 8) |
         ((__u64)bytes[2] << 16) |
         ((__u64)bytes[3] << 24) |
         ((__u64)bytes[4] << 32) |
         ((__u64)bytes[5] << 40) |
         ((__u64)bytes[6] << 48) |
         ((__u64)bytes[7] << 56);
}

#define QAFF_ROTL64(value, bits)                                               \
  (((value) << (bits)) | ((value) >> (64 - (bits))))

#define QAFF_SIPROUND(v0, v1, v2, v3)                                         \
  do {                                                                         \
    (v0) += (v1);                                                              \
    (v1) = QAFF_ROTL64((v1), 13);                                              \
    (v1) ^= (v0);                                                              \
    (v0) = QAFF_ROTL64((v0), 32);                                              \
    (v2) += (v3);                                                              \
    (v3) = QAFF_ROTL64((v3), 16);                                              \
    (v3) ^= (v2);                                                              \
    (v0) += (v3);                                                              \
    (v3) = QAFF_ROTL64((v3), 21);                                              \
    (v3) ^= (v0);                                                              \
    (v2) += (v1);                                                              \
    (v1) = QAFF_ROTL64((v1), 17);                                              \
    (v1) ^= (v2);                                                              \
    (v2) = QAFF_ROTL64((v2), 32);                                              \
  } while (0)

static __always_inline __u64 qaff_profile_tag64(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key) {
  __u64 k0 = qaff_load64_le(config->cid_profile_key);
  __u64 k1 = qaff_load64_le(config->cid_profile_key + 8);
  __u64 v0 = 0x736f6d6570736575ULL ^ k0;
  __u64 v1 = 0x646f72616e646f6dULL ^ k1;
  __u64 v2 = 0x6c7967656e657261ULL ^ k0;
  __u64 v3 = 0x7465646279746573ULL ^ k1;
  __u64 message = qaff_load64_le(key->bytes);
  __u64 final_block = 8ULL << 56;

  v3 ^= message;
  QAFF_SIPROUND(v0, v1, v2, v3);
  QAFF_SIPROUND(v0, v1, v2, v3);
  v0 ^= message;
  v3 ^= final_block;
  QAFF_SIPROUND(v0, v1, v2, v3);
  QAFF_SIPROUND(v0, v1, v2, v3);
  v0 ^= final_block;
  v2 ^= 0xffULL;
  QAFF_SIPROUND(v0, v1, v2, v3);
  QAFF_SIPROUND(v0, v1, v2, v3);
  QAFF_SIPROUND(v0, v1, v2, v3);
  QAFF_SIPROUND(v0, v1, v2, v3);
  return v0 ^ v1 ^ v2 ^ v3;
}

static __always_inline int qaff_is_profile_candidate(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key) {
  return config && config->cid_profile_enabled &&
         key->len == QAFF_CID_PROFILE_LEN &&
         key->bytes[0] == QAFF_CID_PROFILE_MAGIC_0 &&
         key->bytes[1] == QAFF_CID_PROFILE_MAGIC_1;
}

static __always_inline int qaff_profile_worker(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key,
    __u32 *worker_id) {
  if (!qaff_is_profile_candidate(config, key)) {
    return 0;
  }

  __u64 expected = qaff_profile_tag64(config, key);
  __u64 got = ((__u64)key->bytes[8] << 56) |
              ((__u64)key->bytes[9] << 48) |
              ((__u64)key->bytes[10] << 40) |
              ((__u64)key->bytes[11] << 32) |
              ((__u64)key->bytes[12] << 24) |
              ((__u64)key->bytes[13] << 16) |
              ((__u64)key->bytes[14] << 8) |
              (__u64)key->bytes[15];
  if (got != expected) {
    return -1;
  }

  __u32 decoded_worker = ((__u32)key->bytes[2] << 8) | (__u32)key->bytes[3];
  __u32 decoded_generation = (__u32)key->bytes[4];
  __u32 *current_generation =
      bpf_map_lookup_elem(&qaff_worker_generations, &decoded_worker);
  if (!current_generation ||
      *current_generation == 0 ||
      *current_generation != decoded_generation) {
    return -1;
  }

  *worker_id = decoded_worker;
  return 1;
}

static __always_inline int qaff_passive_worker(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key,
    __u32 *worker_id) {
  if (!config || !config->passive_affinity_enabled) {
    return 0;
  }

  struct qaff_passive_cid_value *value =
      bpf_map_lookup_elem(&qaff_passive_cids, key);
  if (!value) {
    qaff_count(QAFF_STAT_PASSIVE_MISS);
    return 0;
  }

  if (value->confidence < config->passive_min_confidence) {
    qaff_count(QAFF_STAT_PASSIVE_REJECT_CONFIDENCE);
    return -1;
  }

  __u64 now_ns = bpf_ktime_get_ns();
  if (value->expires_at_ns != 0 &&
      value->expires_at_ns <= now_ns) {
    qaff_count(QAFF_STAT_PASSIVE_REJECT_EXPIRED);
    return -1;
  }

  __u32 *current_generation =
      bpf_map_lookup_elem(&qaff_worker_generations, &value->worker_id);
  if (value->worker_generation == 0 ||
      !current_generation ||
      *current_generation == 0 ||
      *current_generation != value->worker_generation) {
    qaff_count(QAFF_STAT_PASSIVE_REJECT_GENERATION);
    return -1;
  }

  if (value->expires_at_ns != 0) {
    __u64 ttl_ns = QAFF_PASSIVE_TTL_HIGH_NS;
    if (value->source == QAFF_PASSIVE_SOURCE_EGRESS) {
      ttl_ns = QAFF_PASSIVE_TTL_EGRESS_NS;
    } else if (value->confidence == QAFF_PASSIVE_CONFIDENCE_LOW) {
      ttl_ns = QAFF_PASSIVE_TTL_LOW_NS;
    } else if (value->confidence == QAFF_PASSIVE_CONFIDENCE_MEDIUM) {
      ttl_ns = QAFF_PASSIVE_TTL_MEDIUM_NS;
    }

    /*
     * Use a sliding lifetime for active connections, but refresh only in the
     * latter half of the current TTL to avoid a map-value write per packet.
     * Rejected generation/confidence entries never receive an extension.
     */
    if (value->expires_at_ns - now_ns < ttl_ns / 2u) {
      value->expires_at_ns = now_ns + ttl_ns;
    }
  }

  *worker_id = value->worker_id;
  return 1;
}

static __always_inline int qaff_egress_udp_payload_offset(
    struct __sk_buff *skb,
    __u32 *payload_offset) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (data + 1 > data_end) {
    return QAFF_EGRESS_PARSE_MISS;
  }

  __u8 first = *(__u8 *)data;
  __u8 ip_version = first >> 4;
  if (ip_version == 4) {
    if (data + 20 > data_end) {
      return QAFF_EGRESS_PARSE_MISS;
    }
    __u8 ihl = first & 0x0f;
    if (ihl < 5) {
      return QAFF_EGRESS_PARSE_MISS;
    }
    __u32 ip_header_len = (__u32)ihl * 4u;
    if (data + ip_header_len + QAFF_UDP_HEADER_LEN > data_end) {
      return QAFF_EGRESS_PARSE_MISS;
    }
    __u8 protocol = *(__u8 *)(data + 9);
    if (protocol != QAFF_IPPROTO_UDP) {
      return QAFF_EGRESS_NOT_UDP;
    }
    __u16 fragment = ((__u16)*(__u8 *)(data + 6) << 8) |
                     (__u16)*(__u8 *)(data + 7);
    if (fragment & 0x3fffu) {
      return QAFF_EGRESS_FRAGMENTED;
    }
    *payload_offset = ip_header_len + QAFF_UDP_HEADER_LEN;
    return 0;
  }

  if (ip_version == 6) {
    if (data + 40 > data_end) {
      return QAFF_EGRESS_PARSE_MISS;
    }
    __u8 next_header = *(__u8 *)(data + 6);
    __u32 offset = 40u;

#pragma unroll
    for (int i = 0; i < QAFF_IPV6_MAX_EXTENSION_HEADERS; i++) {
      if (next_header == QAFF_IPPROTO_UDP) {
        if (data + offset + QAFF_UDP_HEADER_LEN > data_end) {
          return QAFF_EGRESS_PARSE_MISS;
        }
        *payload_offset = offset + QAFF_UDP_HEADER_LEN;
        return 0;
      }
      if (next_header == QAFF_IPPROTO_FRAGMENT) {
        return QAFF_EGRESS_FRAGMENTED;
      }
      if (next_header == QAFF_IPPROTO_HOPOPTS ||
          next_header == QAFF_IPPROTO_ROUTING ||
          next_header == QAFF_IPPROTO_DSTOPTS ||
          next_header == QAFF_IPPROTO_MH) {
        if (data + offset + 2 > data_end) {
          return QAFF_EGRESS_PARSE_MISS;
        }
        __u8 extension_next = *(__u8 *)(data + offset);
        __u8 extension_units = *(__u8 *)(data + offset + 1);
        __u32 extension_len = ((__u32)extension_units + 1u) * 8u;
        if (data + offset + extension_len > data_end) {
          return QAFF_EGRESS_PARSE_MISS;
        }
        next_header = extension_next;
        offset += extension_len;
        continue;
      }
      if (next_header == QAFF_IPPROTO_AH) {
        if (data + offset + 2 > data_end) {
          return QAFF_EGRESS_PARSE_MISS;
        }
        __u8 extension_next = *(__u8 *)(data + offset);
        __u8 extension_units = *(__u8 *)(data + offset + 1);
        __u32 extension_len = ((__u32)extension_units + 2u) * 4u;
        if (data + offset + extension_len > data_end) {
          return QAFF_EGRESS_PARSE_MISS;
        }
        next_header = extension_next;
        offset += extension_len;
        continue;
      }
      return QAFF_EGRESS_NOT_UDP;
    }

    if (next_header == QAFF_IPPROTO_UDP &&
        data + offset + QAFF_UDP_HEADER_LEN <= data_end) {
      *payload_offset = offset + QAFF_UDP_HEADER_LEN;
      return 0;
    }
    return QAFF_EGRESS_PARSE_MISS;
  }

  return QAFF_EGRESS_PARSE_MISS;
}

static __always_inline int qaff_extract_long_scid(struct __sk_buff *skb,
                                                  struct qaff_cid_key *key) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __u32 payload_offset = 0;

  int rc = qaff_egress_udp_payload_offset(skb, &payload_offset);
  if (rc != 0) {
    return rc;
  }
  if (data + payload_offset + 6 > data_end) {
    return QAFF_EGRESS_PARSE_MISS;
  }

  __u8 first = *(__u8 *)(data + payload_offset);
  if ((first & 0x80) == 0) {
    return QAFF_EGRESS_SHORT_HEADER;
  }
  if ((first & 0xc0) != 0xc0) {
    return QAFF_EGRESS_PARSE_MISS;
  }

  __u32 version = ((__u32)*(__u8 *)(data + payload_offset + 1) << 24) |
                  ((__u32)*(__u8 *)(data + payload_offset + 2) << 16) |
                  ((__u32)*(__u8 *)(data + payload_offset + 3) << 8) |
                  (__u32)*(__u8 *)(data + payload_offset + 4);
  __u8 packet_type = (first >> 4) & 0x03u;
  if (version != QAFF_QUIC_VERSION_1) {
    return QAFF_EGRESS_REJECT_VERSION;
  }
  if (packet_type == QAFF_QUIC_LONG_TYPE_0RTT_V1) {
    return QAFF_EGRESS_REJECT_TYPE;
  }

  __u8 dcid_len = *(__u8 *)(data + payload_offset + 5);
  if (dcid_len > QAFF_MAX_CID_LEN) {
    return QAFF_EGRESS_PARSE_MISS;
  }

  __u32 scid_len_offset = payload_offset + 6u + (__u32)dcid_len;
  if (data + scid_len_offset + 1 > data_end) {
    return QAFF_EGRESS_PARSE_MISS;
  }

  __u8 scid_len = *(__u8 *)(data + scid_len_offset);
  if (scid_len == 0) {
    return QAFF_EGRESS_ZERO_LENGTH_SCID;
  }
  if (scid_len > QAFF_MAX_CID_LEN) {
    return QAFF_EGRESS_TOO_LONG_SCID;
  }

  return qaff_copy_skb_cid(skb, key, scid_len_offset + 1, scid_len);
}

SEC("sk_reuseport")
int qaff_select(struct sk_reuseport_md *ctx) {
  struct qaff_cid_key key;
  __u32 fallback = QAFF_DEFAULT_WORKER_ID;
  __u32 config_key = 0;
  struct qaff_config_value *config =
      bpf_map_lookup_elem(&qaff_config, &config_key);
  if (config) {
    fallback = config->fallback_worker_id;
  }

  qaff_count(QAFF_STAT_PACKETS);

  int rc = qaff_extract_dcid(ctx, &key);
  if (rc == -2) {
    qaff_count(QAFF_STAT_ZERO_LENGTH_CID);
  } else if (rc < 0) {
    qaff_count(QAFF_STAT_PARSE_ERROR);
  } else {
    struct qaff_cid_value *cid_value =
        bpf_map_lookup_elem(&qaff_cids, &key);
    if (cid_value) {
      __u32 *current_generation = bpf_map_lookup_elem(
          &qaff_worker_generations, &cid_value->worker_id);
      if (!current_generation ||
          cid_value->worker_generation == 0 ||
          *current_generation == 0 ||
          *current_generation != cid_value->worker_generation) {
        qaff_count(QAFF_STAT_CID_MAP_REJECT_GENERATION);
        goto fallback;
      }
      qaff_count(QAFF_STAT_CID_MAP_HIT);
      if (bpf_sk_select_reuseport(ctx,
                                  &qaff_workers,
                                  &cid_value->worker_id,
                                  0) == 0) {
        return SK_PASS;
      }
      qaff_count(QAFF_STAT_WORKER_MISSING);
    } else {
      __u32 profile_worker = 0;
      int profile_rc = qaff_profile_worker(config, &key, &profile_worker);
      if (profile_rc > 0) {
        qaff_count(QAFF_STAT_CID_PROFILE_HIT);
        if (bpf_sk_select_reuseport(ctx,
                                    &qaff_workers,
                                    &profile_worker,
                                    0) == 0) {
          return SK_PASS;
        }
        qaff_count(QAFF_STAT_WORKER_MISSING);
      } else if (profile_rc < 0) {
        qaff_count(QAFF_STAT_CID_PROFILE_REJECT);
      } else {
        __u32 passive_worker = 0;
        int passive_rc = qaff_passive_worker(config, &key, &passive_worker);
        if (passive_rc > 0) {
          qaff_count(QAFF_STAT_PASSIVE_HIT);
          if (bpf_sk_select_reuseport(ctx,
                                      &qaff_workers,
                                      &passive_worker,
                                      0) == 0) {
            return SK_PASS;
          }
          qaff_count(QAFF_STAT_WORKER_MISSING);
        }
      }
    }
  }

fallback:
  qaff_count(QAFF_STAT_FALLBACK);
  if (config && config->fallback_mode == QAFF_FALLBACK_MODE_KERNEL) {
    return SK_PASS;
  }
  if (bpf_sk_select_reuseport(ctx, &qaff_workers, &fallback, 0) == 0) {
    return SK_PASS;
  }
  qaff_count(QAFF_STAT_WORKER_MISSING);
  return SK_DROP;
}

SEC("cgroup_skb/egress")
int qaff_egress_learn(struct __sk_buff *skb) {
  __u32 config_key = 0;
  struct qaff_config_value *config =
      bpf_map_lookup_elem(&qaff_config, &config_key);
  if (!config || !config->passive_affinity_enabled) {
    return 1;
  }

  struct qaff_cid_key key;
  int parse_rc = qaff_extract_long_scid(skb, &key);
  if (parse_rc != 0) {
    if (parse_rc == QAFF_EGRESS_NOT_UDP) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_NOT_UDP);
    } else if (parse_rc == QAFF_EGRESS_ZERO_LENGTH_SCID) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_ZERO_LENGTH_SCID);
    } else if (parse_rc == QAFF_EGRESS_TOO_LONG_SCID) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_TOO_LONG_SCID);
    } else if (parse_rc == QAFF_EGRESS_FRAGMENTED) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_FRAGMENTED);
    } else if (parse_rc == QAFF_EGRESS_REJECT_VERSION) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_REJECT_VERSION);
    } else if (parse_rc == QAFF_EGRESS_REJECT_TYPE) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_REJECT_TYPE);
    } else if (parse_rc == QAFF_EGRESS_SHORT_HEADER) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_SHORT_HEADER);
    } else {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_PARSE_MISS);
    }
    return 1;
  }

  /* The profile namespace is authoritative and must not consume passive LRU. */
  if (qaff_is_profile_candidate(config, &key)) {
    return 1;
  }

  __u64 cookie = bpf_get_socket_cookie(skb);
  if (cookie == 0) {
    qaff_count(QAFF_STAT_PASSIVE_EGRESS_NO_WORKER);
    qaff_count(QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_MISS);
    return 1;
  }

  __u32 *worker_id = bpf_map_lookup_elem(&qaff_socket_workers, &cookie);
  if (!worker_id) {
    qaff_count(QAFF_STAT_PASSIVE_EGRESS_NO_WORKER);
    qaff_count(QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_MISS);
    return 1;
  }
  qaff_count(QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_HIT);

  struct qaff_passive_cid_value value;
  __builtin_memset(&value, 0, sizeof(value));
  value.worker_id = *worker_id;
  __u32 *generation = bpf_map_lookup_elem(&qaff_worker_generations, worker_id);
  if (!generation || *generation == 0) {
    qaff_count(QAFF_STAT_PASSIVE_EGRESS_NO_WORKER);
    return 1;
  }
  value.worker_generation = *generation;
  value.confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  value.source = QAFF_PASSIVE_SOURCE_EGRESS;
  value.expires_at_ns = bpf_ktime_get_ns() + QAFF_PASSIVE_TTL_EGRESS_NS;

  struct qaff_passive_cid_value *existing =
      bpf_map_lookup_elem(&qaff_passive_cids, &key);
  if (existing) {
    if (existing->worker_id != value.worker_id ||
        existing->worker_generation != value.worker_generation) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_CONFLICT);
      return 1;
    }

    /* Same-owner egress observation may strengthen and refresh the record. */
    existing->confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
    existing->source = QAFF_PASSIVE_SOURCE_EGRESS;
    existing->expires_at_ns = value.expires_at_ns;
    if (qaff_drop_stale_egress_learning(&key, &value, generation)) {
      return 1;
    }
    qaff_count(QAFF_STAT_PASSIVE_EGRESS_LEARN);
    return 1;
  }

  if (bpf_map_update_elem(&qaff_passive_cids,
                          &key,
                          &value,
                          BPF_NOEXIST) != 0) {
    /* Resolve a concurrent insert without ever replacing its owner. */
    existing = bpf_map_lookup_elem(&qaff_passive_cids, &key);
    if (existing && existing->worker_id == value.worker_id &&
        existing->worker_generation == value.worker_generation) {
      existing->confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
      existing->source = QAFF_PASSIVE_SOURCE_EGRESS;
      existing->expires_at_ns = value.expires_at_ns;
      if (!qaff_drop_stale_egress_learning(&key, &value, generation)) {
        qaff_count(QAFF_STAT_PASSIVE_EGRESS_LEARN);
      }
    } else if (existing) {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_CONFLICT);
    } else {
      qaff_count(QAFF_STAT_PASSIVE_EGRESS_MAP_UPDATE_ERROR);
    }
    return 1;
  }

  /* Do not leave an in-flight observation behind after worker withdrawal. */
  if (qaff_drop_stale_egress_learning(&key, &value, generation)) {
    return 1;
  }
  qaff_count(QAFF_STAT_PASSIVE_EGRESS_LEARN);
  return 1;
}
