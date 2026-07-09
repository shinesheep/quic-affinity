#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "qaff_bpf.h"

#define QAFF_ETH_P_IP 0x0008
#define QAFF_ETH_P_IPV6 0xdd86
#define QAFF_IPPROTO_UDP 17
#define QAFF_UDP_HEADER_LEN 8

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1048576);
  __type(key, struct qaff_cid_key);
  __type(value, __u32);
} qaff_cids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1048576);
  __type(key, struct qaff_cid_key);
  __type(value, struct qaff_passive_cid_value);
} qaff_passive_cids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u32);
} qaff_workers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);
  __type(value, __u32);
} qaff_socket_workers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 4096);
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

static __always_inline __u32 qaff_profile_hash32(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key,
    __u32 prefix_len) {
  __u32 h = 2166136261u;

#pragma unroll
  for (__u32 i = 0; i < QAFF_CID_PROFILE_KEY_LEN; i++) {
    h ^= config->cid_profile_v1_key[i];
    h *= 16777619u;
  }

#pragma unroll
  for (__u32 i = 0; i < 8; i++) {
    if (i >= prefix_len) {
      break;
    }
    h ^= key->bytes[i];
    h *= 16777619u;
  }

  h ^= h >> 16;
  h *= 2246822519u;
  h ^= h >> 13;
  h *= 3266489917u;
  h ^= h >> 16;
  return h;
}

static __always_inline __u16 qaff_profile_v1_tag(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key) {
  return (__u16)qaff_profile_hash32(config, key, 6);
}

static __always_inline int qaff_profile_v1_worker(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key,
    __u32 *worker_id) {
  if (!config || !config->cid_profile_v1_enabled) {
    return 0;
  }
  if (key->len != QAFF_CID_PROFILE_V1_LEN) {
    return 0;
  }

  __u8 version = key->bytes[0] >> 4;
  if (version != QAFF_CID_PROFILE_V1_VERSION) {
    return 0;
  }

  __u16 expected = qaff_profile_v1_tag(config, key);
  __u16 got = ((__u16)key->bytes[6] << 8) | (__u16)key->bytes[7];
  if (got != expected) {
    return -1;
  }

  *worker_id = ((__u32)key->bytes[1] << 8) | (__u32)key->bytes[2];
  return 1;
}

static __always_inline int qaff_profile_v2_worker(
    const struct qaff_config_value *config,
    const struct qaff_cid_key *key,
    __u32 *worker_id) {
  if (!config || !config->cid_profile_v2_enabled) {
    return 0;
  }
  if (key->len != QAFF_CID_PROFILE_V2_LEN) {
    return 0;
  }

  __u8 version = key->bytes[0] >> 4;
  if (version != QAFF_CID_PROFILE_V2_VERSION) {
    return 0;
  }
  if (key->bytes[1] != config->cid_profile_v2_config_id) {
    return -1;
  }

  __u32 expected = qaff_profile_hash32(config, key, 8);
  __u32 got = ((__u32)key->bytes[8] << 24) |
              ((__u32)key->bytes[9] << 16) |
              ((__u32)key->bytes[10] << 8) |
              (__u32)key->bytes[11];
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

  if (value->worker_generation != 0) {
    __u32 *current_generation =
        bpf_map_lookup_elem(&qaff_worker_generations, &value->worker_id);
    if (!current_generation ||
        *current_generation == 0 ||
        *current_generation != value->worker_generation) {
      qaff_count(QAFF_STAT_PASSIVE_REJECT_GENERATION);
      return -1;
    }
  }

  *worker_id = value->worker_id;
  return 1;
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
    __u32 *worker_id = bpf_map_lookup_elem(&qaff_cids, &key);
    if (worker_id) {
      qaff_count(QAFF_STAT_CID_MAP_HIT);
      if (bpf_sk_select_reuseport(ctx, &qaff_workers, worker_id, 0) == 0) {
        return SK_PASS;
      }
      qaff_count(QAFF_STAT_WORKER_MISSING);
    } else {
      __u32 profile_worker = 0;
      int profile_rc = qaff_profile_v2_worker(config, &key, &profile_worker);
      if (profile_rc == 0) {
        profile_rc = qaff_profile_v1_worker(config, &key, &profile_worker);
      }
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

  qaff_count(QAFF_STAT_FALLBACK);
  bpf_sk_select_reuseport(ctx, &qaff_workers, &fallback, 0);
  return SK_PASS;
}
