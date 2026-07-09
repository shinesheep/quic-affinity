#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "qaff_bpf.h"

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
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u32);
} qaff_workers SEC(".maps");

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

  if (ctx->ip_protocol != QAFF_IPPROTO_UDP) {
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

SEC("sk_reuseport")
int qaff_select(struct sk_reuseport_md *ctx) {
  struct qaff_cid_key key;
  __u32 fallback = QAFF_DEFAULT_WORKER_ID;

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
    }
  }

  qaff_count(QAFF_STAT_FALLBACK);
  bpf_sk_select_reuseport(ctx, &qaff_workers, &fallback, 0);
  return SK_PASS;
}
