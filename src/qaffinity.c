#include "quic_affinity/quic_affinity.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

struct qaff_context {
  int cid_map_fd;
  int worker_sock_map_fd;
  int stats_map_fd;
  int owns_cid_map;
  int owns_worker_sock_map;
  int owns_stats_map;
  uint8_t short_cid_len;
};

static int qaff_create_hash_map(const char *name,
                                uint32_t key_size,
                                uint32_t value_size,
                                uint32_t max_entries) {
  return bpf_map_create(BPF_MAP_TYPE_HASH,
                        name,
                        key_size,
                        value_size,
                        max_entries,
                        NULL);
}

static int qaff_create_sockhash_map(const char *name, uint32_t max_entries) {
  return bpf_map_create(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
                        name,
                        sizeof(uint32_t),
                        sizeof(uint32_t),
                        max_entries,
                        NULL);
}

static int qaff_create_stats_map(const char *name) {
  return bpf_map_create(BPF_MAP_TYPE_ARRAY,
                        name,
                        sizeof(uint32_t),
                        sizeof(uint64_t),
                        QAFF_STAT_MAX,
                        NULL);
}

int qaff_open(const struct qaff_options *options, struct qaff_context **out) {
  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_context *ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    return -1;
  }

  ctx->cid_map_fd = options ? options->cid_map_fd : -1;
  ctx->worker_sock_map_fd = options ? options->worker_sock_map_fd : -1;
  ctx->stats_map_fd = options ? options->stats_map_fd : -1;
  ctx->short_cid_len = options ? options->short_cid_len : 0;

  if (ctx->cid_map_fd < 0) {
    ctx->cid_map_fd = qaff_create_hash_map("qaff_cids",
                                           sizeof(struct qaff_cid_key),
                                           sizeof(uint32_t),
                                           1024 * 1024);
    if (ctx->cid_map_fd < 0) {
      goto fail;
    }
    ctx->owns_cid_map = 1;
  }

  if (ctx->worker_sock_map_fd < 0) {
    ctx->worker_sock_map_fd = qaff_create_sockhash_map("qaff_workers", 4096);
    if (ctx->worker_sock_map_fd < 0) {
      goto fail;
    }
    ctx->owns_worker_sock_map = 1;
  }

  if (ctx->stats_map_fd < 0) {
    ctx->stats_map_fd = qaff_create_stats_map("qaff_stats");
    if (ctx->stats_map_fd < 0) {
      goto fail;
    }
    ctx->owns_stats_map = 1;
  }

  *out = ctx;
  return 0;

fail:
  qaff_close(ctx);
  return -1;
}

void qaff_close(struct qaff_context *ctx) {
  if (ctx == NULL) {
    return;
  }
  if (ctx->owns_cid_map && ctx->cid_map_fd >= 0) {
    close(ctx->cid_map_fd);
  }
  if (ctx->owns_worker_sock_map && ctx->worker_sock_map_fd >= 0) {
    close(ctx->worker_sock_map_fd);
  }
  if (ctx->owns_stats_map && ctx->stats_map_fd >= 0) {
    close(ctx->stats_map_fd);
  }
  free(ctx);
}

int qaff_register_cid(struct qaff_context *ctx,
                      const uint8_t *cid,
                      size_t cid_len,
                      uint32_t worker_id) {
  if (ctx == NULL || ctx->cid_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_cid_key key;
  int rc = qaff_cid_key_from_bytes(cid, cid_len, &key);
  if (rc != QAFF_PARSE_OK) {
    errno = EINVAL;
    return -1;
  }

  return bpf_map_update_elem(ctx->cid_map_fd, &key, &worker_id, BPF_ANY);
}

int qaff_retire_cid(struct qaff_context *ctx,
                    const uint8_t *cid,
                    size_t cid_len) {
  if (ctx == NULL || ctx->cid_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_cid_key key;
  int rc = qaff_cid_key_from_bytes(cid, cid_len, &key);
  if (rc != QAFF_PARSE_OK) {
    errno = EINVAL;
    return -1;
  }

  return bpf_map_delete_elem(ctx->cid_map_fd, &key);
}

int qaff_register_worker_socket(struct qaff_context *ctx,
                                uint32_t worker_id,
                                int socket_fd) {
  if (ctx == NULL || ctx->worker_sock_map_fd < 0 || socket_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  return bpf_map_update_elem(ctx->worker_sock_map_fd,
                             &worker_id,
                             &socket_fd,
                             BPF_ANY);
}

int qaff_get_cid_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->cid_map_fd : -1;
}

int qaff_get_worker_sock_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->worker_sock_map_fd : -1;
}

int qaff_get_stats_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->stats_map_fd : -1;
}

