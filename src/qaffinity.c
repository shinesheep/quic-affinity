#include "quic_affinity/quic_affinity.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct qaff_context {
  int cid_map_fd;
  int worker_sock_map_fd;
  int worker_generation_map_fd;
  int stats_map_fd;
  int config_map_fd;
  int owns_cid_map;
  int owns_worker_sock_map;
  int owns_worker_generation_map;
  int owns_stats_map;
  int owns_config_map;
  const char *pin_root;
  uint8_t short_cid_len;
  uint8_t cid_profile_v1_enabled;
  uint8_t cid_profile_v2_enabled;
  uint8_t cid_profile_v2_config_id;
  uint8_t cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
};

void qaff_options_init(struct qaff_options *options) {
  if (options == NULL) {
    return;
  }
  memset(options, 0, sizeof(*options));
  options->cid_map_fd = -1;
  options->worker_sock_map_fd = -1;
  options->worker_generation_map_fd = -1;
  options->stats_map_fd = -1;
  options->config_map_fd = -1;
  options->pin_root = NULL;
  options->cid_profile_v1_enabled = 0;
  options->cid_profile_v2_enabled = 0;
  options->cid_profile_v2_config_id = 0;
  memset(options->cid_profile_v1_key, 0, sizeof(options->cid_profile_v1_key));
  options->fallback_worker_id = 0;
}

static int qaff_mkdir_p(const char *path) {
  char tmp[PATH_MAX];
  size_t len = strlen(path);
  if (len == 0 || len >= sizeof(tmp)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  memcpy(tmp, path, len + 1);
  for (char *p = tmp + 1; *p; p++) {
    if (*p != '/') {
      continue;
    }
    *p = '\0';
    if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
      return -1;
    }
    *p = '/';
  }

  if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static int qaff_validate_pin_root(const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return -1;
  }
  if (!S_ISDIR(st.st_mode) || (st.st_mode & 0022) != 0) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

static int qaff_pin_path(const char *pin_root,
                         const char *name,
                         char *out,
                         size_t out_len) {
  int n = snprintf(out, out_len, "%s/%s", pin_root, name);
  if (n < 0 || (size_t)n >= out_len) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return 0;
}

static int qaff_open_or_pin_map(const char *pin_root,
                                const char *name,
                                int created_fd) {
  if (pin_root == NULL) {
    return created_fd;
  }

  if (qaff_mkdir_p(pin_root) != 0) {
    close(created_fd);
    return -1;
  }
  if (qaff_validate_pin_root(pin_root) != 0) {
    close(created_fd);
    return -1;
  }

  char path[PATH_MAX];
  if (qaff_pin_path(pin_root, name, path, sizeof(path)) != 0) {
    close(created_fd);
    return -1;
  }

  int pinned_fd = bpf_obj_get(path);
  if (pinned_fd >= 0) {
    close(created_fd);
    return pinned_fd;
  }
  if (errno != ENOENT) {
    int saved_errno = errno;
    close(created_fd);
    errno = saved_errno;
    return -1;
  }

  if (bpf_obj_pin(created_fd, path) != 0) {
    int saved_errno = errno;
    close(created_fd);
    errno = saved_errno;
    return -1;
  }

  return created_fd;
}

static int qaff_get_pinned_map(const char *pin_root, const char *name) {
  if (pin_root == NULL) {
    errno = ENOENT;
    return -1;
  }
  if (qaff_mkdir_p(pin_root) != 0) {
    return -1;
  }
  if (qaff_validate_pin_root(pin_root) != 0) {
    return -1;
  }

  char path[PATH_MAX];
  if (qaff_pin_path(pin_root, name, path, sizeof(path)) != 0) {
    return -1;
  }
  return bpf_obj_get(path);
}

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

static int qaff_validate_map_fd(int fd,
                                enum bpf_map_type type,
                                uint32_t key_size,
                                uint32_t value_size,
                                uint32_t max_entries) {
  struct bpf_map_info info;
  memset(&info, 0, sizeof(info));
  uint32_t info_len = sizeof(info);
  if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
    return -1;
  }
  if (info.type != type ||
      info.key_size != key_size ||
      info.value_size != value_size ||
      info.max_entries != max_entries) {
    errno = EINVAL;
    return -1;
  }
  return 0;
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

static int qaff_create_generation_map(const char *name, uint32_t max_entries) {
  return bpf_map_create(BPF_MAP_TYPE_ARRAY,
                        name,
                        sizeof(uint32_t),
                        sizeof(uint32_t),
                        max_entries,
                        NULL);
}

static int qaff_create_config_map(const char *name) {
  return bpf_map_create(BPF_MAP_TYPE_ARRAY,
                        name,
                        sizeof(uint32_t),
                        sizeof(struct qaff_config_value),
                        1,
                        NULL);
}

static int qaff_write_config(struct qaff_context *ctx) {
  struct qaff_config_value value;
  memset(&value, 0, sizeof(value));
  value.short_cid_len = ctx->short_cid_len;
  value.cid_profile_v1_enabled = ctx->cid_profile_v1_enabled;
  value.cid_profile_v2_enabled = ctx->cid_profile_v2_enabled;
  value.cid_profile_v2_config_id = ctx->cid_profile_v2_config_id;
  memcpy(value.cid_profile_v1_key,
         ctx->cid_profile_v1_key,
         sizeof(value.cid_profile_v1_key));
  value.fallback_worker_id = ctx->fallback_worker_id;

  uint32_t key = 0;
  return bpf_map_update_elem(ctx->config_map_fd, &key, &value, BPF_ANY);
}

static int qaff_validate_context_maps(const struct qaff_context *ctx) {
  if (qaff_validate_map_fd(ctx->cid_map_fd,
                           BPF_MAP_TYPE_HASH,
                           sizeof(struct qaff_cid_key),
                           sizeof(uint32_t),
                           1024 * 1024) != 0 ||
      qaff_validate_map_fd(ctx->worker_sock_map_fd,
                           BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
                           sizeof(uint32_t),
                           sizeof(uint32_t),
                           4096) != 0 ||
      qaff_validate_map_fd(ctx->worker_generation_map_fd,
                           BPF_MAP_TYPE_ARRAY,
                           sizeof(uint32_t),
                           sizeof(uint32_t),
                           4096) != 0 ||
      qaff_validate_map_fd(ctx->stats_map_fd,
                           BPF_MAP_TYPE_ARRAY,
                           sizeof(uint32_t),
                           sizeof(uint64_t),
                           QAFF_STAT_MAX) != 0 ||
      qaff_validate_map_fd(ctx->config_map_fd,
                           BPF_MAP_TYPE_ARRAY,
                           sizeof(uint32_t),
                           sizeof(struct qaff_config_value),
                           1) != 0) {
    return -1;
  }
  return 0;
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

  struct qaff_options defaults;
  if (options == NULL) {
    qaff_options_init(&defaults);
    options = &defaults;
  }

  ctx->cid_map_fd = options->cid_map_fd;
  ctx->worker_sock_map_fd = options->worker_sock_map_fd;
  ctx->worker_generation_map_fd = options->worker_generation_map_fd;
  ctx->stats_map_fd = options->stats_map_fd;
  ctx->config_map_fd = options->config_map_fd;
  ctx->pin_root = options->pin_root;
  ctx->short_cid_len = options->short_cid_len;
  ctx->cid_profile_v1_enabled = options->cid_profile_v1_enabled;
  ctx->cid_profile_v2_enabled = options->cid_profile_v2_enabled;
  ctx->cid_profile_v2_config_id = options->cid_profile_v2_config_id;
  memcpy(ctx->cid_profile_v1_key,
         options->cid_profile_v1_key,
         sizeof(ctx->cid_profile_v1_key));
  ctx->fallback_worker_id = options->fallback_worker_id;

  if (ctx->cid_map_fd < 0) {
    ctx->cid_map_fd = qaff_get_pinned_map(ctx->pin_root, "qaff_cids");
    if (ctx->cid_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->cid_map_fd < 0) {
      ctx->cid_map_fd = qaff_create_hash_map("qaff_cids",
                                             sizeof(struct qaff_cid_key),
                                             sizeof(uint32_t),
                                             1024 * 1024);
    }
    if (ctx->cid_map_fd < 0) {
      goto fail;
    }
    ctx->cid_map_fd = qaff_open_or_pin_map(ctx->pin_root,
                                           "qaff_cids",
                                           ctx->cid_map_fd);
    if (ctx->cid_map_fd < 0) {
      goto fail;
    }
    if (qaff_validate_map_fd(ctx->cid_map_fd,
                             BPF_MAP_TYPE_HASH,
                             sizeof(struct qaff_cid_key),
                             sizeof(uint32_t),
                             1024 * 1024) != 0) {
      goto fail;
    }
    ctx->owns_cid_map = 1;
  }

  if (ctx->worker_sock_map_fd < 0) {
    ctx->worker_sock_map_fd = qaff_get_pinned_map(ctx->pin_root,
                                                  "qaff_workers");
    if (ctx->worker_sock_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->worker_sock_map_fd < 0) {
      ctx->worker_sock_map_fd = qaff_create_sockhash_map("qaff_workers", 4096);
    }
    if (ctx->worker_sock_map_fd < 0) {
      goto fail;
    }
    ctx->worker_sock_map_fd = qaff_open_or_pin_map(ctx->pin_root,
                                                   "qaff_workers",
                                                   ctx->worker_sock_map_fd);
    if (ctx->worker_sock_map_fd < 0) {
      goto fail;
    }
    if (qaff_validate_map_fd(ctx->worker_sock_map_fd,
                             BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
                             sizeof(uint32_t),
                             sizeof(uint32_t),
                             4096) != 0) {
      goto fail;
    }
    ctx->owns_worker_sock_map = 1;
  }

  if (ctx->worker_generation_map_fd < 0) {
    ctx->worker_generation_map_fd = qaff_get_pinned_map(ctx->pin_root,
                                                        "qaff_worker_generations");
    if (ctx->worker_generation_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->worker_generation_map_fd < 0) {
      ctx->worker_generation_map_fd =
          qaff_create_generation_map("qaff_worker_generations", 4096);
    }
    if (ctx->worker_generation_map_fd < 0) {
      goto fail;
    }
    ctx->worker_generation_map_fd =
        qaff_open_or_pin_map(ctx->pin_root,
                             "qaff_worker_generations",
                             ctx->worker_generation_map_fd);
    if (ctx->worker_generation_map_fd < 0) {
      goto fail;
    }
    if (qaff_validate_map_fd(ctx->worker_generation_map_fd,
                             BPF_MAP_TYPE_ARRAY,
                             sizeof(uint32_t),
                             sizeof(uint32_t),
                             4096) != 0) {
      goto fail;
    }
    ctx->owns_worker_generation_map = 1;
  }

  if (ctx->stats_map_fd < 0) {
    ctx->stats_map_fd = qaff_get_pinned_map(ctx->pin_root, "qaff_stats");
    if (ctx->stats_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->stats_map_fd < 0) {
      ctx->stats_map_fd = qaff_create_stats_map("qaff_stats");
    }
    if (ctx->stats_map_fd < 0) {
      goto fail;
    }
    ctx->stats_map_fd = qaff_open_or_pin_map(ctx->pin_root,
                                             "qaff_stats",
                                             ctx->stats_map_fd);
    if (ctx->stats_map_fd < 0) {
      goto fail;
    }
    if (qaff_validate_map_fd(ctx->stats_map_fd,
                             BPF_MAP_TYPE_ARRAY,
                             sizeof(uint32_t),
                             sizeof(uint64_t),
                             QAFF_STAT_MAX) != 0) {
      goto fail;
    }
    ctx->owns_stats_map = 1;
  }

  if (ctx->config_map_fd < 0) {
    ctx->config_map_fd = qaff_get_pinned_map(ctx->pin_root, "qaff_config");
    if (ctx->config_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->config_map_fd < 0) {
      ctx->config_map_fd = qaff_create_config_map("qaff_config");
    }
    if (ctx->config_map_fd < 0) {
      goto fail;
    }
    ctx->config_map_fd = qaff_open_or_pin_map(ctx->pin_root,
                                              "qaff_config",
                                              ctx->config_map_fd);
    if (ctx->config_map_fd < 0) {
      goto fail;
    }
    if (qaff_validate_map_fd(ctx->config_map_fd,
                             BPF_MAP_TYPE_ARRAY,
                             sizeof(uint32_t),
                             sizeof(struct qaff_config_value),
                             1) != 0) {
      goto fail;
    }
    ctx->owns_config_map = 1;
  }

  if (qaff_validate_context_maps(ctx) != 0 ||
      qaff_write_config(ctx) != 0) {
    goto fail;
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
  if (ctx->owns_worker_generation_map && ctx->worker_generation_map_fd >= 0) {
    close(ctx->worker_generation_map_fd);
  }
  if (ctx->owns_stats_map && ctx->stats_map_fd >= 0) {
    close(ctx->stats_map_fd);
  }
  if (ctx->owns_config_map && ctx->config_map_fd >= 0) {
    close(ctx->config_map_fd);
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
  return qaff_register_worker_socket_generation(ctx,
                                                worker_id,
                                                socket_fd,
                                                QAFF_WORKER_GENERATION_DEFAULT);
}

int qaff_register_worker_socket_generation(struct qaff_context *ctx,
                                           uint32_t worker_id,
                                           int socket_fd,
                                           uint32_t generation) {
  if (ctx == NULL || ctx->worker_sock_map_fd < 0 || socket_fd < 0) {
    errno = EINVAL;
    return -1;
  }
  if (generation == 0 || generation > QAFF_WORKER_GENERATION_MAX) {
    errno = EINVAL;
    return -1;
  }

  if (bpf_map_update_elem(ctx->worker_sock_map_fd,
                          &worker_id,
                          &socket_fd,
                          BPF_ANY) != 0) {
    return -1;
  }

  if (ctx->worker_generation_map_fd >= 0 &&
      bpf_map_update_elem(ctx->worker_generation_map_fd,
                          &worker_id,
                          &generation,
                          BPF_ANY) != 0) {
    int saved_errno = errno ? errno : EIO;
    bpf_map_delete_elem(ctx->worker_sock_map_fd, &worker_id);
    errno = saved_errno;
    return -1;
  }

  return 0;
}

int qaff_unregister_worker_socket(struct qaff_context *ctx,
                                  uint32_t worker_id) {
  if (ctx == NULL || ctx->worker_sock_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  int rc = bpf_map_delete_elem(ctx->worker_sock_map_fd, &worker_id);
  if (ctx->worker_generation_map_fd >= 0) {
    uint32_t zero = 0;
    bpf_map_update_elem(ctx->worker_generation_map_fd,
                        &worker_id,
                        &zero,
                        BPF_ANY);
  }
  return rc;
}

int qaff_get_cid_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->cid_map_fd : -1;
}

int qaff_get_worker_sock_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->worker_sock_map_fd : -1;
}

int qaff_get_worker_generation_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->worker_generation_map_fd : -1;
}

int qaff_get_stats_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->stats_map_fd : -1;
}

int qaff_get_config_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->config_map_fd : -1;
}

int qaff_read_stats(struct qaff_context *ctx, struct qaff_stats *out) {
  if (ctx == NULL || out == NULL || ctx->stats_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  memset(out, 0, sizeof(*out));
  for (uint32_t i = 0; i < QAFF_STAT_MAX; i++) {
    uint64_t value = 0;
    if (bpf_map_lookup_elem(ctx->stats_map_fd, &i, &value) != 0) {
      return -1;
    }
    out->values[i] = value;
  }

  return 0;
}

const char *qaff_stat_name(uint32_t index) {
  switch (index) {
  case QAFF_STAT_PACKETS:
    return "packets";
  case QAFF_STAT_CID_MAP_HIT:
    return "cid_map_hit";
  case QAFF_STAT_FALLBACK:
    return "fallback";
  case QAFF_STAT_PARSE_ERROR:
    return "parse_error";
  case QAFF_STAT_ZERO_LENGTH_CID:
    return "zero_length_cid";
  case QAFF_STAT_WORKER_MISSING:
    return "worker_missing";
  case QAFF_STAT_IPV4:
    return "ipv4";
  case QAFF_STAT_IPV6:
    return "ipv6";
  case QAFF_STAT_NOT_UDP:
    return "not_udp";
  case QAFF_STAT_CID_PROFILE_HIT:
    return "cid_profile_hit";
  case QAFF_STAT_CID_PROFILE_REJECT:
    return "cid_profile_reject";
  default:
    return "unknown";
  }
}
