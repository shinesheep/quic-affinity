#include "quic_affinity/quic_affinity.h"

#include "qaffinity_internal.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <linux/bpf.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

struct qaff_context {
  int cid_map_fd;
  int passive_cid_map_fd;
  int worker_sock_map_fd;
  int socket_worker_map_fd;
  int worker_generation_map_fd;
  int stats_map_fd;
  int config_map_fd;
  int owns_cid_map;
  int owns_passive_cid_map;
  int owns_worker_sock_map;
  int owns_socket_worker_map;
  int owns_worker_generation_map;
  int owns_stats_map;
  int owns_config_map;
  const char *pin_root;
  uint8_t short_cid_len;
  uint8_t cid_profile_v2_enabled;
  uint8_t cid_profile_v2_config_id;
  uint8_t passive_affinity_enabled;
  uint8_t passive_min_confidence;
  uint8_t fallback_mode;
  uint8_t cid_profile_key[QAFF_CID_PROFILE_KEY_LEN];
  uint32_t fallback_worker_id;
  pthread_mutex_t mutation_lock;
  int mutation_lock_initialized;
};

static int qaff_lock_mutations(struct qaff_context *ctx) {
  int rc = pthread_mutex_lock(&ctx->mutation_lock);
  if (rc != 0) {
    errno = rc;
    return -1;
  }
  return 0;
}

static void qaff_unlock_mutations(struct qaff_context *ctx) {
  (void)pthread_mutex_unlock(&ctx->mutation_lock);
}

void qaff_options_init(struct qaff_options *options) {
  if (options == NULL) {
    return;
  }
  memset(options, 0, sizeof(*options));
  options->cid_map_fd = -1;
  options->passive_cid_map_fd = -1;
  options->worker_sock_map_fd = -1;
  options->socket_worker_map_fd = -1;
  options->worker_generation_map_fd = -1;
  options->stats_map_fd = -1;
  options->config_map_fd = -1;
  options->pin_root = NULL;
  options->cid_profile_v2_enabled = 0;
  options->cid_profile_v2_config_id = 0;
  options->passive_affinity_enabled = 0;
  options->passive_min_confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  options->fallback_mode = QAFF_FALLBACK_MODE_FIXED;
  memset(options->cid_profile_key, 0, sizeof(options->cid_profile_key));
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

static int qaff_create_lru_hash_map(const char *name,
                                    uint32_t key_size,
                                    uint32_t value_size,
                                    uint32_t max_entries) {
  return bpf_map_create(BPF_MAP_TYPE_LRU_HASH,
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
  value.cid_profile_v2_enabled = ctx->cid_profile_v2_enabled;
  value.cid_profile_v2_config_id = ctx->cid_profile_v2_config_id;
  value.passive_affinity_enabled = ctx->passive_affinity_enabled;
  value.passive_min_confidence = ctx->passive_min_confidence;
  value.fallback_mode = ctx->fallback_mode;
  memcpy(value.cid_profile_key,
         ctx->cid_profile_key,
         sizeof(value.cid_profile_key));
  value.fallback_worker_id = ctx->fallback_worker_id;

  uint32_t key = 0;
  return bpf_map_update_elem(ctx->config_map_fd, &key, &value, BPF_ANY);
}

static int qaff_validate_context_maps(const struct qaff_context *ctx) {
  if (qaff_validate_map_fd(ctx->cid_map_fd,
                           BPF_MAP_TYPE_HASH,
                           sizeof(struct qaff_cid_key),
                           sizeof(struct qaff_cid_value),
                           1024 * 1024) != 0 ||
      qaff_validate_map_fd(ctx->passive_cid_map_fd,
                           BPF_MAP_TYPE_LRU_HASH,
                           sizeof(struct qaff_cid_key),
                           sizeof(struct qaff_passive_cid_value),
                           1024 * 1024) != 0 ||
      qaff_validate_map_fd(ctx->worker_sock_map_fd,
                           BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
                           sizeof(uint32_t),
                           sizeof(uint32_t),
                           QAFF_WORKER_CAPACITY) != 0 ||
      qaff_validate_map_fd(ctx->socket_worker_map_fd,
                           BPF_MAP_TYPE_HASH,
                           sizeof(uint64_t),
                           sizeof(uint32_t),
                           QAFF_WORKER_CAPACITY) != 0 ||
      qaff_validate_map_fd(ctx->worker_generation_map_fd,
                           BPF_MAP_TYPE_ARRAY,
                           sizeof(uint32_t),
                           sizeof(uint32_t),
                           QAFF_WORKER_CAPACITY) != 0 ||
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
  int mutex_rc = pthread_mutex_init(&ctx->mutation_lock, NULL);
  if (mutex_rc != 0) {
    free(ctx);
    errno = mutex_rc;
    return -1;
  }
  ctx->mutation_lock_initialized = 1;

  struct qaff_options defaults;
  if (options == NULL) {
    qaff_options_init(&defaults);
    options = &defaults;
  }

  ctx->cid_map_fd = options->cid_map_fd;
  ctx->passive_cid_map_fd = options->passive_cid_map_fd;
  ctx->worker_sock_map_fd = options->worker_sock_map_fd;
  ctx->socket_worker_map_fd = options->socket_worker_map_fd;
  ctx->worker_generation_map_fd = options->worker_generation_map_fd;
  ctx->stats_map_fd = options->stats_map_fd;
  ctx->config_map_fd = options->config_map_fd;
  ctx->pin_root = options->pin_root;
  ctx->short_cid_len = options->short_cid_len;
  ctx->cid_profile_v2_enabled = options->cid_profile_v2_enabled;
  ctx->cid_profile_v2_config_id = options->cid_profile_v2_config_id;
  ctx->passive_affinity_enabled = options->passive_affinity_enabled;
  ctx->passive_min_confidence = options->passive_min_confidence;
  ctx->fallback_mode = options->fallback_mode;
  if (ctx->fallback_mode != QAFF_FALLBACK_MODE_FIXED &&
      ctx->fallback_mode != QAFF_FALLBACK_MODE_KERNEL) {
    errno = EINVAL;
    goto fail;
  }
  if (ctx->cid_profile_v2_enabled &&
      ctx->short_cid_len != QAFF_CID_PROFILE_V2_LEN) {
    errno = EINVAL;
    goto fail;
  }
  if (options->fallback_worker_id >= QAFF_WORKER_CAPACITY) {
    errno = EINVAL;
    goto fail;
  }
  if (ctx->passive_min_confidence == 0) {
    ctx->passive_min_confidence = QAFF_PASSIVE_CONFIDENCE_HIGH;
  }
  if (ctx->passive_affinity_enabled &&
      (ctx->passive_min_confidence < QAFF_PASSIVE_CONFIDENCE_LOW ||
       ctx->passive_min_confidence > QAFF_PASSIVE_CONFIDENCE_HIGH)) {
    errno = EINVAL;
    goto fail;
  }
  memcpy(ctx->cid_profile_key,
         options->cid_profile_key,
         sizeof(ctx->cid_profile_key));
  ctx->fallback_worker_id = options->fallback_worker_id;

  if (ctx->cid_map_fd < 0) {
    ctx->cid_map_fd = qaff_get_pinned_map(ctx->pin_root, "qaff_cids");
    if (ctx->cid_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->cid_map_fd < 0) {
      ctx->cid_map_fd = qaff_create_hash_map("qaff_cids",
                                             sizeof(struct qaff_cid_key),
                                             sizeof(struct qaff_cid_value),
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
                             sizeof(struct qaff_cid_value),
                             1024 * 1024) != 0) {
      goto fail;
    }
    ctx->owns_cid_map = 1;
  }

  if (ctx->passive_cid_map_fd < 0) {
    ctx->passive_cid_map_fd = qaff_get_pinned_map(ctx->pin_root,
                                                  "qaff_passive_cids");
    if (ctx->passive_cid_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->passive_cid_map_fd < 0) {
      ctx->passive_cid_map_fd =
          qaff_create_lru_hash_map("qaff_passive_cids",
                                   sizeof(struct qaff_cid_key),
                                   sizeof(struct qaff_passive_cid_value),
                                   1024 * 1024);
    }
    if (ctx->passive_cid_map_fd < 0) {
      goto fail;
    }
    ctx->passive_cid_map_fd =
        qaff_open_or_pin_map(ctx->pin_root,
                             "qaff_passive_cids",
                             ctx->passive_cid_map_fd);
    if (ctx->passive_cid_map_fd < 0) {
      goto fail;
    }
    if (qaff_validate_map_fd(ctx->passive_cid_map_fd,
                             BPF_MAP_TYPE_LRU_HASH,
                             sizeof(struct qaff_cid_key),
                             sizeof(struct qaff_passive_cid_value),
                             1024 * 1024) != 0) {
      goto fail;
    }
    ctx->owns_passive_cid_map = 1;
  }

  if (ctx->worker_sock_map_fd < 0) {
    ctx->worker_sock_map_fd = qaff_get_pinned_map(ctx->pin_root,
                                                  "qaff_workers");
    if (ctx->worker_sock_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->worker_sock_map_fd < 0) {
      ctx->worker_sock_map_fd =
          qaff_create_sockhash_map("qaff_workers", QAFF_WORKER_CAPACITY);
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
                             QAFF_WORKER_CAPACITY) != 0) {
      goto fail;
    }
    ctx->owns_worker_sock_map = 1;
  }

  if (ctx->socket_worker_map_fd < 0) {
    ctx->socket_worker_map_fd = qaff_get_pinned_map(ctx->pin_root,
                                                    "qaff_socket_workers");
    if (ctx->socket_worker_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->socket_worker_map_fd < 0) {
      ctx->socket_worker_map_fd = qaff_create_hash_map("qaff_socket_workers",
                                                       sizeof(uint64_t),
                                                       sizeof(uint32_t),
                                                       QAFF_WORKER_CAPACITY);
    }
    if (ctx->socket_worker_map_fd < 0) {
      goto fail;
    }
    ctx->socket_worker_map_fd =
        qaff_open_or_pin_map(ctx->pin_root,
                             "qaff_socket_workers",
                             ctx->socket_worker_map_fd);
    if (ctx->socket_worker_map_fd < 0) {
      goto fail;
    }
    if (qaff_validate_map_fd(ctx->socket_worker_map_fd,
                             BPF_MAP_TYPE_HASH,
                             sizeof(uint64_t),
                             sizeof(uint32_t),
                             QAFF_WORKER_CAPACITY) != 0) {
      goto fail;
    }
    ctx->owns_socket_worker_map = 1;
  }

  if (ctx->worker_generation_map_fd < 0) {
    ctx->worker_generation_map_fd = qaff_get_pinned_map(ctx->pin_root,
                                                        "qaff_worker_generations");
    if (ctx->worker_generation_map_fd < 0 && errno != ENOENT) {
      goto fail;
    }
    if (ctx->worker_generation_map_fd < 0) {
      ctx->worker_generation_map_fd =
          qaff_create_generation_map("qaff_worker_generations",
                                     QAFF_WORKER_CAPACITY);
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
                             QAFF_WORKER_CAPACITY) != 0) {
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
  if (ctx->owns_passive_cid_map && ctx->passive_cid_map_fd >= 0) {
    close(ctx->passive_cid_map_fd);
  }
  if (ctx->owns_worker_sock_map && ctx->worker_sock_map_fd >= 0) {
    close(ctx->worker_sock_map_fd);
  }
  if (ctx->owns_socket_worker_map && ctx->socket_worker_map_fd >= 0) {
    close(ctx->socket_worker_map_fd);
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
  if (ctx->mutation_lock_initialized) {
    (void)pthread_mutex_destroy(&ctx->mutation_lock);
  }
  free(ctx);
}

static int qaff_worker_generation(const struct qaff_context *ctx,
                                  uint32_t worker_id,
                                  uint32_t *generation) {
  if (ctx == NULL || generation == NULL ||
      ctx->worker_generation_map_fd < 0 ||
      worker_id >= QAFF_WORKER_CAPACITY) {
    errno = EINVAL;
    return -1;
  }
  if (bpf_map_lookup_elem(ctx->worker_generation_map_fd,
                          &worker_id,
                          generation) != 0) {
    return -1;
  }
  if (*generation == 0) {
    errno = ENOENT;
    return -1;
  }
  return 0;
}

static int qaff_worker_generation_matches(const struct qaff_context *ctx,
                                          uint32_t worker_id,
                                          uint32_t expected_generation) {
  uint32_t live_generation = 0;
  if (qaff_worker_generation(ctx, worker_id, &live_generation) != 0) {
    return -1;
  }
  if (live_generation != expected_generation) {
    errno = ESTALE;
    return -1;
  }
  return 0;
}

int qaff_register_cid(struct qaff_context *ctx,
                      const uint8_t *cid,
                      size_t cid_len,
                      uint32_t worker_id) {
  if (ctx == NULL || ctx->cid_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }
  if (qaff_lock_mutations(ctx) != 0) {
    return -1;
  }

  uint32_t generation = 0;
  if (qaff_worker_generation(ctx, worker_id, &generation) != 0) {
    qaff_unlock_mutations(ctx);
    return -1;
  }

  struct qaff_cid_key key;
  int rc = qaff_cid_key_from_bytes(cid, cid_len, &key);
  if (rc != QAFF_PARSE_OK) {
    errno = EINVAL;
    qaff_unlock_mutations(ctx);
    return -1;
  }

  /*
   * CID ownership is immutable until the CID is explicitly retired. Using
   * BPF_NOEXIST makes that invariant atomic even when multiple callers share
   * a context or pinned map. Re-registering a CID for its current owner is
   * idempotent; assigning it to another worker is rejected.
   */
  struct qaff_cid_value value = {
      .worker_id = worker_id,
      .worker_generation = generation,
  };
  if (bpf_map_update_elem(ctx->cid_map_fd,
                          &key,
                          &value,
                          BPF_NOEXIST) == 0) {
    if (qaff_worker_generation_matches(ctx, worker_id, generation) != 0) {
      qaff_unlock_mutations(ctx);
      return -1;
    }
    qaff_unlock_mutations(ctx);
    return 0;
  }
  if (errno != EEXIST) {
    qaff_unlock_mutations(ctx);
    return -1;
  }

  struct qaff_cid_value existing;
  if (bpf_map_lookup_elem(ctx->cid_map_fd, &key, &existing) != 0) {
    qaff_unlock_mutations(ctx);
    return -1;
  }
  if (existing.worker_id == worker_id &&
      existing.worker_generation == generation) {
    if (qaff_worker_generation_matches(ctx, worker_id, generation) != 0) {
      qaff_unlock_mutations(ctx);
      return -1;
    }
    qaff_unlock_mutations(ctx);
    return 0;
  }
  errno = EEXIST;
  qaff_unlock_mutations(ctx);
  return -1;
}

int qaff_retire_cid(struct qaff_context *ctx,
                    const uint8_t *cid,
                    size_t cid_len) {
  if (ctx == NULL || ctx->cid_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }
  if (qaff_lock_mutations(ctx) != 0) {
    return -1;
  }

  struct qaff_cid_key key;
  int rc = qaff_cid_key_from_bytes(cid, cid_len, &key);
  if (rc != QAFF_PARSE_OK) {
    errno = EINVAL;
    qaff_unlock_mutations(ctx);
    return -1;
  }

  rc = bpf_map_delete_elem(ctx->cid_map_fd, &key);
  qaff_unlock_mutations(ctx);
  return rc;
}

int qaff_register_passive_cid(struct qaff_context *ctx,
                              const uint8_t *cid,
                              size_t cid_len,
                              const struct qaff_passive_cid_value *value) {
  if (ctx == NULL || ctx->passive_cid_map_fd < 0 || value == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (value->confidence < QAFF_PASSIVE_CONFIDENCE_LOW ||
      value->confidence > QAFF_PASSIVE_CONFIDENCE_HIGH) {
    errno = EINVAL;
    return -1;
  }
  if (value->source != QAFF_PASSIVE_SOURCE_INGRESS &&
      value->source != QAFF_PASSIVE_SOURCE_EGRESS) {
    errno = EINVAL;
    return -1;
  }
  if (value->flags != 0) {
    errno = EINVAL;
    return -1;
  }
  if (qaff_lock_mutations(ctx) != 0) {
    return -1;
  }

  uint32_t generation = 0;
  if (qaff_worker_generation(ctx, value->worker_id, &generation) != 0) {
    qaff_unlock_mutations(ctx);
    return -1;
  }
  if (value->worker_generation != 0 &&
      value->worker_generation != generation) {
    errno = EINVAL;
    qaff_unlock_mutations(ctx);
    return -1;
  }

  struct qaff_cid_key key;
  int rc = qaff_cid_key_from_bytes(cid, cid_len, &key);
  if (rc != QAFF_PARSE_OK) {
    errno = EINVAL;
    qaff_unlock_mutations(ctx);
    return -1;
  }

  struct qaff_passive_cid_value stored = *value;
  stored.worker_generation = generation;
  rc = bpf_map_update_elem(ctx->passive_cid_map_fd, &key, &stored, BPF_ANY);
  if (rc == 0 &&
      qaff_worker_generation_matches(ctx,
                                     stored.worker_id,
                                     stored.worker_generation) != 0) {
    rc = -1;
  }
  qaff_unlock_mutations(ctx);
  return rc;
}

int qaff_retire_passive_cid(struct qaff_context *ctx,
                            const uint8_t *cid,
                            size_t cid_len) {
  if (ctx == NULL || ctx->passive_cid_map_fd < 0) {
    errno = EINVAL;
    return -1;
  }
  if (qaff_lock_mutations(ctx) != 0) {
    return -1;
  }

  struct qaff_cid_key key;
  int rc = qaff_cid_key_from_bytes(cid, cid_len, &key);
  if (rc != QAFF_PARSE_OK) {
    errno = EINVAL;
    qaff_unlock_mutations(ctx);
    return -1;
  }

  rc = bpf_map_delete_elem(ctx->passive_cid_map_fd, &key);
  qaff_unlock_mutations(ctx);
  return rc;
}

int qaff_register_worker_socket(struct qaff_context *ctx,
                                uint32_t worker_id,
                                int socket_fd) {
  return qaff_register_worker_socket_generation(ctx,
                                                worker_id,
                                                socket_fd,
                                                QAFF_WORKER_GENERATION_DEFAULT);
}

static int qaff_find_worker_socket_cookie(struct qaff_context *ctx,
                                          uint32_t worker_id,
                                          uint64_t *cookie_out,
                                          int *found_out) {
  *cookie_out = 0;
  *found_out = 0;

  struct bpf_map_info info;
  memset(&info, 0, sizeof(info));
  uint32_t info_len = sizeof(info);
  if (bpf_obj_get_info_by_fd(ctx->socket_worker_map_fd,
                             &info,
                             &info_len) != 0) {
    return -1;
  }

  uint64_t current = 0;
  if (bpf_map_get_next_key(ctx->socket_worker_map_fd, NULL, &current) != 0) {
    return errno == ENOENT ? 0 : -1;
  }
  for (uint32_t inspected = 0; inspected < info.max_entries; inspected++) {
    uint32_t mapped_worker_id = UINT32_MAX;
    int lookup_rc = bpf_map_lookup_elem(ctx->socket_worker_map_fd,
                                        &current,
                                        &mapped_worker_id);
    if (lookup_rc == 0) {
      if (mapped_worker_id == worker_id) {
        *cookie_out = current;
        *found_out = 1;
        return 0;
      }
    } else if (errno != ENOENT) {
      return -1;
    }

    uint64_t next = 0;
    if (bpf_map_get_next_key(ctx->socket_worker_map_fd,
                             &current,
                             &next) != 0) {
      return errno == ENOENT ? 0 : -1;
    }
    current = next;
  }
  errno = EAGAIN;
  return -1;
}

static int qaff_register_worker_socket_generation_locked(
    struct qaff_context *ctx,
    uint32_t worker_id,
    int socket_fd,
    uint32_t generation) {
  if (ctx == NULL || ctx->worker_sock_map_fd < 0 ||
      ctx->socket_worker_map_fd < 0 || socket_fd < 0 ||
      worker_id >= QAFF_WORKER_CAPACITY) {
    errno = EINVAL;
    return -1;
  }
  if (generation == 0 || generation > QAFF_WORKER_GENERATION_MAX) {
    errno = EINVAL;
    return -1;
  }

  uint64_t socket_cookie = 0;
  socklen_t cookie_len = sizeof(socket_cookie);
  if (getsockopt(socket_fd,
                 SOL_SOCKET,
                 SO_COOKIE,
                 &socket_cookie,
                 &cookie_len) != 0) {
    return -1;
  }
  if (cookie_len != sizeof(socket_cookie) || socket_cookie == 0) {
    errno = EINVAL;
    return -1;
  }

  uint32_t cookie_owner = UINT32_MAX;
  if (bpf_map_lookup_elem(ctx->socket_worker_map_fd,
                          &socket_cookie,
                          &cookie_owner) == 0) {
    if (cookie_owner != worker_id) {
      errno = EEXIST;
      return -1;
    }
  } else if (errno != ENOENT) {
    return -1;
  }

  uint32_t existing_generation = 0;
  if (bpf_map_lookup_elem(ctx->worker_generation_map_fd,
                          &worker_id,
                          &existing_generation) != 0) {
    return -1;
  }
  if (existing_generation != 0) {
    if (generation < existing_generation) {
      errno = EINVAL;
      return -1;
    }
    uint64_t existing_cookie = 0;
    int found_existing_cookie = 0;
    if (qaff_find_worker_socket_cookie(ctx,
                                       worker_id,
                                       &existing_cookie,
                                       &found_existing_cookie) != 0) {
      return -1;
    }
    if (!found_existing_cookie || existing_cookie != socket_cookie) {
      errno = EBUSY;
      return -1;
    }
  }

  int cookie_inserted = 0;
  if (bpf_map_update_elem(ctx->socket_worker_map_fd,
                          &socket_cookie,
                          &worker_id,
                          BPF_NOEXIST) == 0) {
    cookie_inserted = 1;
  } else if (errno == EEXIST) {
    uint32_t existing_worker_id = 0;
    if (bpf_map_lookup_elem(ctx->socket_worker_map_fd,
                            &socket_cookie,
                            &existing_worker_id) != 0) {
      return -1;
    }
    if (existing_worker_id != worker_id) {
      errno = EEXIST;
      return -1;
    }
  } else {
    return -1;
  }

  if (bpf_map_update_elem(ctx->worker_sock_map_fd,
                          &worker_id,
                          &socket_fd,
                          BPF_ANY) != 0) {
    int saved_errno = errno;
    if (cookie_inserted) {
      bpf_map_delete_elem(ctx->socket_worker_map_fd, &socket_cookie);
    }
    errno = saved_errno;
    return -1;
  }

  if (ctx->worker_generation_map_fd >= 0 &&
      bpf_map_update_elem(ctx->worker_generation_map_fd,
                          &worker_id,
                          &generation,
                          BPF_ANY) != 0) {
    int saved_errno = errno ? errno : EIO;
    if (existing_generation == 0) {
      bpf_map_delete_elem(ctx->worker_sock_map_fd, &worker_id);
    }
    if (cookie_inserted) {
      bpf_map_delete_elem(ctx->socket_worker_map_fd, &socket_cookie);
    }
    errno = saved_errno;
    return -1;
  }

  return 0;
}

int qaff_register_worker_socket_generation(struct qaff_context *ctx,
                                           uint32_t worker_id,
                                           int socket_fd,
                                           uint32_t generation) {
  if (ctx == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (qaff_lock_mutations(ctx) != 0) {
    return -1;
  }
  int rc = qaff_register_worker_socket_generation_locked(ctx,
                                                          worker_id,
                                                          socket_fd,
                                                          generation);
  qaff_unlock_mutations(ctx);
  return rc;
}

static int qaff_delete_exact_worker_routes(struct qaff_context *ctx,
                                           uint32_t worker_id) {
  struct bpf_map_info info;
  memset(&info, 0, sizeof(info));
  uint32_t info_len = sizeof(info);
  if (bpf_obj_get_info_by_fd(ctx->cid_map_fd, &info, &info_len) != 0) {
    return -1;
  }

  struct qaff_cid_key current;
  if (bpf_map_get_next_key(ctx->cid_map_fd, NULL, &current) != 0) {
    return errno == ENOENT ? 0 : -1;
  }
  for (uint32_t inspected = 0; inspected < info.max_entries; inspected++) {
    struct qaff_cid_key next;
    int has_next = bpf_map_get_next_key(ctx->cid_map_fd, &current, &next) == 0;
    if (!has_next && errno != ENOENT) {
      return -1;
    }

    struct qaff_cid_value value;
    if (bpf_map_lookup_elem(ctx->cid_map_fd, &current, &value) == 0) {
      if (value.worker_id == worker_id &&
          bpf_map_delete_elem(ctx->cid_map_fd, &current) != 0 &&
          errno != ENOENT) {
        return -1;
      }
    } else if (errno != ENOENT) {
      return -1;
    }

    if (!has_next) {
      return 0;
    }
    current = next;
  }
  errno = EAGAIN;
  return -1;
}

static int qaff_delete_passive_worker_routes(struct qaff_context *ctx,
                                             uint32_t worker_id) {
  struct bpf_map_info info;
  memset(&info, 0, sizeof(info));
  uint32_t info_len = sizeof(info);
  if (bpf_obj_get_info_by_fd(ctx->passive_cid_map_fd,
                             &info,
                             &info_len) != 0) {
    return -1;
  }

  struct qaff_cid_key current;
  if (bpf_map_get_next_key(ctx->passive_cid_map_fd, NULL, &current) != 0) {
    return errno == ENOENT ? 0 : -1;
  }
  for (uint32_t inspected = 0; inspected < info.max_entries; inspected++) {
    struct qaff_cid_key next;
    int has_next =
        bpf_map_get_next_key(ctx->passive_cid_map_fd, &current, &next) == 0;
    if (!has_next && errno != ENOENT) {
      return -1;
    }

    struct qaff_passive_cid_value value;
    if (bpf_map_lookup_elem(ctx->passive_cid_map_fd, &current, &value) == 0) {
      if (value.worker_id == worker_id &&
          bpf_map_delete_elem(ctx->passive_cid_map_fd, &current) != 0 &&
          errno != ENOENT) {
        return -1;
      }
    } else if (errno != ENOENT) {
      return -1;
    }

    if (!has_next) {
      return 0;
    }
    current = next;
  }
  errno = EAGAIN;
  return -1;
}

int qaff_unregister_worker_socket_only(struct qaff_context *ctx,
                                       uint32_t worker_id) {
  if (ctx == NULL || ctx->worker_sock_map_fd < 0 ||
      ctx->socket_worker_map_fd < 0 ||
      worker_id >= QAFF_WORKER_CAPACITY) {
    errno = EINVAL;
    return -1;
  }

  if (ctx->worker_generation_map_fd >= 0) {
    uint32_t zero = 0;
    if (bpf_map_update_elem(ctx->worker_generation_map_fd,
                            &worker_id,
                            &zero,
                            BPF_ANY) != 0) {
      return -1;
    }
  }

  int rc = bpf_map_delete_elem(ctx->worker_sock_map_fd, &worker_id);
  int saved_errno = errno;

  uint64_t cookie = 0;
  int next_rc =
      bpf_map_get_next_key(ctx->socket_worker_map_fd, NULL, &cookie);
  while (next_rc == 0) {
    uint64_t next_cookie = 0;
    next_rc = bpf_map_get_next_key(ctx->socket_worker_map_fd,
                                   &cookie,
                                   &next_cookie);
    if (next_rc != 0 && errno != ENOENT) {
      return -1;
    }

    uint32_t mapped_worker_id = UINT32_MAX;
    if (bpf_map_lookup_elem(ctx->socket_worker_map_fd,
                            &cookie,
                            &mapped_worker_id) != 0) {
      if (errno != ENOENT) {
        return -1;
      }
    } else if (mapped_worker_id == worker_id &&
               bpf_map_delete_elem(ctx->socket_worker_map_fd, &cookie) != 0 &&
               errno != ENOENT) {
      return -1;
    }
    if (next_rc != 0) {
      break;
    }
    cookie = next_cookie;
  }
  if (next_rc != 0 && errno != ENOENT) {
    return -1;
  }
  if (rc != 0) {
    errno = saved_errno;
  }
  return rc;
}

int qaff_unregister_worker_socket(struct qaff_context *ctx,
                                  uint32_t worker_id) {
  if (ctx == NULL || worker_id >= QAFF_WORKER_CAPACITY) {
    errno = EINVAL;
    return -1;
  }
  if (qaff_lock_mutations(ctx) != 0) {
    return -1;
  }

  uint32_t generation = 0;
  if (bpf_map_lookup_elem(ctx->worker_generation_map_fd,
                          &worker_id,
                          &generation) != 0) {
    qaff_unlock_mutations(ctx);
    return -1;
  }
  if (generation == 0) {
    uint64_t cookie = 0;
    int found_cookie = 0;
    if (qaff_find_worker_socket_cookie(ctx,
                                       worker_id,
                                       &cookie,
                                       &found_cookie) != 0) {
      qaff_unlock_mutations(ctx);
      return -1;
    }
    if (!found_cookie) {
      errno = ENOENT;
      qaff_unlock_mutations(ctx);
      return -1;
    }
  }

  uint32_t zero = 0;
  if (bpf_map_update_elem(ctx->worker_generation_map_fd,
                          &worker_id,
                          &zero,
                          BPF_ANY) != 0 ||
      qaff_delete_exact_worker_routes(ctx, worker_id) != 0 ||
      qaff_delete_passive_worker_routes(ctx, worker_id) != 0) {
    qaff_unlock_mutations(ctx);
    return -1;
  }

  int rc = qaff_unregister_worker_socket_only(ctx, worker_id);
  if (rc != 0 && errno == ENOENT) {
    rc = 0;
  }
  qaff_unlock_mutations(ctx);
  return rc;
}

int qaff_get_cid_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->cid_map_fd : -1;
}

int qaff_get_passive_cid_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->passive_cid_map_fd : -1;
}

int qaff_get_worker_sock_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->worker_sock_map_fd : -1;
}

int qaff_get_socket_worker_map_fd(const struct qaff_context *ctx) {
  return ctx ? ctx->socket_worker_map_fd : -1;
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
  case QAFF_STAT_PASSIVE_HIT:
    return "passive_hit";
  case QAFF_STAT_PASSIVE_MISS:
    return "passive_miss";
  case QAFF_STAT_PASSIVE_REJECT_CONFIDENCE:
    return "passive_reject_confidence";
  case QAFF_STAT_PASSIVE_REJECT_GENERATION:
    return "passive_reject_generation";
  case QAFF_STAT_PASSIVE_EGRESS_LEARN:
    return "passive_egress_learn";
  case QAFF_STAT_PASSIVE_EGRESS_NO_WORKER:
    return "passive_egress_no_worker";
  case QAFF_STAT_PASSIVE_REJECT_EXPIRED:
    return "passive_reject_expired";
  case QAFF_STAT_PASSIVE_EGRESS_PARSE_MISS:
    return "passive_egress_parse_miss";
  case QAFF_STAT_PASSIVE_EGRESS_NOT_UDP:
    return "passive_egress_not_udp";
  case QAFF_STAT_PASSIVE_EGRESS_ZERO_LENGTH_SCID:
    return "passive_egress_zero_length_scid";
  case QAFF_STAT_PASSIVE_EGRESS_TOO_LONG_SCID:
    return "passive_egress_too_long_scid";
  case QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_HIT:
    return "passive_egress_socket_cookie_hit";
  case QAFF_STAT_PASSIVE_EGRESS_SOCKET_COOKIE_MISS:
    return "passive_egress_socket_cookie_miss";
  case QAFF_STAT_PASSIVE_EGRESS_MAP_UPDATE_ERROR:
    return "passive_egress_map_update_error";
  case QAFF_STAT_CID_MAP_REJECT_GENERATION:
    return "cid_map_reject_generation";
  default:
    return "unknown";
  }
}
