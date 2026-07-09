#include "quic_affinity/quic_affinity.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif

struct qaff_bpf_object {
  struct bpf_object *obj;
  int program_fd;
};

static int qaff_reuse_map(struct bpf_object *obj,
                          const char *name,
                          int fd,
                          int required) {
  struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
  if (map == NULL) {
    if (required) {
      errno = ENOENT;
      return -1;
    }
    return 0;
  }

  if (fd < 0) {
    errno = EINVAL;
    return -1;
  }

  return bpf_map__reuse_fd(map, fd);
}

int qaff_bpf_object_open(struct qaff_context *ctx,
                         const char *object_path,
                         struct qaff_bpf_object **out) {
  if (ctx == NULL || object_path == NULL || out == NULL) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_bpf_object *object = calloc(1, sizeof(*object));
  if (object == NULL) {
    return -1;
  }
  object->program_fd = -1;

  object->obj = bpf_object__open_file(object_path, NULL);
  if (object->obj == NULL) {
    goto fail;
  }

  if (qaff_reuse_map(object->obj, "qaff_cids", qaff_get_cid_map_fd(ctx), 1) != 0 ||
      qaff_reuse_map(object->obj, "qaff_workers", qaff_get_worker_sock_map_fd(ctx), 1) != 0 ||
      qaff_reuse_map(object->obj, "qaff_stats", qaff_get_stats_map_fd(ctx), 1) != 0 ||
      qaff_reuse_map(object->obj, "qaff_config", qaff_get_config_map_fd(ctx), 1) != 0) {
    goto fail;
  }

  if (bpf_object__load(object->obj) != 0) {
    goto fail;
  }

  struct bpf_program *program =
      bpf_object__find_program_by_name(object->obj, "qaff_select");
  if (program == NULL) {
    errno = ENOENT;
    goto fail;
  }

  object->program_fd = bpf_program__fd(program);
  if (object->program_fd < 0) {
    errno = ENOENT;
    goto fail;
  }

  *out = object;
  return 0;

fail:
  qaff_bpf_object_close(object);
  return -1;
}

void qaff_bpf_object_close(struct qaff_bpf_object *object) {
  if (object == NULL) {
    return;
  }
  if (object->obj != NULL) {
    bpf_object__close(object->obj);
  }
  free(object);
}

int qaff_bpf_program_fd(const struct qaff_bpf_object *object) {
  if (object == NULL) {
    return -1;
  }
  return object->program_fd;
}

int qaff_attach_reuseport_bpf(const struct qaff_bpf_object *object,
                              int socket_fd) {
  if (object == NULL || object->program_fd < 0 || socket_fd < 0) {
    errno = EINVAL;
    return -1;
  }

  return setsockopt(socket_fd,
                    SOL_SOCKET,
                    SO_ATTACH_REUSEPORT_EBPF,
                    &object->program_fd,
                    sizeof(object->program_fd));
}
