#ifndef QUIC_AFFINITY_QUIC_AFFINITY_H
#define QUIC_AFFINITY_QUIC_AFFINITY_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/quic_parser.h"
#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

struct qaff_context;
struct qaff_bpf_object;

struct qaff_options {
  int cid_map_fd;
  int worker_sock_map_fd;
  int stats_map_fd;
  int config_map_fd;
  uint8_t short_cid_len;
};

struct qaff_stats {
  uint64_t values[QAFF_STAT_MAX];
};

void qaff_options_init(struct qaff_options *options);

int qaff_open(const struct qaff_options *options, struct qaff_context **out);
void qaff_close(struct qaff_context *ctx);

int qaff_register_cid(struct qaff_context *ctx,
                      const uint8_t *cid,
                      size_t cid_len,
                      uint32_t worker_id);

int qaff_retire_cid(struct qaff_context *ctx,
                    const uint8_t *cid,
                    size_t cid_len);

int qaff_register_worker_socket(struct qaff_context *ctx,
                                uint32_t worker_id,
                                int socket_fd);

int qaff_get_cid_map_fd(const struct qaff_context *ctx);
int qaff_get_worker_sock_map_fd(const struct qaff_context *ctx);
int qaff_get_stats_map_fd(const struct qaff_context *ctx);
int qaff_get_config_map_fd(const struct qaff_context *ctx);

int qaff_read_stats(struct qaff_context *ctx, struct qaff_stats *out);
const char *qaff_stat_name(uint32_t index);

int qaff_bpf_object_open(struct qaff_context *ctx,
                         const char *object_path,
                         struct qaff_bpf_object **out);

void qaff_bpf_object_close(struct qaff_bpf_object *object);

int qaff_bpf_program_fd(const struct qaff_bpf_object *object);

int qaff_attach_reuseport_bpf(const struct qaff_bpf_object *object,
                              int socket_fd);

#ifdef __cplusplus
}
#endif

#endif
