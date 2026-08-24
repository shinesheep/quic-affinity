#ifndef QUIC_AFFINITY_INTERNAL_H
#define QUIC_AFFINITY_INTERNAL_H

#include <stdint.h>

struct qaff_context;

int qaff_get_cid_map_fd(const struct qaff_context *ctx);
int qaff_get_passive_cid_map_fd(const struct qaff_context *ctx);
int qaff_get_worker_sock_map_fd(const struct qaff_context *ctx);
int qaff_get_socket_worker_map_fd(const struct qaff_context *ctx);
int qaff_get_worker_generation_map_fd(const struct qaff_context *ctx);
int qaff_get_stats_map_fd(const struct qaff_context *ctx);
int qaff_get_config_map_fd(const struct qaff_context *ctx);

/*
 * Remove only worker-map state. qaffd owns CID cleanup and uses this helper
 * for rollback and crash recovery; embedded callers must use the public
 * qaff_unregister_worker_socket(), which also retires worker-owned routes.
 */
int qaff_unregister_worker_socket_only(struct qaff_context *ctx,
                                       uint32_t worker_id);

#endif
