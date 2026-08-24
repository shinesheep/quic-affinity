#ifndef QUIC_AFFINITY_INTERNAL_H
#define QUIC_AFFINITY_INTERNAL_H

#include <stdint.h>

struct qaff_context;

/*
 * Remove only worker-map state. qaffd owns CID cleanup and uses this helper
 * for rollback and crash recovery; embedded callers must use the public
 * qaff_unregister_worker_socket(), which also retires worker-owned routes.
 */
int qaff_unregister_worker_socket_only(struct qaff_context *ctx,
                                       uint32_t worker_id);

#endif
