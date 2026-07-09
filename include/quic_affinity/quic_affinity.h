#ifndef QUIC_AFFINITY_QUIC_AFFINITY_H
#define QUIC_AFFINITY_QUIC_AFFINITY_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/quic_parser.h"
#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque libqaffinity context that owns or references BPF maps. */
struct qaff_context;

/** Opaque loaded eBPF object containing the reuseport selector program. */
struct qaff_bpf_object;

/**
 * Options for qaff_open().
 *
 * Initialize with qaff_options_init() before setting fields. File descriptor
 * fields may be set to existing BPF maps; values less than zero ask
 * libqaffinity to open or create the corresponding map. If pin_root is set,
 * maps are opened from or pinned under that bpffs directory.
 */
struct qaff_options {
  /** qaff_cids map fd, or -1 to open/create it. */
  int cid_map_fd;
  /** qaff_passive_cids map fd, or -1 to open/create it. */
  int passive_cid_map_fd;
  /** qaff_workers REUSEPORT_SOCKARRAY map fd, or -1 to open/create it. */
  int worker_sock_map_fd;
  /** qaff_worker_generations map fd, or -1 to open/create it. */
  int worker_generation_map_fd;
  /** qaff_stats map fd, or -1 to open/create it. */
  int stats_map_fd;
  /** qaff_config map fd, or -1 to open/create it. */
  int config_map_fd;
  /** Optional bpffs directory used for map pinning and restart recovery. */
  const char *pin_root;
  /** Fixed short-header DCID length used by the dataplane parser. */
  uint8_t short_cid_len;
  /** Enable routable CID profile v1 validation in the dataplane. */
  uint8_t cid_profile_v1_enabled;
  /** Enable routable CID profile v2 validation in the dataplane. */
  uint8_t cid_profile_v2_enabled;
  /** Expected v2 config ID. */
  uint8_t cid_profile_v2_config_id;
  /** Enable best-effort passive CID routing in the dataplane. */
  uint8_t passive_affinity_enabled;
  /** Minimum passive confidence accepted by the dataplane. */
  uint8_t passive_min_confidence;
  /** Listener-local key used by enabled routable CID profiles. */
  uint8_t cid_profile_v1_key[QAFF_CID_PROFILE_KEY_LEN];
  /** Worker ID used when parsing or CID lookup cannot select an owner. */
  uint32_t fallback_worker_id;
};

/** Snapshot of dataplane counters read from the qaff_stats map. */
struct qaff_stats {
  uint64_t values[QAFF_STAT_MAX];
};

/** Initialize options with defaults suitable for qaff_open(). */
void qaff_options_init(struct qaff_options *options);

/**
 * Open a libqaffinity context.
 *
 * The context validates map schemas, creates missing maps, optionally pins
 * them, and writes dataplane configuration. Existing map fds supplied in
 * options remain owned by the caller; internally opened/created fds are closed
 * by qaff_close().
 *
 * Returns 0 on success or -1 with errno set.
 */
int qaff_open(const struct qaff_options *options, struct qaff_context **out);

/** Close a context and release fds owned by libqaffinity. */
void qaff_close(struct qaff_context *ctx);

/**
 * Register a server-issued CID to a worker.
 *
 * Packets whose DCID exactly matches cid are routed to worker_id before
 * user-space receives them.
 *
 * Returns 0 on success or -1 with errno set.
 */
int qaff_register_cid(struct qaff_context *ctx,
                      const uint8_t *cid,
                      size_t cid_len,
                      uint32_t worker_id);

/** Remove a CID-to-worker mapping. Returns 0 on success or -1 with errno set. */
int qaff_retire_cid(struct qaff_context *ctx,
                    const uint8_t *cid,
                    size_t cid_len);

/**
 * Register a passive CID routing entry.
 *
 * Passive entries are best-effort black-box hints. Exact CID registrations and
 * routable profile validation take priority over this table in the dataplane.
 */
int qaff_register_passive_cid(struct qaff_context *ctx,
                              const uint8_t *cid,
                              size_t cid_len,
                              const struct qaff_passive_cid_value *value);

/** Remove a passive CID mapping. Returns 0 on success or -1 with errno set. */
int qaff_retire_passive_cid(struct qaff_context *ctx,
                            const uint8_t *cid,
                            size_t cid_len);

/**
 * Register a UDP worker socket with the default worker generation.
 *
 * The socket must be a member of the listener's SO_REUSEPORT group. The kernel
 * stores a reference to the socket in the REUSEPORT_SOCKARRAY map.
 */
int qaff_register_worker_socket(struct qaff_context *ctx,
                                uint32_t worker_id,
                                int socket_fd);

/**
 * Register a UDP worker socket with an explicit worker generation.
 *
 * Use this when routable CID profile v2 is enabled. Incrementing generation on
 * worker-ID reuse prevents stale profile CIDs from selecting a replacement
 * worker.
 *
 * Returns 0 on success or -1 with errno set.
 */
int qaff_register_worker_socket_generation(struct qaff_context *ctx,
                                           uint32_t worker_id,
                                           int socket_fd,
                                           uint32_t generation);

/**
 * Remove a worker socket and clear its generation entry.
 *
 * CIDs that still point at worker_id should be retired before or immediately
 * after unregistering the worker.
 */
int qaff_unregister_worker_socket(struct qaff_context *ctx,
                                  uint32_t worker_id);

/** Return the qaff_cids map fd, or -1 for a NULL context. */
int qaff_get_cid_map_fd(const struct qaff_context *ctx);

/** Return the qaff_passive_cids map fd, or -1 for a NULL context. */
int qaff_get_passive_cid_map_fd(const struct qaff_context *ctx);

/** Return the qaff_workers map fd, or -1 for a NULL context. */
int qaff_get_worker_sock_map_fd(const struct qaff_context *ctx);

/** Return the qaff_worker_generations map fd, or -1 for a NULL context. */
int qaff_get_worker_generation_map_fd(const struct qaff_context *ctx);

/** Return the qaff_stats map fd, or -1 for a NULL context. */
int qaff_get_stats_map_fd(const struct qaff_context *ctx);

/** Return the qaff_config map fd, or -1 for a NULL context. */
int qaff_get_config_map_fd(const struct qaff_context *ctx);

/** Read all dataplane counters. Returns 0 on success or -1 with errno set. */
int qaff_read_stats(struct qaff_context *ctx, struct qaff_stats *out);

/** Return a stable printable counter name for an index. */
const char *qaff_stat_name(uint32_t index);

/**
 * Open and load the reuseport eBPF object using maps from ctx.
 *
 * object_path should point to qaff_reuseport.bpf.o. The loader reuses the maps
 * owned by ctx before loading so user-space and BPF observe the same state.
 *
 * Returns 0 on success or -1 with errno set.
 */
int qaff_bpf_object_open(struct qaff_context *ctx,
                         const char *object_path,
                         struct qaff_bpf_object **out);

/** Close a loaded eBPF object. */
void qaff_bpf_object_close(struct qaff_bpf_object *object);

/** Return the loaded reuseport program fd, or -1 if unavailable. */
int qaff_bpf_program_fd(const struct qaff_bpf_object *object);

/**
 * Attach the loaded reuseport program to a SO_REUSEPORT UDP socket group.
 *
 * The attach is performed with SO_ATTACH_REUSEPORT_EBPF on socket_fd.
 * Returns 0 on success or -1 with errno set.
 */
int qaff_attach_reuseport_bpf(const struct qaff_bpf_object *object,
                              int socket_fd);

#ifdef __cplusplus
}
#endif

#endif
