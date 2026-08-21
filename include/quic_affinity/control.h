#ifndef QUIC_AFFINITY_CONTROL_H
#define QUIC_AFFINITY_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/quic_affinity.h"
#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of worker IDs supported by one qaffd listener. */
#define QAFF_CONTROL_WORKER_CAPACITY 4096u

/** Maximum path bytes carried in control-plane config replies. */
#define QAFF_CONTROL_MAX_PATH 256u

/** Worker is tied to the lifetime of its registering control connection. */
#define QAFF_CONTROL_WORKER_FLAG_LEASED 0x1u

/** qaffd recorded Unix peer credentials for the registering process. */
#define QAFF_CONTROL_WORKER_FLAG_CRED 0x2u

/** qaffd is monitoring the registering process with pidfd. */
#define QAFF_CONTROL_WORKER_FLAG_PIDFD 0x4u

/** qaffd listener configuration and CID-index health summary. */
struct qaff_control_config {
  /** Fixed short-header DCID length used by the dataplane parser. */
  uint8_t short_cid_len;
  /** Non-zero when the reuseport eBPF program has been attached. */
  uint8_t attached;
  /** Non-zero when profile v1 routing is enabled. */
  uint8_t cid_profile_v1_enabled;
  /** Non-zero when profile v2 routing is enabled. */
  uint8_t cid_profile_v2_enabled;
  /** Config ID expected for profile v2 CIDs. */
  uint8_t cid_profile_v2_config_id;
  /** Non-zero when passive CID routing is enabled. */
  uint8_t passive_affinity_enabled;
  /** Minimum passive confidence accepted by the dataplane. */
  uint8_t passive_min_confidence;
  /** Non-zero when the cgroup egress learner has been attached. */
  uint8_t egress_attached;
  /** Fallback policy: QAFF_FALLBACK_MODE_FIXED or _KERNEL. */
  uint8_t fallback_mode;
  uint8_t reserved[3];
  /** Number of registered workers. */
  uint32_t worker_count;
  /** Worker used for fallback when fallback_mode is FIXED. */
  uint32_t fallback_worker_id;
  /** Number of exact CID entries in qaffd's ownership index. */
  uint64_t cid_map_count;
  /** Number of CID ownership entries tracked by qaffd. */
  uint64_t cid_owner_count;
  /** Number of detected differences between qaffd's CID index and BPF map. */
  uint64_t cid_index_mismatch;
  /** Number of entries currently present in qaff_passive_cids. */
  uint64_t passive_entry_count;
  /** Maximum number of entries supported by qaff_passive_cids. */
  uint64_t passive_entry_capacity;
  /** Passive entries removed after their monotonic TTL elapsed. */
  uint64_t passive_expired_count;
  /** Passive entries removed because their worker was unregistered. */
  uint64_t passive_worker_purged_count;
  /** Legacy zero-expiry entries assigned a default lifetime during cleanup. */
  uint64_t passive_expiry_initialized_count;
  /** Passive map cleanup operations that failed. */
  uint64_t passive_cleanup_error_count;
  /** Interval between passive map cleanup scans. */
  uint64_t passive_scan_interval_ms;
  /** bpffs pin root, if configured. */
  char pin_root[QAFF_CONTROL_MAX_PATH];
  /** qaffd restart snapshot path, if configured. */
  char state_path[QAFF_CONTROL_MAX_PATH];
};

/** Information about one registered worker. */
struct qaff_control_worker_info {
  /** Worker ID used by the dataplane. */
  uint32_t worker_id;
  /** Bitwise OR of QAFF_CONTROL_WORKER_FLAG_* values. */
  uint32_t flags;
  /** Registering process ID when credentials were available. */
  uint32_t pid;
  /** Registering process UID when credentials were available. */
  uint32_t uid;
  /** Registering process GID when credentials were available. */
  uint32_t gid;
  /** Real application PID reported by a supervising agent, or zero. */
  uint32_t target_pid;
  /** Approximate age of this registration. */
  uint64_t registered_ms_ago;
  /** Approximate time since the last heartbeat or registration. */
  uint64_t last_seen_ms_ago;
};

/**
 * Connect to a qaffd Unix domain control socket.
 *
 * Returns a connected fd on success or -1 with errno set. The caller owns the
 * returned fd. Use the helpers in this header for all traffic on that fd; the
 * daemon transport format is a private implementation detail.
 */
int qaff_control_connect(const char *socket_path);

/**
 * Register a worker socket by passing socket_fd to qaffd with SCM_RIGHTS.
 *
 * This registration is not tied to the control connection lifetime. New
 * integrations should prefer qaff_control_register_worker_lease().
 */
int qaff_control_register_worker(int control_fd,
                                 uint32_t worker_id,
                                 int socket_fd);

/**
 * Register a leased worker socket.
 *
 * qaffd unregisters the worker if the control connection closes unexpectedly.
 * When supported by the kernel, qaffd also monitors the registering process
 * with pidfd.
 */
int qaff_control_register_worker_lease(int control_fd,
                                       uint32_t worker_id,
                                       int socket_fd);

/**
 * Register a leased worker on behalf of a supervised target PID.
 *
 * target_pid is diagnostic metadata; the registering process remains
 * responsible for monitoring that target and holding the control lease.
 */
int qaff_control_register_worker_lease_for_pid(int control_fd,
                                               uint32_t worker_id,
                                               int socket_fd,
                                               uint32_t target_pid);

/** Refresh liveness for a leased worker when qaffd heartbeat timeout is used. */
int qaff_control_worker_heartbeat(int control_fd, uint32_t worker_id);

/** Unregister a worker socket and retire CIDs owned by that worker. */
int qaff_control_unregister_worker(int control_fd, uint32_t worker_id);

/** Register a server-issued CID to the given worker through qaffd. */
int qaff_control_register_cid(int control_fd,
                              uint32_t worker_id,
                              const uint8_t *cid,
                              size_t cid_len);

/** Retire a previously registered CID through qaffd. */
int qaff_control_retire_cid(int control_fd,
                            const uint8_t *cid,
                            size_t cid_len);

/** Register a passive CID routing hint through qaffd. */
int qaff_control_register_passive_cid(
    int control_fd,
    const uint8_t *cid,
    size_t cid_len,
    const struct qaff_passive_cid_value *value);

/** Retire a passive CID routing hint through qaffd. */
int qaff_control_retire_passive_cid(int control_fd,
                                    const uint8_t *cid,
                                    size_t cid_len);

/** Read dataplane counters through qaffd. */
int qaff_control_read_stats(int control_fd, struct qaff_stats *out);

/** Check whether qaffd is reachable and healthy. */
int qaff_control_health(int control_fd);

/** Read listener configuration and CID-index health. */
int qaff_control_config(int control_fd, struct qaff_control_config *out);

/** Read CID counts and consistency status. */
int qaff_control_cids(int control_fd, struct qaff_control_config *out);

/**
 * List registered worker IDs.
 *
 * workers_len receives the total number of workers known to qaffd, even if
 * workers_cap is smaller and only a prefix was copied. The helper transparently
 * fetches multiple protocol pages when needed.
 */
int qaff_control_workers(int control_fd,
                         uint32_t *workers,
                         size_t workers_cap,
                         size_t *workers_len);

/**
 * List registered workers with lifecycle metadata.
 *
 * workers_len receives the total number of workers known to qaffd, even if
 * workers_cap is smaller and only a prefix was copied. The helper transparently
 * fetches multiple protocol pages when needed.
 */
int qaff_control_workers_info(int control_fd,
                              struct qaff_control_worker_info *workers,
                              size_t workers_cap,
                              size_t *workers_len);

/** Ask qaffd to stop; intended for tests and managed shutdown. */
int qaff_control_stop(int control_fd);

#ifdef __cplusplus
}
#endif

#endif
