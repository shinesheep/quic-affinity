#ifndef QUIC_AFFINITY_CONTROL_H
#define QUIC_AFFINITY_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/quic_affinity.h"
#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Magic value used on the qaffd Unix-socket control protocol. */
#define QAFF_CONTROL_MAGIC 0x51414646u

/** Current qaffd control protocol version. */
#define QAFF_CONTROL_VERSION 1u

/** Maximum workers returned by one control-plane list request. */
#define QAFF_CONTROL_MAX_WORKERS 64u

/** Maximum path bytes carried in control-plane config replies. */
#define QAFF_CONTROL_MAX_PATH 256u

/** Worker is tied to the lifetime of its registering control connection. */
#define QAFF_CONTROL_WORKER_FLAG_LEASED 0x1u

/** qaffd recorded Unix peer credentials for the registering process. */
#define QAFF_CONTROL_WORKER_FLAG_CRED 0x2u

/** qaffd is monitoring the registering process with pidfd. */
#define QAFF_CONTROL_WORKER_FLAG_PIDFD 0x4u

/** Control operations accepted by qaffd. */
enum qaff_control_op {
  QAFF_CONTROL_REGISTER_WORKER = 1,
  QAFF_CONTROL_REGISTER_CID = 2,
  QAFF_CONTROL_RETIRE_CID = 3,
  QAFF_CONTROL_READ_STATS = 4,
  QAFF_CONTROL_STOP = 5,
  QAFF_CONTROL_HEALTH = 6,
  QAFF_CONTROL_CONFIG = 7,
  QAFF_CONTROL_WORKERS = 8,
  QAFF_CONTROL_UNREGISTER_WORKER = 9,
  QAFF_CONTROL_CIDS = 10,
  QAFF_CONTROL_REGISTER_WORKER_LEASE = 11,
  QAFF_CONTROL_WORKER_HEARTBEAT = 12,
};

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
  uint8_t reserved[1];
  /** Number of registered workers. */
  uint32_t worker_count;
  /** Worker used for parse misses, unknown CIDs, and client-generated Initials. */
  uint32_t fallback_worker_id;
  /** Number of exact CID entries in qaffd's ownership index. */
  uint64_t cid_map_count;
  /** Number of CID ownership entries tracked by qaffd. */
  uint64_t cid_owner_count;
  /** Number of detected differences between qaffd's CID index and BPF map. */
  uint64_t cid_index_mismatch;
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
  uint32_t reserved;
  /** Approximate age of this registration. */
  uint64_t registered_ms_ago;
  /** Approximate time since the last heartbeat or registration. */
  uint64_t last_seen_ms_ago;
};

/**
 * Wire message used by the qaffd control protocol.
 *
 * Applications normally call the helper functions below instead of sending this
 * structure directly. The layout is intentionally fixed-size to keep the
 * initial protocol simple.
 */
struct qaff_control_msg {
  uint32_t magic;
  uint16_t version;
  uint16_t op;
  int32_t status;
  uint32_t worker_id;
  uint32_t cid_len;
  uint8_t cid[QAFF_MAX_CID_LEN];
  struct qaff_stats stats;
  struct qaff_control_config config;
  uint32_t workers[QAFF_CONTROL_MAX_WORKERS];
  struct qaff_control_worker_info worker_infos[QAFF_CONTROL_MAX_WORKERS];
  uint32_t workers_len;
};

/**
 * Connect to a qaffd Unix domain control socket.
 *
 * Returns a connected fd on success or -1 with errno set. The caller owns the
 * returned fd.
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
 * workers_cap is smaller and only a prefix was copied.
 */
int qaff_control_workers(int control_fd,
                         uint32_t *workers,
                         size_t workers_cap,
                         size_t *workers_len);

/**
 * List registered workers with lifecycle metadata.
 *
 * workers_len receives the total number of workers known to qaffd, even if
 * workers_cap is smaller and only a prefix was copied.
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
