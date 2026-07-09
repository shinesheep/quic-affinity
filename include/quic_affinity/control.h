#ifndef QUIC_AFFINITY_CONTROL_H
#define QUIC_AFFINITY_CONTROL_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/quic_affinity.h"
#include "quic_affinity/wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QAFF_CONTROL_MAGIC 0x51414646u
#define QAFF_CONTROL_VERSION 1u
#define QAFF_CONTROL_MAX_WORKERS 64u

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
};

struct qaff_control_config {
  uint8_t short_cid_len;
  uint8_t attached;
  uint16_t reserved;
  uint32_t worker_count;
  uint32_t fallback_worker_id;
};

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
  uint32_t workers_len;
};

int qaff_control_connect(const char *socket_path);

int qaff_control_register_worker(int control_fd,
                                 uint32_t worker_id,
                                 int socket_fd);

int qaff_control_unregister_worker(int control_fd, uint32_t worker_id);

int qaff_control_register_cid(int control_fd,
                              uint32_t worker_id,
                              const uint8_t *cid,
                              size_t cid_len);

int qaff_control_retire_cid(int control_fd,
                            const uint8_t *cid,
                            size_t cid_len);

int qaff_control_read_stats(int control_fd, struct qaff_stats *out);

int qaff_control_health(int control_fd);

int qaff_control_config(int control_fd, struct qaff_control_config *out);

int qaff_control_workers(int control_fd,
                         uint32_t *workers,
                         size_t workers_cap,
                         size_t *workers_len);

int qaff_control_stop(int control_fd);

#ifdef __cplusplus
}
#endif

#endif
