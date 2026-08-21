#ifndef QAFF_CONTROL_PROTOCOL_H
#define QAFF_CONTROL_PROTOCOL_H

#include <stdint.h>

#include "quic_affinity/control.h"

#define QAFF_CONTROL_MAGIC 0x51414646u
#define QAFF_CONTROL_VERSION 3u
#define QAFF_CONTROL_PAGE_WORKERS 64u
#define QAFF_CONTROL_MAX_MESSAGE_SIZE 8192u

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
  QAFF_CONTROL_REGISTER_PASSIVE_CID = 13,
  QAFF_CONTROL_RETIRE_PASSIVE_CID = 14,
};

/*
 * Private local transport message shared by qaffd and libqaffinity. This is
 * intentionally not installed as public API. External integrations must use
 * the helpers in quic_affinity/control.h instead of depending on C ABI layout.
 */
struct qaff_control_msg {
  uint32_t magic;
  uint16_t version;
  uint16_t op;
  int32_t status;
  uint32_t worker_id;
  uint32_t target_pid;
  uint32_t cid_len;
  uint8_t cid[QAFF_MAX_CID_LEN];
  struct qaff_passive_cid_value passive_value;
  struct qaff_stats stats;
  struct qaff_control_config config;
  uint32_t workers[QAFF_CONTROL_PAGE_WORKERS];
  struct qaff_control_worker_info worker_infos[QAFF_CONTROL_PAGE_WORKERS];
  uint32_t workers_len;
};

_Static_assert(sizeof(struct qaff_control_msg) <= QAFF_CONTROL_MAX_MESSAGE_SIZE,
               "control message exceeds daemon pending-client budget");

#endif
