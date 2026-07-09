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

enum qaff_control_op {
  QAFF_CONTROL_REGISTER_WORKER = 1,
  QAFF_CONTROL_REGISTER_CID = 2,
  QAFF_CONTROL_RETIRE_CID = 3,
  QAFF_CONTROL_READ_STATS = 4,
  QAFF_CONTROL_STOP = 5,
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
};

int qaff_control_connect(const char *socket_path);

int qaff_control_register_worker(int control_fd,
                                 uint32_t worker_id,
                                 int socket_fd);

int qaff_control_register_cid(int control_fd,
                              uint32_t worker_id,
                              const uint8_t *cid,
                              size_t cid_len);

int qaff_control_retire_cid(int control_fd,
                            const uint8_t *cid,
                            size_t cid_len);

int qaff_control_read_stats(int control_fd, struct qaff_stats *out);

int qaff_control_stop(int control_fd);

#ifdef __cplusplus
}
#endif

#endif

