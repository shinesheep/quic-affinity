#ifndef QAFF_CONTROL_PROTOCOL_H
#define QAFF_CONTROL_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "quic_affinity/control.h"

#define QAFF_CONTROL_MAGIC 0x51414646u
#define QAFF_CONTROL_SCHEMA 1u
#define QAFF_CONTROL_HEADER_SIZE 16u
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
 * Decoded, process-local representation. Its layout is deliberately unrelated
 * to the wire format: control_protocol.c explicitly encodes every field.
 */
struct qaff_control_msg {
  uint16_t op;
  int32_t status;
  uint32_t worker_id;
  uint32_t generation;
  uint64_t cid_profile_key_fingerprint;
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

int qaff_control_encode_request(const struct qaff_control_msg *msg,
                                uint8_t *packet, size_t packet_cap,
                                size_t *packet_len);
int qaff_control_decode_request(const uint8_t *packet, size_t packet_len,
                                struct qaff_control_msg *msg);
int qaff_control_encode_reply(const struct qaff_control_msg *msg,
                              uint8_t *packet, size_t packet_cap,
                              size_t *packet_len);
int qaff_control_decode_reply(const uint8_t *packet, size_t packet_len,
                              struct qaff_control_msg *msg);

#endif
