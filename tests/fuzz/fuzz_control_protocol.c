#include "control_protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint32_t input_hash(const uint8_t *data, size_t size) {
  uint32_t hash = UINT32_C(2166136261);
  for (size_t i = 0; i < size; i++) {
    hash ^= data[i];
    hash *= UINT32_C(16777619);
  }
  return hash;
}

static void verify_request_packet(const uint8_t *packet, size_t packet_len) {
  struct qaff_control_msg decoded;
  if (qaff_control_decode_request(packet, packet_len, &decoded) != 0) {
    return;
  }
  uint8_t encoded[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t encoded_len = 0;
  if (qaff_control_encode_request(&decoded, encoded, sizeof(encoded),
                                  &encoded_len) != 0 ||
      encoded_len != packet_len || memcmp(encoded, packet, packet_len) != 0) {
    abort();
  }
  struct qaff_control_msg round_trip;
  if (qaff_control_decode_request(encoded, encoded_len, &round_trip) != 0) {
    abort();
  }
}

static void verify_reply_packet(const uint8_t *packet, size_t packet_len) {
  struct qaff_control_msg decoded;
  if (qaff_control_decode_reply(packet, packet_len, &decoded) != 0) {
    return;
  }
  uint8_t encoded[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t encoded_len = 0;
  if (qaff_control_encode_reply(&decoded, encoded, sizeof(encoded),
                                &encoded_len) != 0 ||
      encoded_len != packet_len || memcmp(encoded, packet, packet_len) != 0) {
    abort();
  }
  struct qaff_control_msg round_trip;
  if (qaff_control_decode_reply(encoded, encoded_len, &round_trip) != 0) {
    abort();
  }
}

static void fill_cid(struct qaff_control_msg *msg, const uint8_t *data,
                     size_t size, uint32_t hash) {
  msg->cid_len = hash % (QAFF_MAX_CID_LEN + 1u);
  size_t copy_len = msg->cid_len < size ? msg->cid_len : size;
  memcpy(msg->cid, data, copy_len);
}

static void exercise_generated_request(const uint8_t *data, size_t size,
                                       uint32_t hash) {
  static const uint16_t operations[] = {
      QAFF_CONTROL_REGISTER_WORKER,
      QAFF_CONTROL_REGISTER_CID,
      QAFF_CONTROL_RETIRE_CID,
      QAFF_CONTROL_READ_STATS,
      QAFF_CONTROL_STOP,
      QAFF_CONTROL_HEALTH,
      QAFF_CONTROL_CONFIG,
      QAFF_CONTROL_WORKERS,
      QAFF_CONTROL_UNREGISTER_WORKER,
      QAFF_CONTROL_CIDS,
      QAFF_CONTROL_REGISTER_WORKER_LEASE,
      QAFF_CONTROL_WORKER_HEARTBEAT,
      QAFF_CONTROL_REGISTER_PASSIVE_CID,
      QAFF_CONTROL_RETIRE_PASSIVE_CID,
  };
  struct qaff_control_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.op = operations[hash % (sizeof(operations) / sizeof(operations[0]))];
  msg.worker_id = hash;
  msg.target_pid = hash ^ UINT32_C(0xa5a5a5a5);
  msg.passive_value.worker_id = hash;
  msg.passive_value.worker_generation = hash >> 8;
  msg.passive_value.confidence = (uint8_t)hash;
  msg.passive_value.source = (uint8_t)(hash >> 8);
  msg.passive_value.flags = (uint16_t)(hash >> 16);
  msg.passive_value.expires_at_ns = ((uint64_t)hash << 32) | hash;
  fill_cid(&msg, data, size, hash);

  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t packet_len = 0;
  if (qaff_control_encode_request(&msg, packet, sizeof(packet), &packet_len) !=
      0) {
    abort();
  }
  verify_request_packet(packet, packet_len);
}

static void exercise_generated_reply(const uint8_t *data, size_t size,
                                     uint32_t hash) {
  static const uint16_t operations[] = {
      QAFF_CONTROL_REGISTER_WORKER,
      QAFF_CONTROL_REGISTER_CID,
      QAFF_CONTROL_RETIRE_CID,
      QAFF_CONTROL_READ_STATS,
      QAFF_CONTROL_STOP,
      QAFF_CONTROL_HEALTH,
      QAFF_CONTROL_CONFIG,
      QAFF_CONTROL_WORKERS,
      QAFF_CONTROL_UNREGISTER_WORKER,
      QAFF_CONTROL_CIDS,
      QAFF_CONTROL_REGISTER_WORKER_LEASE,
      QAFF_CONTROL_WORKER_HEARTBEAT,
      QAFF_CONTROL_REGISTER_PASSIVE_CID,
      QAFF_CONTROL_RETIRE_PASSIVE_CID,
  };
  struct qaff_control_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.op =
      operations[(hash >> 8) % (sizeof(operations) / sizeof(operations[0]))];
  msg.status = size > 0 && (data[0] & 0x80) != 0
                   ? (int32_t)(hash % UINT32_C(4096) + 1)
                   : 0;
  msg.worker_id = hash;
  msg.config.worker_count = hash >> 16;
  msg.config.cid_map_count = ((uint64_t)hash << 32) | hash;
  msg.config.passive_scan_interval_ms = hash;
  memcpy(msg.config.pin_root, "/sys/fs/bpf/qaff", sizeof("/sys/fs/bpf/qaff"));
  memcpy(msg.config.state_path, "/var/lib/qaff/state",
         sizeof("/var/lib/qaff/state"));
  msg.workers_len = hash % (QAFF_CONTROL_PAGE_WORKERS + 1u);
  for (size_t i = 0; i < msg.workers_len; i++) {
    msg.worker_infos[i].worker_id = hash + (uint32_t)i;
    msg.worker_infos[i].flags = hash ^ (uint32_t)i;
    msg.worker_infos[i].last_seen_ms_ago = ((uint64_t)hash << 32) | i;
  }
  for (size_t i = 0; i < QAFF_STAT_MAX; i++) {
    msg.stats.values[i] = ((uint64_t)hash << 32) | i;
  }

  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t packet_len = 0;
  if (qaff_control_encode_reply(&msg, packet, sizeof(packet), &packet_len) !=
      0) {
    abort();
  }
  verify_reply_packet(packet, packet_len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  verify_request_packet(data, size);
  verify_reply_packet(data, size);
  uint32_t hash = input_hash(data, size);
  exercise_generated_request(data, size, hash);
  exercise_generated_reply(data, size, hash);
  return 0;
}
