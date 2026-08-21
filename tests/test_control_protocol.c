#include "control_protocol.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "control protocol test failed: %s\n", message);
    return -1;
  }
  return 0;
}

static int test_passive_request(void) {
  struct qaff_control_msg input;
  memset(&input, 0, sizeof(input));
  input.op = QAFF_CONTROL_REGISTER_PASSIVE_CID;
  input.cid_len = 4;
  input.cid[0] = 0xde;
  input.cid[1] = 0xad;
  input.cid[2] = 0xbe;
  input.cid[3] = 0xef;
  input.passive_value.worker_id = 0x01020304u;
  input.passive_value.worker_generation = 0x11223344u;
  input.passive_value.confidence = 3;
  input.passive_value.source = 2;
  input.passive_value.flags = 0x5566u;
  input.passive_value.expires_at_ns = UINT64_C(0x0102030405060708);

  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t packet_len = 0;
  if (qaff_control_encode_request(&input, packet, sizeof(packet),
                                  &packet_len) != 0) {
    perror("qaff_control_encode_request");
    return -1;
  }
  if (check(packet_len == QAFF_CONTROL_HEADER_SIZE + 25,
            "passive request length") != 0 ||
      check(packet[0] == 0x51 && packet[1] == 0x41 && packet[2] == 0x46 &&
                packet[3] == 0x46,
            "magic is big-endian") != 0 ||
      check(packet[6] == 0 && packet[7] == QAFF_CONTROL_REGISTER_PASSIVE_CID,
            "operation is big-endian") != 0 ||
      check(packet[16] == 1 && packet[17] == 2 && packet[18] == 3 &&
                packet[19] == 4,
            "worker ID is big-endian") != 0) {
    return -1;
  }

  struct qaff_control_msg output;
  if (qaff_control_decode_request(packet, packet_len, &output) != 0) {
    perror("qaff_control_decode_request");
    return -1;
  }
  return check(output.op == input.op, "passive operation round trip") == 0 &&
                 check(output.worker_id == input.passive_value.worker_id,
                       "passive worker ID round trip") == 0 &&
                 check(output.passive_value.worker_generation ==
                           input.passive_value.worker_generation,
                       "passive generation round trip") == 0 &&
                 check(output.passive_value.expires_at_ns ==
                           input.passive_value.expires_at_ns,
                       "passive expiry round trip") == 0 &&
                 check(output.cid_len == input.cid_len &&
                           memcmp(output.cid, input.cid, input.cid_len) == 0,
                       "passive CID round trip") == 0
             ? 0
             : -1;
}

static int test_config_reply(void) {
  struct qaff_control_msg input;
  memset(&input, 0, sizeof(input));
  input.op = QAFF_CONTROL_CONFIG;
  input.config.short_cid_len = 20;
  input.config.attached = 1;
  input.config.passive_affinity_enabled = 1;
  input.config.worker_count = 73;
  input.config.fallback_worker_id = 42;
  input.config.cid_map_count = UINT64_C(0x0102030405060708);
  input.config.passive_scan_interval_ms = 30000;
  strcpy(input.config.pin_root, "/sys/fs/bpf/qaff");
  strcpy(input.config.state_path, "/var/lib/qaff/state");

  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t packet_len;
  if (qaff_control_encode_reply(&input, packet, sizeof(packet), &packet_len) !=
      0) {
    perror("qaff_control_encode_reply config");
    return -1;
  }
  struct qaff_control_msg output;
  if (qaff_control_decode_reply(packet, packet_len, &output) != 0) {
    perror("qaff_control_decode_reply config");
    return -1;
  }
  return check(output.config.short_cid_len == 20,
               "config byte field round trip") == 0 &&
                 check(output.config.worker_count == 73,
                       "config u32 round trip") == 0 &&
                 check(output.config.cid_map_count ==
                           UINT64_C(0x0102030405060708),
                       "config u64 round trip") == 0 &&
                 check(strcmp(output.config.pin_root, input.config.pin_root) ==
                           0,
                       "config pin path round trip") == 0 &&
                 check(strcmp(output.config.state_path,
                              input.config.state_path) == 0,
                       "config state path round trip") == 0
             ? 0
             : -1;
}

static int test_workers_reply(void) {
  struct qaff_control_msg input;
  memset(&input, 0, sizeof(input));
  input.op = QAFF_CONTROL_WORKERS;
  input.worker_id = UINT32_MAX;
  input.config.worker_count = 2;
  input.workers_len = 2;
  input.worker_infos[0] = (struct qaff_control_worker_info){
      .worker_id = 7,
      .flags = QAFF_CONTROL_WORKER_FLAG_LEASED,
      .pid = 101,
      .uid = 102,
      .gid = 103,
      .target_pid = 104,
      .registered_ms_ago = 105,
      .last_seen_ms_ago = 106,
  };
  input.worker_infos[1] = (struct qaff_control_worker_info){
      .worker_id = 4095,
      .flags = QAFF_CONTROL_WORKER_FLAG_CRED | QAFF_CONTROL_WORKER_FLAG_PIDFD,
      .registered_ms_ago = UINT64_MAX,
      .last_seen_ms_ago = UINT64_C(0x1020304050607080),
  };

  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t packet_len;
  if (qaff_control_encode_reply(&input, packet, sizeof(packet), &packet_len) !=
      0) {
    perror("qaff_control_encode_reply workers");
    return -1;
  }
  struct qaff_control_msg output;
  if (qaff_control_decode_reply(packet, packet_len, &output) != 0) {
    perror("qaff_control_decode_reply workers");
    return -1;
  }
  return check(output.worker_id == UINT32_MAX, "final worker cursor") == 0 &&
                 check(output.config.worker_count == 2, "worker total count") ==
                     0 &&
                 check(output.workers_len == 2, "worker page count") == 0 &&
                 check(output.workers[0] == 7 && output.workers[1] == 4095,
                       "worker IDs derived from records") == 0 &&
                 check(output.worker_infos[0].last_seen_ms_ago == 106,
                       "worker metadata round trip") == 0 &&
                 check(output.worker_infos[1].last_seen_ms_ago ==
                           UINT64_C(0x1020304050607080),
                       "worker u64 metadata round trip") == 0
             ? 0
             : -1;
}

static int test_malformed_packets(void) {
  struct qaff_control_msg input;
  memset(&input, 0, sizeof(input));
  input.op = QAFF_CONTROL_REGISTER_CID;
  input.worker_id = 9;
  input.cid_len = 3;
  memcpy(input.cid, "cid", 3);

  uint8_t packet[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  size_t packet_len;
  if (qaff_control_encode_request(&input, packet, sizeof(packet),
                                  &packet_len) != 0) {
    return -1;
  }
  struct qaff_control_msg output;
  for (size_t len = 0; len < packet_len; len++) {
    errno = 0;
    if (qaff_control_decode_request(packet, len, &output) == 0 ||
        errno != EPROTO) {
      return check(0, "every truncated request is rejected");
    }
  }

  uint8_t changed[QAFF_CONTROL_MAX_MESSAGE_SIZE];
  memcpy(changed, packet, packet_len);
  changed[3] ^= 1;
  if (qaff_control_decode_request(changed, packet_len, &output) == 0) {
    return check(0, "bad magic is rejected");
  }

  memcpy(changed, packet, packet_len);
  changed[15]++;
  if (qaff_control_decode_request(changed, packet_len, &output) == 0) {
    return check(0, "false payload length is rejected");
  }

  memcpy(changed, packet, QAFF_CONTROL_HEADER_SIZE);
  changed[6] = 0x7f;
  changed[7] = 0xff;
  memset(changed + 8, 0, 8);
  errno = 0;
  if (qaff_control_decode_request(changed, QAFF_CONTROL_HEADER_SIZE, &output) ==
          0 ||
      errno != EPROTO) {
    return check(0, "unknown request operation is rejected");
  }

  memcpy(changed, packet, packet_len);
  changed[packet_len] = 0;
  if (qaff_control_decode_request(changed, packet_len + 1, &output) == 0) {
    return check(0, "trailing byte is rejected");
  }

  struct qaff_control_msg error_reply;
  memset(&error_reply, 0, sizeof(error_reply));
  error_reply.op = QAFF_CONTROL_REGISTER_CID;
  error_reply.status = EACCES;
  if (qaff_control_encode_reply(&error_reply, packet, sizeof(packet),
                                &packet_len) != 0 ||
      qaff_control_decode_reply(packet, packet_len, &output) != 0) {
    return check(0, "error reply round trip");
  }
  return check(packet_len == QAFF_CONTROL_HEADER_SIZE,
               "error reply has no payload") == 0 &&
                 check(output.status == EACCES,
                       "error reply preserves errno") == 0
             ? 0
             : -1;
}

int main(void) {
  if (test_passive_request() != 0 || test_config_reply() != 0 ||
      test_workers_reply() != 0 || test_malformed_packets() != 0) {
    return 1;
  }
  puts("control protocol tests passed");
  return 0;
}
