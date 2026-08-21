#include "control_protocol.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

struct qaff_writer {
  uint8_t *data;
  size_t cap;
  size_t pos;
};

struct qaff_reader {
  const uint8_t *data;
  size_t len;
  size_t pos;
};

static int put_bytes(struct qaff_writer *writer, const void *value,
                     size_t len) {
  if (len > writer->cap - writer->pos) {
    errno = EMSGSIZE;
    return -1;
  }
  memcpy(writer->data + writer->pos, value, len);
  writer->pos += len;
  return 0;
}

static int put_u8(struct qaff_writer *writer, uint8_t value) {
  return put_bytes(writer, &value, sizeof(value));
}

static int put_u16(struct qaff_writer *writer, uint16_t value) {
  uint8_t encoded[2] = {
      (uint8_t)(value >> 8),
      (uint8_t)value,
  };
  return put_bytes(writer, encoded, sizeof(encoded));
}

static int put_u32(struct qaff_writer *writer, uint32_t value) {
  uint8_t encoded[4] = {
      (uint8_t)(value >> 24),
      (uint8_t)(value >> 16),
      (uint8_t)(value >> 8),
      (uint8_t)value,
  };
  return put_bytes(writer, encoded, sizeof(encoded));
}

static int put_u64(struct qaff_writer *writer, uint64_t value) {
  uint8_t encoded[8] = {
      (uint8_t)(value >> 56), (uint8_t)(value >> 48), (uint8_t)(value >> 40),
      (uint8_t)(value >> 32), (uint8_t)(value >> 24), (uint8_t)(value >> 16),
      (uint8_t)(value >> 8),  (uint8_t)value,
  };
  return put_bytes(writer, encoded, sizeof(encoded));
}

static int get_bytes(struct qaff_reader *reader, void *value, size_t len) {
  if (len > reader->len - reader->pos) {
    errno = EPROTO;
    return -1;
  }
  memcpy(value, reader->data + reader->pos, len);
  reader->pos += len;
  return 0;
}

static int get_u8(struct qaff_reader *reader, uint8_t *value) {
  return get_bytes(reader, value, sizeof(*value));
}

static int get_u16(struct qaff_reader *reader, uint16_t *value) {
  uint8_t encoded[2];
  if (get_bytes(reader, encoded, sizeof(encoded)) != 0) {
    return -1;
  }
  *value = ((uint16_t)encoded[0] << 8) | encoded[1];
  return 0;
}

static int get_u32(struct qaff_reader *reader, uint32_t *value) {
  uint8_t encoded[4];
  if (get_bytes(reader, encoded, sizeof(encoded)) != 0) {
    return -1;
  }
  *value = ((uint32_t)encoded[0] << 24) | ((uint32_t)encoded[1] << 16) |
           ((uint32_t)encoded[2] << 8) | encoded[3];
  return 0;
}

static int get_u64(struct qaff_reader *reader, uint64_t *value) {
  uint8_t encoded[8];
  if (get_bytes(reader, encoded, sizeof(encoded)) != 0) {
    return -1;
  }
  *value = ((uint64_t)encoded[0] << 56) | ((uint64_t)encoded[1] << 48) |
           ((uint64_t)encoded[2] << 40) | ((uint64_t)encoded[3] << 32) |
           ((uint64_t)encoded[4] << 24) | ((uint64_t)encoded[5] << 16) |
           ((uint64_t)encoded[6] << 8) | encoded[7];
  return 0;
}

static int put_cid(struct qaff_writer *writer, const uint8_t *cid,
                   uint32_t cid_len) {
  if (cid_len > QAFF_MAX_CID_LEN) {
    errno = EINVAL;
    return -1;
  }
  return put_u8(writer, (uint8_t)cid_len) == 0 &&
                 put_bytes(writer, cid, cid_len) == 0
             ? 0
             : -1;
}

static int get_cid(struct qaff_reader *reader, struct qaff_control_msg *msg) {
  uint8_t cid_len;
  if (get_u8(reader, &cid_len) != 0 || cid_len > QAFF_MAX_CID_LEN) {
    errno = EPROTO;
    return -1;
  }
  msg->cid_len = cid_len;
  return get_bytes(reader, msg->cid, cid_len);
}

static int put_path(struct qaff_writer *writer,
                    const char path[QAFF_CONTROL_MAX_PATH]) {
  size_t len = 0;
  while (len < QAFF_CONTROL_MAX_PATH && path[len] != '\0') {
    len++;
  }
  if (len == QAFF_CONTROL_MAX_PATH || len > UINT16_MAX) {
    errno = EINVAL;
    return -1;
  }
  return put_u16(writer, (uint16_t)len) == 0 &&
                 put_bytes(writer, path, len) == 0
             ? 0
             : -1;
}

static int get_path(struct qaff_reader *reader,
                    char path[QAFF_CONTROL_MAX_PATH]) {
  uint16_t len;
  if (get_u16(reader, &len) != 0 || len >= QAFF_CONTROL_MAX_PATH) {
    errno = EPROTO;
    return -1;
  }
  if (get_bytes(reader, path, len) != 0) {
    return -1;
  }
  path[len] = '\0';
  return 0;
}

static int put_config(struct qaff_writer *writer,
                      const struct qaff_control_config *config) {
  if (put_u8(writer, config->short_cid_len) != 0 ||
      put_u8(writer, config->attached) != 0 ||
      put_u8(writer, config->cid_profile_v1_enabled) != 0 ||
      put_u8(writer, config->cid_profile_v2_enabled) != 0 ||
      put_u8(writer, config->cid_profile_v2_config_id) != 0 ||
      put_u8(writer, config->passive_affinity_enabled) != 0 ||
      put_u8(writer, config->passive_min_confidence) != 0 ||
      put_u8(writer, config->egress_attached) != 0 ||
      put_u8(writer, config->fallback_mode) != 0 ||
      put_u32(writer, config->worker_count) != 0 ||
      put_u32(writer, config->fallback_worker_id) != 0 ||
      put_u64(writer, config->cid_map_count) != 0 ||
      put_u64(writer, config->cid_owner_count) != 0 ||
      put_u64(writer, config->cid_index_mismatch) != 0 ||
      put_u64(writer, config->passive_entry_count) != 0 ||
      put_u64(writer, config->passive_entry_capacity) != 0 ||
      put_u64(writer, config->passive_expired_count) != 0 ||
      put_u64(writer, config->passive_worker_purged_count) != 0 ||
      put_u64(writer, config->passive_expiry_initialized_count) != 0 ||
      put_u64(writer, config->passive_cleanup_error_count) != 0 ||
      put_u64(writer, config->passive_scan_interval_ms) != 0 ||
      put_path(writer, config->pin_root) != 0 ||
      put_path(writer, config->state_path) != 0) {
    return -1;
  }
  return 0;
}

static int get_config(struct qaff_reader *reader,
                      struct qaff_control_config *config) {
  if (get_u8(reader, &config->short_cid_len) != 0 ||
      get_u8(reader, &config->attached) != 0 ||
      get_u8(reader, &config->cid_profile_v1_enabled) != 0 ||
      get_u8(reader, &config->cid_profile_v2_enabled) != 0 ||
      get_u8(reader, &config->cid_profile_v2_config_id) != 0 ||
      get_u8(reader, &config->passive_affinity_enabled) != 0 ||
      get_u8(reader, &config->passive_min_confidence) != 0 ||
      get_u8(reader, &config->egress_attached) != 0 ||
      get_u8(reader, &config->fallback_mode) != 0 ||
      get_u32(reader, &config->worker_count) != 0 ||
      get_u32(reader, &config->fallback_worker_id) != 0 ||
      get_u64(reader, &config->cid_map_count) != 0 ||
      get_u64(reader, &config->cid_owner_count) != 0 ||
      get_u64(reader, &config->cid_index_mismatch) != 0 ||
      get_u64(reader, &config->passive_entry_count) != 0 ||
      get_u64(reader, &config->passive_entry_capacity) != 0 ||
      get_u64(reader, &config->passive_expired_count) != 0 ||
      get_u64(reader, &config->passive_worker_purged_count) != 0 ||
      get_u64(reader, &config->passive_expiry_initialized_count) != 0 ||
      get_u64(reader, &config->passive_cleanup_error_count) != 0 ||
      get_u64(reader, &config->passive_scan_interval_ms) != 0 ||
      get_path(reader, config->pin_root) != 0 ||
      get_path(reader, config->state_path) != 0) {
    return -1;
  }
  return 0;
}

static int put_worker_info(struct qaff_writer *writer,
                           const struct qaff_control_worker_info *info) {
  return put_u32(writer, info->worker_id) == 0 &&
                 put_u32(writer, info->flags) == 0 &&
                 put_u32(writer, info->pid) == 0 &&
                 put_u32(writer, info->uid) == 0 &&
                 put_u32(writer, info->gid) == 0 &&
                 put_u32(writer, info->target_pid) == 0 &&
                 put_u64(writer, info->registered_ms_ago) == 0 &&
                 put_u64(writer, info->last_seen_ms_ago) == 0
             ? 0
             : -1;
}

static int get_worker_info(struct qaff_reader *reader,
                           struct qaff_control_worker_info *info) {
  return get_u32(reader, &info->worker_id) == 0 &&
                 get_u32(reader, &info->flags) == 0 &&
                 get_u32(reader, &info->pid) == 0 &&
                 get_u32(reader, &info->uid) == 0 &&
                 get_u32(reader, &info->gid) == 0 &&
                 get_u32(reader, &info->target_pid) == 0 &&
                 get_u64(reader, &info->registered_ms_ago) == 0 &&
                 get_u64(reader, &info->last_seen_ms_ago) == 0
             ? 0
             : -1;
}

static int put_header(uint8_t *packet, size_t packet_cap, uint16_t op,
                      int32_t status, size_t payload_len) {
  if (packet_cap < QAFF_CONTROL_HEADER_SIZE || payload_len > UINT32_MAX ||
      status < 0) {
    errno = EINVAL;
    return -1;
  }
  struct qaff_writer writer = {
      .data = packet,
      .cap = QAFF_CONTROL_HEADER_SIZE,
  };
  return put_u32(&writer, QAFF_CONTROL_MAGIC) == 0 &&
                 put_u16(&writer, QAFF_CONTROL_VERSION) == 0 &&
                 put_u16(&writer, op) == 0 &&
                 put_u32(&writer, (uint32_t)status) == 0 &&
                 put_u32(&writer, (uint32_t)payload_len) == 0
             ? 0
             : -1;
}

static int get_header(const uint8_t *packet, size_t packet_len, uint16_t *op,
                      int32_t *status, struct qaff_reader *payload) {
  if (packet == NULL || packet_len < QAFF_CONTROL_HEADER_SIZE ||
      packet_len > QAFF_CONTROL_MAX_MESSAGE_SIZE) {
    errno = EPROTO;
    return -1;
  }
  struct qaff_reader reader = {.data = packet, .len = packet_len};
  uint32_t magic;
  uint16_t version;
  uint32_t encoded_status;
  uint32_t payload_len;
  if (get_u32(&reader, &magic) != 0 || get_u16(&reader, &version) != 0 ||
      get_u16(&reader, op) != 0 || get_u32(&reader, &encoded_status) != 0 ||
      get_u32(&reader, &payload_len) != 0 || magic != QAFF_CONTROL_MAGIC ||
      version != QAFF_CONTROL_VERSION || encoded_status > INT32_MAX ||
      payload_len != packet_len - reader.pos) {
    errno = EPROTO;
    return -1;
  }
  *status = (int32_t)encoded_status;
  payload->data = packet + reader.pos;
  payload->len = payload_len;
  payload->pos = 0;
  return 0;
}

static int finish_encode(struct qaff_writer *writer,
                         const struct qaff_control_msg *msg,
                         size_t *packet_len) {
  if (put_header(writer->data, writer->cap, msg->op, msg->status,
                 writer->pos - QAFF_CONTROL_HEADER_SIZE) != 0) {
    return -1;
  }
  *packet_len = writer->pos;
  return 0;
}

static int finish_decode(const struct qaff_reader *reader) {
  if (reader->pos != reader->len) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

int qaff_control_encode_request(const struct qaff_control_msg *msg,
                                uint8_t *packet, size_t packet_cap,
                                size_t *packet_len) {
  if (msg == NULL || packet == NULL || packet_len == NULL ||
      packet_cap < QAFF_CONTROL_HEADER_SIZE ||
      packet_cap > QAFF_CONTROL_MAX_MESSAGE_SIZE || msg->status != 0) {
    errno = EINVAL;
    return -1;
  }
  struct qaff_writer writer = {
      .data = packet,
      .cap = packet_cap,
      .pos = QAFF_CONTROL_HEADER_SIZE,
  };
  switch (msg->op) {
  case QAFF_CONTROL_REGISTER_WORKER:
  case QAFF_CONTROL_WORKER_HEARTBEAT:
  case QAFF_CONTROL_UNREGISTER_WORKER:
  case QAFF_CONTROL_WORKERS:
    if (put_u32(&writer, msg->worker_id) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_REGISTER_WORKER_LEASE:
    if (put_u32(&writer, msg->worker_id) != 0 ||
        put_u32(&writer, msg->target_pid) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_REGISTER_CID:
    if (put_u32(&writer, msg->worker_id) != 0 ||
        put_cid(&writer, msg->cid, msg->cid_len) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_RETIRE_CID:
  case QAFF_CONTROL_RETIRE_PASSIVE_CID:
    if (put_cid(&writer, msg->cid, msg->cid_len) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_REGISTER_PASSIVE_CID:
    if (put_u32(&writer, msg->passive_value.worker_id) != 0 ||
        put_u32(&writer, msg->passive_value.worker_generation) != 0 ||
        put_u8(&writer, msg->passive_value.confidence) != 0 ||
        put_u8(&writer, msg->passive_value.source) != 0 ||
        put_u16(&writer, msg->passive_value.flags) != 0 ||
        put_u64(&writer, msg->passive_value.expires_at_ns) != 0 ||
        put_cid(&writer, msg->cid, msg->cid_len) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_READ_STATS:
  case QAFF_CONTROL_STOP:
  case QAFF_CONTROL_HEALTH:
  case QAFF_CONTROL_CONFIG:
  case QAFF_CONTROL_CIDS:
    break;
  default:
    errno = EINVAL;
    return -1;
  }
  return finish_encode(&writer, msg, packet_len);
}

int qaff_control_decode_request(const uint8_t *packet, size_t packet_len,
                                struct qaff_control_msg *msg) {
  if (msg == NULL) {
    errno = EINVAL;
    return -1;
  }
  memset(msg, 0, sizeof(*msg));
  struct qaff_reader reader;
  if (get_header(packet, packet_len, &msg->op, &msg->status, &reader) != 0 ||
      msg->status != 0) {
    errno = EPROTO;
    return -1;
  }
  switch (msg->op) {
  case QAFF_CONTROL_REGISTER_WORKER:
  case QAFF_CONTROL_WORKER_HEARTBEAT:
  case QAFF_CONTROL_UNREGISTER_WORKER:
  case QAFF_CONTROL_WORKERS:
    if (get_u32(&reader, &msg->worker_id) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_REGISTER_WORKER_LEASE:
    if (get_u32(&reader, &msg->worker_id) != 0 ||
        get_u32(&reader, &msg->target_pid) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_REGISTER_CID:
    if (get_u32(&reader, &msg->worker_id) != 0 || get_cid(&reader, msg) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_RETIRE_CID:
  case QAFF_CONTROL_RETIRE_PASSIVE_CID:
    if (get_cid(&reader, msg) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_REGISTER_PASSIVE_CID:
    if (get_u32(&reader, &msg->passive_value.worker_id) != 0 ||
        get_u32(&reader, &msg->passive_value.worker_generation) != 0 ||
        get_u8(&reader, &msg->passive_value.confidence) != 0 ||
        get_u8(&reader, &msg->passive_value.source) != 0 ||
        get_u16(&reader, &msg->passive_value.flags) != 0 ||
        get_u64(&reader, &msg->passive_value.expires_at_ns) != 0 ||
        get_cid(&reader, msg) != 0) {
      return -1;
    }
    msg->worker_id = msg->passive_value.worker_id;
    break;
  case QAFF_CONTROL_READ_STATS:
  case QAFF_CONTROL_STOP:
  case QAFF_CONTROL_HEALTH:
  case QAFF_CONTROL_CONFIG:
  case QAFF_CONTROL_CIDS:
    break;
  default:
    break;
  }
  return finish_decode(&reader);
}

int qaff_control_encode_reply(const struct qaff_control_msg *msg,
                              uint8_t *packet, size_t packet_cap,
                              size_t *packet_len) {
  if (msg == NULL || packet == NULL || packet_len == NULL ||
      packet_cap < QAFF_CONTROL_HEADER_SIZE ||
      packet_cap > QAFF_CONTROL_MAX_MESSAGE_SIZE || msg->status < 0) {
    errno = EINVAL;
    return -1;
  }
  struct qaff_writer writer = {
      .data = packet,
      .cap = packet_cap,
      .pos = QAFF_CONTROL_HEADER_SIZE,
  };
  if (msg->status != 0) {
    return finish_encode(&writer, msg, packet_len);
  }
  switch (msg->op) {
  case QAFF_CONTROL_READ_STATS:
    for (size_t i = 0; i < QAFF_STAT_MAX; i++) {
      if (put_u64(&writer, msg->stats.values[i]) != 0) {
        return -1;
      }
    }
    break;
  case QAFF_CONTROL_CONFIG:
  case QAFF_CONTROL_CIDS:
    if (put_config(&writer, &msg->config) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_WORKERS:
    if (msg->workers_len > QAFF_CONTROL_PAGE_WORKERS) {
      errno = EINVAL;
      return -1;
    }
    if (put_u32(&writer, msg->worker_id) != 0 ||
        put_u32(&writer, msg->config.worker_count) != 0 ||
        put_u16(&writer, (uint16_t)msg->workers_len) != 0) {
      return -1;
    }
    for (size_t i = 0; i < msg->workers_len; i++) {
      if (put_worker_info(&writer, &msg->worker_infos[i]) != 0) {
        return -1;
      }
    }
    break;
  case QAFF_CONTROL_REGISTER_WORKER:
  case QAFF_CONTROL_REGISTER_CID:
  case QAFF_CONTROL_RETIRE_CID:
  case QAFF_CONTROL_STOP:
  case QAFF_CONTROL_HEALTH:
  case QAFF_CONTROL_UNREGISTER_WORKER:
  case QAFF_CONTROL_REGISTER_WORKER_LEASE:
  case QAFF_CONTROL_WORKER_HEARTBEAT:
  case QAFF_CONTROL_REGISTER_PASSIVE_CID:
  case QAFF_CONTROL_RETIRE_PASSIVE_CID:
    break;
  default:
    errno = EINVAL;
    return -1;
  }
  return finish_encode(&writer, msg, packet_len);
}

int qaff_control_decode_reply(const uint8_t *packet, size_t packet_len,
                              struct qaff_control_msg *msg) {
  if (msg == NULL) {
    errno = EINVAL;
    return -1;
  }
  memset(msg, 0, sizeof(*msg));
  struct qaff_reader reader;
  if (get_header(packet, packet_len, &msg->op, &msg->status, &reader) != 0) {
    return -1;
  }
  if (msg->status != 0) {
    return finish_decode(&reader);
  }
  switch (msg->op) {
  case QAFF_CONTROL_READ_STATS:
    for (size_t i = 0; i < QAFF_STAT_MAX; i++) {
      if (get_u64(&reader, &msg->stats.values[i]) != 0) {
        return -1;
      }
    }
    break;
  case QAFF_CONTROL_CONFIG:
  case QAFF_CONTROL_CIDS:
    if (get_config(&reader, &msg->config) != 0) {
      return -1;
    }
    break;
  case QAFF_CONTROL_WORKERS: {
    uint16_t workers_len;
    if (get_u32(&reader, &msg->worker_id) != 0 ||
        get_u32(&reader, &msg->config.worker_count) != 0 ||
        get_u16(&reader, &workers_len) != 0 ||
        workers_len > QAFF_CONTROL_PAGE_WORKERS) {
      errno = EPROTO;
      return -1;
    }
    msg->workers_len = workers_len;
    for (size_t i = 0; i < msg->workers_len; i++) {
      if (get_worker_info(&reader, &msg->worker_infos[i]) != 0) {
        return -1;
      }
      msg->workers[i] = msg->worker_infos[i].worker_id;
    }
    break;
  }
  case QAFF_CONTROL_REGISTER_WORKER:
  case QAFF_CONTROL_REGISTER_CID:
  case QAFF_CONTROL_RETIRE_CID:
  case QAFF_CONTROL_STOP:
  case QAFF_CONTROL_HEALTH:
  case QAFF_CONTROL_UNREGISTER_WORKER:
  case QAFF_CONTROL_REGISTER_WORKER_LEASE:
  case QAFF_CONTROL_WORKER_HEARTBEAT:
  case QAFF_CONTROL_REGISTER_PASSIVE_CID:
  case QAFF_CONTROL_RETIRE_PASSIVE_CID:
    break;
  default:
    errno = EPROTO;
    return -1;
  }
  return finish_decode(&reader);
}
