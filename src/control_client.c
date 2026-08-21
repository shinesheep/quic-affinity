#include "quic_affinity/control.h"
#include "control_protocol.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void qaff_control_msg_init(struct qaff_control_msg *msg,
                                  enum qaff_control_op op) {
  memset(msg, 0, sizeof(*msg));
  msg->magic = QAFF_CONTROL_MAGIC;
  msg->version = QAFF_CONTROL_VERSION;
  msg->op = (uint16_t)op;
}

static int qaff_read_all(int fd, void *buf, size_t len) {
  char *p = buf;
  while (len > 0) {
    ssize_t got = read(fd, p, len);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (got == 0) {
      errno = ECONNRESET;
      return -1;
    }
    p += got;
    len -= (size_t)got;
  }
  return 0;
}

static int qaff_send_msg_with_fd(int fd,
                                 const struct qaff_control_msg *msg,
                                 int pass_fd) {
  size_t sent = 0;
  int rights_sent = 0;
  while (sent < sizeof(*msg)) {
    struct iovec iov = {
      .iov_base = (char *)msg + sent,
      .iov_len = sizeof(*msg) - sent,
    };
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    if (pass_fd >= 0 && !rights_sent) {
      hdr.msg_control = control;
      hdr.msg_controllen = sizeof(control);
      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(int));
      memcpy(CMSG_DATA(cmsg), &pass_fd, sizeof(pass_fd));
    }

    ssize_t written = sendmsg(fd, &hdr, MSG_NOSIGNAL);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (written == 0) {
      errno = EPIPE;
      return -1;
    }
    sent += (size_t)written;
    rights_sent = 1;
  }
  return 0;
}

static int qaff_round_trip(int fd,
                           struct qaff_control_msg *msg,
                           int pass_fd,
                           struct qaff_control_msg *reply) {
  if (qaff_send_msg_with_fd(fd, msg, pass_fd) != 0) {
    return -1;
  }
  if (qaff_read_all(fd, reply, sizeof(*reply)) != 0) {
    return -1;
  }
  if (reply->magic != QAFF_CONTROL_MAGIC ||
      reply->version != QAFF_CONTROL_VERSION ||
      reply->op != msg->op) {
    errno = EPROTO;
    return -1;
  }
  if (reply->status != 0) {
    errno = reply->status;
    return -1;
  }
  return 0;
}

int qaff_control_connect(const char *socket_path) {
  if (socket_path == NULL) {
    errno = EINVAL;
    return -1;
  }

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(socket_path) >= sizeof(addr.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(addr.sun_path, socket_path);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }

  return fd;
}

int qaff_control_register_worker(int control_fd,
                                 uint32_t worker_id,
                                 int socket_fd) {
  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_REGISTER_WORKER);
  msg.worker_id = worker_id;
  return qaff_round_trip(control_fd, &msg, socket_fd, &reply);
}

int qaff_control_register_worker_lease(int control_fd,
                                       uint32_t worker_id,
                                       int socket_fd) {
  return qaff_control_register_worker_lease_for_pid(
      control_fd, worker_id, socket_fd, 0);
}

int qaff_control_register_worker_lease_for_pid(int control_fd,
                                               uint32_t worker_id,
                                               int socket_fd,
                                               uint32_t target_pid) {
  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_REGISTER_WORKER_LEASE);
  msg.worker_id = worker_id;
  msg.target_pid = target_pid;
  return qaff_round_trip(control_fd, &msg, socket_fd, &reply);
}

int qaff_control_worker_heartbeat(int control_fd, uint32_t worker_id) {
  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_WORKER_HEARTBEAT);
  msg.worker_id = worker_id;
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}

int qaff_control_unregister_worker(int control_fd, uint32_t worker_id) {
  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_UNREGISTER_WORKER);
  msg.worker_id = worker_id;
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}

int qaff_control_register_cid(int control_fd,
                              uint32_t worker_id,
                              const uint8_t *cid,
                              size_t cid_len) {
  if (cid == NULL || cid_len > QAFF_MAX_CID_LEN) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_REGISTER_CID);
  msg.worker_id = worker_id;
  msg.cid_len = (uint32_t)cid_len;
  memcpy(msg.cid, cid, cid_len);
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}

int qaff_control_retire_cid(int control_fd,
                            const uint8_t *cid,
                            size_t cid_len) {
  if (cid == NULL || cid_len > QAFF_MAX_CID_LEN) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_RETIRE_CID);
  msg.cid_len = (uint32_t)cid_len;
  memcpy(msg.cid, cid, cid_len);
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}

int qaff_control_register_passive_cid(
    int control_fd,
    const uint8_t *cid,
    size_t cid_len,
    const struct qaff_passive_cid_value *value) {
  if (cid == NULL || cid_len > QAFF_MAX_CID_LEN || value == NULL) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_REGISTER_PASSIVE_CID);
  msg.worker_id = value->worker_id;
  msg.cid_len = (uint32_t)cid_len;
  memcpy(msg.cid, cid, cid_len);
  msg.passive_value = *value;
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}

int qaff_control_retire_passive_cid(int control_fd,
                                    const uint8_t *cid,
                                    size_t cid_len) {
  if (cid == NULL || cid_len > QAFF_MAX_CID_LEN) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_RETIRE_PASSIVE_CID);
  msg.cid_len = (uint32_t)cid_len;
  memcpy(msg.cid, cid, cid_len);
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}

int qaff_control_read_stats(int control_fd, struct qaff_stats *out) {
  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_READ_STATS);
  if (qaff_round_trip(control_fd, &msg, -1, &reply) != 0) {
    return -1;
  }
  *out = reply.stats;
  return 0;
}

int qaff_control_health(int control_fd) {
  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_HEALTH);
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}

int qaff_control_config(int control_fd, struct qaff_control_config *out) {
  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_CONFIG);
  if (qaff_round_trip(control_fd, &msg, -1, &reply) != 0) {
    return -1;
  }
  *out = reply.config;
  return 0;
}

int qaff_control_cids(int control_fd, struct qaff_control_config *out) {
  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }

  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_CIDS);
  if (qaff_round_trip(control_fd, &msg, -1, &reply) != 0) {
    return -1;
  }
  *out = reply.config;
  return 0;
}

static int qaff_control_list_workers(
    int control_fd,
    uint32_t *worker_ids,
    struct qaff_control_worker_info *worker_infos,
    size_t workers_cap,
    size_t *workers_len) {
  uint32_t cursor = 0;
  size_t copied = 0;
  size_t total = 0;

  for (;;) {
    struct qaff_control_msg msg;
    struct qaff_control_msg reply;
    qaff_control_msg_init(&msg, QAFF_CONTROL_WORKERS);
    msg.worker_id = cursor;
    if (qaff_round_trip(control_fd, &msg, -1, &reply) != 0) {
      return -1;
    }
    if (reply.workers_len > QAFF_CONTROL_PAGE_WORKERS ||
        reply.config.worker_count > QAFF_CONTROL_WORKER_CAPACITY) {
      errno = EPROTO;
      return -1;
    }
    if (cursor == 0) {
      total = reply.config.worker_count;
    }

    uint32_t previous = cursor;
    for (size_t i = 0; i < reply.workers_len; i++) {
      uint32_t worker_id = reply.workers[i];
      if (worker_id < cursor || (i > 0 && worker_id <= previous) ||
          worker_id != reply.worker_infos[i].worker_id ||
          worker_id >= QAFF_CONTROL_WORKER_CAPACITY) {
        errno = EPROTO;
        return -1;
      }
      previous = worker_id;
      if (copied < workers_cap) {
        if (worker_ids != NULL) {
          worker_ids[copied] = worker_id;
        }
        if (worker_infos != NULL) {
          worker_infos[copied] = reply.worker_infos[i];
        }
        copied++;
      }
    }

    if (copied == workers_cap || reply.worker_id == UINT32_MAX) {
      break;
    }
    if (reply.workers_len == 0 || reply.worker_id <= cursor ||
        reply.worker_id >= QAFF_CONTROL_WORKER_CAPACITY) {
      errno = EPROTO;
      return -1;
    }
    cursor = reply.worker_id;
  }

  *workers_len = total;
  return 0;
}

int qaff_control_workers(int control_fd,
                         uint32_t *workers,
                         size_t workers_cap,
                         size_t *workers_len) {
  if (workers_len == NULL || (workers_cap > 0 && workers == NULL)) {
    errno = EINVAL;
    return -1;
  }
  return qaff_control_list_workers(control_fd,
                                   workers,
                                   NULL,
                                   workers_cap,
                                   workers_len);
}

int qaff_control_workers_info(int control_fd,
                              struct qaff_control_worker_info *workers,
                              size_t workers_cap,
                              size_t *workers_len) {
  if (workers_len == NULL || (workers_cap > 0 && workers == NULL)) {
    errno = EINVAL;
    return -1;
  }

  return qaff_control_list_workers(control_fd,
                                   NULL,
                                   workers,
                                   workers_cap,
                                   workers_len);
}

int qaff_control_stop(int control_fd) {
  struct qaff_control_msg msg;
  struct qaff_control_msg reply;
  qaff_control_msg_init(&msg, QAFF_CONTROL_STOP);
  return qaff_round_trip(control_fd, &msg, -1, &reply);
}
