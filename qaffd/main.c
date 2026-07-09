#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define QAFFD_MAX_WORKERS 4096

struct qaffd_options {
  const char *socket_path;
  const char *bpf_object_path;
  uint8_t short_cid_len;
  uint32_t fallback_worker_id;
};

struct qaffd_state {
  struct qaff_context *ctx;
  struct qaff_bpf_object *bpf;
  int worker_fds[QAFFD_MAX_WORKERS];
  uint8_t short_cid_len;
  uint32_t fallback_worker_id;
  int attached;
  int stop;
};

static volatile sig_atomic_t g_stop_requested = 0;

static void handle_signal(int signo) {
  (void)signo;
  g_stop_requested = 1;
}

static int install_signal_handlers(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handle_signal;
  if (sigemptyset(&action.sa_mask) != 0) {
    return -1;
  }
  if (sigaction(SIGTERM, &action, NULL) != 0) {
    return -1;
  }
  if (sigaction(SIGINT, &action, NULL) != 0) {
    return -1;
  }
  return 0;
}

static uint32_t worker_count(const struct qaffd_state *state) {
  uint32_t count = 0;
  for (size_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state->worker_fds[i] >= 0) {
      count++;
    }
  }
  return count;
}

static void fill_config_reply(const struct qaffd_state *state,
                              struct qaff_control_msg *reply) {
  reply->config.short_cid_len = state->short_cid_len;
  reply->config.attached = state->attached ? 1 : 0;
  reply->config.worker_count = worker_count(state);
  reply->config.fallback_worker_id = state->fallback_worker_id;
}

static void fill_workers_reply(const struct qaffd_state *state,
                               struct qaff_control_msg *reply) {
  uint32_t total = 0;
  uint32_t written = 0;

  for (uint32_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state->worker_fds[i] < 0) {
      continue;
    }
    if (written < QAFF_CONTROL_MAX_WORKERS) {
      reply->workers[written++] = i;
    }
    total++;
  }

  reply->workers_len = written;
  reply->config.worker_count = total;
}

static void usage(FILE *out) {
  fprintf(out,
          "Usage: qaffd --socket PATH --bpf PATH --short-cid-len N "
          "[--fallback-worker ID]\n");
}

static int parse_args(int argc, char **argv, struct qaffd_options *options) {
  memset(options, 0, sizeof(*options));

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
      options->socket_path = argv[++i];
    } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
      options->bpf_object_path = argv[++i];
    } else if (strcmp(argv[i], "--short-cid-len") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > QAFF_MAX_CID_LEN) {
        return -1;
      }
      options->short_cid_len = (uint8_t)value;
    } else if (strcmp(argv[i], "--fallback-worker") == 0 && i + 1 < argc) {
      char *end = NULL;
      unsigned long value = strtoul(argv[++i], &end, 10);
      if (end == argv[i] || *end != '\0' || value > UINT32_MAX) {
        return -1;
      }
      options->fallback_worker_id = (uint32_t)value;
    } else {
      return -1;
    }
  }

  if (options->socket_path == NULL ||
      options->bpf_object_path == NULL ||
      options->short_cid_len == 0) {
    return -1;
  }

  return 0;
}

static int read_exact(int fd, void *buf, size_t len) {
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

static int write_exact(int fd, const void *buf, size_t len) {
  const char *p = buf;
  while (len > 0) {
    ssize_t written = write(fd, p, len);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    p += written;
    len -= (size_t)written;
  }
  return 0;
}

static int recv_request(int fd, struct qaff_control_msg *msg, int *received_fd) {
  *received_fd = -1;

  struct iovec iov;
  iov.iov_base = msg;
  iov.iov_len = sizeof(*msg);

  char control[CMSG_SPACE(sizeof(int))];
  memset(control, 0, sizeof(control));

  struct msghdr hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  hdr.msg_control = control;
  hdr.msg_controllen = sizeof(control);

  ssize_t got;
  do {
    got = recvmsg(fd, &hdr, 0);
  } while (got < 0 && errno == EINTR);

  if (got < 0) {
    return -1;
  }
  if (got == 0) {
    errno = ECONNRESET;
    return -1;
  }
  if ((size_t)got != sizeof(*msg)) {
    if (read_exact(fd, (char *)msg + got, sizeof(*msg) - (size_t)got) != 0) {
      return -1;
    }
  }

  for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
       cmsg != NULL;
       cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS &&
        cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
      memcpy(received_fd, CMSG_DATA(cmsg), sizeof(int));
      break;
    }
  }

  return 0;
}

static void reply_init(struct qaff_control_msg *reply,
                       const struct qaff_control_msg *request) {
  memset(reply, 0, sizeof(*reply));
  reply->magic = QAFF_CONTROL_MAGIC;
  reply->version = QAFF_CONTROL_VERSION;
  reply->op = request->op;
}

static int handle_register_worker(struct qaffd_state *state,
                                  const struct qaff_control_msg *request,
                                  int socket_fd) {
  if (socket_fd < 0 || request->worker_id >= QAFFD_MAX_WORKERS) {
    errno = EINVAL;
    return -1;
  }

  if (qaff_register_worker_socket(state->ctx,
                                  request->worker_id,
                                  socket_fd) != 0) {
    return -1;
  }

  if (state->worker_fds[request->worker_id] >= 0) {
    close(state->worker_fds[request->worker_id]);
  }
  state->worker_fds[request->worker_id] = socket_fd;

  if (!state->attached) {
    if (qaff_attach_reuseport_bpf(state->bpf, socket_fd) != 0) {
      return -1;
    }
    state->attached = 1;
  }

  return 0;
}

static int handle_unregister_worker(struct qaffd_state *state,
                                    const struct qaff_control_msg *request) {
  if (request->worker_id >= QAFFD_MAX_WORKERS ||
      state->worker_fds[request->worker_id] < 0) {
    errno = ENOENT;
    return -1;
  }

  if (qaff_unregister_worker_socket(state->ctx, request->worker_id) != 0) {
    return -1;
  }

  close(state->worker_fds[request->worker_id]);
  state->worker_fds[request->worker_id] = -1;
  return 0;
}

static int handle_register_cid(struct qaffd_state *state,
                               const struct qaff_control_msg *request) {
  if (request->worker_id >= QAFFD_MAX_WORKERS ||
      state->worker_fds[request->worker_id] < 0) {
    errno = ENOENT;
    return -1;
  }

  return qaff_register_cid(state->ctx,
                           request->cid,
                           request->cid_len,
                           request->worker_id);
}

static int handle_request(struct qaffd_state *state, int client_fd) {
  struct qaff_control_msg request;
  int received_fd = -1;

  if (recv_request(client_fd, &request, &received_fd) != 0) {
    if (received_fd >= 0) {
      close(received_fd);
    }
    if (errno == ECONNRESET) {
      return 0;
    }
    return -1;
  }

  struct qaff_control_msg reply;
  reply_init(&reply, &request);

  if (request.magic != QAFF_CONTROL_MAGIC ||
      request.version != QAFF_CONTROL_VERSION) {
    reply.status = EPROTO;
  } else {
    switch (request.op) {
    case QAFF_CONTROL_REGISTER_WORKER:
      if (handle_register_worker(state, &request, received_fd) != 0) {
        reply.status = errno ? errno : EIO;
        if (received_fd >= 0) {
          close(received_fd);
        }
      } else {
        received_fd = -1;
      }
      break;
    case QAFF_CONTROL_UNREGISTER_WORKER:
      if (handle_unregister_worker(state, &request) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_REGISTER_CID:
      if (handle_register_cid(state, &request) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_RETIRE_CID:
      if (qaff_retire_cid(state->ctx, request.cid, request.cid_len) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_READ_STATS:
      if (qaff_read_stats(state->ctx, &reply.stats) != 0) {
        reply.status = errno ? errno : EIO;
      }
      break;
    case QAFF_CONTROL_HEALTH:
      fill_config_reply(state, &reply);
      break;
    case QAFF_CONTROL_CONFIG:
      fill_config_reply(state, &reply);
      break;
    case QAFF_CONTROL_WORKERS:
      fill_config_reply(state, &reply);
      fill_workers_reply(state, &reply);
      break;
    case QAFF_CONTROL_STOP:
      state->stop = 1;
      break;
    default:
      reply.status = ENOSYS;
      break;
    }
  }

  return write_exact(client_fd, &reply, sizeof(reply));
}

static int make_server_socket(const char *path) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(path) >= sizeof(addr.sun_path)) {
    close(fd);
    errno = ENAMETOOLONG;
    return -1;
  }
  strcpy(addr.sun_path, path);

  unlink(path);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  if (chmod(path, 0600) != 0) {
    close(fd);
    return -1;
  }

  if (listen(fd, 64) != 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static int accept_cloexec(int server_fd) {
  int fd;
  do {
    fd = accept(server_fd, NULL, NULL);
  } while (fd < 0 && errno == EINTR && !g_stop_requested);

  if (fd < 0) {
    return -1;
  }

  int flags = fcntl(fd, F_GETFD, 0);
  if (flags >= 0) {
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
  }
  return fd;
}

int main(int argc, char **argv) {
  struct qaffd_options daemon_options;
  if (parse_args(argc, argv, &daemon_options) != 0) {
    usage(stderr);
    return 2;
  }

  signal(SIGPIPE, SIG_IGN);
  if (install_signal_handlers() != 0) {
    perror("sigaction");
    return 1;
  }

  struct qaffd_state state;
  memset(&state, 0, sizeof(state));
  state.short_cid_len = daemon_options.short_cid_len;
  state.fallback_worker_id = daemon_options.fallback_worker_id;
  for (size_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    state.worker_fds[i] = -1;
  }

  struct qaff_options options;
  qaff_options_init(&options);
  options.short_cid_len = daemon_options.short_cid_len;
  options.fallback_worker_id = daemon_options.fallback_worker_id;

  if (qaff_open(&options, &state.ctx) != 0) {
    perror("qaff_open");
    return 1;
  }

  if (qaff_bpf_object_open(state.ctx,
                           daemon_options.bpf_object_path,
                           &state.bpf) != 0) {
    perror("qaff_bpf_object_open");
    qaff_close(state.ctx);
    return 1;
  }

  int server_fd = make_server_socket(daemon_options.socket_path);
  if (server_fd < 0) {
    perror("make_server_socket");
    qaff_bpf_object_close(state.bpf);
    qaff_close(state.ctx);
    return 1;
  }

  while (!state.stop && !g_stop_requested) {
    int client_fd = accept_cloexec(server_fd);
    if (client_fd < 0) {
      if (g_stop_requested) {
        break;
      }
      perror("accept4");
      break;
    }
    if (handle_request(&state, client_fd) != 0) {
      perror("handle_request");
    }
    close(client_fd);
  }

  close(server_fd);
  unlink(daemon_options.socket_path);
  for (size_t i = 0; i < QAFFD_MAX_WORKERS; i++) {
    if (state.worker_fds[i] >= 0) {
      close(state.worker_fds[i]);
    }
  }
  qaff_bpf_object_close(state.bpf);
  qaff_close(state.ctx);
  return 0;
}
