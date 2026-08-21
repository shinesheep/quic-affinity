#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "quic_affinity/control.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

#ifndef SO_PROTOCOL
#define SO_PROTOCOL 38
#endif

#ifndef SYS_pidfd_open
#if defined(__NR_pidfd_open)
#define SYS_pidfd_open __NR_pidfd_open
#elif defined(__x86_64__)
#define SYS_pidfd_open 434
#endif
#endif

#ifndef SYS_pidfd_getfd
#if defined(__NR_pidfd_getfd)
#define SYS_pidfd_getfd __NR_pidfd_getfd
#elif defined(__x86_64__)
#define SYS_pidfd_getfd 438
#endif
#endif

#define QAFF_AGENT_DISCOVERY_TIMEOUT_MS_DEFAULT 10000u
#define QAFF_AGENT_HEARTBEAT_MS_DEFAULT 1000u
#define QAFF_AGENT_SOCKET_CHECK_MS_DEFAULT 250u
#define QAFF_AGENT_READINESS_TIMEOUT_MS_DEFAULT 5000u
#define QAFF_AGENT_SCAN_INTERVAL_MS 50u
#define QAFF_AGENT_RECONNECT_INTERVAL_MS 100u

enum agent_mode {
  AGENT_MODE_NONE = 0,
  AGENT_MODE_WATCH,
  AGENT_MODE_RUN,
};

struct agent_options {
  enum agent_mode mode;
  const char *control_socket;
  const char *address_text;
  struct sockaddr_storage address;
  socklen_t address_len;
  pid_t target_pid;
  uint32_t worker_id;
  uint16_t port;
  uint64_t discovery_timeout_ms;
  uint64_t heartbeat_ms;
  uint64_t socket_check_ms;
  uint64_t readiness_timeout_ms;
  const char *readiness_command;
  char **command;
};

static volatile sig_atomic_t g_signal = 0;

static void handle_signal(int signo) {
  g_signal = signo;
}

static int install_signal_handlers(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handle_signal;
  if (sigemptyset(&action.sa_mask) != 0 ||
      sigaction(SIGINT, &action, NULL) != 0 ||
      sigaction(SIGTERM, &action, NULL) != 0 ||
      sigaction(SIGHUP, &action, NULL) != 0) {
    return -1;
  }
  signal(SIGPIPE, SIG_IGN);
  return 0;
}

static void usage(FILE *out) {
  fprintf(out,
          "Usage:\n"
          "  qaff-agent watch --socket PATH --pid PID --worker-id ID "
          "--address IP --port PORT [OPTIONS]\n"
          "  qaff-agent run --socket PATH --worker-id ID --address IP "
          "--port PORT [OPTIONS] -- COMMAND [ARG...]\n"
          "\n"
          "Options:\n"
          "  --discovery-timeout-ms N  Socket discovery timeout "
          "(default 10000)\n"
          "  --heartbeat-ms N          Lease heartbeat interval; 0 disables "
          "(default 1000)\n"
          "  --socket-check-ms N       Target socket identity check interval "
          "(default 250)\n"
          "  --readiness-command PATH  Run PATH not-ready/ready around lease "
          "state changes\n"
          "  --readiness-timeout-ms N  Readiness command timeout "
          "(default 5000)\n");
}

static int parse_u64(const char *text, uint64_t maximum, uint64_t *out) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value > maximum) {
    errno = EINVAL;
    return -1;
  }
  *out = (uint64_t)value;
  return 0;
}

static int parse_address(struct agent_options *options) {
  memset(&options->address, 0, sizeof(options->address));

  struct sockaddr_in *addr4 = (struct sockaddr_in *)&options->address;
  if (inet_pton(AF_INET, options->address_text, &addr4->sin_addr) == 1) {
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(options->port);
    options->address_len = sizeof(*addr4);
    return 0;
  }

  struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&options->address;
  if (inet_pton(AF_INET6, options->address_text, &addr6->sin6_addr) == 1) {
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(options->port);
    options->address_len = sizeof(*addr6);
    return 0;
  }

  errno = EINVAL;
  return -1;
}

static int parse_args(int argc, char **argv, struct agent_options *options) {
  memset(options, 0, sizeof(*options));
  options->discovery_timeout_ms =
      QAFF_AGENT_DISCOVERY_TIMEOUT_MS_DEFAULT;
  options->heartbeat_ms = QAFF_AGENT_HEARTBEAT_MS_DEFAULT;
  options->socket_check_ms = QAFF_AGENT_SOCKET_CHECK_MS_DEFAULT;
  options->readiness_timeout_ms =
      QAFF_AGENT_READINESS_TIMEOUT_MS_DEFAULT;

  if (argc < 2) {
    return -1;
  }
  if (strcmp(argv[1], "watch") == 0) {
    options->mode = AGENT_MODE_WATCH;
  } else if (strcmp(argv[1], "run") == 0) {
    options->mode = AGENT_MODE_RUN;
  } else {
    return -1;
  }

  int worker_id_set = 0;
  int port_set = 0;
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      if (options->mode != AGENT_MODE_RUN || i + 1 >= argc) {
        return -1;
      }
      options->command = &argv[i + 1];
      break;
    }
    if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
      options->control_socket = argv[++i];
    } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
      uint64_t value = 0;
      if (parse_u64(argv[++i], INT_MAX, &value) != 0 || value == 0) {
        return -1;
      }
      options->target_pid = (pid_t)value;
    } else if (strcmp(argv[i], "--worker-id") == 0 && i + 1 < argc) {
      uint64_t value = 0;
      if (parse_u64(argv[++i], UINT32_MAX, &value) != 0) {
        return -1;
      }
      options->worker_id = (uint32_t)value;
      worker_id_set = 1;
    } else if (strcmp(argv[i], "--address") == 0 && i + 1 < argc) {
      options->address_text = argv[++i];
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      uint64_t value = 0;
      if (parse_u64(argv[++i], UINT16_MAX, &value) != 0 || value == 0) {
        return -1;
      }
      options->port = (uint16_t)value;
      port_set = 1;
    } else if (strcmp(argv[i], "--discovery-timeout-ms") == 0 &&
               i + 1 < argc) {
      if (parse_u64(argv[++i], UINT32_MAX,
                    &options->discovery_timeout_ms) != 0 ||
          options->discovery_timeout_ms == 0) {
        return -1;
      }
    } else if (strcmp(argv[i], "--heartbeat-ms") == 0 &&
               i + 1 < argc) {
      if (parse_u64(argv[++i], UINT32_MAX, &options->heartbeat_ms) != 0) {
        return -1;
      }
    } else if (strcmp(argv[i], "--socket-check-ms") == 0 &&
               i + 1 < argc) {
      if (parse_u64(argv[++i], UINT32_MAX,
                    &options->socket_check_ms) != 0 ||
          options->socket_check_ms == 0) {
        return -1;
      }
    } else if (strcmp(argv[i], "--readiness-command") == 0 &&
               i + 1 < argc) {
      options->readiness_command = argv[++i];
      if (options->readiness_command[0] == '\0') {
        return -1;
      }
    } else if (strcmp(argv[i], "--readiness-timeout-ms") == 0 &&
               i + 1 < argc) {
      if (parse_u64(argv[++i], UINT32_MAX,
                    &options->readiness_timeout_ms) != 0 ||
          options->readiness_timeout_ms == 0) {
        return -1;
      }
    } else {
      return -1;
    }
  }

  if (options->control_socket == NULL ||
      options->address_text == NULL ||
      !worker_id_set ||
      !port_set ||
      (options->mode == AGENT_MODE_WATCH && options->target_pid <= 0) ||
      (options->mode == AGENT_MODE_RUN && options->command == NULL)) {
    return -1;
  }
  return parse_address(options);
}

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000u +
         (uint64_t)ts.tv_nsec / 1000000u;
}

static int pidfd_open_target(pid_t pid) {
#ifdef SYS_pidfd_open
  return (int)syscall(SYS_pidfd_open, pid, 0);
#else
  (void)pid;
  errno = ENOSYS;
  return -1;
#endif
}

static int pidfd_duplicate_fd(int pidfd, int target_fd) {
#ifdef SYS_pidfd_getfd
  int fd = (int)syscall(SYS_pidfd_getfd, pidfd, target_fd, 0);
  if (fd >= 0) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0) {
      int saved_errno = errno;
      close(fd);
      errno = saved_errno;
      return -1;
    }
  }
  return fd;
#else
  (void)pidfd;
  (void)target_fd;
  errno = ENOSYS;
  return -1;
#endif
}

static int sockaddr_matches(const struct sockaddr_storage *actual,
                            const struct agent_options *options) {
  if (actual->ss_family != options->address.ss_family) {
    return 0;
  }
  if (actual->ss_family == AF_INET) {
    const struct sockaddr_in *left = (const struct sockaddr_in *)actual;
    const struct sockaddr_in *right =
        (const struct sockaddr_in *)&options->address;
    return left->sin_port == right->sin_port &&
           left->sin_addr.s_addr == right->sin_addr.s_addr;
  }
  if (actual->ss_family == AF_INET6) {
    const struct sockaddr_in6 *left = (const struct sockaddr_in6 *)actual;
    const struct sockaddr_in6 *right =
        (const struct sockaddr_in6 *)&options->address;
    return left->sin6_port == right->sin6_port &&
           left->sin6_scope_id == right->sin6_scope_id &&
           memcmp(&left->sin6_addr,
                  &right->sin6_addr,
                  sizeof(left->sin6_addr)) == 0;
  }
  return 0;
}

static int is_target_socket(int fd, const struct agent_options *options) {
  int type = 0;
  socklen_t int_len = sizeof(type);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &int_len) != 0 ||
      type != SOCK_DGRAM) {
    return 0;
  }

  int reuseport = 0;
  int_len = sizeof(reuseport);
  if (getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, &int_len) != 0 ||
      reuseport == 0) {
    return 0;
  }

  int protocol = 0;
  int_len = sizeof(protocol);
  if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &int_len) == 0 &&
      protocol != IPPROTO_UDP) {
    return 0;
  }

  struct sockaddr_storage actual;
  memset(&actual, 0, sizeof(actual));
  socklen_t actual_len = sizeof(actual);
  if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) != 0) {
    return 0;
  }
  return sockaddr_matches(&actual, options);
}

static int read_socket_cookie(int fd, uint64_t *out) {
  uint64_t cookie = 0;
  socklen_t cookie_len = sizeof(cookie);
  if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &cookie_len) != 0) {
    return -1;
  }
  if (cookie_len != sizeof(cookie) || cookie == 0) {
    errno = EINVAL;
    return -1;
  }
  *out = cookie;
  return 0;
}

/*
 * Returns a duplicated listener fd, -1 on a hard error, or -2 when no
 * matching socket exists yet. More than one distinct matching socket is
 * rejected because one worker ID must identify exactly one reuseport socket.
 */
static int scan_target_fds(int pidfd,
                           pid_t pid,
                           const struct agent_options *options,
                           int *target_fd_out) {
  char path[64];
  int n = snprintf(path, sizeof(path), "/proc/%ld/fd", (long)pid);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  DIR *dir = opendir(path);
  if (dir == NULL) {
    return -1;
  }

  int selected = -1;
  int selected_target_fd = -1;
  uint64_t selected_cookie = 0;
  int cookie_valid = 0;
  int hard_errno = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    char *end = NULL;
    errno = 0;
    long target_fd_long = strtol(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0' ||
        target_fd_long < 0 || target_fd_long > INT_MAX) {
      continue;
    }

    int candidate =
        pidfd_duplicate_fd(pidfd, (int)target_fd_long);
    if (candidate < 0) {
      if (errno == EBADF || errno == ENOENT) {
        continue;
      }
      hard_errno = errno;
      break;
    }
    if (!is_target_socket(candidate, options)) {
      close(candidate);
      continue;
    }

    uint64_t cookie = 0;
    int this_cookie_valid = read_socket_cookie(candidate, &cookie) == 0;
    if (selected < 0) {
      selected = candidate;
      selected_target_fd = (int)target_fd_long;
      selected_cookie = cookie;
      cookie_valid = this_cookie_valid;
      continue;
    }
    if (cookie_valid && this_cookie_valid && cookie == selected_cookie) {
      close(candidate);
      continue;
    }

    close(candidate);
    close(selected);
    selected = -1;
    hard_errno = EEXIST;
    break;
  }

  int close_rc = closedir(dir);
  if (hard_errno != 0) {
    errno = hard_errno;
    return -1;
  }
  if (close_rc != 0) {
    if (selected >= 0) {
      close(selected);
    }
    return -1;
  }
  if (selected < 0) {
    errno = ENOENT;
    return -2;
  }
  *target_fd_out = selected_target_fd;
  return selected;
}

static int target_has_exited(int pidfd);

/* Returns 1 while the target still owns the socket, 0 after replacement. */
static int validate_target_socket(int pidfd,
                                  pid_t pid,
                                  const struct agent_options *options,
                                  uint64_t expected_cookie,
                                  int *target_fd_number) {
  int current_target_fd = -1;
  int current =
      scan_target_fds(pidfd, pid, options, &current_target_fd);
  if (current == -2) {
    errno = ESTALE;
    return 0;
  }
  if (current < 0) {
    if (errno == EEXIST) {
      errno = ESTALE;
      return 0;
    }
    if ((errno == ENOENT || errno == ESRCH) && target_has_exited(pidfd)) {
      errno = ESRCH;
    }
    return -1;
  }

  uint64_t current_cookie = 0;
  int cookie_rc = read_socket_cookie(current, &current_cookie);
  int saved_errno = errno;
  close(current);
  if (cookie_rc != 0) {
    errno = saved_errno;
    return -1;
  }
  if (current_cookie != expected_cookie) {
    errno = ESTALE;
    return 0;
  }
  *target_fd_number = current_target_fd;
  return 1;
}

static int target_has_exited(int pidfd) {
  struct pollfd pfd = {
    .fd = pidfd,
    .events = POLLIN,
  };
  int rc;
  do {
    rc = poll(&pfd, 1, 0);
  } while (rc < 0 && errno == EINTR && !g_signal);
  return rc > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR));
}

static int discover_socket(int pidfd,
                           pid_t pid,
                           const struct agent_options *options,
                           int *target_fd_out,
                           int retry_ambiguous) {
  uint64_t started = monotonic_ms();
  for (;;) {
    int fd = scan_target_fds(pidfd, pid, options, target_fd_out);
    if (fd >= 0) {
      return fd;
    }
    if (fd == -1 && !(retry_ambiguous && errno == EEXIST)) {
      return -1;
    }
    if (g_signal) {
      errno = EINTR;
      return -1;
    }
    if (target_has_exited(pidfd)) {
      errno = ESRCH;
      return -1;
    }
    uint64_t now = monotonic_ms();
    if (now == 0 || started == 0 ||
        now - started >= options->discovery_timeout_ms) {
      errno = ETIMEDOUT;
      return -1;
    }

    struct pollfd pfd = {
      .fd = pidfd,
      .events = POLLIN,
    };
    int timeout = QAFF_AGENT_SCAN_INTERVAL_MS;
    uint64_t remaining = options->discovery_timeout_ms - (now - started);
    if (remaining < (uint64_t)timeout) {
      timeout = (int)remaining;
    }
    int rc;
    do {
      rc = poll(&pfd, 1, timeout);
    } while (rc < 0 && errno == EINTR && !g_signal);
    if (rc < 0) {
      return -1;
    }
  }
}

static int wait_for_reconnect_window(int pidfd) {
  struct pollfd pfd = {
    .fd = pidfd,
    .events = POLLIN,
  };
  int rc;
  do {
    rc = poll(&pfd, 1, QAFF_AGENT_RECONNECT_INTERVAL_MS);
  } while (rc < 0 && errno == EINTR && !g_signal);
  if (rc < 0) {
    return -1;
  }
  if (rc > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
    errno = ESRCH;
    return -1;
  }
  if (g_signal) {
    errno = EINTR;
    return -1;
  }
  return 0;
}

static int reconnect_control(int pidfd,
                             int worker_fd,
                             const struct agent_options *options,
                             uint64_t worker_cookie,
                             int *target_fd_number) {
  int last_error = 0;
  int reported_error = 0;
  for (;;) {
    int socket_status = validate_target_socket(pidfd,
                                               options->target_pid,
                                               options,
                                               worker_cookie,
                                               target_fd_number);
    if (socket_status <= 0) {
      if (socket_status == 0) {
        errno = ESTALE;
      }
      return -1;
    }
    int fd = qaff_control_connect(options->control_socket);
    if (fd >= 0) {
      if (qaff_control_register_worker_lease_for_pid(
              fd,
              options->worker_id,
              worker_fd,
              (uint32_t)options->target_pid) == 0) {
        fprintf(stderr,
                "qaff-agent: restored worker_id=%u lease after qaffd "
                "disconnect\n",
                options->worker_id);
        return fd;
      }
      last_error = errno;
      close(fd);
    } else {
      last_error = errno;
    }
    if (last_error != reported_error) {
      fprintf(stderr,
              "qaff-agent: qaffd disconnected; retrying worker_id=%u "
              "registration: %s\n",
              options->worker_id,
              strerror(last_error));
      reported_error = last_error;
    }
    if (wait_for_reconnect_window(pidfd) != 0) {
      return -1;
    }
  }
}

static int run_readiness_command(const struct agent_options *options,
                                 const char *state);

static int monitor_target(int pidfd,
                          int *control_fd,
                          int worker_fd,
                          uint64_t worker_cookie,
                          int *target_fd_number,
                          int *readiness_ready,
                          const struct agent_options *options) {
  uint64_t last_socket_check_ms = monotonic_ms();
  uint64_t last_heartbeat_ms = last_socket_check_ms;
  for (;;) {
    if (g_signal) {
      errno = EINTR;
      return -1;
    }
    struct pollfd fds[2] = {
      {
        .fd = pidfd,
        .events = POLLIN,
      },
      {
        .fd = *control_fd,
        .events = POLLIN,
      },
    };
    int timeout = options->socket_check_ms > INT_MAX
                      ? INT_MAX
                      : (int)options->socket_check_ms;
    if (options->heartbeat_ms != 0 &&
        options->heartbeat_ms < (uint64_t)timeout) {
      timeout = (int)options->heartbeat_ms;
    }
    int rc;
    do {
      rc = poll(fds, 2, timeout);
    } while (rc < 0 && errno == EINTR && !g_signal);
    if (rc < 0) {
      return -1;
    }
    if (rc > 0 &&
        (fds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
      return 0;
    }
    int disconnected =
        rc > 0 &&
        (fds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL));
    uint64_t now = monotonic_ms();
    if (now == 0) {
      return -1;
    }
    if (now - last_socket_check_ms >= options->socket_check_ms) {
      int socket_status = validate_target_socket(pidfd,
                                                 options->target_pid,
                                                 options,
                                                 worker_cookie,
                                                 target_fd_number);
      if (socket_status <= 0) {
        if (socket_status == 0) {
          errno = ESTALE;
          return 1;
        }
        return -1;
      }
      last_socket_check_ms = now;
    }
    if (!disconnected && options->heartbeat_ms != 0 &&
        now - last_heartbeat_ms >= options->heartbeat_ms) {
      if (qaff_control_worker_heartbeat(*control_fd,
                                        options->worker_id) != 0) {
        disconnected = 1;
      } else {
        last_heartbeat_ms = now;
      }
    }
    if (disconnected) {
      if (*readiness_ready &&
          run_readiness_command(options, "not-ready") != 0) {
        return -1;
      }
      *readiness_ready = 0;
      close(*control_fd);
      *control_fd =
          reconnect_control(pidfd,
                            worker_fd,
                            options,
                            worker_cookie,
                            target_fd_number);
      if (*control_fd < 0) {
        if (errno == ESRCH) {
          return 0;
        }
        if (errno == ESTALE) {
          return 1;
        }
        return -1;
      }
      if (run_readiness_command(options, "ready") != 0) {
        return -1;
      }
      *readiness_ready = 1;
      last_heartbeat_ms = monotonic_ms();
    }
  }
}

static void revoke_worker_registration(const struct agent_options *options) {
  int fd = qaff_control_connect(options->control_socket);
  if (fd < 0) {
    return;
  }
  if (qaff_control_unregister_worker(fd, options->worker_id) != 0 &&
      errno != ENOENT) {
    fprintf(stderr,
            "qaff-agent: failed to revoke worker_id=%u registration: %s\n",
            options->worker_id,
            strerror(errno));
  }
  close(fd);
}

static int run_readiness_command(const struct agent_options *options,
                                 const char *state) {
  if (options->readiness_command == NULL) {
    return 0;
  }

  pid_t pid = fork();
  if (pid < 0) {
    return -1;
  }
  if (pid == 0) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);
    execl(options->readiness_command,
          options->readiness_command,
          state,
          (char *)NULL);
    perror("qaff-agent: readiness exec");
    _exit(127);
  }

  uint64_t started = monotonic_ms();
  for (;;) {
    int status = 0;
    pid_t waited = waitpid(pid, &status, WNOHANG);
    if (waited == pid) {
      if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
      }
      errno = EIO;
      return -1;
    }
    if (waited < 0) {
      return -1;
    }

    uint64_t now = monotonic_ms();
    if (now == 0 || started == 0 ||
        now - started >= options->readiness_timeout_ms) {
      int saved_errno = ETIMEDOUT;
      kill(pid, SIGKILL);
      do {
        waited = waitpid(pid, &status, 0);
      } while (waited < 0 && errno == EINTR);
      errno = saved_errno;
      return -1;
    }

    const struct timespec delay = {
      .tv_sec = 0,
      .tv_nsec = 20 * 1000 * 1000,
    };
    nanosleep(&delay, NULL);
  }
}

static pid_t spawn_target(char **command) {
  pid_t pid = fork();
  if (pid != 0) {
    return pid;
  }
  signal(SIGINT, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGHUP, SIG_DFL);
  signal(SIGPIPE, SIG_DFL);
  execvp(command[0], command);
  perror("qaff-agent: execvp");
  _exit(127);
}

static int reap_target(pid_t pid) {
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(pid, &status, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited < 0) {
    return 1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

int main(int argc, char **argv) {
  struct agent_options options;
  if (parse_args(argc, argv, &options) != 0) {
    usage(stderr);
    return 2;
  }
  if (install_signal_handlers() != 0) {
    perror("qaff-agent: sigaction");
    return 1;
  }

  if (run_readiness_command(&options, "not-ready") != 0) {
    perror("qaff-agent: readiness not-ready");
    return 1;
  }

  pid_t spawned_pid = -1;
  if (options.mode == AGENT_MODE_RUN) {
    spawned_pid = spawn_target(options.command);
    if (spawned_pid < 0) {
      perror("qaff-agent: fork");
      return 1;
    }
    options.target_pid = spawned_pid;
  }

  int pidfd = pidfd_open_target(options.target_pid);
  if (pidfd < 0) {
    perror("qaff-agent: pidfd_open");
    if (spawned_pid > 0) {
      kill(spawned_pid, SIGTERM);
      (void)reap_target(spawned_pid);
    }
    return 1;
  }

  int target_fd_number = -1;
  int worker_fd = -1;
  int control_fd = -1;
  int monitor_rc = -1;
  int monitor_errno = 0;
  int registered_once = 0;
  int readiness_ready = 0;

  for (;;) {
    worker_fd = discover_socket(pidfd,
                                options.target_pid,
                                &options,
                                &target_fd_number,
                                registered_once);
    if (worker_fd < 0) {
      monitor_errno = errno;
      if (monitor_errno == ESRCH) {
        monitor_rc = 0;
      } else {
        monitor_rc = -1;
        perror("qaff-agent: discover UDP SO_REUSEPORT socket");
      }
      break;
    }

    uint64_t worker_cookie = 0;
    if (read_socket_cookie(worker_fd, &worker_cookie) != 0) {
      monitor_rc = -1;
      monitor_errno = errno;
      perror("qaff-agent: read target socket cookie");
      break;
    }

    control_fd = qaff_control_connect(options.control_socket);
    if (control_fd < 0) {
      monitor_rc = -1;
      monitor_errno = errno;
      perror("qaff-agent: qaff_control_connect");
      break;
    }
    int replacing_socket = registered_once;
    if (qaff_control_register_worker_lease_for_pid(
            control_fd,
            options.worker_id,
            worker_fd,
            (uint32_t)options.target_pid) != 0) {
      monitor_rc = -1;
      monitor_errno = errno;
      perror("qaff-agent: qaff_control_register_worker_lease");
      break;
    }
    registered_once = 1;
    if (run_readiness_command(&options, "ready") != 0) {
      monitor_rc = -1;
      monitor_errno = errno;
      perror("qaff-agent: readiness ready");
      break;
    }
    readiness_ready = 1;
    fprintf(stderr,
            "qaff-agent: %s worker_id=%u target_pid=%ld target_fd=%d "
            "listen=%s:%u\n",
            replacing_socket ? "re-registered" : "registered",
            options.worker_id,
            (long)options.target_pid,
            target_fd_number,
            options.address_text,
            options.port);
    monitor_rc = monitor_target(pidfd,
                                &control_fd,
                                worker_fd,
                                worker_cookie,
                                &target_fd_number,
                                &readiness_ready,
                                &options);
    monitor_errno = errno;
    if (monitor_rc != 1) {
      break;
    }

    if (run_readiness_command(&options, "not-ready") != 0) {
      monitor_rc = -1;
      monitor_errno = errno;
      perror("qaff-agent: readiness not-ready");
      break;
    }
    readiness_ready = 0;

    fprintf(stderr,
            "qaff-agent: target socket changed; revoking worker_id=%u "
            "target_pid=%ld\n",
            options.worker_id,
            (long)options.target_pid);
    revoke_worker_registration(&options);
    if (control_fd >= 0) {
      close(control_fd);
    }
    control_fd = -1;
    close(worker_fd);
    worker_fd = -1;
  }
  if (readiness_ready &&
      run_readiness_command(&options, "not-ready") != 0) {
    int saved_errno = errno;
    perror("qaff-agent: readiness not-ready");
    if (monitor_rc == 0) {
      monitor_rc = -1;
      monitor_errno = saved_errno;
    }
  }
  if (g_signal && spawned_pid > 0) {
    kill(spawned_pid, g_signal);
  } else if (monitor_rc < 0 && spawned_pid > 0) {
    kill(spawned_pid, SIGTERM);
  }

  if (monitor_rc < 0 && registered_once && !g_signal) {
    revoke_worker_registration(&options);
  }
  if (control_fd >= 0) {
    close(control_fd);
  }
  if (worker_fd >= 0) {
    close(worker_fd);
  }
  close(pidfd);

  if (spawned_pid > 0) {
    int child_rc = reap_target(spawned_pid);
    if (monitor_rc != 0 && monitor_errno != EINTR) {
      errno = monitor_errno;
      perror("qaff-agent: monitor");
      return 1;
    }
    return child_rc;
  }
  if (monitor_rc != 0 && monitor_errno != EINTR) {
    errno = monitor_errno;
    perror("qaff-agent: monitor");
    return 1;
  }
  return g_signal ? 128 + g_signal : 0;
}
