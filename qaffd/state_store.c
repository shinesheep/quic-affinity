#define _POSIX_C_SOURCE 200809L

#include "state_store.h"

#include "quic_affinity/wire.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int validate_state(const int *worker_registered,
                          const uint32_t *worker_generations,
                          size_t worker_capacity) {
  if (worker_registered == NULL || worker_generations == NULL ||
      worker_capacity == 0 || worker_capacity > UINT32_MAX) {
    errno = EINVAL;
    return -1;
  }
  for (size_t i = 0; i < worker_capacity; i++) {
    if ((worker_registered[i] != 0 && worker_registered[i] != 1) ||
        worker_generations[i] > QAFF_WORKER_GENERATION_MAX ||
        (worker_registered[i] && worker_generations[i] == 0)) {
      errno = EINVAL;
      return -1;
    }
  }
  return 0;
}

static ssize_t system_write(void *context, int fd, const void *data,
                            size_t len) {
  (void)context;
  return write(fd, data, len);
}

static int system_fsync(void *context, int fd) {
  (void)context;
  return fsync(fd);
}

static int system_rename(void *context, const char *old_path,
                         const char *new_path) {
  (void)context;
  return rename(old_path, new_path);
}

static const struct qaffd_state_store_io system_io = {
    .write_fn = system_write,
    .fsync_fn = system_fsync,
    .rename_fn = system_rename,
};

static int write_all(const struct qaffd_state_store_io *io, int fd,
                     const void *data, size_t len) {
  const uint8_t *cursor = data;
  while (len > 0) {
    ssize_t written = io->write_fn(io->context, fd, cursor, len);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (written == 0 || (size_t)written > len) {
      errno = EIO;
      return -1;
    }
    cursor += written;
    len -= (size_t)written;
  }
  return 0;
}

static int fsync_parent_directory(const char *path,
                                  const struct qaffd_state_store_io *io) {
  char parent[PATH_MAX];
  size_t len = strlen(path);
  if (len == 0 || len >= sizeof(parent)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memcpy(parent, path, len + 1);

  char *slash = strrchr(parent, '/');
  if (slash == NULL) {
    memcpy(parent, ".", 2);
  } else if (slash == parent) {
    slash[1] = '\0';
  } else {
    *slash = '\0';
  }

  int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  int rc = io->fsync_fn(io->context, fd);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return rc;
}

int qaffd_state_store_save(const char *path, const int *worker_registered,
                           const uint32_t *worker_generations,
                           size_t worker_capacity) {
  return qaffd_state_store_save_with_io(
      path, worker_registered, worker_generations, worker_capacity, &system_io);
}

int qaffd_state_store_save_with_io(const char *path,
                                   const int *worker_registered,
                                   const uint32_t *worker_generations,
                                   size_t worker_capacity,
                                   const struct qaffd_state_store_io *io) {
  if (path == NULL) {
    return 0;
  }
  if (path[0] == '\0' || io == NULL || io->write_fn == NULL ||
      io->fsync_fn == NULL || io->rename_fn == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (validate_state(worker_registered, worker_generations, worker_capacity) !=
      0) {
    return -1;
  }

  char tmp_path[PATH_MAX];
  int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", path);
  if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  int fd = mkstemp(tmp_path);
  if (fd < 0) {
    return -1;
  }
  int fd_flags = fcntl(fd, F_GETFD, 0);
  if (fd_flags < 0 || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) != 0 ||
      fchmod(fd, 0600) != 0) {
    int saved_errno = errno;
    close(fd);
    unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }

  static const char header[] = "qaffd-state\n";
  int rc = write_all(io, fd, header, sizeof(header) - 1);
  for (uint32_t i = 0; rc == 0 && i < worker_capacity; i++) {
    char line[64];
    int line_len = 0;
    if (worker_registered[i]) {
      line_len = snprintf(line, sizeof(line), "worker %u %u\n", i,
                          worker_generations[i]);
    } else if (worker_generations[i] != 0) {
      line_len = snprintf(line, sizeof(line), "generation %u %u\n", i,
                          worker_generations[i]);
    } else {
      continue;
    }
    if (line_len < 0 || (size_t)line_len >= sizeof(line)) {
      errno = EOVERFLOW;
      rc = -1;
    } else {
      rc = write_all(io, fd, line, (size_t)line_len);
    }
  }

  if (rc == 0 && io->fsync_fn(io->context, fd) != 0) {
    rc = -1;
  }
  int saved_errno = errno;
  if (close(fd) != 0 && rc == 0) {
    rc = -1;
    saved_errno = errno;
  }
  if (rc != 0) {
    unlink(tmp_path);
    errno = saved_errno ? saved_errno : EIO;
    return -1;
  }
  if (io->rename_fn(io->context, tmp_path, path) != 0) {
    saved_errno = errno;
    unlink(tmp_path);
    errno = saved_errno;
    return -1;
  }
  if (fsync_parent_directory(path, io) != 0) {
    return QAFFD_STATE_STORE_SAVE_COMMITTED_UNSYNCED;
  }
  return QAFFD_STATE_STORE_SAVE_OK;
}

static int parse_u32(const char **cursor, uint32_t *value) {
  if (**cursor < '0' || **cursor > '9') {
    errno = EINVAL;
    return -1;
  }
  if (**cursor == '0' && (*cursor)[1] >= '0' && (*cursor)[1] <= '9') {
    errno = EINVAL;
    return -1;
  }
  errno = 0;
  char *end = NULL;
  unsigned long parsed = strtoul(*cursor, &end, 10);
  if (errno != 0 || end == *cursor || parsed > UINT32_MAX) {
    errno = EINVAL;
    return -1;
  }
  *cursor = end;
  *value = (uint32_t)parsed;
  return 0;
}

static int parse_record(const char *line, int *registered, uint32_t *worker_id,
                        uint32_t *generation) {
  const char *cursor;
  if (strncmp(line, "worker ", 7) == 0) {
    *registered = 1;
    cursor = line + 7;
  } else if (strncmp(line, "generation ", 11) == 0) {
    *registered = 0;
    cursor = line + 11;
  } else {
    errno = EINVAL;
    return -1;
  }
  if (parse_u32(&cursor, worker_id) != 0 || *cursor++ != ' ' ||
      parse_u32(&cursor, generation) != 0 || strcmp(cursor, "\n") != 0) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

static int open_state_file(const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != geteuid() ||
      (st.st_mode & 0077) != 0) {
    close(fd);
    errno = EACCES;
    return -1;
  }
  return fd;
}

int qaffd_state_store_load(const char *path, int *worker_registered,
                           uint64_t *worker_registered_at_ms,
                           uint64_t *worker_last_seen_ms,
                           uint32_t *worker_generations, size_t worker_capacity,
                           uint64_t loaded_at_ms) {
  if (path == NULL) {
    return 0;
  }
  if (path[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  if (worker_registered == NULL || worker_registered_at_ms == NULL ||
      worker_last_seen_ms == NULL || worker_generations == NULL ||
      worker_capacity == 0 || worker_capacity > UINT32_MAX) {
    errno = EINVAL;
    return -1;
  }

  int fd = open_state_file(path);
  if (fd < 0) {
    return errno == ENOENT ? 0 : -1;
  }
  FILE *in = fdopen(fd, "r");
  if (in == NULL) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }

  int *loaded_registered = calloc(worker_capacity, sizeof(*loaded_registered));
  uint32_t *loaded_generations =
      calloc(worker_capacity, sizeof(*loaded_generations));
  uint8_t *seen_workers = calloc(worker_capacity, sizeof(*seen_workers));
  if (loaded_registered == NULL || loaded_generations == NULL ||
      seen_workers == NULL) {
    int saved_errno = errno ? errno : ENOMEM;
    free(loaded_registered);
    free(loaded_generations);
    free(seen_workers);
    fclose(in);
    errno = saved_errno;
    return -1;
  }

  int rc = 0;
  char *line = NULL;
  size_t line_cap = 0;
  ssize_t line_len = getline(&line, &line_cap, in);
  if (line_len < 0 || (size_t)line_len != strlen(line) ||
      strcmp(line, "qaffd-state\n") != 0) {
    errno = EINVAL;
    rc = -1;
  }

  while (rc == 0 && (line_len = getline(&line, &line_cap, in)) >= 0) {
    if ((size_t)line_len != strlen(line) || line_len == 0 ||
        line[line_len - 1] != '\n') {
      errno = EINVAL;
      rc = -1;
      break;
    }
    int registered;
    uint32_t worker_id;
    uint32_t generation;
    if (parse_record(line, &registered, &worker_id, &generation) != 0 ||
        worker_id >= worker_capacity || seen_workers[worker_id] ||
        generation == 0 || generation > QAFF_WORKER_GENERATION_MAX) {
      errno = EINVAL;
      rc = -1;
      break;
    }
    seen_workers[worker_id] = 1;
    loaded_registered[worker_id] = registered;
    loaded_generations[worker_id] = generation;
  }
  if (rc == 0 && ferror(in)) {
    rc = -1;
  }

  int saved_errno = errno;
  free(line);
  if (fclose(in) != 0 && rc == 0) {
    rc = -1;
    saved_errno = errno;
  }
  if (rc == 0) {
    memset(worker_registered, 0, worker_capacity * sizeof(*worker_registered));
    memset(worker_registered_at_ms, 0,
           worker_capacity * sizeof(*worker_registered_at_ms));
    memset(worker_last_seen_ms, 0,
           worker_capacity * sizeof(*worker_last_seen_ms));
    memcpy(worker_generations, loaded_generations,
           worker_capacity * sizeof(*worker_generations));
    for (size_t i = 0; i < worker_capacity; i++) {
      if (loaded_registered[i]) {
        worker_registered[i] = 1;
        worker_registered_at_ms[i] = loaded_at_ms;
        worker_last_seen_ms[i] = loaded_at_ms;
      }
    }
  }
  free(loaded_registered);
  free(loaded_generations);
  free(seen_workers);
  if (rc != 0) {
    errno = saved_errno ? saved_errno : EIO;
  }
  return rc;
}
