#define _POSIX_C_SOURCE 200809L

#include "state_store.h"

#include "quic_affinity/types.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_WORKERS 8u

static int expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "state store test failed: %s\n", message);
    return -1;
  }
  return 0;
}

static int write_all(int fd, const void *data, size_t len) {
  const char *cursor = data;
  while (len > 0) {
    ssize_t written = write(fd, cursor, len);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    cursor += written;
    len -= (size_t)written;
  }
  return 0;
}

static int write_fixture(const char *path, const void *data, size_t len) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    return -1;
  }
  int rc = write_all(fd, data, len);
  int saved_errno = errno;
  if (close(fd) != 0 && rc == 0) {
    return -1;
  }
  errno = saved_errno;
  return rc;
}

static int load_fixture(const char *path, int registered[TEST_WORKERS],
                        uint64_t registered_at[TEST_WORKERS],
                        uint64_t last_seen[TEST_WORKERS],
                        uint32_t generations[TEST_WORKERS]) {
  return qaffd_state_store_load(path, registered, registered_at, last_seen,
                                generations, TEST_WORKERS, 1234);
}

struct fault_context {
  size_t max_write;
  size_t fail_after;
  size_t written;
  int inject_eintr;
  int inject_zero_write;
  int fsync_failure_call;
  int fsync_calls;
  int rename_failure;
};

static ssize_t fault_write(void *opaque, int fd, const void *data, size_t len) {
  struct fault_context *context = opaque;
  if (context->inject_eintr) {
    context->inject_eintr = 0;
    errno = EINTR;
    return -1;
  }
  if (context->inject_zero_write) {
    context->inject_zero_write = 0;
    return 0;
  }
  if (context->written >= context->fail_after) {
    errno = ENOSPC;
    return -1;
  }
  size_t allowed = len;
  if (context->max_write > 0 && allowed > context->max_write) {
    allowed = context->max_write;
  }
  size_t remaining = context->fail_after - context->written;
  if (allowed > remaining) {
    allowed = remaining;
  }
  ssize_t result = write(fd, data, allowed);
  if (result > 0) {
    context->written += (size_t)result;
  }
  return result;
}

static int fault_fsync(void *opaque, int fd) {
  struct fault_context *context = opaque;
  context->fsync_calls++;
  if (context->fsync_calls == context->fsync_failure_call) {
    errno = EIO;
    return -1;
  }
  return fsync(fd);
}

static int fault_rename(void *opaque, const char *old_path,
                        const char *new_path) {
  struct fault_context *context = opaque;
  if (context->rename_failure) {
    errno = EXDEV;
    return -1;
  }
  return rename(old_path, new_path);
}

static struct qaffd_state_store_io
make_fault_io(struct fault_context *context) {
  return (struct qaffd_state_store_io){
      .context = context,
      .write_fn = fault_write,
      .fsync_fn = fault_fsync,
      .rename_fn = fault_rename,
  };
}

static int save_snapshot(const char *path, uint32_t worker_id,
                         uint32_t generation,
                         const struct qaffd_state_store_io *io) {
  int registered[TEST_WORKERS] = {0};
  uint32_t generations[TEST_WORKERS] = {0};
  registered[worker_id] = 1;
  generations[worker_id] = generation;
  return io == NULL ? qaffd_state_store_save(path, registered, generations,
                                             TEST_WORKERS)
                    : qaffd_state_store_save_with_io(
                          path, registered, generations, TEST_WORKERS, io);
}

static int expect_snapshot(const char *path, uint32_t worker_id,
                           uint32_t generation, const char *message) {
  int registered[TEST_WORKERS] = {0};
  uint64_t registered_at[TEST_WORKERS] = {0};
  uint64_t last_seen[TEST_WORKERS] = {0};
  uint32_t generations[TEST_WORKERS] = {0};
  if (load_fixture(path, registered, registered_at, last_seen, generations) !=
      0) {
    return -1;
  }
  for (size_t i = 0; i < TEST_WORKERS; i++) {
    int expected_registered = i == worker_id;
    uint32_t expected_generation = i == worker_id ? generation : 0;
    uint64_t expected_time = i == worker_id ? 1234 : 0;
    if (registered[i] != expected_registered ||
        generations[i] != expected_generation ||
        registered_at[i] != expected_time || last_seen[i] != expected_time) {
      return expect(0, message);
    }
  }
  return 0;
}

static int count_temporary_files(const char *directory) {
  DIR *dir = opendir(directory);
  if (dir == NULL) {
    return -1;
  }
  int count = 0;
  errno = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strncmp(entry->d_name, "state.tmp.", 10) == 0) {
      count++;
    }
  }
  int saved_errno = errno;
  if (closedir(dir) != 0) {
    return -1;
  }
  errno = saved_errno;
  return saved_errno == 0 ? count : -1;
}

static int expect_injected_save(const char *directory, const char *path,
                                struct fault_context *context,
                                int expected_result, int expected_errno,
                                int expect_new_snapshot, const char *message) {
  if (save_snapshot(path, 1, 3, NULL) != 0) {
    return -1;
  }
  struct qaffd_state_store_io io = make_fault_io(context);
  errno = 0;
  int rc = save_snapshot(path, 6, 8, &io);
  int saved_errno = errno;
  if (expect(rc == expected_result && saved_errno == expected_errno, message) !=
          0 ||
      expect_snapshot(path, expect_new_snapshot ? 6 : 1,
                      expect_new_snapshot ? 8 : 3, message) != 0 ||
      expect(count_temporary_files(directory) == 0,
             "save leaves no temporary file") != 0) {
    return -1;
  }
  return 0;
}

static int test_save_faults(const char *directory, const char *path) {
  struct fault_context short_write = {
      .max_write = 2,
      .fail_after = SIZE_MAX,
      .inject_eintr = 1,
  };
  struct qaffd_state_store_io short_write_io = make_fault_io(&short_write);
  if (save_snapshot(path, 6, 8, &short_write_io) != 0 ||
      expect(short_write.written > 2 && short_write.fsync_calls == 2,
             "short writes and EINTR are retried") != 0 ||
      expect_snapshot(path, 6, 8, "short-write snapshot is complete") != 0 ||
      expect(count_temporary_files(directory) == 0,
             "successful save leaves no temporary file") != 0) {
    return -1;
  }

  const struct qaffd_state_store_io incomplete_io = {0};
  errno = 0;
  int incomplete_rc = save_snapshot(path, 1, 3, &incomplete_io);
  int incomplete_errno = errno;
  if (expect(incomplete_rc == QAFFD_STATE_STORE_SAVE_ERROR &&
                 incomplete_errno == EINVAL,
             "incomplete filesystem callbacks are rejected") != 0 ||
      expect_snapshot(path, 6, 8,
                      "invalid callbacks preserve the old snapshot") != 0 ||
      expect(count_temporary_files(directory) == 0,
             "invalid callbacks create no temporary file") != 0) {
    return -1;
  }

  struct fault_context zero_write = {
      .fail_after = SIZE_MAX,
      .inject_zero_write = 1,
  };
  if (expect_injected_save(directory, path, &zero_write,
                           QAFFD_STATE_STORE_SAVE_ERROR, EIO, 0,
                           "zero-length write is rejected") != 0) {
    return -1;
  }

  struct fault_context write_failure = {
      .max_write = 3,
      .fail_after = 5,
  };
  if (expect_injected_save(directory, path, &write_failure,
                           QAFFD_STATE_STORE_SAVE_ERROR, ENOSPC, 0,
                           "partial write preserves the old snapshot") != 0) {
    return -1;
  }

  struct fault_context file_fsync_failure = {
      .fail_after = SIZE_MAX,
      .fsync_failure_call = 1,
  };
  if (expect_injected_save(
          directory, path, &file_fsync_failure, QAFFD_STATE_STORE_SAVE_ERROR,
          EIO, 0, "file fsync failure preserves the old snapshot") != 0) {
    return -1;
  }

  struct fault_context rename_failure = {
      .fail_after = SIZE_MAX,
      .rename_failure = 1,
  };
  if (expect_injected_save(directory, path, &rename_failure,
                           QAFFD_STATE_STORE_SAVE_ERROR, EXDEV, 0,
                           "rename failure preserves the old snapshot") != 0) {
    return -1;
  }

  struct fault_context directory_fsync_failure = {
      .fail_after = SIZE_MAX,
      .fsync_failure_call = 2,
  };
  return expect_injected_save(
      directory, path, &directory_fsync_failure,
      QAFFD_STATE_STORE_SAVE_COMMITTED_UNSYNCED, EIO, 1,
      "directory fsync failure reports uncertain durability after commit");
}

static int test_round_trip(const char *path) {
  int registered[TEST_WORKERS] = {0};
  uint32_t generations[TEST_WORKERS] = {0};
  registered[1] = 1;
  generations[1] = 3;
  generations[5] = 9;
  if (qaffd_state_store_save(path, registered, generations, TEST_WORKERS) !=
      0) {
    perror("qaffd_state_store_save");
    return -1;
  }

  struct stat st;
  if (stat(path, &st) != 0 ||
      expect((st.st_mode & 0777) == 0600, "snapshot mode is 0600") != 0) {
    return -1;
  }

  int loaded_registered[TEST_WORKERS];
  uint64_t registered_at[TEST_WORKERS];
  uint64_t last_seen[TEST_WORKERS];
  uint32_t loaded_generations[TEST_WORKERS];
  memset(loaded_registered, 0x7f, sizeof(loaded_registered));
  memset(registered_at, 0x7f, sizeof(registered_at));
  memset(last_seen, 0x7f, sizeof(last_seen));
  memset(loaded_generations, 0x7f, sizeof(loaded_generations));
  if (load_fixture(path, loaded_registered, registered_at, last_seen,
                   loaded_generations) != 0) {
    perror("qaffd_state_store_load");
    return -1;
  }
  if (expect(loaded_registered[1] == 1 && loaded_generations[1] == 3,
             "registered worker round trip") != 0 ||
      expect(registered_at[1] == 1234 && last_seen[1] == 1234,
             "recovered worker timestamps") != 0 ||
      expect(loaded_registered[5] == 0 && loaded_generations[5] == 9,
             "generation tombstone round trip") != 0 ||
      expect(loaded_registered[0] == 0 && loaded_generations[0] == 0 &&
                 registered_at[0] == 0 && last_seen[0] == 0,
             "load replaces prior in-memory contents") != 0) {
    return -1;
  }

  memset(registered, 0, sizeof(registered));
  memset(generations, 0, sizeof(generations));
  registered[7] = 1;
  generations[7] = 11;
  if (qaffd_state_store_save(path, registered, generations, TEST_WORKERS) !=
          0 ||
      load_fixture(path, loaded_registered, registered_at, last_seen,
                   loaded_generations) != 0) {
    return -1;
  }
  return expect(loaded_registered[1] == 0 && loaded_generations[1] == 0 &&
                    loaded_registered[7] == 1 && loaded_generations[7] == 11,
                "atomic replacement does not retain old records");
}

static int arrays_unchanged(const int registered[TEST_WORKERS],
                            const uint64_t registered_at[TEST_WORKERS],
                            const uint64_t last_seen[TEST_WORKERS],
                            const uint32_t generations[TEST_WORKERS]) {
  for (size_t i = 0; i < TEST_WORKERS; i++) {
    if (registered[i] != 7 || registered_at[i] != 8 || last_seen[i] != 9 ||
        generations[i] != 10) {
      return 0;
    }
  }
  return 1;
}

static int expect_invalid_fixture(const char *path, const void *data,
                                  size_t len, const char *message) {
  if (write_fixture(path, data, len) != 0) {
    return -1;
  }
  int registered[TEST_WORKERS];
  uint64_t registered_at[TEST_WORKERS];
  uint64_t last_seen[TEST_WORKERS];
  uint32_t generations[TEST_WORKERS];
  for (size_t i = 0; i < TEST_WORKERS; i++) {
    registered[i] = 7;
    registered_at[i] = 8;
    last_seen[i] = 9;
    generations[i] = 10;
  }
  errno = 0;
  int rc =
      load_fixture(path, registered, registered_at, last_seen, generations);
  return expect(
      rc == -1 && errno == EINVAL &&
          arrays_unchanged(registered, registered_at, last_seen, generations),
      message);
}

static int test_invalid_inputs(const char *path) {
  static const char bad_header[] = "qaffd-state-v3\nworker 1 1\n";
  static const char duplicate[] = "qaffd-state\nworker 1 1\ngeneration 1 2\n";
  static const char out_of_range[] = "qaffd-state\nworker 8 1\n";
  static const char zero_generation[] = "qaffd-state\nworker 1 0\n";
  static const char leading_zero[] = "qaffd-state\nworker 01 1\n";
  static const char trailing[] = "qaffd-state\nworker 1 1 extra\n";
  static const char missing_newline[] = "qaffd-state\nworker 1 1";
  static const char embedded_nul[] = "qaffd-state\nworker 1 1\0ignored\n";
  char excessive_generation[96];
  int n = snprintf(excessive_generation, sizeof(excessive_generation),
                   "qaffd-state\nworker 1 %llu\n",
                   (unsigned long long)QAFF_WORKER_GENERATION_MAX + 1);
  if (n < 0 || (size_t)n >= sizeof(excessive_generation)) {
    return -1;
  }

  int registered[TEST_WORKERS] = {0};
  uint64_t registered_at[TEST_WORKERS] = {0};
  uint64_t last_seen[TEST_WORKERS] = {0};
  uint32_t generations[TEST_WORKERS] = {0};
  errno = 0;
  if (expect(qaffd_state_store_save("", registered, generations,
                                    TEST_WORKERS) == -1 &&
                 errno == EINVAL,
             "empty save path is rejected") != 0) {
    return -1;
  }
  errno = 0;
  if (expect(load_fixture("", registered, registered_at, last_seen,
                          generations) == -1 &&
                 errno == EINVAL,
             "empty load path is rejected") != 0) {
    return -1;
  }

  return expect_invalid_fixture(
             path, bad_header, sizeof(bad_header) - 1,
             "obsolete header is rejected transactionally") == 0 &&
                 expect_invalid_fixture(path, duplicate, sizeof(duplicate) - 1,
                                        "duplicate worker is rejected") == 0 &&
                 expect_invalid_fixture(
                     path, out_of_range, sizeof(out_of_range) - 1,
                     "out-of-range worker is rejected") == 0 &&
                 expect_invalid_fixture(path, zero_generation,
                                        sizeof(zero_generation) - 1,
                                        "zero generation is rejected") == 0 &&
                 expect_invalid_fixture(
                     path, leading_zero, sizeof(leading_zero) - 1,
                     "non-canonical decimal is rejected") == 0 &&
                 expect_invalid_fixture(path, excessive_generation, (size_t)n,
                                        "excessive generation is rejected") ==
                     0 &&
                 expect_invalid_fixture(path, trailing, sizeof(trailing) - 1,
                                        "trailing fields are rejected") == 0 &&
                 expect_invalid_fixture(
                     path, missing_newline, sizeof(missing_newline) - 1,
                     "truncated final record is rejected") == 0 &&
                 expect_invalid_fixture(path, embedded_nul,
                                        sizeof(embedded_nul) - 1,
                                        "embedded NUL is rejected") == 0
             ? 0
             : -1;
}

static int test_file_security(const char *directory, const char *path,
                              const char *target_path) {
  static const char valid[] = "qaffd-state\nworker 1 1\n";
  if (write_fixture(path, valid, sizeof(valid) - 1) != 0 ||
      chmod(path, 0644) != 0) {
    return -1;
  }
  int registered[TEST_WORKERS] = {0};
  uint64_t registered_at[TEST_WORKERS] = {0};
  uint64_t last_seen[TEST_WORKERS] = {0};
  uint32_t generations[TEST_WORKERS] = {0};
  errno = 0;
  if (expect(load_fixture(path, registered, registered_at, last_seen,
                          generations) == -1 &&
                 errno == EACCES,
             "group/world-readable state is rejected") != 0 ||
      chmod(path, 0600) != 0 || symlink(path, target_path) != 0) {
    return -1;
  }
  errno = 0;
  if (expect(load_fixture(target_path, registered, registered_at, last_seen,
                          generations) == -1 &&
                 errno == ELOOP,
             "state symlink is rejected") != 0) {
    return -1;
  }

  char directory_target[512];
  int n = snprintf(directory_target, sizeof(directory_target),
                   "%s/state-directory", directory);
  if (n < 0 || (size_t)n >= sizeof(directory_target) ||
      mkdir(directory_target, 0700) != 0) {
    return -1;
  }
  registered[1] = 1;
  generations[1] = 1;
  errno = 0;
  int rc = qaffd_state_store_save(directory_target, registered, generations,
                                  TEST_WORKERS);
  int saved_errno = errno;
  if (rmdir(directory_target) != 0) {
    return -1;
  }
  errno = saved_errno;
  return expect(rc == -1, "failed rename is reported");
}

int main(void) {
  char directory[] = "/tmp/qaffd-state-store-XXXXXX";
  if (mkdtemp(directory) == NULL) {
    perror("mkdtemp");
    return 1;
  }
  char path[512];
  char symlink_path[512];
  if (snprintf(path, sizeof(path), "%s/state", directory) < 0 ||
      snprintf(symlink_path, sizeof(symlink_path), "%s/link", directory) < 0) {
    return 1;
  }

  int rc = test_round_trip(path) != 0 ||
           test_save_faults(directory, path) != 0 ||
           test_invalid_inputs(path) != 0 ||
           test_file_security(directory, path, symlink_path) != 0;
  unlink(symlink_path);
  unlink(path);
  if (rmdir(directory) != 0) {
    perror("rmdir");
    rc = 1;
  }
  if (rc != 0) {
    return 1;
  }
  puts("qaffd state store tests passed");
  return 0;
}
