#include "authorization.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

static int expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "authorization test failed: %s\n", message);
    return -1;
  }
  return 0;
}

static int test_worker_rules(void) {
  struct qaffd_peer_cred peer = {
      .valid = 1,
      .pid = 100,
      .uid = 200,
      .gid = 300,
  };
  struct qaffd_auth_rule rule = {0};
  if (expect(qaffd_auth_worker_registration(&rule, NULL) == 0,
             "unconfigured worker rule allows registration") != 0) {
    return -1;
  }

  rule.uid_set = 1;
  rule.uid = peer.uid;
  if (expect(qaffd_auth_worker_registration(&rule, &peer) == 0,
             "matching worker UID") != 0) {
    return -1;
  }
  rule.gid_set = 1;
  rule.gid = peer.gid;
  if (expect(qaffd_auth_worker_registration(&rule, &peer) == 0,
             "matching worker UID and GID") != 0) {
    return -1;
  }
  rule.gid++;
  errno = 0;
  return expect(qaffd_auth_worker_registration(&rule, &peer) == -1 &&
                    errno == EACCES,
                "worker rule rejects a mismatched GID");
}

static int test_admin_rules(void) {
  struct qaffd_peer_cred peer = {
      .valid = 1,
      .pid = 100,
      .uid = 200,
      .gid = 300,
  };
  struct qaffd_auth_rule rule = {0};
  if (expect(qaffd_auth_daemon_mutation(&rule, peer.uid, &peer) == 0,
             "daemon owner is default admin") != 0) {
    return -1;
  }
  errno = 0;
  if (expect(qaffd_auth_daemon_mutation(&rule, peer.uid + 1, &peer) == -1 &&
                 errno == EACCES,
             "non-owner is rejected without an admin rule") != 0) {
    return -1;
  }

  rule.gid_set = 1;
  rule.gid = peer.gid;
  if (expect(qaffd_auth_daemon_mutation(&rule, 999, &peer) == 0,
             "configured admin GID replaces owner default") != 0) {
    return -1;
  }
  rule.gid++;
  return expect(qaffd_auth_daemon_mutation(&rule, peer.uid, &peer) == -1 &&
                    errno == EACCES,
                "configured admin rule does not fall back to owner");
}

static int test_peer_identity(void) {
  struct qaffd_peer_cred left = {
      .valid = 1,
      .pid = 1,
      .uid = 2,
      .gid = 3,
  };
  struct qaffd_peer_cred right = left;
  if (expect(qaffd_auth_same_peer(&left, &right),
             "identical peer credentials match") != 0) {
    return -1;
  }
  right.pid++;
  if (expect(!qaffd_auth_same_peer(&left, &right),
             "PID is part of worker ownership") != 0) {
    return -1;
  }
  right = left;
  right.valid = 0;
  return expect(!qaffd_auth_same_peer(&left, &right),
                "invalid credentials never match");
}

static int test_socket_credentials(void) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
    perror("socketpair");
    return -1;
  }
  struct qaffd_peer_cred peer;
  int rc = qaffd_get_peer_cred(sockets[0], &peer);
  int saved_errno = errno;
  close(sockets[0]);
  close(sockets[1]);
  errno = saved_errno;
  if (rc != 0) {
    perror("qaffd_get_peer_cred");
    return -1;
  }
  return expect(peer.valid && peer.pid == (uint32_t)getpid() &&
                    peer.uid == (uint32_t)getuid() &&
                    peer.gid == (uint32_t)getgid(),
                "SO_PEERCRED returns the connected process identity");
}

int main(void) {
  if (test_worker_rules() != 0 || test_admin_rules() != 0 ||
      test_peer_identity() != 0 || test_socket_credentials() != 0) {
    return 1;
  }
  puts("qaffd authorization tests passed");
  return 0;
}
