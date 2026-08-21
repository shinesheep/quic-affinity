#define _GNU_SOURCE

#include "authorization.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>

int qaffd_get_peer_cred(int fd, struct qaffd_peer_cred *out) {
  if (out == NULL) {
    errno = EINVAL;
    return -1;
  }
  memset(out, 0, sizeof(*out));
#ifdef SO_PEERCRED
  struct ucred cred;
  socklen_t len = sizeof(cred);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    return -1;
  }
  if (len != sizeof(cred) || cred.pid < 0 || cred.uid > UINT32_MAX ||
      cred.gid > UINT32_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  out->valid = 1;
  out->pid = (uint32_t)cred.pid;
  out->uid = (uint32_t)cred.uid;
  out->gid = (uint32_t)cred.gid;
#else
  (void)fd;
#endif
  return 0;
}

int qaffd_auth_rule_matches(const struct qaffd_auth_rule *rule,
                            const struct qaffd_peer_cred *peer) {
  if (rule == NULL || (!rule->uid_set && !rule->gid_set) || peer == NULL ||
      !peer->valid) {
    return 0;
  }
  if (rule->uid_set && peer->uid != rule->uid) {
    return 0;
  }
  if (rule->gid_set && peer->gid != rule->gid) {
    return 0;
  }
  return 1;
}

int qaffd_auth_worker_registration(const struct qaffd_auth_rule *rule,
                                   const struct qaffd_peer_cred *peer) {
  if (rule == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (!rule->uid_set && !rule->gid_set) {
    return 0;
  }
  if (!qaffd_auth_rule_matches(rule, peer)) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

int qaffd_auth_daemon_mutation(const struct qaffd_auth_rule *rule,
                               uint32_t daemon_uid,
                               const struct qaffd_peer_cred *peer) {
  if (rule == NULL) {
    errno = EINVAL;
    return -1;
  }
  int allowed = rule->uid_set || rule->gid_set
                    ? qaffd_auth_rule_matches(rule, peer)
                    : peer != NULL && peer->valid && peer->uid == daemon_uid;
  if (!allowed) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

int qaffd_auth_same_peer(const struct qaffd_peer_cred *left,
                         const struct qaffd_peer_cred *right) {
  return left != NULL && right != NULL && left->valid && right->valid &&
         left->pid == right->pid && left->uid == right->uid &&
         left->gid == right->gid;
}
