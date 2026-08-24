#ifndef QAFFD_AUTHORIZATION_H
#define QAFFD_AUTHORIZATION_H

#include <stdint.h>

struct qaffd_peer_cred {
  int valid;
  uint32_t pid;
  uint32_t uid;
  uint32_t gid;
};

struct qaffd_auth_rule {
  int uid_set;
  int gid_set;
  uint32_t uid;
  uint32_t gid;
};

int qaffd_get_peer_cred(int fd, struct qaffd_peer_cred *out);
int qaffd_auth_rule_matches(const struct qaffd_auth_rule *rule,
                            const struct qaffd_peer_cred *peer);
int qaffd_auth_worker_registration(const struct qaffd_auth_rule *rule,
                                   const struct qaffd_peer_cred *peer);
int qaffd_auth_daemon_mutation(const struct qaffd_auth_rule *rule,
                               uint32_t daemon_uid,
                               const struct qaffd_peer_cred *peer);
int qaffd_auth_same_peer(const struct qaffd_peer_cred *left,
                         const struct qaffd_peer_cred *right);

#endif
