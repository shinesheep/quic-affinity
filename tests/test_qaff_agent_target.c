#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

static int parse_port(const char *text, uint16_t *out) {
  char *end = NULL;
  unsigned long value = strtoul(text, &end, 10);
  if (end == text || *end != '\0' || value == 0 || value > UINT16_MAX) {
    errno = EINVAL;
    return -1;
  }
  *out = (uint16_t)value;
  return 0;
}

static int make_listener(uint16_t port) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0) {
    close(fd);
    return -1;
  }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static int receive_once(int fd) {
  struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN,
  };
  int rc;
  do {
    rc = poll(&pfd, 1, 15000);
  } while (rc < 0 && errno == EINTR);
  if (rc <= 0) {
    if (rc == 0) {
      errno = ETIMEDOUT;
    }
    return -1;
  }

  uint8_t packet[256];
  ssize_t got = recv(fd, packet, sizeof(packet), 0);
  return got > 0 ? 0 : -1;
}

static int listen_once(uint16_t port) {
  int fd = make_listener(port);
  if (fd < 0) {
    return -1;
  }
  int rc = receive_once(fd);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return rc;
}

static int rotate_listener(uint16_t port) {
  int fd = make_listener(port);
  if (fd < 0) {
    return -1;
  }
  if (receive_once(fd) != 0) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  close(fd);

  const struct timespec replacement_delay = {
    .tv_sec = 0,
    .tv_nsec = 500 * 1000 * 1000,
  };
  if (nanosleep(&replacement_delay, NULL) != 0) {
    return -1;
  }

  fd = make_listener(port);
  if (fd < 0) {
    return -1;
  }
  int rc = receive_once(fd);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return rc;
}

static int send_packet(uint16_t port) {
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  const uint8_t packet[] = {
    0xc3, 0x00, 0x00, 0x00, 0x01, 0x08,
    0xba, 0xad, 0xf0, 0x0d, 0x12, 0x34, 0x56, 0x78,
    0x00, 0x01, 0x02, 0x03, 0x04,
  };
  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(port);
  ssize_t sent = sendto(fd,
                        packet,
                        sizeof(packet),
                        0,
                        (struct sockaddr *)&dst,
                        sizeof(dst));
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return sent == (ssize_t)sizeof(packet) ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s listen|rotate|send PORT\n", argv[0]);
    return 2;
  }
  uint16_t port = 0;
  if (parse_port(argv[2], &port) != 0) {
    perror("parse_port");
    return 2;
  }

  int rc;
  if (strcmp(argv[1], "listen") == 0) {
    rc = listen_once(port);
  } else if (strcmp(argv[1], "rotate") == 0) {
    rc = rotate_listener(port);
  } else if (strcmp(argv[1], "send") == 0) {
    rc = send_packet(port);
  } else {
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
  }
  if (rc != 0) {
    perror(argv[1]);
    return 1;
  }
  return 0;
}
