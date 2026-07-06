/*
 * netns-config: configure a sandbox's network namespace FROM THE HOST.
 *
 * Runs OUTSIDE the sandbox, spawned by the srt host process when the
 * in-sandbox helper phones home over the dedicated rendezvous socket.
 * No namespace is ever created: the host holds full capabilities over
 * the sandbox's namespaces because they are owned by its own euid
 * (user_namespaces(7) owner rule), so this works on hosts that forbid
 * unprivileged user-namespace CREATION (Ubuntu 23.10+ AppArmor
 * confinement, hardened seccomp profiles) — anywhere bwrap itself runs.
 *
 * What it does to the target netns:
 *   1. Bring lo up.
 *   2. Install `local default dev lo` routes (RTM_NEWROUTE, local table,
 *      RTN_LOCAL) for IPv4 and IPv6: every address becomes a *local*
 *      destination, so the in-sandbox helper's wildcard listeners receive
 *      connects to any IP and getsockname() reports the original
 *      destination. IPv6 failure is non-fatal (ipv6.disable=1 kernels).
 *   3. Write net.ipv4.ip_unprivileged_port_start=53 (per-netns sysctl) so
 *      the capability-less helper can bind :53/:80/:443 while lower ports
 *      (:22/:25) stay privileged for the workload.
 *
 * Join sequence (both fds opened before the first setns):
 *   open /proc/PID/ns/net → ioctl NS_GET_USERNS (the netns may be owned
 *   by an ANCESTOR of the payload's userns: bwrap creates its namespaces
 *   in a first userns, then pivots the payload into a second) →
 *   setns(owner userns) → setns(netns).
 *
 * SECURITY: this binary is NOT a privilege boundary — it is unprivileged
 * and grants nothing its invoker doesn't already have. The checks below
 * protect the HOST's decision to act on a request:
 *   - The target is always derived from the REQUESTER itself (peercred
 *     pid of the connected rendezvous socket on fd 0), never from a
 *     caller-supplied pid — a co-uid process cannot point the host at a
 *     third party's namespace.
 *   - The requester's self-reported netns inode (validated by the host,
 *     passed as argv) must match the inode of the netns we actually
 *     open — a pid-reuse race yields a mismatch and a refusal.
 *   - The host's OWN netns is always refused, even on inode match.
 * Protocol on fd 0 (the accepted rendezvous connection): the host JS has
 * already consumed the hello line and validated the session token; this
 * program writes exactly "OK\n" on success. Any failure: message on
 * stderr, non-zero exit, connection closed without "OK" (the helper
 * treats that as fatal — no fallback).
 *
 * Test mode: `netns-config --pid <pid> <inode>` skips the fd-0 protocol
 * (peercred requires a real AF_UNIX connection, which some dev sandboxes
 * cannot create) and reports on stdout. The binary is unprivileged, so
 * this mode grants nothing beyond what any process of the same uid could
 * do with its own copy of these syscalls.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/nsfs.h>
#include <linux/rtnetlink.h>

/* Strict digit-string parse: garbage must refuse, not become 0/ULLONG_MAX. */
static unsigned long long parse_inode(const char *arg) {
  char *end = NULL;
  errno = 0;
  if (arg[0] < '0' || arg[0] > '9') {
    /* strtoull accepts leading whitespace and '-' (wrapping); refuse. */
    fprintf(stderr, "netns-config: invalid inode argument\n");
    exit(1);
  }
  unsigned long long v = strtoull(arg, &end, 10);
  if (errno != 0 || end == arg || *end != '\0' || v == 0) {
    fprintf(stderr, "netns-config: invalid inode argument\n");
    exit(1);
  }
  return v;
}

static void die(const char *what) {
  fprintf(stderr, "netns-config: %s: %s\n", what, strerror(errno));
  exit(1);
}

static void write_file(const char *path, const char *content) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) die(path);
  ssize_t len = (ssize_t)strlen(content);
  ssize_t wrote = write(fd, content, (size_t)len);
  if (wrote != len) {
    if (wrote >= 0) errno = EIO; /* short write: don't report stale errno */
    die(path);
  }
  if (close(fd) != 0) die(path);
}

/* Install one `local default dev lo` route in the local table. */
static void add_local_default_route(int family) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) die("socket(AF_NETLINK)");

  struct {
    struct nlmsghdr nh;
    struct rtmsg rt;
    char attrs[RTA_SPACE(sizeof(int))];
  } req;
  memset(&req, 0, sizeof(req));
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.nh.nlmsg_type = RTM_NEWROUTE;
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.nh.nlmsg_seq = (unsigned int)family;
  req.rt.rtm_family = (unsigned char)family;
  req.rt.rtm_dst_len = 0; /* default */
  req.rt.rtm_table = RT_TABLE_LOCAL;
  req.rt.rtm_protocol = RTPROT_BOOT;
  req.rt.rtm_scope = RT_SCOPE_HOST;
  req.rt.rtm_type = RTN_LOCAL;

  struct rtattr *rta =
      (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
  rta->rta_type = RTA_OIF;
  rta->rta_len = RTA_LENGTH(sizeof(int));
  int lo = (int)if_nametoindex("lo");
  if (lo == 0) die("if_nametoindex(lo)");
  memcpy(RTA_DATA(rta), &lo, sizeof(int));
  req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

  if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) die("send(RTM_NEWROUTE)");

  /* No seq/sender validation needed: fresh CLOEXEC socket, exactly one
   * NLM_F_ACK request in flight, only the kernel can address this socket. */
  union {
    char raw[4096];
    struct nlmsghdr nh;
  } buf;
  ssize_t n = recv(fd, buf.raw, sizeof(buf.raw), 0);
  if (n < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
    if (n >= 0) errno = EPROTO; /* short datagram, not a syscall error */
    die("recv(netlink ack)");
  }
  struct nlmsghdr *nh = &buf.nh;
  if (nh->nlmsg_type != NLMSG_ERROR) {
    errno = EPROTO;
    die("netlink ack: unexpected type");
  }
  struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
  if (err->error != 0) {
    errno = -err->error;
    if (family == AF_INET6) {
      /* ipv6.disable=1 kernels: IPv4-only capture is the right outcome. */
      fprintf(stderr, "netns-config: ipv6 local route skipped: %s\n",
              strerror(errno));
      if (close(fd) != 0) die("close(AF_NETLINK)");
      return;
    }
    die("RTM_NEWROUTE ack");
  }
  if (close(fd) != 0) die("close(AF_NETLINK)");
}

static void configure_current_netns(void) {
  int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) die("socket(AF_INET)");
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
  if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) die("SIOCGIFFLAGS(lo)");
  ifr.ifr_flags |= IFF_UP; /* IFF_RUNNING is kernel-managed (read-only) */
  if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) die("SIOCSIFFLAGS(lo)");
  if (close(s) != 0) die("close(AF_INET)");

  add_local_default_route(AF_INET);
  add_local_default_route(AF_INET6);

  /* Per-netns sysctl. /proc/sys/net resolves against the CURRENT
   * process's netns regardless of when /proc was mounted, so after
   * setns this affects only the sandbox's namespace. 53 (not 0): the
   * helper binds :53/:80/:443 only; ports below stay privileged so a
   * capability-less workload cannot squat :22/:25 (parity with hosts
   * where those binds were always denied). */
  write_file("/proc/sys/net/ipv4/ip_unprivileged_port_start", "53");
}

/* Join <pid>'s netns after verifying it matches the expected inode and is
 * not the host's own. Both fds are opened before the first setns. */
static void join_target_netns(pid_t pid, unsigned long long expected_inode) {
  struct stat own;
  if (stat("/proc/self/ns/net", &own) != 0) die("stat(own netns)");

  char path[64];
  snprintf(path, sizeof(path), "/proc/%ld/ns/net", (long)pid);
  int netfd = open(path, O_RDONLY | O_CLOEXEC);
  if (netfd < 0) die("open(target netns)");

  struct stat st;
  if (fstat(netfd, &st) != 0) die("fstat(target netns)");
  if ((unsigned long long)st.st_ino != expected_inode) {
    fprintf(stderr,
            "netns-config: netns inode mismatch (requester claims %llu, "
            "pid %ld has %llu) — stale pid or race, refusing\n",
            expected_inode, (long)pid, (unsigned long long)st.st_ino);
    exit(1);
  }
  if (st.st_ino == own.st_ino) {
    fprintf(stderr, "netns-config: refusing to configure the host netns\n");
    exit(1);
  }

  /* setns(NEWNET) needs CAP_SYS_ADMIN in the CALLER'S current userns as
   * well as over the target netns's owner. An unprivileged host process
   * has the latter (owner-uid rule) but not the former — so join the
   * netns's owner userns first (grants full caps there), then the netns.
   * NS_GET_USERNS resolves the true owner, which for bwrap is the FIRST
   * userns, not the payload's. */
  int ownerfd = ioctl(netfd, NS_GET_USERNS);
  if (ownerfd < 0) die("NS_GET_USERNS");
  /* Real-root deployments: bwrap runs without a userns, so the target
   * netns is owned by OUR current userns — joining it would EINVAL, and
   * we already hold CAP_SYS_ADMIN there. Skip the join in that case. */
  struct stat owner_st, self_userns_st;
  if (fstat(ownerfd, &owner_st) != 0) die("fstat(owner userns)");
  if (stat("/proc/self/ns/user", &self_userns_st) != 0) {
    die("stat(own userns)");
  }
  if (owner_st.st_ino != self_userns_st.st_ino) {
    if (setns(ownerfd, CLONE_NEWUSER) != 0) die("setns(owner userns)");
  }
  if (setns(netfd, CLONE_NEWNET) != 0) die("setns(netns)");
  if (close(ownerfd) != 0) die("close(owner userns)");
  if (close(netfd) != 0) die("close(netns)");
}

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

int main(int argc, char **argv) {
  /* The requester may close the connection at any point; a SIGPIPE on
   * the final OK write must be a clean error path, not a signal death. */
  signal(SIGPIPE, SIG_IGN);

  if (argc == 4 && strcmp(argv[1], "--pid") == 0) {
    /* Test mode: explicit pid, no rendezvous socket. Grants nothing —
     * this binary is unprivileged; any same-uid process could run the
     * same syscalls itself. Used by e2e tests in environments that
     * cannot create AF_UNIX listeners. */
    pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
    unsigned long long inode = parse_inode(argv[3]);
    join_target_netns(pid, inode);
    configure_current_netns();
    printf("OK\n");
    return 0;
  }

  if (argc != 2) {
    fprintf(stderr,
            "usage: netns-config <expected-netns-inode>   (socket on fd 0)\n"
            "       netns-config --pid <pid> <expected-netns-inode>\n");
    return 1;
  }

  /* Production mode: fd 0 is the accepted rendezvous connection. The
   * target pid comes from the kernel (SO_PEERCRED), never the caller. */
  unsigned long long inode = parse_inode(argv[1]);
  struct ucred cred;
  socklen_t len = sizeof(cred);
  if (getsockopt(0, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    die("getsockopt(SO_PEERCRED)");
  }
  if (cred.pid <= 0) {
    fprintf(stderr, "netns-config: peer pid unavailable\n");
    return 1;
  }
  if (cred.uid != geteuid()) {
    fprintf(stderr, "netns-config: peer uid %u != own uid %u, refusing\n",
            (unsigned)cred.uid, (unsigned)geteuid());
    return 1;
  }

  /* Pid-recycle defense (kernel 6.5+): SO_PEERPIDFD pins the ORIGINAL
   * connect-time peer. The pidfd is acquired BEFORE /proc/<pid> is
   * dereferenced and checked for liveness AFTER join_target_netns opens
   * the netns fd: if the original peer is still alive at that point,
   * cred.pid was never freed in between, so the fd belongs to the
   * requester. On older kernels the getsockopt fails and the residual
   * is the (self-reported-inode-bound) race documented in the review. */
  int peer_pidfd = -1;
  socklen_t pfd_len = sizeof(peer_pidfd);
  if (getsockopt(0, SOL_SOCKET, SO_PEERPIDFD, &peer_pidfd, &pfd_len) != 0) {
    if (errno == ENOPROTOOPT) {
      /* Genuine pre-6.5 kernel: the sockopt does not exist. Proceed
       * unpinned — the residual pid-reuse race is documented; the inode
       * check still refuses accidental mismatches. */
      fprintf(stderr,
              "netns-config: SO_PEERPIDFD unavailable (old kernel), "
              "proceeding without pid pinning\n");
      peer_pidfd = -1;
    } else {
      /* On a supporting kernel any other failure (notably EINVAL when
       * the connect-time peer is already reaped) must fail CLOSED — a
       * freed pid is exactly the recycle window the pin exists for. */
      die("getsockopt(SO_PEERPIDFD)");
    }
  }

  join_target_netns(cred.pid, inode);

  if (peer_pidfd >= 0) {
    struct pollfd pfd = { .fd = peer_pidfd, .events = POLLIN };
    int pr = poll(&pfd, 1, 0);
    if (pr < 0) die("poll(peer pidfd)");
    if (pr > 0) {
      /* pidfd readable = original peer exited: the pid may have been
       * recycled between connect and the /proc open — refuse. */
      fprintf(stderr, "netns-config: peer exited before configuration, "
                      "refusing (pid-reuse guard)\n");
      return 1;
    }
  }

  configure_current_netns();

  /* Ack on the rendezvous connection itself: the helper waits for this
   * exact line before binding listeners. */
  if (write(0, "OK\n", 3) != 3) die("write(OK)");
  return 0;
}
