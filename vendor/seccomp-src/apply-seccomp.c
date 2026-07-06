/*
 * apply-seccomp.c - Apply seccomp BPF filter in an isolated PID namespace
 *
 * Usage: apply-seccomp <command> [args...]
 *
 * This program applies a baked-in seccomp BPF filter, isolates the
 * target command in a nested user+PID+mount namespace so it cannot see or
 * ptrace any process that lacks the filter, applies the filter with
 * prctl(PR_SET_SECCOMP), and execs the command.
 *
 * Process layout inside the outer bwrap sandbox:
 *
 *   bwrap init (PID 1)          <- outer PID ns, no seccomp
 *   \_ bash / socat ...         <- outer PID ns, no seccomp
 *      \_ apply-seccomp [outer] <- outer PID ns, waits for inner init
 *         ================================================= PID ns boundary
 *         \_ apply-seccomp [inner init] <- inner PID 1, PR_SET_DUMPABLE=0
 *            \_ user command            <- inner PID 2, seccomp applied
 *
 * From the user command's point of view /proc contains only its own process
 * tree. The bwrap init, bash wrapper, and socat helpers are not addressable,
 * so they cannot be ptraced or patched via /proc/N/mem even on systems with
 * kernel.yama.ptrace_scope=0. The inner init (PID 1) sets PR_SET_DUMPABLE=0
 * so it cannot be ptraced either.
 *
 * Any failure to set up the nested namespaces aborts with a non-zero exit
 * status; we never fall back to running the command without isolation.
 *
 * Compile: gcc -static -O2 -o apply-seccomp apply-seccomp.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#include "unix-block-bpf.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static int write_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len < 0 || (size_t)len >= sizeof(buf)) {
        errno = EOVERFLOW;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t r = write(fd, buf, (size_t)len);
    int saved = errno;
    close(fd);
    if (r != len) {
        errno = (r < 0) ? saved : EIO;
        return -1;
    }
    return 0;
}

/* PID the current process forwards signals to. Used by both the outer stub
 * (forwards to inner init) and the inner init (forwards to the worker).
 * PID 1 ignores signals it has no handler for, so the inner init MUST install
 * these or SIGTERM from the outside is silently dropped. */
static volatile pid_t forward_target = -1;

static void forward_signal(int sig) {
    if (forward_target > 0) {
        kill(forward_target, sig);
    }
}

static void install_forwarders(pid_t target) {
    forward_target = target;
    struct sigaction sa = { .sa_handler = forward_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

/*
 * Wait for `main_child`, reaping any other children that exit first.
 * Returns as soon as `main_child` terminates — the caller then _exit()s,
 * which as PID 1 tears down the namespace and SIGKILLs any stragglers.
 * Returns an exit(3)-style status: exit code, or 128+signal.
 */
static int reap_until(pid_t main_child) {
    int status = 0;
    for (;;) {
        pid_t r = waitpid(-1, &status, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;  /* ECHILD without seeing main_child — shouldn't happen. */
        }
        if (r == main_child) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 1;
        }
        /* Reaped an orphan that died before main_child; keep waiting. */
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    char **command_argv = &argv[1];

    _Static_assert(sizeof(unix_block_bpf) % sizeof(struct sock_filter) == 0,
                   "BPF filter size must be a multiple of sock_filter");
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(unix_block_bpf) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter *)unix_block_bpf,
    };

    /* ---- New PID + mount namespaces. Children (not us) enter the PID ns. ----
     *
     * Two paths to get CAP_SYS_ADMIN for the unshare:
     *   (a) The caller (bwrap) kept CAP_SYS_ADMIN in this user namespace via
     *       --cap-add. Just unshare directly.
     *   (b) We don't have the cap. Create a nested user namespace to get it,
     *       map uid/gid, then unshare. This also works when apply-seccomp is
     *       run standalone outside bwrap.
     *
     * Path (a) is tried first. If the caller didn't give us the cap, the
     * kernel returns EPERM and we fall through to (b). Path (b) can itself
     * fail on hosts where unprivileged user namespaces are gated by an LSM
     * (Ubuntu 24.04's AppArmor restriction, for example) — the unshare
     * succeeds but the new namespace grants no capabilities, so the setgroups
     * write fails. In that case we abort: the caller must supply CAP_SYS_ADMIN.
     */
    if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
        if (errno != EPERM) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS)");
        }

        uid_t uid = geteuid();
        gid_t gid = getegid();

        if (unshare(CLONE_NEWUSER) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWUSER)");
        }
        if (write_file("/proc/self/setgroups", "deny") < 0) {
            die("apply-seccomp: write /proc/self/setgroups "
                "(nested userns is capability-restricted; "
                "caller must provide CAP_SYS_ADMIN)");
        }
        if (write_file("/proc/self/uid_map", "%u %u 1\n", uid, uid) < 0) {
            die("apply-seccomp: write /proc/self/uid_map");
        }
        if (write_file("/proc/self/gid_map", "%u %u 1\n", gid, gid) < 0) {
            die("apply-seccomp: write /proc/self/gid_map");
        }
        if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS) after userns");
        }
    }

    pid_t child = fork();
    if (child < 0) {
        die("apply-seccomp: fork");
    }

    if (child > 0) {
        /* Outer stub: still in bwrap's PID namespace. Forward signals and
         * wait so the caller sees the real exit status. */
        install_forwarders(child);

        int status;
        for (;;) {
            pid_t r = waitpid(child, &status, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) die("apply-seccomp: waitpid");
            break;
        }
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }

    /* ================================================================
     * Inner init — PID 1 in the nested PID namespace.
     * ================================================================ */

    /* Block ptrace and /proc/1/mem writes against this process. */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_DUMPABLE)");
    }

    /* Don't let our /proc mount propagate anywhere. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        die("apply-seccomp: mount(MS_PRIVATE)");
    }
    /* EPERM here means a masked /proc is underneath (unprivileged Docker)
     * and the kernel domination check refused the overmount. The nested
     * userns above is the isolation boundary; this remount only hides
     * outer PIDs from `ls /proc`. enableWeakerNestedSandbox targets
     * exactly this environment. */
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0
        && errno != EPERM) {
        die("apply-seccomp: mount(/proc)");
    }

    /* bwrap --cap-add places CAP_SYS_ADMIN in the ambient set so it survives
     * exec. Clear it now that the mount is done; combined with
     * PR_SET_NO_NEW_PRIVS, the worker's execve drops to zero capabilities. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_CAP_AMBIENT_CLEAR_ALL)");
    }

    /* Fork the real workload so PID 1 can stay as a non-dumpable reaper. */
    pid_t worker = fork();
    if (worker < 0) {
        die("apply-seccomp: fork(worker)");
    }

    if (worker > 0) {
        /* Inner init: reap everything, exit with the worker's status.
         * When PID 1 exits the kernel tears down the whole namespace.
         * PID 1 drops signals without handlers, so install forwarders. */
        install_forwarders(worker);
        _exit(reap_until(worker));
    }

    /* ---- Worker (inner PID 2): apply seccomp and exec. ---- */

    /* Drop the bounding set so a uid-0 workload cannot regenerate
     * capabilities at execve: the root-exec rule refills permitted and
     * effective from the bounding set, and NO_NEW_PRIVS does not prevent
     * that. For uid != 0 execve clears everything anyway. EPERM means we
     * hold no CAP_SETPCAP — then our capability sets are already empty
     * and a uid != 0 exec keeps nothing; treat as done rather than
     * failing capability-less configurations. */
    /* Clear the INHERITABLE set: with CAP_SETPCAP in a --cap-add style
     * grant, pI could survive exec and re-arm file-caps binaries.
     * Lowering one's own pI never requires privilege. Raw capset(2): no
     * libcap dependency. */
    {
        struct __user_cap_header_struct hdr = {
            .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
        };
        struct __user_cap_data_struct data[2];
        if (syscall(SYS_capget, &hdr, data) == 0) {
            data[0].inheritable = 0;
            data[1].inheritable = 0;
            if (syscall(SYS_capset, &hdr, data) != 0) {
                die("apply-seccomp: capset(clear inheritable)");
            }
        }
        /* capget failure: fall through — the bounding-set verification
         * below still refuses dangerous states for uid 0. */
    }

    int drop_eperm = 0;
    for (int cap = 0;; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == 0) continue;
        if (errno == EINVAL) break; /* past the highest capability */
        if (errno == EPERM) { drop_eperm = 1; break; }
        die("apply-seccomp: prctl(PR_CAPBSET_DROP)");
    }
    if (drop_eperm) {
        /* EPERM means no CAP_SETPCAP. That is only safe when the bounding
         * set is ALREADY empty-of-consequence — a caller that granted us
         * caps without CAP_SETPCAP (bwrap --cap-add configurations) would
         * otherwise let a uid-0 workload regenerate them at execve.
         * Verify the premise instead of assuming it. */
        for (int cap = 0;; cap++) {
            int r = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
            if (r < 0) {
                if (errno == EINVAL) break; /* past the highest capability */
                die("apply-seccomp: prctl(PR_CAPBSET_READ)");
            }
            if (r == 1 && geteuid() == 0) {
                fprintf(stderr,
                        "apply-seccomp: cannot drop bounding set "
                        "(no CAP_SETPCAP) but cap %d is still present and "
                        "euid is 0 — refusing to exec a workload that "
                        "would regain capabilities\n", cap);
                _exit(1);
            }
        }
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_NO_NEW_PRIVS)");
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        die("apply-seccomp: prctl(PR_SET_SECCOMP)");
    }

    execvp(command_argv[0], command_argv);
    die("apply-seccomp: execvp");
    return 1;
}
