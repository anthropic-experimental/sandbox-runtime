/*
 * libcredmask.dylib — DYLD interposer that redirects reads of credential-
 * masked files to their sentinel-content fakes on macOS.
 *
 * WHY THIS EXISTS
 * ---------------
 * On Linux, a `credentials.files` entry with `mode: "mask"` bind-mounts a
 * fake (sentinel-content) file over the real path, so the sandboxed
 * process transparently reads the sentinel. macOS Seatbelt (SBPL) has no
 * bind-mount equivalent — it can only deny — so masked files degrade to
 * `(deny file-read*)` and cooperative tools break with EPERM instead of
 * seeing the sentinel.
 *
 * This library restores the Linux behaviour for COOPERATIVE processes:
 * injected via DYLD_INSERT_LIBRARIES, it interposes the libc file-path
 * entry points and, when the (normalized) path exactly matches a masked
 * real path, substitutes the fake path before calling the real function.
 *
 * SECURITY MODEL — read this before reviewing anything else
 * ---------------------------------------------------------
 * The interposer is a COMPATIBILITY shim, not a security boundary. The
 * SBPL `(deny file-read*)` on the real path remains in force and is the
 * only thing standing between the sandboxed process and the credential.
 * Anything that bypasses this library — SIP-protected binaries (dyld
 * strips DYLD_* at load), statically-linked syscalls, raw syscall(2),
 * paths this file fails to normalize, hooks not in the list below — falls
 * through to the SBPL deny and gets EPERM. Every failure mode here is
 * therefore FAIL-CLOSED with respect to the credential (the real bytes
 * stay unreadable) and FAIL-OPEN with respect to the process (we never
 * crash or alter behaviour for unmasked paths).
 *
 * Consequences of that model, deliberately accepted:
 *   - No attempt to hide from or resist a hostile process. A process that
 *     unsets DYLD_INSERT_LIBRARIES for its children merely loses the shim
 *     and hits the deny.
 *   - Exact-match only. The masked real paths arrive canonicalized
 *     (tilde-expanded + realpath'd) from the TS side; lookups here are
 *     lexically normalized (cwd-join, ".", "..", "//") but symlinks are
 *     NOT resolved. A path that reaches the file through a symlink does
 *     not match and hits the deny.
 *   - A malformed CREDMASK_MAP (or none) turns every hook into a pure
 *     passthrough.
 *
 * MAP FORMAT
 * ----------
 * CREDMASK_MAP is a list of realPath/fakePath pairs:
 *
 *   real1 \x1f fake1 \x1e real2 \x1f fake2 ...
 *
 * \x1f (unit separator) between the two fields, \x1e (record separator)
 * between entries. Both are illegal in the fake paths we generate and
 * absent from any sane real path; the TS encoder skips entries containing
 * either byte (those files simply stay denied), so no escaping is needed.
 * Entries whose fields are not both absolute paths are ignored.
 *
 * CONSTRAINTS
 * -----------
 * Loaded into arbitrary processes, so: no I/O at load time, one-time lazy
 * init guarded by pthread_once, no allocation in the hook fast path after
 * init, errno preserved on the passthrough path, and no dependencies
 * beyond libSystem.
 */

#if !defined(__APPLE__)
#error "credmask interposer is macOS-only (DYLD __interpose)"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CREDMASK_ENV "CREDMASK_MAP"
#define FIELD_SEP '\x1f' /* between realPath and fakePath   */
#define ENTRY_SEP '\x1e' /* between entries                 */

typedef struct {
  const char *real; /* canonical path of the masked credential file */
  const char *fake; /* path of the sentinel-content replacement     */
} credmask_entry;

/* Parsed once by credmask_init(); immutable afterwards, so hooks may read
 * without locking. Both point into memory owned for process lifetime. */
static credmask_entry *entries = NULL;
static size_t entry_count = 0;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

/*
 * Parse CREDMASK_MAP. Runs at most once (pthread_once). Every parse
 * failure leaves entry_count == 0, i.e. pure passthrough — the SBPL deny
 * still protects the credential, so there is nothing to enforce here.
 */
static void credmask_init(void) {
  const char *map = getenv(CREDMASK_ENV);
  if (map == NULL || *map == '\0') {
    return;
  }

  /* Entries keep pointers into this copy; intentionally never freed
   * (lives as long as the process, like environ itself). */
  char *copy = strdup(map);
  if (copy == NULL) {
    return;
  }

  /* Upper bound on entries: one more than the number of separators. */
  size_t cap = 1;
  for (const char *p = copy; *p != '\0'; p++) {
    if (*p == ENTRY_SEP) {
      cap++;
    }
  }
  entries = calloc(cap, sizeof(*entries));
  if (entries == NULL) {
    free(copy);
    return;
  }

  char *cur = copy;
  while (cur != NULL && *cur != '\0') {
    char *next = strchr(cur, ENTRY_SEP);
    if (next != NULL) {
      *next++ = '\0';
    }
    char *sep = strchr(cur, FIELD_SEP);
    /* Accept only well-formed entries: exactly one field separator and
     * two absolute paths. Anything else is skipped — that file simply
     * stays SBPL-denied. */
    if (sep != NULL) {
      *sep = '\0';
      const char *real = cur;
      const char *fake = sep + 1;
      if (real[0] == '/' && fake[0] == '/' &&
          strchr(fake, FIELD_SEP) == NULL) {
        entries[entry_count].real = real;
        entries[entry_count].fake = fake;
        entry_count++;
      }
    }
    cur = next;
  }
}

/*
 * Append one path component to `out` (lexical resolution). "" and "."
 * are dropped; ".." truncates the last component; anything else is
 * appended as "/<comp>". Returns -1 on overflow (caller treats the whole
 * lookup as no-match — passthrough, SBPL decides).
 */
static int apply_component(char *out, size_t outsz, const char *comp,
                           size_t len) {
  if (len == 0 || (len == 1 && comp[0] == '.')) {
    return 0;
  }
  if (len == 2 && comp[0] == '.' && comp[1] == '.') {
    char *slash = strrchr(out, '/');
    if (slash != NULL) {
      *slash = '\0'; /* ".." above root leaves out empty == root */
    }
    return 0;
  }
  size_t cur = strlen(out);
  if (cur + 1 + len + 1 > outsz) {
    return -1;
  }
  out[cur] = '/';
  memcpy(out + cur + 1, comp, len);
  out[cur + 1 + len] = '\0';
  return 0;
}

/* Feed each '/'-separated component of `path` through apply_component. */
static int apply_path(char *out, size_t outsz, const char *path) {
  const char *p = path;
  while (*p != '\0') {
    while (*p == '/') {
      p++;
    }
    const char *start = p;
    while (*p != '\0' && *p != '/') {
      p++;
    }
    if (apply_component(out, outsz, start, (size_t)(p - start)) != 0) {
      return -1;
    }
  }
  return 0;
}

/*
 * Build a lexically-normalized absolute path for `path` into `out`
 * (size >= PATH_MAX). Relative paths are joined onto the directory named
 * by `dirfd` (AT_FDCWD → getcwd). Purely lexical: ".", "..", and "//"
 * collapse, symlinks are NOT followed. Returns 0 on success.
 */
static int normalize_path(int dirfd, const char *path, char *out,
                          size_t outsz) {
  out[0] = '\0';
  if (path[0] != '/') {
    char base[PATH_MAX];
    if (dirfd == AT_FDCWD) {
      if (getcwd(base, sizeof(base)) == NULL) {
        return -1;
      }
    } else if (fcntl(dirfd, F_GETPATH, base) == -1) {
      return -1;
    }
    if (apply_path(out, outsz, base) != 0) {
      return -1;
    }
  }
  if (apply_path(out, outsz, path) != 0) {
    return -1;
  }
  if (out[0] == '\0') {
    /* All components collapsed away: the path names the root. */
    out[0] = '/';
    out[1] = '\0';
  }
  return 0;
}

/*
 * The single decision point every hook funnels through: return the map
 * entry whose real path exactly matches the (normalized) lookup path, or
 * NULL for passthrough. `buf` must be a caller-owned PATH_MAX buffer.
 * Never touches errno from the caller's perspective (saved/restored).
 */
static const credmask_entry *credmask_lookup(int dirfd, const char *path,
                                             char *buf) {
  pthread_once(&init_once, credmask_init);
  if (entry_count == 0 || path == NULL || path[0] == '\0') {
    return NULL;
  }
  int saved_errno = errno;
  const credmask_entry *found = NULL;
  if (normalize_path(dirfd, path, buf, PATH_MAX) == 0) {
    for (size_t i = 0; i < entry_count; i++) {
      if (strcmp(buf, entries[i].real) == 0) {
        found = &entries[i];
        break;
      }
    }
  }
  errno = saved_errno;
  return found;
}

/* ─── Hooks ──────────────────────────────────────────────────────────────
 * Each hook: look the path up; on match call the real function with the
 * fake path (always absolute, so any dirfd becomes irrelevant); otherwise
 * call it with the original arguments untouched. Calls to open/stat/...
 * inside this library reach the REAL libc implementations — dyld does not
 * apply an image's own interpose table to itself. */

static int my_open(const char *path, int oflag, ...) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(AT_FDCWD, path, buf);
  mode_t mode = 0;
  if (oflag & O_CREAT) {
    va_list ap;
    va_start(ap, oflag);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  return open(e != NULL ? e->fake : path, oflag, mode);
}

static int my_openat(int dirfd, const char *path, int oflag, ...) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(dirfd, path, buf);
  mode_t mode = 0;
  if (oflag & O_CREAT) {
    va_list ap;
    va_start(ap, oflag);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  return openat(dirfd, e != NULL ? e->fake : path, oflag, mode);
}

static FILE *my_fopen(const char *restrict path, const char *restrict mode) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(AT_FDCWD, path, buf);
  return fopen(e != NULL ? e->fake : path, mode);
}

static FILE *my_freopen(const char *restrict path, const char *restrict mode,
                        FILE *restrict stream) {
  /* NULL path means "change the mode of the existing stream". */
  if (path == NULL) {
    return freopen(path, mode, stream);
  }
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(AT_FDCWD, path, buf);
  return freopen(e != NULL ? e->fake : path, mode, stream);
}

/* stat/lstat on a masked path report the FAKE's metadata (size etc.), so
 * a tool that stats then reads sees a consistent file. */
static int my_stat(const char *restrict path, struct stat *restrict st) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(AT_FDCWD, path, buf);
  return stat(e != NULL ? e->fake : path, st);
}

static int my_lstat(const char *restrict path, struct stat *restrict st) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(AT_FDCWD, path, buf);
  return lstat(e != NULL ? e->fake : path, st);
}

static int my_fstatat(int dirfd, const char *path, struct stat *st,
                      int flag) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(dirfd, path, buf);
  return fstatat(dirfd, e != NULL ? e->fake : path, st, flag);
}

static int my_access(const char *path, int amode) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(AT_FDCWD, path, buf);
  return access(e != NULL ? e->fake : path, amode);
}

static int my_faccessat(int dirfd, const char *path, int amode, int flag) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(dirfd, path, buf);
  return faccessat(dirfd, e != NULL ? e->fake : path, amode, flag);
}

/*
 * realpath on a masked path returns the entry's REAL path — the map's
 * keys are already canonical, and returning the fake path would leak the
 * store location and break tools that compare resolved paths. The fake is
 * stat'd first so the "file exists" contract holds; if the fake is gone
 * we fall through to the real realpath (whose lstat then hits the SBPL
 * deny — fail-closed).
 */
static char *my_realpath(const char *restrict path, char *restrict resolved) {
  char buf[PATH_MAX];
  const credmask_entry *e = credmask_lookup(AT_FDCWD, path, buf);
  if (e == NULL) {
    return realpath(path, resolved);
  }
  struct stat st;
  if (stat(e->fake, &st) != 0) {
    return realpath(path, resolved);
  }
  if (resolved == NULL) {
    return strdup(e->real);
  }
  if (strlcpy(resolved, e->real, PATH_MAX) >= PATH_MAX) {
    errno = ENAMETOOLONG;
    return NULL;
  }
  return resolved;
}

/* ─── DYLD interpose table ───────────────────────────────────────────────
 * Each pair tells dyld to rebind calls to `orig` (in every image except
 * this one) to `repl`. Referencing &stat here resolves per-arch to the
 * symbol current SDKs emit (stat$INODE64 on x86_64, plain stat on
 * arm64); binaries built against older SDKs that call the legacy plain
 * symbols on x86_64 are not interposed and hit the SBPL deny instead.
 */
typedef struct {
  const void *replacement;
  const void *replacee;
} interpose_t;

#define INTERPOSE(repl, orig)                                    \
  __attribute__((used, section("__DATA,__interpose"))) static    \
      const interpose_t interpose_##orig = {(const void *)&repl, \
                                            (const void *)&orig}

INTERPOSE(my_open, open);
INTERPOSE(my_openat, openat);
INTERPOSE(my_fopen, fopen);
INTERPOSE(my_freopen, freopen);
INTERPOSE(my_stat, stat);
INTERPOSE(my_lstat, lstat);
INTERPOSE(my_fstatat, fstatat);
INTERPOSE(my_access, access);
INTERPOSE(my_faccessat, faccessat);
INTERPOSE(my_realpath, realpath);
