/**
 * Host-side support for Linux transparent networking — THE network
 * sandboxing implementation on Linux (no config knob, no fallback
 * shape). The in-sandbox counterpart is transparent-net-helper.ts; this
 * module resolves where that script lives, manages the protected asset
 * dir (resolv.conf stub + helper copy), and locates the vendored
 * netns-config binary the host runs to configure each sandbox's netns.
 */

import * as fs from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { logForDebugging } from '../utils/debug.js'
import { getVendorSeccompBinaryPath } from './generate-seccomp-filter.js'

export const DEFAULT_TRANSPARENT_TCP_PORTS = [80, 443]

// Cache: resolved helper source path (or null when unresolvable).
let cachedHelperSourcePath: string | null | undefined

/**
 * Resolve the transparent-net helper script. The helper is executed with
 * `process.execPath` inside the sandbox, so it must exist as a real file:
 *   1. transparent-net-helper.js next to this module (dist / bundled)
 *   2. transparent-net-helper.ts next to this module (running from source
 *      under bun, e.g. the test suite)
 * Bundled consumers that compile srt into a single file must ship this
 * script and the vendor binaries, and point the config at them via
 * `seccomp.transparentHelperPath` / `seccomp.netnsConfigPath`.
 */
let overrideNetnsConfigPath: string | undefined
let overrideHelperPath: string | undefined

/**
 * Register explicit locations for the transparent-networking components
 * (config `seccomp.netnsConfigPath` / `seccomp.transparentHelperPath`).
 * Bundled consumers relocate both files, so the module-relative and
 * vendor-dir probing below cannot find them. Clears the caches so a
 * re-initialize with different paths takes effect.
 */
export function setTransparentOverridePaths(overrides: {
  netnsConfigPath?: string
  transparentHelperPath?: string
}): void {
  overrideNetnsConfigPath = overrides.netnsConfigPath
  overrideHelperPath = overrides.transparentHelperPath
  netnsConfigContent = undefined
  cachedHelperSourcePath = undefined
}

export function getTransparentHelperPath(): string | null {
  if (cachedHelperSourcePath !== undefined) return cachedHelperSourcePath
  cachedHelperSourcePath = findHelperPath()
  return cachedHelperSourcePath
}

function findHelperPath(): string | null {
  if (overrideHelperPath !== undefined) {
    if (fs.existsSync(overrideHelperPath)) return overrideHelperPath
    logForDebugging(
      `[Transparent] configured transparentHelperPath missing: ${overrideHelperPath}`,
      { level: 'error' },
    )
    return null
  }
  const baseDir = dirname(fileURLToPath(import.meta.url))
  // The .ts source is only runnable when process.execPath is bun (the
  // helper is executed with process.execPath inside the sandbox); under
  // node, offering it would pass the dependency check and then fail at
  // exec time with ERR_UNKNOWN_FILE_EXTENSION.
  const candidates = process.versions.bun
    ? ['transparent-net-helper.js', 'transparent-net-helper.ts']
    : ['transparent-net-helper.js']
  for (const name of candidates) {
    const candidate = join(baseDir, name)
    if (fs.existsSync(candidate)) return candidate
  }
  logForDebugging(`[Transparent] helper script not found next to ${baseDir}`, {
    level: 'error',
  })
  return null
}

// ============================================================================
// Protected asset directory
// ============================================================================
//
// INVARIANT: every host file the sandbox executes or bind-mounts as a
// source must be unwritable from inside EVERY sandbox of EVERY session on
// the host. Defenses, layered:
//  - All sessions' asset dirs live under ONE fixed parent
//    (<tmpdir>/srt-tp-assets); every wrap ro-binds that PARENT over
//    itself, so session A's sandboxes cannot write session B's assets
//    either.
//  - The per-process dir is STABLE: first-time materialization goes into
//    the existing dir (invalidating the whole dir on any unset record
//    churned dirs, so the ro-bound dir was never the one in use).
//  - Trust is identity + CONTENT: a held-open fd pins the inode
//    (fstat(fd)==lstat(path) proves the path names srt's file; lstat so
//    a planted symlink never validates) AND the on-disk bytes must equal
//    the in-memory copy (an in-place rewrite keeps the inode). Any
//    anomaly abandons the dir for a fresh mkdtemp re-materialized from
//    memory.
//  - The HOST-executed binary (netns-config) never lives on disk at all:
//    the rendezvous writes the cached bytes to an anonymous (immediately
//    unlinked) file, verifies the content THROUGH the very fd that will
//    be executed, and spawns /proc/self/fd/<n> — no path exists to
//    tamper with (closes in-place-rewrite and check-to-use races).

interface ProtectedFile {
  path: string
  fd: number
  content: Buffer
}

let transparentAssetDir: string | undefined
let assetDirIdent: { dev: number; ino: number } | undefined
let protectedHelperFile: ProtectedFile | undefined
let protectedTokensFile: ProtectedFile | undefined
let protectedResolvFile: ProtectedFile | undefined
const assetDirsToCleanup = new Set<string>()
let exitCleanupInstalled = false

// Contents cached in memory at first read/write; re-materialization never
// re-reads the (possibly workload-writable) sources.
let protectedHelperContent: Buffer | undefined
let protectedHelperExt: string | undefined
let netnsConfigContent: Buffer | undefined

const RESOLV_CONTENT = Buffer.from('nameserver 127.0.0.1\n')

/**
 * Candidate parents for asset dirs across ALL processes of this uid —
 * derived from the HOST (uid + well-known paths), NOT from this
 * process's environment: sessions with divergent XDG_RUNTIME_DIR/TMPDIR
 * must still agree on what to ro-bind, or one session's sandbox could
 * write another session's assets. The wrapper binds
 * every candidate that exists.
 */
export function transparentAssetParentCandidates(): string[] {
  const uid = process.getuid!()
  const candidates: string[] = []
  const runUser = `/run/user/${uid}`
  try {
    const st = fs.lstatSync(runUser)
    if (st.isDirectory() && st.uid === uid) {
      candidates.push(join(runUser, 'srt-tp-assets'))
    }
  } catch {
    // no systemd runtime dir
  }
  candidates.push(`/tmp/srt-tp-assets-${uid}`)
  const tmpBase = tmpdir()
  try {
    // Relative TMPDIR is refused BEFORE resolution (realpath would
    // silently absolutize it against a cwd the user never chose).
    if (!tmpBase.startsWith('/')) {
      throw new Error('unusable shape')
    }
    // Resolve symlinks BEFORE deriving the candidate: a symlinked
    // TMPDIR is usable, but bwrap cannot create mount destinations
    // through a symlinked path component — the emitted --tmpfs path
    // must be canonical (and realpath also normalizes '..' segments,
    // so '/tmp/..' cannot dodge the root check). Throws on dangling.
    const tmpReal = fs.realpathSync(tmpBase)
    if (tmpReal === '/') {
      throw new Error('unusable shape')
    }
    if (fs.statSync(tmpReal).isDirectory()) {
      const tmpVariant = join(tmpReal, `srt-tp-assets-${uid}`)
      if (!candidates.includes(tmpVariant)) candidates.push(tmpVariant)
    } else {
      throw new Error('not a directory')
    }
  } catch {
    // A dangling TMPDIR breaks the whole sandbox stack anyway (bridge
    // sockets live under it) — fail with an srt-branded, actionable
    // error instead of a raw bwrap mkdir failure.
    throw new Error(
      `TMPDIR resolves to a missing/invalid directory: ${tmpBase} — ` +
        'unset TMPDIR or point it at an existing private directory',
    )
  }
  return candidates
}

// Pinned for the process lifetime: a mid-session env change (XDG dir
// torn down at logout) must not silently migrate assets to an unbound
// parent — anomalies fail closed instead.
let pinnedParentDir: string | undefined

/** This process's asset parent (first candidate; pinned at first use). */
export function transparentAssetParentDir(): string {
  if (pinnedParentDir !== undefined) return pinnedParentDir
  pinnedParentDir = transparentAssetParentCandidates()[0]!
  return pinnedParentDir
}

function closeQuietly(file: ProtectedFile | undefined): void {
  if (!file) return
  try {
    fs.closeSync(file.fd)
  } catch {
    // already closed
  }
}

function invalidateAssetDir(): void {
  // Release the abandoned dir's lock fd: keeping it would leak one fd
  // per anomaly AND keep refreshing a dead dir's mtime, holding it
  // inside the foreign-pidns age gate forever.
  if (currentLockFd !== undefined) {
    try {
      fs.closeSync(currentLockFd)
    } catch {
      // best effort
    }
    currentLockFd = undefined
  }
  closeQuietly(protectedHelperFile)
  closeQuietly(protectedTokensFile)
  closeQuietly(protectedResolvFile)
  protectedHelperFile = undefined
  protectedTokensFile = undefined
  protectedResolvFile = undefined
  transparentAssetDir = undefined
  assetDirIdent = undefined
}

/** The dir is trusted only while its identity matches creation time. */
function assetDirValid(): boolean {
  if (!transparentAssetDir || !assetDirIdent) return false
  try {
    const st = fs.lstatSync(transparentAssetDir)
    return (
      st.isDirectory() &&
      st.dev === assetDirIdent.dev &&
      st.ino === assetDirIdent.ino
    )
  } catch {
    return false
  }
}

// flock via the only binding node exposes without deps: proper flock(2)
// is unavailable in node's fs API, so liveness uses O_EXCL lock files
// re-checked against process start time — good enough for best-effort GC.
let currentLockFd: number | undefined

/**
 * Bump the lock file's mtime: a live session in a FOREIGN pid namespace
 * is only protected from a sibling's sweep by the age gate, and the
 * mtime is otherwise written once at creation. A cheap refresh on wrap
 * activity (only when the mtime has aged an hour — one fstat per wrap)
 * keeps any active session perpetually inside the gate; a session idle
 * past the whole gate can still be swept, and its next wrap self-heals.
 */
function refreshOwnLockMtime(): void {
  if (currentLockFd === undefined) return
  const now = Date.now()
  try {
    if (fs.fstatSync(currentLockFd).mtimeMs > now - 3_600_000) return
    fs.futimesSync(currentLockFd, now / 1000, now / 1000)
  } catch {
    // best effort — the age gate is a backstop, not a boundary
  }
}

/** Process start time (clock ticks) from /proc — pid-recycle-proof. */
function startTimeOf(pid: number): string | null {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8')
    // field 22, after the parenthesized comm (which may contain spaces)
    const after = stat.slice(stat.lastIndexOf(')') + 2)
    return after.split(' ')[19] ?? null
  } catch {
    return null
  }
}

function ownStartTime(): string {
  return startTimeOf(process.pid) ?? '0'
}

/** This process's pid-namespace identity (e.g. "pid:[4026531836]"). */
function ownPidNamespace(): string {
  try {
    return fs.readlinkSync('/proc/self/ns/pid')
  } catch {
    return 'unknown'
  }
}

const GC_AMBIGUOUS_AGE_MS = 7 * 86_400_000

/**
 * Best-effort reclamation of session dirs whose owning process is gone
 * (exit-hook cleanup misses SIGKILL/crash). Liveness must be robust
 * across PID NAMESPACES, and pid NUMBERS are only meaningful within the
 * namespace that recorded them (a foreign-pidns session's
 * in-namespace pid 1 collided with the sweeper's pid 1 and was judged
 * "recycled"). The lock records pid + starttime + pidns identity:
 *  - same pidns, pid present, starttime matches  → ALIVE (keep)
 *  - same pidns, pid present, starttime differs  → provably recycled
 *  - same pidns, pid absent                      → provably dead
 *  - different/unknown pidns                     → AMBIGUOUS: reclaim
 *    only past a 7-day lock-mtime age gate.
 */
function sweepStaleSessionDirs(parent: string): void {
  let entries: string[]
  try {
    entries = fs.readdirSync(parent)
  } catch {
    return
  }
  for (const entry of entries) {
    if (!entry.startsWith('session-')) continue
    const dir = join(parent, entry)
    if (dir === transparentAssetDir) continue
    try {
      const lockPath = join(dir, 'lock')
      let stale = false
      try {
        // Defensive open: another same-uid process may have planted a
        // FIFO (blocking open wedges the event loop forever), a symlink
        // (e.g. to /dev/zero: unbounded read), or a device node here.
        // O_NONBLOCK makes a FIFO open return immediately, O_NOFOLLOW
        // refuses symlinks, and the fstat type check routes any
        // non-regular file to the age-gate branch below.
        const lfd = fs.openSync(
          lockPath,
          fs.constants.O_RDONLY |
            fs.constants.O_NOFOLLOW |
            fs.constants.O_NONBLOCK,
        )
        let raw: string
        try {
          if (!fs.fstatSync(lfd).isFile()) {
            throw new Error('non-regular lock file')
          }
          const buf = Buffer.alloc(256)
          const n = fs.readSync(lfd, buf, 0, 256, 0)
          raw = buf.subarray(0, n).toString('utf8')
        } finally {
          fs.closeSync(lfd)
        }
        const [pidStr, start, lockNs] = raw.trim().split(' ')
        const pid = Number(pidStr)
        // 'unknown' (readlink failed on either side) must never count as
        // same-namespace — two failures would otherwise "match" and
        // re-enable the cross-pidns collision sweep.
        const ownNs = ownPidNamespace()
        const sameNs =
          lockNs !== undefined &&
          lockNs !== 'unknown' &&
          ownNs !== 'unknown' &&
          lockNs === ownNs
        if (sameNs && Number.isInteger(pid) && pid > 0) {
          const current = startTimeOf(pid)
          if (current !== null) {
            // same namespace: the pid number is meaningful — alive on
            // a starttime match, provably recycled otherwise.
            stale = start !== undefined && current !== start
          } else {
            // same namespace + absent = provably dead: reclaim now
            // (SIGKILL'd sessions must not wait out the age gate).
            stale = true
          }
        } else {
          // foreign/unknown pidns (or old lock format): the pid number
          // is uninterpretable here — age-gate only.
          stale =
            fs.statSync(lockPath).mtimeMs < Date.now() - GC_AMBIGUOUS_AGE_MS
        }
      } catch {
        // no lock file at all: legacy/interrupted dir — age-gate it
        stale = fs.statSync(dir).mtimeMs < Date.now() - GC_AMBIGUOUS_AGE_MS
      }
      if (stale) fs.rmSync(dir, { recursive: true, force: true })
    } catch {
      // races with concurrent sessions are fine — best effort
    }
  }
}

/** Per-process protected dir holding the resolv stub + protected copies. */
export function getTransparentAssetDir(): string {
  if (assetDirValid()) {
    refreshOwnLockMtime()
    return transparentAssetDir!
  }
  invalidateAssetDir()
  const parent = transparentAssetParentDir()
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 })
  // The shared parent must not be a symlink, another uid's dir, or
  // group/other-writable (a workload-pre-created 0777 parent would let
  // OTHER uids rename/replace session dirs). O_NOFOLLOW + fstat closes
  // the check-vs-use symlink race.
  const pfd = fs.openSync(
    parent,
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
  )
  try {
    const pst = fs.fstatSync(pfd)
    if (
      !pst.isDirectory() ||
      pst.uid !== process.getuid!() ||
      (pst.mode & 0o022) !== 0
    ) {
      throw new Error(
        `unsafe asset parent dir: ${parent} (must be a 0700-class ` +
          `directory owned by this uid; run \`chmod 0700 ${parent}\` ` +
          'or remove it and retry — the path is derived from the uid ' +
          'and cannot be relocated via environment variables)',
      )
    }
  } finally {
    fs.closeSync(pfd)
  }
  sweepStaleSessionDirs(parent)
  const dir = fs.realpathSync(fs.mkdtempSync(join(parent, 'session-')))
  fs.chmodSync(dir, 0o700)
  // Liveness marker: a lock file recording pid + starttime + pidns.
  // Later sessions' GC compares it against /proc (within the recording
  // namespace only) — SIGKILL'd owners are provably dead there, so the
  // dir is reclaimable even though the exit hook never ran.
  try {
    const lockFd = fs.openSync(join(dir, 'lock'), 'wx', 0o600)
    fs.writeSync(
      lockFd,
      `${process.pid} ${ownStartTime()} ${ownPidNamespace()}`,
    )
    currentLockFd = lockFd // held open; pid+starttime+pidns checked by GC
  } catch {
    // best effort — GC just won't reclaim this dir early
  }
  const st = fs.lstatSync(dir)
  transparentAssetDir = dir
  assetDirIdent = { dev: st.dev, ino: st.ino }
  assetDirsToCleanup.add(dir)
  if (!exitCleanupInstalled) {
    exitCleanupInstalled = true
    process.once('exit', () => {
      for (const d of assetDirsToCleanup) {
        try {
          fs.rmSync(d, { recursive: true, force: true })
        } catch {
          // Best-effort cleanup
        }
      }
    })
  }
  return dir
}

/**
 * Write `content` into the asset dir and hold an fd open on the result.
 * 'wx' (O_EXCL) refuses symlinks and pre-created files.
 */
function materialize(
  name: string,
  content: Buffer,
  mode: number,
): ProtectedFile {
  const path = join(getTransparentAssetDir(), name)
  // recursive: a planted DIRECTORY at the name must clear like any other
  // plant instead of wedging every subsequent materialization.
  fs.rmSync(path, { recursive: true, force: true })
  fs.writeFileSync(path, content, { mode, flag: 'wx' })
  const fd = fs.openSync(path, 'r')
  return { path, fd, content }
}

/**
 * True while `file.path` still names the exact inode `file.fd` holds AND
 * the on-disk bytes equal the in-memory copy. The inode check alone is
 * insufficient: the file could be rewritten in place.
 */
function protectedFileValid(file: ProtectedFile | undefined): boolean {
  if (!file) return false
  try {
    const held = fs.fstatSync(file.fd)
    const onDisk = fs.lstatSync(file.path) // symlinks never validate
    if (
      !onDisk.isFile() ||
      held.dev !== onDisk.dev ||
      held.ino !== onDisk.ino ||
      onDisk.size !== file.content.length
    ) {
      return false
    }
    return fs.readFileSync(file.path).equals(file.content)
  } catch {
    return false
  }
}

/**
 * Resolution discipline: an UNSET record with a
 * valid dir is first-time materialization into the EXISTING dir — the
 * dir must stay stable so the wrap-time ro-bind covers everything later
 * used. Only an actual anomaly (invalid dir, or a set-but-tampered file)
 * abandons the dir for a fresh one.
 */
function resolveProtected(
  current: ProtectedFile | undefined,
  make: () => ProtectedFile,
): ProtectedFile {
  if (assetDirValid()) {
    if (current === undefined) return make()
    if (protectedFileValid(current)) return current
  }
  invalidateAssetDir()
  return make()
}

/**
 * Path to a resolv.conf pointing at the in-sandbox stub resolver
 * (127.0.0.1). Protected like every other asset (content-verified;
 * ro-bound over /etc/resolv.conf by the Linux wrapper).
 */
export function getSandboxResolvConfPath(): string {
  protectedResolvFile = resolveProtected(protectedResolvFile, () =>
    materialize('resolv.conf', RESOLV_CONTENT, 0o444),
  )
  return protectedResolvFile.path
}

/**
 * The helper path actually executed inside the sandbox: a copy of the
 * resolved helper script inside the protected asset dir. The source (dist
 * file or source checkout) may be workload-writable; the copy is not. The
 * source is read exactly once per process — at the first call, which
 * {@link checkTransparentDependencies} makes during initialize(), BEFORE
 * any sandboxed command has run.
 */
export function getProtectedHelperPath(): string | null {
  if (protectedHelperContent === undefined) {
    const source = getTransparentHelperPath()
    if (source === null) return null
    protectedHelperContent = fs.readFileSync(source)
    // .mjs: the copy lives in a bare tmp dir with no package.json, so a
    // plain .js would be parsed as CJS by node (the package's
    // "type":"module" context does not travel with the file).
    protectedHelperExt = source.endsWith('.ts') ? '.ts' : '.mjs'
  }
  protectedHelperFile = resolveProtected(protectedHelperFile, () =>
    materialize(
      `transparent-net-helper${protectedHelperExt}`,
      protectedHelperContent!,
      0o444,
    ),
  )
  return protectedHelperFile.path
}

/**
 * The netns-config bytes the HOST executes — read from the vendor path
 * exactly once per process and NEVER placed on disk again: the
 * rendezvous execs them via an unlinked, content-verified fd (see
 * spawnNetnsConfig in linux-sandbox-utils.ts), so no filesystem state
 * anywhere can change what runs.
 */
export function getNetnsConfigBytes(): Buffer | null {
  if (netnsConfigContent === undefined) {
    const source =
      overrideNetnsConfigPath ?? getVendorSeccompBinaryPath('netns-config')
    if (source === null) return null
    netnsConfigContent = fs.readFileSync(source)
  }
  return netnsConfigContent
}

/**
 * Seed and write the per-session secrets file (0400, asset dir; the
 * helper reads it via SRT_TP_TOKEN_FILE). Argv/cmdline is world-readable;
 * this file is same-uid only (0400). In-sandbox secrecy from the workload itself
 * is not a goal (same trust domain).
 */
let tokensContent: Buffer | undefined

export function writeProtectedTokensFile(
  tokens: Record<string, string>,
): string {
  for (const [k, v] of Object.entries(tokens)) {
    if (/[=\n]/.test(k) || /\n/.test(v)) {
      throw new Error(`invalid token key/value for ${k}`)
    }
  }
  tokensContent = Buffer.from(
    Object.entries(tokens)
      .filter(([, v]) => v !== '')
      .map(([k, v]) => `${k}=${v}`)
      .join('\n') + '\n',
  )
  closeQuietly(protectedTokensFile)
  protectedTokensFile = undefined
  return getProtectedTokensFilePath()!
}

/** Identity+content-verified tokens-file path; re-materializes from memory. */
export function getProtectedTokensFilePath(): string | null {
  if (tokensContent === undefined) return null
  protectedTokensFile = resolveProtected(protectedTokensFile, () =>
    materialize('tokens', tokensContent!, 0o400),
  )
  return protectedTokensFile.path
}

export interface TransparentDependencyResult {
  errors: string[]
}

/**
 * Check the components Linux network sandboxing REQUIRES (no fallback
 * path exists): the vendored `netns-config` binary — run by the HOST to
 * configure each sandbox's netns from outside via setns(); no namespace
 * is ever created, so this works wherever bwrap works — and the
 * in-sandbox helper script. Errors are hard failures for networked
 * sandboxing, same class as a missing bwrap.
 *
 * Side effect by design: resolving the protected helper here takes the
 * host-side copy of the helper at initialize() time, before any sandboxed
 * command can have tampered with the source.
 */
export function checkTransparentDependencies(): TransparentDependencyResult {
  const errors: string[] = []

  // The host executes netns-config ONLY from these bytes (via an
  // unlinked verified fd) — read once here, before any sandboxed command.
  try {
    if (getNetnsConfigBytes() === null) {
      errors.push(
        'netns-config binary not found (vendor/seccomp/<arch>/netns-config) — ' +
          'required for Linux network sandboxing',
      )
    }
  } catch (err) {
    errors.push(
      `netns-config read failed: ${(err as Error).message} — ` +
        'required for Linux network sandboxing',
    )
  }
  try {
    if (getProtectedHelperPath() === null) {
      errors.push(
        'transparent-net helper script not found — required for Linux ' +
          'network sandboxing',
      )
    }
  } catch (err) {
    errors.push(
      `transparent asset setup failed: ${(err as Error).message} — ` +
        'required for Linux network sandboxing',
    )
  }
  return { errors }
}
