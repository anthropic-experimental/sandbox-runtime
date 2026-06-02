import shellquote from 'shell-quote'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import * as fs from 'fs'
import { spawn, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { ripGrep } from '../utils/ripgrep.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  normalizeCaseForComparison,
  isSymlinkOutsideBoundary,
  DANGEROUS_FILES,
  getDangerousDirectories,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import { getSrtLauncherPath, getSrtLauncherInvocation } from './srt-launcher.js'
import type { LauncherConfig } from './sandbox-config.js'

/**
 * State for the Linux network plumbing.
 *
 * The proxy <-> sandbox link is a pair of unix sockets in a private 0700
 * directory owned by the caller. Inside the sandbox, `srt-launcher run
 * --relay 3128 <httpSock> --relay 1080 <socksSock>` listens on the loopback
 * ports and forwards each connection to the corresponding socket.
 *
 * In the common case (sandbox-manager runs its own proxy servers) those
 * servers listen on the unix sockets directly and there is nothing else to
 * track here. When the user supplies an external `httpProxyPort` /
 * `socksProxyPort`, `initializeLinuxNetworkContext` spawns a host-side
 * `srt-launcher relay` per socket to bridge unix -> 127.0.0.1:<port>, and
 * those child processes are recorded for cleanup.
 */
export interface LinuxNetworkContext {
  socketDir: string
  httpSocketPath: string
  socksSocketPath: string
  /** Host-side relay to an external HTTP proxy. Absent for internal proxy. */
  httpRelay?: ChildProcess
  /** Host-side relay to an external SOCKS proxy. Absent for internal proxy. */
  socksRelay?: ChildProcess
}

export interface LinuxSandboxParams {
  command: string
  needsNetworkRestriction: boolean
  httpSocketPath?: string
  socksSocketPath?: string
  /** Path to the TLS-termination CA cert; injected as trust env vars. */
  caCertPath?: string
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  enableWeakerNestedSandbox?: boolean
  allowAllUnixSockets?: boolean
  binShell?: string
  ripgrepConfig?: { command: string; args?: string[] }
  /** Maximum directory depth to search for dangerous files (default: 3) */
  mandatoryDenySearchDepth?: number
  /** Allow writes to .git/config files (default: false) */
  allowGitConfig?: boolean
  /** Location of the srt-launcher helper binary. */
  launcher?: LauncherConfig
  /** Abort signal to cancel the ripgrep scan */
  abortSignal?: AbortSignal
}

/** Default max depth for searching dangerous files */
const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3

/**
 * Find if any component of the path is a symlink within the allowed write paths.
 * Returns the symlink path if found, or null if no symlinks.
 *
 * This is used to detect and block symlink replacement attacks where an attacker
 * could delete a symlink and create a real directory with malicious content.
 */
function findSymlinkInPath(
  targetPath: string,
  allowedWritePaths: string[],
): string | null {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part

    try {
      const stats = fs.lstatSync(nextPath)
      if (stats.isSymbolicLink()) {
        // Check if this symlink is within an allowed write path
        const isWithinAllowedPath = allowedWritePaths.some(
          allowedPath =>
            nextPath.startsWith(allowedPath + '/') || nextPath === allowedPath,
        )
        if (isWithinAllowedPath) {
          return nextPath
        }
      }
    } catch {
      // Path doesn't exist - no symlink issue here
      break
    }
    currentPath = nextPath
  }

  return null
}

/**
 * Check if any existing component in the path is a file (not a directory).
 * If so, the target path can never be created because you can't mkdir under a file.
 *
 * This handles the git worktree case: .git is a file, so .git/hooks can never
 * exist and there's nothing to deny.
 */
function hasFileAncestor(targetPath: string): boolean {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part
    try {
      const stat = fs.statSync(nextPath)
      if (stat.isFile() || stat.isSymbolicLink()) {
        // This component exists as a file — nothing below it can be created
        return true
      }
    } catch {
      // Path doesn't exist — stop checking
      break
    }
    currentPath = nextPath
  }

  return false
}

/**
 * Find the first non-existent path component.
 * E.g., for "/existing/parent/nonexistent/child/file.txt" where /existing/parent exists,
 * returns "/existing/parent/nonexistent"
 *
 * This is used to block creation of non-existent deny paths by mounting /dev/null
 * at the first missing component, preventing mkdir from creating the parent directories.
 */
function findFirstNonExistentComponent(targetPath: string): string {
  const parts = targetPath.split(path.sep)
  let currentPath = ''

  for (const part of parts) {
    if (!part) continue // Skip empty parts (leading /)
    const nextPath = currentPath + path.sep + part
    if (!fs.existsSync(nextPath)) {
      return nextPath
    }
    currentPath = nextPath
  }

  return targetPath // Shouldn't reach here if called correctly
}

/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 * With --max-depth limiting, this is fast enough to run on each command without memoization.
 */
async function linuxGetMandatoryDenyPaths(
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  maxDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const cwd = process.cwd()
  // Use provided signal or create a fallback controller
  const fallbackController = new AbortController()
  const signal = abortSignal ?? fallbackController.signal
  const dangerousDirectories = getDangerousDirectories()

  // Note: Settings files are added at the callsite in sandbox-manager.ts
  const denyPaths = [
    // Dangerous files in CWD
    ...DANGEROUS_FILES.map(f => path.resolve(cwd, f)),
    // Dangerous directories in CWD
    ...dangerousDirectories.map(d => path.resolve(cwd, d)),
  ]

  // Git hooks and config are only denied when .git exists as a directory.
  // In git worktrees, .git is a file (e.g., "gitdir: /path/..."), so
  // .git/hooks can never exist — denying it would cause the launcher's
  // ro-bind to fail. When .git doesn't exist at all, mounting at .git would
  // block its creation and break git init.
  const dotGitPath = path.resolve(cwd, '.git')
  let dotGitIsDirectory = false
  try {
    dotGitIsDirectory = fs.statSync(dotGitPath).isDirectory()
  } catch {
    // .git doesn't exist
  }

  if (dotGitIsDirectory) {
    // Git hooks always blocked for security
    denyPaths.push(path.resolve(cwd, '.git/hooks'))

    // Git config conditionally blocked based on allowGitConfig setting
    if (!allowGitConfig) {
      denyPaths.push(path.resolve(cwd, '.git/config'))
    }
  }

  // Build iglob args for all patterns in one ripgrep call
  const iglobArgs: string[] = []
  for (const fileName of DANGEROUS_FILES) {
    iglobArgs.push('--iglob', fileName)
  }
  for (const dirName of dangerousDirectories) {
    iglobArgs.push('--iglob', `**/${dirName}/**`)
  }
  // Git hooks always blocked in nested repos
  iglobArgs.push('--iglob', '**/.git/hooks/**')

  // Git config conditionally blocked in nested repos
  if (!allowGitConfig) {
    iglobArgs.push('--iglob', '**/.git/config')
  }

  // Single ripgrep call to find all dangerous paths in subdirectories
  // Limit depth for performance - deeply nested dangerous files are rare
  // and the security benefit doesn't justify the traversal cost
  let matches: string[] = []
  try {
    matches = await ripGrep(
      [
        '--files',
        '--hidden',
        '--max-depth',
        String(maxDepth),
        ...iglobArgs,
        '-g',
        '!**/node_modules/**',
      ],
      cwd,
      signal,
      ripgrepConfig,
    )
  } catch (error) {
    logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`)
  }

  // Process matches
  for (const match of matches) {
    const absolutePath = path.resolve(cwd, match)

    // File inside a dangerous directory -> add the directory path
    let foundDir = false
    for (const dirName of [...dangerousDirectories, '.git']) {
      const normalizedDirName = normalizeCaseForComparison(dirName)
      const segments = absolutePath.split(path.sep)
      const dirIndex = segments.findIndex(
        s => normalizeCaseForComparison(s) === normalizedDirName,
      )
      if (dirIndex !== -1) {
        // For .git, we want hooks/ or config, not the whole .git dir
        if (dirName === '.git') {
          const gitDir = segments.slice(0, dirIndex + 1).join(path.sep)
          if (match.includes('.git/hooks')) {
            denyPaths.push(path.join(gitDir, 'hooks'))
          } else if (match.includes('.git/config')) {
            denyPaths.push(path.join(gitDir, 'config'))
          }
        } else {
          denyPaths.push(segments.slice(0, dirIndex + 1).join(path.sep))
        }
        foundDir = true
        break
      }
    }

    // Dangerous file match
    if (!foundDir) {
      denyPaths.push(absolutePath)
    }
  }

  return [...new Set(denyPaths)]
}

// Track mount points created by srt-launcher for non-existent deny paths.
// When the launcher does --ro-bind /dev/null /nonexistent/path, it creates an
// empty file on the host as a mount point. These persist after the sandbox
// exits and must be cleaned up explicitly.
const sandboxMountPoints: Set<string> = new Set()

// Number of wrapped commands that have been generated but whose cleanup has
// not yet run. cleanupSandboxMountPoints() defers file deletion while this is
// positive, because deleting a mount point file on the host while another
// sandbox instance is still running detaches that instance's bind mount and
// the deny rule stops applying inside it.
let activeSandboxCount = 0

let exitHandlerRegistered = false

/**
 * Register cleanup handler for sandbox mount points
 */
function registerExitCleanupHandler(): void {
  if (exitHandlerRegistered) {
    return
  }

  process.on('exit', () => {
    cleanupSandboxMountPoints({ force: true })
  })

  exitHandlerRegistered = true
}

/**
 * Clean up mount point files created by the launcher for non-existent deny
 * paths.
 *
 * When protecting non-existent deny paths, the launcher creates empty files on
 * the host filesystem as mount points for --ro-bind. These files persist after
 * the sandbox exits. This function removes them.
 *
 * This should be called after each sandboxed command completes to prevent
 * ghost dotfiles (e.g. .bashrc, .gitconfig) from appearing in the working
 * directory. It is also called automatically on process exit as a safety net.
 *
 * Each call decrements the active-sandbox counter that was incremented by
 * wrapCommandWithSandboxLinux(). File deletion is deferred until the counter
 * reaches zero. Deleting a mount point file on the host while another sandbox
 * instance is still running detaches that instance's bind mount (the dentry is
 * unhashed, so path lookup no longer finds the mount) and the deny rule stops
 * applying inside that sandbox.
 *
 * Pass `{ force: true }` to delete unconditionally — used by the process-exit
 * handler and reset() where deferral is not meaningful.
 */
export function cleanupSandboxMountPoints(opts?: { force?: boolean }): void {
  if (!opts?.force) {
    if (activeSandboxCount > 0) {
      activeSandboxCount--
    }
    if (activeSandboxCount > 0) {
      logForDebugging(
        `[Sandbox Linux] Deferring mount point cleanup — ${activeSandboxCount} sandbox(es) still active`,
      )
      return
    }
  } else {
    activeSandboxCount = 0
  }

  for (const mountPoint of sandboxMountPoints) {
    try {
      // Only remove if it's still the empty file/directory the launcher
      // created. If something else has written real content, leave it alone.
      const stat = fs.statSync(mountPoint)
      if (stat.isFile() && stat.size === 0) {
        fs.unlinkSync(mountPoint)
        logForDebugging(
          `[Sandbox Linux] Cleaned up mount point (file): ${mountPoint}`,
        )
      } else if (stat.isDirectory()) {
        // Empty directory mount points are created for intermediate
        // components (Fix 2). Only remove if still empty.
        const entries = fs.readdirSync(mountPoint)
        if (entries.length === 0) {
          fs.rmdirSync(mountPoint)
          logForDebugging(
            `[Sandbox Linux] Cleaned up mount point (dir): ${mountPoint}`,
          )
        }
      }
    } catch {
      // Ignore cleanup errors — the file may have already been removed
    }
  }
  sandboxMountPoints.clear()
}

/**
 * Detailed status of Linux sandbox dependencies
 */
export type LinuxDependencyStatus = {
  hasLauncher: boolean
}

/**
 * Result of checking sandbox dependencies
 */
export type SandboxDependencyCheck = {
  warnings: string[]
  errors: string[]
}

/**
 * Get detailed status of Linux sandbox dependencies.
 *
 * srt-launcher is the only native dependency on Linux — it bundles namespace
 * isolation, the in-sandbox relay, and the seccomp filter into one
 * statically-linked binary.
 */
export function getLinuxDependencyStatus(
  cfg?: LauncherConfig,
): LinuxDependencyStatus {
  return { hasLauncher: getSrtLauncherPath(cfg) !== null }
}

/**
 * Check sandbox dependencies and return structured result
 */
export function checkLinuxDependencies(
  cfg?: LauncherConfig,
): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []

  if (getSrtLauncherPath(cfg) === null) {
    if (cfg?.path) {
      errors.push(`srt-launcher not executable at ${cfg.path}`)
    } else {
      errors.push(
        'srt-launcher binary not found (vendor/srt-launcher/<arch>/srt-launcher). ' +
          'This package ships it; if you are bundling, ensure the vendor ' +
          'directory is preserved or set launcher.path explicitly.',
      )
    }
  }

  return { warnings, errors }
}

/**
 * Spawn a host-side `srt-launcher relay` that listens on `socketPath` and
 * forwards each connection to `127.0.0.1:port`. Resolves once the relay has
 * written its readiness byte to fd 3.
 *
 * The returned child has been `unref()`ed; the binary sets PR_SET_PDEATHSIG
 * so it dies with this process. Callers tear it down with
 * `proc.kill('SIGKILL')`.
 */
async function spawnHostRelay(
  invocation: { argv: string[]; env: Record<string, string> },
  socketPath: string,
  port: number,
  label: string,
): Promise<ChildProcess> {
  const [bin, ...prefix] = invocation.argv
  // Ready-fd is the relay's stdout. The relay writes one byte once it's
  // listening, then closes it; nothing else ever goes to stdout. We avoid an
  // extra `stdio: [..., 'pipe']` (fd 3) slot here because Bun's fd accounting
  // for extra-stdio pipes is fragile across spawn-then-kill cycles: after ~6
  // such children, the next `http.Server.listen()` in the same process returns
  // `address() === null`. Reproduced standalone; stdout is robust.
  const proc = spawn(
    bin!,
    [...prefix, '--ready-fd', '1', socketPath, `127.0.0.1:${port}`],
    {
      stdio: ['ignore', 'pipe', 'inherit'],
      env: { ...process.env, ...invocation.env },
    },
  )

  const readyPipe = proc.stdout!

  // Race readiness against premature exit. Swallow the loser so a later
  // 'error' or 'exit' doesn't surface as an unhandled rejection.
  const readyP = once(readyPipe, 'data')
  readyP.catch(() => {})
  const exitP = once(proc, 'exit')
  exitP.catch(() => {})

  const winner = await Promise.race([
    readyP.then(() => 'ready' as const),
    exitP.then(r => r as [number | null, NodeJS.Signals | null]),
  ])
  if (winner !== 'ready') {
    const [code, signal] = winner
    throw new Error(
      `srt-launcher ${label} relay exited before becoming ready ` +
        `(code=${code}, signal=${signal})`,
    )
  }

  // Detach: PR_SET_PDEATHSIG in the relay handles parent death; we don't keep
  // the event loop alive on this child. Drop the dangling 'exit' listener from
  // the race so the handle is fully quiescent.
  proc.removeAllListeners('exit')
  readyPipe.destroy()
  proc.unref()
  return proc
}

/**
 * Prepare the Linux network context for a sandbox session.
 *
 * The caller (sandbox-manager) owns the private 0700 mkdtemp socket directory
 * and passes the two socket paths in. There are two modes:
 *
 *  - Internal proxy (no `externalHttpPort`/`externalSocksPort`): the caller
 *    has already bound its own proxy servers to the unix socket paths. This
 *    function does nothing beyond packaging the paths into a context object.
 *
 *  - External proxy: the caller passed `network.httpProxyPort` /
 *    `network.socksProxyPort` from config. Spawn one `srt-launcher relay` per
 *    port to bridge the unix socket to `127.0.0.1:<port>`, wait for readiness,
 *    and record the child for cleanup.
 *
 * In both modes, the in-sandbox side is wired up later by
 * `wrapCommandWithSandboxLinux` via `--relay 3128 <httpSock>` /
 * `--relay 1080 <socksSock>`.
 */
export async function initializeLinuxNetworkContext(
  httpSocketPath: string,
  socksSocketPath: string,
  externalHttpPort?: number,
  externalSocksPort?: number,
  launcherCfg?: LauncherConfig,
): Promise<LinuxNetworkContext> {
  const ctx: LinuxNetworkContext = {
    socketDir: path.dirname(httpSocketPath),
    httpSocketPath,
    socksSocketPath,
  }

  if (externalHttpPort === undefined && externalSocksPort === undefined) {
    // Internal-proxy mode: caller already listened on the sockets.
    return ctx
  }

  const invocation = getSrtLauncherInvocation(launcherCfg, 'relay')
  if (!invocation) {
    throw new Error(
      'srt-launcher binary not found — cannot bridge to external proxy',
    )
  }

  try {
    if (externalHttpPort !== undefined) {
      ctx.httpRelay = await spawnHostRelay(
        invocation,
        httpSocketPath,
        externalHttpPort,
        'HTTP',
      )
      logForDebugging(
        `[Sandbox Linux] HTTP relay listening at ${httpSocketPath} -> 127.0.0.1:${externalHttpPort}`,
      )
    }
    if (externalSocksPort !== undefined) {
      ctx.socksRelay = await spawnHostRelay(
        invocation,
        socksSocketPath,
        externalSocksPort,
        'SOCKS',
      )
      logForDebugging(
        `[Sandbox Linux] SOCKS relay listening at ${socksSocketPath} -> 127.0.0.1:${externalSocksPort}`,
      )
    }
  } catch (err) {
    // Partial-failure cleanup: kill whatever started.
    ctx.httpRelay?.kill('SIGKILL')
    ctx.socksRelay?.kill('SIGKILL')
    throw err
  }

  return ctx
}

/**
 * Generate filesystem bind mount arguments for srt-launcher.
 *
 * The flag surface (--bind / --ro-bind / --tmpfs) is identical to bwrap's, so
 * the bind-mount-deny mechanism (mount /dev/null over deny paths, tmpfs over
 * deny-read directories, re-bind writes underneath) is unchanged.
 */
async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  mandatoryDenySearchDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  allowGitConfig = false,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const args: string[] = []
  // fs already imported

  // Collect normalized allowed write paths. Populated in the writeConfig
  // block, read again in the denyRead loop to re-bind writes under tmpfs.
  const allowedWritePaths: string[] = []
  // denyWrite binds are buffered and emitted after denyRead processing so that
  // a denyRead tmpfs over an ancestor directory doesn't wipe them out.
  const denyWriteArgs: string[] = []

  // Determine initial root mount based on write restrictions
  if (writeConfig) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.push('--ro-bind', '/', '/')

    // Allow writes to specific paths
    for (const pathPattern of writeConfig.allowOnly || []) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      logForDebugging(
        `[Sandbox Linux] Processing write path: ${pathPattern} -> ${normalizedPath}`,
      )

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        logForDebugging(`[Sandbox Linux] Skipping /dev path: ${normalizedPath}`)
        continue
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent write path: ${normalizedPath}`,
        )
        continue
      }

      // Check if path is a symlink pointing outside expected boundaries.
      // The launcher follows symlinks, so --bind on a symlink makes the target
      // writable. This could unexpectedly expose paths the user didn't intend
      // to allow.
      try {
        const resolvedPath = fs.realpathSync(normalizedPath)
        // Trim trailing slashes before comparing: realpathSync never returns
        // a trailing slash, but normalizedPath may have one, which would cause
        // a false mismatch and incorrectly treat the path as a symlink.
        const normalizedForComparison = normalizedPath.replace(/\/+$/, '')
        if (
          resolvedPath !== normalizedForComparison &&
          isSymlinkOutsideBoundary(normalizedPath, resolvedPath)
        ) {
          logForDebugging(
            `[Sandbox Linux] Skipping symlink write path pointing outside expected location: ${pathPattern} -> ${resolvedPath}`,
          )
          continue
        }
      } catch {
        // realpathSync failed - path might not exist or be accessible, skip it
        logForDebugging(
          `[Sandbox Linux] Skipping write path that could not be resolved: ${normalizedPath}`,
        )
        continue
      }

      args.push('--bind', normalizedPath, normalizedPath)
      allowedWritePaths.push(normalizedPath)
    }

    // Deny writes within allowed paths (user-specified + mandatory denies)
    const denyPaths = [
      ...(writeConfig.denyWithinAllow || []),
      ...(await linuxGetMandatoryDenyPaths(
        ripgrepConfig,
        mandatoryDenySearchDepth,
        allowGitConfig,
        abortSignal,
      )),
    ]

    // Dedup post-normalization: entries like ['~/.foo', '/home/user/.foo']
    // converge to the same path here. A duplicate --ro-bind /dev/null <dest>
    // hits a char device on the second pass and the launcher's ensure_file()
    // falls through to creat() on a read-only mount.
    const seenDenyWrite = new Set<string>()
    // Directories already ro-bound; a child deny under one of these is
    // redundant and srt-launcher's ensure_file() would creat() the child
    // mountpoint inside what is now a read-only mount.
    const denyWriteDirs: string[] = []
    for (const pathPattern of denyPaths) {
      const normalizedPath = normalizePathForSandbox(pathPattern)
      if (seenDenyWrite.has(normalizedPath)) continue
      seenDenyWrite.add(normalizedPath)
      if (denyWriteDirs.some(d => normalizedPath.startsWith(d + '/'))) {
        logForDebugging(
          `[Sandbox Linux] Skipping deny path under already-denied dir: ${normalizedPath}`,
        )
        continue
      }

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        continue
      }

      // Check for symlinks in the path - if any parent component is a symlink,
      // mount /dev/null there to prevent symlink replacement attacks.
      // Attack scenario: .claude is a symlink to ./decoy/, attacker deletes
      // symlink and creates real .claude/settings.json with malicious hooks.
      const symlinkInPath = findSymlinkInPath(normalizedPath, allowedWritePaths)
      if (symlinkInPath) {
        denyWriteArgs.push('--ro-bind', '/dev/null', symlinkInPath)
        logForDebugging(
          `[Sandbox Linux] Mounted /dev/null at symlink ${symlinkInPath} to prevent symlink replacement attack`,
        )
        continue
      }

      // Handle non-existent paths by mounting /dev/null to block creation.
      // Without this, a sandboxed process could mkdir+write a denied path that
      // doesn't exist yet, bypassing the deny rule entirely.
      //
      // The launcher creates empty files on the host as mount points for these
      // binds. We track them in sandboxMountPoints so cleanupSandboxMountPoints()
      // can remove them after the command exits.
      if (!fs.existsSync(normalizedPath)) {
        // Fix 1 (worktree): If any existing component in the deny path is a
        // file (not a directory), skip the deny entirely. You can't mkdir
        // under a file, so the deny path can never be created. This handles
        // git worktrees where .git is a file.
        if (hasFileAncestor(normalizedPath)) {
          logForDebugging(
            `[Sandbox Linux] Skipping deny path with file ancestor (cannot create paths under a file): ${normalizedPath}`,
          )
          continue
        }

        // Find the deepest existing ancestor directory
        let ancestorPath = path.dirname(normalizedPath)
        while (ancestorPath !== '/' && !fs.existsSync(ancestorPath)) {
          ancestorPath = path.dirname(ancestorPath)
        }

        // Only protect if the existing ancestor is within an allowed write path.
        // If not, the path is already read-only from --ro-bind / /.
        const ancestorIsWithinAllowedPath = allowedWritePaths.some(
          allowedPath =>
            ancestorPath.startsWith(allowedPath + '/') ||
            ancestorPath === allowedPath ||
            normalizedPath.startsWith(allowedPath + '/'),
        )

        if (ancestorIsWithinAllowedPath) {
          const firstNonExistent = findFirstNonExistentComponent(normalizedPath)

          // Fix 2: If firstNonExistent is an intermediate component (not the
          // leaf deny path itself), mount a read-only empty directory instead
          // of /dev/null. This prevents the component from appearing as a file
          // which breaks tools that expect to traverse it as a directory.
          if (firstNonExistent !== normalizedPath) {
            const emptyDir = fs.mkdtempSync(
              path.join(tmpdir(), 'claude-empty-'),
            )
            denyWriteArgs.push('--ro-bind', emptyDir, firstNonExistent)
            sandboxMountPoints.add(firstNonExistent)
            registerExitCleanupHandler()
            logForDebugging(
              `[Sandbox Linux] Mounted empty dir at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          } else {
            denyWriteArgs.push('--ro-bind', '/dev/null', firstNonExistent)
            sandboxMountPoints.add(firstNonExistent)
            registerExitCleanupHandler()
            logForDebugging(
              `[Sandbox Linux] Mounted /dev/null at ${firstNonExistent} to block creation of ${normalizedPath}`,
            )
          }
        } else {
          logForDebugging(
            `[Sandbox Linux] Skipping non-existent deny path not within allowed paths: ${normalizedPath}`,
          )
        }
        continue
      }

      // Only add deny binding if this path is within an allowed write path
      // Otherwise it's already read-only from the initial --ro-bind / /
      const isWithinAllowedPath = allowedWritePaths.some(
        allowedPath =>
          normalizedPath.startsWith(allowedPath + '/') ||
          normalizedPath === allowedPath,
      )

      if (isWithinAllowedPath) {
        denyWriteArgs.push('--ro-bind', normalizedPath, normalizedPath)
        try {
          if (fs.statSync(normalizedPath).isDirectory()) {
            denyWriteDirs.push(normalizedPath)
          }
        } catch {
          // ignore
        }
      } else {
        logForDebugging(
          `[Sandbox Linux] Skipping deny path not within allowed paths: ${normalizedPath}`,
        )
      }
    }
  } else {
    // No write restrictions: Allow all writes
    args.push('--bind', '/', '/')
  }
  // denyWriteArgs is emitted after the denyRead loop below.

  // Handle read restrictions by mounting tmpfs over denied paths
  const readDenyPaths: string[] = []
  const readAllowPaths = (readConfig?.allowWithinDeny || []).map(p =>
    normalizePathForSandbox(p),
  )
  // Files masked by --ro-bind /dev/null below. Used to filter denyWriteArgs so
  // that --ro-bind <host> <host> doesn't undo the mask.
  const maskedFiles = new Set<string>()

  // --tmpfs / would wipe all prior mounts (ro-bind /, write binds, deny binds).
  // Expand a root deny into its direct children so the existing per-dir tmpfs
  // + re-bind logic applies. Skip /proc and /dev: they're remounted by the
  // caller after this function returns. Skip /sys: kernel interface, tmpfs
  // over it breaks tooling and the host /sys is already read-only via ro-bind.
  const rootSkip = new Set(['proc', 'dev', 'sys'])
  for (const p of readConfig?.denyOnly || []) {
    if (normalizePathForSandbox(p) === '/') {
      for (const child of fs.readdirSync('/')) {
        if (!rootSkip.has(child)) readDenyPaths.push('/' + child)
      }
    } else {
      readDenyPaths.push(p)
    }
  }

  // Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
  // SSH is very strict about config file permissions and ownership, and they can
  // appear wrong inside the sandbox causing "Bad owner or permissions" errors
  if (fs.existsSync('/etc/ssh/ssh_config.d')) {
    readDenyPaths.push('/etc/ssh/ssh_config.d')
  }

  // Normalize then sort shallow-first so tmpfs over ancestor dirs lands before
  // /dev/null masks on descendant files. Otherwise a file-deny listed before
  // a dir-deny in denyRead gets wiped when the ancestor tmpfs is applied.
  const normalizedDenyPaths = readDenyPaths
    .map(p => normalizePathForSandbox(p))
    .sort((a, b) => a.split('/').length - b.split('/').length)

  for (const normalizedPath of normalizedDenyPaths) {
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent read deny path: ${normalizedPath}`,
      )
      continue
    }

    const denySep = normalizedPath === '/' ? '/' : normalizedPath + '/'
    const readDenyStat = fs.statSync(normalizedPath)
    if (readDenyStat.isDirectory()) {
      args.push('--tmpfs', normalizedPath)

      // tmpfs wiped any earlier write binds under this path — restore them.
      for (const writePath of allowedWritePaths) {
        if (writePath.startsWith(denySep) || writePath === normalizedPath) {
          args.push('--bind', writePath, writePath)
          logForDebugging(
            `[Sandbox Linux] Re-bound write path wiped by denyRead tmpfs: ${writePath}`,
          )
        }
      }

      // Re-allow specific paths within the denied directory (allowRead overrides denyRead).
      // After mounting tmpfs over the denied dir, bind back the allowed subdirectories
      // so they are readable again.
      for (const allowPath of readAllowPaths) {
        if (allowPath.startsWith(denySep) || allowPath === normalizedPath) {
          if (!fs.existsSync(allowPath)) {
            logForDebugging(
              `[Sandbox Linux] Skipping non-existent read allow path: ${allowPath}`,
            )
            continue
          }
          // Skip only if a write path was re-bound just above AND covers
          // allowPath. A write path that's an ancestor of the deny dir isn't
          // re-bound (it wasn't wiped), so allowPath under it still needs
          // its own ro-bind here.
          if (
            allowedWritePaths.some(
              w =>
                (w.startsWith(denySep) || w === normalizedPath) &&
                (allowPath === w || allowPath.startsWith(w + '/')),
            )
          ) {
            continue
          }
          // Bind the allowed path back over the tmpfs so it's readable
          args.push('--ro-bind', allowPath, allowPath)
          logForDebugging(
            `[Sandbox Linux] Re-allowed read access within denied region: ${allowPath}`,
          )
        }
      }
    } else {
      // For files, only an exact allowRead match overrides the deny. A
      // directory allowRead does not un-deny a file specifically listed in
      // denyRead — otherwise denyRead: ['.env'] + allowRead: ['.'] silently
      // drops the .env deny.
      if (readAllowPaths.includes(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping read deny for re-allowed path: ${normalizedPath}`,
        )
        continue
      }
      // For files, bind /dev/null instead of tmpfs
      args.push('--ro-bind', '/dev/null', normalizedPath)
      maskedFiles.add(normalizedPath)
    }
  }

  // Emitting denyWrite last means these ro-binds layer on top of any write
  // paths the denyRead loop just re-bound. Before this ordering, tmpfs over
  // an ancestor of cwd would wipe the .git/hooks protection. But skip any
  // dest already masked by denyRead — --ro-bind <host> <host> for denyWrite
  // would undo --ro-bind /dev/null <host> from denyRead, which landed first.
  for (let i = 0; i < denyWriteArgs.length; i += 3) {
    const dest = denyWriteArgs[i + 2]!
    if (maskedFiles.has(dest)) continue
    args.push(denyWriteArgs[i]!, denyWriteArgs[i + 1]!, dest)
  }

  return args
}

/**
 * Wrap a command with sandbox restrictions on Linux.
 *
 * Emits a single shell-quoted `srt-launcher run` invocation. The launcher
 * handles, in one process:
 *
 *  - namespace isolation: `--unshare-pid` (always), `--unshare-net` when
 *    network is restricted, `--unshare-user` only in the weaker-nested mode.
 *  - filesystem: `--ro-bind / /` + per-path `--bind`/`--ro-bind`/`--tmpfs`
 *    layered on top, `--dev /dev`, and either a fresh `--proc /proc` or a
 *    bind of the host's `/proc` (`--host-proc /proc`) when running inside an
 *    unprivileged container that can't mount procfs.
 *  - in-sandbox proxy relay: `--relay 3128 <httpSock>` /
 *    `--relay 1080 <socksSock>` fork TCP listeners on loopback inside the
 *    netns that forward to the unix sockets owned by the host-side proxy.
 *  - seccomp: `--seccomp-unix-block` applies the baked-in BPF filter that
 *    rejects `socket(AF_UNIX, ...)` after the relay sockets are open, so the
 *    workload can't open new unix sockets but the relays still work.
 *
 * The seccomp filter only blocks creation; it does not block operations on
 * inherited unix-socket fds nor SCM_RIGHTS passing. allowUnixSockets is not
 * path-based on Linux because seccomp-bpf cannot inspect user-space memory.
 */
export async function wrapCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<string> {
  const {
    command,
    needsNetworkRestriction,
    httpSocketPath,
    socksSocketPath,
    caCertPath,
    readConfig,
    writeConfig,
    enableWeakerNestedSandbox,
    allowAllUnixSockets,
    binShell,
    ripgrepConfig = { command: 'rg' },
    mandatoryDenySearchDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allowGitConfig = false,
    launcher,
    abortSignal,
  } = params

  // Determine if we have restrictions to apply
  // Read: denyOnly pattern - empty array means no restrictions
  // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
  const hasReadRestrictions = readConfig && readConfig.denyOnly.length > 0
  const hasWriteRestrictions = writeConfig !== undefined

  // Check if we need any sandboxing
  if (
    !needsNetworkRestriction &&
    !hasReadRestrictions &&
    !hasWriteRestrictions
  ) {
    return command
  }

  const launcherPath = getSrtLauncherPath(launcher)
  if (!launcherPath) {
    throw new Error(
      'srt-launcher binary not found. Run checkLinuxDependencies() before ' +
        'wrapping commands, or set launcher.path explicitly.',
    )
  }

  // Mark this sandbox invocation as active. cleanupSandboxMountPoints() will
  // defer file deletion until this (and every other concurrent) invocation
  // has been cleaned up. The matching decrement happens in
  // cleanupSandboxMountPoints(), which the caller must invoke after the
  // spawned command exits. If wrapping fails below, the catch block
  // decrements so the count does not leak.
  activeSandboxCount++

  // PID namespace, setsid, and PR_SET_PDEATHSIG are not flag-gated — the
  // launcher applies them unconditionally (they're correctness properties,
  // not tunables). /proc is mounted further down, after the filesystem args:
  // srt-launcher applies mounts in argument order, so a later `--ro-bind / /`
  // would overmount a /proc placed here and expose the host PID list.
  const args: string[] = ['run']

  try {
    if (enableWeakerNestedSandbox) {
      // Unprivileged-container mode: --unshare-user forces the userns path so
      // the launcher gets the caps it needs for the other unshares.
      args.push('--unshare-user')
    }

    // ========== NETWORK RESTRICTIONS ==========
    if (needsNetworkRestriction) {
      // Isolated network namespace: only loopback exists inside.
      args.push('--unshare-net')

      // If proxy sockets are provided, wire up the in-sandbox relays so
      // filtered traffic can leave via the host proxy. If not provided,
      // network is completely blocked.
      if (httpSocketPath && socksSocketPath) {
        if (!fs.existsSync(httpSocketPath)) {
          throw new Error(
            `Linux HTTP proxy socket does not exist: ${httpSocketPath}. ` +
              'The proxy may have died. Try reinitializing the sandbox.',
          )
        }
        if (!fs.existsSync(socksSocketPath)) {
          throw new Error(
            `Linux SOCKS proxy socket does not exist: ${socksSocketPath}. ` +
              'The proxy may have died. Try reinitializing the sandbox.',
          )
        }

        args.push('--relay', '3128', httpSocketPath)
        args.push('--relay', '1080', socksSocketPath)

        // Proxy environment variables: HTTP_PROXY etc. point at the
        // in-sandbox relay listeners on loopback.
        const proxyEnv = generateProxyEnvVars(
          3128,
          1080,
          caCertPath,
          launcherPath,
        )
        for (const env of proxyEnv) {
          const eq = env.indexOf('=')
          args.push('--setenv', env.slice(0, eq), env.slice(eq + 1))
        }
      }
    }

    // ========== SECCOMP FILTER (Unix Socket Blocking) ==========
    // The launcher applies the filter after the relay sockets are open, so the
    // relays keep working but the workload can't create new AF_UNIX sockets.
    if (!allowAllUnixSockets) {
      args.push('--seccomp-unix-block')
      logForDebugging(
        '[Sandbox Linux] Applying seccomp filter for Unix socket blocking',
      )
    } else {
      logForDebugging(
        '[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled',
      )
    }

    // ========== FILESYSTEM RESTRICTIONS ==========
    const fsArgs = await generateFilesystemArgs(
      readConfig,
      writeConfig,
      ripgrepConfig,
      mandatoryDenySearchDepth,
      allowGitConfig,
      abortSignal,
    )
    args.push(...fsArgs)

    // /proc and /dev go after the filesystem args so the root bind from
    // generateFilesystemArgs() doesn't overmount them.
    if (!enableWeakerNestedSandbox) {
      args.push('--proc', '/proc')
    } else {
      // Unprivileged-container mode: the host kernel won't let us mount a
      // fresh procfs. --host-proc binds the outer /proc read-write so
      // /proc/self/{setgroups,uid_map} are writable for the nested userns
      // setup.
      args.push('--host-proc', '/proc')
    }
    args.push('--dev', '/dev')

    // ========== COMMAND ==========
    // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
    // Resolve the full path to the shell binary since the launcher doesn't use $PATH
    const shellName = binShell || 'bash'
    const shell = whichSync(shellName)
    if (!shell) {
      throw new Error(`Shell '${shellName}' not found in PATH`)
    }
    // srt-launcher captures its spawn-time cwd before pivot_root and restores
    // it best-effort afterwards (falling back to / if the path doesn't exist
    // inside the sandbox), so the inner shell sees the caller's cwd without
    // any TS-side handling.
    args.push('--', shell, '-c', command)

    // Multicall mode: when the launcher is compiled into a host binary that
    // dispatches on the ARGV0 env var, prepend the env-assignment word so the
    // shell sets it for the launcher process only.
    const argv0Prefix = launcher?.argv0
      ? 'ARGV0=' + shellquote.quote([launcher.argv0]) + ' '
      : ''
    const wrappedCommand =
      argv0Prefix + shellquote.quote([launcherPath, ...args])

    const restrictions = []
    if (needsNetworkRestriction) restrictions.push('network')
    if (hasReadRestrictions || hasWriteRestrictions)
      restrictions.push('filesystem')
    if (!allowAllUnixSockets) restrictions.push('seccomp(unix-block)')

    logForDebugging(
      `[Sandbox Linux] Wrapped command with srt-launcher (${restrictions.join(', ')} restrictions)`,
    )

    return wrappedCommand
  } catch (error) {
    // Undo the activeSandboxCount increment — the caller won't call
    // cleanupSandboxMountPoints() for a wrap that threw.
    if (activeSandboxCount > 0) {
      activeSandboxCount--
    }
    throw error
  }
}
