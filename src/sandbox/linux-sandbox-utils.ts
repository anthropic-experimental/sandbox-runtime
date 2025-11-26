import shellquote from 'shell-quote'
import { logForDebugging } from '../utils/debug.js'
import { randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { tmpdir } from 'node:os'
import path, { join } from 'node:path'
import { ripGrep } from '../utils/ripgrep.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  normalizeCaseForComparison,
  DANGEROUS_FILES,
  getDangerousDirectories,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'
import {
  generateSeccompFilter,
  cleanupSeccompFilter,
  getPreGeneratedBpfPath,
  getApplySeccompBinaryPath,
} from './generate-seccomp-filter.js'

export interface LinuxNetworkBridgeContext {
  httpSocketPath: string
  socksSocketPath: string
  httpBridgeProcess: ChildProcess
  socksBridgeProcess: ChildProcess
  httpProxyPort: number
  socksProxyPort: number
}

export interface LinuxSandboxParams {
  command: string
  needsNetworkRestriction: boolean
  httpSocketPath?: string
  socksSocketPath?: string
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
  enableWeakerNestedSandbox?: boolean
  allowAllUnixSockets?: boolean
  binShell?: string
  ripgrepConfig?: { command: string; args?: string[] }
  /** Maximum directory depth to search for dangerous files (default: 3) */
  mandatoryDenySearchDepth?: number
  /** Abort signal to cancel the ripgrep scan */
  abortSignal?: AbortSignal
}

/** Default max depth for searching dangerous files */
const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3

/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 * With --max-depth limiting, this is fast enough to run on each command without memoization.
 */
async function linuxGetMandatoryDenyPaths(
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  maxDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
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
    // Git paths in CWD
    path.resolve(cwd, '.git/hooks'),
    path.resolve(cwd, '.git/config'),
  ]

  // Build iglob args for all patterns in one ripgrep call
  const iglobArgs: string[] = []
  for (const fileName of DANGEROUS_FILES) {
    iglobArgs.push('--iglob', fileName)
  }
  for (const dirName of dangerousDirectories) {
    iglobArgs.push('--iglob', `**/${dirName}/**`)
  }
  // Git hooks and config in nested repos
  iglobArgs.push('--iglob', '**/.git/hooks/**')
  iglobArgs.push('--iglob', '**/.git/config')

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

// Track generated seccomp filters for cleanup on process exit
const generatedSeccompFilters: Set<string> = new Set()
let exitHandlerRegistered = false

/**
 * Register cleanup handler for generated seccomp filters
 */
function registerSeccompCleanupHandler(): void {
  if (exitHandlerRegistered) {
    return
  }

  process.on('exit', () => {
    for (const filterPath of generatedSeccompFilters) {
      try {
        cleanupSeccompFilter(filterPath)
      } catch {
        // Ignore cleanup errors during exit
      }
    }
  })

  exitHandlerRegistered = true
}

/**
 * Check if Linux sandbox dependencies are available (synchronous)
 * Returns true if bwrap and socat are installed.
 */
export function hasLinuxSandboxDependenciesSync(
  allowAllUnixSockets = false,
): boolean {
  try {
    const bwrapResult = spawnSync('which', ['bwrap'], {
      stdio: 'ignore',
      timeout: 1000,
    })
    const socatResult = spawnSync('which', ['socat'], {
      stdio: 'ignore',
      timeout: 1000,
    })

    const hasBasicDeps = bwrapResult.status === 0 && socatResult.status === 0

    // Check for seccomp dependencies (optional security feature)
    if (!allowAllUnixSockets) {
      // Check if we have a pre-generated BPF filter for this architecture
      const hasPreGeneratedBpf = getPreGeneratedBpfPath() !== null

      // Check if we have the apply-seccomp binary for this architecture
      const hasApplySeccompBinary = getApplySeccompBinaryPath() !== null

      if (!hasPreGeneratedBpf || !hasApplySeccompBinary) {
        // Seccomp not available - log warning but continue with basic sandbox
        // The sandbox will gracefully fall back to allowAllUnixSockets mode
        logForDebugging(
          `[Sandbox Linux] Seccomp filtering not available (missing binaries for ${process.arch}). ` +
            `Sandbox will run without Unix socket blocking (allowAllUnixSockets mode). ` +
            `This is less restrictive but still provides filesystem and network isolation.`,
          { level: 'warn' },
        )
      }
    }

    return hasBasicDeps
  } catch {
    return false
  }
}

/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
export async function initializeLinuxNetworkBridge(
  httpProxyPort: number,
  socksProxyPort: number,
): Promise<LinuxNetworkBridgeContext> {
  const socketId = randomBytes(8).toString('hex')
  const httpSocketPath = join(tmpdir(), `claude-http-${socketId}.sock`)
  const socksSocketPath = join(tmpdir(), `claude-socks-${socketId}.sock`)

  // Start HTTP bridge
  const httpSocatArgs = [
    `UNIX-LISTEN:${httpSocketPath},fork,reuseaddr`,
    `TCP:localhost:${httpProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting HTTP bridge: socat ${httpSocatArgs.join(' ')}`)

  const httpBridgeProcess = spawn('socat', httpSocatArgs, {
    stdio: 'ignore',
  })

  if (!httpBridgeProcess.pid) {
    throw new Error('Failed to start HTTP bridge process')
  }

  // Add error and exit handlers to monitor bridge health
  httpBridgeProcess.on('error', err => {
    logForDebugging(`HTTP bridge process error: ${err}`, { level: 'error' })
  })
  httpBridgeProcess.on('exit', (code, signal) => {
    logForDebugging(
      `HTTP bridge process exited with code ${code}, signal ${signal}`,
      { level: code === 0 ? 'info' : 'error' },
    )
  })

  // Start SOCKS bridge
  const socksSocatArgs = [
    `UNIX-LISTEN:${socksSocketPath},fork,reuseaddr`,
    `TCP:localhost:${socksProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting SOCKS bridge: socat ${socksSocatArgs.join(' ')}`)

  const socksBridgeProcess = spawn('socat', socksSocatArgs, {
    stdio: 'ignore',
  })

  if (!socksBridgeProcess.pid) {
    // Clean up HTTP bridge
    if (httpBridgeProcess.pid) {
      try {
        process.kill(httpBridgeProcess.pid, 'SIGTERM')
      } catch {
        // Ignore errors
      }
    }
    throw new Error('Failed to start SOCKS bridge process')
  }

  // Add error and exit handlers to monitor bridge health
  socksBridgeProcess.on('error', err => {
    logForDebugging(`SOCKS bridge process error: ${err}`, { level: 'error' })
  })
  socksBridgeProcess.on('exit', (code, signal) => {
    logForDebugging(
      `SOCKS bridge process exited with code ${code}, signal ${signal}`,
      { level: code === 0 ? 'info' : 'error' },
    )
  })

  // Wait for both sockets to be ready
  const maxAttempts = 5
  for (let i = 0; i < maxAttempts; i++) {
    if (
      !httpBridgeProcess.pid ||
      httpBridgeProcess.killed ||
      !socksBridgeProcess.pid ||
      socksBridgeProcess.killed
    ) {
      throw new Error('Linux bridge process died unexpectedly')
    }

    try {
      // fs already imported
      if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSocketPath)) {
        logForDebugging(`Linux bridges ready after ${i + 1} attempts`)
        break
      }
    } catch (err) {
      logForDebugging(`Error checking sockets (attempt ${i + 1}): ${err}`, {
        level: 'error',
      })
    }

    if (i === maxAttempts - 1) {
      // Clean up both processes
      if (httpBridgeProcess.pid) {
        try {
          process.kill(httpBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      if (socksBridgeProcess.pid) {
        try {
          process.kill(socksBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      throw new Error(
        `Failed to create bridge sockets after ${maxAttempts} attempts`,
      )
    }

    await new Promise(resolve => setTimeout(resolve, i * 100))
  }

  return {
    httpSocketPath,
    socksSocketPath,
    httpBridgeProcess,
    socksBridgeProcess,
    httpProxyPort,
    socksProxyPort,
  }
}

/**
 * Build the command that runs inside the sandbox.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 */
function buildSandboxCommand(
  httpSocketPath: string,
  socksSocketPath: string,
  userCommand: string,
  seccompFilterPath: string | undefined,
  shell?: string,
): string {
  // Default to bash for backward compatibility
  const shellPath = shell || 'bash'
  const socatCommands = [
    `socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:${httpSocketPath} >/dev/null 2>&1 &`,
    `socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:${socksSocketPath} >/dev/null 2>&1 &`,
    'trap "kill %1 %2 2>/dev/null; exit" EXIT',
  ]

  // If seccomp filter is provided, use apply-seccomp to apply it
  if (seccompFilterPath) {
    // apply-seccomp approach:
    // 1. Outer bwrap/bash: starts socat processes (can use Unix sockets)
    // 2. apply-seccomp: applies seccomp filter and execs user command
    // 3. User command runs with seccomp active (Unix sockets blocked)
    //
    // apply-seccomp is a simple C program that:
    // - Sets PR_SET_NO_NEW_PRIVS
    // - Applies the seccomp BPF filter via prctl(PR_SET_SECCOMP)
    // - Execs the user command
    //
    // This is simpler and more portable than nested bwrap, with no FD redirects needed.
    const applySeccompBinary = getApplySeccompBinaryPath()
    if (!applySeccompBinary) {
      throw new Error(
        'apply-seccomp binary not found. This should have been caught earlier. ' +
          'Ensure vendor/seccomp/{x64,arm64}/apply-seccomp binaries are included in the package.',
      )
    }

    const applySeccompCmd = shellquote.quote([
      applySeccompBinary,
      seccompFilterPath,
      shellPath,
      '-c',
      userCommand,
    ])

    const innerScript = [...socatCommands, applySeccompCmd].join('\n')
    return `${shellPath} -c ${shellquote.quote([innerScript])}`
  } else {
    // No seccomp filter - run user command directly
    const innerScript = [
      ...socatCommands,
      `eval ${shellquote.quote([userCommand])}`,
    ].join('\n')

    return `${shellPath} -c ${shellquote.quote([innerScript])}`
  }
}

/**
 * Generate filesystem bind mount arguments for bwrap
 */
async function generateFilesystemArgs(
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  mandatoryDenySearchDepth: number = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
  abortSignal?: AbortSignal,
): Promise<string[]> {
  const args: string[] = []
  // fs already imported

  // Determine initial root mount based on write restrictions
  if (writeConfig) {
    // Write restrictions: Start with read-only root, then allow writes to specific paths
    args.push('--ro-bind', '/', '/')

    // Collect normalized allowed write paths for later checking
    const allowedWritePaths: string[] = []

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

      args.push('--bind', normalizedPath, normalizedPath)
      allowedWritePaths.push(normalizedPath)
    }

    // Deny writes within allowed paths (user-specified + mandatory denies)
    const denyPaths = [
      ...(writeConfig.denyWithinAllow || []),
      ...(await linuxGetMandatoryDenyPaths(
        ripgrepConfig,
        mandatoryDenySearchDepth,
        abortSignal,
      )),
    ]

    for (const pathPattern of denyPaths) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      // Skip /dev/* paths since --dev /dev already handles them
      if (normalizedPath.startsWith('/dev/')) {
        continue
      }

      // Skip non-existent paths
      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox Linux] Skipping non-existent deny path: ${normalizedPath}`,
        )
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
        args.push('--ro-bind', normalizedPath, normalizedPath)
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

  // Handle read restrictions by mounting tmpfs over denied paths
  const readDenyPaths = [...(readConfig?.denyOnly || [])]

  // Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
  // SSH is very strict about config file permissions and ownership, and they can
  // appear wrong inside the sandbox causing "Bad owner or permissions" errors
  if (fs.existsSync('/etc/ssh/ssh_config.d')) {
    readDenyPaths.push('/etc/ssh/ssh_config.d')
  }

  for (const pathPattern of readDenyPaths) {
    const normalizedPath = normalizePathForSandbox(pathPattern)
    if (!fs.existsSync(normalizedPath)) {
      logForDebugging(
        `[Sandbox Linux] Skipping non-existent read deny path: ${normalizedPath}`,
      )
      continue
    }

    const readDenyStat = fs.statSync(normalizedPath)
    if (readDenyStat.isDirectory()) {
      args.push('--tmpfs', normalizedPath)
    } else {
      // For files, bind /dev/null instead of tmpfs
      args.push('--ro-bind', '/dev/null', normalizedPath)
    }
  }

  return args
}

/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * UNIX SOCKET BLOCKING (APPLY-SECCOMP):
 * This implementation uses a custom apply-seccomp binary to block Unix domain socket
 * creation for user commands while allowing network infrastructure:
 *
 * Stage 1: Outer bwrap - Network and filesystem isolation (NO seccomp)
 *   - Bubblewrap starts with isolated network namespace (--unshare-net)
 *   - Bubblewrap applies PID namespace isolation (--unshare-pid and --proc)
 *   - Filesystem restrictions are applied (read-only mounts, bind mounts, etc.)
 *   - Socat processes start and connect to Unix socket bridges (can use socket(AF_UNIX, ...))
 *
 * Stage 2: apply-seccomp - Seccomp filter application (ONLY seccomp)
 *   - apply-seccomp binary applies seccomp filter via prctl(PR_SET_SECCOMP)
 *   - Sets PR_SET_NO_NEW_PRIVS to allow seccomp without root
 *   - Execs user command with seccomp active (cannot create new Unix sockets)
 *
 * This solves the conflict between:
 * - Security: Blocking arbitrary Unix socket creation in user commands
 * - Functionality: Network sandboxing requires socat to call socket(AF_UNIX, ...) for bridge connections
 *
 * The seccomp-bpf filter blocks socket(AF_UNIX, ...) syscalls, preventing:
 * - Creating new Unix domain socket file descriptors
 *
 * Security limitations:
 * - Does NOT block operations (bind, connect, sendto, etc.) on inherited Unix socket FDs
 * - Does NOT prevent passing Unix socket FDs via SCM_RIGHTS
 * - For most sandboxing use cases, blocking socket creation is sufficient
 *
 * The filter allows:
 * - All TCP/UDP sockets (AF_INET, AF_INET6) for normal network operations
 * - All other syscalls
 *
 * PLATFORM NOTE:
 * The allowUnixSockets configuration is not path-based on Linux (unlike macOS)
 * because seccomp-bpf cannot inspect user-space memory to read socket paths.
 *
 * Requirements for seccomp filtering:
 * - Pre-built apply-seccomp binaries are included for x64 and ARM64
 * - Pre-generated BPF filters are included for x64 and ARM64
 * - Other architectures are not currently supported (no apply-seccomp binary available)
 * - To use sandboxing without Unix socket blocking on unsupported architectures,
 *   set allowAllUnixSockets: true in your configuration
 * Dependencies are checked by hasLinuxSandboxDependenciesSync() before enabling the sandbox.
 */
export async function wrapCommandWithSandboxLinux(
  params: LinuxSandboxParams,
): Promise<string> {
  const {
    command,
    needsNetworkRestriction,
    httpSocketPath,
    socksSocketPath,
    httpProxyPort,
    socksProxyPort,
    readConfig,
    writeConfig,
    enableWeakerNestedSandbox,
    allowAllUnixSockets,
    binShell,
    ripgrepConfig = { command: 'rg' },
    mandatoryDenySearchDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
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

  const bwrapArgs: string[] = []
  let seccompFilterPath: string | undefined = undefined

  try {
    // ========== SECCOMP FILTER (Unix Socket Blocking) ==========
    // Use bwrap's --seccomp flag to apply BPF filter that blocks Unix socket creation
    //
    // NOTE: Seccomp filtering is only enabled when allowAllUnixSockets is false
    // (when true, Unix sockets are allowed)
    if (!allowAllUnixSockets) {
      seccompFilterPath = generateSeccompFilter() ?? undefined
      if (!seccompFilterPath) {
        // Seccomp not available - log warning and continue without it
        // This provides graceful degradation on systems without seccomp binaries
        logForDebugging(
          '[Sandbox Linux] Seccomp filter not available (missing binaries). ' +
            'Continuing without Unix socket blocking - sandbox will still provide ' +
            'filesystem and network isolation but Unix sockets will be allowed.',
          { level: 'warn' },
        )
      } else {
        // Track filter for cleanup and register exit handler
        // Only track runtime-generated filters (not pre-generated ones from vendor/)
        if (!seccompFilterPath.includes('/vendor/seccomp/')) {
          generatedSeccompFilters.add(seccompFilterPath)
          registerSeccompCleanupHandler()
        }

        logForDebugging(
          '[Sandbox Linux] Generated seccomp BPF filter for Unix socket blocking',
        )
      }
    } else if (allowAllUnixSockets) {
      logForDebugging(
        '[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled',
      )
    }

    // ========== NETWORK RESTRICTIONS ==========
    if (needsNetworkRestriction) {
      // Always unshare network namespace to isolate network access
      // This removes all network interfaces, effectively blocking all network
      bwrapArgs.push('--unshare-net')

      // If proxy sockets are provided, bind them into the sandbox to allow
      // filtered network access through the proxy. If not provided, network
      // is completely blocked (empty allowedDomains = block all)
      if (httpSocketPath && socksSocketPath) {
        // Verify socket files still exist before trying to bind them
        if (!fs.existsSync(httpSocketPath)) {
          throw new Error(
            `Linux HTTP bridge socket does not exist: ${httpSocketPath}. ` +
              'The bridge process may have died. Try reinitializing the sandbox.',
          )
        }
        if (!fs.existsSync(socksSocketPath)) {
          throw new Error(
            `Linux SOCKS bridge socket does not exist: ${socksSocketPath}. ` +
              'The bridge process may have died. Try reinitializing the sandbox.',
          )
        }

        // Bind both sockets into the sandbox
        bwrapArgs.push('--bind', httpSocketPath, httpSocketPath)
        bwrapArgs.push('--bind', socksSocketPath, socksSocketPath)

        // Add proxy environment variables
        // HTTP_PROXY points to the socat listener inside the sandbox (port 3128)
        // which forwards to the Unix socket that bridges to the host's proxy server
        const proxyEnv = generateProxyEnvVars(
          3128, // Internal HTTP listener port
          1080, // Internal SOCKS listener port
        )
        bwrapArgs.push(
          ...proxyEnv.flatMap((env: string) => {
            const firstEq = env.indexOf('=')
            const key = env.slice(0, firstEq)
            const value = env.slice(firstEq + 1)
            return ['--setenv', key, value]
          }),
        )

        // Add host proxy port environment variables for debugging/transparency
        // These show which host ports the Unix socket bridges connect to
        if (httpProxyPort !== undefined) {
          bwrapArgs.push(
            '--setenv',
            'CLAUDE_CODE_HOST_HTTP_PROXY_PORT',
            String(httpProxyPort),
          )
        }
        if (socksProxyPort !== undefined) {
          bwrapArgs.push(
            '--setenv',
            'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT',
            String(socksProxyPort),
          )
        }
      }
      // If no sockets provided, network is completely blocked (--unshare-net without proxy)
    }

    // ========== FILESYSTEM RESTRICTIONS ==========
    const fsArgs = await generateFilesystemArgs(
      readConfig,
      writeConfig,
      ripgrepConfig,
      mandatoryDenySearchDepth,
      abortSignal,
    )
    bwrapArgs.push(...fsArgs)

    // Always bind /dev
    bwrapArgs.push('--dev', '/dev')

    // ========== PID NAMESPACE ISOLATION ==========
    // IMPORTANT: These must come AFTER filesystem binds for nested bwrap to work
    // By default, always unshare PID namespace and mount fresh /proc.
    // If we don't have --unshare-pid, it is possible to escape the sandbox.
    // If we don't have --proc, it is possible to read host /proc and leak information about code running
    // outside the sandbox. But, --proc is not available when running in unprivileged docker containers
    // so we support running without it if explicitly requested.
    bwrapArgs.push('--unshare-pid')
    if (!enableWeakerNestedSandbox) {
      // Mount fresh /proc if PID namespace is isolated (secure mode)
      bwrapArgs.push('--proc', '/proc')
    }

    // ========== COMMAND ==========
    // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
    // Resolve the full path to the shell binary since bwrap doesn't use $PATH
    const shellName = binShell || 'bash'
    const shellPathResult = spawnSync('which', [shellName], {
      encoding: 'utf8',
    })
    if (shellPathResult.status !== 0) {
      throw new Error(`Shell '${shellName}' not found in PATH`)
    }
    const shell = shellPathResult.stdout.trim()
    bwrapArgs.push('--', shell, '-c')

    // If we have network restrictions, use the network bridge setup with apply-seccomp for seccomp
    // Otherwise, just run the command directly with apply-seccomp if needed
    if (needsNetworkRestriction && httpSocketPath && socksSocketPath) {
      // Pass seccomp filter to buildSandboxCommand for apply-seccomp application
      // This allows socat to start before seccomp is applied
      const sandboxCommand = buildSandboxCommand(
        httpSocketPath,
        socksSocketPath,
        command,
        seccompFilterPath,
        shell,
      )
      bwrapArgs.push(sandboxCommand)
    } else if (seccompFilterPath) {
      // No network restrictions but we have seccomp - use apply-seccomp directly
      // apply-seccomp is a simple C program that applies the seccomp filter and execs the command
      const applySeccompBinary = getApplySeccompBinaryPath()
      if (!applySeccompBinary) {
        throw new Error(
          'apply-seccomp binary not found. This should have been caught earlier. ' +
            'Ensure vendor/seccomp/{x64,arm64}/apply-seccomp binaries are included in the package.',
        )
      }

      const applySeccompCmd = shellquote.quote([
        applySeccompBinary,
        seccompFilterPath,
        shell,
        '-c',
        command,
      ])
      bwrapArgs.push(applySeccompCmd)
    } else {
      bwrapArgs.push(command)
    }

    // Build the outer bwrap command
    const wrappedCommand = shellquote.quote(['bwrap', ...bwrapArgs])

    const restrictions = []
    if (needsNetworkRestriction) restrictions.push('network')
    if (hasReadRestrictions || hasWriteRestrictions)
      restrictions.push('filesystem')
    if (seccompFilterPath) restrictions.push('seccomp(unix-block)')

    logForDebugging(
      `[Sandbox Linux] Wrapped command with bwrap (${restrictions.join(', ')} restrictions)`,
    )

    return wrappedCommand
  } catch (error) {
    // Clean up seccomp filter on error
    if (seccompFilterPath && !seccompFilterPath.includes('/vendor/seccomp/')) {
      generatedSeccompFilters.delete(seccompFilterPath)
      try {
        cleanupSeccompFilter(seccompFilterPath)
      } catch (cleanupError) {
        logForDebugging(
          `[Sandbox Linux] Failed to clean up seccomp filter on error: ${cleanupError}`,
          { level: 'error' },
        )
      }
    }
    // Re-throw the original error
    throw error
  }
}
