import { createHttpProxyServer } from './http-proxy.js'
import { createSocksProxyServer } from './socks-proxy.js'
import type { SocksProxyWrapper } from './socks-proxy.js'
import { createMitmCA, disposeMitmCA, type MitmCA } from './mitm-ca.js'
import { logForDebugging } from '../utils/debug.js'
import { whichSync } from '../utils/which.js'
import { getPlatform, getWslVersion } from '../utils/platform.js'
import * as fs from 'fs'
import type { SandboxRuntimeConfig, SeccompConfig } from './sandbox-config.js'
import type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from './sandbox-schemas.js'
import {
  wrapCommandWithSandboxLinux,
  initializeLinuxNetworkBridge,
  type LinuxNetworkBridgeContext,
  checkLinuxDependencies,
  type SandboxDependencyCheck,
  cleanupBwrapMountPoints,
} from './linux-sandbox-utils.js'
import {
  wrapCommandWithSandboxMacOS,
  startMacOSSandboxLogMonitor,
} from './macos-sandbox-utils.js'
import {
  checkWindowsDependencies,
  wrapCommandWithSandboxWindows,
  DEFAULT_WINDOWS_GROUP_NAME,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
  type WindowsGroupRef,
} from './windows-sandbox-utils.js'
import {
  getDefaultWritePaths,
  containsGlobChars,
  removeTrailingGlobSuffix,
  expandGlobPattern,
} from './sandbox-utils.js'
import { SandboxViolationStore } from './sandbox-violation-store.js'
import {
  canonicalizeHost,
  isValidHost,
  redactUrl,
  resolveParentProxy,
  stripBrackets,
} from './parent-proxy.js'
import { isIP } from 'node:net'
import type { ChildProcess } from 'node:child_process'
import type { ResolvedParentProxy } from './parent-proxy.js'
import { EOL } from 'node:os'

interface HostNetworkManagerContext {
  httpProxyPort: number
  socksProxyPort: number
  linuxBridge: LinuxNetworkBridgeContext | undefined
}

// ============================================================================
// Private Module State
// ============================================================================

let config: SandboxRuntimeConfig | undefined
let httpProxyServer: ReturnType<typeof createHttpProxyServer> | undefined
let socksProxyServer: SocksProxyWrapper | undefined
let managerContext: HostNetworkManagerContext | undefined
let initializationPromise: Promise<HostNetworkManagerContext> | undefined
let cleanupRegistered = false
let logMonitorShutdown: (() => void) | undefined
let parentProxy: ResolvedParentProxy | undefined
let mitmCA: MitmCA | undefined
const sandboxViolationStore = new SandboxViolationStore()

// ============================================================================
// Private Helper Functions (not exported)
// ============================================================================

function registerCleanup(): void {
  if (cleanupRegistered) {
    return
  }
  const cleanupHandler = () =>
    reset().catch(e => {
      logForDebugging(`Cleanup failed in registerCleanup ${e}`, {
        level: 'error',
      })
    })
  process.once('exit', cleanupHandler)
  process.once('SIGINT', cleanupHandler)
  process.once('SIGTERM', cleanupHandler)
  cleanupRegistered = true
}

function matchesDomainPattern(hostname: string, pattern: string): boolean {
  const h = hostname.toLowerCase()
  // Support wildcard patterns like *.example.com. Never apply wildcard
  // suffix matching to IP literals — an IPv6 zone-ID payload like
  // `::ffff:1.2.3.4%x.allowed.com` would otherwise pass .endsWith() while
  // the OS connects to the bare IP. isValidHost already rejects `%`, but
  // we refuse here too for defence in depth.
  if (pattern.startsWith('*.')) {
    if (isIP(stripBrackets(h))) return false
    const baseDomain = pattern.substring(2).toLowerCase()
    return h.endsWith('.' + baseDomain)
  }

  // Exact match for non-wildcard patterns
  return h === pattern.toLowerCase()
}

async function filterNetworkRequest(
  port: number,
  host: string,
  sandboxAskCallback?: SandboxAskCallback,
): Promise<boolean> {
  if (!config) {
    logForDebugging('No config available, denying network request')
    return false
  }

  // Reject hosts containing control characters before pattern matching.
  // `matchesDomainPattern` uses string suffix matching which is trivially
  // fooled by e.g. `evil.com\x00.allowed.com` — the null byte passes
  // `.endsWith()` but truncates at the libc DNS layer. The SOCKS path is the
  // main exposure (DOMAINNAME is unvalidated bytes); HTTP is protected by
  // llhttp/URL parsing, but we check here for defence in depth.
  if (!isValidHost(host)) {
    logForDebugging(`Denying malformed host: ${JSON.stringify(host)}:${port}`, {
      level: 'error',
    })
    return false
  }

  // Canonicalize so string comparisons match what getaddrinfo() will dial.
  // Without this, inet_aton shorthand like `2852039166` (= 169.254.169.254)
  // or `127.1` slips past a denylist entry for the dotted-decimal form.
  const canonicalHost = canonicalizeHost(host) ?? host

  // Check denied domains first
  for (const deniedDomain of config.network.deniedDomains) {
    if (matchesDomainPattern(canonicalHost, deniedDomain)) {
      logForDebugging(`Denied by config rule: ${host}:${port}`)
      return false
    }
  }

  // Check allowed domains
  for (const allowedDomain of config.network.allowedDomains) {
    if (matchesDomainPattern(canonicalHost, allowedDomain)) {
      logForDebugging(`Allowed by config rule: ${host}:${port}`)
      return true
    }
  }

  // No matching rules - ask user or deny
  if (!sandboxAskCallback) {
    logForDebugging(`No matching config rule, denying: ${host}:${port}`)
    return false
  }

  logForDebugging(`No matching config rule, asking user: ${host}:${port}`)
  try {
    const userAllowed = await sandboxAskCallback({ host, port })
    if (userAllowed) {
      logForDebugging(`User allowed: ${host}:${port}`)
      return true
    } else {
      logForDebugging(`User denied: ${host}:${port}`)
      return false
    }
  } catch (error) {
    logForDebugging(`Error in permission callback: ${error}`, {
      level: 'error',
    })
    return false
  }
}

/**
 * Get the MITM proxy socket path for a given host, if configured.
 * Returns the socket path if the host matches any MITM domain pattern,
 * otherwise returns undefined.
 */
function getMitmSocketPath(host: string): string | undefined {
  if (!config?.network.mitmProxy) {
    return undefined
  }

  const { socketPath, domains } = config.network.mitmProxy

  for (const pattern of domains) {
    if (matchesDomainPattern(host, pattern)) {
      logForDebugging(`Host ${host} matches MITM pattern ${pattern}`)
      return socketPath
    }
  }

  return undefined
}

/**
 * Bind `server.listen()` to the first free port in `[lo, hi]`,
 * skipping `EADDRINUSE`. With `range` undefined, binds to ephemeral
 * port 0 (the previous behaviour).
 *
 * Used on Windows: the WFP loopback permit only covers a fixed port
 * range (default 60080–60089), so the JS proxies must bind inside it
 * for the sandboxed child to reach them. On other platforms the
 * sandbox layer (seatbelt rule, namespace+socat) targets whatever
 * port we landed on, so ephemeral is fine.
 */
function listenInRange(
  server: {
    once(ev: 'error' | 'listening', cb: (e?: Error) => void): unknown
    removeListener(ev: 'error' | 'listening', cb: (e?: Error) => void): unknown
  },
  doListen: (port: number) => void,
  range: readonly [number, number] | undefined,
  exclude: ReadonlySet<number>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const [lo, hi] = range ?? [0, 0]
    let port = lo
    const tryNext = (): void => {
      while (exclude.has(port) && port <= hi) port++
      if (port > hi) {
        reject(
          new Error(
            `No free port in range ${lo}-${hi} (excluding ${[...exclude].join(',')})`,
          ),
        )
        return
      }
      const onListening = (): void => {
        server.removeListener('error', onError)
        resolve()
      }
      const onError = (err?: Error): void => {
        // The paired 'listening' once-listener never fired; drop it
        // so retries don't accumulate stale listeners.
        server.removeListener('listening', onListening)
        if (
          range &&
          (err as NodeJS.ErrnoException)?.code === 'EADDRINUSE' &&
          port < hi
        ) {
          port++
          tryNext()
          return
        }
        reject(err ?? new Error('listen error'))
      }
      server.once('error', onError)
      server.once('listening', onListening)
      doListen(range ? port : 0)
    }
    tryNext()
  })
}

async function startHttpProxyServer(
  sandboxAskCallback: SandboxAskCallback | undefined,
  portRange: readonly [number, number] | undefined,
  excludePorts: ReadonlySet<number>,
): Promise<number> {
  httpProxyServer = createHttpProxyServer({
    filter: (port: number, host: string) =>
      filterNetworkRequest(port, host, sandboxAskCallback),
    getMitmSocketPath,
    mitmCA,
    filterRequest: config?.network.filterRequest,
    parentProxy,
  })

  const server = httpProxyServer
  await listenInRange(
    server,
    p => server.listen(p, '127.0.0.1'),
    portRange,
    excludePorts,
  )
  const address = server.address()
  if (!address || typeof address !== 'object') {
    throw new Error('Failed to get HTTP proxy server address')
  }
  server.unref()
  logForDebugging(`HTTP proxy listening on localhost:${address.port}`)
  return address.port
}

async function startSocksProxyServer(
  sandboxAskCallback: SandboxAskCallback | undefined,
  portRange: readonly [number, number] | undefined,
  excludePorts: ReadonlySet<number>,
): Promise<number> {
  socksProxyServer = createSocksProxyServer({
    filter: (port: number, host: string) =>
      filterNetworkRequest(port, host, sandboxAskCallback),
    parentProxy,
  })

  const wrapper = socksProxyServer
  // SocksProxyWrapper.listen() resolves with the bound port; we
  // adapt it to the listenInRange shape by retrying on EADDRINUSE
  // here directly rather than via the once('error') path.
  if (!portRange) {
    const port = await wrapper.listen(0, '127.0.0.1')
    wrapper.unref()
    return port
  }
  let lastErr: unknown
  for (let p = portRange[0]; p <= portRange[1]; p++) {
    if (excludePorts.has(p)) continue
    try {
      const port = await wrapper.listen(p, '127.0.0.1')
      wrapper.unref()
      return port
    } catch (err) {
      lastErr = err
      if ((err as NodeJS.ErrnoException)?.code !== 'EADDRINUSE') throw err
    }
  }
  throw new Error(
    `No free SOCKS port in range ${portRange[0]}-${portRange[1]}: ${
      (lastErr as Error)?.message ?? 'all in use'
    }`,
  )
}

// ============================================================================
// Public Module Functions (will be exported via namespace)
// ============================================================================

async function initialize(
  runtimeConfig: SandboxRuntimeConfig,
  sandboxAskCallback?: SandboxAskCallback,
  enableLogMonitor = false,
): Promise<void> {
  // Return if already initializing
  if (initializationPromise) {
    await initializationPromise
    return
  }

  // Store config for use by other functions
  config = runtimeConfig

  // Resolve parent/upstream proxy from config or HTTP_PROXY env before we
  // start our own listeners (which will later shadow those vars in the child).
  parentProxy = resolveParentProxy(runtimeConfig.network.parentProxy)
  if (parentProxy) {
    logForDebugging(
      `Parent proxy configured: http=${redactUrl(parentProxy.httpUrl)} ` +
        `https=${redactUrl(parentProxy.httpsUrl)}`,
    )
  }

  // Load TLS-termination CA if configured. Throws on unreadable/non-PEM —
  // tlsTerminate is explicit opt-in, so a bad config is a hard error.
  if (runtimeConfig.network.tlsTerminate && runtimeConfig.network.mitmProxy) {
    throw new Error(
      'network.tlsTerminate and network.mitmProxy are mutually exclusive',
    )
  }
  mitmCA = runtimeConfig.network.tlsTerminate
    ? createMitmCA(runtimeConfig.network.tlsTerminate)
    : undefined

  // Check dependencies
  const deps = checkDependencies()
  if (deps.errors.length > 0) {
    throw new Error(
      `Sandbox dependencies not available: ${deps.errors.join(', ')}`,
    )
  }

  // Start log monitor for macOS if enabled
  if (enableLogMonitor && getPlatform() === 'macos') {
    logMonitorShutdown = startMacOSSandboxLogMonitor(
      sandboxViolationStore.addViolation.bind(sandboxViolationStore),
      config.ignoreViolations,
    )
    logForDebugging('Started macOS sandbox log monitor')
  }

  // Register cleanup handlers first time
  registerCleanup()

  // Initialize network infrastructure
  initializationPromise = (async () => {
    try {
      // On Windows the WFP loopback permit covers a fixed port
      // range, so the proxies must bind inside it. Other platforms
      // bake the actual ephemeral port into the sandbox profile, so
      // they keep using port 0.
      const portRange: readonly [number, number] | undefined =
        getPlatform() === 'windows'
          ? (config.windows?.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE)
          : undefined

      // Conditionally start proxy servers based on config
      let httpProxyPort: number
      if (config.network.httpProxyPort !== undefined) {
        // Use external HTTP proxy (don't start a server)
        httpProxyPort = config.network.httpProxyPort
        logForDebugging(`Using external HTTP proxy on port ${httpProxyPort}`)
      } else {
        // Start local HTTP proxy
        httpProxyPort = await startHttpProxyServer(
          sandboxAskCallback,
          portRange,
          new Set(),
        )
      }

      let socksProxyPort: number
      if (config.network.socksProxyPort !== undefined) {
        // Use external SOCKS proxy (don't start a server)
        socksProxyPort = config.network.socksProxyPort
        logForDebugging(`Using external SOCKS proxy on port ${socksProxyPort}`)
      } else {
        // Start local SOCKS proxy. Skip the port the HTTP proxy
        // already took.
        socksProxyPort = await startSocksProxyServer(
          sandboxAskCallback,
          portRange,
          new Set([httpProxyPort]),
        )
      }

      // Initialize platform-specific infrastructure
      let linuxBridge: LinuxNetworkBridgeContext | undefined
      if (getPlatform() === 'linux') {
        linuxBridge = await initializeLinuxNetworkBridge(
          httpProxyPort,
          socksProxyPort,
          config.socatPath,
        )
      }

      const context: HostNetworkManagerContext = {
        httpProxyPort,
        socksProxyPort,
        linuxBridge,
      }
      managerContext = context
      logForDebugging('Network infrastructure initialized')
      return context
    } catch (error) {
      // Clear state on error so initialization can be retried
      initializationPromise = undefined
      managerContext = undefined
      reset().catch(e => {
        logForDebugging(`Cleanup failed in initializationPromise ${e}`, {
          level: 'error',
        })
      })
      throw error
    }
  })()

  await initializationPromise
}

function isSupportedPlatform(): boolean {
  const platform = getPlatform()
  if (platform === 'linux') {
    // WSL1 doesn't support bubblewrap
    return getWslVersion() !== '1'
  }
  return platform === 'macos' || platform === 'windows'
}

/**
 * Resolve the Windows group reference from config. Used by both the
 * dependency check and `wrapWithSandbox` so they agree.
 */
function getWindowsGroupRef(): WindowsGroupRef {
  return {
    groupName: config?.windows?.groupName ?? DEFAULT_WINDOWS_GROUP_NAME,
    groupSid: config?.windows?.groupSid,
  }
}

function isSandboxingEnabled(): boolean {
  // Sandboxing is enabled if config has been set (via initialize())
  return config !== undefined
}

/**
 * Check sandbox dependencies for the current platform
 * @param ripgrepConfig - Ripgrep command to check. If not provided, uses config from initialization or defaults to 'rg'
 * @returns { warnings, errors } - errors mean sandbox cannot run, warnings mean degraded functionality
 */
function checkDependencies(ripgrepConfig?: {
  command: string
  args?: string[]
}): SandboxDependencyCheck {
  if (!isSupportedPlatform()) {
    return { errors: ['Unsupported platform'], warnings: [] }
  }

  const errors: string[] = []
  const warnings: string[] = []

  const platform = getPlatform()
  if (platform === 'linux') {
    // ripgrep is Linux-only: it's used by linuxGetMandatoryDenyPaths() to
    // expand glob deny-patterns to concrete paths for bwrap. macOS seatbelt
    // profiles take regex patterns directly, so rg is never invoked there.
    const rgToCheck = ripgrepConfig ?? config?.ripgrep ?? { command: 'rg' }
    if (whichSync(rgToCheck.command) === null) {
      errors.push(`ripgrep (${rgToCheck.command}) not found`)
    }

    const linuxDeps = checkLinuxDependencies({
      seccompConfig: config?.seccomp,
      bwrapPath: config?.bwrapPath,
      socatPath: config?.socatPath,
    })
    errors.push(...linuxDeps.errors)
    warnings.push(...linuxDeps.warnings)
  } else if (platform === 'windows') {
    const winDeps = checkWindowsDependencies(
      getWindowsGroupRef(),
      config?.windows?.wfpSublayerGuid,
    )
    errors.push(...winDeps.errors)
    warnings.push(...winDeps.warnings)
  }

  return { errors, warnings }
}

function getFsReadConfig(): FsReadRestrictionConfig {
  if (!config) {
    return { denyOnly: [], allowWithinDeny: [] }
  }

  const denyPaths: string[] = []
  for (const p of config.filesystem.denyRead) {
    const stripped = removeTrailingGlobSuffix(p)
    if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
      // Expand glob to concrete paths on Linux (bubblewrap doesn't support globs)
      const expanded = expandGlobPattern(p)
      logForDebugging(
        `[Sandbox] Expanded glob pattern "${p}" to ${expanded.length} paths on Linux`,
      )
      denyPaths.push(...expanded)
    } else {
      denyPaths.push(stripped)
    }
  }

  // Process allowRead paths (re-allow within denied regions)
  const allowPaths: string[] = []
  for (const p of config.filesystem.allowRead ?? []) {
    const stripped = removeTrailingGlobSuffix(p)
    if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
      const expanded = expandGlobPattern(p)
      logForDebugging(
        `[Sandbox] Expanded allowRead glob pattern "${p}" to ${expanded.length} paths on Linux`,
      )
      allowPaths.push(...expanded)
    } else {
      allowPaths.push(stripped)
    }
  }

  return {
    denyOnly: denyPaths,
    allowWithinDeny: allowPaths,
  }
}

function getFsWriteConfig(): FsWriteRestrictionConfig {
  if (!config) {
    return { allowOnly: getDefaultWritePaths(), denyWithinAllow: [] }
  }

  // Filter out glob patterns on Linux/WSL for allowWrite (bubblewrap doesn't support globs)
  const allowPaths = config.filesystem.allowWrite
    .map(path => removeTrailingGlobSuffix(path))
    .filter(path => {
      if (getPlatform() === 'linux' && containsGlobChars(path)) {
        logForDebugging(`Skipping glob pattern on Linux/WSL: ${path}`)
        return false
      }
      return true
    })

  // Filter out glob patterns on Linux/WSL for denyWrite (bubblewrap doesn't support globs)
  const denyPaths = config.filesystem.denyWrite
    .map(path => removeTrailingGlobSuffix(path))
    .filter(path => {
      if (getPlatform() === 'linux' && containsGlobChars(path)) {
        logForDebugging(`Skipping glob pattern on Linux/WSL: ${path}`)
        return false
      }
      return true
    })

  // Build allowOnly list: default paths + configured allow paths
  const allowOnly = [...getDefaultWritePaths(), ...allowPaths]

  return {
    allowOnly,
    denyWithinAllow: denyPaths,
  }
}

function getNetworkRestrictionConfig(): NetworkRestrictionConfig {
  if (!config) {
    return {}
  }

  const allowedHosts = config.network.allowedDomains
  const deniedHosts = config.network.deniedDomains

  return {
    ...(allowedHosts.length > 0 && { allowedHosts }),
    ...(deniedHosts.length > 0 && { deniedHosts }),
  }
}

function getAllowUnixSockets(): string[] | undefined {
  return config?.network?.allowUnixSockets
}

function getAllowAllUnixSockets(): boolean | undefined {
  return config?.network?.allowAllUnixSockets
}

function getAllowLocalBinding(): boolean | undefined {
  return config?.network?.allowLocalBinding
}

function getAllowMachLookup(): string[] | undefined {
  return config?.network?.allowMachLookup
}

function getIgnoreViolations(): Record<string, string[]> | undefined {
  return config?.ignoreViolations
}

function getEnableWeakerNestedSandbox(): boolean | undefined {
  return config?.enableWeakerNestedSandbox
}

function getEnableWeakerNetworkIsolation(): boolean | undefined {
  return config?.enableWeakerNetworkIsolation
}

function getAllowAppleEvents(): boolean | undefined {
  return config?.allowAppleEvents
}

function getRipgrepConfig(): { command: string; args?: string[] } {
  return config?.ripgrep ?? { command: 'rg' }
}

function getMandatoryDenySearchDepth(): number {
  return config?.mandatoryDenySearchDepth ?? 3
}

function getAllowGitConfig(): boolean {
  return config?.filesystem?.allowGitConfig ?? false
}

function getSeccompConfig(): SeccompConfig | undefined {
  return config?.seccomp
}

function getProxyPort(): number | undefined {
  return managerContext?.httpProxyPort
}

function getSocksProxyPort(): number | undefined {
  return managerContext?.socksProxyPort
}

function getLinuxHttpSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.httpSocketPath
}

function getLinuxSocksSocketPath(): string | undefined {
  return managerContext?.linuxBridge?.socksSocketPath
}

/**
 * Wait for network initialization to complete if already in progress
 * Returns true if initialized successfully, false otherwise
 */
async function waitForNetworkInitialization(): Promise<boolean> {
  if (!config) {
    return false
  }
  if (initializationPromise) {
    try {
      await initializationPromise
      return true
    } catch {
      return false
    }
  }
  return managerContext !== undefined
}

async function wrapWithSandbox(
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
): Promise<string> {
  const platform = getPlatform()

  // Get configs - use custom if provided, otherwise fall back to main config
  // If neither exists, defaults to empty arrays (most restrictive)
  // Always include default system write paths (like /dev/null, /tmp/claude)
  //
  // Strip trailing /** and filter remaining globs on Linux (bwrap needs
  // real paths, not globs; macOS subpath matching is also recursive so
  // stripping is harmless there).
  const stripWriteGlobs = (paths: string[]): string[] =>
    paths
      .map(p => removeTrailingGlobSuffix(p))
      .filter(p => {
        if (getPlatform() === 'linux' && containsGlobChars(p)) {
          logForDebugging(
            `[Sandbox] Skipping glob write pattern on Linux: ${p}`,
          )
          return false
        }
        return true
      })
  const userAllowWrite = stripWriteGlobs(
    customConfig?.filesystem?.allowWrite ?? config?.filesystem.allowWrite ?? [],
  )
  const writeConfig = {
    allowOnly: [...getDefaultWritePaths(), ...userAllowWrite],
    denyWithinAllow: stripWriteGlobs(
      customConfig?.filesystem?.denyWrite ?? config?.filesystem.denyWrite ?? [],
    ),
  }
  const rawDenyRead =
    customConfig?.filesystem?.denyRead ?? config?.filesystem.denyRead ?? []
  const expandedDenyRead: string[] = []
  for (const p of rawDenyRead) {
    const stripped = removeTrailingGlobSuffix(p)
    if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
      expandedDenyRead.push(...expandGlobPattern(p))
    } else {
      expandedDenyRead.push(stripped)
    }
  }
  const rawAllowRead =
    customConfig?.filesystem?.allowRead ?? config?.filesystem.allowRead ?? []
  const expandedAllowRead: string[] = []
  for (const p of rawAllowRead) {
    const stripped = removeTrailingGlobSuffix(p)
    if (getPlatform() === 'linux' && containsGlobChars(stripped)) {
      expandedAllowRead.push(...expandGlobPattern(p))
    } else {
      expandedAllowRead.push(stripped)
    }
  }
  // The TLS-termination CA cert must be readable by the child so the trust
  // env vars (NODE_EXTRA_CA_CERTS etc.) resolve, even if its path falls
  // under a user-configured denyRead.
  if (mitmCA) {
    expandedAllowRead.push(mitmCA.certPath)
  }
  const readConfig = {
    denyOnly: expandedDenyRead,
    allowWithinDeny: expandedAllowRead,
  }

  // Check if network config is specified - this determines if we need network restrictions
  // Network restriction is needed when:
  // 1. customConfig has network.allowedDomains defined (even if empty array = block all)
  // 2. OR config has network.allowedDomains defined (even if empty array = block all)
  // An empty allowedDomains array means "no domains allowed" = block all network access
  const hasNetworkConfig =
    customConfig?.network?.allowedDomains !== undefined ||
    config?.network?.allowedDomains !== undefined

  // Network RESTRICTION is needed whenever network config is specified
  // This includes empty allowedDomains which means "block all network"
  const needsNetworkRestriction = hasNetworkConfig

  // Network PROXY is needed whenever network config is specified
  // Even with empty allowedDomains, we route through proxy so that:
  // 1. updateConfig() can enable network access for already-running processes
  // 2. The proxy blocks all requests when allowlist is empty
  const needsNetworkProxy = hasNetworkConfig

  // Wait for network initialization only if proxy is actually needed
  if (needsNetworkProxy) {
    await waitForNetworkInitialization()
  }

  // Check custom config to allow pseudo-terminal (can be applied dynamically)
  const allowPty = customConfig?.allowPty ?? config?.allowPty

  switch (platform) {
    case 'macos':
      // macOS sandbox profile supports glob patterns directly, no ripgrep needed
      return wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction,
        // Only pass proxy ports if proxy is running (when there are domains to filter)
        httpProxyPort: needsNetworkProxy ? getProxyPort() : undefined,
        socksProxyPort: needsNetworkProxy ? getSocksProxyPort() : undefined,
        caCertPath: mitmCA?.certPath,
        readConfig,
        writeConfig,
        allowUnixSockets: getAllowUnixSockets(),
        allowAllUnixSockets: getAllowAllUnixSockets(),
        allowLocalBinding: getAllowLocalBinding(),
        allowMachLookup: getAllowMachLookup(),
        ignoreViolations: getIgnoreViolations(),
        allowPty,
        allowGitConfig: getAllowGitConfig(),
        enableWeakerNetworkIsolation: getEnableWeakerNetworkIsolation(),
        allowAppleEvents: getAllowAppleEvents(),
        binShell,
      })

    case 'linux':
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction,
        // Only pass socket paths if proxy is running (when there are domains to filter)
        httpSocketPath: needsNetworkProxy
          ? getLinuxHttpSocketPath()
          : undefined,
        socksSocketPath: needsNetworkProxy
          ? getLinuxSocksSocketPath()
          : undefined,
        httpProxyPort: needsNetworkProxy
          ? managerContext?.httpProxyPort
          : undefined,
        socksProxyPort: needsNetworkProxy
          ? managerContext?.socksProxyPort
          : undefined,
        caCertPath: mitmCA?.certPath,
        readConfig,
        writeConfig,
        enableWeakerNestedSandbox: getEnableWeakerNestedSandbox(),
        allowAllUnixSockets: getAllowAllUnixSockets(),
        binShell,
        ripgrepConfig: getRipgrepConfig(),
        mandatoryDenySearchDepth: getMandatoryDenySearchDepth(),
        allowGitConfig: getAllowGitConfig(),
        seccompConfig: getSeccompConfig(),
        bwrapPath: config?.bwrapPath,
        socatPath: config?.socatPath,
        abortSignal,
      })

    case 'windows':
      // Windows wraps to an argv array, not a shell string. Forcing
      // callers through wrapWithSandboxArgv() means they spawn with
      // {shell:false}, which is the security boundary that keeps the
      // user's command bytes off the HOST shell.
      throw new Error(
        'wrapWithSandbox() returns a shell string and is not supported ' +
          'on Windows. Use SandboxManager.wrapWithSandboxArgv() and ' +
          'spawn the result with {shell: false}.',
      )

    default:
      // Unsupported platform - this should not happen since isSandboxingEnabled() checks platform support
      throw new Error(
        `Sandbox configuration is not supported on platform: ${platform}`,
      )
  }
}

/**
 * Wrap `command` for the sandbox and return a spawn descriptor:
 * `{ argv, env }`, suitable for
 * `spawn(argv[0], argv.slice(1), {shell: false, env})`.
 *
 * On Windows this is the ONLY supported wrap method (see
 * {@link wrapWithSandbox}); `env` carries the full proxy set that the
 * sandboxed child inherits (`srt-win exec` forwards its environment
 * verbatim — see {@link wrapCommandWithSandboxWindows}). On
 * macOS/Linux `argv` is `[binShell, '-c', <wrapWithSandbox result>]`
 * (proxy env is baked into that command) and `env` is the unchanged
 * `process.env`, so callers can spawn uniformly across platforms.
 */
async function wrapWithSandboxArgv(
  command: string,
  binShell?: string,
  customConfig?: Partial<SandboxRuntimeConfig>,
  abortSignal?: AbortSignal,
): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }> {
  const platform = getPlatform()

  if (platform === 'windows') {
    const hasNetworkConfig =
      customConfig?.network?.allowedDomains !== undefined ||
      config?.network?.allowedDomains !== undefined
    if (hasNetworkConfig) {
      await waitForNetworkInitialization()
    }
    return wrapCommandWithSandboxWindows({
      command,
      group: getWindowsGroupRef(),
      httpProxyPort: hasNetworkConfig ? getProxyPort() : undefined,
      socksProxyPort: hasNetworkConfig ? getSocksProxyPort() : undefined,
      binShell,
    })
  }

  // macOS/Linux: delegate to the existing string wrapper, then put
  // the result behind `<shell> -c` so the caller's argv-spawn works.
  const wrapped = await wrapWithSandbox(
    command,
    binShell,
    customConfig,
    abortSignal,
  )
  const shell = binShell ?? '/bin/bash'
  return { argv: [shell, '-c', wrapped], env: process.env }
}

/**
 * Get the current sandbox configuration
 * @returns The current configuration, or undefined if not initialized
 */
function getConfig(): SandboxRuntimeConfig | undefined {
  return config
}

/**
 * Update the sandbox configuration in place.
 *
 * **Network/allowlist changes are a live swap**: the running
 * http/socks proxies read `config.network.allowedDomains` /
 * `deniedDomains` per-request (via `filterNetworkRequest`), so
 * reassigning `config` here takes effect on the next connection
 * with no proxy rebind and no port change — on every platform,
 * including Windows. This is what lets a host enable/deny domains
 * for already-running sandboxed children.
 *
 * Filesystem changes (denyRead/denyWrite) are NOT applied live:
 * macOS bakes them into the seatbelt profile at wrap time, and
 * Windows will need an explicit re-stamp. To change FS
 * restrictions, reset() then initialize() with the new config.
 *
 * @param newConfig - The new configuration to use
 */
function updateConfig(newConfig: SandboxRuntimeConfig): void {
  // Deep clone the config to avoid mutations. structuredClone cannot clone
  // functions, so pull filterRequest out, clone the rest, and put it back —
  // a function reference is immutable in the sense that matters here.
  const { filterRequest, ...rest } = newConfig.network
  config = structuredClone({ ...newConfig, network: rest })
  config.network.filterRequest = filterRequest
  // Re-resolve parent proxy so hot-reload picks up changes. Note: the proxy
  // servers capture `parentProxy` by value at creation, so changes here take
  // effect only on re-initialize. This keeps the state consistent for the
  // next initialize() call.
  parentProxy = resolveParentProxy(newConfig.network.parentProxy)
  logForDebugging('Sandbox configuration updated')
}

/**
 * Lightweight cleanup to call after each sandboxed command completes.
 *
 * On Linux, bwrap creates empty files on the host filesystem as mount points
 * when protecting non-existent deny paths (e.g. ~/.bashrc, ~/.gitconfig).
 * These persist after bwrap exits. This function removes them.
 *
 * Safe to call on any platform — it's a no-op on macOS.
 * Also called automatically by reset() and on process exit as safety nets.
 */
function cleanupAfterCommand(): void {
  cleanupBwrapMountPoints()
}

/**
 * How long to wait for a bridge process to exit after SIGTERM before
 * escalating to SIGKILL.
 *
 * socat exits within ~10ms of SIGTERM; this is purely a safety margin.
 * Keep it well below bun's default 5s test/hook timeout: when a bridge's
 * `'exit'` event is missed entirely (a Linux-only Bun pidfd notification
 * bug, oven-sh/bun#30301), this timer is the only thing that lets `reset()`
 * make progress, and a 5000ms value here loses the race against the hook
 * timer by a couple of milliseconds — that race was the dominant CI flake.
 */
const BRIDGE_EXIT_TIMEOUT_MS = 1500

/**
 * SIGTERM a bridge process and resolve once it has exited.
 *
 * Returns immediately if the process has already exited (`.exitCode` /
 * `.signalCode` set) — registering `.once('exit')` after the event has
 * already been emitted produces a listener that never fires.
 *
 * Falls back to SIGKILL after {@link BRIDGE_EXIT_TIMEOUT_MS}.
 */
function killBridgeProcess(proc: ChildProcess, label: string): Promise<void> {
  // Already exited → 'exit' already emitted → a fresh once('exit') would
  // never fire. Don't wait on it.
  if (!proc.pid || proc.exitCode !== null || proc.signalCode !== null) {
    return Promise.resolve()
  }

  try {
    process.kill(proc.pid, 'SIGTERM')
    logForDebugging(`Sent SIGTERM to ${label} bridge process`)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ESRCH') {
      logForDebugging(`Error killing ${label} bridge: ${err}`, {
        level: 'error',
      })
    }
    // ESRCH = process already gone; nothing to wait for either way.
    return Promise.resolve()
  }

  return new Promise<void>(resolve => {
    let settled = false
    const done = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve()
    }
    proc.once('exit', () => {
      logForDebugging(`${label} bridge process exited`)
      done()
    })
    const timer = setTimeout(() => {
      // Re-check liveness — the 'exit' may have raced us.
      if (proc.exitCode === null && proc.signalCode === null) {
        logForDebugging(`${label} bridge did not exit, forcing SIGKILL`, {
          level: 'warn',
        })
        try {
          if (proc.pid) process.kill(proc.pid, 'SIGKILL')
        } catch {
          // Process may have already exited
        }
      }
      done()
    }, BRIDGE_EXIT_TIMEOUT_MS)
    // The bridge process is being torn down; this timer must not be the
    // only thing keeping the event loop alive.
    timer.unref?.()
  })
}

/**
 * Forcibly close an http.Server, including any in-flight requests.
 *
 * Plain `server.close()` waits for every active request to finish.
 * The proxy may be mid-upstream-request when reset() runs (e.g. a test's
 * curl was killed by --max-time while the proxy was still dialing the
 * real example.com / api.github.com), and `dialDirect()` allows up to
 * 30s before giving up. Combined with a socat fork that hasn't yet seen
 * its unix-socket EOF, that leaves a fully-open inbound connection and
 * `server.close()` never calls back. `closeAllConnections()` (Node 18.2+,
 * also implemented in Bun) tears down those sockets so `close()` resolves
 * immediately.
 */
function forceCloseHttpServer(
  server: ReturnType<typeof createHttpProxyServer>,
): Promise<void> {
  return new Promise<void>(resolve => {
    // Must run *before* close(): in Bun, close() also detaches the
    // underlying handle, so a closeAllConnections() called afterwards
    // becomes a no-op and the close callback waits for the in-flight
    // request to drain — defeating the purpose. With closeAllConnections()
    // first, the connections are gone by the time close() runs and its
    // callback fires immediately (Bun reports "Server is not running.",
    // Node reports no error). Verified against both orderings.
    if (typeof server.closeAllConnections === 'function') {
      server.closeAllConnections()
    }
    server.close(error => {
      if (error && error.message !== 'Server is not running.') {
        logForDebugging(`Error closing HTTP proxy server: ${error.message}`, {
          level: 'error',
        })
      }
      resolve()
    })
  })
}

async function reset(): Promise<void> {
  // Clean up any leftover bwrap mount points. Force past the
  // active-sandbox counter — reset() means the session is over.
  cleanupBwrapMountPoints({ force: true })

  // Stop log monitor
  if (logMonitorShutdown) {
    logMonitorShutdown()
    logMonitorShutdown = undefined
  }

  if (managerContext?.linuxBridge) {
    const {
      httpSocketPath,
      socksSocketPath,
      httpBridgeProcess,
      socksBridgeProcess,
    } = managerContext.linuxBridge

    // Kill both bridges and wait for them to exit
    await Promise.all([
      killBridgeProcess(httpBridgeProcess, 'HTTP'),
      killBridgeProcess(socksBridgeProcess, 'SOCKS'),
    ])

    // Clean up sockets
    if (httpSocketPath) {
      try {
        fs.rmSync(httpSocketPath, { force: true })
        logForDebugging('Cleaned up HTTP socket')
      } catch (err) {
        logForDebugging(`HTTP socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }

    if (socksSocketPath) {
      try {
        fs.rmSync(socksSocketPath, { force: true })
        logForDebugging('Cleaned up SOCKS socket')
      } catch (err) {
        logForDebugging(`SOCKS socket cleanup error: ${err}`, {
          level: 'error',
        })
      }
    }
  }

  // Close servers in parallel (only if they exist, i.e., were started by us)
  const closePromises: Promise<void>[] = []

  if (mitmCA) {
    closePromises.push(disposeMitmCA(mitmCA))
  }

  if (httpProxyServer) {
    closePromises.push(forceCloseHttpServer(httpProxyServer))
  }

  if (socksProxyServer) {
    const socksClose = socksProxyServer.close().catch((error: Error) => {
      logForDebugging(`Error closing SOCKS proxy server: ${error.message}`, {
        level: 'error',
      })
    })
    closePromises.push(socksClose)
  }

  // Wait for all servers to close
  await Promise.all(closePromises)

  // Clear references
  httpProxyServer = undefined
  socksProxyServer = undefined
  managerContext = undefined
  initializationPromise = undefined
  parentProxy = undefined
  mitmCA = undefined
}

function getSandboxViolationStore() {
  return sandboxViolationStore
}

function annotateStderrWithSandboxFailures(
  command: string,
  stderr: string,
): string {
  if (!config) {
    return stderr
  }

  const violations = sandboxViolationStore.getViolationsForCommand(command)
  if (violations.length === 0) {
    return stderr
  }

  let annotated = stderr
  annotated += EOL + '<sandbox_violations>' + EOL
  for (const violation of violations) {
    annotated += violation.line + EOL
  }
  annotated += '</sandbox_violations>'

  return annotated
}

/**
 * Returns glob patterns from Edit/Read permission rules that are not
 * fully supported on Linux. Returns empty array on macOS or when
 * sandboxing is disabled.
 *
 * Patterns ending with /** are excluded since they work as subpaths.
 */
function getLinuxGlobPatternWarnings(): string[] {
  // Only warn on Linux/WSL (bubblewrap doesn't support globs)
  // macOS supports glob patterns via regex conversion
  if (getPlatform() !== 'linux' || !config) {
    return []
  }

  const globPatterns: string[] = []

  // Check filesystem paths for glob patterns
  // Note: denyRead is excluded because globs are now expanded to concrete paths on Linux
  const allPaths = [
    ...config.filesystem.allowWrite,
    ...config.filesystem.denyWrite,
  ]

  for (const path of allPaths) {
    // Strip trailing /** since that's just a subpath (directory and everything under it)
    const pathWithoutTrailingStar = removeTrailingGlobSuffix(path)

    // Only warn if there are still glob characters after removing trailing /**
    if (containsGlobChars(pathWithoutTrailingStar)) {
      globPatterns.push(path)
    }
  }

  return globPatterns
}

// ============================================================================
// Public API Interface
// ============================================================================

/**
 * Interface for the sandbox manager API
 */
export interface ISandboxManager {
  initialize(
    runtimeConfig: SandboxRuntimeConfig,
    sandboxAskCallback?: SandboxAskCallback,
    enableLogMonitor?: boolean,
  ): Promise<void>
  isSupportedPlatform(): boolean
  isSandboxingEnabled(): boolean
  checkDependencies(ripgrepConfig?: {
    command: string
    args?: string[]
  }): SandboxDependencyCheck
  getFsReadConfig(): FsReadRestrictionConfig
  getFsWriteConfig(): FsWriteRestrictionConfig
  getNetworkRestrictionConfig(): NetworkRestrictionConfig
  getAllowUnixSockets(): string[] | undefined
  getAllowLocalBinding(): boolean | undefined
  getAllowMachLookup(): string[] | undefined
  getIgnoreViolations(): Record<string, string[]> | undefined
  getEnableWeakerNestedSandbox(): boolean | undefined
  getProxyPort(): number | undefined
  getSocksProxyPort(): number | undefined
  getLinuxHttpSocketPath(): string | undefined
  getLinuxSocksSocketPath(): string | undefined
  waitForNetworkInitialization(): Promise<boolean>
  wrapWithSandbox(
    command: string,
    binShell?: string,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
  ): Promise<string>
  wrapWithSandboxArgv(
    command: string,
    binShell?: string,
    customConfig?: Partial<SandboxRuntimeConfig>,
    abortSignal?: AbortSignal,
  ): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }>
  getSandboxViolationStore(): SandboxViolationStore
  annotateStderrWithSandboxFailures(command: string, stderr: string): string
  getLinuxGlobPatternWarnings(): string[]
  getConfig(): SandboxRuntimeConfig | undefined
  getMitmCA(): MitmCA | undefined
  updateConfig(newConfig: SandboxRuntimeConfig): void
  cleanupAfterCommand(): void
  reset(): Promise<void>
}

// ============================================================================
// Export as Namespace with Interface
// ============================================================================

/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
export const SandboxManager: ISandboxManager = {
  initialize,
  isSupportedPlatform,
  isSandboxingEnabled,
  checkDependencies,
  getFsReadConfig,
  getFsWriteConfig,
  getNetworkRestrictionConfig,
  getAllowUnixSockets,
  getAllowLocalBinding,
  getAllowMachLookup,
  getIgnoreViolations,
  getEnableWeakerNestedSandbox,
  getProxyPort,
  getSocksProxyPort,
  getLinuxHttpSocketPath,
  getLinuxSocksSocketPath,
  waitForNetworkInitialization,
  wrapWithSandbox,
  wrapWithSandboxArgv,
  cleanupAfterCommand,
  reset,
  getMitmCA: () => mitmCA,
  getSandboxViolationStore,
  annotateStderrWithSandboxFailures,
  getLinuxGlobPatternWarnings,
  getConfig,
  updateConfig,
} as const
