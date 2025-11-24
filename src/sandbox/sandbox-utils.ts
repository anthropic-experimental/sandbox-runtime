import { homedir } from 'os'
import * as path from 'path'
import * as fs from 'fs'
import { getPlatform } from '../utils/platform.js'
import { ripGrep } from '../utils/ripgrep.js'

/**
 * Dangerous files that should be protected from writes.
 * These files can be used for code execution or data exfiltration.
 */
const DANGEROUS_FILES = [
  '.gitconfig',
  '.gitmodules',
  '.bashrc',
  '.bash_profile',
  '.zshrc',
  '.zprofile',
  '.profile',
  '.ripgreprc',
  '.mcp.json',
] as const

/**
 * Dangerous directories that should be protected from writes.
 * These directories contain sensitive configuration or executable files.
 */
const DANGEROUS_DIRECTORIES = ['.git', '.vscode', '.idea'] as const

/**
 * Normalizes a path for case-insensitive comparison.
 * This prevents bypassing security checks using mixed-case paths on case-insensitive
 * filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.
 *
 * We always normalize to lowercase regardless of platform for consistent security.
 * @param path The path to normalize
 * @returns The lowercase path for safe comparison
 */
function normalizeCaseForComparison(pathStr: string): string {
  return pathStr.toLowerCase()
}

/**
 * Check if a path pattern contains glob characters
 */
export function containsGlobChars(pathPattern: string): boolean {
  return (
    pathPattern.includes('*') ||
    pathPattern.includes('?') ||
    pathPattern.includes('[') ||
    pathPattern.includes(']')
  )
}

/**
 * Remove trailing /** glob suffix from a path pattern
 * Used to normalize path patterns since /** just means "directory and everything under it"
 */
export function removeTrailingGlobSuffix(pathPattern: string): string {
  return pathPattern.replace(/\/\*\*$/, '')
}

/**
 * Normalize a path for use in sandbox configurations
 * Handles:
 * - Tilde (~) expansion for home directory
 * - Relative paths (./foo, ../foo, etc.) converted to absolute
 * - Absolute paths remain unchanged
 * - Symlinks are resolved to their real paths for non-glob patterns
 * - Glob patterns preserve wildcards after path normalization
 *
 * Returns the absolute path with symlinks resolved (or normalized glob pattern)
 */
export function normalizePathForSandbox(pathPattern: string): string {
  const cwd = process.cwd()
  let normalizedPath = pathPattern

  // Expand ~ to home directory
  if (pathPattern === '~') {
    normalizedPath = homedir()
  } else if (pathPattern.startsWith('~/')) {
    normalizedPath = homedir() + pathPattern.slice(1)
  } else if (pathPattern.startsWith('./') || pathPattern.startsWith('../')) {
    // Convert relative to absolute based on current working directory
    normalizedPath = path.resolve(cwd, pathPattern)
  } else if (!path.isAbsolute(pathPattern)) {
    // Handle other relative paths (e.g., ".", "..", "foo/bar")
    normalizedPath = path.resolve(cwd, pathPattern)
  }

  // For glob patterns, resolve symlinks for the directory portion only
  if (containsGlobChars(normalizedPath)) {
    // Extract the static directory prefix before glob characters
    const staticPrefix = normalizedPath.split(/[*?[\]]/)[0]
    if (staticPrefix && staticPrefix !== '/') {
      // Get the directory containing the glob pattern
      // If staticPrefix ends with /, remove it to get the directory
      const baseDir = staticPrefix.endsWith('/')
        ? staticPrefix.slice(0, -1)
        : path.dirname(staticPrefix)

      // Try to resolve symlinks for the base directory
      try {
        const resolvedBaseDir = fs.realpathSync(baseDir)
        // Reconstruct the pattern with the resolved directory
        const patternSuffix = normalizedPath.slice(baseDir.length)
        return resolvedBaseDir + patternSuffix
      } catch {
        // If directory doesn't exist or can't be resolved, keep the original pattern
      }
    }
    return normalizedPath
  }

  // Resolve symlinks to real paths to avoid bwrap issues
  try {
    normalizedPath = fs.realpathSync(normalizedPath)
  } catch {
    // If path doesn't exist or can't be resolved, keep the normalized path
  }

  return normalizedPath
}

/**
 * Get recommended system paths that should be writable for commands to work properly
 *
 * WARNING: These default paths are intentionally broad for compatibility but may
 * allow access to files from other processes. In highly security-sensitive
 * environments, you should configure more restrictive write paths.
 */
export function getDefaultWritePaths(): string[] {
  const homeDir = homedir()
  const recommendedPaths = [
    '/dev/stdout',
    '/dev/stderr',
    '/dev/null',
    '/dev/tty',
    '/dev/dtracehelper',
    '/dev/autofs_nowait',
    '/tmp/claude',
    '/private/tmp/claude',
    path.join(homeDir, '.npm/_logs'),
    path.join(homeDir, '.claude/debug'),
  ]

  return recommendedPaths
}

/**
 * Get mandatory deny paths within allowed write areas
 * This uses ripgrep to scan the filesystem for dangerous files and directories
 * Returns absolute paths that must be blocked from writes
 * @param ripgrepConfig Ripgrep configuration (command and optional args)
 * @param skipGitConfigProtection If true, skip blocking .git/config and .git/hooks
 */
export async function getMandatoryDenyWithinAllow(
  ripgrepConfig: { command: string; args?: string[] } = { command: 'rg' },
  skipGitConfigProtection = false,
): Promise<string[]> {
  const denyPaths: string[] = []
  const cwd = process.cwd()

  // Always deny writes to settings.json files
  // Block in home directory
  denyPaths.push(path.join(homedir(), '.claude', 'settings.json'))
  // Block in current directory
  denyPaths.push(path.resolve(cwd, '.claude', 'settings.json'))
  denyPaths.push(path.resolve(cwd, '.claude', 'settings.local.json'))

  // Use shared constants for dangerous files
  const dangerousFiles = [...DANGEROUS_FILES]

  // Use shared constants plus additional Claude-specific directories
  // Note: We don't include .git as a whole directory since we need it to be writable for git operations
  // Instead, we'll block specific dangerous paths within .git (hooks and config) below
  const dangerousDirectories = [
    ...DANGEROUS_DIRECTORIES.filter(d => d !== '.git'),
    '.claude/commands',
    '.claude/agents',
  ]

  // Create an AbortController for ripgrep operations
  const abortController = new AbortController()

  // Add absolute paths for dangerous files in CWD
  for (const fileName of dangerousFiles) {
    // Always include the potential path in CWD (even if file doesn't exist yet)
    const cwdFilePath = path.resolve(cwd, fileName)
    denyPaths.push(cwdFilePath)

    // Find all existing instances of this file in CWD and subdirectories using ripgrep
    try {
      // Use ripgrep to find files with exact name match (case-insensitive)
      // -g/--glob: Include/exclude files matching this glob pattern
      // --files: List files that would be searched
      // --hidden: Search hidden files
      // --iglob: Case-insensitive glob matching to catch .Bashrc, .BASHRC, etc.
      const matches = await ripGrep(
        [
          '--files',
          '--hidden',
          '--iglob',
          fileName,
          '-g',
          '!**/node_modules/**',
        ],
        cwd,
        abortController.signal,
        ripgrepConfig,
      )
      // Convert relative paths to absolute paths
      const absoluteMatches = matches.map(match => path.resolve(cwd, match))
      denyPaths.push(...absoluteMatches)
    } catch (error) {
      // If ripgrep fails, we cannot safely determine all dangerous files
      throw new Error(
        `Failed to scan for dangerous file "${fileName}": ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  // Add absolute paths for dangerous directories in CWD
  for (const dirName of dangerousDirectories) {
    // Always include the potential path in CWD (even if directory doesn't exist yet)
    const cwdDirPath = path.resolve(cwd, dirName)
    denyPaths.push(cwdDirPath)

    // Find all existing instances of this directory in CWD and subdirectories using ripgrep
    try {
      // Use ripgrep to find directories (case-insensitive)
      // Note: ripgrep lists files, so we need to find files within these directories
      // and then extract the directory paths
      const pattern = `**/${dirName}/**`
      const matches = await ripGrep(
        [
          '--files',
          '--hidden',
          '--iglob',
          pattern,
          '-g',
          '!**/node_modules/**',
        ],
        cwd,
        abortController.signal,
        ripgrepConfig,
      )

      // Extract directory paths from file paths
      const dirPaths = new Set<string>()
      for (const match of matches) {
        const absolutePath = path.resolve(cwd, match)
        // Find the dangerous directory in the path (case-insensitive)
        const segments = absolutePath.split(path.sep)
        const normalizedDirName = normalizeCaseForComparison(dirName)
        // Find the directory using case-insensitive comparison
        const dirIndex = segments.findIndex(
          segment => normalizeCaseForComparison(segment) === normalizedDirName,
        )
        if (dirIndex !== -1) {
          // Reconstruct path up to and including the dangerous directory
          const dirPath = segments.slice(0, dirIndex + 1).join(path.sep)
          dirPaths.add(dirPath)
        }
      }
      denyPaths.push(...dirPaths)
    } catch (error) {
      // If ripgrep fails, we cannot safely determine all dangerous directories
      throw new Error(
        `Failed to scan for dangerous directory "${dirName}": ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  }

  // Special handling for dangerous .git paths
  // We block specific paths within .git that can be used for code execution
  // This can be skipped when using an external security proxy that handles these exploits
  if (!skipGitConfigProtection) {
    const dangerousGitPaths = [
      '.git/hooks', // Block all hook files to prevent code execution via git hooks
      '.git/config', // Block config file to prevent dangerous config options like core.fsmonitor
    ]

    for (const gitPath of dangerousGitPaths) {
      // Add the path in the current working directory
      const absoluteGitPath = path.resolve(cwd, gitPath)
      denyPaths.push(absoluteGitPath)

      // Also find .git directories in subdirectories and block their hooks/config
      // This handles nested repositories (case-insensitive)
      try {
        // Find all .git directories by looking for .git/HEAD files (case-insensitive)
        const gitHeadFiles = await ripGrep(
          [
            '--files',
            '--hidden',
            '--iglob',
            '**/.git/HEAD',
            '-g',
            '!**/node_modules/**',
          ],
          cwd,
          abortController.signal,
          ripgrepConfig,
        )

        for (const gitHeadFile of gitHeadFiles) {
          // Get the .git directory path
          const gitDir = path.dirname(gitHeadFile)

          // Add the dangerous path within this .git directory
          if (gitPath === '.git/hooks') {
            const hooksPath = path.join(gitDir, 'hooks')
            denyPaths.push(hooksPath)
          } else if (gitPath === '.git/config') {
            const configPath = path.join(gitDir, 'config')
            denyPaths.push(configPath)
          }
        }
      } catch (error) {
        // If ripgrep fails, we cannot safely determine all .git repositories
        throw new Error(
          `Failed to scan for .git directories: ${error instanceof Error ? error.message : String(error)}`,
        )
      }
    }
  }

  // Remove duplicates and return
  return Array.from(new Set(denyPaths))
}

/**
 * Generate proxy environment variables for sandboxed processes
 */
export function generateProxyEnvVars(
  httpProxyPort?: number,
  socksProxyPort?: number,
  customEnv?: Record<string, string>,
): string[] {
  const envVars: string[] = [`SANDBOX_RUNTIME=1`, `TMPDIR=/tmp/claude`]

  // If no proxy ports provided, return minimal env vars (plus custom env)
  if (!httpProxyPort && !socksProxyPort) {
    if (customEnv) {
      for (const [key, value] of Object.entries(customEnv)) {
        envVars.push(`${key}=${value}`)
      }
    }
    return envVars
  }

  // Always set NO_PROXY to exclude localhost and private networks from proxying
  const noProxyAddresses = [
    'localhost',
    '127.0.0.1',
    '::1',
    '*.local',
    '.local',
    '169.254.0.0/16', // Link-local
    '10.0.0.0/8', // Private network
    '172.16.0.0/12', // Private network
    '192.168.0.0/16', // Private network
  ].join(',')
  envVars.push(`NO_PROXY=${noProxyAddresses}`)
  envVars.push(`no_proxy=${noProxyAddresses}`)

  if (httpProxyPort) {
    envVars.push(`HTTP_PROXY=http://localhost:${httpProxyPort}`)
    envVars.push(`HTTPS_PROXY=http://localhost:${httpProxyPort}`)
    // Lowercase versions for compatibility with some tools
    envVars.push(`http_proxy=http://localhost:${httpProxyPort}`)
    envVars.push(`https_proxy=http://localhost:${httpProxyPort}`)
  }

  if (socksProxyPort) {
    // Use socks5h:// for proper DNS resolution through proxy
    envVars.push(`ALL_PROXY=socks5h://localhost:${socksProxyPort}`)
    envVars.push(`all_proxy=socks5h://localhost:${socksProxyPort}`)

    // Configure Git to use SSH through SOCKS proxy (platform-aware)
    if (getPlatform() === 'macos') {
      // macOS has nc available
      envVars.push(
        `GIT_SSH_COMMAND="ssh -o ProxyCommand='nc -X 5 -x localhost:${socksProxyPort} %h %p'"`,
      )
    }

    // FTP proxy support (use socks5h for DNS resolution through proxy)
    envVars.push(`FTP_PROXY=socks5h://localhost:${socksProxyPort}`)
    envVars.push(`ftp_proxy=socks5h://localhost:${socksProxyPort}`)

    // rsync proxy support
    envVars.push(`RSYNC_PROXY=localhost:${socksProxyPort}`)

    // Database tools NOTE: Most database clients don't have built-in proxy support
    // You typically need to use SSH tunneling or a SOCKS wrapper like tsocks/proxychains

    // Docker CLI uses HTTP for the API
    // This makes Docker use the HTTP proxy for registry operations
    envVars.push(
      `DOCKER_HTTP_PROXY=http://localhost:${httpProxyPort || socksProxyPort}`,
    )
    envVars.push(
      `DOCKER_HTTPS_PROXY=http://localhost:${httpProxyPort || socksProxyPort}`,
    )

    // Kubernetes kubectl - uses standard HTTPS_PROXY
    // kubectl respects HTTPS_PROXY which we already set above

    // AWS CLI - uses standard HTTPS_PROXY (v2 supports it well)
    // AWS CLI v2 respects HTTPS_PROXY which we already set above

    // Google Cloud SDK - has specific proxy settings
    // Use HTTPS proxy to match other HTTP-based tools
    if (httpProxyPort) {
      envVars.push(`CLOUDSDK_PROXY_TYPE=https`)
      envVars.push(`CLOUDSDK_PROXY_ADDRESS=localhost`)
      envVars.push(`CLOUDSDK_PROXY_PORT=${httpProxyPort}`)
    }

    // Azure CLI - uses HTTPS_PROXY
    // Azure CLI respects HTTPS_PROXY which we already set above

    // Terraform - uses standard HTTP/HTTPS proxy vars
    // Terraform respects HTTP_PROXY/HTTPS_PROXY which we already set above

    // gRPC-based tools - use standard proxy vars
    envVars.push(`GRPC_PROXY=socks5h://localhost:${socksProxyPort}`)
    envVars.push(`grpc_proxy=socks5h://localhost:${socksProxyPort}`)
  }

  // WARNING: Do not set HTTP_PROXY/HTTPS_PROXY to SOCKS URLs when only SOCKS proxy is available
  // Most HTTP clients do not support SOCKS URLs in these variables and will fail, and we want
  // to avoid overriding the client otherwise respecting the ALL_PROXY env var which points to SOCKS.

  // Add custom environment variables (these can override the defaults above)
  if (customEnv) {
    for (const [key, value] of Object.entries(customEnv)) {
      envVars.push(`${key}=${value}`)
    }
  }

  return envVars
}

/**
 * Encode a command for sandbox monitoring
 * Truncates to 100 chars and base64 encodes to avoid parsing issues
 */
export function encodeSandboxedCommand(command: string): string {
  const truncatedCommand = command.slice(0, 100)
  return Buffer.from(truncatedCommand).toString('base64')
}

/**
 * Decode a base64-encoded command from sandbox monitoring
 */
export function decodeSandboxedCommand(encodedCommand: string): string {
  return Buffer.from(encodedCommand, 'base64').toString('utf8')
}
