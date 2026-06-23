/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */

import type { FilterRequestCallback } from './request-filter.js'

import { isAbsolute } from 'node:path'
import { z } from 'zod'
import { isInjectHostCoveredByAllowedDomains } from './domain-pattern.js'

/**
 * Schema for domain patterns (e.g., "example.com", "*.npmjs.org")
 * Validates that domain patterns are safe and don't include overly broad wildcards
 */
const domainPatternSchema = z.string().refine(
  val => {
    // Reject protocols, paths, ports, etc.
    if (val.includes('://') || val.includes('/') || val.includes(':')) {
      return false
    }

    // Allow localhost
    if (val === 'localhost') return true

    // Allow wildcard domains like *.example.com
    if (val.startsWith('*.')) {
      const domain = val.slice(2)
      // After the *. there must be a valid domain with at least one more dot
      // e.g., *.example.com is valid, *.com is not (too broad)
      if (
        !domain.includes('.') ||
        domain.startsWith('.') ||
        domain.endsWith('.')
      ) {
        return false
      }
      // Count dots - must have at least 2 parts after the wildcard (e.g., example.com)
      const parts = domain.split('.')
      return parts.length >= 2 && parts.every(p => p.length > 0)
    }

    // Reject any other use of wildcards (e.g., *, *., etc.)
    if (val.includes('*')) {
      return false
    }

    // Regular domains must have at least one dot and only valid characters
    return val.includes('.') && !val.startsWith('.') && !val.endsWith('.')
  },
  {
    message:
      'Invalid domain pattern. Must be a valid domain (e.g., "example.com") or wildcard (e.g., "*.example.com"). Overly broad patterns like "*.com" or "*" are not allowed for security reasons.',
  },
)

/**
 * Schema for filesystem paths
 */
const filesystemPathSchema = z.string().min(1, 'Path cannot be empty')

/**
 * Schema for an absolute path to an external binary.
 * Relative paths are rejected to prevent PATH/CWD-based hijacking — these
 * overrides are intended for admin-managed installs at fixed locations.
 */
const binaryPathSchema = z
  .string()
  .min(1, 'Path cannot be empty')
  .refine(val => isAbsolute(val), {
    message: 'Binary path must be absolute',
  })

/**
 * Schema for MITM proxy configuration
 * Allows routing specific domains through an upstream MITM proxy via Unix socket
 */
const MitmProxyConfigSchema = z.object({
  socketPath: z.string().min(1).describe('Unix socket path to the MITM proxy'),
  domains: z
    .array(domainPatternSchema)
    .min(1)
    .describe(
      'Domains to route through the MITM proxy (e.g., ["api.example.com", "*.internal.org"])',
    ),
})

/**
 * Schema for upstream/parent HTTP proxy configuration.
 * Used when SRT itself runs behind a corporate proxy and cannot make direct
 * outbound connections.
 */
const ParentProxyConfigSchema = z.object({
  http: z
    .string()
    .url()
    .optional()
    .describe('Upstream proxy URL for plain HTTP traffic'),
  https: z
    .string()
    .url()
    .optional()
    .describe(
      'Upstream proxy URL for HTTPS/CONNECT traffic (falls back to http if unset)',
    ),
  noProxy: z
    .string()
    .optional()
    .describe(
      'Comma-separated NO_PROXY list (hostname suffixes and CIDR ranges). ' +
        'Matching destinations connect directly instead of via the parent proxy.',
    ),
})

/**
 * Schema for the access mode of a declared credential source.
 *
 * - `deny` — the sandboxed process cannot read the file / does not see the
 *   environment variable.
 * - `mask` — the sandboxed process sees a per-session sentinel value; the
 *   host proxy substitutes sentinel→real on egress to `injectHosts`.
 *   Currently supported for env vars only; rejected for files until file
 *   masking ships.
 */
const credentialModeSchema = z.enum(['deny', 'mask'])

/**
 * Mode schema for credential files. `mask` is reserved but rejected until
 * file masking ships, so a config can never request behaviour that isn't
 * wired yet.
 */
const credentialFileModeSchema = credentialModeSchema.refine(
  mode => mode !== 'mask',
  {
    message:
      'Credential mode "mask" is not supported for files yet. Use "deny" ' +
      'to block the file inside the sandbox; file masking will be added in ' +
      'a future release. (Env var masking is supported.)',
  },
)

/**
 * Schema for an environment variable name. Restricted to POSIX identifiers so
 * the name can never be parsed as a flag by `env -u` (macOS) or bwrap
 * `--unsetenv` (Linux).
 */
const envVarNameSchema = z
  .string()
  .regex(
    /^[A-Za-z_][A-Za-z0-9_]*$/,
    'Environment variable name must start with a letter or underscore and contain only letters, digits, and underscores',
  )

/**
 * Schema for a single credential file/directory entry.
 */
export const CredentialFileConfigSchema = z.object({
  path: filesystemPathSchema.describe(
    'Path to a credential file or directory. Supports the same path forms as ' +
      'filesystem.denyRead (absolute paths and ~ expansion).',
  ),
  mode: credentialFileModeSchema.describe('Access mode for this path'),
})

/**
 * Schema for a single credential environment variable entry.
 */
export const CredentialEnvVarConfigSchema = z.object({
  name: envVarNameSchema.describe('Environment variable name'),
  mode: credentialModeSchema.describe(
    'Access mode for this environment variable',
  ),
  injectHosts: z
    .array(domainPatternSchema)
    .optional()
    .describe(
      'Optional narrowing of where the proxy substitutes this credential. ' +
        'If unset, defaults to network.allowedDomains — the credential is ' +
        'injected at every reachable host. Only meaningful when mode is ' +
        '"mask"; accepted but ignored for "deny".',
    ),
})

/**
 * Credentials configuration schema for validation.
 *
 * Declares credential sources (files and environment variables) with a
 * per-source mode:
 * - `deny` blocks the source inside the sandbox (file reads are denied via the
 *   filesystem read-deny mechanism, env vars are unset in the child).
 *
 * Additional modes (e.g. `mask`) will be added in future releases.
 *
 * Only the sources declared here are affected; the section applies no
 * implicit restrictions beyond them.
 */
export const CredentialsConfigSchema = z
  .object({
    files: z
      .array(CredentialFileConfigSchema)
      .optional()
      .describe('Credential files or directories to protect'),
    envVars: z
      .array(CredentialEnvVarConfigSchema)
      .optional()
      .describe('Environment variables to protect'),
    allowPlaintextInject: z
      .boolean()
      .optional()
      .describe(
        'Allow sentinel→real substitution on the plain-HTTP proxy path. ' +
          'Defaults to false: without TLS termination the upstream identity ' +
          'is unverified and the credential travels in cleartext. Set only ' +
          'for trusted-network test fixtures.',
      ),
  })
  // Reject unknown keys so a stale `credentials.injectHosts` (the removed
  // block-level default) fails loudly instead of being silently stripped.
  .strict()

/**
 * Network configuration schema for validation
 */
export const NetworkConfigSchema = z.object({
  allowedDomains: z
    .array(domainPatternSchema)
    .describe('List of allowed domains (e.g., ["github.com", "*.npmjs.org"])'),
  deniedDomains: z
    .array(z.union([z.literal('*'), domainPatternSchema]))
    .describe(
      'List of denied domains. Unlike allowedDomains, a bare "*" is accepted here (deny-all).',
    ),
  strictAllowlist: z
    .boolean()
    .optional()
    .describe(
      'If true, hosts not in allowedDomains are denied without consulting the ask callback. Set this when allowedDomains is policy enforcement, not a prompt-suppression hint.',
    ),
  allowUnixSockets: z
    .array(z.string())
    .optional()
    .describe(
      'macOS only: Unix socket paths to allow. Ignored on Linux (seccomp cannot filter by path).',
    ),
  allowAllUnixSockets: z
    .boolean()
    .optional()
    .describe(
      'If true, allow all Unix sockets (disables blocking on both platforms).',
    ),
  allowLocalBinding: z
    .boolean()
    .optional()
    .describe('Whether to allow binding to local ports (default: false)'),
  allowMachLookup: z
    .array(
      z.string().refine(
        val => {
          const prefix = val.endsWith('*') ? val.slice(0, -1) : val
          return !prefix.includes('*')
        },
        {
          message:
            'Wildcards are only allowed as a single trailing "*" (e.g., "com.example.*" or "*" for all services).',
        },
      ),
    )
    .optional()
    .describe(
      'macOS only: Additional XPC/Mach service names to allow looking up. Supports trailing-wildcard prefix matching (e.g., "2BUA8C4S2C.com.1password.*"). Needed for tools like 1Password CLI, Playwright, or the iOS Simulator that communicate via XPC.',
    ),
  httpProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external HTTP proxy to use instead of starting a local one. When provided, the library will skip starting its own HTTP proxy and use this port. The external proxy must handle domain filtering.',
    ),
  socksProxyPort: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe(
      'Port of an external SOCKS proxy to use instead of starting a local one. When provided, the library will skip starting its own SOCKS proxy and use this port. The external proxy must handle domain filtering.',
    ),
  mitmProxy: MitmProxyConfigSchema.optional().describe(
    'Optional MITM proxy configuration. Routes matching domains through an upstream proxy via Unix socket while SRT still handles allow/deny filtering.',
  ),
  filterRequest: z
    .custom<FilterRequestCallback>(v => typeof v === 'function', {
      message: 'filterRequest must be a function',
    })
    .optional()
    .describe(
      'Per-request filter callback. Receives the parsed HTTP request ' +
        '(web-standard Request) and returns {action, reason?}. Denied ' +
        'requests get a 403 with the reason. If the callback throws, the ' +
        'request is denied. Applies to plain HTTP through the proxy and, ' +
        'when tlsTerminate is configured, to terminated HTTPS. SRT does not ' +
        'provide a policy language; library consumers own matching.',
    ),
  tlsTerminate: z
    .object({
      caCertPath: z
        .string()
        .min(1)
        .optional()
        .describe(
          'Path to a PEM-encoded CA certificate. The sandboxed child is ' +
            'configured to trust this CA, and the TLS-terminating proxy uses ' +
            'it to sign per-host certificates. If omitted, SRT generates an ' +
            'ephemeral CA into a temp directory for the lifetime of the ' +
            'session.',
        ),
      caKeyPath: z
        .string()
        .min(1)
        .optional()
        .describe('Path to the PEM-encoded private key for caCertPath.'),
    })
    .refine(o => !o.caCertPath === !o.caKeyPath, {
      message: 'caCertPath and caKeyPath must be provided together',
    })
    .optional()
    .describe(
      '[EXPERIMENTAL] Enable in-process TLS termination so HTTPS ' +
        'request/response bodies are visible to SRT. Provide a CA cert+key, ' +
        'or omit both to have SRT generate an ephemeral one.',
    ),
  parentProxy: ParentProxyConfigSchema.optional().describe(
    "Upstream HTTP proxy for outbound connections. When set, SRT's proxy " +
      'tunnels non-mitmProxy traffic through this parent instead of ' +
      'connecting directly. Falls back to HTTP_PROXY/HTTPS_PROXY/NO_PROXY ' +
      'env vars if unset.',
  ),
})

/**
 * Filesystem configuration schema for validation
 */
export const FilesystemConfigSchema = z.object({
  disabled: z
    .boolean()
    .optional()
    .describe(
      'Disable all filesystem policy enforcement. When true, no read or write rules are emitted: ' +
        'denyRead/allowRead/allowWrite/denyWrite are ignored, and the built-in mandatory write ' +
        'protections (.git/hooks, .git/config, shell rc files, .mcp.json, .vscode/.idea, ' +
        '.claude/commands, .claude/agents) are NOT applied. Use only when the sandboxed process ' +
        'is trusted with full host filesystem access. Network and credential-env restrictions ' +
        'still apply. On Linux, /dev is still replaced by the bwrap minimal devtmpfs.',
    ),
  denyRead: z.array(filesystemPathSchema).describe('Paths denied for reading'),
  allowRead: z
    .array(filesystemPathSchema)
    .optional()
    .describe(
      'Paths to re-allow reading within denied regions (takes precedence over denyRead). ' +
        'Use with denyRead to deny a broad region then allow back specific subdirectories.',
    ),
  allowWrite: z
    .array(filesystemPathSchema)
    .describe('Paths allowed for writing'),
  denyWrite: z
    .array(filesystemPathSchema)
    .describe('Paths denied for writing (takes precedence over allowWrite)'),
  allowGitConfig: z
    .boolean()
    .optional()
    .describe(
      'Allow writes to .git/config files (default: false). Enables git remote URL updates while keeping .git/hooks protected.',
    ),
})

/**
 * Configuration schema for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 */
export const IgnoreViolationsConfigSchema = z
  .record(z.string(), z.array(z.string()))
  .describe(
    'Map of command patterns to filesystem paths to ignore violations for. Use "*" to match all commands',
  )

/**
 * Ripgrep configuration schema
 */
export const RipgrepConfigSchema = z.object({
  command: z.string().describe('The ripgrep command to execute'),
  args: z
    .array(z.string())
    .optional()
    .describe('Additional arguments to pass before ripgrep args'),
  argv0: z
    .string()
    .optional()
    .describe(
      'Override argv[0] when spawning (for multicall binaries that dispatch on argv[0])',
    ),
})

/**
 * Windows-specific configuration schema. See
 * `windows-sandbox-utils.ts` for the install flow these settings
 * must agree with.
 */
export const WindowsConfigSchema = z.object({
  groupName: z
    .string()
    .min(1)
    .default('sandbox-runtime-net')
    .describe(
      'Discriminator group name. Must match the group created at install ' +
        'time. Ignored if groupSid is set.',
    ),
  groupSid: z
    .string()
    .regex(/^S-1-/, 'must be an S-1-… SID string')
    .optional()
    .describe(
      'Discriminator group SID. Overrides groupName lookup — use for ' +
        'domain groups or where name resolution is unreliable.',
    ),
  wfpSublayerGuid: z
    .string()
    .uuid()
    .optional()
    .describe(
      'WFP sublayer GUID under which the filters were installed. Omit to ' +
        'use the srt-win compile-time default. Set this when filters were ' +
        'installed by enterprise tooling under a custom sublayer.',
    ),
  proxyPortRange: z
    .tuple([z.number().int().min(1), z.number().int().max(65535)])
    .refine(([lo, hi]) => lo <= hi && hi - lo <= 64, {
      message: 'low must be ≤ high and range width ≤ 64',
    })
    .optional()
    .describe(
      'Inclusive [low, high] port range the JS http/socks proxies bind ' +
        'inside. MUST match the range passed to `srt-win wfp install ' +
        '--proxy-port-range` (default 60080–60089) — the WFP loopback ' +
        'permit only covers ports in that range.',
    ),
})

/**
 * Seccomp configuration schema (Linux only)
 */
export const SeccompConfigSchema = z.object({
  applyPath: z.string().optional().describe('Path to the apply-seccomp binary'),
  argv0: z
    .string()
    .optional()
    .describe(
      'Invoke apply-seccomp as a multicall binary that dispatches on the ' +
        'ARGV0 environment variable. When set, applyPath is used verbatim ' +
        '(no existence check) and the invocation inside bwrap is prefixed ' +
        'with ARGV0=<this value>. The caller is responsible for ensuring ' +
        'applyPath resolves inside the bwrap namespace and that the target ' +
        'binary implements the apply-seccomp interface when ARGV0 matches.',
    ),
})

/**
 * Main configuration schema for Sandbox Runtime validation
 */
export const SandboxRuntimeConfigSchema = z
  .object({
    network: NetworkConfigSchema.describe('Network restrictions configuration'),
    filesystem: FilesystemConfigSchema.describe(
      'Filesystem restrictions configuration',
    ),
    credentials: CredentialsConfigSchema.optional().describe(
      'Credential handling configuration. Only the explicitly declared files ' +
        'and environment variables are restricted.',
    ),
    ignoreViolations: IgnoreViolationsConfigSchema.optional().describe(
      'Optional configuration for ignoring specific violations',
    ),
    enableWeakerNestedSandbox: z
      .boolean()
      .optional()
      .describe('Enable weaker nested sandbox mode (for Docker environments)'),
    enableWeakerNetworkIsolation: z
      .boolean()
      .optional()
      .describe(
        'Enable weaker network isolation to allow access to com.apple.trustd.agent (macOS only). ' +
          'This is needed for Go programs (gh, gcloud, terraform, kubectl, etc.) to verify TLS certificates ' +
          'when using httpProxyPort with a MITM proxy and custom CA. Enabling this opens a potential data ' +
          'exfiltration vector through the trustd service. Only enable if you need Go TLS verification.',
      ),
    allowAppleEvents: z
      .boolean()
      .optional()
      .describe(
        'Allow sending Apple Events and Launch Services open requests from the sandbox (macOS only). ' +
          'Needed for open, osascript, and anything that opens URLs or scripts other apps via AppleScript. ' +
          'This removes code-execution isolation: sandboxed commands can launch other applications ' +
          'unsandboxed with no user prompt (launched apps are not subject to the sandbox filesystem or ' +
          'network restrictions), and can script running apps subject to TCC automation consent. ' +
          'Default: false.',
      ),
    ripgrep: RipgrepConfigSchema.optional().describe(
      'Custom ripgrep configuration (default: { command: "rg" })',
    ),
    mandatoryDenySearchDepth: z
      .number()
      .int()
      .min(1)
      .max(10)
      .optional()
      .describe(
        'Maximum directory depth to search for dangerous files on Linux (default: 3). ' +
          'Higher values provide more protection but slower performance.',
      ),
    allowPty: z
      .boolean()
      .optional()
      .describe('Allow pseudo-terminal (pty) operations (macOS only)'),
    seccomp: SeccompConfigSchema.optional().describe(
      'Custom seccomp binary paths (Linux only).',
    ),
    bwrapPath: binaryPathSchema
      .optional()
      .describe(
        'Linux only: absolute path to the bwrap (bubblewrap) binary. ' +
          'When set, this path is used directly instead of resolving "bwrap" via PATH.',
      ),
    socatPath: binaryPathSchema
      .optional()
      .describe(
        'Linux only: absolute path to the socat binary. ' +
          'When set, this path is used directly instead of resolving "socat" via PATH.',
      ),
    windows: WindowsConfigSchema.optional().describe(
      'Windows-specific settings (group, WFP sublayer, proxy port range).',
    ),
  })
  .superRefine((cfg, ctx) => {
    const creds = cfg.credentials
    if (!creds) return

    // Every per-entry injectHosts pattern must be reachable via
    // allowedDomains — semantic (wildcard-aware) coverage, not literal
    // string membership, so `injectHosts: ['api.github.com']` is accepted
    // when `allowedDomains: ['*.github.com']`.
    const allowed = cfg.network.allowedDomains
    const checkSubset = (
      hosts: readonly string[],
      path: (string | number)[],
    ) => {
      for (const [i, host] of hosts.entries()) {
        if (!isInjectHostCoveredByAllowedDomains(host, allowed)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [...path, i],
            message:
              `injectHosts entry "${host}" is not reachable via ` +
              `network.allowedDomains — add "${host}" (or a covering ` +
              `wildcard) to allowedDomains, or remove it from injectHosts.`,
          })
        }
      }
    }

    // Per-credential checks. Substitution is gated per sentinel; an entry
    // with no injectHosts defaults to network.allowedDomains (every
    // reachable host), so absence is fine. An *explicit* empty list is
    // rejected — "mask but never inject" is self-contradictory and almost
    // certainly a config mistake.
    let hasMaskedEnv = false
    for (const [idx, v] of (creds.envVars ?? []).entries()) {
      if (v.injectHosts) {
        checkSubset(v.injectHosts, [
          'credentials',
          'envVars',
          idx,
          'injectHosts',
        ])
      }
      if (v.mode !== 'mask') continue
      hasMaskedEnv = true
      if (v.injectHosts !== undefined && v.injectHosts.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['credentials', 'envVars', idx],
          message:
            `injectHosts is explicitly empty — the credential would be ` +
            `masked but never injected. Omit injectHosts to default to ` +
            `network.allowedDomains, or list the intended hosts.`,
        })
      }
    }

    // Masked env vars require the TLS-terminated proxy path so the real
    // credential is only sent to a cert-verified upstream. allowPlaintextInject
    // is the explicit escape hatch.
    if (
      hasMaskedEnv &&
      cfg.network.tlsTerminate === undefined &&
      !creds.allowPlaintextInject
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['credentials'],
        message:
          'Credential masking requires network.tlsTerminate so substitution ' +
          'runs only over a verified TLS connection. Enable tlsTerminate, or ' +
          'set credentials.allowPlaintextInject to opt out (not recommended).',
      })
    }
  })

// Export inferred types
export type MitmProxyConfig = z.infer<typeof MitmProxyConfigSchema>
export type ParentProxyConfig = z.infer<typeof ParentProxyConfigSchema>
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>
export type FilesystemConfig = z.infer<typeof FilesystemConfigSchema>
export type CredentialMode = z.infer<typeof credentialModeSchema>
export type CredentialFileConfig = z.infer<typeof CredentialFileConfigSchema>
export type CredentialEnvVarConfig = z.infer<
  typeof CredentialEnvVarConfigSchema
>
export type CredentialsConfig = z.infer<typeof CredentialsConfigSchema>
export type IgnoreViolationsConfig = z.infer<
  typeof IgnoreViolationsConfigSchema
>
export type RipgrepConfig = z.infer<typeof RipgrepConfigSchema>
export type SeccompConfig = z.infer<typeof SeccompConfigSchema>
export type WindowsConfig = z.infer<typeof WindowsConfigSchema>
export type SandboxRuntimeConfig = z.infer<typeof SandboxRuntimeConfigSchema>
