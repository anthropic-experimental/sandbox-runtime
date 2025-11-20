/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */

import { z } from 'zod'
import * as fs from 'node:fs'
import * as path from 'node:path'

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

const filesystemMappingSchema = z.object({
  hostPath: filesystemPathSchema.describe(
    'Host directory that should be exposed inside the sandbox',
  ),
  sandboxPath: filesystemPathSchema.describe(
    'Path inside the sandbox where the host directory will appear',
  ),
  mode: z
    .enum(['readwrite', 'readonly'])
    .default('readwrite')
    .describe(
      'Whether the sandbox should see the path as readwrite or readonly (default: readwrite)',
    ),
})

const unixSocketMappingSchema = z.object({
  hostPath: filesystemPathSchema.describe(
    'Host unix socket path owned by the supervisor',
  ),
  sandboxPath: filesystemPathSchema.describe(
    'Sandbox-visible path that forwards to hostPath via the unix socket supervisor',
  ),
})

/**
 * Network configuration schema for validation
 */
export const NetworkConfigSchema = z.object({
  allowedDomains: z
    .array(domainPatternSchema)
    .describe('List of allowed domains (e.g., ["github.com", "*.npmjs.org"])'),
  deniedDomains: z
    .array(domainPatternSchema)
    .describe('List of denied domains'),
  allowUnixSockets: z
    .array(z.string())
    .optional()
    .describe('Unix socket paths that are allowed (macOS only)'),
  unixSocketMappings: z
    .array(unixSocketMappingSchema)
    .default([])
    .describe(
      'Map sandbox unix socket paths to host unix sockets managed by the supervisor (Linux only)',
    ),
  allowAllUnixSockets: z
    .boolean()
    .optional()
    .describe(
      'Allow ALL Unix sockets (Linux only - disables Unix socket blocking)',
    ),
  allowLocalBinding: z
    .boolean()
    .optional()
    .describe('Whether to allow binding to local ports (default: false)'),
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
})

/**
 * Filesystem configuration schema for validation
 */
export const FilesystemConfigSchema = z.object({
  denyRead: z.array(filesystemPathSchema).describe('Paths denied for reading'),
  allowWrite: z
    .array(filesystemPathSchema)
    .describe('Paths allowed for writing'),
  denyWrite: z
    .array(filesystemPathSchema)
    .describe('Paths denied for writing (takes precedence over allowWrite)'),
  mappings: z
    .array(filesystemMappingSchema)
    .default([])
    .describe(
      'Map directories inside the sandbox to different host directories (Linux only)',
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
  command: z
    .string()
    .describe('The ripgrep command to execute (e.g., "rg", "claude")'),
  args: z
    .array(z.string())
    .optional()
    .describe(
      'Additional arguments to pass before ripgrep args (e.g., ["--ripgrep"])',
    ),
})

/**
 * Main configuration schema for Sandbox Runtime validation
 */
export const SandboxRuntimeConfigSchema = z.object({
  network: NetworkConfigSchema.describe('Network restrictions configuration'),
  filesystem: FilesystemConfigSchema.describe(
    'Filesystem restrictions configuration',
  ),
  ignoreViolations: IgnoreViolationsConfigSchema.optional().describe(
    'Optional configuration for ignoring specific violations',
  ),
  enableWeakerNestedSandbox: z
    .boolean()
    .optional()
    .describe('Enable weaker nested sandbox mode (for Docker environments)'),
  ripgrep: RipgrepConfigSchema.optional().describe(
    'Custom ripgrep configuration (default: { command: "rg" })',
  ),
})

// Export inferred types
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>
export type FilesystemConfig = z.infer<typeof FilesystemConfigSchema>
export type IgnoreViolationsConfig = z.infer<
  typeof IgnoreViolationsConfigSchema
>
export type RipgrepConfig = z.infer<typeof RipgrepConfigSchema>
export type SandboxRuntimeConfig = z.infer<typeof SandboxRuntimeConfigSchema>

function assertDirectoryExists(targetPath: string, label: string): void {
  if (!fs.existsSync(targetPath)) {
    throw new Error(`${label} does not exist: ${targetPath}`)
  }

  const stats = fs.statSync(targetPath)
  if (!stats.isDirectory()) {
    throw new Error(`${label} must be a directory: ${targetPath}`)
  }
}

export function validateSandboxRuntimePaths(
  config: SandboxRuntimeConfig,
): void {
  for (const mapping of config.filesystem.mappings ?? []) {
    assertDirectoryExists(mapping.hostPath, 'filesystem mapping hostPath')
  }

  for (const socketMapping of config.network.unixSocketMappings ?? []) {
    const parentDir = path.dirname(socketMapping.hostPath)
    assertDirectoryExists(parentDir, 'unix socket mapping parent directory')
  }
}
