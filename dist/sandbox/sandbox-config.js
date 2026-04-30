/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */
import { z } from 'zod';
/**
 * Schema for domain patterns (e.g., "example.com", "*.npmjs.org")
 * Validates that domain patterns are safe and don't include overly broad wildcards
 */
const domainPatternSchema = z.string().refine(val => {
    // Reject protocols, paths, ports, etc.
    if (val.includes('://') || val.includes('/') || val.includes(':')) {
        return false;
    }
    // Allow localhost
    if (val === 'localhost')
        return true;
    // Allow wildcard domains like *.example.com
    if (val.startsWith('*.')) {
        const domain = val.slice(2);
        // After the *. there must be a valid domain with at least one more dot
        // e.g., *.example.com is valid, *.com is not (too broad)
        if (!domain.includes('.') ||
            domain.startsWith('.') ||
            domain.endsWith('.')) {
            return false;
        }
        // Count dots - must have at least 2 parts after the wildcard (e.g., example.com)
        const parts = domain.split('.');
        return parts.length >= 2 && parts.every(p => p.length > 0);
    }
    // Reject any other use of wildcards (e.g., *, *., etc.)
    if (val.includes('*')) {
        return false;
    }
    // Regular domains must have at least one dot and only valid characters
    return val.includes('.') && !val.startsWith('.') && !val.endsWith('.');
}, {
    message: 'Invalid domain pattern. Must be a valid domain (e.g., "example.com") or wildcard (e.g., "*.example.com"). Overly broad patterns like "*.com" or "*" are not allowed for security reasons.',
});
/**
 * Schema for filesystem paths
 */
const filesystemPathSchema = z.string().min(1, 'Path cannot be empty');
/**
 * Schema for MITM proxy configuration
 * Allows routing specific domains through an upstream MITM proxy via Unix socket
 */
const MitmProxyConfigSchema = z.object({
    socketPath: z.string().min(1).describe('Unix socket path to the MITM proxy'),
    domains: z
        .array(domainPatternSchema)
        .min(1)
        .describe('Domains to route through the MITM proxy (e.g., ["api.example.com", "*.internal.org"])'),
});
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
        .describe('Upstream proxy URL for HTTPS/CONNECT traffic (falls back to http if unset)'),
    noProxy: z
        .string()
        .optional()
        .describe('Comma-separated NO_PROXY list (hostname suffixes and CIDR ranges). ' +
        'Matching destinations connect directly instead of via the parent proxy.'),
});
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
    allowAllDomains: z
        .boolean()
        .optional()
        .describe('If true, allow all network traffic by default (deny-list mode). ' +
        'Unmatched hosts are allowed unless they appear in deniedDomains. ' +
        'Mirrors the filesystem read pattern: open by default, block explicitly.'),
    allowUnixSockets: z
        .array(z.string())
        .optional()
        .describe('macOS only: Unix socket paths to allow. Ignored on Linux (seccomp cannot filter by path).'),
    allowAllUnixSockets: z
        .boolean()
        .optional()
        .describe('If true, allow all Unix sockets (disables blocking on both platforms).'),
    allowLocalBinding: z
        .boolean()
        .optional()
        .describe('Whether to allow binding to local ports (default: false)'),
    allowMachLookup: z
        .array(z.string().refine(val => {
        const prefix = val.endsWith('*') ? val.slice(0, -1) : val;
        return !prefix.includes('*');
    }, {
        message: 'Wildcards are only allowed as a single trailing "*" (e.g., "com.example.*" or "*" for all services).',
    }))
        .optional()
        .describe('macOS only: Additional XPC/Mach service names to allow looking up. Supports trailing-wildcard prefix matching (e.g., "2BUA8C4S2C.com.1password.*"). Needed for tools like 1Password CLI, Playwright, or the iOS Simulator that communicate via XPC.'),
    httpProxyPort: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .optional()
        .describe('Port of an external HTTP proxy to use instead of starting a local one. When provided, the library will skip starting its own HTTP proxy and use this port. The external proxy must handle domain filtering.'),
    socksProxyPort: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .optional()
        .describe('Port of an external SOCKS proxy to use instead of starting a local one. When provided, the library will skip starting its own SOCKS proxy and use this port. The external proxy must handle domain filtering.'),
    mitmProxy: MitmProxyConfigSchema.optional().describe('Optional MITM proxy configuration. Routes matching domains through an upstream proxy via Unix socket while SRT still handles allow/deny filtering.'),
    parentProxy: ParentProxyConfigSchema.optional().describe("Upstream HTTP proxy for outbound connections. When set, SRT's proxy " +
        'tunnels non-mitmProxy traffic through this parent instead of ' +
        'connecting directly. Falls back to HTTP_PROXY/HTTPS_PROXY/NO_PROXY ' +
        'env vars if unset.'),
});
/**
 * Filesystem configuration schema for validation
 */
export const FilesystemConfigSchema = z.object({
    denyRead: z.array(filesystemPathSchema).describe('Paths denied for reading'),
    allowRead: z
        .array(filesystemPathSchema)
        .optional()
        .describe('Paths to re-allow reading within denied regions (takes precedence over denyRead). ' +
        'Use with denyRead to deny a broad region then allow back specific subdirectories.'),
    allowWrite: z
        .array(filesystemPathSchema)
        .describe('Paths allowed for writing'),
    denyWrite: z
        .array(filesystemPathSchema)
        .describe('Paths denied for writing (takes precedence over allowWrite)'),
    allowGitConfig: z
        .boolean()
        .optional()
        .describe('Allow writes to .git/config files (default: false). Enables git remote URL updates while keeping .git/hooks protected.'),
});
/**
 * Configuration schema for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 */
export const IgnoreViolationsConfigSchema = z
    .record(z.string(), z.array(z.string()))
    .describe('Map of command patterns to filesystem paths to ignore violations for. Use "*" to match all commands');
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
        .describe('Override argv[0] when spawning (for multicall binaries that dispatch on argv[0])'),
});
/**
 * Seccomp configuration schema (Linux only)
 */
export const SeccompConfigSchema = z.object({
    applyPath: z.string().optional().describe('Path to the apply-seccomp binary'),
    argv0: z
        .string()
        .optional()
        .describe('Invoke apply-seccomp as a multicall binary that dispatches on the ' +
        'ARGV0 environment variable. When set, applyPath is used verbatim ' +
        '(no existence check) and the invocation inside bwrap is prefixed ' +
        'with ARGV0=<this value>. The caller is responsible for ensuring ' +
        'applyPath resolves inside the bwrap namespace and that the target ' +
        'binary implements the apply-seccomp interface when ARGV0 matches.'),
});
/**
 * Main configuration schema for Sandbox Runtime validation
 */
export const SandboxRuntimeConfigSchema = z.object({
    network: NetworkConfigSchema.describe('Network restrictions configuration'),
    filesystem: FilesystemConfigSchema.describe('Filesystem restrictions configuration'),
    ignoreViolations: IgnoreViolationsConfigSchema.optional().describe('Optional configuration for ignoring specific violations'),
    enableWeakerNestedSandbox: z
        .boolean()
        .optional()
        .describe('Enable weaker nested sandbox mode (for Docker environments)'),
    enableWeakerNetworkIsolation: z
        .boolean()
        .optional()
        .describe('Enable weaker network isolation to allow access to com.apple.trustd.agent (macOS only). ' +
        'This is needed for Go programs (gh, gcloud, terraform, kubectl, etc.) to verify TLS certificates ' +
        'when using httpProxyPort with a MITM proxy and custom CA. Enabling this opens a potential data ' +
        'exfiltration vector through the trustd service. Only enable if you need Go TLS verification.'),
    ripgrep: RipgrepConfigSchema.optional().describe('Custom ripgrep configuration (default: { command: "rg" })'),
    mandatoryDenySearchDepth: z
        .number()
        .int()
        .min(1)
        .max(10)
        .optional()
        .describe('Maximum directory depth to search for dangerous files on Linux (default: 3). ' +
        'Higher values provide more protection but slower performance.'),
    allowPty: z
        .boolean()
        .optional()
        .describe('Allow pseudo-terminal (pty) operations (macOS only)'),
    seccomp: SeccompConfigSchema.optional().describe('Custom seccomp binary paths (Linux only).'),
});
//# sourceMappingURL=sandbox-config.js.map