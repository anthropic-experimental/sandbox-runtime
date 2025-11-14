import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as fs from 'node:fs'
import { logForDebugging } from '../utils/debug.js'

/**
 * Map Node.js process.arch to our vendor directory architecture names
 * Returns null for unsupported architectures
 */
function getVendorArchitecture(): string | null {
  const arch = process.arch as string
  switch (arch) {
    case 'x64':
    case 'x86_64':
      return 'x64'
    case 'arm64':
    case 'aarch64':
      return 'arm64'
    case 'ia32':
    case 'x86':
      // TODO: Add support for 32-bit x86 (ia32)
      // Currently blocked because the seccomp filter does not block the socketcall() syscall,
      // which is used on 32-bit x86 for all socket operations (socket, socketpair, bind, connect, etc.).
      // On 32-bit x86, the direct socket() syscall doesn't exist - instead, all socket operations
      // are multiplexed through socketcall(SYS_SOCKET, ...), socketcall(SYS_SOCKETPAIR, ...), etc.
      //
      // To properly support 32-bit x86, we need to:
      // 1. Build a separate i386 BPF filter (BPF bytecode is architecture-specific)
      // 2. Modify vendor/seccomp-src/seccomp-unix-block.c to conditionally add rules that block:
      //    - socketcall(SYS_SOCKET, [AF_UNIX, ...])
      //    - socketcall(SYS_SOCKETPAIR, [AF_UNIX, ...])
      // 3. This requires complex BPF logic to inspect socketcall's sub-function argument
      //
      // Until then, 32-bit x86 is not supported to avoid a security bypass.
      logForDebugging(
        `[SeccompFilter] 32-bit x86 (ia32) is not currently supported due to missing socketcall() syscall blocking. ` +
          `The current seccomp filter only blocks socket(AF_UNIX, ...), but on 32-bit x86, socketcall() can be used to bypass this.`,
        { level: 'error' },
      )
      return null
    default:
      logForDebugging(
        `[SeccompFilter] Unsupported architecture: ${arch}. Only x64 and arm64 are supported.`,
      )
      return null
  }
}

/**
 * Get the path to a pre-generated BPF filter file from the vendor directory
 * Returns the path if it exists, null otherwise
 *
 * Pre-generated BPF files are organized by architecture:
 * - vendor/seccomp/{x64,arm64}/unix-block.bpf
 *
 * Tries multiple paths for resilience:
 * 1. vendor/seccomp/{arch}/unix-block.bpf (bundled - when bundled into consuming packages)
 * 2. ../../vendor/seccomp/{arch}/unix-block.bpf (package root - standard npm installs)
 * 3. ../vendor/seccomp/{arch}/unix-block.bpf (dist/vendor - for bundlers)
 */
export function getPreGeneratedBpfPath(): string | null {
  // Determine architecture
  const arch = getVendorArchitecture()
  if (!arch) {
    logForDebugging(
      `[SeccompFilter] Cannot find pre-generated BPF filter: unsupported architecture ${process.arch}`,
    )
    return null
  }

  logForDebugging(`[SeccompFilter] Detected architecture: ${arch}`)

  // Try to locate the BPF file with fallback paths
  // Path is relative to the compiled code location (dist/sandbox/)
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const relativePath = join('vendor', 'seccomp', arch, 'unix-block.bpf')

  // Try paths in order of preference
  const pathsToTry = [
    join(baseDir, relativePath), // bundled: same directory as bundle (e.g., when bundled into claude-cli)
    join(baseDir, '..', '..', relativePath), // package root: vendor/seccomp/...
    join(baseDir, '..', relativePath), // dist: dist/vendor/seccomp/...
  ]

  for (const bpfPath of pathsToTry) {
    if (fs.existsSync(bpfPath)) {
      logForDebugging(
        `[SeccompFilter] Found pre-generated BPF filter: ${bpfPath} (${arch})`,
      )
      return bpfPath
    }
  }

  logForDebugging(
    `[SeccompFilter] Pre-generated BPF filter not found in any expected location (${arch})`,
  )
  return null
}

/**
 * Get the path to the apply-seccomp binary from the vendor directory
 * Returns the path if it exists, null otherwise
 *
 * Pre-built apply-seccomp binaries are organized by architecture:
 * - vendor/seccomp/{x64,arm64}/apply-seccomp
 *
 * Tries multiple paths for resilience:
 * 1. vendor/seccomp/{arch}/apply-seccomp (bundled - when bundled into consuming packages)
 * 2. ../../vendor/seccomp/{arch}/apply-seccomp (package root - standard npm installs)
 * 3. ../vendor/seccomp/{arch}/apply-seccomp (dist/vendor - for bundlers)
 */
export function getApplySeccompBinaryPath(): string | null {
  // Determine architecture
  const arch = getVendorArchitecture()
  if (!arch) {
    logForDebugging(
      `[SeccompFilter] Cannot find apply-seccomp binary: unsupported architecture ${process.arch}`,
    )
    return null
  }

  logForDebugging(
    `[SeccompFilter] Looking for apply-seccomp binary for architecture: ${arch}`,
  )

  // Try to locate the binary with fallback paths
  // Path is relative to the compiled code location (dist/sandbox/)
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const relativePath = join('vendor', 'seccomp', arch, 'apply-seccomp')

  // Try paths in order of preference
  const pathsToTry = [
    join(baseDir, relativePath), // bundled: same directory as bundle (e.g., when bundled into claude-cli)
    join(baseDir, '..', '..', relativePath), // package root: vendor/seccomp/...
    join(baseDir, '..', relativePath), // dist: dist/vendor/seccomp/...
  ]

  for (const binaryPath of pathsToTry) {
    if (fs.existsSync(binaryPath)) {
      logForDebugging(
        `[SeccompFilter] Found apply-seccomp binary: ${binaryPath} (${arch})`,
      )
      return binaryPath
    }
  }

  logForDebugging(
    `[SeccompFilter] apply-seccomp binary not found in any expected location (${arch})`,
  )
  return null
}

/**
 * Get the path to a pre-generated seccomp BPF filter that blocks Unix domain socket creation
 * Returns the path to the BPF filter file, or null if not available
 *
 * The filter blocks socket(AF_UNIX, ...) syscalls while allowing all other syscalls.
 * This prevents creation of new Unix domain socket file descriptors.
 *
 * Security scope:
 * - Blocks: socket(AF_UNIX, ...) syscall (creating new Unix socket FDs)
 * - Does NOT block: Operations on inherited Unix socket FDs (bind, connect, sendto, etc.)
 * - Does NOT block: Unix socket FDs passed via SCM_RIGHTS
 * - For most sandboxing scenarios, blocking socket creation is sufficient
 *
 * Note: This blocks ALL Unix socket creation, regardless of path. The allowUnixSockets
 * configuration is not supported on Linux due to seccomp-bpf limitations (it cannot
 * read user-space memory to inspect socket paths).
 *
 * Requirements:
 * - Pre-generated BPF filters included for x64 and ARM64 only
 * - Other architectures are not supported
 *
 * @returns Path to the pre-generated BPF filter file, or null if not available
 */
export function generateSeccompFilter(): string | null {
  const preGeneratedBpf = getPreGeneratedBpfPath()
  if (preGeneratedBpf) {
    logForDebugging('[SeccompFilter] Using pre-generated BPF filter')
    return preGeneratedBpf
  }

  logForDebugging(
    '[SeccompFilter] Pre-generated BPF filter not available for this architecture. ' +
      'Only x64 and arm64 are supported.',
    { level: 'error' },
  )
  return null
}

/**
 * Clean up a seccomp filter file
 * Since we only use pre-generated BPF files from vendor/, this is a no-op.
 * Pre-generated files are never deleted.
 * Kept for backward compatibility with existing code that calls it.
 */
export function cleanupSeccompFilter(_filterPath: string): void {
  // No-op: pre-generated BPF files are never cleaned up
}
