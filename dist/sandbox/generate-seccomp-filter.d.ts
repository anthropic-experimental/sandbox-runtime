/**
 * Get the path to the apply-seccomp binary from the vendor directory
 * Returns the path if it exists, null otherwise
 *
 * Pre-built apply-seccomp binaries are organized by architecture:
 * - vendor/seccomp/{x64,arm64}/apply-seccomp
 *
 * Tries multiple paths for resilience:
 * 0. Explicit path provided via parameter (checked first if provided)
 * 1. vendor/seccomp/{arch}/apply-seccomp (bundled - when bundled into consuming packages)
 * 2. ../../vendor/seccomp/{arch}/apply-seccomp (package root - standard npm installs)
 * 3. ../vendor/seccomp/{arch}/apply-seccomp (dist/vendor - for bundlers)
 * 4. Global npm install (if seccompBinaryPath not provided) - for native builds
 *
 * @param seccompBinaryPath - Optional explicit path to the apply-seccomp binary. If provided
 *   and exists, it will be used. If not provided, falls back to searching local paths and
 *   then global npm install (for native builds where vendor directory isn't bundled).
 */
export declare function getApplySeccompBinaryPath(
  seccompBinaryPath?: string,
): string | null
//# sourceMappingURL=generate-seccomp-filter.d.ts.map
