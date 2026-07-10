/**
 * Host-side plumbing for the macOS credential-mask DYLD interposer
 * (vendor/credmask-src/interpose.c).
 *
 * On Linux, `mode: "mask"` files are bind-mounted over by their fakes;
 * macOS Seatbelt cannot redirect reads, only deny them. The interposer
 * lifts that degrade-to-deny for COOPERATIVE processes: injected via
 * DYLD_INSERT_LIBRARIES, it rewrites file-path libc calls whose path
 * matches a masked real path to hit the sentinel-content fake instead.
 *
 * SECURITY MODEL: the SBPL `(deny file-read*)` on the real path stays in
 * force and remains the security boundary. The interposer is a
 * compatibility shim only — SIP-protected binaries (dyld strips DYLD_*
 * at load), static syscalls, or a process that clears the env var simply
 * fall through to the deny and get EPERM. Fail-closed for the
 * credential, fail-open for the process.
 *
 * This module owns the two host-side pieces:
 *  - resolving the built dylib (mirrors the apply-seccomp resolver), and
 *  - encoding the realPath→fakePath map into the CREDMASK_MAP env var.
 */

import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as fs from 'node:fs'
import { logForDebugging } from '../utils/debug.js'
import { getGlobalNpmPaths } from './generate-seccomp-filter.js'
import type { MaskedFileBind } from './credential-mask-files.js'

/** Env var the interposer reads its realPath→fakePath map from. */
export const CREDMASK_MAP_ENV = 'CREDMASK_MAP'

/**
 * CREDMASK_MAP wire format: `real \x1f fake` pairs joined by `\x1e`.
 * ASCII unit/record separators — never present in the fake paths srt
 * generates and absent from any sane credential path, so no escaping
 * layer is needed. Must match FIELD_SEP / ENTRY_SEP in
 * vendor/credmask-src/interpose.c.
 */
export const CREDMASK_FIELD_SEP = '\x1f'
export const CREDMASK_ENTRY_SEP = '\x1e'

/**
 * Encode masked-file binds for the interposer. Entries containing a
 * separator byte or NUL in either path are skipped (they cannot be
 * represented, and env vars cannot carry NUL) — the skipped file simply
 * stays SBPL-denied, so the failure mode is fail-closed.
 */
export function encodeCredmaskMap(binds: readonly MaskedFileBind[]): string {
  const encodable: string[] = []
  for (const b of binds) {
    const unencodable = [CREDMASK_FIELD_SEP, CREDMASK_ENTRY_SEP, '\x00'].some(
      c => b.realPath.includes(c) || b.fakePath.includes(c),
    )
    if (unencodable) {
      logForDebugging(
        `[credmask] Skipping unencodable masked-file path (contains a ` +
          `separator byte); the file stays read-denied: ${b.realPath}`,
        { level: 'warn' },
      )
      continue
    }
    encodable.push(b.realPath + CREDMASK_FIELD_SEP + b.fakePath)
  }
  return encodable.join(CREDMASK_ENTRY_SEP)
}

// Cache for dylib lookups (key: explicit path or empty string).
const credmaskDylibPathCache = new Map<string, string | null>()

/**
 * Local candidate paths for the dylib, mirroring the apply-seccomp
 * resolver's layout logic. The dylib is universal (arm64 + x86_64), so
 * unlike seccomp there is no per-arch directory.
 */
function getLocalCredmaskPaths(): string[] {
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const relativePath = join('vendor', 'credmask', 'libcredmask.dylib')
  return [
    join(baseDir, relativePath), // bundled: same directory as bundle
    join(baseDir, '..', '..', relativePath), // package root
    join(baseDir, '..', relativePath), // dist/vendor
  ]
}

/**
 * Resolve the built libcredmask.dylib, or null when it isn't available
 * (source checkout without `npm run build:credmask`, non-mac install,
 * …). Callers treat null as "keep today's degrade-to-deny behaviour".
 *
 * @param explicitPath - Optional explicit dylib path; used if it exists
 *   (test/native-build override), otherwise falls back to the standard
 *   package locations and the global npm install.
 */
export function getCredmaskDylibPath(explicitPath?: string): string | null {
  const cacheKey = explicitPath ?? ''
  const cached = credmaskDylibPathCache.get(cacheKey)
  if (cached !== undefined) {
    return cached
  }
  const result = findCredmaskDylibPath(explicitPath)
  credmaskDylibPathCache.set(cacheKey, result)
  return result
}

function findCredmaskDylibPath(explicitPath?: string): string | null {
  if (explicitPath) {
    if (fs.existsSync(explicitPath)) {
      logForDebugging(
        `[credmask] Using dylib from explicit path: ${explicitPath}`,
      )
      return explicitPath
    }
    logForDebugging(
      `[credmask] Explicit dylib path provided but not found: ${explicitPath}`,
    )
  }

  for (const p of getLocalCredmaskPaths()) {
    if (fs.existsSync(p)) {
      logForDebugging(`[credmask] Found dylib: ${p}`)
      return p
    }
  }

  for (const globalBase of getGlobalNpmPaths()) {
    const p = join(globalBase, 'vendor', 'credmask', 'libcredmask.dylib')
    if (fs.existsSync(p)) {
      logForDebugging(`[credmask] Found dylib in global install: ${p}`)
      return p
    }
  }

  logForDebugging('[credmask] libcredmask.dylib not found in any location')
  return null
}
