/**
 * Resolve the vendored `srt-launcher` helper binary.
 *
 * srt-launcher is the single Linux-side native helper. It replaces what were
 * previously three external binaries (bwrap, socat, apply-seccomp) with three
 * subcommands of one statically-linked binary:
 *
 *   run [opts] -- CMD     namespaces + mounts + relay forks + seccomp + exec
 *   relay SOCK HOST:PORT  host-side bridge to an external proxy (only used
 *                         when network.{http,socks}ProxyPort is configured)
 *   connect HOST PORT     ssh ProxyCommand HTTP CONNECT helper (in-sandbox)
 *
 * The binary is built from vendor/srt-launcher-rs/ by `npm run build:launcher`
 * and shipped under vendor/srt-launcher/{x64,arm64}/srt-launcher.
 */

import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as fs from 'node:fs'
import { execFileSync } from 'node:child_process'
import { homedir } from 'node:os'
import { logForDebugging } from '../utils/debug.js'
import type { LauncherConfig } from './sandbox-config.js'

let cachedPath: string | null | undefined
let cachedGlobalNpmRoots: string[] | null = null

/** Map process.arch to the vendor directory name. */
function vendorArch(): 'x64' | 'arm64' | null {
  switch (process.arch as string) {
    case 'x64':
    case 'x86_64':
      return 'x64'
    case 'arm64':
    case 'aarch64':
      return 'arm64'
    case 'ia32':
    case 'x86':
      // The seccomp filter only blocks socket(AF_UNIX, ...). 32-bit x86
      // multiplexes all socket ops through socketcall(), bypassing it.
      logForDebugging(
        '[srt-launcher] 32-bit x86 is unsupported (socketcall() seccomp bypass)',
        { level: 'error' },
      )
      return null
    default:
      logForDebugging(`[srt-launcher] unsupported arch: ${process.arch}`)
      return null
  }
}

function isExecutable(p: string): boolean {
  try {
    fs.accessSync(p, fs.constants.X_OK)
    return true
  } catch {
    return false
  }
}

function globalNpmRoots(): string[] {
  if (cachedGlobalNpmRoots) return cachedGlobalNpmRoots
  const roots: string[] = []
  try {
    const npmRoot = execFileSync('npm', ['root', '-g'], {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'ignore'],
    }).trim()
    if (npmRoot) roots.push(join(npmRoot, '@anthropic-ai', 'sandbox-runtime'))
  } catch {
    // npm not available
  }
  const home = homedir()
  roots.push(
    join('/usr', 'lib', 'node_modules', '@anthropic-ai', 'sandbox-runtime'),
    join(
      '/usr',
      'local',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
    join(
      home,
      '.npm-global',
      'lib',
      'node_modules',
      '@anthropic-ai',
      'sandbox-runtime',
    ),
  )
  cachedGlobalNpmRoots = roots
  return roots
}

/**
 * Resolve the srt-launcher binary on disk.
 *
 * Search order:
 *   1. `cfg.path` if provided (must exist and be executable, or null is
 *      returned — an explicit override that doesn't resolve is an error,
 *      not a hint to fall back).
 *   2. Bundled next to this module (the npm-package layout).
 *   3. Global npm install of @anthropic-ai/sandbox-runtime as a fallback for
 *      embedders that strip the vendor directory from their bundle.
 *
 * `cfg.argv0` is the multicall escape hatch: when srt-launcher is compiled
 * into a larger binary, set `path` to that binary and `argv0` to
 * `"srt-launcher"`. The dispatch happens in srt-launcher's main() via the
 * ARGV0 env var. In that mode this function trusts `path` without an
 * existence check (it may be /proc/self/exe or similar).
 */
export function getSrtLauncherPath(cfg?: LauncherConfig): string | null {
  // The schema enforces this too, but this function is exported and may be
  // called with a hand-built object. A relative path resolving via CWD or
  // PATH would be a sandbox-bypass-class footgun.
  if (cfg?.path && !cfg.path.startsWith('/')) {
    throw new Error('launcher.path must be an absolute path')
  }
  if (cfg?.argv0) {
    if (!cfg.path) {
      throw new Error('launcher.argv0 requires launcher.path')
    }
    return cfg.path
  }
  if (cfg?.path) {
    return isExecutable(cfg.path) ? cfg.path : null
  }
  if (cachedPath !== undefined) return cachedPath

  const arch = vendorArch()
  if (!arch) {
    cachedPath = null
    return null
  }
  const rel = join('vendor', 'srt-launcher', arch, 'srt-launcher')
  const here = dirname(fileURLToPath(import.meta.url))
  const candidates = [
    join(here, rel), // bundled: same directory as bundle
    join(here, '..', '..', rel), // package root: vendor/srt-launcher/...
    join(here, '..', rel), // dist: dist/vendor/srt-launcher/...
    ...globalNpmRoots().map(r => join(r, rel)),
    ...globalNpmRoots().map(r => join(r, 'dist', rel)),
  ]
  for (const p of candidates) {
    if (isExecutable(p)) {
      cachedPath = p
      logForDebugging(`[srt-launcher] resolved binary: ${p}`)
      return p
    }
  }
  cachedPath = null
  return null
}

/**
 * Build the argv prefix to invoke srt-launcher (or one of its subcommands).
 * Returns the argv array; callers append the rest of the argv themselves.
 *
 * In multicall mode this is `["ARGV0=srt-launcher", path, sub?]` for use as a
 * shell prefix; otherwise it's `[path, sub?]`. Callers that build a single
 * shell string should `shellquote.quote()` the result; callers that pass argv
 * to spawn() use the array directly and prepend `env: { ARGV0: ... }` instead
 * of the env-string element.
 */
export function getSrtLauncherInvocation(
  cfg: LauncherConfig | undefined,
  subcommand?: 'run' | 'relay' | 'connect',
): { argv: string[]; env: Record<string, string> } | null {
  const path = getSrtLauncherPath(cfg)
  if (!path) return null
  const env: Record<string, string> = {}
  if (cfg?.argv0) env.ARGV0 = cfg.argv0
  const argv = subcommand ? [path, subcommand] : [path]
  return { argv, env }
}

/** Reset module-level caches (test helper). */
export function _resetSrtLauncherCache(): void {
  cachedPath = undefined
  cachedGlobalNpmRoots = null
}
