import * as fs from 'node:fs'
import * as path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import { generateProxyEnvVars } from './sandbox-utils.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'

/**
 * Windows sandbox backend.
 *
 * Network isolation is enforced by `srt-win.exe` — a Rust helper that
 * manages a local discriminator group, a machine-wide WFP filter set
 * keyed on that group's SID, and an `exec` subcommand that spawns the
 * target under a restricted token (group flipped deny-only) inside a
 * hardened job. The sandboxed child reaches the host only via the JS
 * http/socks proxies, which `srt-win exec` points at via env vars.
 *
 * This module is a thin wrapper around the `srt-win` CLI; all status
 * comes from live enumeration (group via `LookupAccountNameW` +
 * token-membership check; WFP via providerData-tag enumeration under
 * the configured sublayer). There is no marker file.
 *
 * Filesystem restrictions are NOT enforced on Windows yet.
 */

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export const DEFAULT_WINDOWS_GROUP_NAME = 'sandbox-runtime-net'
export const DEFAULT_WINDOWS_PROXY_PORT_RANGE: readonly [number, number] = [
  60080, 60089,
]

/** Identifies the discriminator group either by name or by SID. */
export interface WindowsGroupRef {
  /** Local or domain group name. Default: `sandbox-runtime-net`. */
  groupName?: string
  /**
   * Group SID in `S-1-…` form. Takes precedence over `groupName` —
   * use for domain groups or where name resolution is unreliable.
   */
  groupSid?: string
}

export type WindowsGroupStatus = 'absent' | 'created-not-on-token' | 'ready'

export interface WindowsGroupStatusResult {
  state: WindowsGroupStatus
  sid?: string
  warning?: string
  error?: string
}

export type WindowsWfpStatus = 'absent' | 'installed'

export interface WindowsWfpStatusResult {
  state: WindowsWfpStatus
  filters: number
  /** `[low, high]` from the `permit-loopback` filter's tag, when present. */
  portRange?: [number, number]
}

export interface WindowsSandboxParams {
  command: string
  group: WindowsGroupRef
  /** JS HTTP proxy port — fed to `generateProxyEnvVars` for the returned env. */
  httpProxyPort?: number
  /** JS SOCKS proxy port — fed to `generateProxyEnvVars` for the returned env. */
  socksProxyPort?: number
  /**
   * Inner shell. `cmd` (default), `powershell`, or `pwsh`. The child's
   * post-`/c` content is **passthrough** — `&` chains, `"…"` quotes
   * exactly as written. The security boundary is at the OUTER spawn
   * (this argv is spawned with `shell:false`); the inner cmd.exe runs
   * INSIDE the sandbox so its metachars are the user's tool.
   */
  binShell?: string
}

// ────────────────────────────────────────────────────────────────────
// Binary resolution
// ────────────────────────────────────────────────────────────────────

function repoRoot(): string {
  // src/sandbox/windows-sandbox-utils.ts → repo root (compiled: dist/sandbox/…)
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '..', '..')
}

/**
 * Locate `srt-win.exe`. Resolution order:
 *   1. `SRT_WIN_PATH` env var (CI sets this to the freshly-built binary).
 *   2. `<repo>/vendor/srt-win/target/release/srt-win.exe` (local cargo build).
 *   3. `<repo>/dist/vendor/srt-win/target/release/srt-win.exe`
 *      (post-`npm run build` shape, when running from compiled output).
 *
 * Resolution via the optional `@anthropic-ai/sandbox-runtime-win32-*`
 * platform packages is added separately.
 *
 * @throws if none exist.
 */
export function getSrtWinPath(): string {
  const envPath = process.env.SRT_WIN_PATH
  if (envPath && fs.existsSync(envPath)) {
    return envPath
  }
  const root = repoRoot()
  const candidates = [
    path.join(root, 'vendor', 'srt-win', 'target', 'release', 'srt-win.exe'),
    path.join(
      root,
      'dist',
      'vendor',
      'srt-win',
      'target',
      'release',
      'srt-win.exe',
    ),
  ]
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  throw new Error(
    `srt-win.exe not found. Set SRT_WIN_PATH or build with ` +
      `\`cargo build --release --manifest-path vendor/srt-win/Cargo.toml\`. ` +
      `Looked in: ${[envPath, ...candidates].filter(Boolean).join(', ')}`,
  )
}

// ────────────────────────────────────────────────────────────────────
// Internal: spawn helpers
// ────────────────────────────────────────────────────────────────────

function groupRefArgs(ref: WindowsGroupRef): string[] {
  if (ref.groupSid) return ['--group-sid', ref.groupSid]
  return ['--name', ref.groupName ?? DEFAULT_WINDOWS_GROUP_NAME]
}

interface RunResult {
  status: number | null
  stdout: string
  stderr: string
}

function runSrtWin(args: string[]): RunResult {
  const exe = getSrtWinPath()
  const r = spawnSync(exe, args, { encoding: 'utf8', timeout: 15_000 })
  if (r.error) {
    throw new Error(`srt-win ${args[0]}: spawn failed: ${r.error.message}`)
  }
  return {
    status: r.status,
    stdout: (r.stdout ?? '').trim(),
    stderr: (r.stderr ?? '').trim(),
  }
}

function runSrtWinJson<T>(args: string[]): T {
  const r = runSrtWin(args)
  if (r.status !== 0) {
    throw new Error(
      `srt-win ${args.join(' ')} exited ${r.status}: ${r.stderr || r.stdout}`,
    )
  }
  // Status subcommands print exactly one line of JSON to stdout. stderr
  // may carry `srt-win:` diagnostics — ignore it for parsing.
  try {
    return JSON.parse(r.stdout) as T
  } catch (e) {
    throw new Error(
      `srt-win ${args.join(' ')}: unparseable JSON output ` +
        `${JSON.stringify(r.stdout)}: ${(e as Error).message}`,
    )
  }
}

// ────────────────────────────────────────────────────────────────────
// Status / install API
// ────────────────────────────────────────────────────────────────────

/**
 * Query the discriminator group's state in SAM and in the current
 * process's `TokenGroups`. `ready` means the group exists AND is
 * enabled in the caller's token (i.e. the logout/login dance has
 * happened). `created-not-on-token` means the install step ran but
 * a fresh logon is needed before {@link initialize} can succeed.
 */
export function getWindowsGroupStatus(
  ref: WindowsGroupRef,
): WindowsGroupStatusResult {
  return runSrtWinJson(['group', 'status', ...groupRefArgs(ref)])
}

/**
 * Query the WFP filter set under the given sublayer. `installed` means
 * srt-win-tagged `permit-group` AND `block` filters are both present
 * under that sublayer. Detection is **tag-based** (providerData JSON);
 * filters installed by other tooling without the tag are not counted.
 */
export function getWindowsWfpStatus(
  opts: { sublayerGuid?: string } = {},
): WindowsWfpStatusResult {
  const args = ['wfp', 'status']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  const raw = runSrtWinJson<{
    state: WindowsWfpStatus
    filters: number
    port_range?: [number, number]
  }>(args)
  return {
    state: raw.state,
    filters: raw.filters,
    ...(raw.port_range && { portRange: raw.port_range }),
  }
}

export interface WindowsInstallOptions extends WindowsGroupRef {
  /** Add this user (instead of the current user) to the group. */
  userSid?: string
  /** WFP sublayer GUID. Omit for srt-win's compile-time default. */
  sublayerGuid?: string
  /**
   * Loopback PERMIT port range. Must match what
   * `SandboxRuntimeConfig.windows.proxyPortRange` will be set to.
   * Default {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
   */
  proxyPortRange?: readonly [number, number]
  /**
   * Replace an existing install whose configuration differs
   * (different group SID or port range under the same sublayer).
   * Without this, install refuses with "already installed with
   * different config" rather than silently overwriting.
   */
  force?: boolean
}

export interface WindowsInstallResult {
  /** Post-install group state. */
  group: WindowsGroupStatusResult
  /** Post-install WFP state. */
  wfp: WindowsWfpStatusResult
  /**
   * `true` if the user dismissed the UAC prompt. Not an error —
   * the install simply didn't happen. Re-run when the user is
   * ready to grant elevation.
   */
  cancelled?: true
}

/**
 * One-shot install: creates the discriminator group, adds the
 * current user (or `userSid`), and installs the machine-wide WFP
 * filter set — all in a single self-elevating process (one UAC
 * prompt). Idempotent.
 *
 * Network for the calling user is **not disrupted** before the
 * required logout: while the group is absent from the token, WFP
 * filter-0 (PERMIT non-members) matches and traffic flows normally.
 * After log-out/log-in, the group is enabled in the token and
 * filter-1 (PERMIT group-enabled) takes over for the broker; only
 * `srt-win exec` children (group flipped deny-only) fall through to
 * the loopback/BLOCK filters.
 *
 * Returns the post-call group + WFP state. If the user cancels the
 * UAC prompt this returns `{cancelled: true, …}` rather than
 * throwing — cancellation is a user choice, not an error.
 *
 * @throws on group/WFP creation failure, or if filters already
 *   exist under `sublayerGuid` with different configuration and
 *   `force` is not set.
 */
export function installWindowsSandbox(
  opts: WindowsInstallOptions = {},
): WindowsInstallResult {
  const args = ['install', ...groupRefArgs(opts)]
  if (opts.userSid) args.push('--user-sid', opts.userSid)
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.proxyPortRange) {
    args.push(
      '--proxy-port-range',
      `${opts.proxyPortRange[0]}-${opts.proxyPortRange[1]}`,
    )
  }
  if (opts.force) args.push('--force')

  const r = runSrtWin(args)
  logForDebugging(
    `[Sandbox Windows] install exit=${r.status}: ${r.stderr || r.stdout}`,
  )

  // srt-win install exit-code contract:
  //   0  ok
  //   10 user cancelled UAC elevation
  //   11 group create failed
  //   12 WFP install failed
  //   13 already installed with different config (use --force)
  //   1  other error (stderr has detail)
  const out = r.stderr || r.stdout
  switch (r.status) {
    case 0:
      break
    case 10:
      return {
        group: getWindowsGroupStatus(opts),
        wfp: getWindowsWfpStatus({ sublayerGuid: opts.sublayerGuid }),
        cancelled: true,
      }
    case 11:
      throw new Error(`srt-win install: group create failed: ${out}`)
    case 12:
      throw new Error(`srt-win install: WFP filter install failed: ${out}`)
    case 13:
      throw new Error(
        `srt-win install: filters already exist under this sublayer with ` +
          `different configuration (group SID or port range). ` +
          `Pass {force: true} to replace, or pick a different sublayerGuid. ` +
          `Output: ${out}`,
      )
    default:
      throw new Error(`srt-win install failed (exit ${r.status}): ${out}`)
  }

  return {
    group: getWindowsGroupStatus(opts),
    wfp: getWindowsWfpStatus({ sublayerGuid: opts.sublayerGuid }),
  }
}

/**
 * Remove the WFP filter set under `sublayerGuid` (one UAC prompt).
 * Idempotent.
 *
 * **Does NOT delete the discriminator group** — group membership is
 * persistent user state and removing it would force every user to
 * re-do the logout dance on the next install. Call
 * {@link deleteWindowsGroup} explicitly if you want full teardown.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
export function uninstallWindowsSandbox(opts: { sublayerGuid?: string } = {}): {
  cancelled?: true
} {
  const args = ['uninstall']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  const r = runSrtWin(args)
  logForDebugging(
    `[Sandbox Windows] uninstall exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status === 10) return { cancelled: true }
  if (r.status !== 0) {
    throw new Error(
      `srt-win uninstall failed (exit ${r.status}): ${r.stderr || r.stdout}`,
    )
  }
  return {}
}

/**
 * Delete the discriminator group. Separate from
 * {@link uninstallWindowsSandbox} so that uninstall→reinstall
 * doesn't force a fresh logout for every member. **Requires
 * elevation.** Idempotent (no-op if the group doesn't exist).
 */
export function deleteWindowsGroup(ref: WindowsGroupRef): void {
  const r = runSrtWin(['group', 'delete', ...groupRefArgs(ref)])
  if (r.status !== 0) {
    throw new Error(
      `srt-win group delete failed (exit ${r.status}). ` +
        `Requires elevation. Output: ${r.stderr || r.stdout}`,
    )
  }
  logForDebugging(`[Sandbox Windows] group delete: ${r.stderr || r.stdout}`)
}

/**
 * Granular primitive: create the discriminator group and add the
 * current user (or `userSid`). Most callers should use
 * {@link installWindowsSandbox} instead; this exists for
 * enterprise/CI flows that manage group and WFP separately.
 * **Requires elevation.** Idempotent.
 */
export function createWindowsGroup(
  ref: WindowsGroupRef & { userSid?: string },
): void {
  const args = ['group', 'create', ...groupRefArgs(ref)]
  if (ref.userSid) args.push('--user-sid', ref.userSid)
  const r = runSrtWin(args)
  if (r.status !== 0) {
    throw new Error(
      `srt-win group create failed (exit ${r.status}). ` +
        `This requires elevation — run as administrator. ` +
        `Output: ${r.stderr || r.stdout}`,
    )
  }
  logForDebugging(`[Sandbox Windows] group create: ${r.stderr || r.stdout}`)
}

/**
 * Granular primitive: install the machine-wide WFP filter set
 * under `sublayerGuid` keyed on the group SID. Most callers should
 * use {@link installWindowsSandbox} instead; this exists for
 * enterprise/CI flows that manage group and WFP separately.
 * **Requires elevation.** Idempotent — re-running replaces any
 * existing srt-win-tagged filters under that sublayer.
 */
export function createWindowsWfp(
  ref: WindowsGroupRef & {
    sublayerGuid?: string
    proxyPortRange?: readonly [number, number]
  },
): void {
  const args = ['wfp', 'install', ...groupRefArgs(ref)]
  if (ref.sublayerGuid) args.push('--sublayer-guid', ref.sublayerGuid)
  if (ref.proxyPortRange) {
    args.push(
      '--proxy-port-range',
      `${ref.proxyPortRange[0]}-${ref.proxyPortRange[1]}`,
    )
  }
  const r = runSrtWin(args)
  if (r.status !== 0) {
    throw new Error(
      `srt-win wfp install failed (exit ${r.status}). ` +
        `This requires elevation — run as administrator. ` +
        `Output: ${r.stderr || r.stdout}`,
    )
  }
  logForDebugging(`[Sandbox Windows] wfp install: ${r.stderr || r.stdout}`)
}

// ────────────────────────────────────────────────────────────────────
// Wrap
// ────────────────────────────────────────────────────────────────────

/**
 * Build the spawn descriptor for running `command` inside the Windows
 * sandbox: an `argv` array plus the `env` to spawn it with.
 *
 * Caller MUST spawn the result with `{shell: false}` — that is the
 * security boundary that keeps untrusted bytes off the host's shell
 * (the inner `cmd.exe /c` runs INSIDE the sandbox; see
 * `vendor/srt-win/src/launch.rs` `build_cmdline` for the passthrough
 * rationale) — AND with the returned `env`.
 *
 * Proxy configuration is single-sourced by {@link generateProxyEnvVars}
 * (the same canonical builder used on macOS/Linux). `srt-win exec`
 * takes no `--http-proxy` / `--socks-proxy` flags and synthesizes no
 * proxy env; it forwards its own environment to the sandboxed child
 * verbatim. So the full proxy set is merged over the broker's
 * environment here and the child inherits it through the spawn.
 */
export function wrapCommandWithSandboxWindows(p: WindowsSandboxParams): {
  argv: string[]
  env: NodeJS.ProcessEnv
} {
  const exe = getSrtWinPath()
  const argv: string[] = [exe, 'exec', ...groupRefArgs(p.group)]
  argv.push('--')

  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const shell = (p.binShell ?? 'cmd').toLowerCase()
  if (shell === 'pwsh' || shell.includes('powershell')) {
    const psExe =
      shell === 'pwsh'
        ? 'pwsh.exe'
        : path.join(
            systemRoot,
            'System32',
            'WindowsPowerShell',
            'v1.0',
            'powershell.exe',
          )
    argv.push(psExe, '-NoProfile', '-Command', p.command)
  } else {
    // cmd /d (no AutoRun) /s (strip first+last quote of post-/c by
    // position) /c (run-then-exit). The `command` string lands as a
    // single argv element; srt-win's build_cmdline wraps it in one
    // outer "…" pair for /s to consume. See launch.rs.
    argv.push(
      path.join(systemRoot, 'System32', 'cmd.exe'),
      '/d',
      '/s',
      '/c',
      p.command,
    )
  }

  // Generated proxy vars override any inherited ones so the child
  // always routes through this sandbox's proxies.
  const generated = envListToObject(
    generateProxyEnvVars(p.httpProxyPort, p.socksProxyPort),
  )
  // TMPDIR is a POSIX path meant for the macOS/Linux FS sandbox — it
  // serves no purpose on Windows and breaks msys2 tools (mktemp etc.).
  delete generated.TMPDIR
  const env: NodeJS.ProcessEnv = { ...process.env, ...generated }
  return { argv, env }
}

/**
 * Parse a list of `KEY=VALUE` strings (as produced by
 * {@link generateProxyEnvVars}) into an object. Splits on the FIRST
 * `=` only, so values containing `=` survive intact.
 */
function envListToObject(list: string[]): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {}
  for (const entry of list) {
    const eq = entry.indexOf('=')
    if (eq === -1) continue
    out[entry.slice(0, eq)] = entry.slice(eq + 1)
  }
  return out
}

// ────────────────────────────────────────────────────────────────────
// Dependency / readiness check
// ────────────────────────────────────────────────────────────────────

/**
 * Install instructions, surfaced verbatim in error messages.
 * Tailored to the observed group state: if the install already
 * ran (`created-not-on-token`), only the logout is missing.
 */
export function windowsInstallInstructions(
  ref: WindowsGroupRef,
  sublayerGuid: string | undefined,
  groupState: WindowsGroupStatus,
): string {
  if (groupState === 'created-not-on-token') {
    return (
      `The discriminator group exists but is not yet in this session's ` +
      `token. LOG OUT and back in to pick up the new group membership ` +
      `(it enters TokenGroups at logon). Network is not disrupted ` +
      `meanwhile — WFP filter-0 PERMITs traffic while the group is absent ` +
      `from your token.`
    )
  }
  const g = ref.groupSid
    ? `--group-sid ${ref.groupSid}`
    : `--name ${ref.groupName ?? DEFAULT_WINDOWS_GROUP_NAME}`
  const sl = sublayerGuid ? ` --sublayer-guid ${sublayerGuid}` : ''
  return (
    `Windows sandbox needs a one-time install (one UAC prompt):\n` +
    `  npx sandbox-runtime windows-install\n` +
    `  — or call installWindowsSandbox(), or run ` +
    `\`srt-win.exe install ${g}${sl}\` directly —\n` +
    `then LOG OUT and back in (the group SID enters TokenGroups at logon).\n` +
    `Network is not disrupted before the logout: while the group is absent ` +
    `from your token, WFP filter-0 PERMITs all traffic.`
  )
}

/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 */
export function checkWindowsDependencies(
  ref: WindowsGroupRef,
  sublayerGuid?: string,
): SandboxDependencyCheck {
  const errors: string[] = []
  const warnings: string[] = []

  // 1. Binary present.
  let exe: string
  try {
    exe = getSrtWinPath()
  } catch (e) {
    return { errors: [(e as Error).message], warnings }
  }
  logForDebugging(`[Sandbox Windows] using srt-win at ${exe}`)

  // 2. Group ready (exists AND enabled in the caller's token).
  let gs: WindowsGroupStatusResult
  try {
    gs = getWindowsGroupStatus(ref)
  } catch (e) {
    errors.push(`srt-win group status failed: ${(e as Error).message}`)
    return { errors, warnings }
  }
  if (gs.state !== 'ready') {
    errors.push(
      `Discriminator group is ${gs.state}` +
        (gs.sid ? ` (sid=${gs.sid})` : '') +
        `. ` +
        windowsInstallInstructions(ref, sublayerGuid, gs.state),
    )
  }
  if (gs.warning) warnings.push(gs.warning)

  // 3. WFP filters installed under the sublayer.
  let ws: WindowsWfpStatusResult
  try {
    ws = getWindowsWfpStatus({ sublayerGuid })
  } catch (e) {
    errors.push(`srt-win wfp status failed: ${(e as Error).message}`)
    return { errors, warnings }
  }
  if (ws.state !== 'installed') {
    // If the group is also not-ready, the group-state error above
    // already gave the right instruction; don't repeat. Only
    // surface a separate WFP error when group IS ready (i.e.
    // someone uninstalled filters but kept the group).
    if (gs.state === 'ready') {
      errors.push(
        `WFP filters not installed under sublayer ` +
          `${sublayerGuid ?? '(default)'}. ` +
          windowsInstallInstructions(ref, sublayerGuid, 'absent'),
      )
    }
  } else if (ws.portRange) {
    logForDebugging(
      `[Sandbox Windows] WFP installed: ${ws.filters} filters, ` +
        `proxy port range ${ws.portRange[0]}-${ws.portRange[1]}`,
    )
  }

  return { errors, warnings }
}
