import * as fs from 'node:fs'
import * as net from 'node:net'
import * as path from 'node:path'
import { spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import {
  containsGlobCharsWin,
  expandGlobPattern,
  generateProxyEnvVars,
  normalizePathForSandbox,
} from './sandbox-utils.js'
// Re-export so existing tests (glob-expand.test.ts) and any
// out-of-tree caller keep their import path.
export {
  containsGlobCharsWin,
  stripExtendedPathPrefix,
} from './sandbox-utils.js'
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
 * Filesystem deny (`denyRead`/`denyWrite`) is enforced via
 * `srt-win acl stamp` at session start: a broker-only DACL is
 * applied to each listed file plus a `Modify`-minus-`FILE_DELETE_CHILD`
 * allow-list on its immediate parent directory, with restore state
 * sealed by an inert hash-ACE marker so the on-disk SD is
 * self-authenticating. See {@link stampWindowsAcl}.
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

export type WindowsWfpStatus = 'absent' | 'installed' | 'cannot-read'

export interface WindowsWfpStatusResult {
  state: WindowsWfpStatus
  filters: number
  /** `[low, high]` from the `permit-loopback` filter's tag, when present. */
  portRange?: [number, number]
  /**
   * Number of user-SID-keyed filters present (subset of `filters`).
   * Zero on installs that predate the sandbox-user provisioning
   * step, or when only `wfp install` (group set) was run.
   */
  userFilters: number
  /** Sandbox-user SID read from the first user-keyed filter tag. */
  userSid?: string
  /**
   * Populated only on `cannot-read` (BFE enumeration is admin-gated;
   * a non-elevated caller can't read it). The non-elevated readiness
   * check is {@link verifyWindowsWfpEgress}, not this enum.
   */
  hint?: string
}

/**
 * Result of `srt-win wfp verify` on success (exit 0, `blocked`) —
 * see {@link verifyWindowsWfpEgress}. Any other outcome throws, so
 * the tri-state is unobservable on the return path.
 */
export interface WindowsWfpVerifyResult {
  target: string
  /** Runner's stderr (carries the `BLOCKED (…)` diagnostic line). */
  stderr: string
}

/**
 * State of the `srt-sandbox` local account that `srt-win install`
 * provisions. The sandboxed child eventually runs **as** this
 * account; for now it is reported alongside the group/WFP status
 * so callers can surface a "re-run install" diagnostic when the
 * account is missing.
 */
export interface WindowsSandboxUserStatus {
  /** The `srt-sandbox` local account exists. */
  provisioned: boolean
  /** `S-1-5-21-…` of `srt-sandbox`, when provisioned. */
  sid?: string
  /** The `sandbox-runtime-users` local group exists. */
  groupExists: boolean
  /** `S-1-5-21-…` of `sandbox-runtime-users`, when it exists. */
  groupSid?: string
  inBuiltinUsers: boolean
  inSandboxGroup: boolean
  hiddenFromLogon: boolean
  /**
   * The credential row is present in `state.db` and readable by
   * THIS process. False when not yet written, or when called from
   * inside the sandbox (the state-DB directory carries an explicit
   * DENY for `sandbox-runtime-users` — machine-scope DPAPI alone
   * is not a confidentiality boundary).
   */
  credPresent: boolean
  /** Setup marker schema version, when the marker row exists. */
  markerVersion?: number
  /**
   * The calling (real) user's SID — the trustee for `acl stamp`
   * under the separate-user model. Always present.
   */
  realUserSid: string
  /**
   * SHA-1 thumbprint of the install-time CA, when one was
   * installed via `srt-win user trust-ca`. Uppercase hex.
   */
  caCertThumb?: string
  /** PEM-encoded install-time CA certificate, when present. */
  caCertPem?: string
}

/**
 * Inner shell to run `command` under, inside the restricted-token
 * sandbox. The discriminant picks both the executable and the flag
 * shape (`/c` vs `-Command` vs `-c`); see
 * {@link wrapCommandWithSandboxWindows}.
 *
 * For `kind: 'bash'`, `path` is the absolute Git Bash executable
 * (no fixed install location). It MUST originate from trusted host
 * configuration (user settings / install detection), NEVER from
 * workspace or repository content — the inner shell runs INSIDE the
 * restricted-token sandbox so an unexpected path is not a
 * sandbox-escape vector, but it would still be an arbitrary-exec
 * footgun if sourced from untrusted input.
 */
export type WindowsBinShell =
  | { kind: 'cmd' }
  | { kind: 'powershell' }
  | { kind: 'pwsh' }
  | { kind: 'bash'; path: string }

/**
 * Adapter from the cross-platform `binShell?: string` surface
 * ({@link SandboxManager.wrapWithSandboxArgv}) to the Windows
 * discriminated union. Throws on any value outside the recognised
 * set — there is no silent fallback to cmd.exe.
 *
 * Uses `path.win32` explicitly so the function (and its unit test)
 * is platform-independent.
 */
export function parseWindowsBinShell(raw?: string): WindowsBinShell {
  if (raw === undefined) return { kind: 'cmd' }
  // bash/sh: path semantics — match on basename, keep the caller's
  // absolute path verbatim.
  const base = path.win32.basename(raw).toLowerCase()
  if (
    base === 'bash' ||
    base === 'bash.exe' ||
    base === 'sh' ||
    base === 'sh.exe'
  ) {
    if (!path.win32.isAbsolute(raw)) {
      throw new Error(
        `binShell bash path must be absolute (got ${JSON.stringify(raw)}); ` +
          `pass the resolved Git Bash install path`,
      )
    }
    return { kind: 'bash', path: raw }
  }
  // cmd/powershell/pwsh: token semantics — match on the FULL string,
  // not basename, so an absolute path to pwsh.exe (whose path we'd
  // otherwise discard) falls through to the explicit throw rather
  // than silently degrading to a PATH lookup.
  switch (raw.toLowerCase()) {
    case 'pwsh':
    case 'pwsh.exe':
      return { kind: 'pwsh' }
    case 'powershell':
    case 'powershell.exe':
      return { kind: 'powershell' }
    case 'cmd':
    case 'cmd.exe':
      return { kind: 'cmd' }
    default:
      throw new Error(
        `unrecognised binShell ${JSON.stringify(raw)}: expected ` +
          `'cmd' | 'powershell' | 'pwsh' or an absolute path to bash.exe/sh.exe`,
      )
  }
}

export interface WindowsSandboxParams {
  command: string
  group: WindowsGroupRef
  /** JS HTTP proxy port — fed to `generateProxyEnvVars` for the returned env. */
  httpProxyPort?: number
  /** JS SOCKS proxy port — fed to `generateProxyEnvVars` for the returned env. */
  socksProxyPort?: number
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  proxyAuthToken?: string
  /**
   * Credential env vars to drop from the inherited environment
   * (`mode: 'deny'`). Applied BEFORE the proxy assignments so the
   * sandbox's own proxy plumbing survives even if a caller lists
   * one of those names here — same precedence as the macOS/Linux
   * `env -u … VAR=… sandbox-exec` order.
   */
  unsetEnvVars?: readonly string[]
  /**
   * Credential env vars to overwrite with a sentinel
   * (`mode: 'mask'`). Applied BEFORE the proxy assignments for the
   * same precedence reason as {@link unsetEnvVars}.
   */
  setEnvVars?: Readonly<Record<string, string>>
  /**
   * PID of the long-lived host whose `srt-win acl stamp` holds
   * this exec should run under. When set, `srt-win exec` opens a
   * no-`FILE_SHARE_DELETE` handle on each of that holder's stamped
   * directories and fenced files before spawning the child — the
   * OS then refuses delete/rename of those, which the file's DACL
   * alone cannot prevent. Omit for an exec with no file-deny
   * session active.
   */
  holderPid?: number
  /**
   * Per-exec read-deny paths, stamped under the `srt-win exec`
   * process's own PID and restored after the child exits. Same
   * disk-first chokepoint as the session-level
   * {@link stampWindowsAcl}; same fail-closed semantics (exec
   * fails if any path cannot be stamped).
   *
   * Normalized concrete paths — globs expanded by the caller via
   * {@link expandWindowsFsDenyPaths}, the same as session-level.
   * `srt-win exec`'s `canonicalize_deny_targets` hard-fails on a
   * glob (it never expands), so a `*`/`?` reaching this field is
   * a caller bug.
   */
  denyRead?: readonly string[]
  /** Per-exec write-deny paths — see {@link denyRead}. */
  denyWrite?: readonly string[]
  /**
   * Run the child as the dedicated `srt-sandbox` user via the
   * two-hop launch (broker → `CreateProcessWithLogonW(runner)` →
   * runner → restricted-token child). Requires `srt-win install` to
   * have provisioned the sandbox user. Opt-in — when `false` or
   * omitted the same-user deny-only-group path is used. The
   * separate-user path structurally closes the surrogate-spawn
   * class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
   * RunAs="Interactive User" COM): the child's token carries a
   * different user SID, so it cannot reach real-user processes,
   * tasks register under `srt-sandbox`, and the user-SID WFP filter
   * fences `srt-sandbox` egress regardless of how the child was
   * spawned.
   */
  asSandboxUser?: boolean
  /**
   * PEM-encoded CA certificate file. Same parameter macOS/Linux
   * thread to {@link generateProxyEnvVars} for the env-var trust
   * layer (`NODE_EXTRA_CA_CERTS` etc.). NOT passed to `srt-win
   * exec` — schannel-level trust under the sandbox user is set
   * separately via `srt-win user trust-ca` /
   * {@link windowsTrustCa}; per-exec only sets the env-var layer.
   *
   * **Under {@link asSandboxUser}**, this is currently NOT
   * forwarded to the child: the bundle file lives in the broker's
   * `%TEMP%`, which the `srt-sandbox` user cannot read, so OpenSSL
   * clients (msys2 curl, openssl-backed git, node, python) would
   * fail with `ACCESS_DENIED` on the bundle. The schannel-level
   * trust set via {@link windowsTrustCa} is the only CA-trust path
   * for the two-hop launch until working-tree/profile grants land.
   */
  caCertPath?: string
  /**
   * Inner shell. Defaults to `{ kind: 'cmd' }`. The child's post-`/c`
   * (or `-Command` / `-c`) content is **passthrough** — `&` chains,
   * `"…"`/`'…'` quotes exactly as written. The security boundary is at
   * the OUTER spawn (this argv is spawned with `shell:false`); the
   * inner shell runs INSIDE the sandbox so its metachars are the
   * user's tool. See {@link parseWindowsBinShell} for the
   * cross-platform string adapter.
   */
  binShell?: WindowsBinShell
}

// ────────────────────────────────────────────────────────────────────
// Binary resolution
// ────────────────────────────────────────────────────────────────────

function repoRoot(): string {
  // src/sandbox/windows-sandbox-utils.ts → repo root (compiled: dist/sandbox/…)
  const here = path.dirname(fileURLToPath(import.meta.url))
  return path.resolve(here, '..', '..')
}

const nodeArchToDir: Record<string, string> = { x64: 'x64', arm64: 'arm64' }

/**
 * Locate `srt-win.exe`. Resolution order:
 *   1. `SRT_WIN_PATH` env var (CI sets this to the freshly-built binary).
 *   2. `<root>/vendor/srt-win/{arch}/srt-win.exe` (prebuilt — published npm
 *      package, or after `npm run build:srt-win` locally).
 *   3. `<root>/vendor/srt-win-src/target/release/srt-win.exe` (local
 *      `cargo build --release` fallback for development).
 *   4. `<root>/vendor/srt-win/target/release/srt-win.exe` (transitional:
 *      stale local build from before the srt-win-src rename).
 *
 * `<root>` is {@link repoRoot} — `__dirname/../..`, which resolves to the
 * repo root from `src/sandbox/` and `dist/sandbox/` alike, and to the
 * package root when installed under `node_modules`.
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
  const arch = nodeArchToDir[process.arch]
  const candidates: string[] = []
  if (arch) {
    candidates.push(path.join(root, 'vendor', 'srt-win', arch, 'srt-win.exe'))
  }
  candidates.push(
    path.join(
      root,
      'vendor',
      'srt-win-src',
      'target',
      'release',
      'srt-win.exe',
    ),
    // transitional: stale local build from before the srt-win-src rename
    path.join(root, 'vendor', 'srt-win', 'target', 'release', 'srt-win.exe'),
  )
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  throw new Error(
    `srt-win.exe not found. Set SRT_WIN_PATH or build with ` +
      `\`cargo build --release --manifest-path vendor/srt-win-src/Cargo.toml\`. ` +
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

function runSrtWin(
  args: string[],
  stdin?: string,
  timeoutMs = 15_000,
): RunResult {
  const exe = getSrtWinPath()
  const r = spawnSync(exe, args, {
    encoding: 'utf8',
    timeout: timeoutMs,
    ...(stdin !== undefined && { input: stdin }),
  })
  if (r.error) {
    throw new Error(`srt-win ${args[0]}: spawn failed: ${r.error.message}`)
  }
  return {
    status: r.status,
    stdout: (r.stdout ?? '').trim(),
    stderr: (r.stderr ?? '').trim(),
  }
}

// Default: throw on exit≠0 (fail-safe). The one caller that needs
// the JSON despite a non-zero exit (`acl restore --json`, which
// prints per-path outcomes and THEN errors when any path stayed
// stamped) opts in via `allowNonZero: true` and gets the
// `{ok, json, stderr}` shape. Status callers stay one-liners and
// cannot regress to silently treating exit≠0 as success.
function runSrtWinJson<T>(args: string[], opts?: { timeoutMs?: number }): T
function runSrtWinJson<T>(
  args: string[],
  opts: { timeoutMs?: number; allowNonZero: true },
): { ok: boolean; json: T; stderr: string }
function runSrtWinJson<T>(
  args: string[],
  opts?: { timeoutMs?: number; allowNonZero?: boolean },
): T | { ok: boolean; json: T; stderr: string } {
  const r = runSrtWin(args, undefined, opts?.timeoutMs)
  // Parse stdout BEFORE the exit-code check so `allowNonZero`
  // can hand back the JSON on exit≠0. JSON.parse never returns
  // `undefined`, so `json !== undefined` ⇔ parse succeeded.
  let json: T | undefined
  let parseErr: string | undefined
  try {
    json = JSON.parse(r.stdout) as T
  } catch (e) {
    parseErr = (e as Error).message
  }
  if (opts?.allowNonZero && json !== undefined) {
    return { ok: r.status === 0, json, stderr: r.stderr }
  }
  if (r.status !== 0) {
    throw new Error(
      `srt-win ${args.join(' ')} exited ${r.status}: ${r.stderr || r.stdout}`,
    )
  }
  if (json !== undefined) return json
  throw new Error(
    `srt-win ${args.join(' ')}: unparseable JSON output ` +
      `${JSON.stringify(r.stdout)}: ${parseErr}`,
  )
}

export function isWindowsAccessDeniedStatusError(message: string): boolean {
  const normalized = message.toLowerCase()
  return (
    normalized.includes('wfp status') &&
    (normalized.includes('access is denied') ||
      normalized.includes('access denied') ||
      normalized.includes('0x00000005') ||
      normalized.includes('e_accessdenied'))
  )
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
 * Query the WFP filter set under the given sublayer via live BFE
 * enumeration. `installed` means srt-win-tagged `permit-group` AND
 * `block` filters are both present under that sublayer. Detection is
 * **tag-based** (providerData JSON); filters installed by other
 * tooling without the tag are not counted.
 *
 * BFE enumeration is admin-gated — a non-elevated caller gets
 * `state:"cannot-read"` with a `hint` (not an error). The
 * non-elevated readiness check is {@link verifyWindowsWfpEgress}.
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
    user_filters?: number
    user_sid?: string
    hint?: string
  }>(args)
  return {
    state: raw.state,
    filters: raw.filters,
    ...(raw.port_range && { portRange: raw.port_range }),
    userFilters: raw.user_filters ?? 0,
    ...(raw.user_sid && { userSid: raw.user_sid }),
    ...(raw.hint && { hint: raw.hint }),
  }
}

/**
 * Behavioral proof that the WFP egress fence is active for the
 * sandbox user. Binds a local listener on an ephemeral loopback port
 * outside the WFP loopback-permit range, then spawns `srt-win
 * runner` as the sandbox user (via `CreateProcessWithLogonW`) to
 * attempt a direct TCP connect to it. The WFP block-user filter
 * fires at `ALE_AUTH_CONNECT` — before any packet leaves — so an
 * active fence yields WSAEACCES immediately and a missing fence lets
 * the connect through (the kernel completes the handshake against
 * the listening socket's backlog; no event-loop tick required, so
 * the synchronous `runSrtWin` is safe). Does not require elevation
 * and does not depend on any external host.
 *
 * `initialize()` calls this once per session when
 * `windows.asSandboxUser` is set, so a stale install (sandbox user
 * provisioned but filters since removed) fails closed at session
 * start instead of running every exec with full egress.
 *
 * @param opts.target overrides the probe target (skips the local
 *   listener bind).
 * @param opts.proxyPortRange the WFP loopback-permit range the
 *   listener must avoid. Default
 *   {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
 * @throws on any outcome other than `blocked` (exit 0).
 */
export async function verifyWindowsWfpEgress(
  opts: {
    target?: string
    proxyPortRange?: readonly [number, number]
  } = {},
): Promise<WindowsWfpVerifyResult> {
  let target = opts.target
  let server: net.Server | undefined
  if (!target) {
    // Bind ephemeral; retry if it lands inside the WFP
    // loopback-permit range (a port in-range would be PERMITted
    // even with the fence active → false `connected`).
    const [lo, hi] = opts.proxyPortRange ?? DEFAULT_WINDOWS_PROXY_PORT_RANGE
    for (let i = 0; i < 5; i++) {
      const s = net.createServer()
      s.listen(0, '127.0.0.1')
      await once(s, 'listening')
      const p = (s.address() as net.AddressInfo).port
      if (p < lo || p > hi) {
        server = s
        target = `127.0.0.1:${p}`
        break
      }
      s.close()
    }
    if (!target) {
      throw new Error(
        `verifyWindowsWfpEgress: could not bind a loopback ` +
          `listener outside the WFP permit range [${lo},${hi}] in ` +
          `5 attempts`,
      )
    }
  }
  try {
    // 30s: first call after install may create the sandbox user's
    // profile (LOGON_WITH_PROFILE) via CreateProcessWithLogonW —
    // same budget as windowsTrustCa, plus the runner's own 2s
    // connect timeout.
    const r = runSrtWin(
      ['wfp', 'verify', '--target', target],
      undefined,
      30_000,
    )
    logForDebugging(
      `[Sandbox Windows] wfp verify exit=${r.status}: ${r.stderr || r.stdout}`,
    )
    let raw: { egress_probe: string; target: string }
    try {
      raw = JSON.parse(r.stdout)
    } catch {
      throw new Error(
        `WFP egress fence could not be verified — \`srt-win wfp ` +
          `verify\` exited ${r.status} with unparseable output ` +
          `${JSON.stringify(r.stdout)}: ${r.stderr}`,
      )
    }
    if (r.status === 3) {
      throw new Error(
        `WFP egress fence is not active — direct outbound from the ` +
          `sandbox user to ${raw.target} succeeded. Re-run ` +
          `\`srt-win install\` (one UAC prompt). (${r.stderr})`,
      )
    }
    if (r.status !== 0) {
      throw new Error(
        `WFP egress fence could not be verified — probe to ` +
          `${raw.target} was '${raw.egress_probe}' (exit ` +
          `${r.status}). The fence may be absent. Re-run \`srt-win ` +
          `install\`. (${r.stderr})`,
      )
    }
    return { target: raw.target, stderr: r.stderr }
  } finally {
    server?.close()
  }
}

/**
 * Query the sandbox user account's provisioning state. Each field
 * is independently observed so a half-provisioned install (e.g.
 * user exists but credential file missing) is distinguishable.
 * Does not require elevation.
 */
export function getWindowsSandboxUserStatus(): WindowsSandboxUserStatus {
  const raw = runSrtWinJson<{
    user: {
      exists: boolean
      sid?: string
      group_exists: boolean
      group_sid?: string
      in_builtin_users: boolean
      in_sandbox_group: boolean
      hidden_from_logon: boolean
    }
    cred_present: boolean
    marker_version?: number | null
    real_user_sid: string
    ca_cert_thumb?: string | null
    ca_cert_pem?: string | null
  }>(['user', 'status'])
  return {
    provisioned: raw.user.exists,
    ...(raw.user.sid && { sid: raw.user.sid }),
    groupExists: raw.user.group_exists,
    ...(raw.user.group_sid && { groupSid: raw.user.group_sid }),
    inBuiltinUsers: raw.user.in_builtin_users,
    inSandboxGroup: raw.user.in_sandbox_group,
    hiddenFromLogon: raw.user.hidden_from_logon,
    credPresent: raw.cred_present,
    ...(typeof raw.marker_version === 'number' && {
      markerVersion: raw.marker_version,
    }),
    realUserSid: raw.real_user_sid,
    ...(raw.ca_cert_thumb && { caCertThumb: raw.ca_cert_thumb }),
    ...(raw.ca_cert_pem && { caCertPem: raw.ca_cert_pem }),
  }
}

/**
 * Read back the persistent MITM CA the sandbox was installed with
 * (via `srt-win user trust-ca` / {@link windowsTrustCa}).
 * Returns `null` when no CA was installed. The PEM is what `srt-win
 * user status` reconstructs from the DER stored in `state.db`.
 *
 * On Windows with `windows.asSandboxUser`, `tlsTerminate` requires
 * this CA to be present in the sandbox user's `CurrentUser\Root`
 * (schannel-level trust is an install-time concern, not
 * per-session); the host calls this from `initialize()` to fail
 * early with an actionable message when it isn't.
 *
 * @param status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to avoid a second
 *   `srt-win user status` spawn.
 */
export function getWindowsSandboxCaCert(
  status?: WindowsSandboxUserStatus,
): { pem: string; thumb: string } | null {
  const u = status ?? getWindowsSandboxUserStatus()
  if (!u.caCertThumb || !u.caCertPem) return null
  return { pem: u.caCertPem, thumb: u.caCertThumb }
}

/**
 * Install (or replace) the MITM CA in the **sandbox user's**
 * `CurrentUser\Root` and record it in `state.db` (so
 * {@link getWindowsSandboxCaCert} surfaces its thumbprint + PEM).
 * Thin wrapper around `srt-win user trust-ca <path>`. Does NOT
 * require elevation. Persistent until {@link uninstallWindowsSandbox}
 * deletes the sandbox user's profile.
 *
 * The CA has a separate lifecycle from {@link installWindowsSandbox}
 * — install provisions the account/filters and never touches the CA;
 * call this AFTER install when `tlsTerminate` will be used with
 * `windows.asSandboxUser`.
 *
 * @throws when the sandbox user is not provisioned, the file is not a
 *   parseable X.509 certificate, or the registry write into the
 *   sandbox user's hive fails.
 */
export function windowsTrustCa(caCertPath: string): void {
  // 60s: first call may create the sandbox user's profile
  // (LOGON_WITH_PROFILE) via the one-shot CreateProcessWithLogonW.
  const r = runSrtWin(['user', 'trust-ca', caCertPath], undefined, 60_000)
  logForDebugging(
    `[Sandbox Windows] user trust-ca exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new Error(
      `srt-win user trust-ca '${caCertPath}' failed (exit ` +
        `${r.status}): ${r.stderr || r.stdout}`,
    )
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
  /** Post-install sandbox-user state. */
  user: WindowsSandboxUserStatus
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

  const r = runSrtWin(args, undefined, 60_000)
  logForDebugging(
    `[Sandbox Windows] install exit=${r.status}: ${r.stderr || r.stdout}`,
  )

  // srt-win install exit-code contract:
  //   0  ok
  //   10 user cancelled UAC elevation
  //   11 group create failed
  //   12 WFP install failed
  //   13 already installed with different config (use --force)
  //   14 sandbox-user provisioning failed
  //   1  other error (stderr has detail)
  const out = r.stderr || r.stdout
  switch (r.status) {
    case 0:
      break
    case 10:
      return {
        group: getWindowsGroupStatus(opts),
        wfp: getWindowsWfpStatus({ sublayerGuid: opts.sublayerGuid }),
        user: getWindowsSandboxUserStatus(),
        cancelled: true,
      }
    case 11:
      throw new Error(`srt-win install: group create failed: ${out}`)
    case 12:
      throw new Error(`srt-win install: WFP filter install failed: ${out}`)
    case 14:
      throw new Error(
        `srt-win install: sandbox user provisioning failed: ${out}`,
      )
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
    user: getWindowsSandboxUserStatus(),
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
 * **Does** remove the `srt-sandbox` account, its credential file,
 * and the setup marker, unless `keepUser` is set — the credential
 * is useless without the account and vice versa, so they're
 * treated as one unit.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
export function uninstallWindowsSandbox(
  opts: { sublayerGuid?: string; keepUser?: boolean } = {},
): {
  cancelled?: true
} {
  const args = ['uninstall']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.keepUser) args.push('--keep-user')
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
// Filesystem deny (ACL stamp / restore)
// ────────────────────────────────────────────────────────────────────

/**
 * Per-file outcome from `srt-win acl restore --json`. `status:
 * "restored"` covers both `Restored` and `AlreadyOriginal` on the
 * Rust side (the host doesn't need to distinguish them); every
 * other status keeps the snapshot row (fail-closed) and is
 * surfaced to the user as an anomaly to investigate. Mirrors
 * `restore_entry()` in `vendor/srt-win-src/src/main.rs`.
 */
export interface WindowsAclPathOutcome {
  path: string
  status:
    | 'restored'
    | 'relocated'
    | 'missing'
    | 'leftChanged'
    | 'leftUnreadable'
    | 'originalSdTampered'
    | 'originalSdLost'
    | 'stampedUnrecognized'
  /** Hex `FILE_ID_INFO` recorded at stamp time. Present when `status ≠ "restored"`. */
  expectedFileId?: string
  /** Where the protected file was found by `file_id`. Only on `relocated`. */
  movedTo?: string
  /** `true` whenever `status ≠ "restored"` — the snapshot row was kept (restore not confirmed). */
  leftStamped?: boolean
}

/**
 * Per-parent-directory outcome from `srt-win acl restore --json`.
 * `stillHeld` is normal (another active session still references
 * a file under this directory). Mirrors `parent_entries_from()` +
 * `ParentRestoreOutcome::as_str()` in `vendor/srt-win-src/src/`.
 */
export interface WindowsAclParentOutcome {
  path: string
  status:
    | 'restored'
    | 'alreadyOriginal'
    | 'stillHeld'
    | 'leftChanged'
    | 'missing'
    | 'leftStamped'
  /** Underlying error for `leftStamped`. */
  error?: string
}

/** Top-level shape of `srt-win acl restore --json`. */
export interface WindowsAclRestoreResult {
  paths: WindowsAclPathOutcome[]
  parents: WindowsAclParentOutcome[]
}

/**
 * Expand the `denyRead`/`denyWrite` input set to a flat list of
 * existing FILE paths for `srt-win acl stamp`.
 *
 * Every input goes through {@link normalizePathForSandbox} (the
 * single Windows-aware chokepoint: `\\?\`/UNC-strip, drive-letter
 * case-fold, ~-expand, realpath). Globs (`*`/`?` only — `[`/`]`
 * are legal Win32 filename chars) expand via the shared walker
 * with case-insensitive matching (point-in-time: a file appearing
 * after this returns is NOT covered). Each candidate is checked
 * with one `statSync({throwIfNoEntry:false})`: missing → drop
 * (the protection model covers files present at session start);
 * directory → reject (the file stamp applies a per-file DACL plus
 * a per-parent-directory allow-list; stamping a directory itself
 * would touch every child); file → keep.
 */
export function expandWindowsFsDenyPaths(
  patterns: readonly string[],
  opts: { allowDirs?: boolean } = {},
): string[] {
  const out = new Set<string>()
  for (const raw of patterns) {
    const norm = normalizePathForSandbox(raw)
    const candidates = containsGlobCharsWin(norm)
      ? expandGlobPattern(norm, { caseInsensitive: true })
      : [norm]
    for (const c of candidates) {
      const st = fs.statSync(c, { throwIfNoEntry: false })
      if (!st) continue
      if (st.isDirectory() && !opts.allowDirs) {
        throw new Error(
          `Windows fs deny requires explicit file paths; ` +
            `${JSON.stringify(raw)} resolved to directory ` +
            `${JSON.stringify(c)}. Directory targets are only ` +
            `supported under windows.asSandboxUser.`,
        )
      }
      out.add(c)
    }
  }
  return [...out]
}

export interface WindowsAclStampOptions {
  group: WindowsGroupRef
  /** Paths the sandboxed child must not read. */
  denyRead: readonly string[]
  /** Paths the sandboxed child must not write (read stays allowed). */
  denyWrite: readonly string[]
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
  /**
   * Under the separate-user model, the sandbox user's SID
   * ({@link WindowsSandboxUserStatus.sid}). Switches the stamp to
   * an additive `(D;OICI;mask;;;<sb-SID>)` ACE on the target plus a
   * `(D;OICI;FILE_DELETE_CHILD;;;<sb-SID>)` on the parent — no
   * PROTECTED rewrite, no SD snapshot. When omitted (same-user
   * model), the PROTECTED broker-only stamp keyed on the
   * discriminator group is applied.
   */
  sandboxUserSid?: string
}

/**
 * Apply the file-deny stamp set for one host session. Idempotent
 * via `srt-win`'s disk-first `ensure_stamped` chokepoint — calling
 * this again with overlapping paths re-verifies the on-disk DACL
 * against the hash-ACE marker rather than trusting state-DB rows.
 *
 * Inputs are passed verbatim to `srt-win` (which canonicalizes,
 * rejects directories and globs, and stamps each file plus its
 * immediate parent directory). Callers that accept globs should
 * pre-expand via {@link expandWindowsFsDenyPaths}.
 *
 * @throws on exit ≠ 0 — including exit 2 (one or more inputs
 *   skipped). srt-win stamps the resolvable inputs before exiting
 *   2, so on throw the caller should call {@link restoreWindowsAcl}
 *   to release whatever WAS stamped (fail-closed at session start
 *   means tearing down a partial setup).
 */
export function stampWindowsAcl(opts: WindowsAclStampOptions): void {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({
    denyRead: opts.denyRead,
    denyWrite: opts.denyWrite,
  })
  const args = [
    'acl',
    'stamp',
    ...groupRefArgs(opts.group),
    '--holder-pid',
    `${holder}`,
  ]
  if (opts.sandboxUserSid) {
    args.push('--sandbox-user-sid', opts.sandboxUserSid)
  }
  const r = runSrtWin(args, stdin, 60_000)
  logForDebugging(
    `[Sandbox Windows] acl stamp exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    // exit 2 = partial (some inputs skipped); exit 1 = at least
    // one path could not be stamped. Either is a setup failure.
    throw new Error(
      `srt-win acl stamp exited ${r.status} ` +
        (r.status === 2 ? '(partial — some inputs skipped)' : '(failed)') +
        `: ${r.stderr || r.stdout}`,
    )
  }
}

export interface WindowsAclRestoreOptions {
  group: WindowsGroupRef
  /** Long-lived host PID whose holds to release. Default: this process. */
  holderPid?: number
  /**
   * Under the separate-user model, the sandbox user's SID — must
   * match {@link WindowsAclStampOptions.sandboxUserSid}. Switches
   * restore to `REVOKE_ACCESS` for the SID instead of the
   * SD-snapshot restore.
   */
  sandboxUserSid?: string
}

/**
 * Release this holder's file-deny stamps and return per-path /
 * per-parent outcomes. Best-effort: a non-`restored` entry means
 * the file's stamp was LEFT in place (fail-closed) — see
 * {@link WindowsAclPathOutcome} for the cases. Does not throw on
 * anomalies; the caller decides whether to surface them.
 *
 * Returns `undefined` when `srt-win acl restore` itself failed
 * (no JSON to parse) — the caller should log and move on rather
 * than block teardown.
 */
export function restoreWindowsAcl(
  opts: WindowsAclRestoreOptions,
): WindowsAclRestoreResult | undefined {
  const holder = opts.holderPid ?? process.pid
  const args = [
    'acl',
    'restore',
    ...groupRefArgs(opts.group),
    '--holder-pid',
    `${holder}`,
    '--json',
  ]
  if (opts.sandboxUserSid) {
    args.push('--sandbox-user-sid', opts.sandboxUserSid)
  }
  // Don't let a teardown helper throw — the caller's reset() must
  // complete. runSrtWinJson parses stdout before checking the
  // exit code, so a non-zero exit with the per-path JSON intact
  // (`acl restore` prints outcomes THEN errors when any path
  // stayed stamped) still surfaces every entry to reset()'s loop
  // instead of collapsing to `undefined`. Only spawn-fail /
  // unparseable output throws → log and return undefined.
  try {
    const r = runSrtWinJson<WindowsAclRestoreResult>(args, {
      timeoutMs: 60_000,
      allowNonZero: true,
    })
    if (!r.ok) {
      logForDebugging(
        `[Sandbox Windows] acl restore exited non-zero (per-path ` +
          `outcomes preserved): ${r.stderr}`,
        { level: 'error' },
      )
    }
    return r.json
  } catch (e) {
    logForDebugging(`[Sandbox Windows] acl restore: ${(e as Error).message}`, {
      level: 'error',
    })
    return undefined
  }
}

/**
 * Per-path outcomes that mean the file's DACL was returned to its
 * pre-stamp state (or was already there). Anything else left the
 * stamp in place and should be surfaced to the user.
 */
export const WINDOWS_ACL_PATH_OK = new Set<WindowsAclPathOutcome['status']>([
  'restored',
])

export interface WindowsAclGrantOptions {
  group: WindowsGroupRef
  /** Paths to grant `MODIFY_NO_FDC` on (the working tree, `allowWrite`). */
  write: readonly string[]
  /** Paths to grant `FILE_GENERIC_READ|EXECUTE` on (`allowRead`). */
  read: readonly string[]
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  sandboxUserSid: string
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
}

/**
 * Apply per-session additive `(OI)(CI)` ACEs for the sandbox user
 * on each path. Under the separate-user model the sandbox user has
 * no inherent rights on real-user-owned files; this is what makes
 * the working tree (and explicit `allowRead`/`allowWrite` paths)
 * reachable from the child. Idempotent and refcounted via srt-win's
 * `working_aces` table.
 *
 * @throws on exit ≠ 0. On throw the caller should call
 *   {@link revokeWindowsAcl} to release whatever WAS granted.
 */
export function grantWindowsAcl(opts: WindowsAclGrantOptions): void {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({ read: opts.read, write: opts.write })
  const r = runSrtWin(
    [
      'acl',
      'grant',
      ...groupRefArgs(opts.group),
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
    ],
    stdin,
    60_000,
  )
  logForDebugging(
    `[Sandbox Windows] acl grant exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new Error(
      `srt-win acl grant exited ${r.status}: ${r.stderr || r.stdout}`,
    )
  }
}

/** Per-path outcome from `srt-win acl revoke --json`. */
export interface WindowsAclGrantOutcome {
  path: string
  status:
    | 'revoked'
    | 'stillHeld'
    | 'downgraded'
    | 'relocated'
    | 'mismatch'
    | 'missing'
    | 'noRow'
}

/**
 * Release this holder's grants and remove the sandbox-user ACE on
 * any path whose refcount falls to zero. Best-effort (does not
 * throw); logs anomalies.
 */
export function revokeWindowsAcl(opts: {
  group: WindowsGroupRef
  sandboxUserSid: string
  holderPid?: number
}): WindowsAclGrantOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  try {
    const r = runSrtWinJson<WindowsAclGrantOutcome[]>(
      [
        'acl',
        'revoke',
        ...groupRefArgs(opts.group),
        '--holder-pid',
        `${holder}`,
        '--sandbox-user-sid',
        opts.sandboxUserSid,
        '--json',
      ],
      { timeoutMs: 60_000, allowNonZero: true },
    )
    if (!r.ok) {
      logForDebugging(
        `[Sandbox Windows] acl revoke exited non-zero: ${r.stderr}`,
        { level: 'error' },
      )
    }
    return r.json
  } catch (e) {
    logForDebugging(`[Sandbox Windows] acl revoke: ${(e as Error).message}`, {
      level: 'error',
    })
    return undefined
  }
}

/**
 * Per-parent-directory outcomes that are expected during normal
 * teardown. `stillHeld` is normal when another active session
 * still references a file under this directory.
 */
export const WINDOWS_ACL_PARENT_OK = new Set<WindowsAclParentOutcome['status']>(
  ['restored', 'alreadyOriginal', 'stillHeld'],
)

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
 * `vendor/srt-win-src/src/launch.rs` `build_cmdline` for the passthrough
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
  // Generated proxy + CA-trust env. Single-sourced here so the
  // same object feeds (a) the spawn env merge below and (b) the
  // explicit `--env` overlay for the two-hop launch.
  //
  // Under `asSandboxUser` the CA-bundle path is OMITTED: it points
  // into the broker's `%TEMP%\srt-sandbox-…`, which the
  // `srt-sandbox` user cannot read — OpenSSL-backed clients (msys2
  // curl, `git -c http.sslBackend=openssl`, node, python) would
  // fail to open it (curl exit 77 etc.). Schannel-level trust comes
  // from the registry write `srt-win user trust-ca` did at install
  // time; the env-var bundle layer for the two-hop path lands with
  // the working-tree/profile-grant work. See WindowsSandboxParams.
  if (p.asSandboxUser && p.caCertPath !== undefined) {
    logForDebugging(
      `[Sandbox Windows] caCertPath '${p.caCertPath}' not forwarded ` +
        `under asSandboxUser (broker %TEMP% is unreadable by ` +
        `srt-sandbox); schannel trust via 'srt-win user trust-ca' ` +
        `is the only CA-trust path for the two-hop launch`,
    )
  }
  const generated = envListToObject(
    generateProxyEnvVars(
      p.httpProxyPort,
      p.socksProxyPort,
      p.asSandboxUser ? undefined : p.caCertPath,
      p.proxyAuthToken,
    ),
  )
  // TMPDIR is a POSIX path meant for the macOS/Linux FS sandbox — it
  // serves no purpose on Windows and breaks msys2 tools (mktemp etc.).
  delete generated.TMPDIR

  const argv: string[] = [exe, 'exec', ...groupRefArgs(p.group)]
  if (p.holderPid !== undefined) {
    argv.push('--holder-pid', `${p.holderPid}`)
  }
  for (const f of p.denyRead ?? []) argv.push('--deny-read', f)
  for (const f of p.denyWrite ?? []) argv.push('--deny-write', f)
  if (p.asSandboxUser) {
    argv.push('--as-sandbox-user')
    // The two-hop runner starts with the SANDBOX user's profile env
    // (USERPROFILE/TEMP isolated) and overlays exactly what we pass
    // as `--env`. The broker does NOT enumerate its own env — the
    // overlay is built here from the same single source as the
    // same-user path's spawn env.
    const overlay: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      PATHEXT: process.env.PATHEXT,
      ...generated,
    }
    for (const [k, v] of Object.entries(overlay)) {
      if (v !== undefined) argv.push('--env', `${k}=${v}`)
    }
  }
  argv.push('--')

  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const sh = p.binShell ?? { kind: 'cmd' }
  switch (sh.kind) {
    case 'bash':
      // Git Bash: invoke the caller-supplied path directly with
      // `-c <command>`. `command` is a fully-assembled bash command
      // string with its own internal quoting; srt-win's `build_cmdline`
      // takes the generic non-cmd branch and MSVCRT-quotes it as a
      // SINGLE argv element, so bash receives it intact as argv[2].
      // TODO: MSYS2 derives POSIX /tmp from Windows TEMP/TMP itself;
      // revisit whether any extra TEMP/TMP normalisation is needed for
      // the bash inner shell under the restricted token.
      argv.push(sh.path, '-c', p.command)
      break
    case 'pwsh':
      argv.push('pwsh.exe', '-NoProfile', '-Command', p.command)
      break
    case 'powershell':
      argv.push(
        path.join(
          systemRoot,
          'System32',
          'WindowsPowerShell',
          'v1.0',
          'powershell.exe',
        ),
        '-NoProfile',
        '-Command',
        p.command,
      )
      break
    case 'cmd':
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
      break
  }

  // CreateProcessW's lpCommandLine is capped at 32 767 WCHARs.
  // Node's `shell:false` spawn builds it by MSVCRT-quoting each
  // argv element and joining with spaces; the worst-case quote
  // overhead per element is +2 (wrapping `"`) plus backslash
  // doubling before embedded quotes (rare in file paths). A
  // path-count proxy can't see this — 60 long paths overflow
  // while 200 short ones fit — so estimate the actual command
  // line and refuse with the same guidance the old count check
  // gave. ~30 000 leaves headroom for the quote overhead the
  // estimate doesn't model.
  const cmdlineEstimate = argv.reduce((n, a) => n + a.length + 3, 0)
  if (cmdlineEstimate > 30_000) {
    const nDeny = (p.denyRead?.length ?? 0) + (p.denyWrite?.length ?? 0)
    throw new Error(
      `Windows sandbox argv is ~${cmdlineEstimate} chars ` +
        `(CreateProcessW limit is 32 767). ${nDeny} per-exec ` +
        `file-deny path(s) ride on this argv — move broad globs to ` +
        `the session-level filesystem.denyRead/denyWrite (passed to ` +
        `SandboxManager.initialize(), stdin-passed to \`acl stamp\`) ` +
        `instead, or shorten the command.`,
    )
  }

  // Drop/overwrite denied credential env vars from the inherited
  // environment FIRST. The proxy assignments below must come LAST
  // so SRT's own proxy plumbing vars survive even if a caller lists
  // one of them as a denied credential — same precedence as the
  // macOS/Linux `env -u … VAR=… sandbox-exec` order.
  //
  // Windows env is case-insensitive but Node preserves the OS
  // casing on enumeration, so a `delete baseEnv['SECRET']` would
  // miss a `Secret` key. Match by uppercased name instead.
  const baseEnv: NodeJS.ProcessEnv = { ...process.env }
  const unsetUpper = new Set((p.unsetEnvVars ?? []).map(k => k.toUpperCase()))
  for (const k of Object.keys(baseEnv)) {
    if (unsetUpper.has(k.toUpperCase())) delete baseEnv[k]
  }
  Object.assign(baseEnv, p.setEnvVars ?? {})

  // Generated proxy vars override any inherited (or just-masked)
  // ones so the child always routes through this sandbox's proxies.
  const env: NodeJS.ProcessEnv = { ...baseEnv, ...generated }
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

  // 3. WFP filters installed under the sublayer. BFE enumeration is
  // admin-gated; `cannot-read` is informational only — the
  // BEHAVIORAL check (`verifyWindowsWfpEgress`) runs at
  // `initialize()` and is what actually fails closed.
  let ws: WindowsWfpStatusResult
  try {
    ws = getWindowsWfpStatus({ sublayerGuid })
  } catch (e) {
    const message = (e as Error).message
    if (isWindowsAccessDeniedStatusError(message)) {
      warnings.push(
        `srt-win WFP status could not be verified without administrator rights: ${message}`,
      )
      return { errors, warnings }
    }
    errors.push(`srt-win wfp status failed: ${message}`)
    return { errors, warnings }
  }
  if (ws.state === 'cannot-read') {
    logForDebugging(
      `[Sandbox Windows] wfp status cannot-read (non-elevated): ${ws.hint}`,
    )
  } else if (ws.state !== 'installed') {
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
