import * as fs from 'node:fs'
import * as net from 'node:net'
import * as path from 'node:path'
import { spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  containsGlobCharsWin,
  expandGlobPattern,
} from './sandbox-utils.js'
// Re-export so existing tests (glob-expand.test.ts) and any
// out-of-tree caller keep their import path.
export {
  containsGlobCharsWin,
  stripExtendedPathPrefix,
} from './sandbox-utils.js'
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js'
import type { SrtWinConfig } from './sandbox-config.js'

/**
 * Windows sandbox backend.
 *
 * Network isolation is enforced by `srt-win.exe` — a Rust helper that
 * provisions a dedicated `srt-sandbox` local user account, installs a
 * machine-wide WFP filter set keyed on that account's SID, and
 * provides an `exec` subcommand that spawns the target via a two-hop
 * launch (broker → `CreateProcessWithLogonW(runner)` → runner →
 * restricted-token child) under `srt-sandbox`. The sandboxed child
 * reaches the host only via the JS mux proxy, which the caller
 * passes in via `--env`.
 *
 * The separate-user account structurally closes the surrogate-spawn
 * class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
 * RunAs="Interactive User" COM): the child's token carries a
 * different user SID, so it cannot reach real-user processes, tasks
 * register under `srt-sandbox`, and the user-SID WFP filter fences
 * `srt-sandbox` egress regardless of how the child was spawned.
 *
 * This module is a thin wrapper around the `srt-win` CLI; all status
 * comes from live enumeration. There is no marker file.
 *
 * Filesystem rules (`denyRead`/`denyWrite`/`allowRead`/`allowWrite`)
 * are enforced via additive explicit ACEs for `<sb-SID>` — see
 * {@link grantWindowsAcl} / {@link stampWindowsAcl}.
 */

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export const DEFAULT_WINDOWS_PROXY_PORT_RANGE: readonly [number, number] = [
  60080, 60089,
]

/**
 * `cannot-read` is the graceful-degrade state when BFE enumeration
 * is access-denied (it is admin-gated). The non-elevated readiness
 * check is {@link verifyWindowsWfpEgress}, not this enum.
 */
export type WindowsWfpStatus = 'absent' | 'installed' | 'cannot-read'

export interface WindowsWfpStatusResult {
  state: WindowsWfpStatus
  /** Live filter count from BFE enum; `0` on `cannot-read`. */
  filters: number
  /** `[low, high]` for the loopback PERMIT, when known. */
  portRange?: [number, number]
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
 * provisions. The sandboxed child runs **as** this account.
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
   * The calling (real) user's SID — the broker's identity, surfaced
   * for diagnostics. The DENY-ACE trustee is `srt-sandbox`'s SID
   * ({@link sid}), not this. Always present.
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
 * Inner shell to run `command` under, inside the sandbox: the
 * executable to spawn and the flag argv placed between it and the
 * user's command string. `exe` MUST originate from trusted host
 * configuration (user settings / install detection), NEVER from
 * workspace or repository content — the inner shell runs INSIDE the
 * sandbox so an unexpected path is not a sandbox-escape vector, but
 * it would still be an arbitrary-exec footgun if sourced from
 * untrusted input.
 *
 * Construct via {@link parseWindowsBinShell} — it is the SOLE
 * normalizer and the only place validation lives.
 */
export type WindowsBinShell = {
  /** Shell executable to spawn (absolute path when caller-supplied). */
  exe: string
  /** Argv placed between `exe` and the user's command string. */
  args: readonly string[]
}

const PWSH_FLAGS = ['-NoProfile', '-Command'] as const

/**
 * Sole normalizer from the cross-platform `binShell?: string |
 * WindowsBinShell` surface ({@link SandboxManager.wrapWithSandboxArgv})
 * to a spawnable `{exe, args}` pair. All validation lives here —
 * {@link wrapCommandWithSandboxWindows} consumes the result verbatim.
 *
 * String form: bare token (`'cmd'|'pwsh'|'powershell'`) resolves to
 * the default install; absolute path to `bash.exe`/`sh.exe`/
 * `pwsh.exe`/`powershell.exe`/`cmd.exe` keeps the caller's path with
 * the matching flag shape. Object form: `exe` must be absolute; `args`
 * pass through unchanged. Throws on anything else — no silent
 * fallback to cmd.exe.
 *
 * Uses `path.win32` explicitly so the function (and its unit test)
 * is platform-independent.
 */
export function parseWindowsBinShell(
  raw?: string | WindowsBinShell,
): WindowsBinShell {
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows'
  const cmdDefault: WindowsBinShell = {
    exe: path.win32.join(systemRoot, 'System32', 'cmd.exe'),
    args: ['/d', '/s', '/c'],
  }
  if (raw === undefined || raw === null) return cmdDefault
  if (typeof raw === 'object') {
    if (!path.win32.isAbsolute(raw.exe)) {
      throw new Error(
        `binShell.exe must be an absolute path ` +
          `(got ${JSON.stringify(raw.exe)})`,
      )
    }
    if (!Array.isArray(raw.args)) {
      throw new Error(
        `binShell.args must be an array (got ${JSON.stringify(raw.args)})`,
      )
    }
    return raw
  }
  const rawBase = path.win32.basename(raw)
  const base = rawBase.toLowerCase()
  const isAbs = path.win32.isAbsolute(raw)
  // A relative path with a directory component (`bin\bash.exe`) is
  // neither a token nor a resolved install — never silently degrade.
  if (!isAbs && raw !== rawBase) {
    throw new Error(
      `binShell string must be a bare token or an absolute path ` +
        `(got ${JSON.stringify(raw)})`,
    )
  }
  switch (base) {
    case 'bash':
    case 'bash.exe':
    case 'sh':
    case 'sh.exe':
      // Bare 'bash' is ambiguous (WSL vs Git Bash) — require the
      // resolved install path.
      if (!isAbs) {
        throw new Error(
          `binShell bash path must be absolute ` +
            `(got ${JSON.stringify(raw)}); pass the resolved Git Bash ` +
            `install path`,
        )
      }
      return { exe: raw, args: ['-c'] }
    case 'pwsh':
    case 'pwsh.exe':
      return { exe: isAbs ? raw : 'pwsh.exe', args: PWSH_FLAGS }
    case 'powershell':
    case 'powershell.exe':
      return {
        exe: isAbs
          ? raw
          : path.win32.join(
              systemRoot,
              'System32',
              'WindowsPowerShell',
              'v1.0',
              'powershell.exe',
            ),
        args: PWSH_FLAGS,
      }
    case 'cmd':
    case 'cmd.exe':
      return isAbs ? { exe: raw, args: cmdDefault.args } : cmdDefault
    default:
      throw new Error(
        `unrecognised binShell ${JSON.stringify(raw)}: expected ` +
          `'cmd' | 'powershell' | 'pwsh' or an absolute path to ` +
          `bash.exe/sh.exe/pwsh.exe/powershell.exe`,
      )
  }
}

export interface WindowsSandboxParams {
  command: string
  /**
   * JS HTTP proxy port — fed to `generateProxyEnvVars` for the env
   * overlay. With the in-process proxy this is the mux front-end
   * port (same as `socksProxyPort`).
   */
  httpProxyPort?: number
  /**
   * JS SOCKS proxy port — fed to `generateProxyEnvVars` for the env
   * overlay. With the in-process proxy this is the mux front-end
   * port (same as `httpProxyPort`).
   */
  socksProxyPort?: number
  /** Per-session proxy auth token; embedded in proxy env URLs. */
  proxyAuthToken?: string
  /**
   * `mode: 'mask'` credential env vars — sentinel values the
   * sandboxed child should see in place of the real credentials.
   * Threaded through the `--env` overlay so the runner forwards
   * them into the child's fresh profile env (the broker's own
   * environment never reaches the child, so an `env -u`-style
   * scrub is structurally moot — there is no `unsetEnvVars`).
   * Applied BEFORE the proxy assignments so the sandbox's own
   * proxy plumbing survives even if a caller masks one of those
   * names — same precedence as macOS/Linux.
   */
  setEnvVars?: Readonly<Record<string, string>>
  /**
   * Per-exec read-deny paths, applied via an additive
   * `(D;OICI;FA;;;<sb-SID>)` ACE under the `srt-win exec`
   * process's own PID and released after the child exits. Same
   * disk-first chokepoint as the session-level
   * {@link stampWindowsAcl}; same fail-closed semantics (exec
   * fails if any path cannot be stamped).
   *
   * Normalized concrete paths — globs expanded by the caller via
   * {@link expandWindowsFsPaths}, the same as session-level.
   * `srt-win exec`'s `canonicalize_ace_targets` hard-fails on a
   * glob (it never expands), so a `*`/`?` reaching this field is
   * a caller bug.
   */
  denyRead?: readonly string[]
  /** Per-exec write-deny paths — see {@link denyRead}. */
  denyWrite?: readonly string[]
  /**
   * Working directory the child starts in. Fed to
   * {@link buildGitConfigEnv} as a `safe.directory` entry so git
   * inside the sandbox accepts the real-user-owned working tree.
   * Default: `process.cwd()`.
   *
   * `srt-win exec` has no `--cwd` flag — the child's working
   * directory is whatever the caller passes as the spawn `{cwd:}`
   * option (broker `current_dir()` → runner `lpCurrentDirectory` →
   * child inherits). This field must match that spawn option so
   * `safe.directory` covers where git actually runs.
   */
  cwd?: string
  /**
   * Session-level write-granted paths (the resolved
   * `filesystem.allowWrite` set). Each becomes a `safe.directory`
   * entry — see {@link buildGitConfigEnv}.
   */
  allowWrite?: readonly string[]
  /**
   * Path to the TLS-termination trust bundle (the MITM CA + system
   * roots) — fed to {@link generateProxyEnvVars} so the child's
   * `NODE_EXTRA_CA_CERTS` / `CURL_CA_BUNDLE` / `SSL_CERT_FILE` /
   * etc. point at it. Backslashes are normalised to forward slashes
   * before emission so the value survives msys2 env conversion AND
   * is accepted by native tools.
   *
   * The env-var layer covers OpenSSL-backed clients (msys2 curl,
   * openssl-backed git, node, python, cargo). Schannel/.NET clients
   * that read the Windows certificate store exclusively (System32
   * `curl.exe`, `Invoke-WebRequest`, Go-built tools) trust via the
   * separate `srt-win user trust-ca` / {@link windowsTrustCa}
   * install-time write into the sandbox user's `CurrentUser\Root`.
   *
   * The caller is responsible for the sandbox user having read
   * access to this path — `sandbox-manager.ts`'s `initialize()`
   * pushes it into the session's `acl grant` read-set alongside the
   * working-tree grants.
   */
  caCertPath?: string
  /**
   * Suppress srt-win's informational stderr (progress lines,
   * per-exec-deny summary, seclogon-job note). Actual errors still
   * print. Default `true` — the host surfaces sandbox diagnostics
   * via its own debug log, not the child's stderr stream.
   */
  quiet?: boolean
  /**
   * Resolved `srt-win` spawn descriptor — from
   * {@link resolveSrtWin}. Omit to resolve the packaged vendor
   * binary at call time.
   */
  srtWin?: SrtWinSpawn
  /**
   * Inner shell. Defaults to `parseWindowsBinShell(undefined)`
   * (System32 cmd.exe). The child's post-`args` content is
   * **passthrough** — `&` chains, `"…"`/`'…'` quotes exactly as
   * written. The security boundary is at the OUTER spawn (this argv
   * is spawned with `shell:false`); the inner shell runs INSIDE the
   * sandbox so its metachars are the user's tool. Construct via
   * {@link parseWindowsBinShell}.
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
 * Locate the packaged `srt-win.exe`. Resolution order:
 *   1. `<root>/vendor/srt-win/{arch}/srt-win.exe` (prebuilt — published npm
 *      package, or after `npm run build:srt-win` locally).
 *   2. `<root>/vendor/srt-win-src/target/release/srt-win.exe` (local
 *      `cargo build --release` fallback for development).
 *
 * `<root>` is {@link repoRoot} — `__dirname/../..`, which resolves to the
 * repo root from `src/sandbox/` and `dist/sandbox/` alike, and to the
 * package root when installed under `node_modules`.
 *
 * Callers that ship their own binary (or a multicall binary that
 * routes on `argv[1] == `{@link SRT_WIN_DISPATCH_ARG1}) pass
 * `windows.srtWin` instead of relying on this lookup — see
 * {@link resolveSrtWin}.
 *
 * Resolution via the optional `@anthropic-ai/sandbox-runtime-win32-*`
 * platform packages is added separately.
 *
 * @throws if none exist.
 */
export function getSrtWinPath(): string {
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
  )
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  throw new Error(
    `srt-win.exe not found. Set windows.srtWin.path or build with ` +
      `\`cargo build --release --manifest-path vendor/srt-win-src/Cargo.toml\`. ` +
      `Looked in: ${candidates.join(', ')}`,
  )
}

/**
 * `argv[1]` sentinel a multicall embedder's dispatcher matches
 * against to route into `srt_win::run_from_args`. Mirrors the Rust
 * `srt_win::SRT_WIN_DISPATCH_ARG1`; the two MUST stay in sync.
 * `run_from_args` strips it before clap, so the standalone binary
 * accepts it harmlessly.
 */
export const SRT_WIN_DISPATCH_ARG1 = '--srt-win'

/**
 * Resolved `srt-win` spawn descriptor — the executable to load plus
 * the leading arguments that carry the dispatch sentinel. Threaded
 * to every spawn site so {@link resolveSrtWin} runs once (at
 * `initialize()`) instead of re-`stat`ing on every helper call.
 */
export type SrtWinSpawn = Readonly<{
  exe: string
  prependArgs: readonly string[]
}>

/**
 * Resolve the `srt-win` spawn target from config. When `cfg.path` is
 * set it is used verbatim (no fallback to the packaged binary — an
 * explicit override is a directive, not a hint) and
 * {@link SRT_WIN_DISPATCH_ARG1} is prepended so a multicall
 * dispatcher routes on `argv[1]`. When unset, falls back to
 * {@link getSrtWinPath} with no sentinel (the packaged binary
 * doesn't need it; `run_from_args` would strip it anyway).
 */
export function resolveSrtWin(cfg?: SrtWinConfig): SrtWinSpawn {
  if (cfg?.path !== undefined) {
    if (!fs.existsSync(cfg.path)) {
      throw new Error(
        `windows.srtWin.path is set to '${cfg.path}' but the file does ` +
          `not exist; remove srtWin.path to fall back to the packaged ` +
          `binary`,
      )
    }
    return { exe: cfg.path, prependArgs: [SRT_WIN_DISPATCH_ARG1] }
  }
  return { exe: getSrtWinPath(), prependArgs: [] }
}

// ────────────────────────────────────────────────────────────────────
// Internal: spawn helpers
// ────────────────────────────────────────────────────────────────────

interface RunResult {
  status: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
}

interface RunOpts {
  timeoutMs?: number
  stdin?: string
  srtWin?: SrtWinSpawn
}

function runSrtWin(args: string[], opts: RunOpts = {}): RunResult {
  // Direct callers of the exported helpers may omit `srtWin`
  // (backward-compat) — fall back to the packaged-binary lookup.
  // `SandboxManager` resolves once at `initialize()` and threads the
  // handle, so this per-call resolve is only hit outside a session.
  const { exe, prependArgs } = opts.srtWin ?? resolveSrtWin()
  const r = spawnSync(exe, [...prependArgs, ...args], {
    encoding: 'utf8',
    timeout: opts.timeoutMs ?? 15_000,
    ...(opts.stdin !== undefined ? { input: opts.stdin } : {}),
  })
  if (r.error) {
    throw new Error(`srt-win ${args[0]}: spawn failed: ${r.error.message}`)
  }
  return {
    status: r.status,
    signal: r.signal,
    stdout: (r.stdout ?? '').trim(),
    stderr: (r.stderr ?? '').trim(),
  }
}

function runSrtWinJson<T>(args: string[], opts?: RunOpts): T {
  const r = runSrtWin(args, opts)
  if (r.status !== 0) {
    throw new Error(
      `srt-win ${args.join(' ')} exited ${r.status}: ${r.stderr || r.stdout}`,
    )
  }
  try {
    return JSON.parse(r.stdout) as T
  } catch (e) {
    throw new Error(
      `srt-win ${args.join(' ')}: unparseable JSON output ` +
        `${JSON.stringify(r.stdout)}: ${(e as Error).message}`,
    )
  }
}

/**
 * As {@link runSrtWinJson} but parses stdout BEFORE checking the
 * exit code, so a non-zero exit with the per-path JSON intact
 * still surfaces every entry. For best-effort teardown helpers
 * (`acl restore`/`acl revoke`).
 */
function runSrtWinJsonAllowFail<T>(
  args: string[],
  opts: RunOpts,
): { ok: boolean; json: T; stderr: string } {
  const r = runSrtWin(args, opts)
  let json: T
  try {
    json = JSON.parse(r.stdout) as T
  } catch (e) {
    throw new Error(
      `srt-win ${args.join(' ')}: unparseable JSON output ` +
        `${JSON.stringify(r.stdout)}: ${(e as Error).message}`,
    )
  }
  return { ok: r.status === 0, json, stderr: r.stderr }
}

// ────────────────────────────────────────────────────────────────────
// Status / install API
// ────────────────────────────────────────────────────────────────────

/**
 * Query the WFP filter set under the given sublayer via live BFE
 * enumeration. `installed` means at least one srt-win-tagged
 * `block-user` filter is present. Detection is **tag-based**
 * (providerData JSON); filters installed by other tooling without the
 * tag are not counted.
 *
 * BFE enumeration is admin-gated — a non-elevated caller gets
 * `state:"cannot-read"` with a `hint` (not an error). The
 * non-elevated readiness check is {@link verifyWindowsWfpEgress}.
 */
export function getWindowsWfpStatus(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): WindowsWfpStatusResult {
  const args = ['wfp', 'status']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  const raw = runSrtWinJson<{
    state: WindowsWfpStatus
    filters: number
    port_range?: [number, number]
    user_sid?: string
    hint?: string
  }>(args, { srtWin: opts.srtWin })
  return {
    state: raw.state,
    filters: raw.filters,
    ...(raw.port_range && { portRange: raw.port_range }),
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
 * `initialize()` calls this once per session, so a stale install
 * (sandbox user provisioned but filters since removed) fails closed
 * at session start instead of running every exec with full egress.
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
    srtWin?: SrtWinSpawn
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
    const r = runSrtWin(['wfp', 'verify', '--target', target], {
      timeoutMs: 30_000,
      srtWin: opts.srtWin,
    })
    logForDebugging(
      `[Sandbox Windows] wfp verify exit=${r.status}: ${r.stderr || r.stdout}`,
    )
    let raw: { egress_probe: string; target: string }
    try {
      raw = JSON.parse(r.stdout)
    } catch {
      // status=null → spawnSync killed the child (timeout or external
      // signal). Include signal + stderr so the CI log self-explains
      // instead of just `exited null with unparseable output ""`.
      throw new Error(
        `WFP egress fence could not be verified — \`srt-win wfp ` +
          `verify\` exited ${r.status}` +
          (r.signal ? ` (signal ${r.signal})` : '') +
          ` with unparseable output ${JSON.stringify(r.stdout)} ` +
          `(stderr: ${JSON.stringify(r.stderr)})`,
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
export function getWindowsSandboxUserStatus(
  opts: { srtWin?: SrtWinSpawn } = {},
): WindowsSandboxUserStatus {
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
  }>(['user', 'status'], { srtWin: opts.srtWin })
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
 * On Windows, `tlsTerminate` requires this CA to be present in the
 * sandbox user's `CurrentUser\Root` (schannel-level trust is an
 * install-time concern, not per-session); the host calls this from
 * `initialize()` to fail early with an actionable message when it
 * isn't.
 *
 * @param status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to avoid a second
 *   `srt-win user status` spawn.
 */
export function getWindowsSandboxCaCert(
  status?: WindowsSandboxUserStatus,
  opts: { srtWin?: SrtWinSpawn } = {},
): { pem: string; thumb: string } | null {
  const u = status ?? getWindowsSandboxUserStatus(opts)
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
 * call this AFTER install when `tlsTerminate` will be used.
 *
 * @throws when the sandbox user is not provisioned, the file is not a
 *   parseable X.509 certificate, or the registry write into the
 *   sandbox user's hive fails.
 */
export function windowsTrustCa(
  caCertPath: string,
  opts: { srtWin?: SrtWinSpawn } = {},
): void {
  // 60s: first call may create the sandbox user's profile
  // (LOGON_WITH_PROFILE) via the one-shot CreateProcessWithLogonW.
  const r = runSrtWin(['user', 'trust-ca', caCertPath], {
    timeoutMs: 60_000,
    srtWin: opts.srtWin,
  })
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

export interface WindowsInstallOptions {
  /** WFP sublayer GUID. Omit for srt-win's compile-time default. */
  sublayerGuid?: string
  /**
   * Loopback PERMIT port range. Must match what
   * `SandboxRuntimeConfig.windows.proxyPortRange` will be set to.
   * Default {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
   */
  proxyPortRange?: readonly [number, number]
  /**
   * Name for the sandbox user account (created if absent, adopted
   * if it already exists as a local user). Default `srt-sandbox`.
   */
  sandboxUser?: string
  /**
   * Replace an existing install whose configuration differs
   * (different port range or sandbox-user name under the same
   * sublayer). Without this, install refuses with "already
   * installed with different config" rather than silently
   * overwriting.
   */
  force?: boolean
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

export interface WindowsInstallResult {
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
 * One-shot install: provisions the `srt-sandbox` user account and
 * installs the user-SID-keyed WFP filter set — all in a single
 * self-elevating process (one UAC prompt). Idempotent; re-running
 * rotates the sandbox user's password.
 *
 * Network for the calling user is **not disrupted**: the filters key
 * on the `srt-sandbox` user's SID, so the broker, services, and
 * every other principal fall through to default-permit. No logout
 * is required.
 *
 * Returns the post-call WFP + sandbox-user state. If the user
 * cancels the UAC prompt this returns `{cancelled: true, …}` rather
 * than throwing — cancellation is a user choice, not an error.
 *
 * @throws on user/WFP creation failure, or if filters already exist
 *   under `sublayerGuid` with a different port range and `force` is
 *   not set.
 */
export function installWindowsSandbox(
  opts: WindowsInstallOptions = {},
): WindowsInstallResult {
  const srtWin = opts.srtWin ?? resolveSrtWin()
  const args = ['install']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.proxyPortRange) {
    args.push(
      '--proxy-port-range',
      `${opts.proxyPortRange[0]}-${opts.proxyPortRange[1]}`,
    )
  }
  if (opts.sandboxUser) args.push('--sandbox-user', opts.sandboxUser)
  if (opts.force) args.push('--force')

  const r = runSrtWin(args, { timeoutMs: 60_000, srtWin })
  logForDebugging(
    `[Sandbox Windows] install exit=${r.status}: ${r.stderr || r.stdout}`,
  )

  // srt-win install exit-code contract:
  //   0  ok
  //   10 user cancelled UAC elevation
  //   12 WFP install failed
  //   13 already installed with different config (use --force)
  //   14 sandbox-user provisioning failed
  //   1  other error (stderr has detail)
  const out = r.stderr || r.stdout
  const readBack = () => ({
    wfp: getWindowsWfpStatus({ sublayerGuid: opts.sublayerGuid, srtWin }),
    user: getWindowsSandboxUserStatus({ srtWin }),
  })
  switch (r.status) {
    case 0:
      return readBack()
    case 10:
      return { ...readBack(), cancelled: true }
    case 12:
      throw new Error(`srt-win install: WFP filter install failed: ${out}`)
    case 14:
      throw new Error(
        `srt-win install: sandbox user provisioning failed: ${out}`,
      )
    case 13:
      throw new Error(
        `srt-win install: filters already exist under this sublayer with ` +
          `a different port range or sandbox-user name. Pass ` +
          `{force: true} to replace, or pick a different sublayerGuid. ` +
          `Output: ${out}`,
      )
    default:
      throw new Error(`srt-win install failed (exit ${r.status}): ${out}`)
  }
}

/**
 * Remove the WFP filter set under `sublayerGuid` and the
 * `srt-sandbox` account, its credential file, and the setup marker
 * (one UAC prompt). Idempotent.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
export function uninstallWindowsSandbox(
  opts: {
    sublayerGuid?: string
    keepUser?: boolean
    srtWin?: SrtWinSpawn
  } = {},
): {
  cancelled?: true
} {
  const args = ['uninstall']
  if (opts.sublayerGuid) args.push('--sublayer-guid', opts.sublayerGuid)
  if (opts.keepUser) args.push('--keep-user')
  const r = runSrtWin(args, { srtWin: opts.srtWin })
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
 * Resolve any Windows filesystem-config path list — `allowRead`/
 * `allowWrite` grants and `denyRead`/`denyWrite` stamps — to
 * concrete existing paths via the single platform-aware
 * {@link normalizePathForSandbox} chokepoint (Linux/macOS parity:
 * point-in-time expansion at session initialize, not per-exec).
 * Glob patterns are expanded; non-glob paths are normalized and
 * returned 1:1. Missing paths are dropped (statSync probe).
 * Directory targets are accepted — the additive sandbox-user ACE
 * carries `(OI)(CI)` so it covers the subtree.
 */
export function expandWindowsFsPaths(patterns: readonly string[]): string[] {
  const out = new Set<string>()
  for (const raw of patterns) {
    const norm = normalizePathForSandbox(raw)
    const candidates = containsGlobCharsWin(norm)
      ? expandGlobPattern(norm, { caseInsensitive: true })
      : [norm]
    for (const c of candidates) {
      const st = fs.statSync(c, { throwIfNoEntry: false })
      if (!st) continue
      out.add(c)
    }
  }
  return [...out]
}

export interface WindowsAclStampOptions {
  /** Paths the sandboxed child must not read. */
  denyRead: readonly string[]
  /** Paths the sandboxed child must not write (read stays allowed). */
  denyWrite: readonly string[]
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  sandboxUserSid: string
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

/**
 * Apply the file-deny ACE set for one host session: an additive
 * `(D;OICI;mask;;;<sb-SID>)` on the target plus a
 * `(D;OICI;FILE_DELETE_CHILD;;;<sb-SID>)` on the parent — no
 * PROTECTED rewrite, no SD snapshot. Idempotent and refcounted via
 * srt-win's `working_aces` table.
 *
 * Inputs are passed verbatim to `srt-win` (which canonicalizes and
 * rejects globs). Callers that accept globs should pre-expand via
 * {@link expandWindowsFsPaths}.
 *
 * @throws on exit ≠ 0 — including exit 2 (one or more inputs
 *   skipped). srt-win stamps the resolvable inputs before exiting
 *   2, so on throw the caller should call {@link restoreWindowsAcl}
 *   to release whatever WAS stamped.
 */
export function stampWindowsAcl(opts: WindowsAclStampOptions): void {
  const holder = opts.holderPid ?? process.pid
  const stdin = JSON.stringify({
    denyRead: opts.denyRead,
    denyWrite: opts.denyWrite,
  })
  const r = runSrtWin(
    [
      'acl',
      'stamp',
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
    ],
    { timeoutMs: 60_000, stdin, srtWin: opts.srtWin },
  )
  logForDebugging(
    `[Sandbox Windows] acl stamp exit=${r.status}: ${r.stderr || r.stdout}`,
  )
  if (r.status !== 0) {
    throw new Error(
      `srt-win acl stamp exited ${r.status} ` +
        (r.status === 2 ? '(partial — some inputs skipped)' : '(failed)') +
        `: ${r.stderr || r.stdout}`,
    )
  }
}

/**
 * Per-path outcome from `srt-win acl restore --json` /
 * `revoke --json`. The status set is intentionally loose: the
 * pre-/post- same-user-removal `srt-win` builds emit different
 * vocabularies for `restore` (`restored`/`leftChanged`/… vs
 * `revoked`/`stillHeld`/…). Callers (`reset()`) only log these,
 * so the union is whatever the binary on PATH says.
 */
export interface WindowsAclAceOutcome {
  path: string
  status: string
}

/**
 * Release this holder's deny ACEs and remove the sandbox-user ACE
 * on any path whose refcount falls to zero. Best-effort (does not
 * throw on per-path anomalies); returns per-path outcomes for the
 * caller to surface. Returns `undefined` only when `srt-win`
 * itself failed (no JSON to parse).
 */
export function restoreWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclAceOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  // Don't let a teardown helper throw — the caller's reset() must
  // complete. runSrtWinJsonAllowFail parses stdout before checking
  // the exit code, so a non-zero exit with the per-path JSON intact
  // still surfaces every entry to reset()'s loop. Only spawn-fail
  // / unparseable output throws → log and return undefined.
  try {
    const r = runSrtWinJsonAllowFail<
      | WindowsAclAceOutcome[]
      | { paths?: WindowsAclAceOutcome[]; parents?: WindowsAclAceOutcome[] }
    >(
      [
        'acl',
        'restore',
        '--holder-pid',
        `${holder}`,
        '--sandbox-user-sid',
        opts.sandboxUserSid,
        '--json',
      ],
      { timeoutMs: 60_000, srtWin: opts.srtWin },
    )
    if (!r.ok) {
      logForDebugging(
        `[Sandbox Windows] acl restore exited non-zero (per-path ` +
          `outcomes preserved): ${r.stderr}`,
        { level: 'error' },
      )
    }
    // Pre- same-user-removal builds emit `{paths, parents}`; post-
    // emit a flat array. Flatten either so reset()'s logging loop
    // is shape-agnostic across the transition.
    return Array.isArray(r.json)
      ? r.json
      : [...(r.json.paths ?? []), ...(r.json.parents ?? [])]
  } catch (e) {
    logForDebugging(`[Sandbox Windows] acl restore: ${(e as Error).message}`, {
      level: 'error',
    })
    return undefined
  }
}

export interface WindowsAclGrantOptions {
  /** Paths to grant `MODIFY_NO_FDC` on (the working tree, `allowWrite`). */
  write: readonly string[]
  /** Paths to grant `FILE_GENERIC_READ|EXECUTE` on (`allowRead`). */
  read: readonly string[]
  /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
  sandboxUserSid: string
  /** Long-lived host PID the holds are tied to. Default: this process. */
  holderPid?: number
  /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
  srtWin?: SrtWinSpawn
}

/**
 * Apply per-session additive `(OI)(CI)` ALLOW ACEs for the sandbox
 * user on each path. The sandbox user has no inherent rights on
 * real-user-owned files; this is what makes the working tree (and
 * explicit `allowRead`/`allowWrite` paths) reachable from the
 * child. Idempotent and refcounted via srt-win's `working_aces`
 * table.
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
      '--holder-pid',
      `${holder}`,
      '--sandbox-user-sid',
      opts.sandboxUserSid,
    ],
    { timeoutMs: 60_000, stdin, srtWin: opts.srtWin },
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

/**
 * Release this holder's grants and remove the sandbox-user ACE on
 * any path whose refcount falls to zero. Best-effort (does not
 * throw); logs anomalies.
 */
export function revokeWindowsAcl(opts: {
  sandboxUserSid: string
  holderPid?: number
  srtWin?: SrtWinSpawn
}): WindowsAclAceOutcome[] | undefined {
  const holder = opts.holderPid ?? process.pid
  try {
    const r = runSrtWinJsonAllowFail<WindowsAclAceOutcome[]>(
      [
        'acl',
        'revoke',
        '--holder-pid',
        `${holder}`,
        '--sandbox-user-sid',
        opts.sandboxUserSid,
        '--json',
      ],
      { timeoutMs: 60_000, srtWin: opts.srtWin },
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

// ────────────────────────────────────────────────────────────────────
// Wrap
// ────────────────────────────────────────────────────────────────────

/**
 * `safe.directory` entries above this count collapse to a single
 * `safe.directory=*`. Keeps `GIT_CONFIG_COUNT` (and the `--env`
 * argv it rides on) bounded when `allowWrite` is wide.
 */
const SAFE_DIRECTORY_WILDCARD_THRESHOLD = 8

/**
 * Build the `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` /
 * `GIT_CONFIG_VALUE_<n>` env-var set for the sandboxed child.
 *
 * Emits:
 *   - `safe.directory=<dir>` for each entry in `safeDirs` (or one
 *     `safe.directory=*` when the list is long) — the working tree
 *     is owned by the real user, so git running as `srt-sandbox`
 *     refuses with "detected dubious ownership" without it.
 *   - `http.schannelUseSSLCAInfo=true` and
 *     `http.schannelCheckRevoke=false` when `schannelCa` — makes
 *     git's default (schannel) backend honor `GIT_SSL_CAINFO`
 *     without `-c http.sslBackend=openssl`. Revocation is disabled
 *     because CryptoAPI CRL/OCSP fetches ignore proxy env and would
 *     be WFP-fenced.
 *
 * Composes with an existing `GIT_CONFIG_COUNT` in `baseEnv` by
 * continuing its numbering; the returned `GIT_CONFIG_COUNT` is the
 * new total. Under the two-hop launch the broker's own environment
 * never reaches the child, so `baseEnv` is the caller-supplied
 * overlay ({@link WindowsSandboxParams.setEnvVars}), not
 * `process.env`.
 *
 * Paths are emitted with forward slashes so the value survives
 * msys2's env conversion untouched and native git accepts it.
 */
export function buildGitConfigEnv(opts: {
  safeDirs: readonly string[]
  schannelCa: boolean
  baseEnv?: Readonly<Record<string, string | undefined>>
}): Record<string, string> {
  // An explicit `GIT_CONFIG_COUNT=0` in baseEnv is an opt-out ("no
  // env-level git config") — respect it rather than overwriting.
  if (opts.baseEnv?.GIT_CONFIG_COUNT === '0') return {}
  const parsed = Number.parseInt(opts.baseEnv?.GIT_CONFIG_COUNT ?? '', 10)
  const start = Number.isFinite(parsed) && parsed >= 0 ? parsed : 0
  let n = start
  const out: Record<string, string> = {}
  const emit = (key: string, value: string) => {
    out[`GIT_CONFIG_KEY_${n}`] = key
    out[`GIT_CONFIG_VALUE_${n}`] = value
    n++
  }
  const dirs = [
    ...new Set(
      opts.safeDirs
        .filter((d): d is string => !!d)
        .map(d => {
          const fwd = d.replace(/\\/g, '/')
          const stripped = fwd.replace(/\/+$/, '')
          // Don't strip the trailing slash off a drive root — `C:`
          // is drive-relative-cwd, not the root; git wants `C:/`.
          return /^[A-Za-z]:$/.test(stripped) ? `${stripped}/` : stripped
        }),
    ),
  ]
  if (dirs.length > SAFE_DIRECTORY_WILDCARD_THRESHOLD) {
    emit('safe.directory', '*')
  } else {
    // git matches safe.directory against the REPO TOP-LEVEL exactly,
    // so a workspace root doesn't cover a nested repo. Emit both the
    // exact path and the `<dir>/*` glob (git ≥2.46) so any repo
    // at-or-under a granted dir is trusted.
    for (const d of dirs) {
      emit('safe.directory', d)
      emit('safe.directory', `${d}/*`)
    }
  }
  if (opts.schannelCa) {
    emit('http.schannelUseSSLCAInfo', 'true')
    emit('http.schannelCheckRevoke', 'false')
  }
  if (n === start) return {}
  out.GIT_CONFIG_COUNT = String(n)
  return out
}

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
 * proxy env. The two-hop runner starts with the SANDBOX user's
 * profile env (`USERPROFILE`/`TEMP` isolated) and overlays exactly
 * what we pass as `--env` — built here from the broker's `PATH` plus
 * the generated proxy set.
 */
export function wrapCommandWithSandboxWindows(p: WindowsSandboxParams): {
  argv: string[]
  env: NodeJS.ProcessEnv
} {
  const { exe, prependArgs } = p.srtWin ?? resolveSrtWin()
  // Generated proxy + CA-trust env. Single-sourced here so the
  // same object feeds (a) the spawn env merge below and (b) the
  // explicit `--env` overlay for the runner.
  //
  // The CA trust-bundle path is emitted with forward slashes:
  // msys2's POSIX-path conversion leaves `C:/…` alone and every
  // tool we set the var for (curl, git, node, python, …) accepts
  // forward slashes on Windows; backslashes would be mangled if
  // the value passes through a bash command line. Schannel-level
  // trust comes from the registry write `srt-win user trust-ca`
  // did at install time; the env-var layer here covers the
  // OpenSSL-backed tools.
  const generated = envListToObject(
    generateProxyEnvVars(
      p.httpProxyPort,
      p.socksProxyPort,
      p.caCertPath?.replace(/\\/g, '/'),
      p.proxyAuthToken,
    ),
  )
  // TMPDIR is a POSIX path meant for the macOS/Linux FS sandbox — it
  // serves no purpose on Windows and breaks msys2 tools (mktemp etc.).
  delete generated.TMPDIR
  // NO_PROXY=localhost,127.0.0.1,… is correct on POSIX where seatbelt/
  // bwrap allow direct loopback: a NO_PROXY match makes the client
  // connect directly and it works. On Windows the WFP fence blocks
  // ALL direct connects from the sandbox user — including loopback
  // outside the proxy-port PERMIT range — so NO_PROXY makes clients
  // bypass the proxy and hit the fence; every localhost/127.0.0.1
  // request fails. Consumers currently work around with
  // `curl --noproxy ""`. Drop NO_PROXY here so localhost goes through
  // the proxy (which connects on the child's behalf, from the broker's
  // SID, and is not fenced).
  delete generated.NO_PROXY
  delete generated.no_proxy

  // GIT_CONFIG_* set — safe.directory (dubious-ownership) + the
  // schannel CA knobs. Composed against setEnvVars so a caller
  // that already emits GIT_CONFIG_COUNT keeps its entries.
  const gitCfg = buildGitConfigEnv({
    safeDirs: [p.cwd ?? process.cwd(), ...(p.allowWrite ?? [])],
    schannelCa: p.caCertPath !== undefined,
    baseEnv: p.setEnvVars,
  })

  const argv: string[] = [exe, ...prependArgs, 'exec']
  if (p.quiet !== false) argv.push('--quiet')
  for (const d of p.denyRead ?? []) argv.push('--deny-read', d)
  for (const d of p.denyWrite ?? []) argv.push('--deny-write', d)
  // The two-hop runner starts with the SANDBOX user's profile env
  // (USERPROFILE/TEMP isolated) and overlays exactly what we pass as
  // `--env`. The broker does NOT enumerate its own env — the overlay
  // is built here from the broker's PATH, the mode:'mask' sentinel
  // set, the generated proxy set, and the GIT_CONFIG_* set.
  // Sentinels precede `generated` so a caller masking e.g.
  // `HTTPS_PROXY` cannot break the sandbox's own proxy plumbing —
  // same precedence as the macOS/Linux `env -u … VAR=…
  // sandbox-exec` order. `gitCfg` is last so its GIT_CONFIG_COUNT
  // (which composes against setEnvVars) wins.
  const overlay: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    PATHEXT: process.env.PATHEXT,
    ...(p.setEnvVars ?? {}),
    ...generated,
    ...gitCfg,
  }
  for (const [k, v] of Object.entries(overlay)) {
    if (v !== undefined) argv.push('--env', `${k}=${v}`)
  }
  argv.push('--')

  // Inner shell: `{exe, args}` from parseWindowsBinShell — the SOLE
  // normalizer. `p.command` lands as a single argv element; srt-win's
  // `build_cmdline` MSVCRT-quotes it (or wraps in one outer "…" for
  // cmd /s) so the inner shell receives it intact. See launch.rs.
  const sh = p.binShell ?? parseWindowsBinShell(undefined)
  argv.push(sh.exe, ...sh.args, p.command)

  // CreateProcessW's lpCommandLine is capped at 32 767 WCHARs.
  // Node's `shell:false` spawn builds it by MSVCRT-quoting each
  // argv element and joining with spaces; ~30 000 leaves headroom
  // for the quote overhead the estimate doesn't model.
  const cmdlineEstimate = argv.reduce((n, a) => n + a.length + 3, 0)
  if (cmdlineEstimate > 30_000) {
    throw new Error(
      `Windows sandbox argv is ~${cmdlineEstimate} chars ` +
        `(CreateProcessW limit is 32 767). Shorten the command, ` +
        `or move broad globs to session-level filesystem.denyRead.`,
    )
  }

  // The two-hop runner starts with a FRESH `srt-sandbox` profile
  // env (`lpEnvironment = NULL` + `LOGON_WITH_PROFILE`), so the
  // broker process's environment never reaches the child. The
  // returned `env` is the spawn env for the broker (srt-win)
  // process only; the child sees the `--env` overlay built into
  // `argv` above (PATH/PATHEXT + mode:'mask' sentinels + proxy).
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
 */
export function windowsInstallInstructions(
  sublayerGuid: string | undefined,
): string {
  const sl = sublayerGuid ? ` --sublayer-guid ${sublayerGuid}` : ''
  return (
    `Windows sandbox needs a one-time install (one UAC prompt):\n` +
    `  npx sandbox-runtime windows-install\n` +
    `  — or call installWindowsSandbox(), or run ` +
    `\`srt-win.exe install${sl}\` directly.\n` +
    `No logout is needed: the WFP filter keys on the dedicated ` +
    `\`srt-sandbox\` user's SID, so your network is unaffected.`
  )
}

/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 */
export function checkWindowsDependencies(
  opts: { sublayerGuid?: string; srtWin?: SrtWinSpawn } = {},
): SandboxDependencyCheck {
  const { sublayerGuid } = opts
  const errors: string[] = []
  const warnings: string[] = []

  // 1. Binary present (`resolveSrtWin` throws on a missing
  // override, `getSrtWinPath` on a missing packaged binary). Resolve
  // once and reuse for the status calls below.
  let srtWin: SrtWinSpawn
  try {
    srtWin = opts.srtWin ?? resolveSrtWin()
  } catch (e) {
    return { errors: [(e as Error).message], warnings }
  }
  logForDebugging(`[Sandbox Windows] using srt-win at ${srtWin.exe}`)

  // 2. Sandbox user provisioned + credential readable.
  let us: WindowsSandboxUserStatus
  try {
    us = getWindowsSandboxUserStatus({ srtWin })
  } catch (e) {
    errors.push(`srt-win user status failed: ${(e as Error).message}`)
    return { errors, warnings }
  }
  if (!us.provisioned || !us.credPresent) {
    errors.push(
      `Sandbox user is not provisioned (user=${us.provisioned}, ` +
        `cred=${us.credPresent}). ` +
        windowsInstallInstructions(sublayerGuid),
    )
  }

  // 3. WFP filters installed under the sublayer. BFE enumeration is
  // admin-gated; `cannot-read` is informational only — the
  // BEHAVIORAL check (`verifyWindowsWfpEgress`) runs at
  // `initialize()` and is what actually fails closed.
  let ws: WindowsWfpStatusResult
  try {
    ws = getWindowsWfpStatus({ sublayerGuid, srtWin })
  } catch (e) {
    errors.push(`srt-win wfp status failed: ${(e as Error).message}`)
    return { errors, warnings }
  }
  if (ws.state === 'cannot-read') {
    logForDebugging(
      `[Sandbox Windows] wfp status cannot-read (non-elevated): ${ws.hint}`,
    )
  } else if (ws.state !== 'installed') {
    // 'absent'. If the user is also not-provisioned, the user-state
    // error above already gave the right instruction; don't repeat.
    if (us.provisioned && us.credPresent) {
      errors.push(
        `WFP filters not installed under sublayer ` +
          `${sublayerGuid ?? '(default)'}. ` +
          windowsInstallInstructions(sublayerGuid),
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
