import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
  renameSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer, type Server } from 'node:net'
import type { AddressInfo } from 'node:net'
import { isWindows } from '../helpers/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import {
  getSrtWinPath,
  getWindowsGroupStatus,
  getWindowsWfpStatus,
  getWindowsSandboxUserStatus,
  installWindowsSandbox,
  isWindowsAccessDeniedStatusError,
  uninstallWindowsSandbox,
  verifyWindowsWfpEgress,
  deleteWindowsGroup,
  wrapCommandWithSandboxWindows,
  parseWindowsBinShell,
  restoreWindowsAcl,
  expandWindowsFsDenyPaths,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
} from '../../src/sandbox/windows-sandbox-utils.js'

/**
 * Windows network-sandbox integration tests.
 *
 * CI strategy: the discriminator group must be enabled in the
 * caller's token, but a freshly-created custom group only enters
 * `TokenGroups` at the next logon — and CI can't log out mid-job.
 * So these tests use `BUILTIN\Administrators` (S-1-5-32-544) as the
 * discriminator: the GHA runner user already has it enabled, and
 * `srt-win exec` already adds it to `SidsToDisable`. Filters install
 * under a dedicated test sublayer so they don't touch any production
 * sandbox state on the same machine.
 *
 * Real end-to-end (the actual fence) is also covered by
 * `vendor/srt-win-src/ci/smoke-exec.ps1` which runs before this file in
 * CI; this suite proves the TS layer wires correctly on top.
 */

// `BUILTIN\Administrators` — present and enabled on the GHA Windows
// runner; `srt-win exec` puts it in SidsToDisable regardless of the
// configured group, so the child has it deny-only.
const ADMINS_SID = 'S-1-5-32-544'

// Dedicated test sublayer (distinct from smoke.ps1's a91b6f12-… and
// smoke-exec.ps1's 5b0e64f4-… so the three suites are independent).
const TEST_SUBLAYER = '7c1f0e90-3a2b-4f5d-9e8c-1d2e3f4a5b6c'

// Match smoke-exec.ps1's range; the WFP install below uses it.
const PORT_RANGE: readonly [number, number] = DEFAULT_WINDOWS_PROXY_PORT_RANGE

// Bash userland gates (Group E). git-for-windows ships the first;
// msys2 wget only exists on runners with msys2 installed.
const GIT_BASH = 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'
const MSYS2_WGET = 'C:\\msys64\\usr\\bin\\wget.exe'

describe('Windows sandbox: WFP status access-denied detection', () => {
  it('recognizes access denied errors from wfp status', () => {
    expect(
      isWindowsAccessDeniedStatusError(
        'srt-win wfp status exited 1: srt-win: error: FwpmEngineOpen0 failed: 0x00000005',
      ),
    ).toBe(true)
    expect(
      isWindowsAccessDeniedStatusError(
        'srt-win wfp status exited 1: srt-win: error: Access is denied.',
      ),
    ).toBe(true)
    expect(
      isWindowsAccessDeniedStatusError(
        'srt-win wfp status exited 1: E_ACCESSDENIED',
      ),
    ).toBe(true)
  })

  it('does not classify unrelated wfp status failures as access denied', () => {
    expect(
      isWindowsAccessDeniedStatusError(
        'srt-win wfp status exited 1: unparseable JSON output',
      ),
    ).toBe(false)
    expect(
      isWindowsAccessDeniedStatusError(
        'srt-win group status exited 1: Access is denied.',
      ),
    ).toBe(false)
  })
})

/** True if `name` resolves on PATH (via `where.exe`). */
function hasTool(name: string): boolean {
  if (!isWindows) return false
  const r = spawnSync('where', [name], { encoding: 'utf8', timeout: 5_000 })
  return r.status === 0
}

function createTestConfig(
  allowedDomains: string[] = ['example.com'],
): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains,
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowRead: [],
      allowWrite: [],
      denyWrite: [],
    },
    windows: {
      groupName: 'unused-when-sid-set',
      groupSid: ADMINS_SID,
      wfpSublayerGuid: TEST_SUBLAYER,
      proxyPortRange: [PORT_RANGE[0], PORT_RANGE[1]],
      asSandboxUser: false,
    },
  }
}

/** Run a command inside the Windows sandbox and capture output. */
async function runSandboxed(
  command: string,
  timeoutMs = 30_000,
  extraEnv?: Record<string, string>,
): Promise<{
  stdout: string
  stderr: string
  status: number | null
}> {
  const { argv, env } = await SandboxManager.wrapWithSandboxArgv(command)
  // The child inherits the proxy set via srt-win's environment, so the
  // spawn MUST carry `env` — srt-win exec no longer injects proxy vars.
  // `extraEnv` lets a row add tool-specific vars on top.
  return spawnAsync(argv[0], argv.slice(1), {
    timeout: timeoutMs,
    env: extraEnv ? { ...env, ...extraEnv } : env,
  })
}

type RunResult = { stdout: string; stderr: string; status: number | null }

/**
 * Run a sandboxed command up to `attempts` times until `ok` holds.
 * For ALLOW rows only (they hit live hosts; a registry/network blip
 * should not read as a security regression). NEVER use on BLOCK
 * rows — those must stay single-shot so a fluke "allowed" can't be
 * retried away.
 */
async function runSandboxedUntil(
  command: string,
  ok: (r: RunResult) => boolean,
  attempts = 2,
  timeoutMs = 30_000,
  extraEnv?: Record<string, string>,
): Promise<RunResult> {
  let last: RunResult = { stdout: '', stderr: '', status: null }
  for (let i = 0; i < attempts; i++) {
    last = await runSandboxed(command, timeoutMs, extraEnv)
    if (ok(last)) return last
  }
  return last
}

/**
 * Assert the sandboxed run exited with one of `allowed`; on failure
 * throw with captured stdout+stderr so a CI failure self-explains
 * (curl/tool errors go to stderr — keep `-sS` on curl rows).
 */
function expectStatus(label: string, r: RunResult, allowed: number[]): void {
  if (allowed.includes(r.status ?? -999)) return
  throw new Error(
    `${label}: exit ${r.status} not in [${allowed.join(',')}] · ` +
      `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr)}`,
  )
}

/**
 * Assert a sandboxed BLOCK row did NOT succeed (exit 0 = the egress
 * reached the host = fence broken). The exact failure code varies by
 * platform/build (DNS-resolve, resolver-thread, connect, TLS, …), so
 * assert only not-success and capture stderr for diagnosis —
 * enumerating codes is cross-platform whack-a-mole. Do NOT re-tighten.
 */
function expectEgressBlocked(label: string, r: RunResult): void {
  if (r.status !== 0) return
  throw new Error(
    `${label}: direct/blocked egress unexpectedly SUCCEEDED (exit 0) · ` +
      `stdout=${JSON.stringify(r.stdout)} · stderr=${JSON.stringify(r.stderr)}`,
  )
}

interface BoundListener {
  port: number
  close: () => Promise<void>
}

function listenOn(port: number): Promise<BoundListener> {
  return new Promise((resolve, reject) => {
    // Minimal HTTP/1.1 responder so a sandboxed `curl` that REACHES
    // it exits 0. A raw-TCP "ok\n" reply makes curl exit non-zero on
    // HTTP-parse failure even though the TCP connect — the filter-2
    // PERMIT we're proving — succeeded.
    const srv: Server = createServer(sock => {
      sock.on('data', () => {
        sock.end(
          'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n',
        )
      })
      sock.on('error', () => {})
    })
    srv.once('error', reject)
    srv.listen(port, '127.0.0.1', () => {
      const actual = (srv.address() as AddressInfo).port
      resolve({
        port: actual,
        close: () =>
          new Promise<void>(r => {
            srv.close(() => r())
          }),
      })
    })
  })
}

/**
 * Bind the first free port from `candidates`, retrying on
 * EADDRINUSE. Used by the IN-range loopback row (C6) where the
 * candidate list is the proxy range minus the live proxy ports.
 */
async function bindFirstFree(candidates: number[]): Promise<BoundListener> {
  let lastErr: unknown
  for (const p of candidates) {
    try {
      return await listenOn(p)
    } catch (e) {
      lastErr = e
      if ((e as NodeJS.ErrnoException)?.code !== 'EADDRINUSE') throw e
    }
  }
  throw new Error(
    `no free port among ${candidates.join(',')}: ${(lastErr as Error)?.message}`,
  )
}

/**
 * Bind an ephemeral loopback port (the OS picks) and return it
 * provided it falls OUTSIDE the WFP-allowed proxy port range. If
 * the assigned port lands in the range (the Windows ephemeral pool
 * 49152–65535 overlaps it), close and retry — capped at 5; the
 * chance of all 5 landing in a 10-port window of ~16k is
 * effectively zero. Avoids the fixed-port collisions a candidate
 * list can hit on a busy runner.
 */
async function bindOutOfRange(): Promise<BoundListener> {
  for (let i = 0; i < 5; i++) {
    const l = await listenOn(0)
    if (l.port < PORT_RANGE[0] || l.port > PORT_RANGE[1]) {
      return l
    }
    await l.close()
  }
  throw new Error(
    `bindOutOfRange: 5 ephemeral binds all landed in ` +
      `[${PORT_RANGE[0]}, ${PORT_RANGE[1]}]`,
  )
}

// Pure-JS object test — runs on all platforms (the Windows env
// case-insensitivity bug is in the plain-object scrub, not in any
// Windows API). SRT_WIN_PATH is pointed at any existing file so
// getSrtWinPath() doesn't throw on non-Windows hosts.
describe('wrapCommandWithSandboxWindows env scrub (pure, all platforms)', () => {
  it('unsetEnvVars scrubs case-insensitively', () => {
    const prevSrtWin = process.env.SRT_WIN_PATH
    process.env.SRT_WIN_PATH = process.execPath
    process.env.test_secret_lower = 'x'
    try {
      const { env } = wrapCommandWithSandboxWindows({
        command: 'echo',
        group: { groupName: 'g' },
        unsetEnvVars: ['TEST_SECRET_LOWER'],
      })
      // No casing of the name should survive.
      for (const k of Object.keys(env)) {
        expect(k.toUpperCase()).not.toBe('TEST_SECRET_LOWER')
      }
      expect(env.test_secret_lower).toBeUndefined()
      expect(env.TEST_SECRET_LOWER).toBeUndefined()
    } finally {
      delete process.env.test_secret_lower
      if (prevSrtWin === undefined) delete process.env.SRT_WIN_PATH
      else process.env.SRT_WIN_PATH = prevSrtWin
    }
  })
})

describe('parseWindowsBinShell (pure, all platforms)', () => {
  it('maps tokens/paths and rejects the rest', () => {
    expect(parseWindowsBinShell(undefined)).toEqual({ kind: 'cmd' })
    expect(parseWindowsBinShell('cmd')).toEqual({ kind: 'cmd' })
    expect(parseWindowsBinShell('pwsh')).toEqual({ kind: 'pwsh' })
    expect(parseWindowsBinShell('PowerShell')).toEqual({ kind: 'powershell' })
    for (const p of [
      'C:\\Program Files\\Git\\bin\\bash.exe',
      'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
      'C:\\Program Files\\Git\\bin\\sh.exe',
    ]) {
      expect(parseWindowsBinShell(p)).toEqual({ kind: 'bash', path: p })
    }
    // Bare/relative bash token: caller must pass the resolved absolute
    // install path (PATH-resolved 'bash' could be WSL, not Git Bash).
    expect(() => parseWindowsBinShell('bash')).toThrow(/absolute/)
    // Unknown values fail loud rather than silently routing to cmd.exe.
    expect(() => parseWindowsBinShell('zsh')).toThrow(/unrecognised binShell/)
    expect(() =>
      parseWindowsBinShell('C:\\Program Files\\Git\\git-bash.exe'),
    ).toThrow(/unrecognised binShell/)
    // An absolute path to pwsh/cmd is NOT a token — reject rather than
    // silently dropping the caller's path and degrading to PATH lookup.
    expect(() =>
      parseWindowsBinShell('C:\\Program Files\\PowerShell\\7\\pwsh.exe'),
    ).toThrow(/unrecognised binShell/)
  })
})

describe.if(isWindows)('Windows sandbox: srt-win helpers', () => {
  it('getSrtWinPath resolves to an existing binary', () => {
    const p = getSrtWinPath()
    expect(existsSync(p)).toBe(true)
    expect(p).toMatch(/srt-win\.exe$/i)
  })

  it('getWindowsGroupStatus reports BUILTIN\\Administrators as ready', () => {
    // The GHA runner is admin; this is the precondition smoke-exec
    // already asserted.
    const gs = getWindowsGroupStatus({ groupSid: ADMINS_SID })
    expect(gs.state).toBe('ready')
    expect(gs.sid).toBe(ADMINS_SID)
  })

  it('getWindowsGroupStatus reports a non-existent SID as absent', () => {
    const gs = getWindowsGroupStatus({ groupSid: 'S-1-5-32-9999' })
    expect(gs.state).toBe('absent')
  })

  it('wrapCommandWithSandboxWindows: binShell={kind:bash} → [path, -c, cmd] (not cmd.exe)', () => {
    // The bash arm treats binShell.path as the literal exe to invoke
    // (Git Bash has no fixed install path). The command string — bash
    // metachars and all — must land as the single argv element after
    // `-c`, untouched.
    const cmd = `echo 'a b' && printf '%s' x | cat`
    const bashPath = 'C:\\Program Files\\Git\\bin\\bash.exe'
    const { argv } = wrapCommandWithSandboxWindows({
      command: cmd,
      group: { groupSid: ADMINS_SID },
      binShell: { kind: 'bash', path: bashPath },
    })
    expect(argv.slice(-3)).toEqual([bashPath, '-c', cmd])
    expect(argv).not.toContain('/c')
    expect(argv.join(' ')).not.toMatch(/cmd\.exe/i)
  })

  it('getWindowsWfpStatus reports absent for a never-installed sublayer', () => {
    const ws = getWindowsWfpStatus({
      sublayerGuid: '11111111-2222-3333-4444-555555555555',
    })
    expect(ws.state).toBe('absent')
    expect(ws.filters).toBe(0)
  })

  it('initialize() throws with install instructions when group is absent', async () => {
    const cfg = createTestConfig()
    cfg.windows!.groupSid = 'S-1-5-32-9999' // valid form, definitely absent
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(SandboxManager.initialize(cfg)).rejects.toThrow(
      /one-time install.*npx sandbox-runtime windows-install/is,
    )
    await SandboxManager.reset()
  })

  // The non-elevated readiness check that initialize() runs.
  // Hermetic sublayer + full-uninstall in finally so the
  // round-trips test below starts from an unprovisioned state.
  it('verifyWindowsWfpEgress: blocked after install; throws after uninstall --keep-user', async () => {
    const sl = '6a1e0f80-2b3c-4d5e-9f8a-1b2c3d4e5f60'
    installWindowsSandbox({
      groupSid: ADMINS_SID,
      sublayerGuid: sl,
      proxyPortRange: PORT_RANGE,
    })
    try {
      // Fence active: WFP block-user filter fires at
      // ALE_AUTH_CONNECT before any packet leaves → WSAEACCES. The
      // probe binds a local out-of-range loopback listener; no
      // external host involved.
      const v = await verifyWindowsWfpEgress({ proxyPortRange: PORT_RANGE })
      expect(v.target).toMatch(/^127\.0\.0\.1:\d+$/)
      // Filters removed, sandbox user kept → fence inactive →
      // throws. This is the throw initialize() relays when a stale
      // install (user provisioned, filters since removed) would
      // otherwise run every exec with full egress. The regex
      // matches both the exit-3 (`is not active`) and exit-2
      // (`could not be verified`) messages — either is correct
      // fail-closed behaviour.
      uninstallWindowsSandbox({ sublayerGuid: sl, keepUser: true })
      // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
      await expect(
        verifyWindowsWfpEgress({ proxyPortRange: PORT_RANGE }),
      ).rejects.toThrow(/WFP egress fence/i)
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl })
    }
  }, 60_000)

  it('installWindowsSandbox round-trips group + wfp under a fresh sublayer', () => {
    // Use a unique group name + sublayer so this test is hermetic.
    // The runner is admin (precondition asserted by smoke-exec.ps1),
    // so srt-win install runs without a UAC prompt and `cancelled`
    // is never set. The cancelled path (exit 10) can't be exercised
    // in CI — no interactive desktop for the UAC dialog.
    const grp = `srt-ts-test-${process.pid}`
    const sl = '8d2f1e91-4b3c-5a6e-af9d-2e3f4a5b6c7d'
    try {
      const r = installWindowsSandbox({
        groupName: grp,
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
      })
      expect(r.cancelled).toBeUndefined()
      // No logout in CI → group exists in SAM but not on the
      // caller's token. That's the documented post-install state.
      expect(r.group.state).toBe('created-not-on-token')
      expect(r.group.sid).toMatch(/^S-1-5-/)
      expect(r.wfp.state).toBe('installed')
      expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[1]])
      // Sandbox user provisioned alongside the group + WFP.
      expect(r.user.provisioned).toBe(true)
      expect(r.user.sid).toMatch(/^S-1-5-21-/)
      expect(r.user.groupExists).toBe(true)
      expect(r.user.inBuiltinUsers).toBe(true)
      expect(r.user.inSandboxGroup).toBe(true)
      expect(r.user.credPresent).toBe(true)
      expect(r.user.markerVersion).toBe(1)
      // user-SID-keyed filter set present alongside the group set,
      // tagged with the provisioned SID.
      expect(r.wfp.userFilters).toBeGreaterThanOrEqual(4)
      expect(r.wfp.userSid).toBe(r.user.sid)
      // Idempotent re-run with the SAME config also succeeds.
      const r2 = installWindowsSandbox({
        groupName: grp,
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
      })
      expect(r2.cancelled).toBeUndefined()
      expect(r2.wfp.state).toBe('installed')
    } finally {
      // uninstall removes filters only; group is kept by design.
      const u = uninstallWindowsSandbox({ sublayerGuid: sl })
      expect(u.cancelled).toBeUndefined()
      deleteWindowsGroup({ groupName: grp })
    }
    // After uninstall+delete, all three gone (group, WFP, sandbox
    // user). Discriminator group needed explicit delete; sandbox
    // user is removed by uninstall (no --keep-user).
    expect(getWindowsWfpStatus({ sublayerGuid: sl }).state).toBe('absent')
    expect(getWindowsGroupStatus({ groupName: grp }).state).toBe('absent')
    const u = getWindowsSandboxUserStatus()
    expect(u.provisioned).toBe(false)
    expect(u.credPresent).toBe(false)
    expect(u.markerVersion).toBeUndefined()
  })

  it('installWindowsSandbox refuses different-config without force (exit 13)', () => {
    const grp = `srt-ts-test-13-${process.pid}`
    const sl = '9e3a2fa2-5c4d-6b7f-ba0e-3f4a5b6c7d8e'
    try {
      installWindowsSandbox({
        groupName: grp,
        sublayerGuid: sl,
        proxyPortRange: PORT_RANGE,
      })
      // Re-install with a DIFFERENT port range under the same
      // sublayer without force → exit 13 → throw.
      expect(() =>
        installWindowsSandbox({
          groupName: grp,
          sublayerGuid: sl,
          proxyPortRange: [PORT_RANGE[0], PORT_RANGE[0] + 1],
        }),
      ).toThrow(/already exist.*different config/i)
      // With force → succeeds and replaces.
      const r = installWindowsSandbox({
        groupName: grp,
        sublayerGuid: sl,
        proxyPortRange: [PORT_RANGE[0], PORT_RANGE[0] + 1],
        force: true,
      })
      expect(r.wfp.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[0] + 1])
    } finally {
      uninstallWindowsSandbox({ sublayerGuid: sl })
      deleteWindowsGroup({ groupName: grp })
    }
  })
})

describe.if(isWindows)('Windows sandbox: SandboxManager network', () => {
  let exe: string

  beforeAll(async () => {
    // Checkpoints to stderr (flushed synchronously) so that if the
    // runtime faults mid-setup — e.g. bun 1.3.1 segfaults here on
    // win-arm64 — the LAST line in the CI log localizes the faulting
    // step. Harmless elsewhere (prints on every platform).
    console.error('[winsrt beforeAll] start')
    exe = getSrtWinPath()
    // Install WFP filters under the test sublayer keyed on
    // S-1-5-32-544. smoke-exec.ps1 has its own sublayer; this suite
    // owns this one.
    console.error('[winsrt beforeAll] wfp install: begin')
    const inst = spawnSync(
      exe,
      [
        'wfp',
        'install',
        '--group-sid',
        ADMINS_SID,
        '--sublayer-guid',
        TEST_SUBLAYER,
        '--proxy-port-range',
        `${PORT_RANGE[0]}-${PORT_RANGE[1]}`,
      ],
      { encoding: 'utf8' },
    )
    if (inst.status !== 0) {
      throw new Error(
        `wfp install for test sublayer failed: ${inst.stderr || inst.stdout}`,
      )
    }
    console.error('[winsrt beforeAll] wfp install: done')
    const ws = getWindowsWfpStatus({ sublayerGuid: TEST_SUBLAYER })
    expect(ws.state).toBe('installed')
    expect(ws.filters).toBeGreaterThanOrEqual(8)
    expect(ws.portRange).toEqual([PORT_RANGE[0], PORT_RANGE[1]])

    console.error('[winsrt beforeAll] SandboxManager.initialize: begin')
    await SandboxManager.initialize(createTestConfig())
    console.error('[winsrt beforeAll] done')
  })

  afterAll(async () => {
    await SandboxManager.reset()
    // Always tear down — the runner is ephemeral on GHA but devs
    // may run this locally.
    spawnSync(exe, ['wfp', 'uninstall', '--sublayer-guid', TEST_SUBLAYER], {
      encoding: 'utf8',
    })
  })

  it('wrapWithSandbox() throws on Windows (use wrapWithSandboxArgv)', async () => {
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(SandboxManager.wrapWithSandbox('echo hi')).rejects.toThrow(
      /wrapWithSandboxArgv/,
    )
  })

  it('wrapWithSandboxArgv returns argv + env carrying the full proxy set', async () => {
    const { argv, env } = await SandboxManager.wrapWithSandboxArgv('echo hi')
    expect(argv[0]).toMatch(/srt-win\.exe$/i)
    expect(argv).toContain('exec')
    expect(argv).toContain('--group-sid')
    expect(argv[argv.indexOf('--group-sid') + 1]).toBe(ADMINS_SID)

    // Proxy ports are NO LONGER argv flags — srt-win exec is a pure
    // passthrough; the proxy set rides in the returned env instead.
    expect(argv).not.toContain('--http-proxy')
    expect(argv).not.toContain('--socks-proxy')

    // Standard proxy vars present and pointed at the in-range mux port.
    // The mux serves both protocols on one port. ALL_PROXY is advertised
    // as http:// (not socks5h://) so httpx-style clients don't try to
    // import a SOCKS dependency; the mux still answers SOCKS on that port.
    const httpProxy = env.HTTP_PROXY ?? env.http_proxy
    const allProxy = env.ALL_PROXY ?? env.all_proxy
    expect(httpProxy).toMatch(/^http:\/\/.+:\d+$/)
    expect(allProxy).toMatch(/^http:\/\/.+:\d+$/)
    const httpPort = Number(httpProxy!.split(':').pop())
    const socksPort = Number(allProxy!.split(':').pop())
    expect(httpPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(httpPort).toBeLessThanOrEqual(PORT_RANGE[1])
    expect(httpPort).toBe(socksPort)

    // The FULL set rides along, not just the standard trio — assert an
    // extra var from generateProxyEnvVars is present too.
    expect(env.DOCKER_HTTP_PROXY).toMatch(/^http:\/\//)
    expect(env.GRPC_PROXY ?? env.grpc_proxy).toMatch(/^socks5h:\/\//)

    // Last element is the user's command, passed verbatim to cmd /c.
    expect(argv.slice(-4)).toEqual(['/d', '/s', '/c', 'echo hi'])
  })

  it('proxy ports match what SandboxManager reports', () => {
    const httpPort = SandboxManager.getProxyPort()
    const socksPort = SandboxManager.getSocksProxyPort()
    expect(httpPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(httpPort).toBeLessThanOrEqual(PORT_RANGE[1])
    expect(socksPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(socksPort).toBeLessThanOrEqual(PORT_RANGE[1])
  })

  // ════════════════════════════════════════════════════════════════
  // Group B — egress via real tools (allowed → reaches host via proxy)
  // ════════════════════════════════════════════════════════════════
  // Each row that needs hosts beyond example.com calls updateConfig()
  // first: the JS proxy's filter reads config.network.allowedDomains
  // live, so the allowlist changes without rebinding the proxies (the
  // WFP filters reference the port RANGE, not specific ports).

  it('B1: curl to an allowedDomains host → 200 via proxy', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxedUntil(
      'curl -s -m 15 -o NUL -w "%{http_code}" https://example.com',
      x => x.stdout.trim() === '200',
    )
    expectStatus('B1', r, [0])
    expect(r.stdout.trim()).toBe('200')
  }, 60_000)

  it('B2: powershell Invoke-WebRequest to a NON-allowed host → blocked', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    // IWR may or may not honour HTTP_PROXY depending on WinINET
    // config. Either way the security property holds: via proxy →
    // google.com refused (not allowlisted); direct → WFP blocks.
    const r = await runSandboxed(
      `powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; try { (Invoke-WebRequest https://google.com -UseBasicParsing -TimeoutSec 8).StatusCode } catch { 'ERR' }"`,
    )
    expect(r.stdout.trim()).not.toBe('200')
  }, 40_000)

  it('B3: cmd /c curl to a SECOND allowed host (github.com) → 200', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com', 'github.com']))
    const r = await runSandboxedUntil(
      'curl -s -m 15 -o NUL -w "%{http_code}" https://github.com',
      x => x.stdout.trim() === '200',
    )
    expectStatus('B3', r, [0])
    expect(r.stdout.trim()).toBe('200')
  }, 60_000)

  it.skipIf(!hasTool('git'))(
    'B4: git ls-remote a real repo over the proxy → refs',
    async () => {
      SandboxManager.updateConfig(
        createTestConfig(['example.com', 'github.com']),
      )
      // GIT_CURL_VERBOSE/GIT_TRACE_CURL reveal whether git tunnels via
      // the proxy (CONNECT to 127.0.0.1:<port>) or wrongly goes DIRECT
      // to github (→ WFP-fenced → 60s hang). Captured into the failure
      // message so a recurrence self-explains. NO_DATA keeps the trace
      // to headers/connection (no body dumps). 45s/attempt: git
      // smart-HTTP is heavier than curl.
      const REPO = 'https://github.com/anthropic-experimental/sandbox-runtime'
      const r = await runSandboxedUntil(
        `set GIT_TRACE=1&&set GIT_CURL_VERBOSE=1&&set GIT_TRACE_CURL=1&&set GIT_TRACE_CURL_NO_DATA=1&&git ls-remote --heads ${REPO}`,
        x => x.status === 0 && /refs\/heads/.test(x.stdout),
        2,
        45_000,
      )
      if (r.status !== 0 || !/refs\/heads/.test(r.stdout)) {
        throw new Error(
          `B4 git ls-remote via proxy failed: status=${r.status} · ` +
            `stdout=${JSON.stringify(r.stdout.slice(0, 400))} · ` +
            `git-trace(tail)=${JSON.stringify(r.stderr.slice(-3500))}`,
        )
      }
    },
    120_000,
  )

  it.skipIf(!hasTool('node'))(
    'B5: node https.get direct egress is BLOCKED (proxy env not honoured)',
    async () => {
      // KEY: Node's built-in https does NOT read HTTPS_PROXY, so it
      // attempts a DIRECT connect. WFP filter-3 must refuse it. This
      // is the load-bearing proof that WFP — not the proxy env vars —
      // is the real network boundary.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "const s=Date.now();require('https').get('https://example.com',r=>{console.log('OK:'+r.statusCode);process.exit(0)}).on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});setTimeout(()=>{console.log('TIMEOUT');process.exit(2)},6000)"`,
      )
      // The direct connect must NOT succeed.
      expect(r.stdout.startsWith('OK:')).toBe(false)
    },
    20_000,
  )

  // ════════════════════════════════════════════════════════════════
  // Group C — direct-egress / bypass resistance
  // ════════════════════════════════════════════════════════════════

  it('C1: powershell Test-NetConnection 1.1.1.1:80 → blocked at WFP', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      `powershell -NoProfile -Command "$ErrorActionPreference='SilentlyContinue'; (Test-NetConnection 1.1.1.1 -Port 80 -WarningAction SilentlyContinue).TcpTestSucceeded"`,
    )
    // Anything other than `true` is the kernel-fence pass (False, or
    // empty if the inner probe is still hanging when curl's timeout
    // fires — itself proof the SYN was dropped).
    expect(r.stdout.trim().toLowerCase()).not.toBe('true')
  }, 40_000)

  it.skipIf(!hasTool('nslookup'))(
    'C2: nslookup with explicit server → direct UDP 53 blocked',
    async () => {
      // nslookup does its OWN direct UDP-53 query (bypasses the DNS
      // Client service), so the child's token hits WFP filter-3.
      // NOTE: this is the DIRECT-DNS path; resolution via getaddrinfo
      // (Dnscache) is a separate, documented residual — see R1 below.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed('nslookup example.com 1.1.1.1')
      // Don't lean on exit code (varies across Windows builds) or on
      // the generic "Address:" line (nslookup prints the SERVER's own
      // address before any answer). Assert the resolved-NAME answer
      // section is absent AND a failure signature is present.
      expect(r.stdout).not.toMatch(/Name:\s*example\.com/i)
      expect(r.stdout + r.stderr).toMatch(
        /timed out|can't find|no response|request to .* failed|server failed/i,
      )
    },
    20_000,
  )

  // C3 (ping ICMP blocked) is intentionally NOT asserted as blocked:
  // ICMP doesn't traverse FWPM_LAYER_ALE_AUTH_CONNECT, so the v1
  // design does not fence it. Pinned as a residual (R2) instead.

  it('C4: curl --noproxy "*" strips env → WFP still BLOCKS', async () => {
    // KEY: clearing the proxy env makes curl attempt direct egress;
    // WFP must still refuse it. Pairs with B5 as the "env-var bypass
    // doesn't defeat WFP" proof.
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed(
      'curl --noproxy "*" -sS -m 5 https://example.com',
    )
    // --noproxy strips the proxy so curl attempts a DIRECT connection;
    // WFP (filter-3) must prevent it. The exact curl failure code
    // varies by platform/build — x64: 6 (couldn't-resolve), arm64: 2
    // (resolver thread won't start under the sandbox token/job) — so
    // assert only that it did NOT succeed. Exit 0 would mean the
    // bypass reached example.com = real regression. stderr captured.
    expectEgressBlocked('C4', r)
  }, 20_000)

  it.skipIf(!hasTool('node'))(
    'C5: node raw socket to 1.1.1.1:80 → not CONNECTED',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "const s=require('net').connect(80,'1.1.1.1');s.setTimeout(4000);s.on('connect',()=>{console.log('CONNECTED');process.exit(0)});s.on('error',e=>{console.log('ERR:'+e.code);process.exit(1)});s.on('timeout',()=>{console.log('TIMEOUT');process.exit(2)})"`,
      )
      expect(r.stdout.includes('CONNECTED')).toBe(false)
    },
    20_000,
  )

  // ── loopback port-range fence (filter-2 / filter-3) — kept ───────

  it('C6: child reaches an IN-range loopback port (filter-2 PERMIT)', async () => {
    // Bind a listener on a free IN-range port that is NOT one of the
    // live JS proxy ports (those also live in the range). Walk the
    // range top-down, skipping the proxy ports, so we never collide
    // with them (which would EADDRINUSE) and never curl a proxy port.
    const httpP = SandboxManager.getProxyPort()
    const socksP = SandboxManager.getSocksProxyPort()
    const candidates: number[] = []
    for (let p = PORT_RANGE[1]; p >= PORT_RANGE[0]; p--) {
      if (p !== httpP && p !== socksP) candidates.push(p)
    }
    const l = await bindFirstFree(candidates)
    try {
      // -sS so curl prints any error to stderr (captured on failure).
      const r = await runSandboxed(
        `curl -sS -m 5 -o NUL -w "%{http_code}" --noproxy "*" http://127.0.0.1:${l.port}`,
      )
      // Exit 0 = the direct loopback connect was PERMITTED (filter-2)
      // and the minimal HTTP responder replied 200.
      expectStatus('C6', r, [0])
    } finally {
      await l.close()
    }
  }, 20_000)

  it('C7: child BLOCKED from an OUT-of-range loopback port (filter-3)', async () => {
    // Ephemeral bind, retried until the OS-assigned port falls
    // outside the WFP-allowed proxy range — robust to both
    // fixed-port collisions on a busy runner AND the ephemeral pool
    // overlapping the proxy range.
    const l = await bindOutOfRange()
    try {
      // Sanity: genuinely outside the proxy port range.
      expect(l.port < PORT_RANGE[0] || l.port > PORT_RANGE[1]).toBe(true)
      const r = await runSandboxed(
        `curl -sS -m 5 -o NUL -w "%{http_code}" --noproxy "*" http://127.0.0.1:${l.port}`,
      )
      // WFP filter-3 BLOCK at the TCP layer → curl can't connect.
      // Exact failure code varies by platform; assert only not-success
      // (exit 0 = reached the out-of-range listener = fence broken).
      expectEgressBlocked('C7', r)
    } finally {
      await l.close()
    }
  }, 20_000)

  // ════════════════════════════════════════════════════════════════
  // Group D — the proxy port is not an open relay
  // ════════════════════════════════════════════════════════════════
  // The shared JS proxy now requires a per-session secret (matching
  // the donor's design): a host process without it is refused at the
  // handshake. With the secret, the destination filter still applies.

  it.skipIf(!hasTool('curl'))(
    'D2: host curl --socks5 to proxy is not an open relay (disallowed host refused)',
    async () => {
      const socksPort = SandboxManager.getSocksProxyPort()
      const token = SandboxManager.getProxyAuthToken()
      expect(socksPort).toBeGreaterThan(0)
      expect(token).toBeTruthy()

      // Drive curl through the SOCKS proxy to a LOCAL responder via
      // ASYNC spawn. Two reasons this must NOT use spawnSync + a live
      // host (the original D2 bug): (1) spawnSync blocks bun's event
      // loop, but the SOCKS proxy runs IN this process — it can't tick
      // while curl waits → self-deadlock → timeout (see the warning in
      // test/helpers/spawn.ts). (2) proxy-liveness checks route to
      // 127.0.0.1, never a live host (cf. tls-terminate-proxy /
      // parent-proxy-tunnel tests).
      const l = await listenOn(0)
      // 127.0.0.1 is exact-matched by the proxy's domain filter; this
      // is the network/allowlist live-swap path of updateConfig.
      SandboxManager.updateConfig(createTestConfig(['127.0.0.1']))
      const socks = (host: string, withAuth = true): string[] => [
        '--socks5-hostname',
        withAuth
          ? `srt:${token}@127.0.0.1:${socksPort}`
          : `127.0.0.1:${socksPort}`,
        '-sS',
        '-m',
        '5',
        '-o',
        'NUL',
        '-w',
        '%{http_code}',
        host,
      ]
      try {
        // Host process WITHOUT the secret → refused at the SOCKS
        // handshake, never reaches the destination filter.
        const noAuth = await spawnAsync(
          'curl',
          socks(`http://127.0.0.1:${l.port}`, false),
          { timeout: 10_000 },
        )
        expect(noAuth.status).not.toBe(0)

        // Allowed dest (loopback responder) reached THROUGH the proxy →
        // proves the port is up and an allowlisted dest passes the
        // filter. All-loopback + ticking proxy = deterministic (no
        // retry needed).
        const ok = await spawnAsync(
          'curl',
          socks(`http://127.0.0.1:${l.port}`),
          { timeout: 10_000 },
        )
        if (ok.stdout.trim() !== '200') {
          throw new Error(
            `D2 allowed (host socks5 → 127.0.0.1:${l.port}): expected 200 · ` +
              `status=${ok.status} · stdout=${JSON.stringify(ok.stdout)} · ` +
              `stderr=${JSON.stringify(ok.stderr)}`,
          )
        }

        // Disallowed dest → refused by the filter PRE-DIAL (never
        // contacted). STRICT single-shot: the real "not an open relay"
        // property — now genuinely exercised (the old spawnSync
        // deadlock-timeout was masking it).
        const blocked = await spawnAsync('curl', socks('https://google.com'), {
          timeout: 10_000,
        })
        expectEgressBlocked('D2 disallowed (host socks5 → google.com)', blocked)
      } finally {
        await l.close()
      }
    },
  )

  // ════════════════════════════════════════════════════════════════
  // Group E — bash userland (gated; skip if absent)
  // ════════════════════════════════════════════════════════════════

  it.skipIf(!existsSync(GIT_BASH))(
    'E1: git-bash curl to an allowed host → 200',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxedUntil(
        `"${GIT_BASH}" -c "curl -s -m 15 -o /dev/null -w '%{http_code}' https://example.com"`,
        x => x.stdout.trim() === '200',
      )
      expect(r.stdout.trim()).toBe('200')
    },
    60_000,
  )

  it.skipIf(!existsSync(GIT_BASH) || !hasTool('git'))(
    'E2: git-bash git ls-remote github.com → refs',
    async () => {
      SandboxManager.updateConfig(
        createTestConfig(['example.com', 'github.com']),
      )
      // Same proxy/direct diagnosis as B4, via git-bash. Inline env
      // prefix (bash) + GIT_*_VERBOSE trace captured on failure.
      const r = await runSandboxedUntil(
        `"${GIT_BASH}" -c "GIT_TRACE=1 GIT_CURL_VERBOSE=1 GIT_TRACE_CURL=1 GIT_TRACE_CURL_NO_DATA=1 git ls-remote --heads https://github.com/anthropic-experimental/sandbox-runtime"`,
        x => x.status === 0 && /refs\/heads/.test(x.stdout),
        2,
        45_000,
      )
      if (r.status !== 0 || !/refs\/heads/.test(r.stdout)) {
        throw new Error(
          `E2 git-bash ls-remote via proxy failed: status=${r.status} · ` +
            `stdout=${JSON.stringify(r.stdout.slice(0, 400))} · ` +
            `git-trace(tail)=${JSON.stringify(r.stderr.slice(-3500))}`,
        )
      }
    },
    120_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E4: binShell=bash.exe — direct egress BLOCKED (WFP applies under bash inner shell)',
    async () => {
      // E1/E2 wrap git-bash inside `cmd /c "…bash.exe" -c …`. This row
      // exercises the first-class bash inner-shell branch: srt-win
      // spawns bash.exe DIRECTLY under the restricted token. The
      // --noproxy strip forces a direct connect; WFP filter-3 must
      // refuse it exactly as it does for cmd (cf. C4).
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const cmd = `curl --noproxy '*' -sS -m 5 https://example.com`
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        cmd,
        GIT_BASH,
      )
      // Sanity: routed via the bash branch, not cmd.
      expect(argv.slice(-3)).toEqual([GIT_BASH, '-c', cmd])
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 20_000,
        env,
      })
      expectEgressBlocked('E4', r)
    },
    30_000,
  )

  it.skipIf(!existsSync(GIT_BASH))(
    'E5: binShell=bash.exe — &&, single-quote, pipe survive argv round-trip',
    async () => {
      // Proves bash — not cmd — evaluates the command: `printf` is a
      // bash builtin (cmd has no `printf`), single-quotes are bash
      // quoting (cmd would emit them literally), and `|`/`&&` chain
      // under bash semantics. srt-win's build_cmdline takes the
      // generic MSVCRT-quote path for non-cmd targets, so the whole
      // string reaches bash as one argv[2].
      const cmd = `printf '%s ' one && printf '%s' two | tr a-z A-Z`
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        cmd,
        GIT_BASH,
      )
      expect(argv.slice(-3)).toEqual([GIT_BASH, '-c', cmd])
      const r = await spawnAsync(argv[0], argv.slice(1), {
        timeout: 20_000,
        env,
      })
      expectStatus('E5', r, [0])
      expect(r.stdout.trim()).toBe('one TWO')
    },
    30_000,
  )

  it.skipIf(!existsSync(MSYS2_WGET))(
    'E3: msys2 wget to an allowed host → 200',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      // No -q: wget's connection log (which proxy address it dialed,
      // and any "failed: Connection refused") goes to stderr so a
      // failure self-explains in the message below.
      const r = await runSandboxed(
        `"${MSYS2_WGET}" -O NUL --server-response --timeout=15 https://example.com`,
      )
      if (!/HTTP\/[\d.]+ 200/.test(r.stderr + r.stdout)) {
        throw new Error(
          `E3 wget via proxy: no HTTP 200 seen · status=${r.status} · ` +
            `stdout=${JSON.stringify(r.stdout.slice(0, 400))} · ` +
            `stderr=${JSON.stringify(r.stderr.slice(-2000))}`,
        )
      }
    },
    30_000,
  )

  // ════════════════════════════════════════════════════════════════
  // Tool-compat matrix — real proxied fetch, allowed → ok (gated)
  // ════════════════════════════════════════════════════════════════

  it.skipIf(!hasTool('npm'))(
    'tool/npm: npm view fetches a package version via the proxy',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['registry.npmjs.org']))
      const r = await runSandboxedUntil(
        'npm view left-pad version',
        x => x.status === 0 && /^\d+\.\d+\.\d+/.test(x.stdout.trim()),
      )
      expectStatus('tool/npm', r, [0])
      expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/)
    },
    90_000,
  )

  it.skipIf(!hasTool('pip'))(
    'tool/pip: pip download fetches a wheel via the proxy',
    async () => {
      SandboxManager.updateConfig(
        createTestConfig(['pypi.org', 'files.pythonhosted.org']),
      )
      const dest = `${process.env.TEMP ?? 'C:\\Windows\\Temp'}\\srt-pip-${process.pid}`
      const r = await runSandboxedUntil(
        `pip download --no-deps --dest "${dest}" six`,
        x => x.status === 0,
      )
      expectStatus('tool/pip', r, [0])
      expect(r.stdout + r.stderr).toMatch(/Saved|Downloading/i)
    },
    120_000,
  )

  it.skipIf(!hasTool('go'))(
    'tool/go: go list -m resolves a module via the proxy',
    async () => {
      SandboxManager.updateConfig(createTestConfig(['proxy.golang.org']))
      const r = await runSandboxedUntil(
        'go list -m rsc.io/quote@latest',
        x => x.status === 0 && /rsc\.io\/quote/.test(x.stdout),
      )
      expectStatus('tool/go', r, [0])
      expect(r.stdout).toMatch(/rsc\.io\/quote/)
    },
    120_000,
  )

  it.skipIf(!hasTool('cargo'))(
    'tool/cargo: cargo search hits crates.io via the proxy',
    async () => {
      SandboxManager.updateConfig(
        createTestConfig(['crates.io', 'static.crates.io']),
      )
      // CARGO_HTTP_CHECK_REVOKE=false: schannel's certificate
      // revocation lookup goes through CryptoAPI/WinHTTP, which never
      // reads proxy env vars, so under the egress sandbox it can't
      // reach the CRL endpoint unless the runner's CRL cache happens
      // to be warm. Standard practice behind corporate proxies; this
      // row proves cargo's own traffic routes via the proxy, not
      // revocation policy.
      const r = await runSandboxedUntil(
        'cargo search serde --limit 1',
        x => x.status === 0 && /serde/.test(x.stdout),
        2,
        30_000,
        { CARGO_HTTP_CHECK_REVOKE: 'false' },
      )
      expectStatus('tool/cargo', r, [0])
      expect(r.stdout).toMatch(/serde/)
    },
    120_000,
  )

  // ════════════════════════════════════════════════════════════════
  // Residual pins (documented Windows limitations — NOT bugs)
  // ════════════════════════════════════════════════════════════════
  // These fail loudly if a future change accidentally CLOSES a
  // documented residual. See PLAN-winsrt-upstream.md known-bypass
  // table.

  it.skipIf(!hasTool('node'))(
    'R1: DNS resolution via getaddrinfo/Dnscache is NOT fenced',
    async () => {
      // getaddrinfo → DNS Client service (NetworkService token) does
      // the wire query, so ALE_USER_ID never sees the child. The
      // child can therefore resolve ARBITRARY names (a DNS-exfil
      // channel) even for hosts it cannot connect to. Resolve a
      // non-allowlisted name to make the point.
      SandboxManager.updateConfig(createTestConfig(['example.com']))
      const r = await runSandboxed(
        `node -e "require('dns').lookup('google.com',(e,a)=>{console.log(e?'ERR:'+e.code:'OK:'+a);process.exit(e?1:0)})"`,
      )
      expect(r.stdout.startsWith('OK:')).toBe(true)
    },
    20_000,
  )

  it('R2: ICMP (ping) is NOT fenced', async () => {
    SandboxManager.updateConfig(createTestConfig(['example.com']))
    const r = await runSandboxed('ping -n 1 -w 3000 8.8.8.8')
    // ICMP doesn't traverse ALE_AUTH_CONNECT, so the v1 design can't
    // fence it. A regression that DID start blocking ICMP would make
    // ping report "General failure" (the WFP-drop signature) rather
    // than a network timeout — assert we never see that.
    expect(r.stdout).not.toMatch(/General failure/i)
  }, 20_000)
})

// ────────────────────────────────────────────────────────────────────
// Group F — file deny (denyRead/denyWrite via srt-win acl)
// ────────────────────────────────────────────────────────────────────
//
// End-to-end through SandboxManager: initialize() runs `srt-win acl
// stamp`; wrapWithSandboxArgv() passes `--holder-pid` so exec
// engages the per-exec dir/file fence; reset() runs `acl restore
// --json`. The per-Rust-arm cases (A1-A25, H1-H9) are covered by
// vendor/srt-win-src/ci/smoke-acl.ps1 — these rows prove the TS layer
// wires correctly on top.

/**
 * Capture a file's effective DACL via icacls. The leading file
 * path and the per-ACE `(I)` (INHERITED_ACE) flag are stripped:
 * `(I)` is OS-managed inheritance metadata — a parent-DACL write
 * (e.g. `srt-win`'s parent stamp+restore) re-evaluates inheritance
 * for children and can flip an ACE between explicit and inherited
 * with no change to who-can-do-what. Same noise class as
 * SE_DACL_AUTO_INHERITED (which `acl::sd_equiv` already masks).
 */
function captureEffectiveDacl(p: string): string {
  const r = spawnSync('icacls', [p], { encoding: 'utf8', timeout: 5_000 })
  if (r.status !== 0) {
    throw new Error(`icacls "${p}" exit ${r.status}: ${r.stderr || r.stdout}`)
  }
  return r.stdout
    .replace(p, '')
    .replace(/\(I\)/g, '')
    .replace(/\s+/g, ' ')
    .trim()
}

function createFsTestConfig(
  fs: Partial<SandboxRuntimeConfig['filesystem']>,
): SandboxRuntimeConfig {
  const base = createTestConfig()
  return { ...base, filesystem: { ...base.filesystem, ...fs } }
}

describe.if(isWindows)('Windows sandbox: file deny', () => {
  // One scratch dir per suite under the user's temp; the parent
  // allow-list stamp lands on this dir. cleanup.ps1 runs `acl
  // recover --force` after the suite, so a left-over stamp from a
  // throw mid-test is mopped up.
  let scratch: string
  let secret: string // denyRead target
  let cfg: string // denyWrite target

  beforeAll(async () => {
    scratch = mkdtempSync(join(tmpdir(), 'srt-fsdeny-'))
    secret = join(scratch, 'secret.txt')
    cfg = join(scratch, 'config.txt')
    writeFileSync(secret, 'TOP-SECRET')
    writeFileSync(cfg, 'CONFIG-V1')
    // Glob targets (F6).
    writeFileSync(join(scratch, 'a.env'), 'ENV-A')
    writeFileSync(join(scratch, 'b.env'), 'ENV-B')
    // F4 impostor.
    writeFileSync(join(scratch, 'impostor.txt'), 'IMPOSTOR')

    // Reuse the network describe's WFP install (already done in CI
    // by smoke.ps1 or the network suite's beforeAll). If filters
    // are absent, install them — same shape as the network suite.
    const wfp = getWindowsWfpStatus({ sublayerGuid: TEST_SUBLAYER })
    if (wfp.state !== 'installed') {
      installWindowsSandbox({
        groupSid: ADMINS_SID,
        sublayerGuid: TEST_SUBLAYER,
        proxyPortRange: PORT_RANGE,
      })
    }

    await SandboxManager.initialize(
      createFsTestConfig({ denyRead: [secret], denyWrite: [cfg] }),
    )
  })

  afterAll(async () => {
    await SandboxManager.reset()
    // Best-effort scratch cleanup. If a stamp was left behind
    // (relocated/missing/…), the per-run %LOCALAPPDATA% override in
    // smoke-acl.ps1 doesn't apply here — but cleanup.ps1 runs
    // `acl recover --force` after the suite.
    try {
      rmSync(scratch, { recursive: true, force: true })
    } catch {
      /* left-over stamps can block this; cleanup.ps1 handles it */
    }
  })

  it('F1: denyRead — child cannot read the secret', async () => {
    const r = await runSandboxed(`type "${secret}"`)
    if (r.stdout.includes('TOP-SECRET')) {
      throw new Error(
        `F1: child read the denyRead target — exit=${r.status} ` +
          `stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr)}`,
      )
    }
    // cmd `type` exits non-zero on access-denied; assert on the
    // CONTENT (the line above) plus exit≠0, not on the localised
    // error string.
    expect(r.status).not.toBe(0)
  })

  it('F2: denyWrite — child cannot write but CAN read', async () => {
    const w = await runSandboxed(`echo POISONED>"${cfg}"`)
    const after = readFileSync(cfg, 'utf8')
    if (after !== 'CONFIG-V1') {
      throw new Error(
        `F2: denyWrite target was modified — content=${JSON.stringify(after)} ` +
          `exit=${w.status} stderr=${JSON.stringify(w.stderr)}`,
      )
    }
    // denyWrite leaves read open.
    const r = await runSandboxed(`type "${cfg}"`)
    expect(r.stdout.trim()).toBe('CONFIG-V1')
  })

  it('F3: child cannot delete the denyRead target (parent allow-list)', async () => {
    // cmd `del` exit code is UNRELIABLE on sharing-violation /
    // access-denied — gate on existence + content, not exit code.
    await runSandboxed(`del /f /q "${secret}"`)
    if (!existsSync(secret) || readFileSync(secret, 'utf8') !== 'TOP-SECRET') {
      throw new Error(`F3: child deleted the denyRead target`)
    }
  })

  it('F4: child cannot rename over the denyWrite target', async () => {
    const impostor = join(scratch, 'impostor.txt')
    await runSandboxed(`move /y "${impostor}" "${cfg}"`)
    const after = readFileSync(cfg, 'utf8')
    if (after !== 'CONFIG-V1') {
      throw new Error(
        `F4: rename-over succeeded — content=${JSON.stringify(after)}`,
      )
    }
    // Impostor should still be at its original path.
    expect(existsSync(impostor)).toBe(true)
  })

  it('F8: --holder-pid reaches exec (dir-fence diag in stderr)', async () => {
    const r = await runSandboxed('echo F8')
    // `srt-win exec --holder-pid` emits `dir fence: N/N dir(s)
    // fenced` to stderr when it engages. With at least one stamped
    // file, ≥1 parent dir + the state-DB dir are fenced.
    if (!/dir fence:\s*\d+\/\d+\s*dir/i.test(r.stderr)) {
      throw new Error(
        `F8: no dir-fence diag — --holder-pid not received? ` +
          `stderr=${JSON.stringify(r.stderr)}`,
      )
    }
  })

  it('F6: glob denyRead — *.env all denied (point-in-time)', async () => {
    // Re-init with a glob; the existing session must reset first.
    await SandboxManager.reset()
    const pattern = join(scratch, '*.env')
    // Sanity: expansion finds both files and rejects nothing.
    const expanded = expandWindowsFsDenyPaths([pattern])
    expect(expanded.sort()).toEqual(
      [join(scratch, 'a.env'), join(scratch, 'b.env')].sort(),
    )
    await SandboxManager.initialize(createFsTestConfig({ denyRead: [pattern] }))
    for (const f of ['a.env', 'b.env']) {
      const r = await runSandboxed(`type "${join(scratch, f)}"`)
      if (/ENV-/.test(r.stdout)) {
        throw new Error(
          `F6: child read ${f} via glob denyRead — ` +
            `stdout=${JSON.stringify(r.stdout)}`,
        )
      }
    }
  }, 30_000)

  // F5 overlaps smoke-acl A9/A11 (the Rust-level DACL round-trip).
  // Intentional defence-in-depth: those rows pin the srt-win
  // behaviour; this row pins that SandboxManager calls into it
  // correctly end-to-end (initialize→stamp, reset→restore).
  it('F5: reset() restores a target to its pre-stamp effective DACL', async () => {
    // The F6 session is active; reset it.
    await SandboxManager.reset()
    // Fresh subdir + fresh file → its parent has never been
    // stamp-cycled by an earlier F-row, so the before/stamped/after
    // capture is isolated from prior parent-restore inheritance
    // re-evaluation on the suite-shared `scratch`.
    const sub = mkdtempSync(join(scratch, 'f5-'))
    const tgt = join(sub, 'f5.txt')
    writeFileSync(tgt, 'F5')
    const before = captureEffectiveDacl(tgt)
    await SandboxManager.initialize(createFsTestConfig({ denyRead: [tgt] }))
    const stamped = captureEffectiveDacl(tgt)
    expect(stamped).not.toBe(before)
    await SandboxManager.reset()
    const after = captureEffectiveDacl(tgt)
    if (after !== before) {
      throw new Error(
        `F5: post-reset effective DACL differs from pre-stamp.\n` +
          `  before:  ${before}\n` +
          `  stamped: ${stamped}\n` +
          `  after:   ${after}`,
      )
    }
  }, 30_000)

  // F7 overlaps smoke-acl A19 (relocated → leftStamped at the
  // Rust level). Intentional defence-in-depth at the
  // SandboxManager↔srt-win integration boundary: smoke-acl pins
  // the Rust behaviour; this row pins that the TS plumbing
  // surfaces the same outcome.
  it('F7: relocated file → restore reports relocated, stays stamped', async () => {
    const reloc = join(scratch, 'reloc.txt')
    const sub = join(scratch, 'moved')
    mkdirSync(sub, { recursive: true })
    writeFileSync(reloc, 'RELOC')
    await SandboxManager.initialize(createFsTestConfig({ denyRead: [reloc] }))
    // Move from OUTSIDE the sandbox (the host does this; the
    // protection model says a file moved by the host is no longer
    // at its recorded path → restore must fail-closed).
    const movedTo = join(sub, 'reloc.txt')
    renameSync(reloc, movedTo)
    // Call restore directly so we can inspect the per-path
    // outcome (SandboxManager.reset() only logs it). This also
    // releases the holder, so the reset() below has nothing
    // left to restore.
    const out = restoreWindowsAcl({
      group: { groupSid: ADMINS_SID },
    })
    expect(out).toBeDefined()
    const entry = out!.paths.find(e => e.path.endsWith('reloc.txt'))
    if (!entry || entry.status !== 'relocated') {
      throw new Error(
        `F7: expected status=relocated, got ` + `${JSON.stringify(out!.paths)}`,
      )
    }
    expect(entry.leftStamped).toBe(true)
    expect(entry.movedTo).toMatch(/reloc\.txt$/i)
    // The relocated file must still be read-denied (stamp travels
    // with the inode). Stamp a fresh session so runSandboxed has a
    // sandbox to run under, then probe.
    await SandboxManager.reset()
    await SandboxManager.initialize(createFsTestConfig({}))
    const r = await runSandboxed(`type "${movedTo}"`)
    if (r.stdout.includes('RELOC')) {
      throw new Error(
        `F7: relocated file is readable after restore — stamp lost`,
      )
    }
    // Cleanup: move it back so a later `acl recover` can clear it.
    await SandboxManager.reset()
    renameSync(movedTo, reloc)
  }, 30_000)

  it('F9: changing fs via reset+initialize takes effect', async () => {
    const swap1 = join(scratch, 'swap1.txt')
    const swap2 = join(scratch, 'swap2.txt')
    writeFileSync(swap1, 'SWAP1')
    writeFileSync(swap2, 'SWAP2')
    await SandboxManager.initialize(createFsTestConfig({ denyRead: [swap1] }))
    expect((await runSandboxed(`type "${swap1}"`)).stdout).not.toMatch(/SWAP1/)
    expect((await runSandboxed(`type "${swap2}"`)).stdout).toMatch(/SWAP2/)
    // updateConfig with a different denyRead does NOT live-swap
    // (it warns); reset+initialize is the contract.
    await SandboxManager.reset()
    await SandboxManager.initialize(createFsTestConfig({ denyRead: [swap2] }))
    expect((await runSandboxed(`type "${swap1}"`)).stdout).toMatch(/SWAP1/)
    expect((await runSandboxed(`type "${swap2}"`)).stdout).not.toMatch(/SWAP2/)
    await SandboxManager.reset()
  }, 30_000)

  it('F10: filesystem.allowWrite throws on Windows (deny-only)', async () => {
    // eslint-disable-next-line @typescript-eslint/await-thenable -- bun:test types .rejects.toThrow() as void; the await is required at runtime
    await expect(
      SandboxManager.initialize(createFsTestConfig({ allowWrite: [scratch] })),
    ).rejects.toThrow(
      /allowWrite is not supported on Windows without windows.asSandboxUser/,
    )
    await SandboxManager.reset()
  })

  it('F11: per-exec deny via customConfig — stamped, denied, restored', async () => {
    // Session-level stamp on `secret` so we can assert it stays
    // intact across the per-exec stamp/restore cycle.
    writeFileSync(secret, 'TOP-SECRET')
    await SandboxManager.initialize(createFsTestConfig({ denyRead: [secret] }))
    const cred = join(scratch, 'f11-cred.txt')
    const fs2 = join(scratch, 'f11-fs.txt')
    writeFileSync(cred, 'F11-CRED')
    writeFileSync(fs2, 'F11-FS')
    // Pre: broker can read both (not yet stamped).
    expect(readFileSync(cred, 'utf8')).toBe('F11-CRED')
    // (a) credentials.files[mode=deny] — the original throw-case.
    const { argv: a1, env: e1 } = await SandboxManager.wrapWithSandboxArgv(
      `type "${cred}" & type "${secret}"`,
      undefined,
      { credentials: { files: [{ path: cred, mode: 'deny' }] } },
    )
    // The per-exec path made it onto the argv as a --deny-read
    // flag; the session-level path (already stamped) did NOT.
    expect(a1).toContain('--deny-read')
    expect(a1[a1.indexOf('--deny-read') + 1]).toContain('f11-cred.txt')
    expect(a1.filter(x => x === '--deny-read')).toHaveLength(1)
    const r1 = await spawnAsync(a1[0], a1.slice(1), {
      timeout: 30_000,
      env: e1,
    })
    if (r1.stdout.includes('F11-CRED')) {
      throw new Error(
        `F11(a): child read the per-exec credential deny target — ` +
          `stdout=${JSON.stringify(r1.stdout)} stderr=${JSON.stringify(r1.stderr)}`,
      )
    }
    if (r1.stdout.includes('TOP-SECRET')) {
      throw new Error(
        `F11(a): child read the SESSION-level denyRead target — ` +
          `session stamp lost during per-exec? ` +
          `stderr=${JSON.stringify(r1.stderr)}`,
      )
    }
    expect(r1.stderr).toMatch(/per-exec deny: holder_pid=\d+ → 1 path/)
    // Post: per-exec stamp restored on child exit. The broker
    // (this process) would read `cred` REGARDLESS (group enabled
    // → matches the broker-only DACL), so prove restore via a
    // SECOND sandboxed child with no per-exec deny — only true if
    // the stamp was lifted.
    const rR = await runSandboxed(`type "${cred}"`)
    if (!rR.stdout.includes('F11-CRED')) {
      throw new Error(
        `F11(a): per-exec stamp NOT restored — fresh child still ` +
          `denied. stdout=${JSON.stringify(rR.stdout)} ` +
          `stderr=${JSON.stringify(rR.stderr)}`,
      )
    }
    // Session-level stamp on `secret` survived: a fresh child
    // (no per-exec deny) is still denied.
    const rS = await runSandboxed(`type "${secret}"`)
    if (rS.stdout.includes('TOP-SECRET')) {
      throw new Error(
        `F11(a): session-level stamp on '${secret}' was torn down ` +
          `by the per-exec restore — refcount broken`,
      )
    }
    // (b) filesystem.denyRead — same mechanism, different config
    // key. Include the session-stamped `secret` to assert the
    // per-exec set is filtered against `windowsFsStampedSet` —
    // only `fs2` should reach the argv.
    const { argv: a2, env: e2 } = await SandboxManager.wrapWithSandboxArgv(
      `type "${fs2}"`,
      undefined,
      {
        filesystem: { denyRead: [secret, fs2], allowWrite: [], denyWrite: [] },
      },
    )
    const flags2 = a2.filter(x => x === '--deny-read')
    if (flags2.length !== 1) {
      throw new Error(
        `F11(b): expected exactly one --deny-read (session-stamped ` +
          `'${secret}' should be filtered out); got ${flags2.length}: ` +
          JSON.stringify(a2),
      )
    }
    expect(a2[a2.indexOf('--deny-read') + 1]).toContain('f11-fs.txt')
    const r2 = await spawnAsync(a2[0], a2.slice(1), {
      timeout: 30_000,
      env: e2,
    })
    if (r2.stdout.includes('F11-FS')) {
      throw new Error(
        `F11(b): child read the per-exec filesystem.denyRead target — ` +
          `stdout=${JSON.stringify(r2.stdout)} stderr=${JSON.stringify(r2.stderr)}`,
      )
    }
    const rR2 = await runSandboxed(`type "${fs2}"`)
    if (!rR2.stdout.includes('F11-FS')) {
      throw new Error(
        `F11(b): per-exec stamp NOT restored — fresh child still denied. ` +
          `stderr=${JSON.stringify(rR2.stderr)}`,
      )
    }
    await SandboxManager.reset()
  }, 60_000)

  it('F12: per-exec refuse-escalation — ReadDeny on a session-WriteDeny path fails the exec', async () => {
    // Session holds `cfg` at WriteDeny. A per-exec ReadDeny on the
    // same canonical path would escalate the on-disk mask; the
    // per-exec restore would then see refcount>0 (session holder)
    // and leave it ReadDeny for the rest of the session. The guard
    // lives in srt-win's `ensure_stamped` (refuse_escalation) — NOT
    // a TS string-compare — so canonical-path identity and
    // concurrent holders are authoritative. The exec FAILS rather
    // than silently stick the stricter mask.
    writeFileSync(cfg, 'CONFIG-V1')
    await SandboxManager.initialize(createFsTestConfig({ denyWrite: [cfg] }))
    const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
      `type "${cfg}"`,
      undefined,
      { filesystem: { denyRead: [cfg], allowWrite: [], denyWrite: [] } },
    )
    // The TS filter only drops same-or-stricter session matches;
    // ReadDeny-on-WriteDeny is forwarded to srt-win.
    expect(argv).toContain('--deny-read')
    const r = await spawnAsync(argv[0], argv.slice(1), {
      timeout: 30_000,
      env,
    })
    if (r.status === 0) {
      throw new Error(
        `F12: exec succeeded — refuse-escalation guard did not fire. ` +
          `stderr=${JSON.stringify(r.stderr)}`,
      )
    }
    if (!/would escalate .* from WriteDeny to ReadDeny/.test(r.stderr)) {
      throw new Error(
        `F12: expected refuse-escalation error in stderr; got ` +
          `status=${r.status} stderr=${JSON.stringify(r.stderr)}`,
      )
    }
    // Mask was NOT escalated: a fresh child (no per-exec deny) can
    // still read `cfg` (WriteDeny leaves read open). And the
    // session WriteDeny stamp survived the failed batch's rollback.
    const rR = await runSandboxed(`type "${cfg}"`)
    if (!rR.stdout.includes('CONFIG-V1')) {
      throw new Error(
        `F12: child cannot read a WriteDeny-only file — mask was ` +
          `escalated to ReadDeny despite refuse-escalation. ` +
          `stderr=${JSON.stringify(rR.stderr)}`,
      )
    }
    const rW = await runSandboxed(`echo POISON > "${cfg}"`)
    if (readFileSync(cfg, 'utf8').includes('POISON')) {
      throw new Error(
        `F12: session WriteDeny stamp was torn down by the failed ` +
          `per-exec batch's rollback. stderr=${JSON.stringify(rW.stderr)}`,
      )
    }
    await SandboxManager.reset()
  }, 60_000)

  it('F13: per-exec deny self-registers — --holder-pid only when session stamped', async () => {
    // Per-exec `--deny-*` stamps under the exec process's OWN
    // pid (`std::process::id()`), not a flag-passed holder. The
    // `--holder-pid` flag is the SESSION fence's holder and is
    // independent — present iff this session ran `acl stamp`
    // (windowsFsStampedSet set). Assert both halves so the two
    // concerns can't be re-coupled.
    await SandboxManager.reset()
    const f13 = join(scratch, 'f13.txt')
    writeFileSync(f13, 'F13')
    // (a) No session-level fs deny → windowsFsStampedSet is
    // undefined → no --holder-pid; per-exec deny still rides.
    await SandboxManager.initialize(createFsTestConfig({}))
    const { argv: aN } = await SandboxManager.wrapWithSandboxArgv(
      'exit 0',
      undefined,
      { filesystem: { denyRead: [f13], allowWrite: [], denyWrite: [] } },
    )
    if (aN.includes('--holder-pid')) {
      throw new Error(
        `F13(a): --holder-pid present with no session stamp — ` +
          `per-exec deny is not self-registering. argv=${JSON.stringify(aN)}`,
      )
    }
    expect(aN).toContain('--deny-read')
    await SandboxManager.reset()
    // (b) Session-level stamp → --holder-pid present (session
    // fence), independent of per-exec flags.
    writeFileSync(secret, 'TOP-SECRET')
    await SandboxManager.initialize(createFsTestConfig({ denyRead: [secret] }))
    const { argv: aS } = await SandboxManager.wrapWithSandboxArgv('exit 0')
    if (!aS.includes('--holder-pid')) {
      throw new Error(
        `F13(b): --holder-pid absent despite session stamp — ` +
          `session fence not engaged. argv=${JSON.stringify(aS)}`,
      )
    }
    expect(aS[aS.indexOf('--holder-pid') + 1]).toBe(`${process.pid}`)
    expect(aS).not.toContain('--deny-read')
    await SandboxManager.reset()
  }, 60_000)
})

// ────────────────────────────────────────────────────────────────────
// Group H — --as-sandbox-user two-hop launch (separate-user path)
//
// H0 is a pure argv-shape assertion (runs on every platform). H1+ do
// actual two-hop execs and are gated on
// `SRT_WIN_AS_SANDBOX_USER=1`: they need the `srt-sandbox` account
// provisioned, and the same-user E/B/C/D/F rows above must stay
// green regardless of whether the separate-user path is enabled.
// `vendor/srt-win-src/ci/smoke-exec.ps1` R1-R9b cover the two-hop
// end-to-end on every CI run; this block proves the TS plumbing on
// top once the path is enabled.
// ────────────────────────────────────────────────────────────────────

describe('Windows sandbox: --as-sandbox-user argv shape (pure, all platforms)', () => {
  it('H0: asSandboxUser:true adds --as-sandbox-user before --, omits when false', () => {
    const prev = process.env.SRT_WIN_PATH
    process.env.SRT_WIN_PATH = process.execPath
    try {
      const on = wrapCommandWithSandboxWindows({
        command: 'exit 0',
        group: { groupSid: ADMINS_SID },
        asSandboxUser: true,
        caCertPath: 'C:/ca.pem',
        httpProxyPort: 60080,
      })
      expect(on.argv).toContain('--as-sandbox-user')
      // CA trust is install-time, NEVER on the per-exec argv.
      expect(on.argv).not.toContain('--ca-trust')
      // Flags must precede `--` (clap stops parsing after it).
      expect(on.argv.indexOf('--as-sandbox-user')).toBeLessThan(
        on.argv.indexOf('--'),
      )
      // Two-hop overlay rides on --env: PATH + the single-sourced
      // proxy set. Values follow each --env as KEY=VALUE.
      const envArgs = on.argv.filter((_, i) => on.argv[i - 1] === '--env')
      expect(envArgs.some(e => e.startsWith('PATH='))).toBe(true)
      expect(envArgs).toContain('HTTP_PROXY=http://localhost:60080')
      // CA-bundle vars are NOT forwarded under asSandboxUser — the
      // bundle lives in broker %TEMP%, unreadable by srt-sandbox.
      // Schannel trust comes from `user trust-ca` instead.
      expect(envArgs.some(e => e.startsWith('NODE_EXTRA_CA_CERTS='))).toBe(
        false,
      )
      expect(envArgs.some(e => e.startsWith('SSL_CERT_FILE='))).toBe(false)
      // Every --env must precede `--`.
      expect(on.argv.lastIndexOf('--env')).toBeLessThan(on.argv.indexOf('--'))
      const off = wrapCommandWithSandboxWindows({
        command: 'exit 0',
        group: { groupSid: ADMINS_SID },
      })
      expect(off.argv).not.toContain('--as-sandbox-user')
      expect(off.argv).not.toContain('--env')
    } finally {
      if (prev === undefined) delete process.env.SRT_WIN_PATH
      else process.env.SRT_WIN_PATH = prev
    }
  })
})

const asSandboxUserEnabled = process.env.SRT_WIN_AS_SANDBOX_USER === '1'

describe.if(isWindows && asSandboxUserEnabled)(
  'Windows sandbox: --as-sandbox-user two-hop (H-rows)',
  () => {
    let exe: string
    let sbSid: string

    beforeAll(() => {
      exe = getSrtWinPath()
      // Full install under the test sublayer — provisions
      // srt-sandbox + cred + user-SID WFP filters. Idempotent.
      const inst = spawnSync(
        exe,
        [
          'install',
          '--group-sid',
          ADMINS_SID,
          '--sublayer-guid',
          TEST_SUBLAYER,
          '--proxy-port-range',
          `${PORT_RANGE[0]}-${PORT_RANGE[1]}`,
        ],
        { encoding: 'utf8' },
      )
      if (inst.status !== 0) {
        throw new Error(`srt-win install failed: ${inst.stderr || inst.stdout}`)
      }
      const us = getWindowsSandboxUserStatus()
      if (!us.provisioned || !us.sid || !us.credPresent) {
        throw new Error(
          `srt-sandbox not provisioned after install: ${JSON.stringify(us)}`,
        )
      }
      sbSid = us.sid
    })

    afterAll(() => {
      spawnSync(exe, ['uninstall', '--sublayer-guid', TEST_SUBLAYER], {
        encoding: 'utf8',
      })
    })

    async function rexec(tail: string) {
      const { argv, env } = wrapCommandWithSandboxWindows({
        command: tail,
        group: { groupSid: ADMINS_SID },
        asSandboxUser: true,
      })
      return spawnAsync(argv[0], argv.slice(1), {
        env,
        timeout: 60_000,
      })
    }

    it('H1: child runs as srt-sandbox (different user SID)', async () => {
      const r = await rexec('whoami /user /FO CSV /NH')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain(sbSid)
    }, 60_000)

    it('H2: stdout marker pipes through runner to broker', async () => {
      const r = await rexec('echo H2-STDOUT-MARK')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('H2-STDOUT-MARK')
    }, 60_000)

    it('H3: USERPROFILE isolated to srt-sandbox', async () => {
      const r = await rexec('echo %USERPROFILE%')
      expect(r.status).toBe(0)
      expect(r.stdout.toLowerCase()).toContain('srt-sandbox')
    }, 60_000)

    it('H4: direct outbound blocked by F-USER-BLOCK', async () => {
      const r = await rexec(
        'set "HTTP_PROXY=" & set "HTTPS_PROXY=" & set "ALL_PROXY=" & ' +
          'curl -sS -m 5 https://example.com',
      )
      // Exit-code only — see B/C convention: any non-zero is fenced.
      expect(r.status).not.toBe(0)
    }, 60_000)

    // ── H5-H8: FS parity under asSandboxUser via SandboxManager ──
    // The G-rows in smoke-exec.ps1 exercise the srt-win primitives
    // directly; these check the SandboxManager.initialize() →
    // grant + stamp → reset() → revoke + restore plumbing.
    let hScratch: string
    let hSecret: string
    let hSibling: string

    function createSbUserFsConfig(fs: FsOverrides): SandboxRuntimeConfig {
      const base = createFsTestConfig(fs)
      return { ...base, windows: { ...base.windows!, asSandboxUser: true } }
    }

    async function rexecSandboxed(cmd: string, fs: FsOverrides) {
      await SandboxManager.initialize(createSbUserFsConfig(fs))
      try {
        const wrapped = await SandboxManager.wrapWithSandboxArgv(cmd)
        return await spawnAsync(wrapped.argv[0], wrapped.argv.slice(1), {
          env: wrapped.env,
          timeout: 60_000,
        })
      } finally {
        await SandboxManager.reset()
      }
    }

    it('H5: allowWrite grants the working tree — child reads sibling', async () => {
      hScratch = mkdtempSync(join(tmpdir(), 'srt-h-'))
      hSecret = join(hScratch, 'secret.txt')
      hSibling = join(hScratch, 'sibling.txt')
      writeFileSync(hSecret, 'SECRET')
      writeFileSync(hSibling, 'SIBLING')
      const r = await rexecSandboxed(`type "${hSibling}"`, {
        allowWrite: [hScratch],
      })
      if (r.status !== 0 || !r.stdout.includes('SIBLING')) {
        throw new Error(
          `H5: child read sibling under allowWrite tree failed — ` +
            `exit=${r.status} stderr=${JSON.stringify(r.stderr)} ` +
            `stdout=${JSON.stringify(r.stdout)}`,
        )
      }
    }, 90_000)

    it('H6: allowWrite + denyRead — secret denied, sibling readable', async () => {
      const r = await rexecSandboxed(
        `type "${hSecret}" & echo --SEP-- & type "${hSibling}"`,
        { allowWrite: [hScratch], denyRead: [hSecret] },
      )
      if (r.stdout.includes('SECRET')) {
        throw new Error(
          `H6: child read the denyRead target under asSandboxUser — ` +
            `stdout=${JSON.stringify(r.stdout)}`,
        )
      }
      if (!r.stdout.includes('SIBLING')) {
        throw new Error(
          `H6: sibling unreadable post-stamp — ` +
            `stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr)}`,
        )
      }
    }, 90_000)

    it('H7: no allowWrite — child has no rights on real-user file', async () => {
      const r = await rexecSandboxed(`type "${hSibling}"`, {})
      if (r.status === 0 || r.stdout.includes('SIBLING')) {
        throw new Error(
          `H7: child read a real-user file with no grant — ` +
            `exit=${r.status} stdout=${JSON.stringify(r.stdout)}`,
        )
      }
    }, 90_000)

    it('H-glob: per-exec denyRead glob — expanded TS-side, both denied, restored', async () => {
      // Red→green for the per-exec/session-level glob asymmetry:
      // before this PR a per-exec `glob-*.secret` reached
      // `srt-win exec --deny-read` raw and `canonicalize_path`
      // hard-failed; now `wrapWithSandboxArgv` routes it through
      // `expandWindowsFsDenyPaths` (same chokepoint as session-
      // level) so the child sees two concrete `--deny-read` paths.
      const dir = mkdtempSync(join(tmpdir(), 'srt-hglob-'))
      const a = join(dir, 'glob-a.secret')
      const b = join(dir, 'glob-b.secret')
      writeFileSync(a, 'GLOB-A')
      writeFileSync(b, 'GLOB-B')
      await SandboxManager.initialize(
        createSbUserFsConfig({ allowWrite: [dir] }),
      )
      try {
        const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
          `type "${a}" & echo --SEP-- & type "${b}"`,
          undefined,
          {
            filesystem: {
              denyRead: [join(dir, 'glob-*.secret')],
              allowWrite: [],
              denyWrite: [],
            },
          },
        )
        // Glob expanded TS-side: exactly two --deny-read flags;
        // no glob char survives onto the argv (Rust would
        // hard-fail otherwise).
        const denyIdx = argv.flatMap((x, i) => (x === '--deny-read' ? [i] : []))
        if (denyIdx.length !== 2) {
          throw new Error(
            `H-glob: expected 2 --deny-read flags after glob expand; ` +
              `got ${denyIdx.length}: ${JSON.stringify(argv)}`,
          )
        }
        for (const i of denyIdx) {
          if (argv[i + 1].includes('*') || argv[i + 1].includes('?')) {
            throw new Error(
              `H-glob: glob char survived into --deny-read value ` +
                `'${argv[i + 1]}' — per-exec expand not applied`,
            )
          }
        }
        const r = await spawnAsync(argv[0], argv.slice(1), {
          env,
          timeout: 60_000,
        })
        if (r.stdout.includes('GLOB-A') || r.stdout.includes('GLOB-B')) {
          throw new Error(
            `H-glob: child read a glob-expanded deny target — ` +
              `stdout=${JSON.stringify(r.stdout)} stderr=${JSON.stringify(r.stderr)}`,
          )
        }
        // Per-exec restore: a fresh child (no customConfig) under
        // the same session can read both — proves the per-exec
        // stamp was lifted on child exit, not leaked onto disk.
        const wf = await SandboxManager.wrapWithSandboxArgv(
          `type "${a}" & type "${b}"`,
        )
        const rR = await spawnAsync(wf.argv[0], wf.argv.slice(1), {
          env: wf.env,
          timeout: 60_000,
        })
        if (!rR.stdout.includes('GLOB-A') || !rR.stdout.includes('GLOB-B')) {
          throw new Error(
            `H-glob: per-exec stamp NOT restored — fresh child still ` +
              `denied. stdout=${JSON.stringify(rR.stdout)} ` +
              `stderr=${JSON.stringify(rR.stderr)}`,
          )
        }
      } finally {
        await SandboxManager.reset()
        rmSync(dir, { recursive: true, force: true })
      }
    }, 120_000)

    it('H8: reset() revokes the grant — sandbox-user ACE gone', async () => {
      // After H5/H6/H7's reset() calls, the root's DACL must NOT
      // carry an explicit ACE for the sandbox user.
      const out = spawnSync('icacls', [hScratch], {
        encoding: 'utf8',
        timeout: 5_000,
      })
      if (out.stdout.includes(sbSid) || out.stdout.includes('srt-sandbox')) {
        throw new Error(
          `H8: srt-sandbox ACE still on '${hScratch}' after reset(): ` +
            out.stdout,
        )
      }
      rmSync(hScratch, { recursive: true, force: true })
    }, 30_000)
  },
)

type FsOverrides = Partial<SandboxRuntimeConfig['filesystem']>
