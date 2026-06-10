import { afterAll, beforeAll, describe, expect, it } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
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
  installWindowsSandbox,
  uninstallWindowsSandbox,
  deleteWindowsGroup,
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
 * `vendor/srt-win/ci/smoke-exec.ps1` which runs before this file in
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
 * EADDRINUSE. Used for the out-of-range loopback row: we need a
 * FIXED port outside the proxy range (Windows ephemeral ports are
 * 49152–65535, which overlaps the proxy range and is unstable for
 * a "definitely out of range" assertion).
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
    expect(SandboxManager.initialize(cfg)).rejects.toThrow(
      /one-time install.*npx sandbox-runtime windows-install/is,
    )
    await SandboxManager.reset()
  })

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
    // After uninstall+delete, both gone.
    expect(getWindowsWfpStatus({ sublayerGuid: sl }).state).toBe('absent')
    expect(getWindowsGroupStatus({ groupName: grp }).state).toBe('absent')
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

  it('wrapWithSandbox() throws on Windows (use wrapWithSandboxArgv)', () => {
    expect(SandboxManager.wrapWithSandbox('echo hi')).rejects.toThrow(
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

    // Standard proxy vars present and pointed at an in-range port.
    const httpProxy = env.HTTP_PROXY ?? env.http_proxy
    const allProxy = env.ALL_PROXY ?? env.all_proxy
    expect(httpProxy).toMatch(/^http:\/\/.+:\d+$/)
    expect(allProxy).toMatch(/^socks5h:\/\/.+:\d+$/)
    const httpPort = Number(httpProxy!.split(':').pop())
    const socksPort = Number(allProxy!.split(':').pop())
    expect(httpPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(httpPort).toBeLessThanOrEqual(PORT_RANGE[1])
    expect(socksPort).toBeGreaterThanOrEqual(PORT_RANGE[0])
    expect(socksPort).toBeLessThanOrEqual(PORT_RANGE[1])
    expect(httpPort).not.toBe(socksPort)

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
    // FIXED out-of-range port (50000, matching smoke.ps1) with
    // retry on EADDRINUSE. Binding ephemeral port 0 would land in
    // 49152–65535, which OVERLAPS the proxy range — sometimes
    // in-range (filter-2 PERMITs → wrong) and the `< lo` sanity
    // check flaked ~1/3 of runs.
    const l = await bindFirstFree([50000, 50001, 50002, 49500, 51000])
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
  // DESIGN NOTE / divergence from the donor: the donor's throwaway
  // SOCKS proxy required a per-launch secret, so even a same-user
  // host process was turned away at the handshake (donor D1/D2). Our
  // shared JS proxy has NO secret — it filters by DESTINATION. So:
  //   - a host (un-sandboxed, group-enabled) process CAN TCP-connect
  //     to the proxy port (WFP filter-1 PERMITs it) — donor D1's
  //     "connect fails" is therefore not reproduced;
  //   - but the proxy refuses any destination not in allowedDomains,
  //     regardless of caller — so it is never an open relay (D2).
  // The host using the proxy to reach an ALLOWED host is harmless:
  // the host user is unrestricted anyway.

  it.skipIf(!hasTool('curl'))(
    'D2: host curl --socks5 to proxy is not an open relay (disallowed host refused)',
    async () => {
      const socksPort = SandboxManager.getSocksProxyPort()
      expect(socksPort).toBeGreaterThan(0)

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
      const socks = (host: string): string[] => [
        '--socks5-hostname',
        `127.0.0.1:${socksPort}`,
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
