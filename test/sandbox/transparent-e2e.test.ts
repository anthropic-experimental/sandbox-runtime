import { describe, it, expect } from 'bun:test'
import { spawn, execFileSync, execSync } from 'node:child_process'
import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { hasTransparentPrereqs } from '../helpers/transparent.js'
import {
  getSandboxResolvConfPath,
  transparentAssetParentCandidates,
} from '../../src/sandbox/transparent-net.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { getVendorSeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'

/**
 * End-to-end test of transparent capture with the PRODUCTION mechanism:
 * the HOST (this test process) configures bwrap's netns from outside via
 * the vendored netns-config (setns; --pid test mode, since the
 * production unix-socket rendezvous needs AF_UNIX listeners some dev
 * sandboxes deny — CI integration covers that form):
 *
 *   bwrap --unshare-net                      (outer deny boundary)
 *     driver.cjs: writes netns inode → waits for host configuration →
 *       fake CONNECT proxy on 127.0.0.1:18080 + helper-hello OK stub
 *         transparent-net-helper (stub DNS :53 + capture :80/:443)
 *           client.cjs: raw http.get — NO proxy env vars
 *   test: reads inode → finds the sandbox pid by netns-inode scan →
 *     netns-config --pid <pid> <inode> → signals done
 *
 * The fake proxy answers each tunnel with a body naming the CONNECT
 * target, so assertions prove the helper recovered the right destination
 * from the stub-DNS fake IP (or the raw IP literal).
 */

const FIXTURES = resolve(import.meta.dir, '../fixtures/transparent')
const HELPER = resolve(
  import.meta.dir,
  '../../src/sandbox/transparent-net-helper.ts',
)

/** bun < 1.4 ignores server-side allowHalfOpen; fixed in 1.4.0. */
function bunLacksServerAllowHalfOpen(): boolean {
  const v = process.versions.bun
  if (!v) return false
  const [major = 0, minor = 0] = v.split('.').map(Number)
  return major < 1 || (major === 1 && minor < 4)
}

describe.if(hasTransparentPrereqs())('transparent proxy e2e (in-bwrap)', () => {
  // The production resolv.conf helper, so the e2e exercises the same file
  // content the real wrapper bind-mounts.
  const resolvPath = getSandboxResolvConfPath()

  /** Find the host-view pid whose netns inode matches. */
  function findPidByNetnsInode(inode: string): number | null {
    for (const entry of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(entry)) continue
      try {
        const link = fs.readlinkSync(`/proc/${entry}/ns/net`)
        if (link === `net:[${inode}]`) return Number(entry)
      } catch {
        // raced exit or not ours — skip
      }
    }
    return null
  }

  async function runClient(url: string, clientFile = 'client.cjs') {
    const netnsConfig = getVendorSeccompBinaryPath('netns-config')!
    const rdvDir = fs.mkdtempSync(join(tmpdir(), 'srt-e2e-rdv-'))
    const args = [
      '--bind',
      '/',
      '/',
      '--bind',
      rdvDir,
      rdvDir,
      '--ro-bind',
      resolvPath,
      '/etc/resolv.conf',
      '--dev',
      '/dev',
      '--proc',
      '/proc',
      '--unshare-net',
      '--unshare-pid',
      '--die-with-parent',
      '--',
      process.execPath,
      join(FIXTURES, 'driver.cjs'),
    ]
    // Strip proxy env vars at spawn time: bun snapshots them at process
    // startup, so the client fixture's in-process delete is not enough
    // when the tests run under bun.
    const env: NodeJS.ProcessEnv = {
      SRT_TP_HELPER: HELPER,
      SRT_TP_CLIENT: join(FIXTURES, clientFile),
      SRT_TP_URL: url,
      SRT_TP_RDV_DIR: rdvDir,
    }
    for (const [k, v] of Object.entries(process.env)) {
      if (!/^(https?_proxy|all_proxy|no_proxy)$/i.test(k)) env[k] ??= v
    }

    try {
      return await new Promise<{
        stdout: string
        stderr: string
        status: number | null
      }>((resolvePromise, reject) => {
        const child = spawn('bwrap', args, { env })
        let stdout = ''
        let stderr = ''
        child.stdout.on('data', d => (stdout += String(d)))
        child.stderr.on('data', d => (stderr += String(d)))
        const timeout = setTimeout(() => {
          child.kill('SIGKILL')
        }, 25000)

        // Host side of the handshake: wait for the driver's inode file,
        // configure the sandbox netns, signal done.
        const inodeFile = join(rdvDir, 'inode')
        const poll = setInterval(() => {
          if (!fs.existsSync(inodeFile)) return
          clearInterval(poll)
          try {
            const inode = fs.readFileSync(inodeFile, 'utf8').trim()
            const pid = findPidByNetnsInode(inode)
            if (pid === null) throw new Error(`no pid with netns ${inode}`)
            execFileSync(netnsConfig, ['--pid', String(pid), inode], {
              stdio: 'pipe',
              timeout: 5000,
            })
            fs.writeFileSync(join(rdvDir, 'done'), '')
          } catch (err) {
            stderr += `HARNESS-ERR ${(err as Error).message}\n`
            child.kill('SIGKILL')
          }
        }, 50)

        child.on('error', err => {
          clearTimeout(timeout)
          clearInterval(poll)
          reject(err)
        })
        child.on('exit', (code, sig) => {
          clearTimeout(timeout)
          clearInterval(poll)
          resolvePromise({ stdout, stderr, status: sig ? null : code })
        })
      })
    } finally {
      fs.rmSync(rdvDir, { recursive: true, force: true })
    }
  }

  it('routes a hostname dial through stub DNS + capture + CONNECT', async () => {
    const r = await runClient('http://tp-e2e.test/hello')
    expect(r.stderr).not.toContain('CLIENT-ERR')
    expect(r.stdout).toContain('CLIENT-OK status=200')
    expect(r.stdout).toContain('tunnel-ok target=tp-e2e.test:80')
    // helper authenticated to the proxy with the srt token form
    expect(r.stdout).toContain('auth=srt:e2e-test-token')
    // port-80 captures are marked as plaintext for the host pipeline
    expect(r.stdout).toContain('cp=1')
    expect(r.status).toBe(0)
  }, 30000)

  it('captures raw IP-literal destinations (no DNS involved)', async () => {
    const r = await runClient('http://203.0.113.9/x')
    expect(r.stdout).toContain('CLIENT-OK status=200')
    expect(r.stdout).toContain('tunnel-ok target=203.0.113.9:80')
    expect(r.status).toBe(0)
  }, 30000)

  it('fails closed (fast ECONNREFUSED) on uncaptured ports', async () => {
    const start = Date.now()
    const r = await runClient('http://tp-e2e.test:8080/x')
    expect(r.stdout).not.toContain('CLIENT-OK')
    expect(r.stderr).toContain('ECONNREFUSED')
    expect(r.status).not.toBe(0)
    // refused locally, not a hang-until-timeout
    expect(Date.now() - start).toBeLessThan(10000)
  }, 30000)

  // Skipped under bun < 1.4: those versions ignore net.createServer's
  // allowHalfOpen (the accepted socket closes on client FIN without even
  // delivering data sent in the same packet — repro: server
  // {allowHalfOpen:true}, client write+end, node delivers REQ + 'end',
  // old bun delivers nothing). Fixed in bun 1.4.0. The helper runs on
  // process.execPath in this test, so the gate tracks the test runtime.
  it.skipIf(bunLacksServerAllowHalfOpen())(
    'preserves half-close: FIN after request still gets the response',
    async () => {
      const r = await runClient('http://tp-e2e.test/hc', 'client-halfclose.cjs')
      expect(r.stderr).not.toContain('CLIENT-ERR')
      expect(r.stderr).not.toContain('CLIENT-TIMEOUT')
      expect(r.stdout).toContain('CLIENT-OK halfclose')
      expect(r.stdout).toContain('tunnel-ok target=tp-e2e.test:80')
      expect(r.status).toBe(0)
    },
    30000,
  )

  it('never forwards loopback destinations to the proxy', async () => {
    // 127.0.0.5:80 lands on the wildcard capture listener (no in-sandbox
    // server is bound there), but loopback must stay inside the namespace
    // — the helper destroys it instead of issuing CONNECT 127.0.0.5:80.
    const r = await runClient('http://127.0.0.5/x')
    expect(r.stdout).not.toContain('CLIENT-OK')
    expect(r.stdout).not.toContain('tunnel-ok')
    // Positive anchor: the client RAN and its connection was actively
    // terminated by the helper (not some unrelated harness failure).
    expect(r.stderr).toContain('CLIENT-ERR')
    expect(r.status).not.toBe(0)
  }, 30000)

  it('creates absent asset-parent candidates so ro-root sandboxes still launch', async () => {
    // A candidate that exists only as a --tmpfs target would make bwrap
    // fail ('Can't mkdir ... Read-only file system') on hosts where the
    // pinned parent is elsewhere and the write config leaves the
    // candidate's parent read-only. The wrap must pre-create every
    // candidate host-side.
    const freshTmp = fs.mkdtempSync(join(tmpdir(), 'srt-cand-'))
    const prevTmpdir = process.env.TMPDIR
    process.env.TMPDIR = freshTmp
    try {
      const cmd = await wrapCommandWithSandboxLinux({
        command: 'echo candidates-ok',
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: [process.cwd()], denyWithinAllow: [] },
      })
      for (const parent of transparentAssetParentCandidates()) {
        expect(fs.existsSync(parent)).toBe(true)
        expect(cmd).toContain(`--tmpfs ${parent}`)
      }
      const out = execSync(cmd, {
        timeout: 20_000,
        encoding: 'utf8',
        stdio: 'pipe',
      })
      expect(out).toContain('candidates-ok')
    } finally {
      if (prevTmpdir === undefined) delete process.env.TMPDIR
      else process.env.TMPDIR = prevTmpdir
      fs.rmSync(freshTmp, { recursive: true, force: true })
    }
  })

  it('netns-config REFUSES to configure the host netns (TPROXY-catastrophe guard)', () => {
    // The classic unscoped-local-route disaster (operators killing their
    // own connectivity) is excluded by this exact refusal: even a
    // correct pid+inode pair naming OUR OWN namespace must be rejected.
    const netnsConfig = getVendorSeccompBinaryPath('netns-config')!
    const ino = /net:\[(\d+)\]/.exec(fs.readlinkSync('/proc/self/ns/net'))![1]!
    let failed = false
    let stderr = ''
    try {
      execFileSync(netnsConfig, ['--pid', String(process.pid), ino], {
        stdio: 'pipe',
        timeout: 5000,
      })
    } catch (err) {
      failed = true
      stderr = String((err as { stderr?: Buffer }).stderr ?? '')
    }
    expect(failed).toBe(true)
    expect(stderr).toContain('refusing to configure the host netns')
  })

  it('surfaces a proxy refusal as a reset, not a hang', async () => {
    // driver.cjs answers CONNECTs to refused.test with 403 — the helper
    // must abort the captured connection (non-200 path).
    const start = Date.now()
    const r = await runClient('http://refused.test/x')
    expect(r.stdout).not.toContain('CLIENT-OK')
    expect(r.stderr).toContain('CLIENT-ERR')
    expect(r.status).not.toBe(0)
    expect(Date.now() - start).toBeLessThan(10000)
  }, 30000)
})
