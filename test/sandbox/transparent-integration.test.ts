import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { resolve } from 'node:path'
import {
  hasTransparentPrereqs,
  canListenUnixSockets,
} from '../helpers/transparent.js'
import { spawnAsync } from '../helpers/spawn.js'
import { quote } from '../../src/utils/shell-quote.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'

/**
 * Full-stack transparent proxy test: real SandboxManager (host proxy +
 * unix bridge), real bwrap wrap, real egress to example.com — but the
 * client uses raw http/https.get and NEVER reads the proxy env vars.
 *
 * Requires: Linux, bwrap, the vendored netns-config + helper, host
 * AF_UNIX listeners (bridge + netns rendezvous), and network egress.
 * Skips itself where any of those are unavailable (e.g. sandboxed dev
 * environments). This is the test that exercises the PRODUCTION
 * rendezvous form (unix socket + SO_PEERCRED in netns-config).
 */

const CLIENT = resolve(import.meta.dir, '../fixtures/transparent/client.cjs')

function hasPrereqs(): boolean {
  // The bridge needs host-side AF_UNIX listeners on top of the shared
  // transparent prerequisites; some dev sandboxes deny socket(AF_UNIX).
  return hasTransparentPrereqs() && canListenUnixSockets()
}

const config: SandboxRuntimeConfig = {
  network: {
    allowedDomains: ['example.com'],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: [],
    allowWrite: ['/tmp'],
    denyWrite: [],
  },
}

describe.if(hasPrereqs())('transparent proxy full-stack integration', () => {
  beforeAll(async () => {
    await SandboxManager.initialize(config)
  })

  afterAll(async () => {
    await SandboxManager.reset()
  })

  async function runClient(url: string) {
    // `env -u`: the sandbox env intentionally carries HTTP(S)_PROXY as a
    // compatibility hint, but this test must prove the TRANSPARENT path,
    // and bun-based clients snapshot proxy env at startup. Strip at exec.
    const unsetArgs = [
      'HTTP_PROXY',
      'HTTPS_PROXY',
      'http_proxy',
      'https_proxy',
      'ALL_PROXY',
      'all_proxy',
    ].flatMap(v => ['-u', v])
    const wrapped = await SandboxManager.wrapWithSandbox(
      quote(['env', ...unsetArgs, process.execPath, CLIENT, url]),
    )
    const result = await spawnAsync('bash', ['-c', wrapped], {
      timeout: 30000,
    })
    SandboxManager.cleanupAfterCommand()
    return result
  }

  it('plain HTTP from a proxy-unaware client reaches an allowed domain', async () => {
    const r = await runClient('http://example.com/')
    expect(r.stderr).not.toContain('CLIENT-ERR')
    expect(r.stdout).toContain('CLIENT-OK')
    expect(r.stdout.toLowerCase()).toContain('example domain')
    expect(r.status).toBe(0)
  }, 40000)

  it('HTTPS passes through as an end-to-end TLS tunnel', async () => {
    const r = await runClient('https://example.com/')
    expect(r.stderr).not.toContain('CLIENT-ERR')
    expect(r.stdout).toContain('CLIENT-OK status=200')
    expect(r.stdout.toLowerCase()).toContain('example domain')
    expect(r.status).toBe(0)
  }, 40000)

  it('denies non-allowlisted domains at the host proxy', async () => {
    const r = await runClient('https://example.org/')
    expect(r.stdout).not.toContain('CLIENT-OK')
    expect(r.stderr).toContain('CLIENT-ERR')
    expect(r.status).not.toBe(0)
  }, 40000)
})

/**
 * Rendezvous fd lifecycle: each connection stages one temporary fd that
 * is handed to the config child. Ownership rules differ per runtime
 * (bun's Subprocess releases a numeric stdio fd itself after a
 * successful spawn; a failed spawn is reclaimed by the host). Two
 * regressions this pins: unconditional manual close (a later runtime
 * release then lands on a REUSED fd number — unrelated host fds die),
 * and unconditional never-close (one fd retained per connection —
 * unbounded growth).
 */
describe.if(hasPrereqs())('rendezvous fd lifecycle', () => {
  it('fd table returns near baseline and unrelated fds survive', async () => {
    const { initializeNetnsRendezvous } = await import(
      '../../src/sandbox/linux-sandbox-utils.js'
    )
    const fsMod = await import('node:fs')
    const netMod = await import('node:net')
    const fdCount = () => fsMod.readdirSync('/proc/self/fd').length
    const ctx = await initializeNetnsRendezvous('fd-lifecycle-token')
    const baseline = fdCount()
    const canaries: number[] = []
    const CONNS = 20
    for (let i = 0; i < CONNS; i++) {
      await new Promise<void>((resolvePromise, reject) => {
        const s = netMod.connect(ctx.socketPath)
        s.once('connect', () => s.write('fd-lifecycle-token 12345\n'))
        s.once('close', () => resolvePromise())
        s.once('error', reject)
        setTimeout(() => {
          s.destroy()
          resolvePromise()
        }, 3000)
      })
      // Unrelated host fd opened between connections: a stray release
      // of a recycled fd number would hit one of these.
      canaries.push(fsMod.openSync('/etc/hostname', 'r'))
    }
    // Let the runtime run its deferred releases.
    if (typeof Bun !== 'undefined') {
      Bun.gc(true)
      await new Promise(r => setTimeout(r, 200))
      Bun.gc(true)
    }
    let dead = 0
    for (const c of canaries) {
      try {
        fsMod.fstatSync(c)
      } catch {
        dead++
      }
    }
    const after = fdCount() - canaries.length
    for (const c of canaries) {
      try {
        fsMod.closeSync(c)
      } catch {
        // counted above
      }
    }
    await ctx.close()
    expect(dead).toBe(0)
    // Allow slack for the staged master fd and transient sockets, but
    // per-connection retention (>= CONNS) must fail.
    expect(after - baseline).toBeLessThan(CONNS / 2)
  }, 30000)
})
