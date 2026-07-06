import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { createServer, type Server } from 'node:http'
import { connect, type AddressInfo } from 'node:net'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'

/**
 * Host-side test of the captured-plaintext pipeline: a CONNECT carrying
 * X-SRT-Captured-Plaintext (as the transparent helper sends for non-443
 * captures) must route the tunnel's origin-form requests through the full
 * request pipeline — filterRequest, Host rewriting to the CONNECT target,
 * readable 403 bodies — instead of an opaque byte tunnel.
 */

/** bun < 1.4 throws (instead of emitting) 'aborted' inside its http
 * internals when a request is destroyed mid-body; fixed in 1.4.0. */
function bunThrowsOnAbortedBody(): boolean {
  const v = process.versions.bun
  if (!v) return false
  const [major = 0, minor = 0] = v.split('.').map(Number)
  return major < 1 || (major === 1 && minor < 4)
}

const TOKEN = 'capture-test-token'
const AUTH = `Basic ${Buffer.from(`srt:${TOKEN}`).toString('base64')}`

let upstream: Server
let upstreamPort: number
const upstreamPaths: string[] = []
let proxy: Server
let proxyPort: number

/** Open a raw connection to the proxy and run a CONNECT handshake. */
function dialTunnel(opts: {
  auth?: string
  captured?: boolean
  targetPort?: number
}): Promise<{
  write: (s: string) => void
  read: (until: string) => Promise<string>
  end: () => void
}> {
  return new Promise((resolve, reject) => {
    const sock = connect(proxyPort, '127.0.0.1', () => {
      let buf = ''
      const waiters: Array<{ until: string; cb: (s: string) => void }> = []
      sock.setEncoding('utf8')
      sock.on('data', d => {
        buf += d
        while (waiters.length > 0 && buf.includes(waiters[0]!.until)) {
          const w = waiters.shift()!
          const idx = buf.indexOf(w.until) + w.until.length
          const chunk = buf.slice(0, idx)
          buf = buf.slice(idx)
          w.cb(chunk)
        }
      })
      const api = {
        write: (s: string) => sock.write(s),
        read: (until: string) =>
          new Promise<string>(cb => {
            if (buf.includes(until)) {
              const idx = buf.indexOf(until) + until.length
              const chunk = buf.slice(0, idx)
              buf = buf.slice(idx)
              cb(chunk)
              return
            }
            waiters.push({ until, cb })
          }),
        end: () => sock.destroy(),
      }
      const target = `127.0.0.1:${opts.targetPort ?? upstreamPort}`
      sock.write(
        `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n` +
          (opts.auth ? `Proxy-Authorization: ${opts.auth}\r\n` : '') +
          (opts.captured ? 'X-SRT-Captured-Plaintext: 1\r\n' : '') +
          '\r\n',
      )
      resolve(api)
    })
    sock.on('error', reject)
  })
}

describe('captured plaintext tunnel pipeline', () => {
  beforeAll(async () => {
    upstream = createServer((req, res) => {
      upstreamPaths.push(req.url ?? '')
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(`upstream saw ${req.method} ${req.url} host=${req.headers.host}`)
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      // Allow only the upstream loopback target in this test.
      filter: (_port, host) => host === '127.0.0.1',
      proxyAuthToken: TOKEN,
      filterRequest: async req => {
        const url = new URL(req.url)
        return url.pathname === '/blocked'
          ? { action: 'deny', reason: 'blocked-by-test' }
          : { action: 'allow' }
      },
      mutateHeadersPlaintext: headers => {
        headers['x-injected'] = 'yes'
      },
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', r))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    proxy.closeAllConnections?.()
    upstream.closeAllConnections?.()
    await Promise.all([
      new Promise(r => proxy.close(r)),
      new Promise(r => upstream.close(r)),
    ])
  })

  it('parses origin-form requests and forwards to the CONNECT target', async () => {
    const t = await dialTunnel({ auth: AUTH, captured: true })
    expect(await t.read('\r\n\r\n')).toContain('200 Connection Established')
    // Spoofed Host header must not redirect: the target is the CONNECT's.
    t.write('GET /hello HTTP/1.1\r\nHost: spoofed.example\r\n\r\n')
    const resp = await t.read(`host=127.0.0.1:${upstreamPort}`)
    expect(resp).toContain('HTTP/1.1 200')
    expect(resp).toContain('upstream saw GET /hello')
    t.end()
  })

  it('applies filterRequest with a readable 403 inside the tunnel', async () => {
    const t = await dialTunnel({ auth: AUTH, captured: true })
    await t.read('\r\n\r\n')
    t.write('GET /blocked HTTP/1.1\r\nHost: x\r\n\r\n')
    const resp = await t.read('blocked-by-test')
    expect(resp).toContain('HTTP/1.1 403')
    t.end()
  })

  it('keeps the tunnel alive across a denied request (keep-alive 403)', async () => {
    // A denied request must yield its 403 and leave the shared tunnel
    // usable for subsequent requests (the deny path used to destroy the
    // backend socket, killing the queued 403 and the connection).
    // Sequential keep-alive: bun's server chokes on pipelined BURSTS
    // through this double-pipe topology (node handles them; verified
    // separately), and pipelining isn't the property under test.
    const t = await dialTunnel({ auth: AUTH, captured: true })
    await t.read('\r\n\r\n')
    t.write('GET /a HTTP/1.1\r\nHost: x\r\n\r\n')
    const first = await t.read('upstream saw GET /a')
    expect(first).toContain('HTTP/1.1 200')
    t.write('GET /blocked HTTP/1.1\r\nHost: x\r\n\r\n')
    const denied = await t.read('blocked-by-test')
    expect(denied).toContain('HTTP/1.1 403')
    t.write('GET /b HTTP/1.1\r\nHost: x\r\n\r\n')
    const third = await t.read('upstream saw GET /b')
    expect(third).toContain('200')
    t.end()
  })

  it('denied body-carrying request gets its 403 and does not crash the host', async () => {
    // Regression: deny + full POST body used to throw
    // ERR_INVALID_STATE inside node's webstream tee pump (uncaught,
    // host-fatal), and an aborted body threw 'aborted'. The 403 must
    // still be DELIVERED before the connection closes.
    const t = await dialTunnel({ auth: AUTH, captured: true })
    await t.read('\r\n\r\n')
    t.write(
      'POST /blocked HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello',
    )
    const denied = await t.read('blocked-by-test')
    expect(denied).toContain('HTTP/1.1 403')
    t.end()
    // Aborted mid-body upload must not take the process down either.
    // (bun < 1.4 throws 'aborted' inside its own http internals here —
    // a runtime bug fixed in 1.4.0; node is verified by the bundled
    // crash repro. Skip only the abort sub-case on old bun.)
    if (!bunThrowsOnAbortedBody()) {
      const t2 = await dialTunnel({ auth: AUTH, captured: true })
      await t2.read('\r\n\r\n')
      t2.write(
        'POST /t HTTP/1.1\r\nHost: h\r\nContent-Length: 99999\r\n\r\npartial',
      )
      await new Promise(r => setTimeout(r, 100))
      t2.end()
      await new Promise(r => setTimeout(r, 150))
    }
    // Reaching here without an uncaughtException IS the assertion; prove
    // the proxy still works end-to-end afterwards.
    const t3 = await dialTunnel({ auth: AUTH, captured: true })
    await t3.read('\r\n\r\n')
    t3.write('GET /after HTTP/1.1\r\nHost: x\r\n\r\n')
    expect(await t3.read('upstream saw GET /after')).toContain('200')
    t3.end()
  })

  it('rejects request-smuggling shapes (llhttp CVE lineage — hard-close)', async () => {
    // The filter's decision must never rest on a parse the upstream
    // could disagree with. Node's post-CVE parser rejects these; pin
    // that behavior so a runtime downgrade or lenient flag regression
    // is caught. None of these may reach the upstream.
    const shapes = [
      // TE + CL together
      'POST /smuggle1 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n',
      // duplicate Content-Length
      'POST /smuggle2 HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nAAAA',
      // obs-fold / multiline Transfer-Encoding
      'POST /smuggle3 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n abc\r\n\r\n0\r\n\r\n',
      // bare-CR header delimiter (CVE-2023-30589 shape)
      'POST /smuggle4 HTTP/1.1\rHost: h\r\nContent-Length: 4\r\n\r\nAAAA',
    ]
    for (const shape of shapes) {
      const t = await dialTunnel({ auth: AUTH, captured: true })
      await t.read('\r\n\r\n')
      t.write(shape)
      // Each shape must be REJECTED (4xx) — read the status line rather
      // than sleeping (sleep-based sync could false-pass).
      const resp = await t.read('\r\n')
      // 4xx normally; bun rejects the bare-CR shape as 505 (malformed
      // version) — any non-2xx rejection is the pinned property.
      expect(resp).toMatch(/HTTP\/1\.[01] (4\d\d|505)/)
      t.end()
    }
    // Prove the upstream never observed any smuggled path: it echoes
    // every request it sees, so a follow-up probe shares its state.
    const probe = await dialTunnel({ auth: AUTH, captured: true })
    await probe.read('\r\n\r\n')
    probe.write('GET /post-shapes-probe HTTP/1.1\r\nHost: x\r\n\r\n')
    const resp = await probe.read('upstream saw GET /post-shapes-probe')
    expect(resp).toContain('200')
    expect(upstreamPaths.some(p => p.includes('smuggle'))).toBe(false)
    probe.end()
  })

  it('rejects absolute-form requests inside a captured tunnel', async () => {
    const t = await dialTunnel({ auth: AUTH, captured: true })
    await t.read('\r\n\r\n')
    t.write(`GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n`)
    const resp = await t.read('origin-form')
    expect(resp).toContain('HTTP/1.1 400')
    t.end()
  })

  it('still requires CONNECT auth when the captured flag is set', async () => {
    const t = await dialTunnel({ captured: true })
    const resp = await t.read('\r\n\r\n')
    expect(resp).toContain('407')
    t.end()
  })

  it('keeps unflagged CONNECTs as opaque tunnels', async () => {
    const t = await dialTunnel({ auth: AUTH })
    expect(await t.read('\r\n\r\n')).toContain('200 Connection Established')
    // Raw HTTP through the opaque tunnel reaches the upstream verbatim —
    // including the spoofed Host (no parsing, classic behavior).
    t.write('GET /opaque HTTP/1.1\r\nHost: spoofed.example\r\n\r\n')
    const resp = await t.read('host=spoofed.example')
    expect(resp).toContain('upstream saw GET /opaque')
    t.end()
  })

  it('injects plaintext headers on captured requests', async () => {
    // Repoint upstream assertion: x-injected must arrive. Restore the
    // original handlers after — the shared server must not leak state
    // into any test that runs later.
    const original = upstream.listeners('request')
    const seen: string[] = []
    upstream.removeAllListeners('request')
    upstream.on('request', (req, res) => {
      seen.push(String(req.headers['x-injected']))
      res.writeHead(200)
      res.end(`done host=${req.headers.host}`)
    })
    try {
      const t = await dialTunnel({ auth: AUTH, captured: true })
      await t.read('\r\n\r\n')
      t.write('GET /inj HTTP/1.1\r\nHost: x\r\n\r\n')
      await t.read('done host=')
      expect(seen).toEqual(['yes'])
      t.end()
    } finally {
      upstream.removeAllListeners('request')
      for (const l of original) upstream.on('request', l as never)
    }
  })
})
