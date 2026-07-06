/**
 * Node-host leg of the captured-plaintext pipeline checks.
 *
 * CI unit tests run under bun, but the production embedder hosts the
 * proxy on node — the crash-sensitive paths (denied body teardown,
 * aborted uploads, smuggling-shape rejection) must be exercised on the
 * runtime that actually ships them. Bundled with `bun build
 * --target=node` and executed with `node` in CI.
 */
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { connect } from 'node:net'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'

const TOKEN = 'node-leg-token'
const AUTH = Buffer.from(`srt:${TOKEN}`).toString('base64')

function fail(msg: string): never {
  console.error(`FAIL: ${msg}`)
  process.exit(1)
}

// A hung battery must fail red, not eat the CI job's default timeout.
setTimeout(() => fail('watchdog: battery exceeded 60s'), 60_000).unref?.()

const upstreamPaths: string[] = []
const upstream = createServer((req, res) => {
  upstreamPaths.push(req.url ?? '')
  res.writeHead(200)
  res.end(`upstream saw ${req.url}`)
})
await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
const upstreamPort = (upstream.address() as AddressInfo).port

const proxy = createHttpProxyServer({
  filter: (_port: number, host: string) => host === '127.0.0.1',
  proxyAuthToken: TOKEN,
  filterRequest: async (req: { url: string }) =>
    new URL(req.url).pathname === '/blocked'
      ? { action: 'deny' as const, reason: 'node-leg-blocked' }
      : { action: 'allow' as const },
})
await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
const proxyPort = (proxy.address() as AddressInfo).port

function tunnel(): Promise<{
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
          const i = buf.indexOf(w.until) + w.until.length
          const chunk = buf.slice(0, i)
          buf = buf.slice(i)
          w.cb(chunk)
        }
      })
      // A torn-down tunnel must flush pending readers (with whatever
      // buffered) instead of leaving the battery waiting forever.
      sock.on('close', () => {
        for (const w of waiters.splice(0)) w.cb(buf)
      })
      sock.write(
        `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${upstreamPort}\r\n` +
          `Proxy-Authorization: Basic ${AUTH}\r\n` +
          'X-SRT-Captured-Plaintext: 1\r\n\r\n',
      )
      resolve({
        write: s => void sock.write(s),
        read: until =>
          new Promise(cb => {
            if (buf.includes(until)) {
              const i = buf.indexOf(until) + until.length
              const chunk = buf.slice(0, i)
              buf = buf.slice(i)
              cb(chunk)
              return
            }
            waiters.push({ until, cb })
          }),
        end: () => sock.destroy(),
      })
    })
    sock.on('error', reject)
  })
}

// 1. Denied POST with full body: 403 delivered, no crash.
{
  const t = await tunnel()
  await t.read('\r\n\r\n')
  t.write('POST /blocked HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello')
  const resp = await t.read('node-leg-blocked')
  if (!resp.includes('403')) fail(`deny body: expected 403, got: ${resp}`)
  t.end()
}

// 2. Aborted mid-body upload: no host crash.
{
  const t = await tunnel()
  await t.read('\r\n\r\n')
  t.write('POST /t HTTP/1.1\r\nHost: h\r\nContent-Length: 99999\r\n\r\npartial')
  await new Promise(r => setTimeout(r, 100))
  t.end()
  await new Promise(r => setTimeout(r, 150))
}

// 3. Smuggling shapes rejected, upstream never sees them.
for (const shape of [
  'POST /s1 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n',
  'POST /s2 HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nAAAA',
  'POST /s3 HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n abc\r\n\r\n0\r\n\r\n',
  'POST /s4 HTTP/1.1\rHost: h\r\nContent-Length: 4\r\n\r\nAAAA',
]) {
  const t = await tunnel()
  await t.read('\r\n\r\n')
  t.write(shape)
  const resp = await t.read('\r\n')
  if (!/HTTP\/1\.[01] (4\d\d|505)/.test(resp)) {
    fail(`smuggle shape not rejected: ${resp.slice(0, 60)}`)
  }
  t.end()
}
if (upstreamPaths.some(p => p.startsWith('/s'))) {
  fail(`upstream saw smuggled path: ${upstreamPaths.join(',')}`)
}

// 4. Pipeline still healthy end-to-end afterwards.
{
  const t = await tunnel()
  await t.read('\r\n\r\n')
  t.write('GET /healthy HTTP/1.1\r\nHost: x\r\n\r\n')
  const resp = await t.read('upstream saw /healthy')
  if (!resp.includes('200')) fail(`post-battery health check: ${resp}`)
  t.end()
}

console.log('NODE-LEG: PASS')
process.exit(0)
