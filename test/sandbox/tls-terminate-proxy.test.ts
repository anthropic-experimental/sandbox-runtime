import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import type { Server, AddressInfo } from 'node:net'
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

// Drive the proxy with curl so we exercise a real CONNECT-through-proxy
// client. (Bun's https.request ignores createConnection, so an in-process
// client would bypass the proxy.)
describe('tls-terminate-proxy: end-to-end through createHttpProxyServer', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  // Upstream HTTPS server. Uses a leaf cert for 127.0.0.1 signed by the
  // fixture CA; the proxy's outbound https.request trusts it via
  // tlsTerminateUpstreamCA. Leaf-only — Bun's TLS client mis-verifies when
  // the root CA is appended to the server chain.
  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number

  beforeAll(async () => {
    const upCert = mintLeafCert(ca, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        let body = ''
        req.on('data', c => (body += c))
        req.on('end', () => {
          res.writeHead(200, {
            'content-type': 'application/json',
            'x-upstream': 'ok',
          })
          res.end(
            JSON.stringify({
              echoed: body,
              path: req.url,
              method: req.method,
              host: req.headers.host,
            }),
          )
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    proxyPort = (proxy.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => proxy.close(() => r()))
    await new Promise<void>(r => upstream.close(() => r()))
  })

  test('terminates client TLS, forwards request, pipes response back', async () => {
    const r = await curlViaProxy(
      proxyPort,
      `https://127.0.0.1:${upstreamPort}/hello?a=1`,
      {
        method: 'POST',
        body: 'hi-from-client',
      },
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(r.headers['x-upstream']).toBe('ok')
    const parsed = JSON.parse(r.body)
    expect(parsed.echoed).toBe('hi-from-client')
    expect(parsed.path).toBe('/hello?a=1')
    expect(parsed.method).toBe('POST')
    expect(parsed.host).toBe(`127.0.0.1:${upstreamPort}`)
    // The client saw a leaf cert issued by our fixture CA — proves termination
    // happened (curl verified the chain via --cacert).
    expect(r.stderr).toMatch(/issuer:.*srt-test-ca/)
  })

  test('GET works (no body)', async () => {
    const r = await curlViaProxy(
      proxyPort,
      `https://127.0.0.1:${upstreamPort}/ping`,
    )
    expect(r.exit).toBe(0)
    expect(r.status).toBe(200)
    expect(JSON.parse(r.body).path).toBe('/ping')
  })

  test('upstream connect failure → 502 from the terminating proxy', async () => {
    // Proves we are NOT an opaque tunnel: a tunnel would surface a TLS/TCP
    // error to the client (curl exit 35/56); the terminating proxy speaks
    // HTTP and returns 502 over the established TLS session.
    const r = await curlViaProxy(proxyPort, `https://127.0.0.1:1/`)
    expect(r.exit).toBe(0)
    expect(r.status).toBe(502)
  })

  test('domain filter still gates termination (CONNECT 403)', async () => {
    const blocked = createHttpProxyServer({ filter: () => false, mitmCA: ca })
    await new Promise<void>(r => blocked.listen(0, '127.0.0.1', () => r()))
    const port = (blocked.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(port, `https://127.0.0.1:${upstreamPort}/`)
      // curl: 56 = "Failure when receiving data from the peer" / proxy CONNECT refused
      expect(r.exit).not.toBe(0)
      expect(r.stderr).toMatch(/403/)
    } finally {
      await new Promise<void>(r => blocked.close(() => r()))
    }
  })

  test('without mitmCA, CONNECT is still an opaque tunnel (regression)', async () => {
    const tunnelProxy = createHttpProxyServer({ filter: () => true })
    await new Promise<void>(r => tunnelProxy.listen(0, '127.0.0.1', () => r()))
    const port = (tunnelProxy.address() as AddressInfo).port
    try {
      const r = await curlViaProxy(
        port,
        `https://127.0.0.1:${upstreamPort}/tunnel`,
      )
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      expect(JSON.parse(r.body).path).toBe('/tunnel')
    } finally {
      await new Promise<void>(r => tunnelProxy.close(() => r()))
    }
  })
})

// Regression: same end-to-end path with an SRT-generated ephemeral CA
// (createMitmCA({})). #259 introduced ephemeral CAs; the leaf-minting AKI
// extension turned out to encode the SKI as a hex string (rather than raw
// bytes) for forge-created CAs, breaking chain verification — caught only
// when testing against a non-fixture CA.
describe('tls-terminate-proxy: end-to-end with ephemeral CA', () => {
  test('curl trusts the ephemeral-CA-signed leaf and round-trips', async () => {
    const ca = createMitmCA({})
    // Upstream uses the FIXTURE CA (same as the other describe) so the
    // proxy's outbound `ca:` value is identical across the file — Bun's
    // https.request caches the first `ca:` process-wide. The regression
    // under test is the client-facing leaf (ephemeral CA → curl), which is
    // covered by mitmCA below + curl --cacert pointing at the ephemeral CA.
    const fixtureCA = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    const upCert = mintLeafCert(fixtureCA, '127.0.0.1')
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    const upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        let body = ''
        req.on('data', c => (body += c))
        req.on('end', () => {
          res.writeHead(200, { 'x-upstream': 'ok' })
          res.end(JSON.stringify({ echoed: body, path: req.url }))
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    const upstreamPort = (upstream.address() as AddressInfo).port

    const proxy = createHttpProxyServer({
      filter: () => true,
      mitmCA: ca,
      tlsTerminateUpstreamCA: CA_PEM,
    })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    const proxyPort = (proxy.address() as AddressInfo).port

    try {
      const r = await curlViaProxy(
        proxyPort,
        `https://127.0.0.1:${upstreamPort}/hello?a=1`,
        { method: 'POST', body: 'from-ephemeral', cacert: ca.certPath },
      )
      expect(r.exit).toBe(0)
      expect(r.status).toBe(200)
      expect(r.headers['x-upstream']).toBe('ok')
      const parsed = JSON.parse(r.body)
      expect(parsed.echoed).toBe('from-ephemeral')
      expect(parsed.path).toBe('/hello?a=1')
      expect(r.stderr).toMatch(/issuer:.*sandbox-runtime ephemeral CA/)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
      await new Promise<void>(r => upstream.close(() => r()))
      await disposeMitmCA(ca)
    }
  })
})

type CurlResult = {
  exit: number
  status: number
  headers: Record<string, string>
  body: string
  stderr: string
}

async function curlViaProxy(
  proxyPort: number,
  url: string,
  opts: { method?: string; body?: string; cacert?: string } = {},
): Promise<CurlResult> {
  const args = [
    '-sS',
    '-v', // TLS issuer line goes to stderr
    '--proxy',
    `http://127.0.0.1:${proxyPort}`,
    '--cacert',
    opts.cacert ?? CA_CERT,
    '--max-time',
    '10',
    '-D',
    '-', // dump response headers to stdout before body
    '-X',
    opts.method ?? 'GET',
  ]
  if (opts.body !== undefined) args.push('--data-binary', opts.body)
  args.push(url)

  // Async spawn so the in-process proxy/upstream can service the request.
  const child = spawn('curl', args)
  let out = ''
  let stderr = ''
  child.stdout.setEncoding('utf8').on('data', c => (out += c))
  child.stderr.setEncoding('utf8').on('data', c => (stderr += c))
  // Drain both streams to 'end' before reading the exit code — Bun's
  // ChildProcess 'close' can fire before all 'data' events are delivered.
  await Promise.all([
    new Promise<void>(r => child.stdout.once('end', r)),
    new Promise<void>(r => child.stderr.once('end', r)),
  ])
  const exit = await new Promise<number>(resolve =>
    child.on('close', code => resolve(code ?? 1)),
  )

  // -D - prints headers (possibly multiple blocks: CONNECT response, then the
  // real response) followed by body. Take the LAST header block.
  const sep = out.lastIndexOf('\r\n\r\n')
  const headerPart = sep >= 0 ? out.slice(0, sep) : ''
  const body = sep >= 0 ? out.slice(sep + 4) : out
  const blocks = headerPart.split(/\r\n\r\n/)
  const lastHdr = blocks[blocks.length - 1] ?? ''
  const lines = lastHdr.split('\r\n')
  const statusLine = lines.shift() ?? ''
  const m = /HTTP\/[\d.]+ (\d+)/.exec(statusLine)
  const status = m ? Number(m[1]) : 0
  const headers: Record<string, string> = {}
  for (const line of lines) {
    const i = line.indexOf(':')
    if (i > 0)
      headers[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim()
  }
  return { exit, status, headers, body, stderr }
}
