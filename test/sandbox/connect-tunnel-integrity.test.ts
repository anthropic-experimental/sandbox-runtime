import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import type { Server, AddressInfo } from 'node:net'
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA, disposeMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import { relayPullMode } from '../../src/sandbox/stream-relay.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md. Used
// here only to mint a cert for the in-process HTTPS upstream; the proxy
// never terminates TLS in these tests (no mitmCA), so the CONNECT is an
// opaque byte tunnel and curl verifies the upstream directly.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')

describe('relayPullMode', () => {
  test('relays all bytes and ends the destination', async () => {
    const src = new PassThrough()
    const dst = new PassThrough()
    const chunks: Buffer[] = []
    dst.on('data', c => chunks.push(c as Buffer))
    const done = new Promise<void>(r => dst.once('end', r))
    relayPullMode(src, dst)
    src.write('hello ')
    src.write('world')
    src.end()
    await done
    expect(Buffer.concat(chunks).toString()).toBe('hello world')
  })

  test('resumes after destination backpressure', async () => {
    const src = new PassThrough()
    const dst = new PassThrough({ highWaterMark: 8 })
    const done = new Promise<Buffer>(resolve => {
      const chunks: Buffer[] = []
      dst.on('data', c => chunks.push(c as Buffer))
      dst.once('end', () => resolve(Buffer.concat(chunks)))
    })
    relayPullMode(src, dst)
    // Large enough to make dst.write() return false several times.
    const payload = Buffer.alloc(64 * 1024, 'x')
    src.end(payload)
    expect((await done).equals(payload)).toBe(true)
  })
})

// Regression test for the opaque (non-MITM) CONNECT tunnel in
// createHttpProxyServer: under Bun, relaying the 'connect'-event socket
// with pipe() corrupted the byte stream across pipe()'s pause/resume
// cycles once upstream writes queued. Through the opaque tunnel this
// surfaced as the end-to-end TLS session failing record MAC verification
// mid-upload (curl exit 56 / bad_record_mac), near-deterministic at
// 64 MiB under Bun 1.3.14. Node is unaffected. See relayPullMode.
describe('opaque CONNECT tunnel: multi-megabyte upload integrity', () => {
  const SIZE = 64 * 1024 * 1024

  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  let upstream: Server
  let upstreamPort: number
  let proxy: Server
  let proxyPort: number
  let bodyDir: string
  let bigFile: string
  let expectedSha: string
  let received: { len: number; sha: string } | undefined

  beforeAll(async () => {
    const upCert = mintLeafCert(ca, '127.0.0.1')
    // Leaf-only — Bun's TLS client mis-verifies when the root CA is
    // appended to the server chain.
    const upLeafOnly = upCert.certPem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
    )![0]
    upstream = createHttpsServer(
      { cert: upLeafOnly, key: upCert.keyPem },
      (req, res) => {
        const h = createHash('sha256')
        let len = 0
        req.on('data', c => {
          h.update(c as Buffer)
          len += (c as Buffer).length
        })
        req.on('end', () => {
          received = { len, sha: h.digest('hex') }
          res.writeHead(200)
          res.end('ok')
        })
      },
    )
    upstream.listen(0, '127.0.0.1')
    await new Promise<void>(r => upstream.once('listening', r))
    upstreamPort = (upstream.address() as AddressInfo).port

    // No mitmCA: CONNECT opens an opaque byte tunnel, the corruption
    // trigger under test. TCP listener — the trigger needs a TCP-accepted
    // client socket (the Windows mux backend and direct embedders both
    // accept the http proxy over TCP).
    proxy = createHttpProxyServer({ filter: () => true })
    proxy.listen(0, '127.0.0.1')
    await new Promise<void>(r => proxy.once('listening', r))
    proxyPort = (proxy.address() as AddressInfo).port

    bodyDir = mkdtempSync(join(tmpdir(), 'srt-tunnel-big-'))
    bigFile = join(bodyDir, 'big')
    const body = Buffer.alloc(SIZE, 'a')
    expectedSha = createHash('sha256').update(body).digest('hex')
    writeFileSync(bigFile, body)
  })

  afterAll(async () => {
    rmSync(bodyDir, { recursive: true, force: true })
    proxy.close()
    upstream.close()
    await disposeMitmCA(ca)
  })

  test('a 64 MiB PUT through the tunnel arrives byte-intact', async () => {
    received = undefined
    const child = spawn('curl', [
      '-sS',
      '--proxy',
      `http://127.0.0.1:${proxyPort}`,
      '--cacert',
      CA_CERT,
      '--max-time',
      '90',
      '-o',
      '/dev/null',
      '-w',
      '%{http_code}',
      '-X',
      'PUT',
      '--data-binary',
      `@${bigFile}`,
      // curl would otherwise send Expect: 100-continue and stall the
      // upload behind a 100 the opaque tunnel cannot synthesize quickly.
      '-H',
      'Expect:',
      `https://127.0.0.1:${upstreamPort}/big`,
    ])
    let out = ''
    let stderr = ''
    child.stdout.setEncoding('utf8').on('data', c => (out += c))
    child.stderr.setEncoding('utf8').on('data', c => (stderr += c))
    await Promise.all([
      new Promise<void>(r => child.stdout.once('end', r)),
      new Promise<void>(r => child.stderr.once('end', r)),
    ])
    const exit = await new Promise<number>(resolve =>
      child.on('close', code => resolve(code ?? 1)),
    )

    // The historical failure mode was TLS bad_record_mac (curl exit 56)
    // partway through the upload; assert content too so a silent-corruption
    // regression cannot pass.
    expect(`exit=${exit} ${stderr.trim()}`).toBe('exit=0 ')
    expect(out).toBe('200')
    expect(received?.len).toBe(SIZE)
    expect(received?.sha).toBe(expectedSha)
  }, 120000)
})
