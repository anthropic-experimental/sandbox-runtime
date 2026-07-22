/**
 * Outbound framing for chunked request bodies on methods Node does not
 * auto-chunk.
 *
 * stripHopByHop removes Transfer-Encoding (hop-by-hop) and relies on the
 * outbound HTTP client to re-frame the piped body. Node only auto-chunks
 * methods with chunked encoding on by default (POST, PUT, PATCH, …) — for a
 * chunked GET/HEAD/OPTIONS/DELETE with no Content-Length, the piped body
 * bytes used to land on the upstream socket with no framing at all, and the
 * upstream parsed them as the start of a separate pipelined request (a
 * request-smuggling shape). prepareOutboundBodyFraming +
 * applyOutboundBodyFraming restore chunked framing so the upstream sees
 * exactly the body, once.
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import type {
  ClientRequest,
  IncomingHttpHeaders,
  IncomingMessage,
} from 'node:http'
import { createServer as createHttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import type { Server, AddressInfo } from 'node:net'
import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'
import {
  applyOutboundBodyFraming,
  prepareOutboundBodyFraming,
} from '../../src/sandbox/parent-proxy.js'
import { rawHttpRequest } from '../helpers/raw-http.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

describe('prepareOutboundBodyFraming', () => {
  const inbound = (method: string, headers: IncomingHttpHeaders) =>
    ({ method, headers }) as IncomingMessage

  test('true for a chunked inbound body on a non-auto-chunk method', () => {
    for (const method of ['GET', 'HEAD', 'OPTIONS', 'DELETE']) {
      expect(
        prepareOutboundBodyFraming(
          inbound(method, { 'transfer-encoding': 'chunked' }),
          {},
        ),
      ).toBe(true)
    }
  })

  test('true when body-substitution deleted the Content-Length', () => {
    // Inbound declared a body via Content-Length, but the outbound header
    // was deleted (length-changing sentinel substitution) — the body still
    // needs framing.
    expect(
      prepareOutboundBodyFraming(
        inbound('DELETE', { 'content-length': '9' }),
        {},
      ),
    ).toBe(true)
  })

  test('false for methods Node auto-chunks (POST, PUT, PATCH)', () => {
    for (const method of ['POST', 'PUT', 'PATCH']) {
      const fwd: IncomingHttpHeaders = { expect: '100-continue' }
      expect(
        prepareOutboundBodyFraming(
          inbound(method, { 'transfer-encoding': 'chunked' }),
          fwd,
        ),
      ).toBe(false)
      // Expect survives on auto-chunk methods — SigV4 clients may sign it.
      expect(fwd.expect).toBe('100-continue')
    }
  })

  test('false when the inbound request declares no body', () => {
    for (const headers of [{}, { 'content-length': '0' }]) {
      expect(prepareOutboundBodyFraming(inbound('GET', headers), {})).toBe(
        false,
      )
    }
  })

  test('false when the outbound request is already framed', () => {
    const req = inbound('GET', { 'transfer-encoding': 'chunked' })
    for (const fwd of [
      { 'content-length': '9' },
      // transfer-encoding never survives stripHopByHop; defensive only.
      { 'transfer-encoding': 'chunked' },
    ] as IncomingHttpHeaders[]) {
      expect(prepareOutboundBodyFraming(req, fwd)).toBe(false)
    }
  })

  test('deletes a framing-defeating Expect header when the flip applies', () => {
    // Expect makes Node's ClientRequest store its header block in the
    // constructor, before applyOutboundBodyFraming can act — whoever set
    // it (client or a mutateHeaders hook), it must not reach construction
    // alongside the flip.
    const fwd: IncomingHttpHeaders = { expect: '100-continue' }
    expect(
      prepareOutboundBodyFraming(
        inbound('GET', { 'transfer-encoding': 'chunked' }),
        fwd,
      ),
    ).toBe(true)
    expect(fwd.expect).toBeUndefined()
  })

  test('applyOutboundBodyFraming flips the flag only when needed', () => {
    const out = { useChunkedEncodingByDefault: false } as ClientRequest
    applyOutboundBodyFraming(out, false)
    expect(out.useChunkedEncodingByDefault).toBe(false)
    applyOutboundBodyFraming(out, true)
    expect(out.useChunkedEncodingByDefault).toBe(true)
  })
})

describe('chunked bodies on methods Node does not auto-chunk', () => {
  const TEST_TIMEOUT = 15_000
  const PAYLOAD = 'chunked-body-payload'
  const CHUNKED_WIRE = `${PAYLOAD.length.toString(16)}\r\n${PAYLOAD}\r\n0\r\n\r\n`

  let upstream: Server
  let upstreamPort: number
  let requestCount = 0
  let clientErrors = 0
  let lastBody = ''

  beforeAll(async () => {
    upstream = createHttpServer((req, res) => {
      requestCount++
      let body = ''
      req.on('data', c => (body += c))
      req.on('end', () => {
        lastBody = body
        res.end(JSON.stringify({ method: req.method, echoed: body }))
      })
    })
    upstream.on('clientError', (_err, sock) => {
      clientErrors++
      sock.destroy()
    })
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', () => r()))
    upstreamPort = (upstream.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => upstream.close(() => r()))
  })

  async function withPlainProxy(
    fn: (proxyPort: number) => Promise<void>,
  ): Promise<void> {
    // No filterRequest: with one configured, GET/HEAD bodies are denied
    // outright (see request-filter.test.ts) — this suite covers the
    // framing of what IS forwarded.
    const proxy = createHttpProxyServer({ filter: () => true })
    await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
    try {
      await fn((proxy.address() as AddressInfo).port)
    } finally {
      await new Promise<void>(r => proxy.close(() => r()))
    }
  }

  for (const method of ['GET', 'DELETE']) {
    test(
      `chunked ${method} reaches the upstream framed — exactly the body, once`,
      async () => {
        requestCount = 0
        clientErrors = 0
        lastBody = ''
        await withPlainProxy(async port => {
          const resp = await rawHttpRequest(
            port,
            `${method} http://127.0.0.1:${upstreamPort}/c HTTP/1.1\r\n` +
              `Host: 127.0.0.1:${upstreamPort}\r\n` +
              `Connection: close\r\n` +
              `Transfer-Encoding: chunked\r\n\r\n` +
              CHUNKED_WIRE,
          )
          expect(resp).toContain('200')
          expect(resp).toContain(`"echoed":"${PAYLOAD}"`)
        })
        // The pre-fix failure mode: body bytes arrive after the header
        // block with no framing, and the upstream parses them as a second,
        // garbage request. Exactly one clean request must arrive.
        expect(lastBody).toBe(PAYLOAD)
        expect(requestCount).toBe(1)
        expect(clientErrors).toBe(0)
      },
      TEST_TIMEOUT,
    )
  }

  // Runtime divergence (same as OPTIONS in request-filter.test.ts): Bun's
  // http server discards OPTIONS request bodies before user code runs, so
  // under Bun (the only runtime this suite executes on) the upstream sees
  // an empty body — but exactly one clean request and no stray bytes, which
  // is the anti-smuggling property this suite pins. Node delivers the body;
  // that direction is covered by the shared framing decision (same code as
  // the GET/DELETE rows above).
  test(
    'chunked OPTIONS: one clean upstream request, nothing smuggled',
    async () => {
      requestCount = 0
      clientErrors = 0
      lastBody = ''
      await withPlainProxy(async port => {
        const resp = await rawHttpRequest(
          port,
          `OPTIONS http://127.0.0.1:${upstreamPort}/o HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            `Connection: close\r\n` +
            `Transfer-Encoding: chunked\r\n\r\n` +
            CHUNKED_WIRE,
        )
        expect(resp).toContain('200')
      })
      expect(requestCount).toBe(1)
      expect(clientErrors).toBe(0)
    },
    TEST_TIMEOUT,
  )

  test(
    'chunked GET with Expect: 100-continue still reaches the upstream framed',
    async () => {
      // A forwarded Expect makes Node's ClientRequest store its header
      // block in the constructor, before applyOutboundBodyFraming can flip
      // useChunkedEncodingByDefault — a client-controlled way to reopen
      // the unframed-body hole. prepareOutboundBodyFraming deletes it when
      // the flip applies.
      requestCount = 0
      clientErrors = 0
      lastBody = ''
      await withPlainProxy(async port => {
        const resp = await rawHttpRequest(
          port,
          `GET http://127.0.0.1:${upstreamPort}/e HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            `Connection: close\r\n` +
            `Expect: 100-continue\r\n` +
            `Transfer-Encoding: chunked\r\n\r\n` +
            CHUNKED_WIRE,
        )
        expect(resp).toContain('200')
        expect(resp).toContain(`"echoed":"${PAYLOAD}"`)
      })
      expect(lastBody).toBe(PAYLOAD)
      expect(requestCount).toBe(1)
      expect(clientErrors).toBe(0)
    },
    TEST_TIMEOUT,
  )

  test(
    'a mutateHeaders hook re-adding Expect cannot reopen the unframed hole',
    async () => {
      // The framing decision runs AFTER all header mutation: a consumer
      // hook that adds Expect for a chunked GET must not resurrect the
      // constructor-time header storage that defeats the flag flip.
      requestCount = 0
      clientErrors = 0
      lastBody = ''
      const proxy = createHttpProxyServer({
        filter: () => true,
        mutateHeadersPlaintext: headers => {
          headers.expect = '100-continue'
        },
      })
      await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
      try {
        const port = (proxy.address() as AddressInfo).port
        const resp = await rawHttpRequest(
          port,
          `GET http://127.0.0.1:${upstreamPort}/h HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            `Connection: close\r\n` +
            `Transfer-Encoding: chunked\r\n\r\n` +
            CHUNKED_WIRE,
        )
        expect(resp).toContain('200')
        expect(resp).toContain(`"echoed":"${PAYLOAD}"`)
      } finally {
        await new Promise<void>(r => proxy.close(() => r()))
      }
      expect(lastBody).toBe(PAYLOAD)
      expect(requestCount).toBe(1)
      expect(clientErrors).toBe(0)
    },
    TEST_TIMEOUT,
  )

  test(
    'chunked POST still forwards (auto-chunked path, non-regression)',
    async () => {
      requestCount = 0
      clientErrors = 0
      await withPlainProxy(async port => {
        const resp = await rawHttpRequest(
          port,
          `POST http://127.0.0.1:${upstreamPort}/p HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${upstreamPort}\r\n` +
            `Connection: close\r\n` +
            `Transfer-Encoding: chunked\r\n\r\n` +
            CHUNKED_WIRE,
        )
        expect(resp).toContain('200')
        expect(resp).toContain(`"echoed":"${PAYLOAD}"`)
      })
      expect(requestCount).toBe(1)
      expect(clientErrors).toBe(0)
    },
    TEST_TIMEOUT,
  )

  test(
    'chunked GET through the TLS-terminated path reaches the upstream framed',
    async () => {
      const ca0 = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
      const upCert = mintLeafCert(ca0, '127.0.0.1')
      const upLeafOnly = upCert.certPem.match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
      )![0]
      let tlsRequests = 0
      let tlsClientErrors = 0
      let tlsBody = ''
      const tlsUp = createHttpsServer(
        { cert: upLeafOnly, key: upCert.keyPem },
        (req, res) => {
          tlsRequests++
          let body = ''
          req.on('data', c => (body += c))
          req.on('end', () => {
            tlsBody = body
            res.end(JSON.stringify({ echoed: body }))
          })
        },
      )
      tlsUp.on('clientError', (_err, sock) => {
        tlsClientErrors++
        sock.destroy()
      })
      await new Promise<void>(r => tlsUp.listen(0, '127.0.0.1', () => r()))
      const tlsUpPort = (tlsUp.address() as AddressInfo).port

      const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
      const proxy = createHttpProxyServer({
        filter: () => true,
        mitmCA: ca,
        tlsTerminateUpstreamCA: CA_PEM,
      })
      await new Promise<void>(r => proxy.listen(0, '127.0.0.1', () => r()))
      const proxyPort = (proxy.address() as AddressInfo).port
      try {
        // curl chunk-encodes the upload when the request carries an
        // explicit `Transfer-Encoding: chunked` header.
        const out = await new Promise<string>(resolve => {
          const child = spawn('curl', [
            '-sS',
            '--proxy',
            `http://127.0.0.1:${proxyPort}`,
            '--cacert',
            CA_CERT,
            '--max-time',
            '10',
            '-X',
            'GET',
            '-H',
            'Transfer-Encoding: chunked',
            '--data-binary',
            PAYLOAD,
            `https://127.0.0.1:${tlsUpPort}/c`,
          ])
          let buf = ''
          child.stdout.setEncoding('utf8').on('data', c => (buf += c))
          child.stderr.setEncoding('utf8').on('data', () => {})
          child.on('close', () => resolve(buf))
        })
        expect(out).toContain(`"echoed":"${PAYLOAD}"`)
        expect(tlsBody).toBe(PAYLOAD)
        expect(tlsRequests).toBe(1)
        expect(tlsClientErrors).toBe(0)
      } finally {
        await new Promise<void>(r => proxy.close(() => r()))
        await new Promise<void>(r => tlsUp.close(() => r()))
      }
    },
    TEST_TIMEOUT,
  )
})
