import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpsServer } from 'node:https'
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { connect } from 'node:net'
import { readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createHostHeaderProxyServer,
  parseHostHeader,
} from '../../src/sandbox/host-header-proxy.js'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert } from '../../src/sandbox/mitm-leaf.js'

const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')
const CA_PEM = readFileSync(CA_CERT, 'utf8')

describe('parseHostHeader', () => {
  test('bare host defaults to 443', () => {
    expect(parseHostHeader('api.github.com')).toEqual({
      hostname: 'api.github.com',
      port: 443,
    })
  })
  test('host:port', () => {
    expect(parseHostHeader('example.com:8443')).toEqual({
      hostname: 'example.com',
      port: 8443,
    })
  })
  test('bracketed IPv6 with and without port', () => {
    expect(parseHostHeader('[::1]')).toEqual({ hostname: '::1', port: 443 })
    expect(parseHostHeader('[::1]:9443')).toEqual({
      hostname: '::1',
      port: 9443,
    })
  })
  test('rejects garbage', () => {
    for (const bad of [
      undefined,
      '',
      'a/b',
      'user@host',
      'host:0',
      'host:70000',
      'host:abc',
      '[::1%lo0]',
      'a b',
      'host:443:1',
    ]) {
      expect(parseHostHeader(bad)).toBeUndefined()
    }
  })
})

/** Send one raw HTTP/1.1 request over the unix socket, gh-style. */
function rawRequest(
  sockPath: string,
  lines: string[],
  body = '',
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const s = connect({ path: sockPath })
    const chunks: Buffer[] = []
    s.on('error', reject)
    s.on('data', c => {
      chunks.push(c)
      // Like a real client, stop once the framed body is complete rather
      // than waiting for the server's FIN.
      const raw = Buffer.concat(chunks).toString('latin1')
      const m = /content-length:\s*(\d+)/i.exec(raw)
      const sep = raw.indexOf('\r\n\r\n')
      if (m && sep !== -1 && raw.length >= sep + 4 + Number(m[1])) {
        s.destroy()
      }
    })
    s.on('close', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      const sep = raw.indexOf('\r\n\r\n')
      const head = raw.slice(0, sep).split('\r\n')
      const status = Number(head[0]!.split(' ')[1])
      const headers: Record<string, string> = {}
      for (const h of head.slice(1)) {
        const i = h.indexOf(':')
        headers[h.slice(0, i).toLowerCase()] = h.slice(i + 1).trim()
      }
      let rest = raw.slice(sep + 4)
      if (headers['transfer-encoding'] === 'chunked') {
        let out = ''
        while (rest.length) {
          const nl = rest.indexOf('\r\n')
          const n = parseInt(rest.slice(0, nl), 16)
          if (!n) break
          out += rest.slice(nl + 2, nl + 2 + n)
          rest = rest.slice(nl + 2 + n + 2)
        }
        rest = out
      }
      resolve({ status, headers, body: rest })
    })
    s.once('connect', () => {
      s.write(lines.join('\r\n') + '\r\n\r\n' + body)
    })
  })
}

describe('host-header-proxy: plaintext over a unix socket into a verified TLS upstream', () => {
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
  let upstream: ReturnType<typeof createHttpsServer>
  let upstreamPort: number
  let upstreamSeen: Array<{
    method: string
    url: string
    host: string | undefined
    injected: string | undefined
    body: string
  }> = []

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
          upstreamSeen.push({
            method: req.method!,
            url: req.url!,
            host: req.headers.host,
            injected: req.headers['x-injected'] as string | undefined,
            body,
          })
          res.writeHead(200, { 'x-upstream': 'ok' })
          res.end(JSON.stringify({ path: req.url }))
        })
      },
    )
    await new Promise<void>(r => upstream.listen(0, '127.0.0.1', r))
    upstreamPort = (upstream.address() as AddressInfo).port
  })

  afterAll(async () => {
    await new Promise<void>(r => upstream.close(() => r()))
  })

  let seq = 0
  async function startProxy(
    opts: Partial<Parameters<typeof createHostHeaderProxyServer>[0]> = {},
  ): Promise<{ server: Server; sockPath: string; close(): Promise<void> }> {
    const sockPath = join(tmpdir(), `srt-hhp-test-${process.pid}-${seq++}.sock`)
    rmSync(sockPath, { force: true })
    const server = createHostHeaderProxyServer({
      filter: () => true,
      upstreamCA: CA_PEM,
      ...opts,
    })
    await new Promise<void>(r => server.listen(sockPath, r))
    return {
      server,
      sockPath,
      close: async () => {
        await new Promise<void>(r => server.close(() => r()))
        rmSync(sockPath, { force: true })
      },
    }
  }

  const upstreamHost = () => `127.0.0.1:${upstreamPort}`

  test('origin-form request: Host names the HTTPS upstream; response relayed', async () => {
    upstreamSeen = []
    const filtered: Array<[number, string]> = []
    const p = await startProxy({
      filter: (port, host) => {
        filtered.push([port, host])
        return true
      },
    })
    try {
      const r = await rawRequest(
        p.sockPath,
        [
          'POST /repos/x/y?per_page=1 HTTP/1.1',
          `Host: ${upstreamHost()}`,
          'Authorization: token ghp_probe',
          'Content-Length: 5',
          'Connection: close',
        ],
        'hello',
      )
      expect(r.status).toBe(200)
      expect(r.headers['x-upstream']).toBe('ok')
      expect(JSON.parse(r.body).path).toBe('/repos/x/y?per_page=1')
      expect(filtered).toEqual([[upstreamPort, '127.0.0.1']])
      expect(upstreamSeen).toHaveLength(1)
      expect(upstreamSeen[0]!.method).toBe('POST')
      expect(upstreamSeen[0]!.body).toBe('hello')
      expect(upstreamSeen[0]!.host).toBe(upstreamHost())
    } finally {
      await p.close()
    }
  })

  test('missing Host → 400, nothing dialed', async () => {
    upstreamSeen = []
    const p = await startProxy()
    try {
      const r = await rawRequest(p.sockPath, [
        'GET / HTTP/1.0',
        'Connection: close',
      ])
      expect(r.status).toBe(400)
      expect(upstreamSeen).toHaveLength(0)
    } finally {
      await p.close()
    }
  })

  test('invalid Host → 400, filter never consulted', async () => {
    let filterCalls = 0
    const p = await startProxy({
      filter: () => {
        filterCalls++
        return true
      },
    })
    try {
      const r = await rawRequest(p.sockPath, [
        'GET / HTTP/1.1',
        'Host: evil.example/../x',
        'Connection: close',
      ])
      expect(r.status).toBe(400)
      expect(filterCalls).toBe(0)
    } finally {
      await p.close()
    }
  })

  test('allowlist deny → 403 with X-Proxy-Error, nothing dialed', async () => {
    upstreamSeen = []
    const p = await startProxy({ filter: () => false })
    try {
      const r = await rawRequest(p.sockPath, [
        'GET /user HTTP/1.1',
        `Host: ${upstreamHost()}`,
        'Connection: close',
      ])
      expect(r.status).toBe(403)
      expect(r.headers['x-proxy-error']).toBe('blocked-by-allowlist')
      expect(upstreamSeen).toHaveLength(0)
    } finally {
      await p.close()
    }
  })

  test('filterRequest sees https URL built from Host; deny → 403 with reason', async () => {
    upstreamSeen = []
    const seen: string[] = []
    const denied: string[] = []
    const p = await startProxy({
      filterRequest: async r => {
        seen.push(`${r.method} ${r.url}`)
        return r.method === 'DELETE'
          ? { action: 'deny', reason: 'no deletes' }
          : { action: 'allow' }
      },
      onFilterRequestDenied: i =>
        denied.push(`${i.method} ${i.url} ${i.reason}`),
    })
    try {
      const ok = await rawRequest(p.sockPath, [
        'GET /ok HTTP/1.1',
        `Host: ${upstreamHost()}`,
        'Connection: close',
      ])
      expect(ok.status).toBe(200)
      const no = await rawRequest(p.sockPath, [
        'DELETE /repos/x HTTP/1.1',
        `Host: ${upstreamHost()}`,
        'Connection: close',
      ])
      expect(no.status).toBe(403)
      expect(no.body).toContain('no deletes')
      expect(seen).toEqual([
        `GET https://${upstreamHost()}/ok`,
        `DELETE https://${upstreamHost()}/repos/x`,
      ])
      expect(denied).toEqual([
        `DELETE https://${upstreamHost()}/repos/x no deletes`,
      ])
      expect(upstreamSeen.map(s => s.url)).toEqual(['/ok'])
    } finally {
      await p.close()
    }
  })

  test('absolute-form target: authority is discarded, Host stays authoritative', async () => {
    upstreamSeen = []
    const filtered: string[] = []
    const seen: string[] = []
    const p = await startProxy({
      filter: (_port, host) => {
        filtered.push(host)
        return true
      },
      filterRequest: async r => {
        seen.push(r.url)
        return { action: 'allow' }
      },
    })
    try {
      const r = await rawRequest(p.sockPath, [
        'GET https://attacker.example/p?q=1 HTTP/1.1',
        `Host: ${upstreamHost()}`,
        'Connection: close',
      ])
      expect(r.status).toBe(200)
      expect(filtered).toEqual(['127.0.0.1'])
      expect(seen).toEqual([`https://${upstreamHost()}/p?q=1`])
      expect(upstreamSeen[0]!.url).toBe('/p?q=1')
    } finally {
      await p.close()
    }
  })

  test('TLS-path header hook runs (credential injection reaches the upstream)', async () => {
    upstreamSeen = []
    const p = await startProxy({
      mutateHeaders: (headers, host) => {
        headers['x-injected'] = `for:${host}`
      },
    })
    try {
      const r = await rawRequest(p.sockPath, [
        'GET /inj HTTP/1.1',
        `Host: ${upstreamHost()}`,
        'Connection: close',
      ])
      expect(r.status).toBe(200)
      expect(upstreamSeen[0]!.injected).toBe('for:127.0.0.1')
    } finally {
      await p.close()
    }
  })

  test('upstream cert is verified: unknown CA → 502, request never delivered', async () => {
    upstreamSeen = []
    const p = await startProxy({ upstreamCA: undefined })
    try {
      const r = await rawRequest(p.sockPath, [
        'GET /untrusted HTTP/1.1',
        `Host: ${upstreamHost()}`,
        'Connection: close',
      ])
      expect(r.status).toBe(502)
      expect(upstreamSeen).toHaveLength(0)
    } finally {
      await p.close()
    }
  })
})
