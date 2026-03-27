import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { createServer as createHttpServer, type Server } from 'node:http'
import { connect, type Socket } from 'node:net'
import { type AddressInfo } from 'node:net'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { resolveParentProxy } from '../../src/sandbox/parent-proxy.js'

/**
 * End-to-end: client -> SRT HTTP proxy -> parent HTTP proxy -> origin.
 * The parent proxy records every CONNECT it receives so we can assert SRT
 * chained through it rather than dialing the origin directly.
 */
describe('parent-proxy: HTTP CONNECT tunnelling', () => {
  let origin: Server
  let originPort: number
  let parent: Server
  let parentPort: number
  let srt: Server
  let srtPort: number
  const parentConnects: string[] = []

  beforeAll(async () => {
    // Origin: plain HTTP server that responds with a marker body.
    origin = createHttpServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('hello-from-origin')
    })
    await new Promise<void>(r => origin.listen(0, '127.0.0.1', r))
    originPort = (origin.address() as AddressInfo).port

    // Parent proxy: handles CONNECT by dialing the requested host:port and
    // piping. Records each CONNECT target.
    parent = createHttpServer()
    parent.on('connect', (req, clientSock) => {
      parentConnects.push(req.url!)
      const [h, p] = req.url!.split(':')
      const up = connect(Number(p), h, () => {
        clientSock.write('HTTP/1.1 200 OK\r\n\r\n')
        up.pipe(clientSock)
        clientSock.pipe(up)
      })
      up.on('error', () => clientSock.destroy())
    })
    await new Promise<void>(r => parent.listen(0, '127.0.0.1', r))
    parentPort = (parent.address() as AddressInfo).port

    // SRT proxy configured with the parent.
    srt = createHttpProxyServer({
      filter: () => true,
      parentProxy: resolveParentProxy({
        http: `http://127.0.0.1:${parentPort}`,
        // Deliberately NOT putting 127.0.0.1 in noProxy — we want to test
        // that the always-bypass-loopback rule works. But for this test we
        // need to tunnel to 127.0.0.1, so use a noProxy that excludes nothing
        // and reach origin via a name that isn't loopback-special-cased.
        // Simpler: just test that the CONNECT goes to the parent by using a
        // hostname alias. We'll use 'localtest.me' style by targeting the
        // literal IP but as a string the bypass check won't treat as loopback
        // — actually it will. So instead: put noProxy empty and connect to
        // 127.0.0.1, and assert it BYPASSES (direct). Then use a second test
        // for the tunnel path with a non-loopback target.
        noProxy: '',
      }),
    })
    await new Promise<void>(r => srt.listen(0, '127.0.0.1', () => r()))
    srtPort = (srt.address() as AddressInfo).port
  })

  afterAll(async () => {
    await Promise.all([
      new Promise<void>(r => origin.close(() => r())),
      new Promise<void>(r => parent.close(() => r())),
      new Promise<void>(r => srt.close(() => r())),
    ])
  })

  test('loopback destination bypasses parent proxy', async () => {
    parentConnects.length = 0
    const body = await connectAndGet(srtPort, '127.0.0.1', originPort, '/')
    expect(body).toContain('hello-from-origin')
    // Parent should NOT have seen this — loopback always bypasses.
    expect(parentConnects).toEqual([])
  })

  test('non-loopback destination tunnels through parent', async () => {
    // Spin up a second SRT proxy whose parentProxy has noProxy empty, and
    // hit a non-loopback hostname that resolves to the origin. We fake this
    // by having the parent proxy rewrite the CONNECT target to our origin.
    parentConnects.length = 0

    const rewritingParent = createHttpServer()
    rewritingParent.on('connect', (req, clientSock) => {
      parentConnects.push(req.url!)
      // Ignore requested target; always connect to our local origin.
      const up = connect(originPort, '127.0.0.1', () => {
        clientSock.write('HTTP/1.1 200 OK\r\n\r\n')
        up.pipe(clientSock)
        clientSock.pipe(up)
      })
      up.on('error', () => clientSock.destroy())
    })
    await new Promise<void>(r => rewritingParent.listen(0, '127.0.0.1', r))
    const rpPort = (rewritingParent.address() as AddressInfo).port

    const srt2 = createHttpProxyServer({
      filter: () => true,
      parentProxy: resolveParentProxy({
        http: `http://127.0.0.1:${rpPort}`,
        noProxy: '',
      }),
    })
    await new Promise<void>(r => srt2.listen(0, '127.0.0.1', () => r()))
    const srt2Port = (srt2.address() as AddressInfo).port

    try {
      const body = await connectAndGet(srt2Port, 'upstream.example', 80, '/')
      expect(body).toContain('hello-from-origin')
      expect(parentConnects).toEqual(['upstream.example:80'])
    } finally {
      await new Promise<void>(r => srt2.close(() => r()))
      await new Promise<void>(r => rewritingParent.close(() => r()))
    }
  })
})

/** Issue CONNECT to proxyPort, then GET path over the tunnel. Returns body. */
function connectAndGet(
  proxyPort: number,
  destHost: string,
  destPort: number,
  path: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock: Socket = connect(proxyPort, '127.0.0.1', () => {
      sock.write(
        `CONNECT ${destHost}:${destPort} HTTP/1.1\r\n` +
          `Host: ${destHost}:${destPort}\r\n\r\n`,
      )
    })
    let phase: 'connect' | 'body' = 'connect'
    let buf = ''
    sock.on('data', chunk => {
      buf += chunk.toString()
      if (phase === 'connect') {
        const i = buf.indexOf('\r\n\r\n')
        if (i === -1) return
        const status = buf.slice(0, buf.indexOf('\r\n'))
        if (!status.includes(' 200 ')) {
          return reject(new Error(`CONNECT failed: ${status}`))
        }
        buf = buf.slice(i + 4)
        phase = 'body'
        sock.write(
          `GET ${path} HTTP/1.1\r\nHost: ${destHost}\r\nConnection: close\r\n\r\n`,
        )
      }
    })
    sock.on('end', () => resolve(buf))
    sock.on('error', reject)
  })
}
