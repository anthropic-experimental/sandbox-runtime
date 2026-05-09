/**
 * In-process TLS termination for HTTPS traffic through the forward proxy.
 *
 * When a MitmCA is configured, the forward proxy hands CONNECT requests here
 * instead of opening an opaque byte tunnel. We terminate the client's TLS
 * with a per-host leaf cert (see mitm-leaf.ts), parse the decrypted stream
 * as HTTP/1.1, and re-issue each request upstream over a real TLS
 * connection. The optional `filterRequest` callback runs on each parsed
 * request before it is forwarded.
 */

import {
  createServer as createHttpsServer,
  request as httpsRequest,
} from 'node:https'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { connect, isIP } from 'node:net'
import { unlink } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Duplex, Readable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import type { MitmCA } from './mitm-ca.js'
import {
  decideAndRespond,
  type FilterRequestCallback,
} from './request-filter.js'
import { mintLeafCert, secureContextFor } from './mitm-leaf.js'
import { stripHopByHop } from './parent-proxy.js'

export type TerminateTarget = {
  hostname: string
  port: number
  /**
   * Additional trusted CA(s) for the proxy's outbound TLS leg. Unset → system
   * roots + NODE_EXTRA_CA_CERTS. Primarily a test seam (NODE_EXTRA_CA_CERTS
   * is read at process start, so tests can't set it from inside the suite).
   */
  upstreamCA?: string | Buffer | Array<string | Buffer>
}

/**
 * Terminate the client's TLS on `socket`, parse the decrypted HTTP/1.1
 * stream, and forward each request to `target` over a fresh upstream TLS
 * connection.
 *
 * Preconditions: the caller has already validated `target` against the
 * domain allowlist; this function does not re-check it.
 *
 * Implementation: we stand up a short-lived https.Server on a unix socket
 * and pipe the client socket through it. The Node-idiomatic alternative —
 * feeding the raw socket to a non-listening server via
 * `emit('connection', socket)` — is not implemented by Bun's https.Server,
 * and SRT runs under both runtimes. A per-connection server lets the
 * request handler close over `target` (which carries the originally-
 * requested host:port) without socket-keyed lookups.
 */
export function terminateAndForward(
  ca: MitmCA,
  filterRequest: FilterRequestCallback | undefined,
  socket: Duplex,
  head: Buffer,
  target: TerminateTarget,
): void {
  // ALPN advertises HTTP/1.1 only — terminating HTTP/2 would require a frame
  // parser; clients negotiate down. The base secureContext covers clients
  // that don't send SNI; SNICallback covers everyone else.
  const baseLeaf = mintLeafCert(ca, target.hostname)
  const inner = createHttpsServer({
    ALPNProtocols: ['http/1.1'],
    cert: baseLeaf.certPem,
    key: baseLeaf.keyPem,
    SNICallback: (servername, cb) => {
      try {
        cb(null, secureContextFor(ca, servername || target.hostname))
      } catch (err) {
        cb(err as Error)
      }
    },
  })

  inner.on('request', (req, res) => {
    void forwardUpstream(filterRequest, req, res, target)
  })
  inner.on('tlsClientError', (err, sock) => {
    logForDebugging(
      `[tls-terminate] client TLS error for ${target.hostname}: ${err.message}`,
      { level: 'error' },
    )
    sock.destroy()
  })
  inner.on('upgrade', (_req, sock) => {
    // WebSocket / non-HTTP over TLS — out of scope for now.
    logForDebugging('[tls-terminate] upgrade request refused', {
      level: 'warn',
    })
    sock.destroy()
  })

  const sockPath = innerSocketPath()
  const cleanup = () => {
    inner.close()
    unlink(sockPath, () => {})
  }
  inner.on('error', err => {
    logForDebugging(
      `[tls-terminate] inner server listen failed: ${err.message}`,
      { level: 'error' },
    )
    socket.destroy()
    cleanup()
  })
  inner.listen(sockPath, () => {
    const loop = connect({ path: sockPath })
    loop.on('error', err => {
      logForDebugging(`[tls-terminate] inner loopback failed: ${err.message}`, {
        level: 'error',
      })
      socket.destroy()
      cleanup()
    })
    loop.once('connect', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      // Any bytes the client sent in the same packet as the CONNECT are the
      // start of its ClientHello — forward them first.
      if (head.length) loop.write(head)
      socket.pipe(loop)
      loop.pipe(socket)
    })
    socket.on('error', () => loop.destroy())
    socket.once('close', () => {
      loop.destroy()
      cleanup()
    })
    loop.once('close', () => socket.destroy())
  })
  inner.unref()
}

async function forwardUpstream(
  filterRequest: FilterRequestCallback | undefined,
  req: IncomingMessage,
  res: ServerResponse,
  target: TerminateTarget,
): Promise<void> {
  let body: Readable = req
  if (filterRequest) {
    const ac = new AbortController()
    res.once('close', () => ac.abort())
    const host =
      req.headers.host ??
      (target.port === 443
        ? target.hostname
        : `${target.hostname}:${target.port}`)
    const out = await decideAndRespond(
      filterRequest,
      req,
      res,
      `https://${host}${req.url ?? '/'}`,
      ac.signal,
    )
    if (out === null) return
    body = out
  }

  // Bun's https.request verifies the upstream cert against headers.host
  // verbatim (including ":port"), which never matches a SAN. Drop the host
  // header and let the runtime derive it from {host, port} — same wire value,
  // correct verification under both Node and Bun.
  const fwdHeaders = stripHopByHop(req.headers)
  delete fwdHeaders.host

  // TODO(terminating-tls): honour parentProxy for the upstream leg.
  const upstream = httpsRequest(
    {
      host: target.hostname,
      port: target.port,
      path: req.url,
      method: req.method,
      headers: fwdHeaders,
      // We're a TLS-terminating proxy, not a trust boundary for the upstream
      // server's identity — let the runtime do normal verification against
      // system roots (and NODE_EXTRA_CA_CERTS). servername must match the
      // host the client intended; SNI cannot carry an IP literal, and Bun's
      // https.request treats `servername: undefined` differently from
      // omitting the key, so spread conditionally.
      ...(isIP(target.hostname) ? {} : { servername: target.hostname }),
      ...(target.upstreamCA ? { ca: target.upstreamCA } : {}),
    },
    upRes => {
      res.writeHead(upRes.statusCode ?? 502, stripHopByHop(upRes.headers))
      upRes.pipe(res)
    },
  )

  upstream.on('error', err => {
    logForDebugging(
      `[tls-terminate] upstream ${target.hostname}:${target.port} failed: ${err.message}`,
      { level: 'error' },
    )
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain' })
      res.end('Bad Gateway')
    } else {
      res.destroy()
    }
  })

  res.on('close', () => upstream.destroy())
  body.pipe(upstream)
}

let sockSeq = 0
function innerSocketPath(): string {
  // Keep it short — macOS sun_path is 104 bytes.
  return join(
    tmpdir(),
    `srt-tt-${process.pid}-${(sockSeq++).toString(36)}.sock`,
  )
}
