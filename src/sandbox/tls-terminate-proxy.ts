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
  type MutateForwardedHeaders,
} from './request-filter.js'
import {
  prepareBodySubstitution,
  type GetBodySubstitutions,
} from './body-substitution.js'
import { mintLeafCert, secureContextFor } from './mitm-leaf.js'
import { stripHopByHop } from './parent-proxy.js'

/**
 * True if `buf` starts with a TLS Handshake record header.
 *
 * Three bytes: content type 0x16 (Handshake) + legacy_record_version
 * 0x03,0x00–0x03. RFC 8446 §5.1 froze the record-layer version (TLS 1.3+
 * negotiate via the supported_versions extension, the wire header stays
 * ≤0x0303), so this holds for current and future TLS. Same predicate as
 * mitmproxy `starts_like_tls_record`; nginx `ssl_preread` routes on byte 0
 * alone and HAProxy `req.ssl_hello_type` reads 9 bytes to also extract the
 * handshake type — 3 is the established middle ground for "is this TLS".
 *
 * Routing heuristic, not a security check: a non-TLS stream that happens to
 * start 16 03 0x is handed to the TLS server, which then rejects it properly.
 */
export function looksLikeClientHello(buf: Buffer): boolean {
  return (
    buf.length >= 3 && buf[0] === 0x16 && buf[1] === 0x03 && buf[2]! <= 0x03
  )
}

/**
 * Wait for the client's first post-CONNECT bytes and report whether they look
 * like a TLS ClientHello. The caller must already have written the
 * `200 Connection Established` line — clients don't send until they see it.
 *
 * Any bytes consumed here are returned in `.head` so the caller can forward
 * them to whichever downstream (terminate or opaque tunnel) it picks. The
 * socket is left paused so further bytes buffer until the downstream
 * `pipe()` resumes it.
 */
export function peekForClientHello(
  socket: Duplex,
  head: Buffer,
): Promise<{ isTLS: boolean; head: Buffer }> {
  if (head.length >= 3) {
    return Promise.resolve({ isTLS: looksLikeClientHello(head), head })
  }
  return new Promise(resolve => {
    let buf = head
    const done = () => {
      socket.removeListener('data', onData)
      socket.removeListener('close', done)
      resolve({ isTLS: looksLikeClientHello(buf), head: buf })
    }
    const onData = (chunk: Buffer) => {
      // Pause synchronously so anything after this chunk buffers for the
      // downstream pipe() rather than being dropped in flowing mode.
      socket.pause()
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk
      if (buf.length >= 3) return done()
      socket.resume()
    }
    socket.on('data', onData)
    socket.once('close', done)
  })
}

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
  mutateHeaders: MutateForwardedHeaders | undefined,
  getBodySubstitutions: GetBodySubstitutions | undefined,
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
    void forwardUpstream(
      filterRequest,
      mutateHeaders,
      getBodySubstitutions,
      req,
      res,
      target,
    )
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
      // The caller wrote `200 Connection Established` before sniffing for the
      // ClientHello; `head` holds whatever the sniff consumed.
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
  mutateHeaders: MutateForwardedHeaders | undefined,
  getBodySubstitutions: GetBodySubstitutions | undefined,
  req: IncomingMessage,
  res: ServerResponse,
  target: TerminateTarget,
): Promise<void> {
  // req.url is the request-target verbatim. Inside a CONNECT tunnel almost
  // every client sends origin-form (`/path?q`), but RFC 7230 §5.3.2 also
  // permits absolute-form (`https://host/path`) and servers MUST accept it.
  // Normalize to origin-form so concatenating onto `https://${host}` below
  // yields a well-formed URL, and discard any client-supplied authority so
  // the CONNECT-verified target stays authoritative (same rationale as the
  // Host-header note below).
  const path = originFormPath(req.url)
  let body: Readable = req
  if (filterRequest) {
    const ac = new AbortController()
    res.once('close', () => ac.abort())
    // Build the URL passed to filterRequest from the CONNECT target,
    // NOT from `req.headers.host`. The Host header is supplied by the
    // sandboxed client and can be spoofed: a sandboxed process can
    // CONNECT to allowlisted host A and then send a decrypted request
    // with `Host: B` (where B is some other allowlisted host). If we
    // built the filterRequest URL from req.headers.host the callback
    // would see "host=B" while the request is actually delivered to A.
    // A consumer using filterRequest for per-host method gating (e.g.
    // "POST allowed only to inference endpoints") would be bypassed —
    // the agent could spoof Host: api.example.com on a CONNECT to a
    // different allowlisted host, get the POST allowed, and have it
    // delivered to the CONNECT target instead.
    //
    // Always derive the URL from the verified CONNECT target so
    // filterRequest sees the actual upstream destination.
    const host =
      target.port === 443
        ? target.hostname
        : `${target.hostname}:${target.port}`
    const out = await decideAndRespond(
      filterRequest,
      req,
      res,
      `https://${host}${path}`,
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
  // Header mutation runs after the allow decision and before httpsRequest.
  // The upstream TLS handshake (rejectUnauthorized defaults to true)
  // completes before any HTTP bytes are written, so mutated headers never
  // reach an unverified server.
  mutateHeaders?.(fwdHeaders, target.hostname)
  // Masked-credential substitution in the request body, mirroring the
  // header substitution above. undefined → the bare pipe below, exactly as
  // before. May delete content-length from fwdHeaders (chunked fallback).
  const bodyTransform = prepareBodySubstitution(
    getBodySubstitutions,
    req,
    fwdHeaders,
    target.hostname,
  )

  // TODO(terminating-tls): honour parentProxy for the upstream leg.
  const upstream = httpsRequest(
    {
      host: target.hostname,
      port: target.port,
      path,
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
      // No global agent: a proxy's outbound leg shouldn't share a connection
      // pool keyed on the proxy process. Also works around a Bun quirk where
      // the first request's `ca:` value is cached on the global agent and
      // subsequent calls with a different `ca:` are silently ignored.
      agent: false,
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
  if (bodyTransform) {
    // Errors on either side of the extra pipe stage tear the chain down —
    // a stalled half-open upstream would otherwise wait for the client.
    bodyTransform.on('error', err => upstream.destroy(err))
    body.on('error', err => bodyTransform.destroy(err))
    res.on('close', () => bodyTransform.destroy())
    body.pipe(bodyTransform).pipe(upstream)
  } else {
    body.pipe(upstream)
  }
}

function originFormPath(reqUrl: string | undefined): string {
  const raw = reqUrl ?? '/'
  if (raw.startsWith('/')) return raw
  try {
    const u = new URL(raw)
    return `${u.pathname}${u.search}` || '/'
  } catch {
    // asterisk-form (`OPTIONS *`) or anything else non-absolute — pass through.
    return raw
  }
}

let sockSeq = 0
function innerSocketPath(): string {
  // Keep it short — macOS sun_path is 104 bytes.
  return join(
    tmpdir(),
    `srt-tt-${process.pid}-${(sockSeq++).toString(36)}.sock`,
  )
}
