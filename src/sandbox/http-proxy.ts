import type { Socket } from 'node:net'
import type { Duplex, Readable } from 'node:stream'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { Agent, createServer } from 'node:http'
import { timingSafeTokenEqual } from '../utils/timing-safe.js'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect } from 'node:net'
import { URL } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import type { MitmCA } from './mitm-ca.js'
import {
  decideAndRespond,
  type FilterRequestCallback,
  type MutateForwardedHeaders,
} from './request-filter.js'
import {
  peekForClientHello,
  terminateAndForward,
} from './tls-terminate-proxy.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import { formatConnectHost } from './transparent-net-helper.js'
import {
  connectViaParentProxy,
  vettedLookup,
  dialDirect,
  openConnectTunnel,
  proxyAuthHeader,
  selectParentProxyUrl,
  shouldBypassParentProxy,
  stripBrackets,
  stripHopByHop,
} from './parent-proxy.js'

export interface HttpProxyServerOptions {
  filter(
    port: number,
    host: string,
    socket: Socket | Duplex,
  ): Promise<boolean> | boolean

  /**
   * Optional function to get the MITM proxy socket path for a given host.
   * If returns a socket path, the request will be routed through that MITM proxy.
   * If returns undefined, the request will be handled directly.
   */
  getMitmSocketPath?(host: string): string | undefined

  /**
   * If present, CONNECT requests are TLS-terminated in-process and the
   * decrypted HTTP forwarded upstream over real TLS, instead of opening an
   * opaque byte tunnel. Mutually exclusive with getMitmSocketPath at the
   * config layer (sandbox-manager rejects both being set).
   */
  mitmCA?: MitmCA

  /**
   * Per-host opt-out of TLS termination; consulted only when `mitmCA` is
   * set. Return false to leave that CONNECT as an opaque byte tunnel
   * (still hostname-allowlisted via `filter`, but not content-inspected —
   * the same posture as the non-tlsTerminate path), so the sandboxed
   * client performs its own TLS handshake end-to-end with the upstream.
   *
   * Use for upstreams the proxy must not re-originate: mTLS services
   * (only the in-sandbox client holds the client certificate) and
   * certificate-pinning clients that reject the MITM CA. Note that
   * `filterRequest` and `mutateHeaders` never see the HTTPS traffic to
   * these hosts; plain-HTTP proxy requests to them are unaffected (those
   * are readable without termination and keep the normal request pipeline).
   *
   * Absent, or returning true, means today's behaviour: terminate.
   */
  shouldTerminateTLS?(hostname: string, port: number): boolean

  /**
   * Per-request filter; runs on plain-HTTP proxy requests and on terminated
   * HTTPS requests. See request-filter.ts.
   */
  filterRequest?: FilterRequestCallback

  /**
   * Mutate forwarded headers on the TLS-terminated path, after the allow
   * decision and before the upstream request is built. The upstream leg is
   * always cert-verified (rejectUnauthorized defaults to true), so the TLS
   * handshake fails before any mutated header bytes reach an unverified
   * server. See {@link MutateForwardedHeaders}.
   */
  mutateHeaders?: MutateForwardedHeaders

  /**
   * Mutate forwarded headers on the plain-HTTP path. Separate from
   * `mutateHeaders` so callers can wire the TLS path only — credential
   * injection over plaintext is opt-in.
   */
  mutateHeadersPlaintext?: MutateForwardedHeaders

  /**
   * Additional trusted CA(s) for the terminating proxy's outbound TLS leg.
   * Unset → system roots + NODE_EXTRA_CA_CERTS. Primarily a test seam.
   */
  tlsTerminateUpstreamCA?: string | Buffer | Array<string | Buffer>

  /**
   * Optional upstream HTTP proxy. When present, direct-connect traffic (i.e.
   * not routed via mitmProxy) is tunnelled through this parent instead of
   * connecting directly. NO_PROXY-matched hosts still connect directly.
   */
  parentProxy?: ResolvedParentProxy

  /**
   * Per-session bearer token. When set, every CONNECT and absolute-URI
   * request must carry `Proxy-Authorization: Basic base64("srt:<token>")`
   * or it gets a 407. Without this, any host process can dial 127.0.0.1
   * and reach the filter callback.
   */
  proxyAuthToken?: string
}

export function createHttpProxyServer(options: HttpProxyServerOptions): Server {
  const server = createServer()

  // Tunnels flagged by the transparent helper as captured plain HTTP
  // (X-SRT-Captured-Plaintext on an authenticated CONNECT). Instead of an
  // opaque byte tunnel, each origin-form request inside them goes through
  // the normal request pipeline — filterRequest, plaintext credential
  // injection, readable 403 bodies — addressed to the CONNECT target.
  // The flag can only make filtering STRICTER: a client setting it on a
  // non-HTTP stream just gets its bytes parsed (and rejected) instead of
  // blindly tunnelled.
  //
  // Mechanically, the tunnel is piped into a private 127.0.0.1 HTTP
  // backend owned by this proxy (`server.emit('connection', socket)` would
  // be free, but bun's http.Server doesn't implement that injection path —
  // same constraint the mux works around). The CONNECT target travels
  // across the hop keyed by the self-dial's local port: registered before
  // any tunnel bytes are written, so no request can be parsed untagged.
  // Keyed by the socket OBJECT (not net.Socket-typed): bun's http server
  // hands out its own socket class, so instanceof checks would miss.
  const capturedTunnelTargets = new WeakMap<
    object,
    { hostname: string; port: number }
  >()
  const pendingCapturedDials = new Map<
    number,
    { hostname: string; port: number }
  >()
  const capturedBackendSockets = new WeakSet<object>()
  let capturedBackend: Server | undefined
  let capturedBackendPort: Promise<number> | undefined
  let proxyClosed = false

  function ensureCapturedBackend(): Promise<number> {
    // A flagged CONNECT parked in the filter (ask-callback) can outlive
    // reset(); never resurrect a backend for a closed proxy.
    if (proxyClosed) {
      return Promise.reject(new Error('proxy is closed'))
    }
    if (capturedBackendPort) return capturedBackendPort
    capturedBackendPort = new Promise<number>((resolve, reject) => {
      const backend = createServer()
      capturedBackend = backend
      backend.on('connection', sock => {
        // Mark provenance only. The target lookup happens lazily at
        // request time: this event can fire BEFORE the dialing side's
        // 'connect' callback registers the mapping, but request bytes
        // only flow after registration, so the request-time lookup is
        // race-free. Restricting the lookup to backend-accepted sockets
        // keeps a front-door client from ever matching a pending dial by
        // remote-port coincidence. Only 127.0.0.1 peers count: a local
        // process forging a 127.0.0.2 source must not be able
        // to steal a pending dial's identity.
        if (sock.remoteAddress !== '127.0.0.1') {
          sock.destroy()
          return
        }
        capturedBackendSockets.add(sock)
      })
      backend.on('request', handleRequest)
      // reject only matters pre-settle; afterwards this keeps a backend
      // 'error' from becoming an uncaught exception, with a trace.
      backend.on('error', err => {
        logForDebugging(`captured backend error: ${err.message}`, {
          level: 'error',
        })
        reject(err)
      })
      backend.listen(0, '127.0.0.1', () => {
        const addr = backend.address()
        if (addr === null || typeof addr === 'string') {
          reject(new Error('captured backend: no address'))
          return
        }
        backend.unref()
        resolve(addr.port)
      })
    })
    // A transient listen failure must not permanently poison the cache
    // (every later flagged CONNECT would 500 forever).
    capturedBackendPort.catch(() => {
      capturedBackendPort = undefined
      capturedBackend = undefined
    })
    return capturedBackendPort
  }

  // The private backend lives and dies with the proxy server.
  server.on('close', () => {
    proxyClosed = true
    capturedBackend?.close()
    if (typeof capturedBackend?.closeAllConnections === 'function') {
      capturedBackend.closeAllConnections()
    }
    capturedBackend = undefined
    capturedBackendPort = undefined
  })

  const checkAuth = (got: string | undefined): boolean => {
    if (!options.proxyAuthToken) return true
    const m = /^basic\s+([a-z0-9+/=]+)\s*$/i.exec(got ?? '')
    if (!m) return false
    const decoded = Buffer.from(m[1]!, 'base64').toString('utf8')
    const sep = decoded.indexOf(':')
    if (sep <= 0) return false
    const presented = Buffer.from(decoded.slice(sep + 1), 'utf8')
    const expected = Buffer.from(options.proxyAuthToken, 'utf8')
    return timingSafeTokenEqual(presented, expected)
  }

  // Handle CONNECT requests for HTTPS traffic
  server.on('connect', async (req, socket, head) => {
    // Attach error handler immediately to prevent unhandled errors
    socket.on('error', err => {
      logForDebugging(`Client socket error: ${err.message}`, { level: 'error' })
    })

    // Track client liveness so we can abort the upstream dial if they bail.
    let clientGone = false
    socket.once('close', () => {
      clientGone = true
    })

    try {
      if (!checkAuth(req.headers['proxy-authorization'])) {
        socket.end(
          'HTTP/1.1 407 Proxy Authentication Required\r\n' +
            'Proxy-Authenticate: Basic realm="srt"\r\n\r\n',
        )
        return
      }
      const target = parseConnectTarget(req.url!)
      if (!target) {
        logForDebugging(`Invalid CONNECT request: ${req.url}`, {
          level: 'error',
        })
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
        return
      }
      const { hostname, port } = target

      const allowed = await options.filter(port, hostname, socket)
      if (!allowed) {
        logForDebugging(`Connection blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        socket.end(
          'HTTP/1.1 403 Forbidden\r\n' +
            'Content-Type: text/plain\r\n' +
            'X-Proxy-Error: blocked-by-allowlist\r\n' +
            '\r\n' +
            'Connection blocked by network allowlist',
        )
        return
      }

      // Transparently captured plain-HTTP tunnel: pipe the tunnel into the
      // private backend so each request inside it runs the full request
      // pipeline instead of an opaque tunnel. The CONNECT was
      // authenticated and allowlist-filtered above; the per-request path
      // re-filters and rewrites Host to the CONNECT target.
      if (req.headers['x-srt-captured-plaintext'] === '1' && port !== 443) {
        const backendPort = await ensureCapturedBackend()
        if (clientGone) return
        const self = connect(backendPort, '127.0.0.1')
        let dialKey: number | undefined
        let tunnelOpen = false
        const pendingEntry = { hostname, port }
        self.once('connect', () => {
          // Register the CONNECT target BEFORE any tunnel bytes flow, so
          // the backend can never parse an untagged captured request.
          // Capture the key now — localPort is undefined again after the
          // handle closes, which would leak the pending entry.
          dialKey = self.localPort!
          pendingCapturedDials.set(dialKey, pendingEntry)
          tunnelOpen = true
          socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
          if (head.length) self.write(head)
          socket.pipe(self)
          self.pipe(socket)
        })
        self.on('error', err => {
          logForDebugging(`captured backend dial failed: ${err.message}`, {
            level: 'error',
          })
          // Mirror the classic CONNECT contract: a failure before the 200
          // gets an HTTP status, not a bare RST.
          if (!tunnelOpen) socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
          else socket.destroy()
        })
        self.on('close', () => {
          // Identity-checked: a stale close (backpressure-parked socket whose
          // port the kernel already recycled) must not evict a NEWER tunnel's
          // registration under the same key.
          if (
            dialKey !== undefined &&
            pendingCapturedDials.get(dialKey) === pendingEntry
          ) {
            pendingCapturedDials.delete(dialKey)
          }
          socket.destroy()
        })
        socket.on('close', () => self.destroy())
        return
      }

      // Decide upstream route:
      //   in-process TLS termination
      //   > external MITM unix socket
      //   > parent HTTP proxy
      //   > direct
      // (tlsTerminate and mitmProxy are mutually exclusive at the config
      // layer, so the first two never both apply.)
      let wrote200 = false
      if (
        options.mitmCA &&
        (options.shouldTerminateTLS?.(hostname, port) ?? true)
      ) {
        if (clientGone) return
        // We can only terminate TLS. CONNECT also carries non-TLS streams —
        // notably SSH on Linux, where the sandbox's own GIT_SSH_COMMAND
        // routes `ssh` through this proxy via `socat - PROXY:`. Send 200 so
        // the client transmits its first bytes, sniff for a ClientHello, and
        // only terminate if it is one. Non-TLS falls through to the opaque
        // tunnel below — i.e. base-sandbox behaviour, hostname-allowlisted
        // but not content-inspected (same as the SOCKS path).
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        wrote200 = true
        const peeked = await peekForClientHello(socket, head)
        if (clientGone) return
        if (peeked.isTLS) {
          terminateAndForward(
            options.mitmCA,
            options.filterRequest,
            options.mutateHeaders,
            socket,
            peeked.head,
            { hostname, port, upstreamCA: options.tlsTerminateUpstreamCA },
          )
          return
        }
        logForDebugging(
          `[tls-terminate] non-TLS bytes on CONNECT ${hostname}:${port}; opaque-tunnelling`,
        )
        head = peeked.head
      } else if (options.mitmCA) {
        // Per-host termination opt-out: the policy exempts this host (mTLS
        // upstream, cert-pinning client), so skip the MITM entirely and
        // take the opaque tunnel below, exactly as if mitmCA were unset.
        logForDebugging(
          `[tls-terminate] policy exempts ${hostname}:${port}; opaque-tunnelling`,
        )
      }

      const mitmSocketPath = options.getMitmSocketPath?.(hostname)
      const parentUrl =
        !mitmSocketPath &&
        options.parentProxy &&
        !shouldBypassParentProxy(options.parentProxy, hostname)
          ? selectParentProxyUrl(options.parentProxy, { isHttps: true })
          : undefined

      let upstream: Socket
      try {
        if (mitmSocketPath) {
          logForDebugging(
            `Routing CONNECT ${hostname}:${port} through MITM proxy at ${mitmSocketPath}`,
          )
          upstream = await openConnectTunnel({
            dial: () => connect({ path: mitmSocketPath }),
            readyEvent: 'connect',
            destHost: hostname,
            destPort: port,
          })
        } else if (parentUrl) {
          upstream = await connectViaParentProxy(parentUrl, hostname, port)
        } else {
          upstream = await dialDirect(hostname, port)
        }
      } catch (err) {
        logForDebugging(`CONNECT tunnel failed: ${(err as Error).message}`, {
          level: 'error',
        })
        // If we already sent 200 (mitmCA sniff path), an HTTP status line now
        // would land inside the tunnel as payload. Just close.
        if (wrote200) socket.destroy()
        else socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        return
      }

      if (clientGone) {
        upstream.on('error', () => {}) // swallow post-resolve errors
        upstream.destroy()
        return
      }

      if (!wrote200) {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      }
      // Forward any bytes the client sent in the same packet as the CONNECT
      // (Node delivers these as the `head` buffer, not via the socket stream),
      // plus anything the ClientHello sniff consumed when mitmCA is on.
      if (head.length) upstream.write(head)
      upstream.pipe(socket)
      socket.pipe(upstream)

      upstream.on('error', err => {
        logForDebugging(`CONNECT tunnel failed: ${err.message}`, {
          level: 'error',
        })
        socket.destroy()
      })
      socket.on('close', () => upstream.destroy())
      upstream.on('close', () => socket.destroy())
    } catch (err) {
      logForDebugging(`Error handling CONNECT: ${err}`, { level: 'error' })
      socket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n')
    }
  })

  // Handle regular HTTP requests (front door and the captured backend).
  const handleRequest = async (
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> => {
    // Attach BEFORE any await: a client abort mid-body emits 'aborted' on
    // req, and with no listener that is an uncaughtException that kills
    // the embedding host process (bun surfaces it even earlier than node).
    req.on('error', err => {
      logForDebugging(`proxy request error: ${err.message}`)
    })
    res.on('error', err => {
      logForDebugging(`proxy response error: ${err.message}`)
    })
    try {
      // Requests inside a captured plain-HTTP tunnel were authenticated at
      // CONNECT time and are origin-form, addressed to the CONNECT target.
      // Everything else must be an authenticated absolute-URI proxy
      // request. The target lookup is lazy (see the backend 'connection'
      // comment) and scoped to sockets the captured backend accepted.
      let captured = capturedTunnelTargets.get(req.socket)
      if (
        !captured &&
        capturedBackendSockets.has(req.socket) &&
        req.socket.remoteAddress === '127.0.0.1' &&
        req.socket.remotePort !== undefined
      ) {
        captured = pendingCapturedDials.get(req.socket.remotePort)
        if (captured) {
          pendingCapturedDials.delete(req.socket.remotePort)
          capturedTunnelTargets.set(req.socket, captured)
        }
      }
      if (!captured && !checkAuth(req.headers['proxy-authorization'])) {
        res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="srt"' })
        res.end()
        return
      }
      let url: URL
      if (captured) {
        if (!req.url?.startsWith('/')) {
          // Only origin-form may ride a captured tunnel — an absolute-URI
          // here would re-route the request away from the filtered CONNECT
          // target.
          res.writeHead(400, { 'Content-Type': 'text/plain' })
          res.end('Captured tunnels accept origin-form requests only')
          return
        }
        url = new URL(
          `http://${formatConnectHost(captured.hostname)}:${captured.port}${req.url}`,
        )
      } else {
        url = new URL(req.url!)
      }
      const hostname = stripBrackets(url.hostname)
      const port = url.port
        ? parseInt(url.port, 10)
        : url.protocol === 'https:'
          ? 443
          : 80

      // Captured tunnels skip the host-level filter per request: the URL
      // is forced to the CONNECT target that the filter (and possibly the
      // ask callback) already approved at tunnel establishment, so
      // re-checking the identical tuple would only turn one keep-alive
      // connection into N ask prompts. This matches the TLS-terminate
      // contract, where in-tunnel requests run filterRequest only.
      const allowed = captured
        ? true
        : await options.filter(port, hostname, req.socket)
      if (!allowed) {
        logForDebugging(`HTTP request blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        res.writeHead(403, {
          'Content-Type': 'text/plain',
          'X-Proxy-Error': 'blocked-by-allowlist',
        })
        res.end('Connection blocked by network allowlist')
        return
      }

      // Client may have disconnected while we awaited the filter; bail now
      // rather than dialing an upstream nobody will read from.
      if (req.socket.destroyed) return

      const fwdHeaders = { ...stripHopByHop(req.headers), host: url.host }
      options.mutateHeadersPlaintext?.(fwdHeaders, hostname)

      // Decide upstream route: MITM unix socket > parent HTTP proxy > direct.
      const mitmSocketPath = options.getMitmSocketPath?.(hostname)
      const parentUrl =
        !mitmSocketPath &&
        options.parentProxy &&
        !shouldBypassParentProxy(options.parentProxy, hostname)
          ? selectParentProxyUrl(options.parentProxy, {
              isHttps: url.protocol === 'https:',
            })
          : undefined

      // Reconstruct the absolute URI from parsed components rather than
      // forwarding the client's raw req.url. This ensures the upstream proxy
      // sees exactly the host we allowlist-checked, closing URL-parser
      // differential bypasses.
      const absUrl = `${url.protocol}//${url.host}${url.pathname}${url.search}`

      // Per-request filter applies to plain HTTP too — otherwise a sandboxed
      // client could bypass it by using http:// where the upstream serves it.
      let body: Readable = req
      if (options.filterRequest) {
        const ac = new AbortController()
        res.once('close', () => ac.abort())
        const out = await decideAndRespond(
          options.filterRequest,
          req,
          res,
          absUrl,
          ac.signal,
        )
        if (out === null) return
        body = out
      }

      let proxyReq
      if (mitmSocketPath) {
        logForDebugging(
          `Routing HTTP ${req.method} ${hostname}:${port} through MITM proxy at ${mitmSocketPath}`,
        )
        const mitmAgent = new Agent({
          // @ts-expect-error - socketPath is valid but not in types
          socketPath: mitmSocketPath,
        })
        proxyReq = httpRequest(
          {
            agent: mitmAgent,
            path: absUrl,
            method: req.method,
            headers: fwdHeaders,
          },
          proxyRes => {
            res.writeHead(proxyRes.statusCode!, stripHopByHop(proxyRes.headers))
            proxyRes.pipe(res)
          },
        )
      } else if (parentUrl) {
        const parentHost = stripBrackets(parentUrl.hostname)
        const parentPort =
          Number(parentUrl.port) || (parentUrl.protocol === 'https:' ? 443 : 80)
        const auth = proxyAuthHeader(parentUrl)
        const requestFn =
          parentUrl.protocol === 'https:' ? httpsRequest : httpRequest
        proxyReq = requestFn(
          {
            hostname: parentHost,
            port: parentPort,
            path: absUrl,
            method: req.method,
            headers: auth
              ? { ...fwdHeaders, 'proxy-authorization': auth }
              : fwdHeaders,
          },
          proxyRes => {
            res.writeHead(proxyRes.statusCode!, stripHopByHop(proxyRes.headers))
            proxyRes.pipe(res)
          },
        )
      } else {
        const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest
        proxyReq = requestFn(
          {
            hostname,
            port,
            path: url.pathname + url.search,
            method: req.method,
            headers: fwdHeaders,
            // Rebinding guard: names resolving to loopback/link-local/
            // reserved ranges are refused at dial time (IP literals are
            // exempt — the filter allowed them explicitly). agent: false
            // so a pooled keep-alive socket can never skip the vetted
            // lookup (the global agent would reuse by host:port).
            lookup: vettedLookup as never,
            agent: false,
          },
          proxyRes => {
            res.writeHead(proxyRes.statusCode!, stripHopByHop(proxyRes.headers))
            proxyRes.pipe(res)
          },
        )
      }

      proxyReq.on('error', err => {
        logForDebugging(`Proxy request failed: ${err.message}`, {
          level: 'error',
        })
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain' })
          res.end('Bad Gateway')
        } else {
          res.destroy()
        }
      })

      // Tear down the upstream request if the client goes away mid-flight.
      res.on('close', () => proxyReq.destroy())

      body.pipe(proxyReq)
    } catch (err) {
      logForDebugging(`Error handling HTTP request: ${err}`, { level: 'error' })
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' })
        res.end('Internal Server Error')
      } else {
        res.destroy()
      }
    }
  }
  server.on('request', handleRequest)

  return server
}

/**
 * Parse a CONNECT request-target into host + port. Handles both plain
 * `host:port` and bracketed IPv6 `[::1]:port`.
 */
function parseConnectTarget(
  target: string,
): { hostname: string; port: number } | undefined {
  // Restrict to the charsets the URL parser and dialers agree on, so the
  // CONNECT-time filter string can never diverge from the per-request /
  // dial interpretation (e.g. `a@b` or `a/b` pseudo-hosts).
  const m =
    /^\[([0-9A-Fa-f:.]+)\]:(\d+)$/.exec(target) ??
    /^([A-Za-z0-9._-]+):(\d+)$/.exec(target)
  if (!m) return undefined
  const port = Number(m[2])
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined
  return { hostname: m[1]!, port }
}
