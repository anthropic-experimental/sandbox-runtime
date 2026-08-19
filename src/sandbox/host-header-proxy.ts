import type { Server } from 'node:http'
import { createServer } from 'node:http'
import type { Socket } from 'node:net'
import type { Duplex } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'
import type { GetBodySubstitutions } from './body-substitution.js'
import type { PlanSigv4 } from './credential-aws-pairs.js'
import { canonicalizeHost, isValidHost, stripBrackets } from './parent-proxy.js'
import type {
  FilterRequestCallback,
  MutateForwardedHeaders,
} from './request-filter.js'
import { forwardUpstreamGuarded } from './tls-terminate-proxy.js'

/**
 * Options for {@link createHostHeaderProxyServer}. Each hook has the same
 * contract as its namesake on HttpProxyServerOptions (http-proxy.ts) —
 * this listener is a second front door onto the same pipeline, not a
 * second policy.
 */
export interface HostHeaderProxyOptions {
  /**
   * Host-allowlist decision, called with the `Host` header's host and port
   * exactly as the client spelled them. There is no Proxy-Authorization on
   * this path (the socket file's permissions are the credential), so no
   * encodedCommand is available: denials are attributed to the session,
   * not to a specific command.
   */
  filter(
    port: number,
    host: string,
    socket: Socket | Duplex,
  ): Promise<boolean> | boolean
  filterRequest?: FilterRequestCallback
  onFilterRequestDenied?: (info: {
    method: string
    url: string
    reason: string
  }) => void
  /** TLS-path hooks: the upstream leg is always cert-verified TLS. */
  mutateHeaders?: MutateForwardedHeaders
  getBodySubstitutions?: GetBodySubstitutions
  planSigv4?: PlanSigv4
  /** Additional trusted CA(s) for the upstream leg. Test seam. */
  upstreamCA?: string | Buffer | Array<string | Buffer>
}

/**
 * A plaintext-HTTP front door for clients that cannot use the CONNECT proxy
 * with TLS termination because they ignore every CA-bundle env var — Go
 * binaries on macOS verify against the system keychain (and the sandbox
 * blocks `trustd`), and on Windows against the CryptoAPI store.
 *
 * The listener speaks HTTP/1.1 and treats each request's `Host` header as
 * an HTTPS origin: allowlist-check it, then forward over a fresh,
 * cert-verified upstream TLS connection through the same per-request
 * pipeline as a TLS-terminated CONNECT (filterRequest, credential
 * substitution, SigV4). The client never performs a TLS handshake, so
 * which roots it trusts is irrelevant.
 *
 * Today's consumer is `gh`: its `http_unix_socket` setting sends every API
 * request as plain HTTP over a unix socket (go-gh sets both `Dial` and
 * `DialTLS` to a raw unix dial, so the `https://` URL scheme is kept but
 * no TLS happens). The server is generic — anything that can send
 * origin-form HTTP with a Host header to the socket gets the same
 * treatment — but the sandbox only wires it up for gh.
 *
 * Security posture: the socket is the credential. The caller must bind it
 * at a 0600 path the sandboxed child can reach; there is no
 * Proxy-Authorization check here. Host is caller-asserted, which is why it
 * goes through `filter` like a CONNECT authority does, and why the
 * forwarded URL is rebuilt from the canonical form of the allowed host
 * rather than echoing the client's bytes.
 */
export function createHostHeaderProxyServer(
  options: HostHeaderProxyOptions,
): Server {
  const server = createServer()

  server.on('clientError', (err, socket) => {
    logForDebugging(`[host-header-proxy] client error: ${err.message}`, {
      level: 'error',
    })
    socket.on('error', () => {})
    if (
      (err as NodeJS.ErrnoException).code !== 'ECONNRESET' &&
      socket.writable
    ) {
      socket.end('HTTP/1.1 400 Bad Request\r\n\r\n', () => socket.destroy())
      const backstop = setTimeout(() => socket.destroy(), 1000)
      backstop.unref?.()
      return
    }
    socket.destroy()
  })

  server.on('upgrade', (_req, socket) => {
    logForDebugging('[host-header-proxy] upgrade request refused', {
      level: 'warn',
    })
    socket.destroy()
  })

  server.on('request', (req, res) => {
    req.on('error', err => {
      logForDebugging(
        `[host-header-proxy] client request error: ${err.message}`,
        {
          level: 'error',
        },
      )
    })
    res.on('error', err => {
      logForDebugging(
        `[host-header-proxy] client response error: ${err.message}`,
        { level: 'error' },
      )
      res.socket?.destroy()
    })

    void (async () => {
      const target = parseHostHeader(req.headers.host)
      if (!target) {
        logForDebugging(
          `[host-header-proxy] missing or invalid Host header: ${String(req.headers.host)}`,
          { level: 'error' },
        )
        res.writeHead(400, { 'Content-Type': 'text/plain' })
        res.end('Missing or invalid Host header')
        return
      }
      const { hostname: requestedHost, port } = target

      const allowed = await options.filter(port, requestedHost, req.socket)
      if (!allowed) {
        logForDebugging(
          `[host-header-proxy] request blocked to ${requestedHost}:${port}`,
          { level: 'error' },
        )
        if (req.socket.destroyed || res.destroyed) {
          res.destroy()
          return
        }
        res.writeHead(403, {
          'Content-Type': 'text/plain',
          'X-Proxy-Error': 'blocked-by-allowlist',
        })
        res.end('Connection blocked by network allowlist')
        return
      }
      // Client gone during the decision: nothing to forward.
      if (req.socket.destroyed || res.destroyed) return

      // Same rule as the CONNECT handler: everything after the allow
      // decision keys off the canonical spelling the allowlist evaluated.
      const hostname = canonicalizeHost(requestedHost) ?? requestedHost
      forwardUpstreamGuarded(
        options.filterRequest,
        options.mutateHeaders,
        options.getBodySubstitutions,
        req,
        res,
        {
          hostname,
          port,
          upstreamCA: options.upstreamCA,
          onFilterRequestDeny: options.onFilterRequestDenied
            ? (method, url, reason) =>
                options.onFilterRequestDenied!({ method, url, reason })
            : undefined,
        },
        options.planSigv4,
      )
    })().catch(err => {
      logForDebugging(
        `[host-header-proxy] request handling failed: ${(err as Error).message}`,
        { level: 'error' },
      )
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' })
        res.end('Internal Server Error')
      } else {
        res.destroy()
      }
    })
  })

  return server
}

/**
 * Parse an HTTP `Host` header into hostname + port. Accepts `host`,
 * `host:port`, `[v6]` and `[v6]:port`; the port defaults to 443 because
 * every request on this listener is an HTTPS origin. Rejects anything
 * that is not a syntactically valid host (see isValidHost) so a crafted
 * header cannot smuggle a path, userinfo, or zone id into the upstream
 * dial.
 */
export function parseHostHeader(
  raw: string | undefined,
): { hostname: string; port: number } | undefined {
  if (!raw) return undefined
  const m =
    /^\[([^\]]+)\](?::(\d+))?$/.exec(raw) ?? /^([^:[\]]+)(?::(\d+))?$/.exec(raw)
  if (!m) return undefined
  const hostname = stripBrackets(m[1]!)
  if (!isValidHost(hostname)) return undefined
  const port = m[2] === undefined ? 443 : Number(m[2])
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined
  return { hostname, port }
}
