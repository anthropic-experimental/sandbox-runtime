import type { Socket, Server } from 'node:net'
import type { Duplex } from 'node:stream'
import { Agent, createServer } from 'node:http'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect } from 'node:net'
import { URL } from 'node:url'
import { logForDebugging, logProxyDeny } from '../utils/debug.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import {
  connectViaParentProxy,
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
   * Optional upstream HTTP proxy. When present, direct-connect traffic (i.e.
   * not routed via mitmProxy) is tunnelled through this parent instead of
   * connecting directly. NO_PROXY-matched hosts still connect directly.
   */
  parentProxy?: ResolvedParentProxy
}

export function createHttpProxyServer(options: HttpProxyServerOptions): Server {
  const server = createServer()

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
        logProxyDeny('HTTPS-CONNECT', hostname, port)
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

      // Decide upstream route: MITM unix socket > parent HTTP proxy > direct.
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
        socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        return
      }

      if (clientGone) {
        upstream.on('error', () => {}) // swallow post-resolve errors
        upstream.destroy()
        return
      }

      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
      // Forward any bytes the client sent in the same packet as the CONNECT
      // (Node delivers these as the `head` buffer, not via the socket stream).
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

  // Handle regular HTTP requests
  server.on('request', async (req, res) => {
    try {
      const url = new URL(req.url!)
      const hostname = stripBrackets(url.hostname)
      const port = url.port
        ? parseInt(url.port, 10)
        : url.protocol === 'https:'
          ? 443
          : 80

      const allowed = await options.filter(port, hostname, req.socket)
      if (!allowed) {
        logProxyDeny('HTTP', hostname, port)
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

      req.pipe(proxyReq)
    } catch (err) {
      logForDebugging(`Error handling HTTP request: ${err}`, { level: 'error' })
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' })
        res.end('Internal Server Error')
      } else {
        res.destroy()
      }
    }
  })

  return server
}

/**
 * Parse a CONNECT request-target into host + port. Handles both plain
 * `host:port` and bracketed IPv6 `[::1]:port`.
 */
function parseConnectTarget(
  target: string,
): { hostname: string; port: number } | undefined {
  const m =
    /^\[([^\]]+)\]:(\d+)$/.exec(target) ?? /^([^:]+):(\d+)$/.exec(target)
  if (!m) return undefined
  const port = Number(m[2])
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined
  return { hostname: m[1]!, port }
}
