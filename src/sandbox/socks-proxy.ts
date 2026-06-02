import type { Server as NetServer, Socket } from 'net'
import type { Socks5Server } from '@pondwader/socks5-server'
import { createServer } from '@pondwader/socks5-server'
import { logForDebugging } from '../utils/debug.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import {
  connectViaParentProxy,
  dialDirect,
  isValidHost,
  selectParentProxyUrl,
  shouldBypassParentProxy,
} from './parent-proxy.js'

export interface SocksProxyServerOptions {
  filter(port: number, host: string): Promise<boolean> | boolean

  /**
   * Optional upstream HTTP proxy. When present, SOCKS CONNECT requests are
   * tunnelled through the parent's HTTP CONNECT instead of dialing directly.
   * NO_PROXY-matched hosts still connect directly.
   */
  parentProxy?: ResolvedParentProxy
}

/**
 * Where to listen. macOS uses a TCP port (the seatbelt sandbox connects to
 * `localhost:<port>` directly). Linux listens on a unix socket: the
 * srt-launcher relay inside the sandbox netns connects to that socket via a
 * bind-mount, and there is no TCP loopback hop on the host.
 */
export type ProxyListenTarget =
  | { kind: 'tcp'; port: number; hostname: string }
  | { kind: 'unix'; path: string }

export interface SocksProxyWrapper {
  server: Socks5Server
  /**
   * Start listening. Resolves to the actual TCP port (for `kind: 'tcp'`; the
   * port can be 0 to let the OS pick) or the socket path (for `kind: 'unix'`).
   */
  listen(target: ProxyListenTarget): Promise<number | string>
  close(): Promise<void>
  unref(): void
}

export function createSocksProxyServer(
  options: SocksProxyServerOptions,
): SocksProxyWrapper {
  const socksServer = createServer()

  socksServer.setRulesetValidator(async conn => {
    try {
      const hostname = conn.destAddress
      const port = conn.destPort

      // SOCKS5 DOMAINNAME is a raw length-prefixed byte string with zero
      // validation from the protocol or the library. Reject control chars
      // (null bytes, CRLF) here so they never reach the allowlist matcher,
      // where string suffix matching would be trivially fooled.
      if (!isValidHost(hostname)) {
        logForDebugging(
          `Rejecting malformed SOCKS host: ${JSON.stringify(hostname)}`,
          { level: 'error' },
        )
        return false
      }

      logForDebugging(`Connection request to ${hostname}:${port}`)

      const allowed = await options.filter(port, hostname)

      if (!allowed) {
        logForDebugging(`Connection blocked to ${hostname}:${port}`, {
          level: 'error',
        })
        return false
      }

      logForDebugging(`Connection allowed to ${hostname}:${port}`)
      return true
    } catch (error) {
      logForDebugging(`Error validating connection: ${error}`, {
        level: 'error',
      })
      return false
    }
  })

  // Override the default connection handler so we can route through a parent
  // HTTP proxy when one is configured. The default handler does a straight
  // net.connect() which fails when direct egress is blocked.
  socksServer.setConnectionHandler((conn, sendStatus) => {
    const host = conn.destAddress
    const port = conn.destPort

    // Track client liveness so we can abort the upstream dial if they bail.
    let clientGone = false
    let upstreamRef: Socket | undefined
    conn.socket.once('close', () => {
      clientGone = true
      upstreamRef?.destroy()
    })
    conn.socket.on('error', () => upstreamRef?.destroy())

    // SOCKS is an opaque TCP tunnel — semantically identical to HTTP
    // CONNECT — so always prefer HTTPS_PROXY if set, regardless of dest port.
    const parentUrl =
      options.parentProxy && !shouldBypassParentProxy(options.parentProxy, host)
        ? selectParentProxyUrl(options.parentProxy, { isHttps: true })
        : undefined

    const open = parentUrl
      ? connectViaParentProxy(parentUrl, host, port)
      : dialDirect(host, port)

    open
      .then(upstream => {
        upstreamRef = upstream
        upstream.on('error', () => conn.socket.destroy())
        if (clientGone) {
          upstream.destroy()
          return
        }
        sendStatus('REQUEST_GRANTED')
        upstream.pipe(conn.socket)
        conn.socket.pipe(upstream)
        upstream.on('close', () => conn.socket.destroy())
      })
      .catch(err => {
        logForDebugging(
          `SOCKS connect to ${host}:${port} failed: ${(err as Error).message}`,
          { level: 'error' },
        )
        if (!clientGone) {
          try {
            sendStatus('HOST_UNREACHABLE')
          } catch {
            // socket may have closed between the check and the write
          }
        }
      })
  })

  // Track every accepted client socket so close() can tear them down
  // immediately. `net.Server.close()`'s callback waits for all open
  // connections to finish, and a SOCKS connection mid-`dialDirect()` (30s
  // timeout) or mid-relay holds the server open indefinitely. During
  // SandboxManager.reset() that turns into a hang that can outlive bun's
  // 5s test/hook timeout, so we destroy connections rather than drain them.
  const internalServer = (socksServer as unknown as { server?: NetServer })
    ?.server
  const openSockets = new Set<Socket>()
  internalServer?.on('connection', (socket: Socket) => {
    openSockets.add(socket)
    socket.once('close', () => openSockets.delete(socket))
  })

  return {
    server: socksServer,
    listen(target: ProxyListenTarget): Promise<number | string> {
      return new Promise((resolve, reject) => {
        internalServer?.once('error', reject)
        const listeningCallback = (): void => {
          internalServer?.removeListener('error', reject)
          const addr = internalServer?.address()
          if (target.kind === 'unix') {
            logForDebugging(`SOCKS proxy listening on ${target.path}`)
            resolve(target.path)
          } else if (addr && typeof addr === 'object') {
            logForDebugging(
              `SOCKS proxy listening on ${target.hostname}:${addr.port}`,
            )
            resolve(addr.port)
          } else {
            reject(new Error('Failed to get SOCKS proxy server address'))
          }
        }
        // @pondwader/socks5-server's `listen` is a verbatim pass-through to
        // net.Server.listen(...args), so it accepts a unix-socket path despite
        // the (port, hostname) typing. net.Server.listen has ~10 overloads;
        // `Parameters<>` picks the first, so cast through `unknown[]` rather
        // than fork the dependency for a type-only fix.
        const polymorphicListen = socksServer.listen.bind(socksServer) as (
          ...a: unknown[]
        ) => void
        if (target.kind === 'unix') {
          polymorphicListen(target.path, listeningCallback)
        } else {
          polymorphicListen(target.port, target.hostname, listeningCallback)
        }
      })
    },
    async close(): Promise<void> {
      return new Promise((resolve, reject) => {
        socksServer.close(error => {
          if (error) {
            // Only reject for actual errors, not for "already closed" states
            // Check for common "already closed" error patterns
            const errorMessage = error.message?.toLowerCase() || ''
            const isAlreadyClosed =
              errorMessage.includes('not running') ||
              errorMessage.includes('already closed') ||
              errorMessage.includes('not listening')

            if (!isAlreadyClosed) {
              reject(error)
              return
            }
          }
          resolve()
        })
        // Forcibly drop any sockets still open. close() above stopped the
        // listener; the callback won't fire until these drain on their own,
        // and a stuck upstream dial means they may never drain.
        for (const socket of openSockets) {
          socket.destroy()
        }
        openSockets.clear()
      })
    },
    unref(): void {
      // Access the internal server to call unref
      try {
        if (internalServer && typeof internalServer?.unref === 'function') {
          internalServer.unref()
        }
      } catch (error) {
        logForDebugging(`Error calling unref: ${error}`, { level: 'error' })
      }
    },
  }
}
