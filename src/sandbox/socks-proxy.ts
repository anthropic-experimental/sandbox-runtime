import type { Server as NetServer, Socket } from 'net'
import { connect as netConnect } from 'net'
import type { Socks5Server } from '@pondwader/socks5-server'
import { createServer } from '@pondwader/socks5-server'
import { logForDebugging } from '../utils/debug.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import {
  connectViaParentProxy,
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

export interface SocksProxyWrapper {
  server: Socks5Server
  getPort(): number | undefined
  listen(port: number, hostname: string): Promise<number>
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

    const parentUrl =
      options.parentProxy &&
      !shouldBypassParentProxy(options.parentProxy, host, port)
        ? selectParentProxyUrl(options.parentProxy, { isHttps: port === 443 })
        : undefined

    const open = parentUrl
      ? connectViaParentProxy(parentUrl, host, port)
      : new Promise<Socket>((resolve, reject) => {
          const s = netConnect(port, host, () => resolve(s))
          s.once('error', reject)
        })

    open.then(
      upstream => {
        sendStatus('REQUEST_GRANTED')
        upstream.pipe(conn.socket)
        conn.socket.pipe(upstream)
        upstream.on('error', () => conn.socket.destroy())
        conn.socket.on('error', () => upstream.destroy())
        conn.socket.on('end', () => upstream.end())
        upstream.on('end', () => conn.socket.end())
      },
      err => {
        logForDebugging(
          `SOCKS connect to ${host}:${port} failed: ${(err as Error).message}`,
          { level: 'error' },
        )
        sendStatus('HOST_UNREACHABLE')
      },
    )
  })

  return {
    server: socksServer,
    getPort(): number | undefined {
      // Access the internal server to get the port
      // We need to use type assertion here as the server property is private
      try {
        const serverInternal = (
          socksServer as unknown as { server?: NetServer }
        )?.server
        if (serverInternal && typeof serverInternal?.address === 'function') {
          const address = serverInternal.address()
          if (address && typeof address === 'object' && 'port' in address) {
            return address.port
          }
        }
      } catch (error) {
        // Server might not be listening yet or property access failed
        logForDebugging(`Error getting port: ${error}`, { level: 'error' })
      }
      return undefined
    },
    listen(port: number, hostname: string): Promise<number> {
      return new Promise((resolve, reject) => {
        const listeningCallback = (): void => {
          const actualPort = this.getPort()
          if (actualPort) {
            logForDebugging(
              `SOCKS proxy listening on ${hostname}:${actualPort}`,
            )
            resolve(actualPort)
          } else {
            reject(new Error('Failed to get SOCKS proxy server port'))
          }
        }
        socksServer.listen(port, hostname, listeningCallback)
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
      })
    },
    unref(): void {
      // Access the internal server to call unref
      try {
        const serverInternal = (
          socksServer as unknown as { server?: NetServer }
        )?.server
        if (serverInternal && typeof serverInternal?.unref === 'function') {
          serverInternal.unref()
        }
      } catch (error) {
        logForDebugging(`Error calling unref: ${error}`, { level: 'error' })
      }
    },
  }
}
