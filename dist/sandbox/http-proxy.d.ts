import type { Socket, Server } from 'node:net'
import type { Duplex } from 'node:stream'
import type { ResolvedParentProxy } from './parent-proxy.js'
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
export declare function createHttpProxyServer(
  options: HttpProxyServerOptions,
): Server
//# sourceMappingURL=http-proxy.d.ts.map
