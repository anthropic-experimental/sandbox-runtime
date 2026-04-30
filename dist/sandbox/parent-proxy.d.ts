/**
 * Parent/upstream HTTP proxy support.
 *
 * When SRT runs in an environment that requires an HTTP proxy for outbound
 * internet access (e.g. inside a VM on a host behind a corporate proxy),
 * SRT's own proxies must chain through that upstream rather than connecting
 * directly.
 *
 * This module provides:
 *   - config resolution (explicit config -> HTTP_PROXY/HTTPS_PROXY/NO_PROXY env)
 *   - NO_PROXY matching (hostname suffix + CIDR via net.BlockList). Follows
 *     golang.org/x/net/http/httpproxy semantics for suffix matching. Note:
 *     port-specific NO_PROXY entries (e.g. `host:8080`) are matched by host
 *     only; the port is ignored.
 *   - a generic CONNECT-tunnel helper that works over Unix socket, TCP, or TLS
 */
import type { Socket } from 'node:net'
import type { IncomingHttpHeaders } from 'node:http'
import { BlockList } from 'node:net'
import { URL } from 'node:url'
import type { ParentProxyConfig } from './sandbox-config.js'
export interface ResolvedParentProxy {
  httpUrl?: URL
  httpsUrl?: URL
  noProxy: NoProxyRules
}
interface NoProxyRules {
  all: boolean
  suffixes: string[]
  cidr: BlockList
}
/**
 * Resolve the parent proxy config, falling back to the SRT process's own
 * environment. Note: SRT later overwrites HTTP_PROXY etc. in the *sandboxed
 * child's* environment to point at itself — but process.env here reflects the
 * environment SRT itself was launched with, which is what we want.
 */
export declare function resolveParentProxy(
  cfg?: ParentProxyConfig,
): ResolvedParentProxy | undefined
/**
 * Returns true if the given host should bypass the parent proxy and connect
 * directly. Always bypasses loopback.
 *
 * NB: the port is not consulted. NO_PROXY entries of the form `host:port` are
 * matched by host only (the port suffix is stripped during parsing).
 */
export declare function shouldBypassParentProxy(
  resolved: ResolvedParentProxy,
  host: string,
): boolean
/**
 * Pick which parent proxy URL to use for a given destination.
 */
export declare function selectParentProxyUrl(
  resolved: ResolvedParentProxy,
  opts: {
    isHttps: boolean
  },
): URL | undefined
export interface ConnectTunnelOptions {
  /** Establish the transport to the proxy. */
  dial(): Socket
  /** Fired when the transport is ready to write (e.g. 'connect'/'secureConnect'). */
  readyEvent: 'connect' | 'secureConnect'
  destHost: string
  destPort: number
  authHeader?: string
  timeoutMs?: number
}
/**
 * Generic CONNECT-tunnel: dial a proxy transport (unix/tcp/tls), send
 * `CONNECT host:port`, wait for a 2xx, and resolve with the tunnelled socket.
 * Validates destHost to prevent CRLF injection from untrusted callers.
 */
export declare function openConnectTunnel(
  opts: ConnectTunnelOptions,
): Promise<Socket>
/**
 * Open a CONNECT tunnel through a parent HTTP(S) proxy specified by URL.
 * Thin wrapper around openConnectTunnel that dials TCP or TLS based on the
 * proxy URL scheme.
 */
export declare function connectViaParentProxy(
  proxyUrl: URL,
  destHost: string,
  destPort: number,
): Promise<Socket>
export declare function proxyAuthHeader(proxyUrl: URL): string | undefined
/**
 * Strip hop-by-hop and proxy-specific headers before forwarding upstream.
 * Also strips any headers named in the incoming `Connection` header, per
 * RFC 7230 §6.1.
 */
export declare function stripHopByHop(
  h: IncomingHttpHeaders,
): IncomingHttpHeaders
/** Remove surrounding square brackets from an IPv6 literal. */
export declare function stripBrackets(host: string): string
/** Redact userinfo from a URL for safe logging. */
export declare function redactUrl(u: URL | undefined): string
/**
 * Hostname validation: accepts DNS names and IP literals (without zone IDs).
 * Primary purpose is to block control characters (CRLF injection, null-byte
 * DNS truncation) and zone-identifier allowlist bypasses from reaching the
 * wire or the allowlist matcher.
 *
 * IPv6 zone IDs (`fe80::1%eth0`) are rejected because `isIP` accepts a very
 * permissive zone charset including dots — `::ffff:1.2.3.4%x.allowed.com`
 * would pass `isIP`, pass a `.endsWith('.allowed.com')` wildcard check, and
 * then connect to 1.2.3.4 when the OS discards the bogus scope.
 */
export declare function isValidHost(h: string): boolean
/**
 * Canonicalize a host string via the WHATWG URL parser so that string
 * comparisons in the allowlist agree with what `net.connect()`/`getaddrinfo()`
 * will actually dial. This normalizes:
 *   - inet_aton shorthand (`127.1` → `127.0.0.1`, `2130706433` → `127.0.0.1`)
 *   - hex/octal octets (`0x7f.0.0.1` → `127.0.0.1`)
 *   - IPv6 compression (`0:0:0:0:0:0:0:1` → `::1`)
 *   - trailing dots, case, brackets
 *
 * Returns undefined if the input is not a valid URL host.
 */
export declare function canonicalizeHost(h: string): string | undefined
/**
 * Dial `host:port` directly with a bounded timeout. Shared by the HTTP and
 * SOCKS direct-connect paths so they get the same timeout behaviour as the
 * CONNECT-tunnelled paths.
 */
export declare function dialDirect(
  host: string,
  port: number,
  timeoutMs?: number,
): Promise<Socket>
export {}
//# sourceMappingURL=parent-proxy.d.ts.map
