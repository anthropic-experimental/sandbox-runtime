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
 *   - NO_PROXY matching (hostname suffix + CIDR via net.BlockList,
 *     golang.org/x/net/http/httpproxy semantics)
 *   - a generic CONNECT-tunnel helper that works over Unix socket, TCP, or TLS
 */

import type { Socket } from 'node:net'
import type { IncomingHttpHeaders } from 'node:http'
import { BlockList, connect as netConnect, isIP } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { URL } from 'node:url'
import { logForDebugging } from '../utils/debug.js'

export interface ParentProxyConfig {
  http?: string
  https?: string
  noProxy?: string
}

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

const CONNECT_TIMEOUT_MS = 30_000

/**
 * Hop-by-hop headers per RFC 7230 §6.1, plus proxy-specific headers that
 * MUST NOT be forwarded to the upstream.
 */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * Resolve the parent proxy config, falling back to the SRT process's own
 * environment. Note: SRT later overwrites HTTP_PROXY etc. in the *sandboxed
 * child's* environment to point at itself — but process.env here reflects the
 * environment SRT itself was launched with, which is what we want.
 */
export function resolveParentProxy(
  cfg?: ParentProxyConfig,
): ResolvedParentProxy | undefined {
  const http =
    cfg?.http ?? process.env.HTTP_PROXY ?? process.env.http_proxy ?? undefined
  const https =
    cfg?.https ??
    process.env.HTTPS_PROXY ??
    process.env.https_proxy ??
    // Fall back to HTTP_PROXY for HTTPS if HTTPS_PROXY is unset — this is
    // the de-facto behaviour of curl and most tooling.
    http
  const noProxyRaw =
    cfg?.noProxy ?? process.env.NO_PROXY ?? process.env.no_proxy ?? ''

  if (!http && !https) return undefined

  const parse = (u: string | undefined): URL | undefined => {
    if (!u) return undefined
    try {
      return new URL(u)
    } catch {
      logForDebugging(
        `Invalid parent proxy URL, ignoring: ${redactUserinfo(u)}`,
        { level: 'error' },
      )
      return undefined
    }
  }

  return {
    httpUrl: parse(http),
    httpsUrl: parse(https),
    noProxy: parseNoProxy(noProxyRaw),
  }
}

function parseNoProxy(raw: string): NoProxyRules {
  const rules: NoProxyRules = {
    all: false,
    suffixes: [],
    cidr: new BlockList(),
  }

  for (let entry of raw.split(',')) {
    entry = entry.trim()
    if (!entry) continue
    if (entry === '*') {
      rules.all = true
      continue
    }

    // CIDR?
    const slash = entry.indexOf('/')
    if (slash !== -1) {
      const ip = entry.slice(0, slash)
      const prefixStr = entry.slice(slash + 1)
      const fam = isIP(ip)
      if (fam && prefixStr !== '' && /^\d+$/.test(prefixStr)) {
        const prefix = Number(prefixStr)
        const max = fam === 6 ? 128 : 32
        if (prefix >= 0 && prefix <= max) {
          try {
            rules.cidr.addSubnet(ip, prefix, fam === 6 ? 'ipv6' : 'ipv4')
          } catch {
            // BlockList rejected it; fall through to suffix handling below
          }
          continue
        }
      }
      // malformed CIDR → ignore (do NOT treat as suffix; `/` isn't a valid
      // hostname char)
      continue
    }

    // Hostname suffix. Normalise: lowercase, strip leading `*.`, strip a
    // trailing `:port` — but only if the entry isn't itself an IP literal
    // (IPv6 addresses contain colons).
    let v = entry.toLowerCase()
    if (v.startsWith('*.')) v = v.slice(1)
    if (!isIP(v.replace(/^\[|\]$/g, ''))) {
      const colon = v.lastIndexOf(':')
      if (colon !== -1 && /^\d+$/.test(v.slice(colon + 1))) {
        v = v.slice(0, colon)
      }
    }
    rules.suffixes.push(v)
  }

  return rules
}

/**
 * Returns true if the given host should bypass the parent proxy and connect
 * directly. Always bypasses loopback.
 */
export function shouldBypassParentProxy(
  resolved: ResolvedParentProxy,
  host: string,
  _port: number,
): boolean {
  const h = stripBrackets(host.toLowerCase().replace(/\.$/, ''))

  // Always bypass loopback — chaining localhost through an upstream proxy is
  // never what you want. Covers the whole 127/8 block and IPv4-mapped forms.
  if (h === 'localhost') return true
  const fam = isIP(h)
  if (fam) {
    if (LOOPBACK.check(h, fam === 6 ? 'ipv6' : 'ipv4')) return true
  }

  if (resolved.noProxy.all) return true

  if (fam) {
    if (resolved.noProxy.cidr.check(h, fam === 6 ? 'ipv6' : 'ipv4')) return true
  }

  for (const v of resolved.noProxy.suffixes) {
    if (v.startsWith('.')) {
      // .example.com matches foo.example.com and example.com
      if (h === v.slice(1) || h.endsWith(v)) return true
    } else {
      // example.com matches example.com and foo.example.com (golang semantics)
      if (h === v || h.endsWith('.' + v)) return true
    }
  }
  return false
}

const LOOPBACK = (() => {
  const bl = new BlockList()
  bl.addSubnet('127.0.0.0', 8, 'ipv4')
  bl.addAddress('::1', 'ipv6')
  bl.addSubnet('::ffff:127.0.0.0', 104, 'ipv6') // v4-mapped loopback
  return bl
})()

/**
 * Pick which parent proxy URL to use for a given destination.
 */
export function selectParentProxyUrl(
  resolved: ResolvedParentProxy,
  opts: { isHttps: boolean },
): URL | undefined {
  return opts.isHttps
    ? (resolved.httpsUrl ?? resolved.httpUrl)
    : (resolved.httpUrl ?? resolved.httpsUrl)
}

// ---------------------------------------------------------------------------
// CONNECT tunnelling
// ---------------------------------------------------------------------------

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
export function openConnectTunnel(opts: ConnectTunnelOptions): Promise<Socket> {
  const { destHost, destPort } = opts

  // CRLF-injection guard: destHost may originate from an untrusted SOCKS5
  // DOMAINNAME field. Reject anything that isn't a plain hostname or IP.
  const bare = stripBrackets(destHost)
  if (!isValidHost(bare)) {
    return Promise.reject(
      new Error(
        `Invalid destination host for CONNECT: ${JSON.stringify(destHost)}`,
      ),
    )
  }
  if (!Number.isInteger(destPort) || destPort < 1 || destPort > 65535) {
    return Promise.reject(new Error(`Invalid destination port: ${destPort}`))
  }

  const authority =
    isIP(bare) === 6 ? `[${bare}]:${destPort}` : `${bare}:${destPort}`

  return new Promise((resolve, reject) => {
    const sock = opts.dial()
    let settled = false

    const fail = (err: Error) => {
      if (settled) return
      settled = true
      sock.destroy()
      reject(err)
    }

    sock.setTimeout(opts.timeoutMs ?? CONNECT_TIMEOUT_MS, () =>
      fail(new Error('CONNECT handshake timed out')),
    )
    sock.once('error', fail)
    sock.once('close', () =>
      fail(new Error('Proxy closed during CONNECT handshake')),
    )

    sock.once(opts.readyEvent, () => {
      sock.write(
        `CONNECT ${authority} HTTP/1.1\r\n` +
          `Host: ${authority}\r\n` +
          (opts.authHeader
            ? `Proxy-Authorization: ${opts.authHeader}\r\n`
            : '') +
          '\r\n',
      )

      let buf = ''
      const onData = (chunk: Buffer) => {
        buf += chunk.toString('latin1')
        const end = buf.indexOf('\r\n\r\n')
        if (end === -1) {
          // Cap header size to avoid unbounded buffering on a misbehaving proxy.
          if (buf.length > 16 * 1024)
            fail(new Error('CONNECT response header too large'))
          return
        }
        sock.removeListener('data', onData)

        const statusLine = buf.slice(0, buf.indexOf('\r\n'))
        if (!/^HTTP\/1\.[01] 2\d\d(?:\s|$)/.test(statusLine)) {
          return fail(new Error(`Proxy refused CONNECT: ${statusLine.trim()}`))
        }

        // Re-emit any bytes that arrived after the header terminator.
        const rest = buf.slice(end + 4)
        if (rest.length) sock.unshift(Buffer.from(rest, 'latin1'))

        settled = true
        sock.setTimeout(0)
        sock.removeListener('error', fail)
        sock.removeAllListeners('close')
        resolve(sock)
      }
      sock.on('data', onData)
    })
  })
}

/**
 * Open a CONNECT tunnel through a parent HTTP(S) proxy specified by URL.
 * Thin wrapper around openConnectTunnel that dials TCP or TLS based on the
 * proxy URL scheme.
 */
export function connectViaParentProxy(
  proxyUrl: URL,
  destHost: string,
  destPort: number,
): Promise<Socket> {
  const proxyHost = stripBrackets(proxyUrl.hostname)
  const proxyPort =
    Number(proxyUrl.port) || (proxyUrl.protocol === 'https:' ? 443 : 80)
  const useTls = proxyUrl.protocol === 'https:'

  return openConnectTunnel({
    destHost,
    destPort,
    authHeader: proxyAuthHeader(proxyUrl),
    readyEvent: useTls ? 'secureConnect' : 'connect',
    dial: () =>
      useTls
        ? tlsConnect({
            host: proxyHost,
            port: proxyPort,
            // SNI must be a hostname, never an IP literal (RFC 6066 §3).
            ...(isIP(proxyHost) ? {} : { servername: proxyHost }),
          })
        : netConnect(proxyPort, proxyHost),
  })
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export function proxyAuthHeader(proxyUrl: URL): string | undefined {
  if (!proxyUrl.username) return undefined
  const creds = `${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`
  return `Basic ${Buffer.from(creds).toString('base64')}`
}

/** Strip hop-by-hop and proxy-specific headers before forwarding upstream. */
export function stripHopByHop(h: IncomingHttpHeaders): IncomingHttpHeaders {
  const out: IncomingHttpHeaders = {}
  for (const [k, v] of Object.entries(h)) {
    if (!HOP_BY_HOP.has(k.toLowerCase())) out[k] = v
  }
  return out
}

/** Remove surrounding square brackets from an IPv6 literal. */
export function stripBrackets(host: string): string {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
}

/** Redact userinfo from a URL for safe logging. */
export function redactUrl(u: URL | undefined): string {
  if (!u) return '-'
  if (!u.username && !u.password) return u.href
  const c = new URL(u.href)
  c.username = '***'
  c.password = '***'
  return c.href
}

function redactUserinfo(raw: string): string {
  // Best-effort redaction for unparseable URLs.
  return raw.replace(/\/\/[^@/]*@/, '//***:***@')
}

/** Hostname validation for CONNECT request-target. */
function isValidHost(h: string): boolean {
  if (!h || h.length > 255) return false
  if (isIP(h)) return true
  // RFC 1123 hostname: letters, digits, hyphens, dots. No leading/trailing
  // hyphen in a label; we only enforce the character set here since the goal
  // is CRLF/header injection prevention, not full DNS validation.
  return /^[A-Za-z0-9.-]+$/.test(h)
}
