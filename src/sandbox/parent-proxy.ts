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
import * as dns from 'node:dns'
import { BlockList, connect as netConnect, isIP } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { URL } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
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

const CONNECT_TIMEOUT_MS = 30_000

/**
 * Hop-by-hop headers per RFC 7230 §6.1, plus proxy-specific headers that
 * MUST NOT be forwarded to the upstream. `transfer-encoding` is included
 * because we re-frame bodies via Node's client; Content-Length is preserved
 * end-to-end (Node's llhttp already rejects the TE+CL smuggling vector).
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
    // Accept schemeless `host:port` like curl does, but reject any scheme
    // other than http/https.
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(u)
    const withScheme = hasScheme ? u : `http://${u}`
    try {
      const parsed = new URL(withScheme)
      if (
        (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
        !parsed.hostname
      ) {
        throw new Error('unsupported scheme or empty host')
      }
      return parsed
    } catch {
      logForDebugging(
        `Invalid parent proxy URL, ignoring: ${redactUserinfo(u)}`,
        { level: 'error' },
      )
      return undefined
    }
  }

  const httpUrl = parse(http)
  const httpsUrl = parse(https)
  // If both parsed to undefined, behave as if no parent proxy was configured
  // rather than returning a husk object that makes callers do bypass checks
  // for nothing.
  if (!httpUrl && !httpsUrl) return undefined

  return { httpUrl, httpsUrl, noProxy: parseNoProxy(noProxyRaw) }
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
            // BlockList rejected it — ignore this entry.
          }
          continue
        }
      }
      // malformed CIDR → ignore (do NOT treat as suffix; `/` isn't a valid
      // hostname char)
      continue
    }

    // Hostname suffix. Normalise: lowercase, strip brackets (handling the
    // `[v6]:port` form), strip leading `*.`, strip a trailing `:port` (unless
    // the entry is an IP literal — IPv6 addresses contain colons).
    let v = entry.toLowerCase()
    const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(v)
    if (bracketed) v = bracketed[1]!
    if (v.startsWith('*.')) v = v.slice(1)
    const bareFam = isIP(v)
    if (!bareFam) {
      const colon = v.lastIndexOf(':')
      if (colon !== -1 && /^\d+$/.test(v.slice(colon + 1))) {
        v = v.slice(0, colon)
      }
    } else {
      // Bare IP literal — store as an exact-match /32 or /128 CIDR so that
      // lookups go through BlockList rather than string suffix matching.
      try {
        rules.cidr.addAddress(v, bareFam === 6 ? 'ipv6' : 'ipv4')
        continue
      } catch {
        // fall through to suffix push
      }
    }
    rules.suffixes.push(v)
  }

  return rules
}

/**
 * Returns true if the given host should bypass the parent proxy and connect
 * directly. Always bypasses loopback.
 *
 * NB: the port is not consulted. NO_PROXY entries of the form `host:port` are
 * matched by host only (the port suffix is stripped during parsing).
 */
export function shouldBypassParentProxy(
  resolved: ResolvedParentProxy,
  host: string,
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
  if (opts.isHttps) return resolved.httpsUrl ?? resolved.httpUrl
  // For plain HTTP we only fall back to HTTPS_PROXY if it was explicitly set
  // — matches curl's behaviour where HTTP requests go direct if only
  // HTTPS_PROXY is configured.
  return resolved.httpUrl
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
    const onClose = () =>
      fail(new Error('Proxy closed during CONNECT handshake'))

    sock.setTimeout(opts.timeoutMs ?? CONNECT_TIMEOUT_MS, () =>
      fail(new Error('CONNECT handshake timed out')),
    )
    sock.once('error', fail)
    sock.once('close', onClose)

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
        // Pause before detaching the data listener so the stream stops
        // flowing — otherwise the unshift below (or any bytes arriving
        // between now and the caller's pipe()) would be dropped.
        sock.pause()
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
        sock.removeListener('close', onClose)
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
  if (!proxyUrl.username && !proxyUrl.password) return undefined
  try {
    const creds = `${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`
    return `Basic ${Buffer.from(creds).toString('base64')}`
  } catch {
    // Malformed percent-encoding in userinfo — fall back to raw values
    // rather than throwing synchronously into the caller.
    const creds = `${proxyUrl.username}:${proxyUrl.password}`
    return `Basic ${Buffer.from(creds).toString('base64')}`
  }
}

/**
 * Strip hop-by-hop and proxy-specific headers before forwarding upstream.
 * Also strips any headers named in the incoming `Connection` header, per
 * RFC 7230 §6.1.
 */
export function stripHopByHop(h: IncomingHttpHeaders): IncomingHttpHeaders {
  const extra = new Set<string>()
  const connHeader = h.connection
  if (connHeader) {
    for (const tok of String(connHeader).split(',')) {
      extra.add(tok.trim().toLowerCase())
    }
  }
  const out: IncomingHttpHeaders = {}
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase()
    if (!HOP_BY_HOP.has(lk) && !extra.has(lk)) out[k] = v
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
export function isValidHost(h: string): boolean {
  if (!h || h.length > 255) return false
  const bare = stripBrackets(h)
  // Reject zone identifiers outright (see doc comment).
  if (bare.includes('%')) return false
  if (isIP(bare)) return true
  // DNS label charset. Underscore is permitted for compatibility with real-
  // world DNS records (_dmarc, _acme-challenge, etc.).
  return /^[A-Za-z0-9._-]+$/.test(bare)
}

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
export function canonicalizeHost(h: string): string | undefined {
  try {
    const bare = stripBrackets(h)
    // WHATWG URL rejects zone IDs and most garbage; it normalizes inet_aton
    // forms and IPv6 compression. It does NOT strip trailing dots or IPv6
    // brackets from the output, so we do that ourselves.
    const bracketed = isIP(bare) === 6 ? `[${bare}]` : bare
    const out = new URL(`http://${bracketed}/`).hostname
    return stripBrackets(out).replace(/\.$/, '')
  } catch {
    return undefined
  }
}

/** Parse an IPv6 string to 16 bytes; null when unparseable. */
function ipv6ToBytes(addr: string): Uint8Array | null {
  let a = addr
  let embeddedV4: number[] | null = null
  const dq = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(a)
  if (dq) {
    // Strict dotted quad (inet_pton parity): no leading zeros/signs.
    const quad = dq[2]!.split('.')
    if (quad.some(p => !/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255)) {
      return null
    }
    embeddedV4 = quad.map(Number)
    a = dq[1]! + '0:0' // placeholder, replaced below
  }
  const halves = a.split('::')
  if (halves.length > 2) return null
  const head = halves[0] === '' ? [] : halves[0]!.split(':')
  const tail =
    halves.length === 2 ? (halves[1] === '' ? [] : halves[1]!.split(':')) : []
  const groups = halves.length === 2 ? head.length + tail.length : head.length
  if (halves.length === 1 && groups !== 8) return null
  if (groups > 8) return null
  const words: number[] = []
  const parseGroups = (gs: string[]) => {
    for (const g of gs) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false
      words.push(parseInt(g, 16))
    }
    return true
  }
  if (!parseGroups(head)) return null
  const fill = 8 - groups
  // RFC 4291 / inet_pton: '::' must stand for at least ONE zero group —
  // 8-explicit-groups-plus-'::' spellings are kernel-invalid and must
  // refuse (fail closed) rather than parse.
  if (halves.length === 2 && fill < 1) return null
  for (let i = 0; i < (halves.length === 2 ? fill : 0); i++) words.push(0)
  if (!parseGroups(tail)) return null
  if (words.length !== 8) return null
  const bytes = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    bytes[2 * i] = words[i]! >> 8
    bytes[2 * i + 1] = words[i]! & 0xff
  }
  if (embeddedV4) {
    bytes[12] = embeddedV4[0]!
    bytes[13] = embeddedV4[1]!
    bytes[14] = embeddedV4[2]!
    bytes[15] = embeddedV4[3]!
  }
  return bytes
}

function isBlockedV4Octets(o: number[]): boolean {
  if (o[0] === 127 || o[0] === 0) return true // loopback, "this network"
  if (o[0] === 169 && o[1] === 254) return true // link-local + metadata
  // Azure WireServer: a fixed PUBLIC-range address serving the
  // metadata/agent plane on Azure VMs (Microsoft-documented).
  if (o[0] === 168 && o[1] === 63 && o[2] === 129 && o[3] === 16) return true
  if (o[0] === 198 && (o[1] === 18 || o[1] === 19)) return true // fake pool
  // CGNAT 100.64/10 policy — DELIBERATE, mirrors the RFC1918 decision:
  // resolved-to-private is allowed BY DESIGN (intranet/tailnet names
  // legitimately resolve there; Tailscale assigns across the ENTIRE /10,
  // so there is no narrower tailnet carve-out), but documented metadata
  // services inside the range are denied. Known: Alibaba Cloud metadata
  // (100.100.100.200) and its internal-service /16. If another cloud
  // ships CGNAT-hosted metadata, extend THIS list — do not widen to the
  // full /10 without also blocking RFC1918, or the policy is incoherent.
  if (o[0] === 100 && o[1] === 100) return true // Alibaba 100.100/16
  if (o[0]! >= 224 && o[0]! <= 239) return true // multicast 224/4
  // Class E 240/4 unicast is ALLOWED (same resolved-to-private policy
  // as RFC1918/CGNAT above: Kubernetes fabrics use it as pod/service
  // space) — only the limited-broadcast address is refused.
  if (o[0] === 255 && o[1] === 255 && o[2] === 255 && o[3] === 255) {
    return true
  }
  return false
}

/**
 * True for address ranges the proxy must never dial as the result of a
 * NAME resolution: DNS rebinding would otherwise turn one approved
 * hostname into host-loopback/link-local (cloud metadata) reach — the
 * exact resources netns isolation withholds. IP LITERALS are exempt by
 * design: the filter saw the literal and allowed it explicitly (tests
 * and intranet configs legitimately allow 127.0.0.1 or 10.x).
 * IPv6 is classified on PARSED BYTES: every spelling form —
 * compressed, uncompressed, mixed case, hex-mapped, v4-compatible —
 * lands on the same rules; unparseable v6 fails closed.
 */
export function isBlockedResolvedAddress(addr: string): boolean {
  const a = addr.toLowerCase()
  if (!a.includes(':')) {
    // Strict dotted-quad: digits only, no leading zeros (inet_pton
    // parity — '1e2'/'+66'/'0177' spellings refuse rather than parse).
    const parts = a.split('.')
    if (
      parts.length !== 4 ||
      parts.some(p2 => !/^(0|[1-9]\d{0,2})$/.test(p2) || Number(p2) > 255)
    ) {
      return true
    }
    return isBlockedV4Octets(parts.map(Number))
  }
  const b = ipv6ToBytes(a)
  if (b === null) return true // unparseable v6: refuse
  const allZero = (from: number, to: number) => {
    for (let i = from; i < to; i++) if (b[i] !== 0) return false
    return true
  }
  // :: and ::1
  if (allZero(0, 15) && (b[15] === 0 || b[15] === 1)) return true
  // v4-mapped ::ffff:0:0/96 and v4-compatible ::/96 → v4 rules
  if (allZero(0, 10) && b[10] === 0xff && b[11] === 0xff) {
    return isBlockedV4Octets([b[12]!, b[13]!, b[14]!, b[15]!])
  }
  if (allZero(0, 12)) {
    return isBlockedV4Octets([b[12]!, b[13]!, b[14]!, b[15]!])
  }
  // SIIT "IPv4-translated" ::ffff:0:a.b.c.d (RFC 2765) → v4 rules too.
  if (
    allZero(0, 8) &&
    b[8] === 0xff &&
    b[9] === 0xff &&
    b[10] === 0 &&
    b[11] === 0
  ) {
    return isBlockedV4Octets([b[12]!, b[13]!, b[14]!, b[15]!])
  }
  // NAT64 64:ff9b::/96
  if (
    b[0] === 0 &&
    b[1] === 0x64 &&
    b[2] === 0xff &&
    b[3] === 0x9b &&
    allZero(4, 12)
  ) {
    return true
  }
  if (b[0] === 0xff) return true // multicast ff00::/8
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true // fe80::/10
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0xc0) return true // fec0::/10
  if ((b[0]! & 0xfe) === 0xfc) return true // ULA fc00::/7
  if (b[0] === 0x20 && b[1] === 0x02) return true // 6to4 2002::/16
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0 && b[3] === 0) return true // Teredo
  return false
}

/**
 * dns.lookup wrapper that refuses blocked resolved addresses. Passed as
 * the `lookup` option on every direct-egress dial; node skips it for IP
 * literals (which stay the filter's explicit responsibility). localhost
 * is exempt like a literal: allowing the NAME localhost is unambiguous.
 */
export function vettedLookup(
  hostname: string,
  optionsOrCallback:
    | dns.LookupOptions
    | number
    | ((
        err: NodeJS.ErrnoException | null,
        address: string | dns.LookupAddress[],
        family?: number,
      ) => void),
  maybeCallback?: (
    err: NodeJS.ErrnoException | null,
    address: string | dns.LookupAddress[],
    family?: number,
  ) => void,
): void {
  // Normalize dns.lookup's legacy arities: (host, cb) and (host, family,
  // cb) — silently dropping a family constraint would change dial
  // behavior for callers using the old forms.
  const callback =
    typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback!
  const options: dns.LookupOptions =
    typeof optionsOrCallback === 'function'
      ? {}
      : typeof optionsOrCallback === 'number'
        ? { family: optionsOrCallback as 4 | 6 }
        : optionsOrCallback
  // localhost names are EXPECTED to be loopback (RFC 6761) — enforce
  // that intent instead of exempting them entirely: only loopback
  // results pass, so a resolver answering a public IP for *.localhost
  // is refused too.
  // DNS names are case-insensitive (RFC 4343) and the allowlist
  // matcher already folds case — fold here too or 'LOCALHOST' skips
  // the exemption and refuses where a plain dial connected.
  const hn = hostname.toLowerCase()
  const localhostName = hn === 'localhost' || hn.endsWith('.localhost')
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) {
      callback(err, options.all ? [] : '', 4)
      return
    }
    const isLoopback = (addr: string) =>
      addr === '::1' || /^127\./.test(addr) || addr === '::ffff:127.0.0.1'
    const list = (addresses as dns.LookupAddress[]).filter(a =>
      localhostName
        ? isLoopback(a.address)
        : !isBlockedResolvedAddress(a.address),
    )
    if (list.length === 0) {
      const e = new Error(
        `refusing to dial ${hostname}: resolves only to blocked address ranges (loopback/link-local/reserved)`,
      ) as NodeJS.ErrnoException
      e.code = 'ERT_BLOCKED_RESOLVE'
      callback(e, options.all ? [] : '', 4)
      return
    }
    if (options.all) callback(null, list)
    else callback(null, list[0]!.address, list[0]!.family)
  })
}

/**
 * Dial `host:port` directly with a bounded timeout. Shared by the HTTP and
 * SOCKS direct-connect paths so they get the same timeout behaviour as the
 * CONNECT-tunnelled paths.
 */
export function dialDirect(
  host: string,
  port: number,
  timeoutMs = CONNECT_TIMEOUT_MS,
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const s = netConnect({
      port,
      host,
      lookup: vettedLookup as never,
    })
    let settled = false
    const done = (err?: Error) => {
      if (settled) return
      settled = true
      s.setTimeout(0)
      if (err) {
        s.destroy()
        reject(err)
      } else {
        resolve(s)
      }
    }
    s.setTimeout(timeoutMs, () => done(new Error('connect timed out')))
    s.once('connect', () => done())
    s.once('error', done)
    s.once('close', () => done(new Error('socket closed before connect')))
  })
}
