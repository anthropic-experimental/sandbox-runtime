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
 *   - NO_PROXY matching (hostname suffix + CIDR, golang.org/x/net/http/httpproxy
 *     semantics)
 *   - a CONNECT-tunnel helper that returns a raw TCP socket piped through the
 *     parent
 */

import type { Socket } from 'node:net'
import { connect as netConnect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import { isIP } from 'node:net'
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
  noProxy: NoProxyRule[]
}

interface NoProxyRule {
  kind: 'all' | 'suffix' | 'cidr'
  value: string
  /** For cidr: pre-parsed bits for matching */
  cidr?: { ip: number[]; prefix: number; v6: boolean }
}

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
      logForDebugging(`Invalid parent proxy URL, ignoring: ${u}`, {
        level: 'error',
      })
      return undefined
    }
  }

  return {
    httpUrl: parse(http),
    httpsUrl: parse(https),
    noProxy: parseNoProxy(noProxyRaw),
  }
}

function parseNoProxy(raw: string): NoProxyRule[] {
  return raw
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map((entry): NoProxyRule => {
      if (entry === '*') return { kind: 'all', value: '*' }
      const cidr = parseCidr(entry)
      if (cidr) return { kind: 'cidr', value: entry, cidr }
      // Normalise: strip leading *./. and a trailing :port, lowercase
      let v = entry.toLowerCase()
      if (v.startsWith('*.')) v = v.slice(1)
      // suffix rules keep a leading dot to mean "subdomain-of"; bare names
      // match exactly *or* as a suffix (golang httpproxy semantics)
      const colon = v.lastIndexOf(':')
      if (colon !== -1 && /^\d+$/.test(v.slice(colon + 1))) {
        v = v.slice(0, colon)
      }
      return { kind: 'suffix', value: v }
    })
}

/**
 * Returns true if the given host:port should bypass the parent proxy.
 * Always bypasses loopback.
 */
export function shouldBypassParentProxy(
  resolved: ResolvedParentProxy,
  host: string,
  _port: number,
): boolean {
  const h = host.toLowerCase().replace(/\.$/, '')

  // Always bypass loopback regardless of NO_PROXY — chaining localhost through
  // an upstream proxy is never what you want.
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return true

  for (const rule of resolved.noProxy) {
    if (rule.kind === 'all') return true
    if (rule.kind === 'cidr' && rule.cidr) {
      if (isIP(h) && ipInCidr(h, rule.cidr)) return true
      continue
    }
    // suffix
    const v = rule.value
    if (v.startsWith('.')) {
      // .example.com matches foo.example.com and example.com
      if (h === v.slice(1) || h.endsWith(v)) return true
    } else {
      // example.com matches example.com and foo.example.com
      if (h === v || h.endsWith('.' + v)) return true
    }
  }
  return false
}

/**
 * Pick which parent proxy URL to use for a given destination port. We treat
 * 443 as HTTPS and everything else as HTTP — callers that know better should
 * pass an explicit `isHttps`.
 */
export function selectParentProxyUrl(
  resolved: ResolvedParentProxy,
  opts: { isHttps: boolean },
): URL | undefined {
  return opts.isHttps
    ? (resolved.httpsUrl ?? resolved.httpUrl)
    : (resolved.httpUrl ?? resolved.httpsUrl)
}

/**
 * Open a TCP connection to `destHost:destPort` tunnelled through the parent
 * HTTP proxy's CONNECT method. Resolves with a socket that is already piped
 * through to the destination; the caller can immediately pipe TLS or raw TCP
 * over it.
 */
export function connectViaParentProxy(
  proxyUrl: URL,
  destHost: string,
  destPort: number,
): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const proxyPort = Number(proxyUrl.port) || defaultPort(proxyUrl.protocol)
    const proxyHost = proxyUrl.hostname

    const useTls = proxyUrl.protocol === 'https:'
    const sock: Socket = useTls
      ? tlsConnect({
          host: proxyHost,
          port: proxyPort,
          servername: proxyHost,
        })
      : netConnect(proxyPort, proxyHost)

    let settled = false
    const fail = (err: Error) => {
      if (settled) return
      settled = true
      sock.destroy()
      reject(err)
    }

    sock.once('error', fail)

    const onConnect = () => {
      const authHeader = proxyAuthHeader(proxyUrl)
      sock.write(
        `CONNECT ${destHost}:${destPort} HTTP/1.1\r\n` +
          `Host: ${destHost}:${destPort}\r\n` +
          (authHeader ? `Proxy-Authorization: ${authHeader}\r\n` : '') +
          '\r\n',
      )

      let buf = ''
      const onData = (chunk: Buffer) => {
        buf += chunk.toString('latin1')
        const end = buf.indexOf('\r\n\r\n')
        if (end === -1) return
        sock.removeListener('data', onData)

        const statusLine = buf.slice(0, buf.indexOf('\r\n'))
        if (!/ 200 /.test(statusLine)) {
          return fail(
            new Error(`Parent proxy refused CONNECT: ${statusLine.trim()}`),
          )
        }

        // Re-emit any bytes the proxy sent after the header terminator —
        // rare for CONNECT but possible.
        const rest = buf.slice(end + 4)
        if (rest.length) sock.unshift(Buffer.from(rest, 'latin1'))

        settled = true
        sock.removeListener('error', fail)
        resolve(sock)
      }
      sock.on('data', onData)
    }

    if (useTls) sock.once('secureConnect', onConnect)
    else sock.once('connect', onConnect)
  })
}

export function proxyAuthHeader(proxyUrl: URL): string | undefined {
  if (!proxyUrl.username) return undefined
  const creds = `${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`
  return `Basic ${Buffer.from(creds).toString('base64')}`
}

function defaultPort(protocol: string): number {
  return protocol === 'https:' ? 443 : 80
}

// --- CIDR matching --------------------------------------------------------

function parseCidr(
  s: string,
): { ip: number[]; prefix: number; v6: boolean } | undefined {
  const slash = s.indexOf('/')
  if (slash === -1) return undefined
  const ipStr = s.slice(0, slash)
  const prefix = Number(s.slice(slash + 1))
  if (!Number.isInteger(prefix) || prefix < 0) return undefined
  const fam = isIP(ipStr)
  if (fam === 4) {
    if (prefix > 32) return undefined
    const parts = ipStr.split('.').map(Number)
    return { ip: parts, prefix, v6: false }
  }
  if (fam === 6) {
    if (prefix > 128) return undefined
    return { ip: expandV6(ipStr), prefix, v6: true }
  }
  return undefined
}

function ipInCidr(
  ipStr: string,
  cidr: { ip: number[]; prefix: number; v6: boolean },
): boolean {
  const fam = isIP(ipStr)
  if (fam === 4 && !cidr.v6) {
    const ip = ipStr.split('.').map(Number)
    return bitsMatch(ip, cidr.ip, cidr.prefix, 8)
  }
  if (fam === 6 && cidr.v6) {
    const ip = expandV6(ipStr)
    return bitsMatch(ip, cidr.ip, cidr.prefix, 16)
  }
  return false
}

function bitsMatch(
  a: number[],
  b: number[],
  prefix: number,
  bitsPerWord: number,
): boolean {
  let remaining = prefix
  for (let i = 0; i < a.length && remaining > 0; i++) {
    const take = Math.min(bitsPerWord, remaining)
    const mask = (0xffff << (bitsPerWord - take)) & ((1 << bitsPerWord) - 1)
    if ((a[i]! & mask) !== (b[i]! & mask)) return false
    remaining -= take
  }
  return true
}

function expandV6(s: string): number[] {
  // Produce 8 x 16-bit groups. Handles :: compression; does not handle
  // embedded v4 (rare in NO_PROXY).
  const parts = s.split('::')
  const head = parts[0] ? parts[0].split(':') : []
  const tail = parts[1] ? parts[1].split(':') : []
  const fill = 8 - head.length - tail.length
  const groups = [
    ...head,
    ...Array(Math.max(0, fill)).fill('0'),
    ...tail,
  ].slice(0, 8)
  return groups.map(g => parseInt(g || '0', 16))
}
