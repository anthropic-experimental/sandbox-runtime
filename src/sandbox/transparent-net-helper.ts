/**
 * In-sandbox transparent network helper (Linux only).
 *
 * Runs INSIDE the sandbox, in bwrap's network namespace, which the HOST
 * configures from outside at this helper's request (vendored
 * netns-config, setns via the owner-uid rule — no namespace is ever
 * created in-sandbox, so this works wherever bwrap works). After
 * configuration the namespace has a `local default` route on lo, so every
 * TCP connect to any IP is delivered to local wildcard listeners and
 * `getsockname()` on the accepted socket reports the original
 * destination — no nftables, no IP_TRANSPARENT, no SO_ORIGINAL_DST.
 *
 * The helper provides:
 *  1. A stub DNS resolver on 127.0.0.1:53 (UDP + TCP) that answers every
 *     A query with a unique fake IP from 198.18.0.0/15 (RFC 2544 benchmark
 *     range) and remembers fakeIP→hostname.
 *  2. Transparent TCP capture listeners on a configurable port list. On
 *     accept, the original destination is recovered from the socket's
 *     local address; fake IPs map back to the hostname the client
 *     resolved, anything else is treated as a raw IP-literal destination.
 *     Each captured connection is forwarded to the host-side filtering
 *     proxy (via the existing unix-socket bridge) as an HTTP CONNECT
 *     tunnel, so ALL policy (allowlist, ask-callback, TLS termination,
 *     credential injection) stays on the host, outside the sandbox.
 *  3. Child-process supervision: once the listeners are bound the helper
 *     spawns the user command (argv after `--`) with inherited stdio and
 *     propagates its exit status. This makes listener readiness a
 *     happens-before of the user command with no polling.
 *
 * SECURITY: this process is part of the sandboxed workload, not the
 * enforcement boundary. If it dies or is tampered with, the result is no
 * connectivity (the outer bwrap netns has no interfaces), never wider
 * access. It must stay dependency-free (node builtins only) because it is
 * executed with the host's `process.execPath` inside the sandbox.
 *
 * Environment interface (set by the generated sandbox script):
 *   SRT_TP_BRIDGE  "unix:<path>" or "tcp:<host>:<port>" — the bridge to the
 *                  host-side proxy. tcp form is for tests.
 *   SRT_TP_TOKEN   per-session proxy auth token (optional).
 *   SRT_TP_NETNS   "unix:<path>" or "tcp:<host>:<port>" — the host netns
 *                  rendezvous. FIRST act: send `<token> <netns-inode>\n`,
 *                  require "OK\n" — the host then has configured this
 *                  netns (lo up, local-default routes, low ports) from
 *                  outside via setns. Any failure is FATAL: errors
 *                  propagate, nothing degrades.
 *   SRT_TP_NETNS_TOKEN  secret for the rendezvous hello (tests; production
 *                  uses SRT_TP_TOKEN_FILE).
 *   SRT_TP_TOKEN_FILE  0400 file with `netns=…`/`proxy=…` lines — the
 *                  production secret channel (argv/cmdline is
 *                  world-readable on the host; this file is not).
 *   SRT_TP_CHILD_ARGV0  when set, exported as ARGV0 to the child (the
 *                  apply-seccomp multicall dispatch).
 *   SRT_TP_PORTS   comma-separated TCP ports to capture.
 *   SRT_TP_DEBUG   when set, log to stderr.
 */

import * as net from 'node:net'
import * as dgram from 'node:dgram'
import * as fs from 'node:fs'
import { spawn } from 'node:child_process'
import { constants as osConstants } from 'node:os'
import { pathToFileURL } from 'node:url'

// ============================================================================
// Fake IP pool (198.18.0.0/15)
// ============================================================================

const POOL_BASE = (198 << 24) | (18 << 16) // 198.18.0.0
const POOL_SIZE = 1 << 17 // /15 = 131072 addresses

/**
 * Bidirectional hostname ⇄ fake-IP map. Allocation is sequential from
 * 198.18.0.1. Mappings are NEVER evicted or reused: a slot that changed
 * hostnames mid-command would let one process's stale cached fake IP
 * connect as a different hostname than it resolved. The pool holds 131071
 * names (198.18.0.1 – 198.19.255.255; .0 is skipped) — no legitimate command resolves that many — so on exhaustion new
 * names simply fail to resolve (fail closed).
 */
export class FakeIpPool {
  private hostToIp = new Map<string, string>()
  private ipToHost = new Map<string, string>()
  private allocated = 0

  ipForHost(hostname: string): string | null {
    const host = hostname.toLowerCase()
    const existing = this.hostToIp.get(host)
    if (existing) return existing
    if (this.allocated >= POOL_SIZE - 1) return null // exhausted: fail closed
    // DETERMINISTIC slot (FNV-1a): the same hostname maps to the same
    // fake IP across commands, sessions, and hosts. Sequential
    // allocation was the Clash fake-ip failure mode: an app that
    // persists a resolved fake IP across commands would reconnect to a
    // slot owned by a DIFFERENT (still-allowed) hostname and leak
    // host-A credentials to host B. Collisions (different names, same
    // hash slot) linear-probe — only those rare names are
    // order-dependent, and mappings still never change within a
    // command.
    let h = 0x811c9dc5
    for (let i = 0; i < host.length; i++) {
      h ^= host.charCodeAt(i)
      h = Math.imul(h, 0x01000193) >>> 0
    }
    let slot = 1 + (h % (POOL_SIZE - 1))
    let ip = formatIpv4(POOL_BASE + slot)
    while (this.ipToHost.has(ip)) {
      slot = slot >= POOL_SIZE - 1 ? 1 : slot + 1
      ip = formatIpv4(POOL_BASE + slot)
    }
    this.allocated += 1
    this.hostToIp.set(host, ip)
    this.ipToHost.set(ip, host)
    return ip
  }

  hostForIp(ip: string): string | undefined {
    return this.ipToHost.get(ip)
  }
}

function formatIpv4(n: number): string {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join('.')
}

/** True if `ip` (dotted v4) falls inside the 198.18.0.0/15 fake pool. */
export function isFakePoolIp(ip: string): boolean {
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  const a = Number(parts[0])
  const b = Number(parts[1])
  return a === 198 && (b === 18 || b === 19)
}

// ============================================================================
// DNS codec — just enough for a stub resolver
// ============================================================================

export interface DnsQuery {
  id: number
  flags: number
  /** Lowercased query name, no trailing dot. */
  name: string
  qtype: number
  qclass: number
  /** Raw question section bytes (name + type + class), for echoing. */
  questionBytes: Buffer
}

export const QTYPE_A = 1
export const QTYPE_AAAA = 28

/**
 * Parse a DNS query. Returns null for anything that is not a well-formed
 * single-question query (the caller answers FORMERR or drops it).
 * Compression pointers are not accepted in the question section — real
 * resolvers never send them there.
 */
export function parseDnsQuery(buf: Buffer): DnsQuery | null {
  if (buf.length < 12) return null
  const id = buf.readUInt16BE(0)
  const flags = buf.readUInt16BE(2)
  if (flags & 0x8000) return null // QR set: a response, not a query
  if ((flags & 0x7800) !== 0) return null // non-QUERY opcode (IQUERY/STATUS/…)
  const qdcount = buf.readUInt16BE(4)
  if (qdcount !== 1) return null

  const labels: string[] = []
  let off = 12
  let nameLen = 0
  for (;;) {
    if (off >= buf.length) return null
    const len = buf[off]!
    if (len === 0) {
      off += 1
      break
    }
    if (len > 63) return null // compression pointer or invalid
    nameLen += len + 1
    // RFC 1035 §3.1: whole-name limit is 255 octets INCLUDING the root
    // label's terminating zero, so the label bytes may total at most 254.
    if (nameLen > 254) return null
    if (off + 1 + len > buf.length) return null
    const label = buf.subarray(off + 1, off + 1 + len).toString('latin1')
    // DNS labels are 8-bit clean on the wire, but the name is later
    // interpolated into a CONNECT request line — restrict to LDH plus
    // underscore (covers punycode and _service names) so a sandboxed
    // process can't smuggle CRLF/whitespace through the stub resolver.
    if (!/^[A-Za-z0-9_-]+$/.test(label)) return null
    labels.push(label)
    off += 1 + len
  }
  if (off + 4 > buf.length) return null
  const qtype = buf.readUInt16BE(off)
  const qclass = buf.readUInt16BE(off + 2)
  return {
    id,
    flags,
    name: labels.join('.').toLowerCase(),
    qtype,
    qclass,
    questionBytes: buf.subarray(12, off + 4),
  }
}

/**
 * Build a response for `query`. With `answerIp` set, one A record (TTL 1)
 * is returned; otherwise NOERROR with zero answers (the standard "name
 * exists, no records of this type" reply, which makes stub resolvers fall
 * back from AAAA/HTTPS-RR to A without retrying other servers).
 */
export function buildDnsResponse(
  query: DnsQuery,
  answerIp: string | null,
): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(query.id, 0)
  // QR | (RD from query) | RA, RCODE 0
  header.writeUInt16BE(0x8080 | (query.flags & 0x0100), 2)
  header.writeUInt16BE(1, 4) // QDCOUNT
  header.writeUInt16BE(answerIp ? 1 : 0, 6) // ANCOUNT
  if (!answerIp) return Buffer.concat([header, query.questionBytes])

  const answer = Buffer.alloc(16)
  answer.writeUInt16BE(0xc00c, 0) // pointer to qname at offset 12
  answer.writeUInt16BE(QTYPE_A, 2)
  answer.writeUInt16BE(1, 4) // IN
  answer.writeUInt32BE(1, 6) // TTL 1s — don't let mappings outlive the helper
  answer.writeUInt16BE(4, 10)
  const parts = answerIp.split('.')
  for (let i = 0; i < 4; i++) answer[12 + i] = Number(parts[i])
  return Buffer.concat([header, query.questionBytes, answer])
}

/** FORMERR response for queries we could at least read an ID from. */
export function buildDnsFormErr(buf: Buffer): Buffer | null {
  if (buf.length < 2) return null
  const header = Buffer.alloc(12)
  header.writeUInt16BE(buf.readUInt16BE(0), 0)
  header.writeUInt16BE(0x8001, 2) // QR, RCODE=1 FORMERR
  return header
}

// ============================================================================
// Capture address handling
// ============================================================================

/**
 * Normalize an accepted socket's local address: strip the IPv4-mapped
 * IPv6 prefix a dual-stack listener reports for v4 connections.
 */
export function normalizeCaptureAddress(addr: string): string {
  return addr.startsWith('::ffff:') && addr.includes('.') ? addr.slice(7) : addr
}

/** Format a destination for a CONNECT request-target (bracket IPv6). */
export function formatConnectHost(host: string): string {
  return host.includes(':') ? `[${host}]` : host
}

/**
 * Destinations that must never be forwarded out of the namespace. In the
 * classic path an in-sandbox dial to loopback can structurally never leave
 * the sandbox; forwarding a captured 127.x/::1 connection to the host
 * proxy would re-originate it against the HOST's loopback whenever the
 * config allowlists it. Link-local is excluded for the same reason
 * (169.254.169.254 metadata services). 0.0.0.0 and `::` dial HOST loopback
 * when connect()ed host-side, and v4-compatible ::/96 forms (`::7f00:1`)
 * embed the same; broadcast/multicast have no legitimate forward meaning.
 * The guard does not rely on the kernel canonicalizing these before
 * delivery (it usually does) — fail closed regardless. Destroy instead of
 * forwarding.
 */
export function isForwardableDestination(ip: string): boolean {
  if (ip.startsWith('127.')) return false
  if (ip.startsWith('0.')) return false // 0.0.0.0/8 (0.0.0.0 = host loopback)
  if (ip.startsWith('169.254.')) return false
  if (ip === '255.255.255.255') return false
  if (ip.startsWith('::')) return false // ::, ::1, v4-compatible ::/96
  if (/^fe[89ab]/i.test(ip)) return false // fe80::/10 link-local
  if (/^fe[cdef]/i.test(ip)) return false // fec0::/10 site-local (deprecated)
  if (/^ff[0-9a-f][0-9a-f]:/i.test(ip)) return false // ff00::/8 multicast
  const dot = ip.indexOf('.')
  if (dot > 0 && !ip.includes(':')) {
    const firstOctet = Number(ip.slice(0, dot))
    if (firstOctet >= 224 && firstOctet <= 239) return false // multicast
  }
  return true
}

/** Build the CONNECT request the host-side proxy expects. */
export function buildConnectRequest(
  host: string,
  port: number,
  token: string | undefined,
  markCapturedPlaintext = false,
): string {
  // Defense in depth behind the DNS-label validation: nothing that can
  // break the request line or inject headers may reach the wire.
  if (/[\r\n\s]/.test(host)) {
    throw new Error(`invalid CONNECT host: ${JSON.stringify(host)}`)
  }
  const target = `${formatConnectHost(host)}:${port}`
  let req = `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n`
  if (token) {
    const auth = Buffer.from(`srt:${token}`).toString('base64')
    req += `Proxy-Authorization: Basic ${auth}\r\n`
  }
  if (markCapturedPlaintext) {
    // Tells the host proxy this tunnel carries transparently captured
    // plain HTTP: instead of an opaque byte tunnel it parses the requests
    // through the normal pipeline (filterRequest, credential injection,
    // 403 bodies). Strictly MORE filtering — a client faking the header
    // on a non-HTTP stream just gets its connection parsed and rejected.
    req += 'X-SRT-Captured-Plaintext: 1\r\n'
  }
  return req + '\r\n'
}

/**
 * Find the end of an HTTP response head in `buf` and extract the status
 * code. Returns null while incomplete; throws on a malformed status line.
 */
export function parseProxyResponseHead(
  buf: Buffer,
): { statusCode: number; headLength: number } | null {
  const end = buf.indexOf('\r\n\r\n')
  if (end === -1) return null
  const statusLine = buf.subarray(0, buf.indexOf('\r\n')).toString('latin1')
  const m = /^HTTP\/1\.[01] (\d{3})(?!\d)/.exec(statusLine)
  if (!m) throw new Error(`malformed proxy response: ${statusLine}`)
  return { statusCode: Number(m[1]), headLength: end + 4 }
}

// ============================================================================
// Runtime (only used when executed as a script)
// ============================================================================

type BridgeTarget =
  | { kind: 'unix'; path: string }
  | { kind: 'tcp'; host: string; port: number }

export function parseBridgeSpec(spec: string): BridgeTarget {
  if (spec.startsWith('unix:')) return { kind: 'unix', path: spec.slice(5) }
  if (spec.startsWith('tcp:')) {
    const rest = spec.slice(4)
    const sep = rest.lastIndexOf(':')
    if (sep > 0) {
      const port = Number(rest.slice(sep + 1))
      if (Number.isInteger(port) && port > 0 && port < 65536) {
        return { kind: 'tcp', host: rest.slice(0, sep), port }
      }
    }
  }
  throw new Error(`invalid SRT_TP_BRIDGE: ${spec}`)
}

const debugEnabled = !!process.env.SRT_TP_DEBUG

function debugLog(msg: string): void {
  if (debugEnabled) process.stderr.write(`[srt-transparent] ${msg}\n`)
}

function warnLog(msg: string): void {
  process.stderr.write(`[srt-transparent] warning: ${msg}\n`)
}

const MAX_PROXY_HEAD = 8192
// Early client data is a TLS ClientHello or a plain-HTTP request head —
// a few KB. The cap keeps a sandboxed sender from ballooning the helper
// while a slow proxy dial is in flight.
const MAX_EARLY_CLIENT_DATA = 65536
// Generous because tunnel establishment can legitimately block on a HUMAN:
// the host proxy holds the CONNECT open while the ask-callback waits for
// approval. 30s killed approved connections mid-prompt; per-connection
// parked cost is bounded (64KiB early-data cap).
const BRIDGE_ESTABLISH_TIMEOUT_MS = 300_000

// allowHalfOpen on both legs: a captured connection must emulate a direct
// TCP connection, where shutdown(SHUT_WR) after the request still lets the
// response flow back. pipe() propagates each direction's FIN; the 'close'
// handlers below reap the peer once a socket is fully closed.
function dialBridge(bridge: BridgeTarget): net.Socket {
  return bridge.kind === 'unix'
    ? net.connect({ path: bridge.path, allowHalfOpen: true })
    : net.connect({
        host: bridge.host,
        port: bridge.port,
        allowHalfOpen: true,
      })
}

/**
 * Forward one captured connection: CONNECT through the bridge, then splice.
 * Early client bytes (a TLS ClientHello or plain-HTTP request sent right
 * after the TCP handshake, before the tunnel is up) are buffered
 * explicitly and replayed once the proxy answers 200 — runtimes differ on
 * whether a listener-less socket reliably holds data back.
 */
function forwardCapturedConnection(
  client: net.Socket,
  host: string,
  port: number,
  bridge: BridgeTarget,
  token: string | undefined,
): void {
  // Fail closed on any host string that could break the CONNECT request
  // line (see buildConnectRequest); pool hostnames are label-validated at
  // DNS parse time and IP literals come from the kernel, so this firing
  // means something upstream went wrong.
  if (/[\r\n\s]/.test(host)) {
    debugLog(`refusing unsafe CONNECT host ${JSON.stringify(host)}`)
    client.destroy()
    return
  }
  const upstream = dialBridge(bridge)
  upstream.setNoDelay(true)
  client.setNoDelay(true)

  let established = false
  let head = Buffer.alloc(0)
  let clientEndedEarly = false
  let earlyClientBytes = 0
  const earlyClientData: Buffer[] = []
  const onEarlyClientData = (chunk: Buffer) => {
    earlyClientBytes += chunk.length
    earlyClientData.push(chunk)
    if (earlyClientBytes >= MAX_EARLY_CLIENT_DATA) {
      // Cap reached: stop reading and let TCP backpressure park the rest
      // in kernel buffers. Aborting here would deterministically kill
      // legitimate eager uploads (>64 KiB plain-HTTP POSTs) racing the
      // bridge dial — or parked behind a human ask-callback approval.
      // Memory bound stays ~cap + one chunk; pipe() resumes flow on
      // establishment.
      client.pause()
    }
  }
  client.on('data', onEarlyClientData)

  const abort = (why: string) => {
    debugLog(`tunnel ${host}:${port} aborted: ${why}`)
    clearTimeout(timer)
    client.destroy()
    upstream.destroy()
  }

  const timer = setTimeout(
    () => abort('proxy response timeout'),
    BRIDGE_ESTABLISH_TIMEOUT_MS,
  )
  timer.unref()

  client.on('error', err => {
    if (!established) abort(`client: ${err.message}`)
    else upstream.destroy()
  })
  upstream.on('error', err => abort(`bridge: ${err.message}`))
  // A bridge half-close before the proxy response means no response is
  // coming — abort now instead of parking until the establish timeout.
  upstream.on('end', () => {
    if (!established) abort('bridge closed before proxy response')
  })

  // With allowHalfOpen, a pre-establish client FIN no longer destroys the
  // socket — record it so the FIN can be replayed to the upstream after
  // the buffered request bytes.
  client.on('end', () => {
    if (!established) clientEndedEarly = true
  })

  upstream.on('connect', () => {
    // Non-443 captures are plain protocols (the default port set is 80 and
    // 443; 443 keeps the host's TLS handling: terminate-or-tunnel).
    upstream.write(buildConnectRequest(host, port, token, port !== 443))
  })

  upstream.on('data', chunk => {
    if (established) return // piped below; this listener is removed
    head = Buffer.concat([head, chunk])
    let parsed
    try {
      parsed = parseProxyResponseHead(head)
    } catch (err) {
      abort((err as Error).message)
      return
    }
    if (!parsed) {
      if (head.length > MAX_PROXY_HEAD) abort('oversized proxy response head')
      return
    }
    clearTimeout(timer)
    if (parsed.statusCode !== 200) {
      abort(`proxy refused (${parsed.statusCode})`)
      return
    }
    established = true
    upstream.removeAllListeners('data')
    const leftover = head.subarray(parsed.headLength)
    if (leftover.length) client.write(leftover)
    client.removeListener('data', onEarlyClientData)
    for (const buffered of earlyClientData) upstream.write(buffered)
    earlyClientData.length = 0
    if (clientEndedEarly) {
      // Client already half-closed: forward the FIN; pipe() below won't
      // (its source's 'end' has already fired).
      upstream.end()
      upstream.pipe(client)
    } else {
      client.pipe(upstream)
      upstream.pipe(client)
    }
    debugLog(`tunnel established ${host}:${port}`)
  })

  // 'close' fires only when a socket is FULLY closed (both directions done
  // or destroyed) — half-close keeps the tunnel alive above. Reap the peer
  // with end() (flush, then FIN), not destroy(): destroy() would discard
  // the peer's unflushed outbound bytes, truncating in-flight tunnel data
  // on an orderly close. The peer's remote (the bridge proxy / the
  // in-sandbox app) closes its side in turn, completing the teardown.
  upstream.on('close', () => {
    clearTimeout(timer)
    client.end()
  })
  client.on('close', () => {
    upstream.end()
  })
}

function startCaptureListener(
  port: number,
  pool: FakeIpPool,
  bridge: BridgeTarget,
  token: string | undefined,
): Promise<void> {
  return new Promise(resolve => {
    // allowHalfOpen: see forwardCapturedConnection — captured connections
    // must support shutdown(SHUT_WR) like a direct TCP connection would.
    const server = net.createServer({ allowHalfOpen: true }, sock => {
      const rawDst = sock.localAddress
      if (!rawDst) {
        sock.destroy()
        return
      }
      const dst = normalizeCaptureAddress(rawDst)
      const mapped = pool.hostForIp(dst)
      // Forward target: stub-DNS hostname for fake-pool IPs; the literal
      // IP otherwise (host-side filter decides). Fail closed for unmapped
      // fake-pool addresses (nothing legitimate resolves there) and for
      // loopback/link-local destinations (must never leave the namespace).
      const host =
        mapped ??
        (isFakePoolIp(dst) || !isForwardableDestination(dst) ? null : dst)
      if (host === null) {
        sock.destroy()
        return
      }
      forwardCapturedConnection(
        sock,
        host,
        sock.localPort ?? port,
        bridge,
        token,
      )
    })
    let listening = false
    let triedIpv4Fallback = false
    server.on('error', err => {
      // Kernels with IPv6 disabled outright (ipv6.disable=1) refuse the
      // dual-stack bind; IPv4-only capture is the right degradation there.
      // Only retry for a BIND failure — listen() on an already-listening
      // server throws synchronously.
      if (!listening && !triedIpv4Fallback) {
        triedIpv4Fallback = true
        debugLog(
          `dual-stack bind :${port} failed (${(err as Error).message}); retrying IPv4-only`,
        )
        server.listen({ port, host: '0.0.0.0' }, () => {
          listening = true
          debugLog(`capturing tcp :${port} (ipv4-only)`)
          resolve()
        })
        return
      }
      warnLog(`capture listener :${port} failed: ${(err as Error).message}`)
      resolve()
    })
    // Dual-stack so both fake-IPv4 and IPv6-literal destinations land here.
    server.listen({ port, host: '::', ipv6Only: false }, () => {
      listening = true
      debugLog(`capturing tcp :${port}`)
      resolve()
    })
  })
}

export function handleDnsQuery(buf: Buffer, pool: FakeIpPool): Buffer | null {
  // Drop DNS responses (QR=1) outright instead of answering FORMERR: a
  // spoofed-source response addressed to our own port must not start a
  // FORMERR ↔ FORMERR packet loop.
  if (buf.length >= 4 && (buf.readUInt16BE(2) & 0x8000) !== 0) return null
  const query = parseDnsQuery(buf)
  if (!query) return buildDnsFormErr(buf)
  let ip: string | null = null
  if (query.qclass === 1 && query.qtype === QTYPE_A && query.name) {
    if (query.name === 'localhost') {
      ip = '127.0.0.1'
    } else if (net.isIP(query.name) === 4) {
      // IP-literal "name": answer with itself — except fake-pool literals,
      // which would alias live pool slots (the capture path would forward
      // whatever hostname currently owns that slot).
      ip = isFakePoolIp(query.name) ? null : query.name
    } else {
      ip = pool.ipForHost(query.name)
    }
  }
  debugLog(`dns ${query.name} type=${query.qtype} -> ${ip ?? '(empty)'}`)
  return buildDnsResponse(query, ip)
}

function startDnsUdp(pool: FakeIpPool): Promise<void> {
  return new Promise(resolve => {
    const sock = dgram.createSocket('udp4')
    sock.on('error', err => {
      warnLog(`dns udp :53 failed: ${err.message}`)
      resolve()
    })
    sock.on('message', (msg, rinfo) => {
      // rinfo.port can be 0 from a raw-socket sender; dgram send() to port
      // 0 throws synchronously, which would kill the helper (and with it
      // the user command). Drop and guard.
      if (!rinfo.port) return
      try {
        const resp = handleDnsQuery(msg, pool)
        if (resp) sock.send(resp, rinfo.port, rinfo.address)
      } catch (err) {
        debugLog(`dns udp reply failed: ${(err as Error).message}`)
      }
    })
    sock.bind(53, '127.0.0.1', () => {
      debugLog('dns udp :53 ready')
      resolve()
    })
  })
}

/**
 * Pull complete length-prefixed DNS-over-TCP frames off an accumulation
 * buffer. Pure (exported for tests): returns the extracted frames and
 * the unconsumed remainder.
 */
export function extractDnsTcpFrames(input: Buffer): {
  frames: Buffer[]
  rest: Buffer
} {
  let buf: Buffer = input
  const frames: Buffer[] = []
  while (buf.length >= 2) {
    const len = buf.readUInt16BE(0)
    if (buf.length < 2 + len) break
    frames.push(buf.subarray(2, 2 + len))
    buf = buf.subarray(2 + len)
  }
  return { frames, rest: buf }
}

function startDnsTcp(pool: FakeIpPool): Promise<void> {
  return new Promise(resolve => {
    const server = net.createServer(sock => {
      let buf: Buffer = Buffer.alloc(0)
      sock.on('error', () => {})
      // DNS-over-TCP exchanges are short-lived; reap parked connections so
      // a workload can't accumulate idle sockets against the stub.
      sock.setTimeout(30_000, () => sock.destroy())
      sock.on('data', chunk => {
        buf = Buffer.concat([buf, chunk])
        const { frames, rest } = extractDnsTcpFrames(buf)
        buf = rest
        for (const frame of frames) {
          const resp = handleDnsQuery(frame, pool)
          if (resp) {
            const out = Buffer.alloc(2 + resp.length)
            out.writeUInt16BE(resp.length, 0)
            resp.copy(out, 2)
            sock.write(out)
          }
        }
        if (buf.length > 4096) sock.destroy() // garbage stream
      })
    })
    server.on('error', err => {
      warnLog(`dns tcp :53 failed: ${(err as Error).message}`)
      resolve()
    })
    server.listen(53, '127.0.0.1', () => {
      debugLog('dns tcp :53 ready')
      resolve()
    })
  })
}

function signalExitCode(sig: NodeJS.Signals): number {
  const num = (osConstants.signals as Record<string, number>)[sig]
  return 128 + (num ?? 15)
}

/** Inode of this process's network namespace (from /proc/self/ns/net). */
function ownNetnsInode(): string {
  const link = fs.readlinkSync('/proc/self/ns/net') // "net:[4026531993]"
  const m = /^net:\[(\d+)\]$/.exec(link)
  if (!m) throw new Error(`unparseable netns link: ${link}`)
  return m[1]!
}

const NETNS_RENDEZVOUS_TIMEOUT_MS = 15_000

/**
 * Ask the host to configure this netns. Resolves once the host's
 * netns-config has written "OK\n" on the connection; rejects on anything
 * else — the caller exits, failing the command loudly (no fallback).
 */
function requestNetnsConfig(
  target: BridgeTarget,
  token: string | undefined,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = dialBridge(target)
    const timer = setTimeout(() => {
      sock.destroy()
      reject(new Error('netns rendezvous timed out'))
    }, NETNS_RENDEZVOUS_TIMEOUT_MS)
    timer.unref()
    let buf = ''
    sock.on('connect', () => {
      sock.write(`${token ?? ''} ${ownNetnsInode()}\n`)
    })
    sock.on('data', chunk => {
      buf += String(chunk)
      if (buf.includes('OK\n')) {
        clearTimeout(timer)
        sock.destroy()
        resolve()
      } else if (buf.length > 64) {
        clearTimeout(timer)
        sock.destroy()
        reject(new Error(`unexpected rendezvous reply: ${buf.slice(0, 64)}`))
      }
    })
    sock.on('error', err => {
      clearTimeout(timer)
      reject(new Error(`netns rendezvous failed: ${err.message}`))
    })
    // 'end' (half-close) does not always surface as 'close' promptly
    // under node — a refusal must reject NOW, or the command would
    // proceed as a silent no-op instead of failing loudly.
    sock.on('end', () => {
      clearTimeout(timer)
      sock.destroy()
      if (!buf.includes('OK\n')) {
        reject(new Error('netns rendezvous ended without OK'))
      }
    })
    sock.on('close', () => {
      clearTimeout(timer)
      if (!buf.includes('OK\n')) {
        reject(new Error('netns rendezvous closed without OK'))
      }
    })
  })
}

async function main(): Promise<void> {
  // A helper crash kills the whole command (the user command is our
  // child; bwrap's pidns dies with the inner shell). Stay fail-closed but
  // diagnosable: name the error before exiting.
  process.on('uncaughtException', err => {
    process.stderr.write(
      `[srt-transparent] fatal: ${err?.stack ?? err?.message ?? err}\n`,
    )
    process.exit(1)
  })

  const bridgeSpec = process.env.SRT_TP_BRIDGE
  if (!bridgeSpec) {
    process.stderr.write('[srt-transparent] SRT_TP_BRIDGE not set\n')
    process.exit(1)
  }
  const bridge = parseBridgeSpec(bridgeSpec)
  // Secrets: production delivers them via a 0600 file in the ro asset
  // dir; tests may use plain env vars.
  let token = process.env.SRT_TP_TOKEN || undefined
  let netnsToken = process.env.SRT_TP_NETNS_TOKEN || undefined
  const tokenFile = process.env.SRT_TP_TOKEN_FILE
  if (tokenFile) {
    try {
      for (const line of fs.readFileSync(tokenFile, 'utf8').split('\n')) {
        const eq = line.indexOf('=')
        if (eq === -1) continue
        const key = line.slice(0, eq)
        const value = line.slice(eq + 1).trim()
        if (key === 'proxy' && value) token = value
        if (key === 'netns' && value) netnsToken = value
      }
    } catch (err) {
      process.stderr.write(
        `[srt-transparent] cannot read token file: ${(err as Error).message}\n`,
      )
      process.exit(112)
    }
  }

  // FIRST: have the host configure this netns from outside. Everything
  // below (low-port binds, wildcard capture, the user command's network
  // expectations) depends on it; failure is fatal for the command.
  const netnsSpec = process.env.SRT_TP_NETNS
  if (!netnsSpec) {
    process.stderr.write('[srt-transparent] SRT_TP_NETNS not set\n')
    process.exit(1)
  }
  try {
    await requestNetnsConfig(parseBridgeSpec(netnsSpec), netnsToken)
  } catch (err) {
    process.stderr.write(
      `[srt-transparent] host netns configuration failed: ` +
        `${(err as Error).message}\n`,
    )
    process.exit(112)
  }

  const ports = (process.env.SRT_TP_PORTS ?? '80,443')
    .split(',')
    .map(p => Number(p.trim()))
    .filter(p => Number.isInteger(p) && p > 0 && p < 65536)

  // Child argv is everything after the script path. The `--` separator is
  // optional because runtimes disagree about it: node keeps it in
  // process.argv, bun strips it.
  let childArgv = process.argv.slice(2)
  if (childArgv[0] === '--') childArgv = childArgv.slice(1)

  // bun < 1.4.0 ignores server-side allowHalfOpen: a client FIN after the
  // request kills the accepted socket, silently losing captured-tunnel
  // responses. Fixed in bun 1.4.0.
  // Unconditional: silent captured-response truncation on old bun is
  // worse than one stderr line.
  if (process.versions.bun) {
    const [maj = 0, min = 0] = process.versions.bun.split('.').map(Number)
    if (maj < 1 || (maj === 1 && min < 4)) {
      warnLog(
        `bun ${process.versions.bun} ignores server allowHalfOpen — ` +
          'half-closing clients will lose captured responses; use bun >= 1.4 or node',
      )
    }
  }

  const pool = new FakeIpPool()

  // Bind everything before the user command starts: listener readiness is
  // the happens-before edge that replaces polling. Individual bind
  // failures degrade that listener (warned above) but never block the
  // command — the env-var proxy path still works without us.
  await Promise.all([
    startDnsUdp(pool),
    startDnsTcp(pool),
    ...ports.map(p => startCaptureListener(p, pool, bridge, token)),
  ])

  if (childArgv.length === 0) {
    debugLog('no child command; serving until killed')
    return
  }

  // Scrub helper plumbing from the child env: the workload has no use
  // for the rendezvous address/secrets, and in no-seccomp configurations
  // the env would otherwise hand them over trivially. (Not a secrecy
  // boundary — same trust domain, /proc is readable in-namespace — just
  // removal of the zero-effort path.)
  const childEnv: NodeJS.ProcessEnv = { ...process.env }
  for (const key of Object.keys(childEnv)) {
    if (key.startsWith('SRT_TP_')) delete childEnv[key]
  }
  if (process.env.SRT_TP_CHILD_ARGV0) {
    childEnv.ARGV0 = process.env.SRT_TP_CHILD_ARGV0
  }
  const child = spawn(childArgv[0]!, childArgv.slice(1), {
    stdio: 'inherit',
    env: childEnv,
  })
  for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP'] as const) {
    process.on(sig, () => child.kill(sig))
  }
  child.on('error', err => {
    process.stderr.write(`[srt-transparent] spawn failed: ${err.message}\n`)
    process.exit(127)
  })
  child.on('exit', (code, sig) => {
    process.exit(sig ? signalExitCode(sig) : (code ?? 1))
  })
}

const isMain = (() => {
  try {
    if (!process.argv[1]) return false
    // Basename gate first: when srt is BUNDLED into a consumer's single
    // file, import.meta.url and argv[1] both point at the consumer's
    // bundle and the URL comparison alone would run main() inside the
    // embedding process (and exit it). The executed helper is always
    // named transparent-net-helper.* (the protected copy preserves it).
    const base = process.argv[1].split('/').pop() ?? ''
    if (!/^transparent-net-helper\.(?:ts|mjs|js)$/.test(base)) return false
    // node realpaths import.meta.url for the entry module but leaves
    // argv[1] as invoked — a symlinked tmpdir component would otherwise
    // make this false and the helper silently exit 0 without running.
    const argvPath = fs.realpathSync(process.argv[1])
    return import.meta.url === pathToFileURL(argvPath).href
  } catch {
    return false
  }
})()

if (isMain) {
  main().catch(err => {
    process.stderr.write(`[srt-transparent] fatal: ${err?.message ?? err}\n`)
    process.exit(1)
  })
}
