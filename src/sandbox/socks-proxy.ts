import { timingSafeEqual } from 'node:crypto'
import type { Socket } from 'net'
import { logForDebugging } from '../utils/debug.js'
import type { ResolvedParentProxy } from './parent-proxy.js'
import {
  connectViaParentProxy,
  dialDirect,
  isValidHost,
  selectParentProxyUrl,
  shouldBypassParentProxy,
} from './parent-proxy.js'

/**
 * Minimal SOCKS5 server (RFC 1928 CONNECT + RFC 1929 user/pass auth),
 * implemented in-house so the greeting can offer BOTH auth methods at once —
 * which is what makes sandboxed git-over-SSH work on macOS:
 *
 * When `proxyAuthToken` is set, credential-capable clients (curl via
 * FTP_PROXY, etc.) authenticate with user "srt" + the token, exactly as
 * before. But Apple's /usr/bin/nc — the only tunnel helper macOS ships for
 * ssh's ProxyCommand — cannot speak SOCKS5 auth at all (it has no -P flag,
 * and offers only the no-auth method). For those clients the server accepts
 * the no-auth method and moves the credential into the one field nc DOES
 * transmit verbatim: the destination hostname. The injected GIT_SSH_COMMAND
 * dials `<token>.<host>`, and an unauthenticated connection is admitted only
 * when its destination carries that prefix, which is stripped before the
 * allowlist filter and the dial. Same secret, same strength, different
 * field. A no-auth connection without the prefix is refused — that class of
 * connection could not connect at all before this mechanism existed. The
 * prefix only fits in a DOMAINNAME destination; no-auth requests carrying a
 * raw IPv4/IPv6 address (clients that pre-resolve DNS) stay refused, exactly
 * as they were.
 */

/** RFC 1928 auth method codes. */
const AUTH_NONE = 0x00
const AUTH_USERPASS = 0x02
const AUTH_NO_ACCEPTABLE = 0xff

/** RFC 1928 reply codes. */
const REPLY_SUCCEEDED = 0x00
const REPLY_NOT_ALLOWED = 0x02
const REPLY_NETWORK_UNREACHABLE = 0x03
const REPLY_HOST_UNREACHABLE = 0x04
const REPLY_CONNECTION_REFUSED = 0x05
const REPLY_COMMAND_NOT_SUPPORTED = 0x07

/** Bound on the pre-tunnel phase (handshake through dial). Generous — a real
 *  client completes it in milliseconds — but finite, so stalled or lingering
 *  connections can't pin sockets until close(). */
const HANDSHAKE_TIMEOUT_MS = 30_000

export interface SocksProxyServerOptions {
  filter(port: number, host: string): Promise<boolean> | boolean

  /**
   * Optional upstream HTTP proxy. When present, SOCKS CONNECT requests are
   * tunnelled through the parent's HTTP CONNECT instead of dialing directly.
   * NO_PROXY-matched hosts still connect directly.
   */
  parentProxy?: ResolvedParentProxy

  /**
   * Per-session token (same value as the HTTP proxy's). When set, a
   * connection must either authenticate via SOCKS5 username/password as
   * user "srt" with this token, or prefix its destination hostname with
   * `<token>.` (the no-auth escape hatch for clients like Apple's nc that
   * cannot speak SOCKS5 auth — see the module doc).
   */
  proxyAuthToken?: string
}

export interface SocksProxyWrapper {
  /**
   * Hand an already-accepted socket to the SOCKS state machine. Used by the
   * mux front-end after first-byte sniffing. The socket must carry the full
   * SOCKS greeting starting at byte 0 (i.e. any peeked bytes already
   * `unshift()`ed back).
   */
  handleConnection(socket: Socket): void
  /** Force-destroy all injected connections. */
  close(): Promise<void>
}

/**
 * Incremental reader over a paused socket: each read() takes exactly `len`
 * bytes, pushing any surplus back onto the stream for the next read (or for
 * the relay phase, which starts from whatever the reader didn't consume).
 * Rejects on close/error so an abandoned handshake can't leak a promise.
 */
function makeByteReader(socket: Socket): (len: number) => Promise<Buffer> {
  return (len: number) =>
    new Promise<Buffer>((resolve, reject) => {
      // A zero-length field (RFC 1929 ULEN/PLEN, DOMAINNAME length) must
      // resolve immediately — waiting for a data event would stall until
      // the client's NEXT write.
      if (len === 0) {
        resolve(Buffer.alloc(0))
        return
      }
      const buf = Buffer.allocUnsafe(len)
      let offset = 0
      const cleanup = (): void => {
        socket.removeListener('data', onData)
        socket.removeListener('close', onClose)
        socket.removeListener('error', onClose)
      }
      const onClose = (): void => {
        cleanup()
        reject(new Error('socket closed during SOCKS handshake'))
      }
      const onData = (chunk: Buffer): void => {
        const take = Math.min(chunk.length, len - offset)
        chunk.copy(buf, offset, 0, take)
        offset += take
        if (offset < len) return
        cleanup()
        if (take < chunk.length) socket.unshift(chunk.subarray(take))
        socket.pause()
        resolve(buf)
      }
      socket.on('data', onData)
      socket.once('close', onClose)
      socket.once('error', onClose)
      socket.resume()
    })
}

/** `05 REP 00 01 0.0.0.0 0000` — the fixed-shape reply every client we care
 *  about accepts (BND fields are meaningless for CONNECT-through-proxy). */
function replyBytes(code: number): Buffer {
  return Buffer.from([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

export function createSocksProxyServer(
  options: SocksProxyServerOptions,
): SocksProxyWrapper {
  const openSockets = new Set<Socket>()

  async function handshake(
    socket: Socket,
    onEstablished: () => void,
  ): Promise<void> {
    const read = makeByteReader(socket)

    // --- Greeting: VER NMETHODS METHODS... ---
    const greetingHead = await read(2)
    if (greetingHead.readUInt8(0) !== 0x05) {
      socket.destroy()
      return
    }
    const methodCount = greetingHead.readUInt8(1)
    if (methodCount === 0) {
      socket.destroy()
      return
    }
    const methods = await read(methodCount)

    // Method selection: user/pass when the client can and a token is
    // configured; plain no-auth otherwise (the destination-prefix gate below
    // covers unauthenticated connections when a token is configured).
    let credentialAuthed = false
    if (options.proxyAuthToken && methods.includes(AUTH_USERPASS)) {
      socket.write(Buffer.from([0x05, AUTH_USERPASS]))
      // --- RFC 1929 sub-negotiation: VER ULEN UNAME PLEN PASSWD ---
      if ((await read(1)).readUInt8() !== 0x01) {
        socket.destroy()
        return
      }
      const username = (await read((await read(1)).readUInt8())).toString()
      const password = (await read((await read(1)).readUInt8())).toString()
      if (username !== 'srt' || password !== options.proxyAuthToken) {
        logForDebugging('SOCKS auth rejected', { level: 'error' })
        socket.end(Buffer.from([0x01, 0x01]))
        return
      }
      socket.write(Buffer.from([0x01, 0x00]))
      credentialAuthed = true
    } else if (methods.includes(AUTH_NONE)) {
      socket.write(Buffer.from([0x05, AUTH_NONE]))
    } else {
      socket.end(Buffer.from([0x05, AUTH_NO_ACCEPTABLE]))
      return
    }

    // --- Request: VER CMD RSV ATYP DST.ADDR DST.PORT ---
    const requestHead = await read(4)
    if (requestHead.readUInt8(0) !== 0x05) {
      socket.destroy()
      return
    }
    const command = requestHead.readUInt8(1)
    const addrType = requestHead.readUInt8(3)
    let destAddress: string
    switch (addrType) {
      case 0x01: // IPv4
        destAddress = (await read(4)).join('.')
        break
      case 0x03: {
        // DOMAINNAME — a raw length-prefixed byte string. This is the field
        // that carries the token prefix for no-auth clients.
        destAddress = (await read((await read(1)).readUInt8())).toString()
        break
      }
      case 0x04: {
        // IPv6, rendered as fully-padded 4-hex-digit groups — the exact
        // string shape the previous implementation produced, so existing
        // allowlist entries with IPv6 literals keep matching.
        const bytes = await read(16)
        const groups: string[] = []
        for (let i = 0; i < 16; i += 2) {
          groups.push(bytes.readUInt16BE(i).toString(16).padStart(4, '0'))
        }
        destAddress = groups.join(':')
        break
      }
      default:
        socket.destroy()
        return
    }
    const destPort = (await read(2)).readUInt16BE()

    // Destination-token gate for unauthenticated connections (see module
    // doc). Runs before host validation, filtering, and the command check,
    // so once a request frame parses, an unauthenticated caller without the
    // prefix gets the same REPLY_NOT_ALLOWED regardless of what it asked
    // for. Compared in constant time: this is an unauthenticated path
    // handling a secret.
    if (options.proxyAuthToken && !credentialAuthed) {
      const prefix = Buffer.from(`${options.proxyAuthToken}.`)
      const candidate = Buffer.from(destAddress).subarray(0, prefix.length)
      if (
        candidate.length !== prefix.length ||
        !timingSafeEqual(candidate, prefix)
      ) {
        logForDebugging('SOCKS auth rejected', { level: 'error' })
        socket.end(replyBytes(REPLY_NOT_ALLOWED))
        return
      }
      destAddress = destAddress.slice(`${options.proxyAuthToken}.`.length)
    }

    if (command !== 0x01 /* CONNECT */) {
      socket.end(replyBytes(REPLY_COMMAND_NOT_SUPPORTED))
      return
    }

    // SOCKS5 DOMAINNAME has zero validation from the protocol. Reject
    // control chars (null bytes, CRLF) here so they never reach the
    // allowlist matcher, where string suffix matching would be trivially
    // fooled.
    if (!isValidHost(destAddress)) {
      logForDebugging(
        `Rejecting malformed SOCKS host: ${JSON.stringify(destAddress)}`,
        { level: 'error' },
      )
      socket.end(replyBytes(REPLY_NOT_ALLOWED))
      return
    }

    // Track client liveness from here on: the filter can be slow (it may
    // prompt the user), and a client that hangs up during it must abort the
    // dial rather than leak an upstream connection.
    let clientGone = false
    let upstreamRef: Socket | undefined
    socket.once('close', () => {
      clientGone = true
      upstreamRef?.destroy()
    })

    logForDebugging(`Connection request to ${destAddress}:${destPort}`)
    let allowed: boolean
    try {
      allowed = await options.filter(destPort, destAddress)
    } catch (error) {
      logForDebugging(`Error validating connection: ${error}`, {
        level: 'error',
      })
      allowed = false
    }
    if (!allowed) {
      logForDebugging(`Connection blocked to ${destAddress}:${destPort}`, {
        level: 'error',
      })
      socket.end(replyBytes(REPLY_NOT_ALLOWED))
      return
    }
    if (clientGone) {
      return
    }
    logForDebugging(`Connection allowed to ${destAddress}:${destPort}`)

    // SOCKS is an opaque TCP tunnel — semantically identical to HTTP
    // CONNECT — so always prefer HTTPS_PROXY if set, regardless of dest port.
    const parentUrl =
      options.parentProxy &&
      !shouldBypassParentProxy(options.parentProxy, destAddress)
        ? selectParentProxyUrl(options.parentProxy, { isHttps: true })
        : undefined

    try {
      const upstream = parentUrl
        ? await connectViaParentProxy(parentUrl, destAddress, destPort)
        : await dialDirect(destAddress, destPort)
      upstreamRef = upstream
      upstream.on('error', () => socket.destroy())
      if (clientGone) {
        upstream.destroy()
        return
      }
      onEstablished()
      socket.write(replyBytes(REPLY_SUCCEEDED))
      upstream.pipe(socket)
      socket.pipe(upstream)
      upstream.on('close', () => socket.destroy())
      socket.resume()
    } catch (err) {
      logForDebugging(
        `SOCKS connect to ${destAddress}:${destPort} failed: ${(err as Error).message}`,
        { level: 'error' },
      )
      if (!clientGone) {
        const code = (err as NodeJS.ErrnoException).code
        socket.end(
          replyBytes(
            code === 'ENETUNREACH'
              ? REPLY_NETWORK_UNREACHABLE
              : code === 'ECONNREFUSED'
                ? REPLY_CONNECTION_REFUSED
                : REPLY_HOST_UNREACHABLE,
          ),
        )
      }
    }
  }

  return {
    handleConnection(socket: Socket): void {
      socket.setNoDelay()
      openSockets.add(socket)
      socket.once('close', () => openSockets.delete(socket))
      socket.on('error', err =>
        logForDebugging(`SOCKS client socket error: ${err.message}`, {
          level: 'error',
        }),
      )
      // Bound the whole pre-tunnel phase. The mux's first-byte timeout is
      // already spent by the time the socket lands here, so without this a
      // client that stalls mid-handshake — or lingers after a refusal
      // reply — would pin the socket until close(). Cleared only once the
      // tunnel is established; destroying an already-closed socket is a
      // no-op.
      const deadline = setTimeout(() => {
        logForDebugging('SOCKS handshake timed out; destroying connection')
        socket.destroy()
      }, HANDSHAKE_TIMEOUT_MS)
      if (typeof deadline.unref === 'function') deadline.unref()
      handshake(socket, () => clearTimeout(deadline)).catch(err => {
        // Reader rejection (client hung up mid-handshake) or a write race —
        // nothing to answer; make sure the socket is gone.
        logForDebugging(`SOCKS handshake aborted: ${(err as Error).message}`)
        socket.destroy()
      })
    },
    async close(): Promise<void> {
      for (const socket of openSockets) socket.destroy()
      openSockets.clear()
    },
  }
}
