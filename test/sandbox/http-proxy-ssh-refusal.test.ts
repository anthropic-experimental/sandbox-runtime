import { afterEach, describe, expect, it } from 'bun:test'
import type { Server } from 'node:http'
import { connect, type Socket } from 'node:net'
import { once } from 'node:events'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'

/**
 * A blocked CONNECT to an SSH destination must say why.
 *
 * The SOCKS side already does this: an unauthenticated client asking for
 * port 22 gets an in-band SSH identification plus a plaintext
 * SSH_MSG_DISCONNECT carrying the policy reason, which OpenSSH prints
 * verbatim. The CONNECT side is now the transport macOS git-over-ssh uses
 * (see the GIT_SSH_COMMAND branch in sandbox-utils), so without the same
 * treatment a denied host degrades to "Connection closed by UNKNOWN port
 * 65535" with no reason. The HTTP status lines precede the SSH banner and
 * OpenSSH discards them (RFC 4253 §4.2), so both can share one response.
 */
describe('HTTP CONNECT refusal for SSH destinations', () => {
  const HOST = '127.0.0.1'
  let server: Server | undefined

  afterEach(async () => {
    if (server) {
      const s = server
      server = undefined
      await new Promise<void>(r => s.close(() => r()))
    }
  })

  async function startProxy(): Promise<number> {
    server = createHttpProxyServer({ filter: () => false })
    const s = server
    s.listen(0, HOST)
    await once(s, 'listening')
    return (s.address() as { port: number }).port
  }

  async function connectTo(
    proxyPort: number,
    target: string,
  ): Promise<Buffer> {
    const client: Socket = connect(proxyPort, HOST)
    client.on('error', () => {})
    await once(client, 'connect')
    client.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`)
    const chunks: Buffer[] = []
    client.on('data', c => chunks.push(c))
    await once(client, 'close')
    return Buffer.concat(chunks)
  }

  /** Description field of a pre-key-exchange SSH_MSG_DISCONNECT. */
  function disconnectReason(packet: Buffer): string {
    // uint32 packet_length, byte padding_length, byte msg (1), uint32 reason,
    // then a uint32-prefixed description.
    expect(packet[5]).toBe(0x01)
    const len = packet.readUInt32BE(10)
    return packet.subarray(14, 14 + len).toString('utf8')
  }

  it('follows the 403 with an SSH disconnect naming the reason', async () => {
    const port = await startProxy()

    const response = await connectTo(port, 'blocked.example:22')

    const text = response.toString('latin1')
    expect(text).toStartWith('HTTP/1.1 403 Forbidden\r\n')
    const bannerAt = text.indexOf('SSH-2.0-policy_refusal\r\n')
    expect(bannerAt).toBeGreaterThan(0)
    const packet = response.subarray(
      bannerAt + 'SSH-2.0-policy_refusal\r\n'.length,
    )
    expect(disconnectReason(packet)).toContain('allowlist')
  })

  it('leaves non-SSH destinations as a plain 403', async () => {
    const port = await startProxy()

    const response = await connectTo(port, 'blocked.example:443')

    const text = response.toString('latin1')
    expect(text).toStartWith('HTTP/1.1 403 Forbidden\r\n')
    expect(text).not.toContain('SSH-2.0')
  })
})
