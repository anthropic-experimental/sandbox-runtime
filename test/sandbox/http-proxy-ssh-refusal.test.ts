import { afterEach, describe, expect, it } from 'bun:test'
import type { Server } from 'node:http'
import {
  connect,
  createServer as createNetServer,
  type Server as NetServer,
  type Socket,
} from 'node:net'
import { once } from 'node:events'
import { execFile } from 'node:child_process'
import { createHttpProxyServer } from '../../src/sandbox/http-proxy.js'
import { generateProxyEnvVars } from '../../src/sandbox/sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

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

/**
 * The end-to-end claim for the macOS GIT_SSH_COMMAND branch: the string
 * generateProxyEnvVars emits, handed to a real OpenSSH the way git hands it
 * over, authenticates to the proxy and tunnels — and when the destination is
 * blocked, ssh prints why.
 *
 * macOS-gated because that branch is macOS-only and because it needs a real
 * OpenSSH. It drives the proxy directly rather than through
 * SandboxManager.initialize: the seatbelt wrapper is not what this change
 * touches, and skipping it keeps the test runnable outside a sandbox host.
 */
describe.if(isMacOS)('macOS GIT_SSH_COMMAND end to end', () => {
  const HOST = '127.0.0.1'
  const TOKEN = 'tok-e2e'
  let proxy: Server | undefined
  let upstream: NetServer | undefined

  afterEach(async () => {
    if (proxy) {
      const p = proxy
      proxy = undefined
      await new Promise<void>(r => p.close(() => r()))
    }
    upstream?.close()
    upstream = undefined
  })

  async function startProxy(allow: boolean): Promise<number> {
    proxy = createHttpProxyServer({
      filter: () => allow,
      proxyAuthToken: TOKEN,
    })
    const p = proxy
    p.listen(0, HOST)
    await once(p, 'listening')
    return (p.address() as { port: number }).port
  }

  /** Runs ssh exactly as git would: the whole value through a shell. */
  function runSsh(gitSshCommand: string, target: string): Promise<string> {
    return new Promise(resolve => {
      execFile(
        '/bin/sh',
        [
          '-c',
          `${gitSshCommand} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -T ${target} 2>&1`,
        ],
        { timeout: 20000 },
        (_err, stdout) => resolve(stdout),
      )
    })
  }

  function sshCommandFor(proxyPort: number): string {
    const line = generateProxyEnvVars(
      proxyPort,
      proxyPort,
      undefined,
      TOKEN,
      true,
    ).find(v => v.startsWith('GIT_SSH_COMMAND='))!
    return line.slice('GIT_SSH_COMMAND='.length)
  }

  it('tunnels ssh to the destination', async () => {
    // A stand-in for sshd: enough to prove ssh's own bytes crossed the
    // proxy. Reaching key exchange is not the claim under test.
    const seen: Buffer[] = []
    upstream = createNetServer(sock => {
      sock.write('SSH-2.0-srt_test\r\n')
      // Hang up once ssh has identified itself, so it fails fast on the
      // key exchange we are not here to perform.
      sock.once('data', c => {
        seen.push(c)
        sock.end()
      })
    })
    upstream.listen(0, HOST)
    await once(upstream, 'listening')
    const upstreamPort = (upstream.address() as { port: number }).port
    const proxyPort = await startProxy(true)

    await runSsh(sshCommandFor(proxyPort), `-p ${upstreamPort} git@${HOST}`)

    expect(Buffer.concat(seen).toString('latin1')).toContain('SSH-2.0-')
  }, 20000)

  it('prints the reason when the destination is blocked', async () => {
    const proxyPort = await startProxy(false)

    const output = await runSsh(sshCommandFor(proxyPort), 'git@blocked.example')

    expect(output).toContain('blocked by the sandbox network allowlist')
    expect(output).not.toContain('Connection closed by UNKNOWN')
  }, 20000)
})
