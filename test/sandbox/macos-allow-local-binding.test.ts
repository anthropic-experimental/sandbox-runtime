import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import net from 'node:net'
import shellquote from 'shell-quote'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

function runInSandbox(
  pythonCode: string,
  allowLocalBinding: boolean,
): ReturnType<typeof spawnSync> {
  const command = `python3 -c "${pythonCode}"`
  const wrappedCommand = wrapCommandWithSandboxMacOS({
    command,
    needsNetworkRestriction: true,
    allowLocalBinding,
    readConfig: undefined,
    writeConfig: undefined,
  })

  return spawnSync(wrappedCommand, {
    shell: true,
    encoding: 'utf8',
    timeout: 10000,
  })
}

// Extract the Seatbelt profile passed to `sandbox-exec -p <profile>` from a
// command produced by wrapCommandWithSandboxMacOS. Parsing the `-p` argument is
// more robust than substring-matching the shell-escaped command string.
function extractSandboxProfile(wrappedCommand: string): string {
  const parsed = shellquote.parse(wrappedCommand)
  const profileIndex = parsed.indexOf('-p')
  if (profileIndex === -1) {
    throw new Error(`sandbox-exec -p argument not found: ${wrappedCommand}`)
  }
  const profile = parsed[profileIndex + 1]
  if (typeof profile !== 'string') {
    throw new Error('sandbox-exec -p argument was not a string')
  }
  return profile
}

// Start a localhost-only TCP server on an ephemeral port for direct-egress tests.
async function listenOnLocalhost(): Promise<{
  port: number
  close: () => Promise<void>
}> {
  const server = net.createServer(socket => {
    socket.end('OK')
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })

  const address = server.address()
  if (!address || typeof address === 'string') {
    throw new Error('expected a TCP server address')
  }

  return {
    port: address.port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close(error => (error ? reject(error) : resolve()))
      }),
  }
}

// Python one-liners for socket bind tests
// AF_INET bind
const bindIPv4 = (addr: string) =>
  `import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('${addr}', 0)); print('BOUND'); s.close()`

// AF_INET6 dual-stack bind (IPV6_V6ONLY=0, same as Java ServerSocketChannel.open())
const bindIPv6DualStack = (addr: string) =>
  `import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(('${addr}', 0)); print('BOUND'); s.close()`

// AF_INET direct connect (outbound)
const connectIPv4 = (addr: string, port: number) =>
  `import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3); s.connect(('${addr}', ${port})); print('CONNECTED'); s.close()`

// Profile-generation guards run on any platform (no sandbox-exec required).
describe('macOS allowLocalBinding profile generation', () => {
  it('grants local bind/inbound but not broad outbound', () => {
    const profile = extractSandboxProfile(
      wrapCommandWithSandboxMacOS({
        command: 'echo ok',
        needsNetworkRestriction: true,
        allowLocalBinding: true,
        readConfig: undefined,
        writeConfig: undefined,
      }),
    )

    expect(profile).toContain('(allow network-bind (local ip "*:*"))')
    expect(profile).toContain('(allow network-inbound (local ip "*:*"))')
    // Without a proxy, local binding must grant zero outbound of ANY shape —
    // not just the historical `(local ip "*:*")` form. Asserting the absence of
    // the whole `network-outbound` operation catches a regression that reopens
    // egress via a different rule (e.g. `(remote ip "*:*")`).
    expect(profile).not.toContain('network-outbound')
  })

  it('preserves proxy-specific outbound localhost rules', () => {
    const profile = extractSandboxProfile(
      wrapCommandWithSandboxMacOS({
        command: 'echo ok',
        needsNetworkRestriction: true,
        allowLocalBinding: true,
        httpProxyPort: 48111,
        socksProxyPort: 48112,
        readConfig: undefined,
        writeConfig: undefined,
      }),
    )

    expect(profile).toContain(
      '(allow network-outbound (remote ip "localhost:48111"))',
    )
    expect(profile).toContain(
      '(allow network-outbound (remote ip "localhost:48112"))',
    )
    expect(profile).not.toContain('(allow network-outbound (local ip "*:*"))')
  })
})

describe.if(isMacOS)('macOS Seatbelt allowLocalBinding', () => {
  describe('when allowLocalBinding is true', () => {
    it('should allow AF_INET bind to 127.0.0.1', () => {
      const result = runInSandbox(bindIPv4('127.0.0.1'), true)

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('BOUND')
    })

    it('should allow AF_INET6 dual-stack bind to ::ffff:127.0.0.1', () => {
      // This is the case that breaks Java/Gradle: an IPv6 dual-stack socket
      // binding to 127.0.0.1, which the kernel represents as ::ffff:127.0.0.1
      const result = runInSandbox(bindIPv6DualStack('::ffff:127.0.0.1'), true)

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('BOUND')
    })

    it('should allow AF_INET6 bind to ::1', () => {
      const result = runInSandbox(bindIPv6DualStack('::1'), true)

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('BOUND')
    })
  })

  describe('outbound is not granted by allowLocalBinding', () => {
    it('should block direct outbound TCP even when allowLocalBinding is true', async () => {
      const server = await listenOnLocalhost()

      try {
        const result = runInSandbox(connectIPv4('127.0.0.1', server.port), true)

        expect(result.status).not.toBe(0)
        expect(result.stdout).not.toContain('CONNECTED')
        expect(`${result.stderr}\n${result.stdout}`).toMatch(
          /Operation not permitted|PermissionError|EPERM|not permitted|denied/i,
        )
      } finally {
        await server.close()
      }
    })
  })

  describe('when allowLocalBinding is false', () => {
    it('should block AF_INET bind to 127.0.0.1', () => {
      const result = runInSandbox(bindIPv4('127.0.0.1'), false)

      expect(result.status).not.toBe(0)
    })

    it('should block AF_INET6 dual-stack bind to ::ffff:127.0.0.1', () => {
      const result = runInSandbox(bindIPv6DualStack('::ffff:127.0.0.1'), false)

      expect(result.status).not.toBe(0)
    })
  })
})
