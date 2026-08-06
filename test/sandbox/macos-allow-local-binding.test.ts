import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

function wrapWithJavaEnv(options: {
  setEnvVars?: Record<string, string>
  unsetEnvVars?: string[]
}): string {
  return wrapCommandWithSandboxMacOS({
    command: 'true',
    needsNetworkRestriction: true,
    allowLocalBinding: true,
    readConfig: undefined,
    writeConfig: undefined,
    ...options,
  })
}

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

// Python one-liners for socket bind tests
// AF_INET bind
const bindIPv4 = (addr: string) =>
  `import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('${addr}', 0)); print('BOUND'); s.close()`

// AF_INET6 dual-stack bind (IPV6_V6ONLY=0, same as Java ServerSocketChannel.open())
const bindIPv6DualStack = (addr: string) =>
  `import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(('${addr}', 0)); print('BOUND'); s.close()`

// Outbound TCP connect to a public IP (Seatbelt check, not reachability — settimeout
// keeps the success path bounded; the deny path is an immediate EPERM at connect()).
const connectTCP = (addr: string, port: number) =>
  `import socket; s = socket.socket(); s.settimeout(3); s.connect(('${addr}', ${port})); print('CONNECTED')`

// Outbound UDP sendto a public IP (DNS-exfil shape, #88).
const sendUDP = (addr: string, port: number) =>
  `import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'x', ('${addr}', ${port})); print('SENT')`

// Bind a loopback listener and connect to it from a sibling AF_INET socket
// in the same sandboxed process.
const loopbackIPC = `
import socket, threading
srv = socket.socket()
srv.bind(('127.0.0.1', 0)); srv.listen(1)
port = srv.getsockname()[1]
def serve():
    c, _ = srv.accept(); c.send(b'HI'); c.close()
threading.Thread(target=serve, daemon=True).start()
cli = socket.socket(); cli.settimeout(3)
cli.connect(('127.0.0.1', port))
print('IPC', cli.recv(2).decode())
`

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

    it('should allow connect to a self-bound 127.0.0.1 listener', () => {
      const result = runInSandbox(loopbackIPC, true)

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('IPC HI')
    })

    it('should still block outbound TCP to a non-loopback host (#225)', () => {
      const result = runInSandbox(connectTCP('1.1.1.1', 443), true)

      expect(result.status).not.toBe(0)
      expect(result.stderr).toContain('Operation not permitted')
    })

    it('should still block outbound UDP to a non-loopback host (#88)', () => {
      const result = runInSandbox(sendUDP('1.1.1.1', 53), true)

      expect(result.status).not.toBe(0)
      expect(result.stderr).toContain('Operation not permitted')
    })
  })

  describe('JAVA_TOOL_OPTIONS compatibility', () => {
    it('preserves inherited options', () => {
      const previous = process.env.JAVA_TOOL_OPTIONS
      process.env.JAVA_TOOL_OPTIONS = '-Dinherited=true'
      try {
        const wrapped = wrapWithJavaEnv({})
        expect(wrapped).toContain('-Dinherited=true')
        expect(wrapped).toContain('-Djava.net.preferIPv4Stack=true')
      } finally {
        if (previous === undefined) delete process.env.JAVA_TOOL_OPTIONS
        else process.env.JAVA_TOOL_OPTIONS = previous
      }
    })

    it('preserves a masked value instead of restoring the inherited value', () => {
      const previous = process.env.JAVA_TOOL_OPTIONS
      process.env.JAVA_TOOL_OPTIONS = '-Dsecret=true'
      try {
        const wrapped = wrapWithJavaEnv({
          setEnvVars: { JAVA_TOOL_OPTIONS: 'masked-value' },
        })
        expect(wrapped).toContain('masked-value')
        expect(wrapped).toContain('-Djava.net.preferIPv4Stack=true')
        expect(wrapped).not.toContain('-Dsecret=true')
      } finally {
        if (previous === undefined) delete process.env.JAVA_TOOL_OPTIONS
        else process.env.JAVA_TOOL_OPTIONS = previous
      }
    })

    it('does not restore an unset inherited value', () => {
      const previous = process.env.JAVA_TOOL_OPTIONS
      process.env.JAVA_TOOL_OPTIONS = '-Dsecret=true'
      try {
        const wrapped = wrapWithJavaEnv({
          unsetEnvVars: ['JAVA_TOOL_OPTIONS'],
        })
        expect(wrapped).toContain('-Djava.net.preferIPv4Stack=true')
        expect(wrapped).not.toContain('-Dsecret=true')
      } finally {
        if (previous === undefined) delete process.env.JAVA_TOOL_OPTIONS
        else process.env.JAVA_TOOL_OPTIONS = previous
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
