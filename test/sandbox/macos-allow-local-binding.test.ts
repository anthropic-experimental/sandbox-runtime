import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacos } from '../helpers/platform.js'

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

describe.if(isMacos)('macOS Seatbelt allowLocalBinding', () => {
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
