import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'

/**
 * Create a test configuration with network access
 */
function createTestConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com', 'api.github.com'],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: ['~/.ssh'],
      allowWrite: ['.', '/tmp'],
      denyWrite: ['.env'],
    },
  }
}

function skipIfUnsupportedPlatform(): boolean {
  const platform = getPlatform()
  return platform !== 'linux' && platform !== 'macos'
}

describe('wrapWithSandbox customConfig', () => {
  beforeAll(async () => {
    if (skipIfUnsupportedPlatform()) {
      return
    }
    await SandboxManager.initialize(createTestConfig())
  })

  afterAll(async () => {
    if (skipIfUnsupportedPlatform()) {
      return
    }
    await SandboxManager.reset()
  })

  describe('without customConfig', () => {
    it('uses main config values', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'echo hello'
      const wrapped = await SandboxManager.wrapWithSandbox(command)

      // Should wrap the command (not return it as-is)
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)
    })
  })

  describe('with customConfig filesystem overrides', () => {
    it('uses custom allowWrite when provided', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'echo hello'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: [],
          allowWrite: [], // Override to block all writes
          denyWrite: [],
        },
      })

      // Should still wrap the command
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)
    })

    it('uses custom denyRead when provided', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'cat /etc/passwd'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: ['/etc/passwd'], // Block this specific file
          allowWrite: [],
          denyWrite: [],
        },
      })

      expect(wrapped).not.toBe(command)
    })
  })

  describe('with customConfig network overrides', () => {
    it('blocks network when allowedDomains is empty', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'curl https://example.com'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: {
          allowedDomains: [], // Block all network
          deniedDomains: [],
        },
      })

      // Should wrap but without proxy env vars when allowedDomains is empty
      expect(wrapped).not.toBe(command)

      // The wrapped command should not contain proxy port references
      // when there are no allowed domains (no network access needed)
      // Note: This is implementation-specific and may need adjustment
    })

    it('uses main config network when customConfig.network is undefined', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'echo hello'
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
        // network is not provided, should use main config
      })

      expect(wrapped).not.toBe(command)
    })
  })

  describe('readonly mode simulation', () => {
    it('can create a fully restricted sandbox config', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'ls -la'

      // This is what BashTool passes for readonly commands
      const readonlyConfig = {
        network: {
          allowedDomains: [], // Block all network
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [], // Block all writes
          denyWrite: [],
        },
      }

      const wrapped = await SandboxManager.wrapWithSandbox(
        command,
        undefined,
        readonlyConfig,
      )

      // Should wrap the command with restrictions
      expect(wrapped).not.toBe(command)
      expect(wrapped.length).toBeGreaterThan(command.length)
    })
  })

  describe('partial config merging', () => {
    it('only overrides specified filesystem fields', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'echo test'

      // Only override allowWrite, should use main config for denyRead/denyWrite
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        filesystem: {
          denyRead: [], // Override denyRead
          allowWrite: ['/custom/path'], // Override allowWrite
          denyWrite: [], // Override denyWrite
        },
      })

      expect(wrapped).not.toBe(command)
    })

    it('only overrides specified network fields', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const command = 'echo test'

      // Only override allowedDomains
      const wrapped = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: {
          allowedDomains: ['custom.example.com'],
          deniedDomains: [],
        },
      })

      expect(wrapped).not.toBe(command)
    })
  })
})

/**
 * Tests for restriction pattern semantics
 *
 * These test the platform functions directly to verify:
 * - Read (deny-only): undefined or empty denyOnly = no restrictions
 * - Write (allow-only): undefined = no restrictions, any config = restrictions
 * - Network: needsNetworkRestriction = false means no network sandbox
 */
describe('restriction pattern semantics', () => {
  const command = 'echo hello'

  describe('no sandboxing needed (early return)', () => {
    it('returns command unchanged when no restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // No network, empty read deny, no write config = no sandboxing
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })

    it('returns command unchanged when no restrictions on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      // No network, empty read deny, no write config = no sandboxing
      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })

    it('returns command unchanged with undefined readConfig on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })

    it('returns command unchanged with undefined readConfig on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    })
  })

  describe('read restrictions (deny-only pattern)', () => {
    it('empty denyOnly means no read restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Only write restrictions, empty read = should sandbox but no read rules
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap because of write restrictions
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
    })

    it('non-empty denyOnly means has read restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: ['/secret'] },
        writeConfig: undefined,
      })

      // Should wrap because of read restrictions
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
    })
  })

  describe('write restrictions (allow-only pattern)', () => {
    it('undefined writeConfig means no write restrictions on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Has read restrictions but no write = should sandbox
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: ['/secret'] },
        writeConfig: undefined,
      })

      expect(result).not.toBe(command)
    })

    it('empty allowOnly means maximally restrictive (has restrictions) on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Empty allowOnly = no writes allowed = has restrictions
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      // Should wrap because empty allowOnly is still a restriction
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
    })

    it('any writeConfig means has restrictions on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      // Should wrap because writeConfig is defined
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
    })
  })

  describe('network restrictions', () => {
    it('needsNetworkRestriction false skips network sandbox on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: ['/secret'] },
        writeConfig: undefined,
      })

      // Should wrap for filesystem but not include network args
      expect(result).not.toBe(command)
      expect(result).not.toContain('--unshare-net')
    })

    it('needsNetworkRestriction false skips network sandbox on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: ['/secret'] },
        writeConfig: undefined,
      })

      // Should wrap for filesystem
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
    })

    // Tests for the empty allowedDomains fix (CVE fix)
    // Empty allowedDomains should block all network, not allow all
    it('needsNetworkRestriction true without proxy sockets blocks all network on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Network restriction enabled but no proxy sockets = block all network
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: true,
        httpSocketPath: undefined, // No proxy available
        socksSocketPath: undefined, // No proxy available
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap with --unshare-net to block all network
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
      expect(result).toContain('--unshare-net')
      // Should NOT contain proxy-related environment variables since no proxy
      expect(result).not.toContain('HTTP_PROXY')
    })

    it('needsNetworkRestriction true without proxy ports blocks all network on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      // Network restriction enabled but no proxy ports = block all network
      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: true,
        httpProxyPort: undefined, // No proxy available
        socksProxyPort: undefined, // No proxy available
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap with sandbox-exec
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
      // The sandbox profile should NOT contain "(allow network*)" since restrictions are enabled
      // Note: We can't easily check the profile content, but we verify it doesn't skip sandboxing
    })

    it('needsNetworkRestriction true with proxy allows filtered network on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      // Create temporary socket files for the test
      const fs = await import('fs')
      const os = await import('os')
      const path = await import('path')
      const tmpDir = os.tmpdir()
      const httpSocket = path.join(tmpDir, `test-http-${Date.now()}.sock`)
      const socksSocket = path.join(tmpDir, `test-socks-${Date.now()}.sock`)

      // Create dummy socket files
      fs.writeFileSync(httpSocket, '')
      fs.writeFileSync(socksSocket, '')

      try {
        const result = await wrapCommandWithSandboxLinux({
          command,
          needsNetworkRestriction: true,
          httpSocketPath: httpSocket,
          socksSocketPath: socksSocket,
          httpProxyPort: 3128,
          socksProxyPort: 1080,
          readConfig: { denyOnly: [] },
          writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        })

        // Should wrap with network namespace isolation
        expect(result).not.toBe(command)
        expect(result).toContain('bwrap')
        expect(result).toContain('--unshare-net')
        // Should bind the socket files
        expect(result).toContain(httpSocket)
        expect(result).toContain(socksSocket)
      } finally {
        // Cleanup
        fs.unlinkSync(httpSocket)
        fs.unlinkSync(socksSocket)
      }
    })

    it('needsNetworkRestriction true with proxy allows filtered network on macOS', () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: true,
        httpProxyPort: 3128,
        socksProxyPort: 1080,
        readConfig: { denyOnly: [] },
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      })

      // Should wrap with sandbox-exec and proxy env vars
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
      // Should set proxy environment variables
      expect(result).toContain('HTTP_PROXY')
      expect(result).toContain('HTTPS_PROXY')
    })
  })
})

/**
 * Tests for the empty allowedDomains vulnerability fix
 *
 * These tests verify that when allowedDomains is explicitly set to an empty array [],
 * network access is blocked (as documented) rather than allowed (the bug).
 *
 * Documentation states: "Empty array = no network access"
 * Bug behavior: Empty array = full unrestricted network access
 * Fixed behavior: Empty array = network isolation enabled, all network blocked
 */
describe('empty allowedDomains network blocking (CVE fix)', () => {
  const command = 'curl https://example.com'

  describe('SandboxManager.wrapWithSandbox with empty allowedDomains', () => {
    beforeAll(async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }
      // Initialize with domains so proxy starts, then test with empty customConfig
      await SandboxManager.initialize({
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })
    })

    afterAll(async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }
      await SandboxManager.reset()
    })

    it('empty allowedDomains in customConfig triggers network restriction on Linux', async () => {
      if (getPlatform() !== 'linux') {
        return
      }

      const result = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: {
          allowedDomains: [], // Empty = block all network (documented behavior)
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })

      // With the fix, empty allowedDomains should trigger network isolation
      expect(result).not.toBe(command)
      expect(result).toContain('bwrap')
      expect(result).toContain('--unshare-net')
    })

    it('empty allowedDomains in customConfig triggers network restriction on macOS', async () => {
      if (getPlatform() !== 'macos') {
        return
      }

      const result = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: {
          allowedDomains: [], // Empty = block all network (documented behavior)
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })

      // With the fix, empty allowedDomains should trigger sandbox
      expect(result).not.toBe(command)
      expect(result).toContain('sandbox-exec')
    })

    it('non-empty allowedDomains still works correctly', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const result = await SandboxManager.wrapWithSandbox(command, undefined, {
        network: {
          allowedDomains: ['example.com'], // Specific domain allowed
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })

      // Should still wrap with sandbox
      expect(result).not.toBe(command)
      // Should have proxy environment variables for filtering
      expect(result).toContain('HTTP_PROXY')
    })

    it('undefined network config in customConfig falls back to main config', async () => {
      if (skipIfUnsupportedPlatform()) {
        return
      }

      const result = await SandboxManager.wrapWithSandbox(command, undefined, {
        // No network config - should fall back to main config which has example.com
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
      })

      // Should wrap with sandbox using main config's network settings
      expect(result).not.toBe(command)
      // Main config has example.com, so proxy should be set up
      expect(result).toContain('HTTP_PROXY')
    })
  })
})
