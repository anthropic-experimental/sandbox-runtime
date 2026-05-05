import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { SandboxManager } from '../../src/index.js'
import { connect } from 'net'
import { getPlatform } from '../../src/utils/platform.js'
import { spawnAsync } from '../helpers/spawn.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Helper to make a CONNECT request through the proxy using raw TCP
 */
function proxyRequest(
  proxyPort: number,
  targetHost: string,
): Promise<{ allowed: boolean; statusCode?: number; response?: string }> {
  return new Promise(resolve => {
    const socket = connect(proxyPort, '127.0.0.1', () => {
      socket.write(
        `CONNECT ${targetHost}:443 HTTP/1.1\r\nHost: ${targetHost}:443\r\n\r\n`,
      )
    })

    let data = ''
    socket.on('data', chunk => {
      data += chunk.toString()
      // Check if we have a complete HTTP response line
      if (data.includes('\r\n')) {
        socket.destroy()
        const statusMatch = data.match(/HTTP\/1\.\d (\d+)/)
        const statusCode = statusMatch ? parseInt(statusMatch[1]) : 0
        resolve({
          allowed: statusCode === 200,
          statusCode,
          response: data,
        })
      }
    })

    socket.on('error', err => {
      resolve({ allowed: false, response: err.message })
    })

    socket.setTimeout(2000, () => {
      socket.destroy()
      resolve({ allowed: false, response: 'timeout' })
    })
  })
}

describe('SandboxManager.updateConfig', () => {
  beforeEach(async () => {
    await SandboxManager.reset()
  })

  afterEach(async () => {
    await SandboxManager.reset()
  })

  it('should handle updateConfig called before initialize', async () => {
    // updateConfig before initialize - should not throw
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Config should be set
    expect(SandboxManager.getConfig()).toBeDefined()

    // But network infrastructure not ready
    expect(SandboxManager.getProxyPort()).toBeUndefined()

    // Initialize should still work and respect the pre-set config
    await SandboxManager.initialize({
      network: { allowedDomains: ['other.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // initialize() overwrites config
    const config = SandboxManager.getConfig()
    expect(config?.network.allowedDomains).toContain('other.com')
    expect(config?.network.allowedDomains).not.toContain('example.com')
  })

  it('should update network restriction config dynamically', async () => {
    // Initialize with no allowed domains
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Initial state: no allowed hosts (empty array becomes undefined in getter)
    expect(
      SandboxManager.getNetworkRestrictionConfig().allowedHosts,
    ).toBeUndefined()

    // Update config to allow example.com
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Config should now reflect the update
    const config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toContain('example.com')
  })

  it('should handle moving domain from allowlist to denylist', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    let config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toContain('example.com')
    expect(config.deniedHosts).toBeUndefined()

    // Move to denylist
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: ['example.com'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toBeUndefined()
    expect(config.deniedHosts).toContain('example.com')

    // Move back to allowlist
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    config = SandboxManager.getNetworkRestrictionConfig()
    expect(config.allowedHosts).toContain('example.com')
    expect(config.deniedHosts).toBeUndefined()
  })

  it('should handle updating to empty allowlist', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    expect(SandboxManager.getNetworkRestrictionConfig().allowedHosts).toContain(
      'example.com',
    )

    // Update to empty allowlist (should block all)
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Empty array becomes undefined in getter
    expect(
      SandboxManager.getNetworkRestrictionConfig().allowedHosts,
    ).toBeUndefined()

    // Verify the actual config still exists
    const fullConfig = SandboxManager.getConfig()
    expect(fullConfig).toBeDefined()
    expect(fullConfig?.network.allowedDomains).toEqual([])
  })
})

describe('SandboxManager.updateConfig proxy filtering', () => {
  afterEach(async () => {
    await SandboxManager.reset()
  })

  it('should allow then block domain after config update', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Should be allowed initially
    const result1 = await proxyRequest(proxyPort!, 'example.com')
    expect(result1.allowed).toBe(true)

    // Update to block example.com (empty allowlist)
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should now be blocked
    const result2 = await proxyRequest(proxyPort!, 'example.com')
    expect(result2.allowed).toBe(false)
  })

  it('should block then allow domain after config update', async () => {
    // Initialize with empty allowlist (blocks all)
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Should be blocked initially
    const result1 = await proxyRequest(proxyPort!, 'example.com')
    expect(result1.allowed).toBe(false)

    // Update to allow example.com
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should now be allowed
    const result2 = await proxyRequest(proxyPort!, 'example.com')
    expect(result2.allowed).toBe(true)
  })

  it('should handle moving domain between allow and deny lists', async () => {
    // Initialize with example.com allowed
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Should be allowed initially
    const result1 = await proxyRequest(proxyPort!, 'example.com')
    expect(result1.allowed).toBe(true)

    // Move to denylist
    SandboxManager.updateConfig({
      network: { allowedDomains: [], deniedDomains: ['example.com'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should now be blocked
    const result2 = await proxyRequest(proxyPort!, 'example.com')
    expect(result2.allowed).toBe(false)

    // Move back to allowlist
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Should be allowed again
    const result3 = await proxyRequest(proxyPort!, 'example.com')
    expect(result3.allowed).toBe(true)
  })

  it('should handle rapid config updates', async () => {
    await SandboxManager.initialize({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Rapid updates
    for (let i = 0; i < 5; i++) {
      SandboxManager.updateConfig({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      SandboxManager.updateConfig({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })
    }

    // Final state should allow example.com
    const result = await proxyRequest(proxyPort!, 'example.com')
    expect(result.allowed).toBe(true)
  })
})

/**
 * Integration tests using wrapWithSandbox() to verify sandbox wrapper generation
 * and actual network behavior with sandboxed curl commands.
 */
describe('SandboxManager.updateConfig integration (wrapWithSandbox)', () => {
  afterEach(async () => {
    await SandboxManager.reset()
  })

  it.if(isLinux)(
    'should block then allow domain after updateConfig with sandboxed curl',
    async () => {
      // Initialize with empty allowlist (blocks all)
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // First request should be blocked
      const cmd1 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 3 http://example.com 2>&1',
      )
      const result1 = await spawnAsync(cmd1, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })
      const output1 = (result1.stdout + result1.stderr).toLowerCase()
      // With empty allowlist, network is completely blocked (no proxy)
      expect(output1).not.toContain('example domain')

      // Update config to allow example.com
      SandboxManager.updateConfig({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Second request should succeed
      // Note: wrapWithSandbox() generates new command with updated config
      const cmd2 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 5 http://example.com 2>&1',
      )
      const result2 = await spawnAsync(cmd2, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      expect(result2.status).toBe(0)
      expect(result2.stdout).toContain('Example Domain')
    },
    20000,
  )

  it.if(isLinux)(
    'should allow then block domain after updateConfig with sandboxed curl',
    async () => {
      // Initialize with example.com allowed
      await SandboxManager.initialize({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // First request should succeed
      const cmd1 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 5 http://example.com 2>&1',
      )
      const result1 = await spawnAsync(cmd1, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      expect(result1.status).toBe(0)
      expect(result1.stdout).toContain('Example Domain')

      // Update config to block all
      SandboxManager.updateConfig({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Second request should be blocked
      const cmd2 = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 3 http://example.com 2>&1',
      )
      const result2 = await spawnAsync(cmd2, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })
      const output2 = (result2.stdout + result2.stderr).toLowerCase()
      expect(output2).not.toContain('example domain')
    },
    20000,
  )

  it.if(isLinux)(
    'should allow network via curl after updateConfig when started with empty allowlist',
    async () => {
      // Initialize with EMPTY allowlist
      await SandboxManager.initialize({
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Update config to allow example.com
      SandboxManager.updateConfig({
        network: { allowedDomains: ['example.com'], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      })

      // Full integration: sandboxed curl should work
      const cmd = await SandboxManager.wrapWithSandbox(
        'curl -s --max-time 5 http://example.com 2>&1',
      )
      const result = await spawnAsync(cmd, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('Example Domain')
    },
    20000,
  )

  /**
   * This test verifies the exact user scenario:
   * 1. Start sandbox with allowedDomains: [], deniedDomains: ["example.com"]
   * 2. Generate wrapper (should include proxy config even with empty allowlist)
   * 3. Update config to allow example.com
   * 4. Proxy should now allow requests (tested via raw TCP)
   *
   * The fix: even with empty allowlist, wrapper includes proxy config so
   * updateConfig() can enable network access for sandboxed processes.
   */
  it('should allow network after updateConfig when started with empty allowlist and denylist', async () => {
    // Initialize with empty allowlist, example.com in denylist (user's exact scenario)
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: ['example.com'] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Wrapper should include proxy config even with empty allowlist
    const cmd = await SandboxManager.wrapWithSandbox('echo test')
    const platform = getPlatform()
    if (platform === 'macos') {
      expect(cmd).toContain('HTTP_PROXY')
    } else if (platform === 'linux') {
      expect(cmd).toMatch(/HTTP_PROXY|\.sock/)
    }

    // Proxy should be running
    const proxyPort = SandboxManager.getProxyPort()
    expect(proxyPort).toBeDefined()

    // Initially, example.com should be blocked (empty allowlist = block all)
    const blockedResult = await proxyRequest(proxyPort!, 'example.com')
    expect(blockedResult.allowed).toBe(false)

    // Update config to allow example.com
    SandboxManager.updateConfig({
      network: { allowedDomains: ['example.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Now example.com should be allowed
    const allowedResult = await proxyRequest(proxyPort!, 'example.com')
    expect(allowedResult.allowed).toBe(true)
  })

  /**
   * This test verifies the core fix: sandbox wrapper should include proxy config
   * even with empty allowlist, enabling dynamic updates.
   */
  it('should include proxy in sandbox wrapper even with empty allowlist', async () => {
    // Initialize with EMPTY allowlist - this is the bug scenario
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })

    // Get the sandbox wrapper command
    const wrapper = await SandboxManager.wrapWithSandbox('echo test')

    // The wrapper should include proxy configuration
    // On macOS: HTTP_PROXY and HTTPS_PROXY env vars
    // On Linux: socket paths
    const platform = getPlatform()
    if (platform === 'macos') {
      expect(wrapper).toContain('HTTP_PROXY')
      expect(wrapper).toContain('HTTPS_PROXY')
    } else if (platform === 'linux') {
      // Linux uses unix sockets, check for socket paths or proxy env vars
      expect(wrapper).toMatch(/HTTP_PROXY|http_proxy|\.sock/)
    }
  })
})
