import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  unlinkSync,
  mkdirSync,
  rmSync,
  readFileSync,
} from 'node:fs'
import type { Server } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { generateSeccompFilter } from '../../src/sandbox/generate-seccomp-filter.js'

/**
 * Create a minimal test configuration for the sandbox with example.com allowed
 */
function createTestConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: ['example.com'],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

function skipIfNotLinux(): boolean {
  return getPlatform() !== 'linux'
}

// ============================================================================
// Helper Function
// ============================================================================

/**
 * Assert that the sandbox is using pre-generated BPF files from vendor/
 */
function assertPrecompiledBpfInUse(): void {
  const bpfPath = generateSeccompFilter()

  expect(bpfPath).toBeTruthy()
  expect(bpfPath).toContain('/vendor/seccomp/')
  expect(existsSync(bpfPath!)).toBe(true)

  console.log(`✓ Verified using pre-compiled BPF: ${bpfPath}`)
}

// ============================================================================
// Main Test Suite
// ============================================================================

describe('Sandbox Integration Tests', () => {
  const TEST_SOCKET_PATH = '/tmp/claude-test.sock'
  // Use a directory within the repository (which is the CWD)
  const TEST_DIR = join(process.cwd(), '.sandbox-test-tmp')
  let socketServer: Server | null = null

  beforeAll(async () => {
    if (skipIfNotLinux()) {
      return
    }

    // Create test directory
    if (!existsSync(TEST_DIR)) {
      mkdirSync(TEST_DIR, { recursive: true })
    }

    // Create a Unix socket server for testing
    // We'll use Node.js to create a simple socket server
    const net = await import('node:net')

    // Clean up any existing socket
    if (existsSync(TEST_SOCKET_PATH)) {
      unlinkSync(TEST_SOCKET_PATH)
    }

    // Create Unix socket server
    socketServer = net.createServer(socket => {
      socket.on('data', data => {
        socket.write('Echo: ' + data.toString())
      })
    })

    await new Promise<void>((resolve, reject) => {
      socketServer!.listen(TEST_SOCKET_PATH, () => {
        console.log(`Test socket server listening on ${TEST_SOCKET_PATH}`)
        resolve()
      })
      socketServer!.on('error', reject)
    })

    // Initialize sandbox
    await SandboxManager.initialize(createTestConfig())
  })

  afterAll(async () => {
    if (skipIfNotLinux()) {
      return
    }

    // Clean up socket server
    if (socketServer) {
      socketServer.close()
    }

    // Clean up socket file
    if (existsSync(TEST_SOCKET_PATH)) {
      unlinkSync(TEST_SOCKET_PATH)
    }

    // Clean up test directory
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }

    // Reset sandbox
    await SandboxManager.reset()
  })

  // ==========================================================================
  // Scenario 1: With Pre-compiled BPF
  // ==========================================================================

  describe('With Pre-compiled BPF', () => {
    beforeAll(() => {
      if (skipIfNotLinux()) {
        return
      }

      console.log('\n=== Testing with Pre-compiled BPF ===')
      assertPrecompiledBpfInUse()
    })

    describe('Unix Socket Restrictions', () => {
      it('should block Unix socket connections with seccomp', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Wrap command with sandbox
        const command = await SandboxManager.wrapWithSandbox(
          `echo "Test message" | nc -U ${TEST_SOCKET_PATH}`,
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should fail due to seccomp filter blocking socket creation
        const output = (result.stderr || result.stdout || '').toLowerCase()
        // Different netcat versions report the error differently
        const hasExpectedError =
          output.includes('operation not permitted') ||
          output.includes('create unix socket failed')
        expect(hasExpectedError).toBe(true)
        expect(result.status).not.toBe(0)
      })
    })

    describe('Network Restrictions', () => {
      it('should block HTTP requests to non-allowlisted domains', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox(
          'curl -s http://blocked-domain.example',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).toContain('blocked by network allowlist')
      })

      it('should block HTTP requests to anthropic.com (not in allowlist)', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Use --max-time to timeout quickly, and --show-error to see proxy errors
        const command = await SandboxManager.wrapWithSandbox(
          'curl -s --show-error --max-time 2 https://www.anthropic.com',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // The proxy blocks the connection, causing curl to timeout or fail
        // Check that the request did not succeed
        const output = (result.stderr || result.stdout || '').toLowerCase()
        const didFail = result.status !== 0 || result.status === null
        expect(didFail).toBe(true)

        // The output should either contain an error or be empty (timeout)
        // It should NOT contain successful HTML response
        expect(output).not.toContain('<!doctype html')
        expect(output).not.toContain('<html')
      })

      it('should allow HTTP requests to allowlisted domains', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Note: example.com should be in the allowlist via .claude/settings.json
        const command = await SandboxManager.wrapWithSandbox(
          'curl -s http://example.com',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })

        // Should succeed and return HTML
        const output = result.stdout || ''
        expect(result.status).toBe(0)
        expect(output).toContain('Example Domain')
      })
    })

    describe('Filesystem Restrictions', () => {
      it('should block writes outside current working directory', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const testFile = join(tmpdir(), 'sandbox-blocked-write.txt')

        // Clean up if exists
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }

        const command = await SandboxManager.wrapWithSandbox(
          `echo "should fail" > ${testFile}`,
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Should fail with read-only file system error
        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).toContain('read-only file system')
        expect(existsSync(testFile)).toBe(false)
      })

      it('should allow writes within current working directory', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Ensure test directory exists
        if (!existsSync(TEST_DIR)) {
          mkdirSync(TEST_DIR, { recursive: true })
        }

        const testFile = join(TEST_DIR, 'allowed-write.txt')
        const testContent = 'test content from sandbox'

        // Clean up if exists
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }

        const command = await SandboxManager.wrapWithSandbox(
          `echo "${testContent}" > allowed-write.txt`,
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Debug output if failed
        if (result.status !== 0) {
          console.error('Command failed:', command)
          console.error('Status:', result.status)
          console.error('Stdout:', result.stdout)
          console.error('Stderr:', result.stderr)
          console.error('CWD:', TEST_DIR)
          console.error('Test file path:', testFile)
        }

        // Should succeed
        expect(result.status).toBe(0)
        expect(existsSync(testFile)).toBe(true)

        // Verify content
        const content = Bun.file(testFile).text()
        expect(await content).toContain(testContent)

        // Clean up
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }
      })

      it('should allow reads from anywhere', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Try reading from home directory
        const command = await SandboxManager.wrapWithSandbox(
          'head -n 5 ~/.bashrc',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should succeed (assuming .bashrc exists)
        expect(result.status).toBe(0)

        // If .bashrc exists, should have some content
        if (existsSync(`${process.env.HOME}/.bashrc`)) {
          expect(result.stdout).toBeTruthy()
        }
      })

      it('should allow writes in seccomp-only mode (no network restrictions)', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Import wrapCommandWithSandboxLinux to call directly
        const { wrapCommandWithSandboxLinux } = await import(
          '../../src/sandbox/linux-sandbox-utils.js'
        )

        const testFile = join(TEST_DIR, 'seccomp-only-write.txt')
        const testContent = 'seccomp-only test content'

        // Call wrapCommandWithSandboxLinux with no network restrictions
        // This forces the seccomp-only code path (line 629 in linux-sandbox-utils.ts)
        const command = await wrapCommandWithSandboxLinux({
          command: `echo "${testContent}" > ${testFile}`,
          needsNetworkRestriction: false, // No network - forces seccomp-only path
          writeConfig: {
            allowOnly: [TEST_DIR], // Only allow writes to TEST_DIR
            denyWithinAllow: [],
          },
          allowAllUnixSockets: false, // Enable seccomp
        })

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        if (result.status !== 0) {
          console.error('Command failed in seccomp-only mode')
          console.error('Status:', result.status)
          console.error('Stdout:', result.stdout)
          console.error('Stderr:', result.stderr)
          console.error('CWD:', TEST_DIR)
          console.error('Test file path:', testFile)
        }

        // Should succeed
        expect(result.status).toBe(0)
        expect(existsSync(testFile)).toBe(true)

        const content = readFileSync(testFile, 'utf8')
        expect(content.trim()).toBe(testContent)

        // Clean up
        if (existsSync(testFile)) {
          unlinkSync(testFile)
        }
      })
    })

    describe('Command Execution', () => {
      it('should execute basic commands successfully', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox(
          'echo "Hello from sandbox"',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain('Hello from sandbox')
      })

      it('should handle complex command pipelines', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const command = await SandboxManager.wrapWithSandbox(
          'echo "line1\nline2\nline3" | grep line2',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain('line2')
        expect(result.stdout).not.toContain('line1')
      })
    })

    describe('Shell Selection (binShell parameter)', () => {
      it('should execute commands with zsh when binShell is specified', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Check if zsh is available
        const zshCheck = spawnSync('which zsh', {
          shell: true,
          encoding: 'utf8',
        })
        if (zshCheck.status !== 0) {
          console.log('zsh not available, skipping test')
          return
        }

        // Use a zsh-specific feature: $ZSH_VERSION
        const command = await SandboxManager.wrapWithSandbox(
          'echo "Shell: $ZSH_VERSION"',
          'zsh',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        // Should contain version number (e.g., "Shell: 5.8.1")
        expect(result.stdout).toMatch(/Shell: \d+\.\d+/)
      })

      it('should use zsh syntax successfully with binShell=zsh', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Check if zsh is available
        const zshCheck = spawnSync('which zsh', {
          shell: true,
          encoding: 'utf8',
        })
        if (zshCheck.status !== 0) {
          console.log('zsh not available, skipping test')
          return
        }

        // Use zsh parameter expansion feature
        const command = await SandboxManager.wrapWithSandbox(
          'VAR="hello world" && echo ${VAR:u}',
          'zsh',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain('HELLO WORLD')
      })

      it('should default to bash when binShell is not specified', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Check for bash-specific variable
        const command = await SandboxManager.wrapWithSandbox(
          'echo "Shell: $BASH_VERSION"',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        // Should contain bash version
        expect(result.stdout).toMatch(/Shell: \d+\.\d+/)
      })
    })

    describe('Security Boundaries', () => {
      it('should isolate PID namespace - sandboxed processes cannot see host PIDs', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Use /proc to check PID namespace isolation
        // Inside sandbox, should only see sandbox PIDs in /proc
        const command = await SandboxManager.wrapWithSandbox(
          'ls /proc | grep -E "^[0-9]+$" | wc -l',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)

        // Should see very few PIDs (only sandbox processes)
        const pidCount = parseInt(result.stdout.trim())
        expect(pidCount).toBeLessThan(30) // Host would have 100+
        expect(pidCount).toBeGreaterThan(0) // But at least some processes
      })

      it('should prevent symlink-based filesystem escape attempts', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Note: Reads are allowed from anywhere, so test WRITE escape attempt
        const linkInAllowed = join(TEST_DIR, 'escape-link-write')
        const targetOutside = '/tmp/escape-test-' + Date.now() + '.txt'

        // Try to create symlink inside allowed dir pointing to restricted location
        // Then try to write through it
        const command = await SandboxManager.wrapWithSandbox(
          `ln -s ${targetOutside} ${linkInAllowed} 2>&1 && echo "escaped" > ${linkInAllowed} 2>&1`,
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Write should fail (read-only file system for /tmp)
        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).toContain('read-only file system')

        // Target file should NOT exist
        expect(existsSync(targetOutside)).toBe(false)

        // Clean up
        if (existsSync(linkInAllowed)) {
          unlinkSync(linkInAllowed)
        }
        if (existsSync(targetOutside)) {
          unlinkSync(targetOutside)
        }
      })

      it('should terminate background processes when sandbox exits', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Create a unique marker file that a background process will touch
        const markerFile = join(TEST_DIR, 'background-process-marker.txt')

        if (existsSync(markerFile)) {
          unlinkSync(markerFile)
        }

        // Start a background process that writes every 0.5 second
        const command = await SandboxManager.wrapWithSandbox(
          `(while true; do echo "alive" >> ${markerFile}; sleep 0.5; done) & sleep 2`,
        )

        const startTime = Date.now()
        spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })
        const endTime = Date.now()

        // Wait a bit to ensure background process would continue if not killed
        await new Promise(resolve => setTimeout(resolve, 2000))

        if (existsSync(markerFile)) {
          const content = readFileSync(markerFile, 'utf8')
          const lines = content.trim().split('\n').length

          // Should have ~4 lines (2 seconds / 0.5s each), not 10+ (if process continued for 5s)
          expect(lines).toBeLessThan(10)

          unlinkSync(markerFile)
        } else {
          // If file doesn't exist, that's also fine - process was killed
          expect(true).toBe(true)
        }

        // Verify total execution was ~2 seconds, not hanging
        expect(endTime - startTime).toBeLessThan(4000)
      })

      it('should prevent privilege escalation attempts', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Test 1: Setuid binaries cannot actually elevate privileges
        // Note: The setuid bit CAN be set on files in writable directories,
        // but bwrap ensures it doesn't grant actual privilege escalation
        const setuidTest = join(TEST_DIR, 'setuid-test')

        const command1 = await SandboxManager.wrapWithSandbox(
          `cp /bin/bash ${setuidTest} 2>&1 && chmod u+s ${setuidTest} 2>&1 && ${setuidTest} -c "id -u" 2>&1`,
        )

        const result1 = spawnSync(command1, {
          shell: true,
          encoding: 'utf8',
          cwd: TEST_DIR,
          timeout: 5000,
        })

        // Should still run as the same UID (not root), proving setuid doesn't work
        const uid = result1.stdout.trim().split('\n').pop()
        expect(parseInt(uid || '0')).toBeGreaterThan(0) // Not root (0)

        // Test 2: Cannot use sudo/su (should not be available or fail)
        const command2 = await SandboxManager.wrapWithSandbox(
          'sudo -n echo "elevated" 2>&1 || su -c "echo elevated" 2>&1 || echo "commands blocked"',
        )

        const result2 = spawnSync(command2, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should not successfully escalate
        const output = result2.stdout.toLowerCase()
        if (
          output.includes('elevated') &&
          !output.includes('commands blocked')
        ) {
          // If "elevated" appears without "commands blocked", it should be in an error message
          expect(output).toMatch(
            /not found|command not found|no such file|not permitted|password|cannot|no password/,
          )
        }

        // Cleanup
        if (existsSync(setuidTest)) {
          unlinkSync(setuidTest)
        }
      })

      it('should enforce network restrictions across protocols and ports', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Test 1: HTTPS to blocked domain (not just HTTP)
        const command1 = await SandboxManager.wrapWithSandbox(
          'curl -s --show-error --max-time 2 --connect-timeout 2 https://blocked-domain.example 2>&1 || echo "curl_failed"',
        )

        const result1 = spawnSync(command1, {
          shell: true,
          encoding: 'utf8',
          timeout: 4000,
        })

        // Should fail - curl should not succeed
        const output1 = result1.stdout.toLowerCase()
        // Should either timeout, fail to resolve, or curl should fail
        const didNotSucceed =
          output1.includes('curl_failed') ||
          output1.includes('timeout') ||
          output1.includes('could not resolve') ||
          output1.includes('failed') ||
          output1.length === 0 // Timeout with no output
        expect(didNotSucceed).toBe(true)

        // Test 2: Non-standard port should also be blocked
        const command2 = await SandboxManager.wrapWithSandbox(
          'curl -s --show-error --max-time 2 http://blocked-domain.example:8080 2>&1',
        )

        const result2 = spawnSync(command2, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // Should be blocked - check output contains block message
        const output2 = result2.stdout.toLowerCase()
        expect(output2).toContain('blocked by network allowlist')

        // Test 3: Direct IP addresses should also be blocked
        // The network allowlist blocks ALL domains/IPs not explicitly allowed
        const command3 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 2 http://1.1.1.1 2>&1', // Cloudflare DNS
        )

        const result3 = spawnSync(command3, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // IP addresses should be blocked by the proxy
        // Note: curl may return 0 even when blocked if it receives a 403 response
        const output3 = result3.stdout.toLowerCase()
        expect(output3).toContain('blocked by network allowlist')

        // Test 4: Verify HTTPS to allowed domain still works
        const command4 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 5 https://example.com 2>&1',
        )

        const result4 = spawnSync(command4, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })

        // HTTPS should work for allowed domain (unless transient network issue)
        // At minimum, it shouldn't be blocked by our proxy
        const output4 = result4.stdout.toLowerCase()
        expect(output4).not.toContain('blocked by network allowlist')
        if (result4.status === 0) {
          expect(result4.stdout).toContain('Example Domain')
        }
      })

      it('should enforce wildcard domain pattern matching correctly', async () => {
        if (skipIfNotLinux()) {
          return
        }

        // Reset and reinitialize with wildcard pattern
        await SandboxManager.reset()
        await SandboxManager.initialize({
          network: {
            allowedDomains: ['*.github.com', 'example.com'],
            deniedDomains: [],
          },
          filesystem: {
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          },
        })

        // Test 1: Subdomain should match wildcard
        const command1 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 3 http://api.github.com 2>&1 | head -20',
        )

        const result1 = spawnSync(command1, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // Should NOT be blocked - api.github.com matches *.github.com
        const output1 = result1.stdout.toLowerCase()
        expect(output1).not.toContain('blocked by network allowlist')

        // Test 2: Base domain should NOT match wildcard (*.github.com doesn't match github.com)
        const command2 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 2 http://github.com 2>&1',
        )

        const result2 = spawnSync(command2, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // Should be blocked - github.com does NOT match *.github.com
        const output2 = result2.stdout.toLowerCase()
        expect(output2).toContain('blocked by network allowlist')

        // Test 3: Malicious lookalike domain should NOT match
        const command3 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 2 http://malicious-github.com 2>&1',
        )

        const result3 = spawnSync(command3, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // Should be blocked - malicious-github.com does NOT match *.github.com
        const output3 = result3.stdout.toLowerCase()
        expect(output3).toContain('blocked by network allowlist')

        // Test 4: Multiple subdomains should match
        const command4 = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 3 http://raw.githubusercontent.com 2>&1 | head -20',
        )

        const result4 = spawnSync(command4, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        // githubusercontent.com should be blocked (doesn't match *.github.com)
        const output4 = result4.stdout.toLowerCase()
        expect(output4).toContain('blocked by network allowlist')

        // Restore original config
        await SandboxManager.reset()
        await SandboxManager.initialize(createTestConfig())
      })

      it('should prevent creation of special file types that could bypass restrictions', async () => {
        if (skipIfNotLinux()) {
          return
        }

        const fifoPath = join(TEST_DIR, 'test.fifo')
        const regularFile = join(TEST_DIR, 'regular.txt')
        const hardlinkPath = join(TEST_DIR, 'hardlink.txt')
        const devicePath = join(TEST_DIR, 'fake-device')

        // Clean up any existing test files
        ;[fifoPath, regularFile, hardlinkPath, devicePath].forEach(path => {
          if (existsSync(path)) {
            unlinkSync(path)
          }
        })

        // Test 1: FIFO (named pipe) creation in allowed location should work
        const command1 = await SandboxManager.wrapWithSandbox(
          `mkfifo ${fifoPath} && test -p ${fifoPath} && echo "FIFO created"`,
        )

        const result1 = spawnSync(command1, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        expect(result1.status).toBe(0)
        expect(result1.stdout).toContain('FIFO created')
        expect(existsSync(fifoPath)).toBe(true)

        // Test 2: Hard link pointing outside allowed location should fail
        // First create a file in allowed location
        const command2a = await SandboxManager.wrapWithSandbox(
          `echo "test content" > ${regularFile}`,
        )

        spawnSync(command2a, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // Try to create hard link to /etc/passwd (outside allowed location)
        const command2b = await SandboxManager.wrapWithSandbox(
          `ln /etc/passwd ${hardlinkPath} 2>&1`,
        )

        const result2b = spawnSync(command2b, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // Should fail - cannot create hard link to read-only location
        // Note: May fail with "invalid cross-device link" due to mount namespaces
        expect(result2b.status).not.toBe(0)
        const output2 = result2b.stdout.toLowerCase()
        expect(output2).toMatch(
          /read-only|permission denied|not permitted|operation not permitted|cross-device/,
        )

        // Test 3: Device node creation should fail (requires CAP_MKNOD which sandbox doesn't have)
        const command3 = await SandboxManager.wrapWithSandbox(
          `mknod ${devicePath} c 1 3 2>&1`,
        )

        const result3 = spawnSync(command3, {
          shell: true,
          encoding: 'utf8',
          timeout: 3000,
        })

        // Should fail - mknod requires special privileges
        expect(result3.status).not.toBe(0)
        const output3 = result3.stdout.toLowerCase()
        expect(output3).toMatch(
          /operation not permitted|permission denied|not permitted/,
        )
        expect(existsSync(devicePath)).toBe(false)

        // Cleanup
        ;[fifoPath, regularFile, hardlinkPath, devicePath].forEach(path => {
          if (existsSync(path)) {
            unlinkSync(path)
          }
        })
      })
    })
  })
})
