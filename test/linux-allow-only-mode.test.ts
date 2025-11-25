import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  unlinkSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../src/utils/platform.js'
import { wrapCommandWithSandboxLinux } from '../src/sandbox/linux-sandbox-utils.js'

/**
 * Tests for Linux allow-only read mode
 *
 * This test suite verifies that the allow-only read mode works correctly on Linux.
 * In allow-only mode, only explicitly allowed paths are readable, providing stricter
 * isolation than deny-only mode.
 */

function skipIfNotLinux(): boolean {
  return getPlatform() !== 'linux'
}

describe('Linux Allow-Only Read Mode', () => {
  const TEST_DIR = join(process.cwd(), '.sandbox-test-allow-only')
  const ALLOWED_FILE = join(TEST_DIR, 'allowed.txt')
  const DENIED_FILE = join(TEST_DIR, 'denied.txt')
  const SUBDIR = join(TEST_DIR, 'subdir')
  const SUBDIR_FILE = join(SUBDIR, 'file.txt')

  beforeAll(() => {
    if (skipIfNotLinux()) {
      return
    }

    // Create test directory structure
    if (!existsSync(TEST_DIR)) {
      mkdirSync(TEST_DIR, { recursive: true })
    }
    if (!existsSync(SUBDIR)) {
      mkdirSync(SUBDIR, { recursive: true })
    }

    // Create test files
    writeFileSync(ALLOWED_FILE, 'This file is allowed')
    writeFileSync(DENIED_FILE, 'This file should be denied')
    writeFileSync(SUBDIR_FILE, 'This is in a subdirectory')
  })

  afterAll(() => {
    if (skipIfNotLinux()) {
      return
    }

    // Clean up test directory
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  describe('Basic allow-only functionality', () => {
    it('should allow reading explicitly allowed paths', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await wrapCommandWithSandboxLinux({
        command: `cat ${ALLOWED_FILE}`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [ALLOWED_FILE, '/usr', '/lib', '/lib64'],
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('This file is allowed')
    })

    it('should block reading non-allowed paths', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await wrapCommandWithSandboxLinux({
        command: `cat ${DENIED_FILE}`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [ALLOWED_FILE, '/usr', '/lib', '/lib64'], // Only allow ALLOWED_FILE (plus system paths for shell)
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - file not in allowed paths
      expect(result.status).not.toBe(0)
      const output = (result.stderr || result.stdout || '').toLowerCase()
      expect(output).toMatch(/no such file|cannot access|not found/)
    })

    it('should allow reading entire directory when directory is in allowPaths', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await wrapCommandWithSandboxLinux({
        command: `cat ${ALLOWED_FILE} && cat ${DENIED_FILE}`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'], // Allow entire TEST_DIR
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('This file is allowed')
      expect(result.stdout).toContain('This file should be denied')
    })
  })

  describe('denyWithinAllow functionality', () => {
    it('should deny specific files within allowed directory', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await wrapCommandWithSandboxLinux({
        command: `cat ${ALLOWED_FILE} 2>&1 && cat ${DENIED_FILE} 2>&1`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'],
          denyWithinAllow: [DENIED_FILE], // Deny this specific file
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // First cat should succeed, second should fail
      const output = result.stdout || result.stderr || ''
      expect(output).toContain('This file is allowed')
      expect(output).not.toContain('This file should be denied')
      expect(output.toLowerCase()).toMatch(
        /no such file|cannot access|permission denied/,
      )
    })

    it('should handle subdirectory denials correctly', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await wrapCommandWithSandboxLinux({
        command: `cat ${SUBDIR_FILE} 2>&1`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'],
          denyWithinAllow: [SUBDIR], // Deny the subdirectory
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - subdirectory is denied
      expect(result.status).not.toBe(0)
      const output = (result.stderr || result.stdout || '').toLowerCase()
      expect(output).toMatch(/no such file|cannot access|not found/)
    })
  })

  describe('System paths in allow-only mode', () => {
    it('should allow access to system binaries when explicitly allowed', async () => {
      if (skipIfNotLinux()) {
        return
      }

      // Allow /usr/bin so we can execute ls
      const command = await wrapCommandWithSandboxLinux({
        command: 'ls /usr/bin/ls',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/usr', '/lib', '/lib64'],
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('/usr/bin/ls')
    })

    it('should block access to system paths not in allowlist', async () => {
      if (skipIfNotLinux()) {
        return
      }

      // Don't allow /etc
      const command = await wrapCommandWithSandboxLinux({
        command: 'cat /etc/passwd 2>&1',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/usr', '/lib', '/lib64'], // No /etc
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - /etc not in allowed paths
      expect(result.status).not.toBe(0)
      const output = (result.stderr || result.stdout || '').toLowerCase()
      expect(output).toMatch(/no such file|cannot access|not found/)
    })
  })

  describe('allow-only with write restrictions', () => {
    it('should combine allow-only read with allow-only write', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const testWriteFile = join(TEST_DIR, 'write-test.txt')

      // Clean up if exists
      if (existsSync(testWriteFile)) {
        unlinkSync(testWriteFile)
      }

      const command = await wrapCommandWithSandboxLinux({
        command: `echo "test write" > ${testWriteFile} && cat ${testWriteFile}`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'],
          denyWithinAllow: [],
        },
        writeConfig: {
          allowOnly: [TEST_DIR],
          denyWithinAllow: [],
        },
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        cwd: TEST_DIR,
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('test write')
      expect(existsSync(testWriteFile)).toBe(true)

      // Clean up
      if (existsSync(testWriteFile)) {
        unlinkSync(testWriteFile)
      }
    })

    it('should enforce write restrictions in allow-only read mode', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const blockedWrite = join(tmpdir(), 'blocked-write.txt')

      // Clean up if exists
      if (existsSync(blockedWrite)) {
        unlinkSync(blockedWrite)
      }

      const command = await wrapCommandWithSandboxLinux({
        command: `echo "should fail" > ${blockedWrite} 2>&1`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, tmpdir(), '/usr', '/lib', '/lib64'], // Allow reading /tmp
          denyWithinAllow: [],
        },
        writeConfig: {
          allowOnly: [TEST_DIR], // But only allow writing to TEST_DIR
          denyWithinAllow: [],
        },
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - /tmp not in write allowlist
      const output = (result.stderr || result.stdout || '').toLowerCase()
      expect(output).toContain('read-only file system')
      expect(existsSync(blockedWrite)).toBe(false)
    })

    it('should respect denyWithinAllow for writes in allow-only mode', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const deniedWrite = join(TEST_DIR, 'denied-write.txt')

      const command = await wrapCommandWithSandboxLinux({
        command: `echo "should fail" > ${deniedWrite} 2>&1`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'],
          denyWithinAllow: [],
        },
        writeConfig: {
          allowOnly: [TEST_DIR],
          denyWithinAllow: [deniedWrite], // Deny this specific file
        },
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - file is in denyWithinAllow for writes
      const output = (result.stderr || result.stdout || '').toLowerCase()
      expect(output).toMatch(/read-only file system|permission denied/)
    })
  })

  describe('Empty allowPaths behavior', () => {
    it('should block all reads when allowPaths is empty', async () => {
      if (skipIfNotLinux()) {
        return
      }

      // Empty allowPaths = maximum restriction (nothing readable except system paths for shell)
      const command = await wrapCommandWithSandboxLinux({
        command: `cat ${ALLOWED_FILE} 2>&1`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/usr', '/lib', '/lib64'], // Only system paths, not test file
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - nothing is in allowPaths
      expect(result.status).not.toBe(0)
      const output = (result.stderr || result.stdout || '').toLowerCase()
      expect(output).toMatch(/no such file|cannot access|not found/)
    })

    it('should still allow shell execution with minimal allowPaths', async () => {
      if (skipIfNotLinux()) {
        return
      }

      // Just allow enough for bash to work
      const command = await wrapCommandWithSandboxLinux({
        command: 'echo "Hello from sandbox"',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/usr', '/lib', '/lib64'], // Minimal system paths
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('Hello from sandbox')
    })
  })

  describe('allow-only vs deny-only comparison', () => {
    it('allow-only should be more restrictive than deny-only for same paths', async () => {
      if (skipIfNotLinux()) {
        return
      }

      // Test 1: deny-only with empty denyPaths = everything readable
      const denyOnlyCommand = await wrapCommandWithSandboxLinux({
        command: 'cat /etc/passwd 2>&1',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'deny-only',
          denyPaths: [], // Nothing denied = everything allowed
        },
        writeConfig: undefined,
      })

      const denyOnlyResult = spawnSync(denyOnlyCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should succeed - deny-only with empty list allows everything
      expect(denyOnlyResult.status).toBe(0)

      // Test 2: allow-only without /etc = /etc blocked
      const allowOnlyCommand = await wrapCommandWithSandboxLinux({
        command: 'cat /etc/passwd 2>&1',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/usr', '/lib', '/lib64'], // System paths but not /etc
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const allowOnlyResult = spawnSync(allowOnlyCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - allow-only without /etc blocks /etc/passwd
      expect(allowOnlyResult.status).not.toBe(0)
      const output = (
        allowOnlyResult.stderr ||
        allowOnlyResult.stdout ||
        ''
      ).toLowerCase()
      expect(output).toMatch(/no such file|cannot access|not found/)
    })

    it('allow-only provides stricter isolation than deny-only', async () => {
      if (skipIfNotLinux()) {
        return
      }

      // Test that allow-only blocks paths that deny-only would allow

      // Create a file in /tmp
      const tmpFile = join(tmpdir(), `test-isolation-${Date.now()}.txt`)
      writeFileSync(tmpFile, 'test content')

      // Test 1: deny-only (doesn't block /tmp unless explicitly denied)
      const denyOnlyCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${tmpFile}`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'deny-only',
          denyPaths: ['/etc/shadow'], // Only deny /etc/shadow
        },
        writeConfig: undefined,
      })

      const denyOnlyResult = spawnSync(denyOnlyCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should succeed - /tmp not in denyPaths
      expect(denyOnlyResult.status).toBe(0)

      // Test 2: allow-only (blocks /tmp unless explicitly allowed)
      const allowOnlyCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${tmpFile} 2>&1`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'], // Only allow TEST_DIR, not /tmp
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const allowOnlyResult = spawnSync(allowOnlyCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail - /tmp not in allowPaths
      expect(allowOnlyResult.status).not.toBe(0)
      const output = (
        allowOnlyResult.stderr ||
        allowOnlyResult.stdout ||
        ''
      ).toLowerCase()
      expect(output).toMatch(/no such file|cannot access|not found/)

      // Clean up
      if (existsSync(tmpFile)) {
        unlinkSync(tmpFile)
      }
    })
  })

  // cSpell:ignore seccomp
  describe('Seccomp filter compatibility with allow-only mode', () => {
    it('should work with seccomp filter (Unix socket blocking)', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const command = await wrapCommandWithSandboxLinux({
        command: 'echo "test with seccomp"',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/usr', '/lib', '/lib64'],
          denyWithinAllow: [],
        },
        writeConfig: undefined,
        allowAllUnixSockets: false, // Enable seccomp filter
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('test with seccomp')
    })

    it('should combine allow-only mode with seccomp to block Unix sockets', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const socketPath = '/tmp/test-socket-allow-only.sock'

      // Clean up if exists
      if (existsSync(socketPath)) {
        unlinkSync(socketPath)
      }

      // Try to create Unix socket
      const command = await wrapCommandWithSandboxLinux({
        command: `echo "test" | nc -U ${socketPath} 2>&1 || echo "socket_blocked"`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: ['/usr', '/lib', '/lib64', '/tmp'],
          denyWithinAllow: [],
        },
        writeConfig: undefined,
        allowAllUnixSockets: false, // Enable seccomp to block sockets
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should fail due to seccomp filter
      const output = (result.stderr || result.stdout || '').toLowerCase()
      const hasExpectedError =
        output.includes('operation not permitted') ||
        output.includes('socket_blocked') ||
        output.includes('create unix socket failed')
      expect(hasExpectedError).toBe(true)
    })
  })

  describe('Edge cases and error handling', () => {
    it('should handle non-existent paths in allowPaths gracefully', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const nonExistentPath = '/path/that/does/not/exist'

      const command = await wrapCommandWithSandboxLinux({
        command: 'echo "test"',
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [nonExistentPath, '/usr', '/lib', '/lib64'], // Include non-existent path
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Should succeed - non-existent paths are skipped
      expect(result.status).toBe(0)
      expect(result.stdout).toContain('test')
    })

    it('should handle symlinks in allowPaths correctly', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const symlinkPath = join(TEST_DIR, 'symlink-to-allowed')
      const targetPath = ALLOWED_FILE

      // Create symlink
      if (existsSync(symlinkPath)) {
        unlinkSync(symlinkPath)
      }
      spawnSync(`ln -s ${targetPath} ${symlinkPath}`, {
        shell: true,
      })

      const command = await wrapCommandWithSandboxLinux({
        command: `cat ${symlinkPath}`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'], // Allow entire directory
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('This file is allowed')

      // Clean up
      if (existsSync(symlinkPath)) {
        unlinkSync(symlinkPath)
      }
    })

    it('should handle paths with special characters', async () => {
      if (skipIfNotLinux()) {
        return
      }

      const specialFile = join(TEST_DIR, 'file with spaces.txt')
      writeFileSync(specialFile, 'special content')

      const command = await wrapCommandWithSandboxLinux({
        command: `cat "${specialFile}"`,
        needsNetworkRestriction: false,
        readConfig: {
          mode: 'allow-only',
          allowPaths: [TEST_DIR, '/usr', '/lib', '/lib64'],
          denyWithinAllow: [],
        },
        writeConfig: undefined,
      })

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('special content')

      // Clean up
      if (existsSync(specialFile)) {
        unlinkSync(specialFile)
      }
    })
  })
})
