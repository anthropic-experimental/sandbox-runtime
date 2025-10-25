import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type { FsReadRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'

/**
 * Tests for macOS Seatbelt read bypass vulnerability
 *
 * Issue: Files protected by read deny rules could be exfiltrated by moving them
 * to readable locations using the mv command. The rename() syscall was not blocked
 * by file-read* rules.
 *
 * Fix: Added file-write-unlink deny rules to block rename/move operations on:
 * 1. The denied files/directories themselves
 * 2. All ancestor directories (to prevent moving parent directories)
 *
 * These tests use the actual sandbox profile generation code to ensure real-world coverage.
 */

function skipIfNotMacOS(): boolean {
  return getPlatform() !== 'macos'
}

describe('macOS Seatbelt Read Bypass Prevention', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-test-' + Date.now())
  const TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied-dir')
  const TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_SECRET_CONTENT = 'SECRET_CREDENTIAL_DATA'
  const TEST_MOVED_FILE = join(TEST_BASE_DIR, 'moved-secret.txt')
  const TEST_MOVED_DIR = join(TEST_BASE_DIR, 'moved-denied-dir')

  // Additional test files for glob pattern testing
  const TEST_GLOB_DIR = join(TEST_BASE_DIR, 'glob-test')
  const TEST_GLOB_FILE1 = join(TEST_GLOB_DIR, 'secret1.txt')
  const TEST_GLOB_FILE2 = join(TEST_GLOB_DIR, 'secret2.log')
  const TEST_GLOB_MOVED = join(TEST_BASE_DIR, 'moved-glob.txt')

  beforeAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Create test directory structure
    mkdirSync(TEST_DENIED_DIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)

    // Create glob test files
    mkdirSync(TEST_GLOB_DIR, { recursive: true })
    writeFileSync(TEST_GLOB_FILE1, 'GLOB_SECRET_1')
    writeFileSync(TEST_GLOB_FILE2, 'GLOB_SECRET_2')
  })

  afterAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Clean up test directory
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('Literal Path - Direct File Move Prevention', () => {
    it('should block moving a read-denied file to a readable location', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config with literal path
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR]
      }

      // Generate actual sandbox command using our production code
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_SECRET_FILE} ${TEST_MOVED_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify the file exists before test
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail with operation not permitted
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_SECRET_FILE)).toBe(true)
      expect(existsSync(TEST_MOVED_FILE)).toBe(false)
    })

    it('should still block reading the file (sanity check)', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR]
      }

      // Generate actual sandbox command
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The read should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Should NOT see the secret content
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })
  })

  describe('Literal Path - Ancestor Directory Move Prevention', () => {
    it('should block moving an ancestor directory of a read-denied file', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR]
      }

      // Generate actual sandbox command
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_DENIED_DIR} ${TEST_MOVED_DIR}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify the directory exists before test
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)
      expect(existsSync(TEST_MOVED_DIR)).toBe(false)
    })

    it('should block moving the grandparent directory', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Deny reading a specific file deep in the hierarchy
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_SECRET_FILE]
      }

      const movedBaseDir = join(tmpdir(), 'moved-base-' + Date.now())

      // Try to move the grandparent directory (TEST_BASE_DIR)
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_BASE_DIR} ${movedBaseDir}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_BASE_DIR is an ancestor of TEST_SECRET_FILE
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_BASE_DIR)).toBe(true)
      expect(existsSync(movedBaseDir)).toBe(false)
    })
  })

  describe('Glob Pattern - File Move Prevention', () => {
    it('should block moving files matching a glob pattern (*.txt)', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern that matches all .txt files in glob-test directory
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern]
      }

      // Try to move a .txt file that matches the pattern
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_FILE1} ${TEST_GLOB_MOVED}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Verify file exists
      expect(existsSync(TEST_GLOB_FILE1)).toBe(true)

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail for .txt file
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_GLOB_FILE1)).toBe(true)
      expect(existsSync(TEST_GLOB_MOVED)).toBe(false)
    })

    it('should still block reading files matching the glob pattern', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern]
      }

      // Try to read a file matching the glob
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_GLOB_FILE1}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The read should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Should NOT see the content
      expect(result.stdout).not.toContain('GLOB_SECRET_1')
    })

    it('should block moving the parent directory containing glob-matched files', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern]
      }

      const movedGlobDir = join(TEST_BASE_DIR, 'moved-glob-dir')

      // Try to move the parent directory
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_DIR} ${movedGlobDir}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_GLOB_DIR is an ancestor of the glob pattern
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_GLOB_DIR)).toBe(true)
      expect(existsSync(movedGlobDir)).toBe(false)
    })
  })

  describe('Glob Pattern - Recursive Patterns', () => {
    it('should block moving files matching a recursive glob pattern (**/*.txt)', async () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create nested directory structure
      const nestedDir = join(TEST_GLOB_DIR, 'nested')
      const nestedFile = join(nestedDir, 'nested-secret.txt')
      mkdirSync(nestedDir, { recursive: true })
      writeFileSync(nestedFile, 'NESTED_SECRET')

      // Use recursive glob pattern
      const globPattern = join(TEST_GLOB_DIR, '**/*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern]
      }

      const movedNested = join(TEST_BASE_DIR, 'moved-nested.txt')

      // Try to move the nested file
      const wrappedCommand = await wrapCommandWithSandboxMacOS({
        command: `mv ${nestedFile} ${movedNested}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      // Execute the wrapped command
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(nestedFile)).toBe(true)
      expect(existsSync(movedNested)).toBe(false)
    })
  })
})
