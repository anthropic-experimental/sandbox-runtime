import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from '../../src/sandbox/sandbox-schemas.js'

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
    it('should block moving a read-denied file to a readable location', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config with literal path
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command using our production code
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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

    it('should still block reading the file (sanity check)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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
    it('should block moving an ancestor directory of a read-denied file', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use actual read restriction config
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
      }

      // Generate actual sandbox command
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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

    it('should block moving the grandparent directory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Deny reading a specific file deep in the hierarchy
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_SECRET_FILE],
      }

      const movedBaseDir = join(tmpdir(), 'moved-base-' + Date.now())

      // Try to move the grandparent directory (TEST_BASE_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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
    it('should block moving files matching a glob pattern (*.txt)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern that matches all .txt files in glob-test directory
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      // Try to move a .txt file that matches the pattern
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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

    it('should still block reading files matching the glob pattern', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      // Try to read a file matching the glob
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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

    it('should block moving the parent directory containing glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Use glob pattern
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [globPattern],
      }

      const movedGlobDir = join(TEST_BASE_DIR, 'moved-glob-dir')

      // Try to move the parent directory
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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
    it('should block moving files matching a recursive glob pattern (**/*.txt)', () => {
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
        denyOnly: [globPattern],
      }

      const movedNested = join(TEST_BASE_DIR, 'moved-nested.txt')

      // Try to move the nested file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
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

describe('macOS Seatbelt Write Bypass Prevention', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'seatbelt-write-test-' + Date.now())
  const TEST_ALLOWED_DIR = join(TEST_BASE_DIR, 'allowed')
  const TEST_DENIED_DIR = join(TEST_ALLOWED_DIR, 'secrets')
  const TEST_DENIED_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_ORIGINAL_CONTENT = 'ORIGINAL_CONTENT'
  const TEST_MODIFIED_CONTENT = 'MODIFIED_CONTENT'

  // Additional test paths
  const TEST_RENAMED_DIR = join(TEST_BASE_DIR, 'renamed-secrets')

  // Glob pattern test paths
  const TEST_GLOB_DIR = join(TEST_ALLOWED_DIR, 'glob-test')
  const TEST_GLOB_SECRET1 = join(TEST_GLOB_DIR, 'secret1.txt')
  const TEST_GLOB_SECRET2 = join(TEST_GLOB_DIR, 'secret2.log')
  const TEST_GLOB_RENAMED = join(TEST_BASE_DIR, 'renamed-glob')

  beforeAll(() => {
    if (skipIfNotMacOS()) {
      return
    }

    // Create test directory structure
    mkdirSync(TEST_DENIED_DIR, { recursive: true })
    mkdirSync(TEST_GLOB_DIR, { recursive: true })

    // Create test files with original content
    writeFileSync(TEST_DENIED_FILE, TEST_ORIGINAL_CONTENT)
    writeFileSync(TEST_GLOB_SECRET1, TEST_ORIGINAL_CONTENT)
    writeFileSync(TEST_GLOB_SECRET2, TEST_ORIGINAL_CONTENT)
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

  describe('Literal Path - Direct Directory Move Prevention', () => {
    it('should block write bypass via directory rename (mv a c, write c/b, mv c a)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Allow writing to TEST_ALLOWED_DIR but deny TEST_DENIED_DIR
      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_DIR],
      }

      // Step 1: Try to rename the denied directory
      const mvCommand1 = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_DENIED_DIR} ${TEST_RENAMED_DIR}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result1 = spawnSync(mvCommand1, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result1.status).not.toBe(0)
      const output1 = (result1.stderr || '').toLowerCase()
      expect(output1).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_DENIED_DIR)).toBe(true)
      expect(existsSync(TEST_RENAMED_DIR)).toBe(false)
    })

    it('should still block direct writes to denied paths (sanity check)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_DIR],
      }

      // Try to write directly to the denied file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_MODIFIED_CONTENT}" > ${TEST_DENIED_FILE}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The write should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT modified
      const content = readFileSync(TEST_DENIED_FILE, 'utf8')
      expect(content).toBe(TEST_ORIGINAL_CONTENT)
    })
  })

  describe('Literal Path - Ancestor Directory Move Prevention', () => {
    it('should block moving an ancestor directory of a write-denied path', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const movedAllowedDir = join(TEST_BASE_DIR, 'moved-allowed')

      // Try to move the parent directory (TEST_ALLOWED_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_ALLOWED_DIR} ${movedAllowedDir}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_ALLOWED_DIR is an ancestor
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_ALLOWED_DIR)).toBe(true)
      expect(existsSync(movedAllowedDir)).toBe(false)
    })

    it('should block moving the grandparent directory', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [TEST_DENIED_FILE],
      }

      const movedBaseDir = join(tmpdir(), 'moved-write-base-' + Date.now())

      // Try to move the grandparent directory (TEST_BASE_DIR)
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_BASE_DIR} ${movedBaseDir}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail because TEST_BASE_DIR is an ancestor
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the directory was NOT moved
      expect(existsSync(TEST_BASE_DIR)).toBe(true)
      expect(existsSync(movedBaseDir)).toBe(false)
    })
  })

  describe('Glob Pattern - File Move Prevention', () => {
    it('should block write bypass via moving glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Allow writing to TEST_ALLOWED_DIR but deny *.txt files in glob-test
      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to move a .txt file
      const mvCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_SECRET1} ${join(TEST_BASE_DIR, 'moved-secret.txt')}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(mvCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The move should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT moved
      expect(existsSync(TEST_GLOB_SECRET1)).toBe(true)
    })

    it('should still block direct writes to glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to write to a glob-matched file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "${TEST_MODIFIED_CONTENT}" > ${TEST_GLOB_SECRET1}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // The write should fail
      expect(result.status).not.toBe(0)
      const output = (result.stderr || '').toLowerCase()
      expect(output).toContain('operation not permitted')

      // Verify the file was NOT modified
      const content = readFileSync(TEST_GLOB_SECRET1, 'utf8')
      expect(content).toBe(TEST_ORIGINAL_CONTENT)
    })

    it('should block moving the parent directory containing glob-matched files', () => {
      if (skipIfNotMacOS()) {
        return
      }

      const globPattern = join(TEST_GLOB_DIR, '*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      // Try to move the parent directory
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${TEST_GLOB_DIR} ${TEST_GLOB_RENAMED}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

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
      expect(existsSync(TEST_GLOB_DIR)).toBe(true)
      expect(existsSync(TEST_GLOB_RENAMED)).toBe(false)
    })
  })

  describe('Glob Pattern - Recursive Patterns', () => {
    it('should block moving files matching a recursive glob pattern (**/*.txt)', () => {
      if (skipIfNotMacOS()) {
        return
      }

      // Create nested directory structure
      const nestedDir = join(TEST_GLOB_DIR, 'nested')
      const nestedFile = join(nestedDir, 'nested-secret.txt')
      mkdirSync(nestedDir, { recursive: true })
      writeFileSync(nestedFile, TEST_ORIGINAL_CONTENT)

      // Use recursive glob pattern
      const globPattern = join(TEST_GLOB_DIR, '**/*.txt')

      const writeConfig: FsWriteRestrictionConfig = {
        allowOnly: [TEST_ALLOWED_DIR],
        denyWithinAllow: [globPattern],
      }

      const movedNested = join(TEST_BASE_DIR, 'moved-nested.txt')

      // Try to move the nested file
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `mv ${nestedFile} ${movedNested}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })

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
