import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
  readFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Unit tests for symlink write path detection in generateFilesystemArgs.
 *
 * When an allowWrite path is a symlink pointing outside its expected boundaries,
 * bwrap would follow the symlink and make the target writable. The fix detects
 * this and skips the path with a warning.
 */
describe.if(isLinux)('Symlink write path detection (unit)', () => {
  const TEST_ID = `symlink-write-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const TEST_BASE = join(tmpdir(), TEST_ID)
  const USER_AREA = join(TEST_BASE, 'user_area')
  const PROTECTED = join(TEST_BASE, 'protected')

  beforeEach(() => {
    mkdirSync(USER_AREA, { recursive: true })
    mkdirSync(PROTECTED, { recursive: true })
    writeFileSync(join(PROTECTED, 'secret.txt'), 'secret data')
  })

  afterEach(() => {
    rmSync(TEST_BASE, { recursive: true, force: true })
  })

  it('should include normal (non-symlink) write paths in bwrap args', async () => {
    const result = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [USER_AREA],
        denyWithinAllow: [],
      },
    })

    // The normal path should be included as --bind
    expect(result).toContain(USER_AREA)
    expect(result).toContain('--bind')
  })

  it('should skip symlink write paths pointing outside expected boundaries', async () => {
    // Create symlink: user_area/evil -> protected/
    const evilLink = join(USER_AREA, 'evil')
    symlinkSync(PROTECTED, evilLink)

    const result = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [evilLink],
        denyWithinAllow: [],
      },
    })

    // The symlink path should NOT be bound writable
    // Since it's the only allowOnly path and it's skipped, the result should
    // still have bwrap but without --bind for this path
    expect(result).toContain('bwrap')
    // The evil link target (PROTECTED) should not appear as a --bind target
    expect(result).not.toContain(`--bind ${evilLink} ${evilLink}`)
  })

  it('should keep legitimate write paths while skipping symlink paths', async () => {
    // Create symlink: user_area/evil -> protected/
    const evilLink = join(USER_AREA, 'evil')
    symlinkSync(PROTECTED, evilLink)

    const result = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [USER_AREA, evilLink],
        denyWithinAllow: [],
      },
    })

    // The legitimate path should be included
    expect(result).toContain(USER_AREA)
    // The symlink path should NOT produce a --bind with its own path
    expect(result).not.toContain(`--bind ${evilLink} ${evilLink}`)
  })

  it('should skip write paths that cannot be resolved', async () => {
    // Create a broken symlink
    const brokenLink = join(USER_AREA, 'broken')
    symlinkSync('/nonexistent/path/that/does/not/exist', brokenLink)

    const result = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [USER_AREA, brokenLink],
        denyWithinAllow: [],
      },
    })

    // The broken symlink should be skipped (existsSync returns false for broken symlinks)
    // but the legitimate path should still work
    expect(result).toContain(USER_AREA)
  })

  it('should allow symlinks that resolve within the same directory', async () => {
    // Create a subdirectory and a symlink within user_area pointing to it
    const subdir = join(USER_AREA, 'actual_data')
    mkdirSync(subdir, { recursive: true })
    const link = join(USER_AREA, 'link_to_data')
    symlinkSync(subdir, link)

    const result = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [link],
        denyWithinAllow: [],
      },
    })

    // Symlink within same area should be allowed (resolves to deeper path)
    expect(result).toContain('bwrap')
  })

  it('should include write paths with trailing slashes (not treat them as symlinks)', async () => {
    // When normalizedPath has a trailing slash, realpathSync returns it without one.
    // The comparison `resolvedPath !== normalizedPath` would incorrectly be true,
    // potentially causing the path to be skipped as if it were a symlink.
    const pathWithTrailingSlash = USER_AREA + '/'

    const result = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [pathWithTrailingSlash],
        denyWithinAllow: [],
      },
    })

    // The path should be included as --bind, not skipped
    expect(result).toContain('--bind')
    expect(result).toContain(USER_AREA)
  })
})

/**
 * Integration tests for symlink write path detection.
 *
 * These tests create actual symlinks and verify that the sandbox correctly
 * prevents writes through symlinks pointing outside allowed boundaries.
 */
describe.if(isLinux)('Symlink write path detection (integration)', () => {
  const TEST_ID = `symlink-integ-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const TEST_BASE = join(tmpdir(), TEST_ID)
  const USER_AREA = join(TEST_BASE, 'user_area')
  const PROTECTED = join(TEST_BASE, 'protected')

  beforeEach(() => {
    mkdirSync(USER_AREA, { recursive: true })
    mkdirSync(PROTECTED, { recursive: true })
    writeFileSync(join(PROTECTED, 'secret.txt'), 'secret data')
  })

  afterEach(() => {
    rmSync(TEST_BASE, { recursive: true, force: true })
  })

  it('should block writes through symlink pointing to protected directory', async () => {
    // Attack scenario: user_area/evil_symlink -> protected/
    const evilLink = join(USER_AREA, 'evil_symlink')
    symlinkSync(PROTECTED, evilLink)

    // Configure sandbox to allow writes to user_area and the evil symlink
    const command = await wrapCommandWithSandboxLinux({
      command: `echo "pwned" > ${evilLink}/secret.txt`,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [USER_AREA, evilLink],
        denyWithinAllow: [],
      },
    })

    spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // The write should fail because the symlink path was skipped
    const secretContent = readFileSync(join(PROTECTED, 'secret.txt'), 'utf8')
    expect(secretContent).toBe('secret data')
    expect(secretContent).not.toContain('pwned')
  })

  it('should allow normal writes to non-symlink paths', async () => {
    const testFile = join(USER_AREA, 'normal-write.txt')

    const command = await wrapCommandWithSandboxLinux({
      command: `echo "allowed content" > ${testFile}`,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [USER_AREA],
        denyWithinAllow: [],
      },
    })

    const result = spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(existsSync(testFile)).toBe(true)
    expect(readFileSync(testFile, 'utf8').trim()).toBe('allowed content')
  })

  it('should block writes through symlink pointing to /etc', async () => {
    // Classic attack: src -> /etc
    const srcLink = join(USER_AREA, 'src')
    symlinkSync('/etc', srcLink)

    const command = await wrapCommandWithSandboxLinux({
      command: `echo "malicious" > ${srcLink}/test-sandbox-escape.txt`,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [USER_AREA, srcLink],
        denyWithinAllow: [],
      },
    })

    spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // /etc should remain read-only
    expect(existsSync('/etc/test-sandbox-escape.txt')).toBe(false)
  })

  it('should block writes through symlink pointing to parent directory', async () => {
    // Symlink pointing to parent (broadens scope)
    const parentLink = join(USER_AREA, 'parent')
    symlinkSync(TEST_BASE, parentLink)

    const escapePath = join(TEST_BASE, 'escaped-file.txt')

    const command = await wrapCommandWithSandboxLinux({
      command: `echo "escaped" > ${parentLink}/escaped-file.txt`,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: {
        allowOnly: [parentLink],
        denyWithinAllow: [],
      },
    })

    spawnSync(command, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    // The escape file should not have been created via the symlink
    // (since the symlink is skipped, no write paths are available)
    expect(existsSync(escapePath)).toBe(false)
  })
})
