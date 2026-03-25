import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'

function skipIfNotLinux(): boolean {
  return getPlatform() !== 'linux'
}

/**
 * Tests for deny paths that are symlinks.
 *
 * When a deny path (e.g. .bashrc from DANGEROUS_FILES) is a symlink pointing
 * to a read-only location (e.g. /nix/store/...), bwrap cannot create a
 * bind-mount over the symlink and fails with:
 *   "bwrap: Can't create file at /home/user/.bashrc: No such file or directory"
 *
 * The fix skips the deny bind-mount when the symlink target is already in a
 * read-only location (outside all allowed write paths), since the content is
 * already immutable.
 */
describe('Symlink deny path handling (Linux)', () => {
  const TEST_ID = `symlink-deny-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const TEST_BASE = join(tmpdir(), TEST_ID)
  const WORK_DIR = join(TEST_BASE, 'workdir')
  const READONLY_DIR = join(TEST_BASE, 'readonly')

  beforeEach(() => {
    if (skipIfNotLinux()) return
    mkdirSync(WORK_DIR, { recursive: true })
    mkdirSync(READONLY_DIR, { recursive: true })
  })

  afterEach(() => {
    if (skipIfNotLinux()) return
    rmSync(TEST_BASE, { recursive: true, force: true })
  })

  it('should not fail when deny path is a symlink to a read-only location', async () => {
    if (skipIfNotLinux()) return

    // Create a file in the "read-only" area (simulating /nix/store/)
    const realFile = join(READONLY_DIR, '.bashrc')
    writeFileSync(realFile, '# managed by home-manager')

    // Create a symlink in the workdir pointing to the read-only file
    const symlinkPath = join(WORK_DIR, '.bashrc')
    symlinkSync(realFile, symlinkPath)

    // Wrap a command with the workdir as an allowed write path.
    // The .bashrc symlink is in WORK_DIR (writable) but points to
    // READONLY_DIR (not writable). The sandbox should not try to
    // --ro-bind over the symlink.
    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      writeConfig: {
        allowOnly: [WORK_DIR],
        denyWithinAllow: [symlinkPath],
      },
    })

    // The command should be wrapped (not fail during argument generation)
    expect(wrapped).toContain('bwrap')
    expect(wrapped).toContain('echo hello')
    // The symlink path should NOT appear as a --ro-bind target
    expect(wrapped).not.toContain(symlinkPath)
  })

  it('should still deny symlinks pointing to writable locations', async () => {
    if (skipIfNotLinux()) return

    // Create a file inside the writable area itself
    const realFile = join(WORK_DIR, 'real-config')
    writeFileSync(realFile, 'sensitive')

    // Symlink within the same writable directory
    const symlinkPath = join(WORK_DIR, '.env-link')
    symlinkSync(realFile, symlinkPath)

    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      writeConfig: {
        allowOnly: [WORK_DIR],
        denyWithinAllow: [symlinkPath],
      },
    })

    expect(wrapped).toContain('bwrap')
    // The symlink target is within a writable path, so it should still
    // be protected (via /dev/null mount on the symlink)
    expect(wrapped).toContain('/dev/null')
  })
})
