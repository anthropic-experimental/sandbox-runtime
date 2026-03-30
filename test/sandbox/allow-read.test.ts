import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import type { FsReadRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'
import { isLinux, isMacos, isSupportedPlatform } from '../helpers/platform.js'

/**
 * Tests for the allowRead (allowWithinDeny) feature.
 *
 * allowRead re-allows read access within regions blocked by denyRead.
 * allowRead takes precedence over denyRead — the opposite of write,
 * where denyWrite takes precedence over allowWrite.
 */
describe('allowRead precedence over denyRead', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'allow-read-test-' + Date.now())
  const TEST_DENIED_DIR = join(TEST_BASE_DIR, 'denied')
  const TEST_ALLOWED_SUBDIR = join(TEST_DENIED_DIR, 'allowed')
  const TEST_SECRET_FILE = join(TEST_DENIED_DIR, 'secret.txt')
  const TEST_ALLOWED_FILE = join(TEST_ALLOWED_SUBDIR, 'visible.txt')
  const TEST_SECRET_CONTENT = 'TOP_SECRET'
  const TEST_ALLOWED_CONTENT = 'VISIBLE_DATA'

  beforeAll(() => {
    if (!isSupportedPlatform) return

    mkdirSync(TEST_ALLOWED_SUBDIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)
    writeFileSync(TEST_ALLOWED_FILE, TEST_ALLOWED_CONTENT)
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('macOS Seatbelt', () => {
    it.if(isMacos)('should deny reading a file in a denied directory', () => {
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: [TEST_DENIED_DIR],
        allowWithinDeny: [],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${TEST_SECRET_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).not.toBe(0)
      expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    })

    it.if(isMacos)(
      'should allow reading a file in an allowWithinDeny subdirectory',
      () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `cat ${TEST_ALLOWED_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
      },
    )

    it.if(isMacos)(
      'should still deny reading files outside the re-allowed subdirectory',
      () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `cat ${TEST_SECRET_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
      },
    )
  })

  describe('Linux bwrap', () => {
    it.if(isLinux)(
      'should deny reading a file in a denied directory',
      async () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_SECRET_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
      },
    )

    it.if(isLinux)(
      'should allow reading a file in an allowWithinDeny subdirectory',
      async () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_ALLOWED_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
      },
    )

    it.if(isLinux)(
      'should still deny reading files outside the re-allowed subdirectory',
      async () => {
        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_DENIED_DIR],
          allowWithinDeny: [TEST_ALLOWED_SUBDIR],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_SECRET_FILE}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig: undefined,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
      },
    )

    // Regression: the write-path skip check in the allowRead re-bind loop was
    // too broad — it skipped any allowPath under ANY allowWrite, not just
    // writes actually re-bound under this tmpfs. With allowWrite as an
    // ancestor of denyRead (not wiped, not re-bound), allowRead under it was
    // skipped and left sitting in the empty tmpfs.
    // Shape: allowWrite: [~], denyRead: [~/.ssh], allowRead: [~/.ssh/known_hosts].
    it.if(isLinux)(
      'should re-allow under denyRead when allowWrite is an ancestor of the deny',
      async () => {
        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `cat ${TEST_ALLOWED_FILE}`,
          needsNetworkRestriction: false,
          readConfig: {
            denyOnly: [TEST_DENIED_DIR],
            allowWithinDeny: [TEST_ALLOWED_SUBDIR],
          },
          writeConfig: {
            allowOnly: [TEST_BASE_DIR], // ancestor of denyRead
            denyWithinAllow: [],
          },
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(result.stdout).toContain(TEST_ALLOWED_CONTENT)
      },
    )
  })
})

/**
 * Regression: denyRead: ['/'] + allowRead: [<project>] used to deny everything.
 *
 * macOS: (subpath "/") denies the root inode; no allowWithinDeny subpath covers
 *   "/", so dyld SIGABRTs before exec. Fix emits (allow file-read* (literal "/")).
 * Linux: --tmpfs / wiped all prior mounts, and the carve-out prefix check
 *   startsWith('/' + '/') never matched. Fix expands '/' into its children.
 *
 * Test dir lives under $HOME (not tmpdir) so the macOS /tmp → /private/tmp
 * symlink doesn't confuse Seatbelt path matching.
 */
describe('allowRead carve-out with denyRead at filesystem root (issue #10)', () => {
  const TEST_DIR = join(
    homedir(),
    '.sandbox-runtime-test-root-deny-' + Date.now(),
  )
  const TEST_FILE = join(TEST_DIR, 'visible.txt')
  const TEST_CONTENT = 'ROOT_CARVE_OUT'
  // Paths needed for sh/cat to load at all when the whole filesystem is denied.
  // /private covers /tmp and /var (macOS symlinks). /lib* for Linux ld.so.
  const EXEC_DEPS = [
    '/bin',
    '/usr',
    '/lib',
    '/lib64',
    '/System',
    '/private',
    '/dev',
    '/etc',
  ]

  beforeAll(() => {
    if (!isSupportedPlatform) return
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(TEST_FILE, TEST_CONTENT)
  })

  afterAll(() => {
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  it.if(isMacos)('macOS: re-allows carve-out under a root-level deny', () => {
    const readConfig: FsReadRestrictionConfig = {
      denyOnly: ['/'],
      allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
    }

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `cat ${TEST_FILE}`,
      needsNetworkRestriction: false,
      readConfig,
      writeConfig: undefined,
      // Pin to system bash: PATH may resolve to /opt/homebrew/bin/bash
      // on Apple Silicon, which is outside EXEC_DEPS.
      binShell: '/bin/bash',
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout).toContain(TEST_CONTENT)
  })

  it.if(isMacos)(
    'macOS: still denies paths outside the carve-out under a root-level deny',
    () => {
      const outside = join(homedir(), '.bashrc')
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      }

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `cat ${outside} 2>/dev/null; true`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
        binShell: '/bin/bash',
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      // Process must exec (no SIGABRT) and stdout must be empty (cat denied)
      expect(result.status).toBe(0)
      expect(result.stdout).toBe('')
    },
  )

  it.if(isLinux)(
    'Linux: re-allows carve-out under a root-level deny',
    async () => {
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      }

      // allowAllUnixSockets: true bypasses the seccomp path — otherwise the
      // apply-seccomp binary under <repo>/vendor/ is hidden by the root deny.
      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${TEST_FILE}`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
        allowAllUnixSockets: true,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain(TEST_CONTENT)
    },
  )

  it.if(isLinux)(
    'Linux: still denies paths outside the carve-out under a root-level deny',
    async () => {
      const outside = join(homedir(), '.bashrc')
      const readConfig: FsReadRestrictionConfig = {
        denyOnly: ['/'],
        allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
      }

      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `cat ${outside} 2>/dev/null; true`,
        needsNetworkRestriction: false,
        readConfig,
        writeConfig: undefined,
        allowAllUnixSockets: true,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toBe('')
    },
  )

  it.if(isLinux)(
    'Linux: preserves write binds when denyRead ancestor wipes them',
    async () => {
      const writeTarget = join(TEST_DIR, 'written.txt')
      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `echo WRITE_OK > ${writeTarget} && cat ${writeTarget}`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: ['/'],
          allowWithinDeny: [...EXEC_DEPS],
        },
        writeConfig: {
          allowOnly: [TEST_DIR],
          denyWithinAllow: [],
        },
        allowAllUnixSockets: true,
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('WRITE_OK')
    },
  )
})

/**
 * Tests that allowRead-only configs (no denyRead) do not trigger sandbox overhead.
 */
describe('allowRead without denyRead does not trigger sandboxing', () => {
  const command = 'echo hello'

  it.if(isMacos)(
    'returns command unchanged on macOS when only allowWithinDeny is set',
    () => {
      const result = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [], allowWithinDeny: ['/some/path'] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    },
  )

  it.if(isLinux)(
    'returns command unchanged on Linux when only allowWithinDeny is set',
    async () => {
      const result = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [], allowWithinDeny: ['/some/path'] },
        writeConfig: undefined,
      })

      expect(result).toBe(command)
    },
  )
})
