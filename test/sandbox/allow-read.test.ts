import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from '../../src/sandbox/sandbox-schemas.js'
import { isLinux, isMacOS, isSupportedPlatform } from '../helpers/platform.js'

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
    it.if(isMacOS)('should deny reading a file in a denied directory', () => {
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

    it.if(isMacOS)(
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

    it.if(isMacOS)(
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

  it.if(isMacOS)('macOS: re-allows carve-out under a root-level deny', () => {
    const readConfig: FsReadRestrictionConfig = {
      denyOnly: ['/'],
      allowWithinDeny: [TEST_DIR, ...EXEC_DEPS],
    }

    // EXEC_DEPS covers /bin and /usr but not /opt/homebrew — pin the shell
    // so denying the filesystem root doesn't break execvp on Homebrew-bash Macs.
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `cat ${TEST_FILE}`,
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

    expect(result.status).toBe(0)
    expect(result.stdout).toContain(TEST_CONTENT)
  })

  it.if(isMacOS)(
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

  it.if(isMacOS)(
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

// A literal denyRead path nested under a literal allowRead subpath must keep
// its deny: Seatbelt is last-match-wins, so the deny is re-emitted after the
// allow. (Glob paths are out of scope; denyReadAlways is the lever there.)
describe.if(isMacOS)('macOS denyRead nested under allowRead', () => {
  it('re-emits the deny after the allow so it stays denied', () => {
    const result = wrapCommandWithSandboxMacOS({
      command: 'cat /work/secrets/key',
      needsNetworkRestriction: false,
      readConfig: {
        denyOnly: ['/work/secrets'],
        allowWithinDeny: ['/work'],
      },
      writeConfig: undefined,
    })
    // The profile is embedded in a shell command, so quotes are escaped —
    // match on the unquoted skeleton.
    const allowAt = result.indexOf('(allow file-read*\n  (subpath')
    const lastDenySecrets = result.lastIndexOf('/work/secrets')
    const firstDenySecrets = result.indexOf('/work/secrets')
    expect(allowAt).toBeGreaterThan(-1)
    // The deny on /work/secrets appears both before and after the allow:
    // original emit, then re-emit after allowWithinDeny.
    expect(firstDenySecrets).toBeLessThan(allowAt)
    expect(lastDenySecrets).toBeGreaterThan(allowAt)
  })
})

describe('rm in allowWrite under denyRead ancestor (issue #171)', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'rm-under-denyread-' + Date.now())
  const TEST_PROJECT_DIR = join(TEST_BASE_DIR, 'project')
  const TEST_OUTSIDE_DIR = join(TEST_BASE_DIR, 'outside')

  beforeAll(() => {
    if (!isSupportedPlatform) return

    mkdirSync(TEST_PROJECT_DIR, { recursive: true })
    mkdirSync(TEST_OUTSIDE_DIR, { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  describe('macOS Seatbelt', () => {
    // The read section's move-blocking rules emit a broad
    // (deny file-write-unlink (subpath <denyRead>)) that a specific
    // (allow file-write*) does not override. Without a re-allow for
    // file-write-unlink on allowWrite paths, rm fails even though
    // touch/write succeed.

    it.if(isMacOS)(
      'should allow rm inside an allowWrite path under a denyRead ancestor',
      () => {
        const targetFile = join(TEST_PROJECT_DIR, 'deleteme.txt')
        writeFileSync(targetFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `rm ${targetFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(existsSync(targetFile)).toBe(false)
      },
    )

    it.if(isMacOS)(
      'should still block rm outside allowWrite under the same denyRead ancestor',
      () => {
        const protectedFile = join(TEST_OUTSIDE_DIR, 'protected.txt')
        writeFileSync(protectedFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `rm ${protectedFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(existsSync(protectedFile)).toBe(true)
      },
    )

    it.if(isMacOS)(
      'should still block rm of denyWithinAllow paths despite the re-allow',
      () => {
        // The re-allow of file-write-unlink for allowWrite paths is emitted in
        // the read section. The write section's own move-blocking rules for
        // denyWithinAllow are emitted later and must win (last-match).
        const protectedDir = join(TEST_PROJECT_DIR, 'protected')
        const protectedFile = join(protectedDir, 'keep.txt')
        mkdirSync(protectedDir, { recursive: true })
        writeFileSync(protectedFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [protectedDir],
        }

        const wrappedCommand = wrapCommandWithSandboxMacOS({
          command: `rm ${protectedFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).not.toBe(0)
        expect(existsSync(protectedFile)).toBe(true)
      },
    )
  })

  describe('Linux bwrap', () => {
    // #190 fixed the Linux analogue by re-binding allowWrite paths after
    // the denyRead tmpfs wipes them. Verify rm works end-to-end.

    it.if(isLinux)(
      'should allow rm inside an allowWrite path under a denyRead ancestor',
      async () => {
        const targetFile = join(TEST_PROJECT_DIR, 'deleteme-linux.txt')
        writeFileSync(targetFile, 'data')

        const readConfig: FsReadRestrictionConfig = {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        }
        const writeConfig: FsWriteRestrictionConfig = {
          allowOnly: [TEST_PROJECT_DIR],
          denyWithinAllow: [],
        }

        const wrappedCommand = await wrapCommandWithSandboxLinux({
          command: `rm ${targetFile}`,
          needsNetworkRestriction: false,
          readConfig,
          writeConfig,
        })

        const result = spawnSync(wrappedCommand, {
          shell: true,
          encoding: 'utf8',
          timeout: 5000,
        })

        expect(result.status).toBe(0)
        expect(existsSync(targetFile)).toBe(false)
      },
    )
  })
})

describe('allowWrite nested inside allowRead under denyRead ancestor (issue #446)', () => {
  // The nested sibling of #171/#190: there the write path EQUALS the read
  // carve-out and the skip clause covers it. Here the write path is strictly
  // deeper than a read carve-out that is itself inside a denyRead directory —
  // the carve-out's ro-bind used to be emitted after the restored write bind
  // and shadowed it, so the "allowed" write path was read-only in the jail.
  const TEST_BASE_DIR = join(tmpdir(), 'rw-in-ro-in-deny-' + Date.now())
  const TEST_PROJECT_DIR = join(TEST_BASE_DIR, 'project')
  const TEST_STATE_DIR = join(TEST_PROJECT_DIR, 'state')

  beforeAll(() => {
    if (!isSupportedPlatform) return
    mkdirSync(TEST_STATE_DIR, { recursive: true })
    writeFileSync(join(TEST_PROJECT_DIR, 'readme.txt'), 'readable')
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  it.if(isLinux)(
    'emits the read carve-out ro-bind before the nested write bind',
    async () => {
      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        },
        writeConfig: {
          allowOnly: [TEST_STATE_DIR],
          denyWithinAllow: [],
        },
      })
      const roBind = wrappedCommand.indexOf(`--ro-bind ${TEST_PROJECT_DIR}`)
      const rwBind = wrappedCommand.lastIndexOf(`--bind ${TEST_STATE_DIR}`)
      expect(roBind).toBeGreaterThan(-1)
      expect(rwBind).toBeGreaterThan(-1)
      // Later mounts stack over earlier ones, so the deeper rw bind must
      // come after its ancestor's ro-bind or it is shadowed read-only.
      expect(rwBind).toBeGreaterThan(roBind)
    },
  )

  it.if(isLinux)(
    'nested write path is writable while the carve-out stays read-only',
    async () => {
      const probe = join(TEST_STATE_DIR, 'probe.txt')
      const wrappedCommand = await wrapCommandWithSandboxLinux({
        command: `touch ${probe} && cat ${join(TEST_PROJECT_DIR, 'readme.txt')} && ! touch ${join(TEST_PROJECT_DIR, 'not-writable.txt')}`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [TEST_BASE_DIR],
          allowWithinDeny: [TEST_PROJECT_DIR],
        },
        writeConfig: {
          allowOnly: [TEST_STATE_DIR],
          denyWithinAllow: [],
        },
      })
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 5000,
      })
      expect(result.status).toBe(0)
      expect(existsSync(probe)).toBe(true)
      expect(existsSync(join(TEST_PROJECT_DIR, 'not-writable.txt'))).toBe(false)
    },
  )
})
