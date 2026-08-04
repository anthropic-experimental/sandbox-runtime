import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  realpathSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * On macOS, location-independent deny globs such as `**\/.env` are normalized
 * against `process.cwd()`. These tests show that they apply beneath cwd but not
 * to matching paths elsewhere in the same sandbox root. See #432.
 *
 * Bun accepts any throw in `it.failing` as the expected failure, so those bodies
 * return early when the sandbox did not run. An infrastructure failure then
 * surfaces as "marked failing but passed" instead of as a passing test.
 */
describe.if(isMacOS)('deny globs outside process.cwd()', () => {
  const ORIGINAL = 'ORIGINAL'
  const MODIFIED = 'MODIFIED'
  const STARTED = '__DENY_GLOB_CWD_SCOPE_STARTED__'

  let tempRoot: string
  let allowedRoot: string
  let projectDir: string
  let outsideDir: string
  let originalCwd: string

  beforeAll(() => {
    originalCwd = process.cwd()
    // Timestamp-based roots can collide when runs start in the same millisecond.
    tempRoot = mkdtempSync(join(tmpdir(), 'deny-glob-cwd-scope-'))
    // Resolve macOS's symlinked temp path to the canonical path Seatbelt sees.
    allowedRoot = realpathSync(tempRoot)
    projectDir = join(allowedRoot, 'proj')
    outsideDir = join(allowedRoot, 'outside')
  })

  afterAll(() => {
    process.chdir(originalCwd)
    rmSync(tempRoot, { recursive: true, force: true })
  })

  beforeEach(() => {
    process.chdir(originalCwd)
    rmSync(projectDir, { recursive: true, force: true })
    rmSync(outsideDir, { recursive: true, force: true })
    mkdirSync(join(projectDir, 'sub'), { recursive: true })
    mkdirSync(join(outsideDir, 'newdir'), { recursive: true })

    writeFileSync(join(projectDir, '.env'), ORIGINAL)
    writeFileSync(join(projectDir, 'sub', '.env'), ORIGINAL)
    writeFileSync(join(outsideDir, '.env'), ORIGINAL)
    writeFileSync(join(projectDir, 'secret.txt'), ORIGINAL)
    writeFileSync(join(outsideDir, 'secret.txt'), ORIGINAL)
    // Leave `outside/newdir/.env` absent to exercise `file-write-create`.

    process.chdir(projectDir)
  })

  function runSandboxed(
    command: string,
    policy: { denyWrite?: string[]; denyRead?: string[] },
  ): { executed: boolean; success: boolean; stdout: string; stderr: string } {
    const prefix = `${STARTED}\n`

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `printf '%s\\n' '${STARTED}'; ${command}`,
      needsNetworkRestriction: false,
      readConfig: policy.denyRead
        ? { denyOnly: policy.denyRead, allowWithinDeny: [] }
        : undefined,
      writeConfig: {
        allowOnly: [allowedRoot],
        denyWithinAllow: policy.denyWrite ?? [],
      },
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    const rawStdout = result.stdout ?? ''
    // Requiring the sentinel keeps sandbox startup failures from masquerading
    // as denied operations.
    const markerSeen = rawStdout.startsWith(prefix)
    const executed =
      result.error === undefined && result.signal === null && markerSeen

    return {
      executed,
      success: executed && result.status === 0,
      stdout: markerSeen ? rawStdout.slice(prefix.length) : rawStdout,
      stderr: result.stderr ?? '',
    }
  }

  describe('user-written denyWrite glob', () => {
    it('control: blocks an overwrite under cwd', () => {
      const target = join(projectDir, 'sub', '.env')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
        denyWrite: ['**/.env'],
      })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: an absolute entry outside cwd is enforced', () => {
      const target = join(outsideDir, '.env')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
        denyWrite: [target],
      })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: an absolute-prefixed glob outside cwd is enforced', () => {
      // The absolute prefix prevents cwd rebasing, isolating the defect to
      // leading `**/` patterns rather than glob handling in general.
      const target = join(outsideDir, '.env')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
        denyWrite: [join(allowedRoot, '**', '.env')],
      })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: a write outside cwd matching no deny entry succeeds', () => {
      // Prevents a blanket write failure from satisfying every write assertion.
      const target = join(outsideDir, 'safe.txt')
      writeFileSync(target, ORIGINAL)

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
        denyWrite: ['**/.env'],
      })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(true)
      expect(readFileSync(target, 'utf8').trim()).toBe(MODIFIED)
    })

    it.failing(
      'blocks an overwrite outside cwd but inside the allowed write root',
      () => {
        const target = join(outsideDir, '.env')

        const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
          denyWrite: ['**/.env'],
        })

        if (!result.executed) return

        expect(result.success).toBe(false)
        expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
      },
    )

    it.failing(
      'blocks creating a new file outside cwd (file-write-create)',
      () => {
        const target = join(outsideDir, 'newdir', '.env')

        const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
          denyWrite: ['**/.env'],
        })

        if (!result.executed) return

        expect(result.success).toBe(false)
        expect(existsSync(target)).toBe(false)
      },
    )
  })

  describe('user-written denyRead glob', () => {
    it('control: denies reading a matched file under cwd', () => {
      const target = join(projectDir, 'secret.txt')

      const result = runSandboxed(`cat '${target}'`, {
        denyRead: ['**/secret.txt'],
      })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })

    it('control: an absolute entry outside cwd is enforced', () => {
      const target = join(outsideDir, 'secret.txt')

      const result = runSandboxed(`cat '${target}'`, { denyRead: [target] })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })

    it('control: a read outside cwd matching no deny entry succeeds', () => {
      // Prevents a blanket read failure from satisfying every read assertion.
      const target = join(outsideDir, 'public.txt')
      writeFileSync(target, ORIGINAL)

      const result = runSandboxed(`cat '${target}'`, {
        denyRead: ['**/secret.txt'],
      })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(true)
      expect(result.stdout).toContain(ORIGINAL)
    })

    it.failing('denies reading a matched file outside cwd', () => {
      const target = join(outsideDir, 'secret.txt')

      const result = runSandboxed(`cat '${target}'`, {
        denyRead: ['**/secret.txt'],
      })

      if (!result.executed) return

      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })
  })

  describe('built-in mandatory deny (same normalization)', () => {
    it.failing('blocks an overwrite of .zshrc outside cwd', () => {
      const target = join(outsideDir, '.zshrc')
      writeFileSync(target, ORIGINAL)

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {})

      if (!result.executed) return

      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it.failing('blocks creating .git/hooks/pre-commit outside cwd', () => {
      const hooks = join(outsideDir, 'repo', '.git', 'hooks')
      mkdirSync(hooks, { recursive: true })
      const target = join(hooks, 'pre-commit')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {})

      if (!result.executed) return

      expect(result.success).toBe(false)
      expect(existsSync(target)).toBe(false)
    })
  })
})
