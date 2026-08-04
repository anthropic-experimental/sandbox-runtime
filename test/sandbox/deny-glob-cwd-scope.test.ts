import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
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
 * A deny entry written as a location-independent glob (`**\/<name>`) is resolved
 * against process.cwd() by normalizePathForSandbox() and then anchored by
 * globToRegex(), so it is only enforced beneath cwd.
 *
 * Every case below uses the same layout, with cwd a strict subdirectory of the
 * allowed write root:
 *
 *   ROOT/            <- allowOnly root
 *     proj/          <- process.cwd()
 *       sub/
 *     outside/       <- inside the allowed write root, outside cwd
 *
 * The `it()` cases are controls: they hold today and pin the harness — two of them
 * assert a permitted operation, so a profile that never applied cannot satisfy
 * the whole set. A red run points at the scope and not at the setup. The `it.failing()` cases are the
 * ones this PR is about — they pass because the assertion inside them currently
 * fails, and they start failing the moment the behaviour changes, which is the
 * signal to drop the marker.
 *
 * macOS only: the Linux and Windows backends consume these patterns through
 * different code, which is not exercised here.
 *
 * See #432.
 */
describe.if(isMacOS)('deny globs outside process.cwd()', () => {
  const ROOT_RAW = join(tmpdir(), `deny-glob-cwd-scope-${Date.now()}`)
  const ORIGINAL = 'ORIGINAL'
  const MODIFIED = 'MODIFIED'
  // Printed by the sandboxed shell before the command under test. If it is
  // missing, the profile never applied and every "blocked" assertion below
  // would otherwise pass for the wrong reason.
  const STARTED = '__DENY_GLOB_CWD_SCOPE_STARTED__'

  let ROOT: string
  let PROJ: string
  let OUTSIDE: string
  let originalCwd: string

  beforeAll(() => {
    originalCwd = process.cwd()
    mkdirSync(ROOT_RAW, { recursive: true })
    // On macOS tmpdir() sits behind a symlink; resolve it so the allow root and
    // the paths the sandbox sees are the same strings.
    ROOT = realpathSync(ROOT_RAW)
    PROJ = join(ROOT, 'proj')
    OUTSIDE = join(ROOT, 'outside')
  })

  afterAll(() => {
    process.chdir(originalCwd)
    rmSync(ROOT_RAW, { recursive: true, force: true })
  })

  beforeEach(() => {
    process.chdir(originalCwd)
    rmSync(PROJ, { recursive: true, force: true })
    rmSync(OUTSIDE, { recursive: true, force: true })
    mkdirSync(join(PROJ, 'sub'), { recursive: true })
    mkdirSync(join(OUTSIDE, 'newdir'), { recursive: true })

    writeFileSync(join(PROJ, '.env'), ORIGINAL)
    writeFileSync(join(PROJ, 'sub', '.env'), ORIGINAL)
    writeFileSync(join(OUTSIDE, '.env'), ORIGINAL)
    writeFileSync(join(PROJ, 'secret.txt'), ORIGINAL)
    writeFileSync(join(OUTSIDE, 'secret.txt'), ORIGINAL)
    // OUTSIDE/newdir/.env is deliberately NOT created: that case exercises
    // file-write-create rather than file-write-data.

    // cwd is a strict subdirectory of the allowed write root.
    process.chdir(PROJ)
  })

  function runSandboxed(
    command: string,
    policy: { denyWrite?: string[]; denyRead?: string[] },
  ): { executed: boolean; success: boolean; stdout: string; stderr: string } {
    const prefix = `${STARTED}
`

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `printf '%s\\n' '${STARTED}'; ${command}`,
      needsNetworkRestriction: false,
      readConfig: policy.denyRead
        ? { denyOnly: policy.denyRead, allowWithinDeny: [] }
        : undefined,
      writeConfig: {
        allowOnly: [ROOT],
        denyWithinAllow: policy.denyWrite ?? [],
      },
    })

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    const rawStdout = result.stdout ?? ''
    const markerSeen = rawStdout.startsWith(prefix)
    // `executed` is what separates "the sandbox ran and denied this" from
    // "the sandbox never started": a failed profile, a syntax error, a spawn
    // failure and a timeout all leave the marker unprinted.
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
      const target = join(PROJ, 'sub', '.env')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
        denyWrite: ['**/.env'],
      })

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: an absolute entry outside cwd is enforced', () => {
      const target = join(OUTSIDE, '.env')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
        denyWrite: [target],
      })

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: an absolute-prefixed glob outside cwd is enforced', () => {
      // Same wildcard, but the pattern starts with a path separator, so
      // normalizePathForSandbox() leaves it alone. This is what pins the defect
      // to the leading `**/` form rather than to glob handling in general.
      const target = join(OUTSIDE, '.env')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
        denyWrite: [join(ROOT, '**', '.env')],
      })

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it('control: a write outside cwd matching no deny entry succeeds', () => {
      // Positive control. Every other write case asserts a denial, so a profile
      // that failed to apply would satisfy all of them. This one only passes if
      // the sandbox is running and permissive where it should be.
      const target = join(OUTSIDE, 'safe.txt')
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
        const target = join(OUTSIDE, '.env')

        const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
          denyWrite: ['**/.env'],
        })

        expect(result.executed).toBe(true)

        expect(result.success).toBe(false)
        expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
      },
    )

    it.failing(
      'blocks creating a new file outside cwd (file-write-create)',
      () => {
        const target = join(OUTSIDE, 'newdir', '.env')

        const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {
          denyWrite: ['**/.env'],
        })

        expect(result.executed).toBe(true)

        expect(result.success).toBe(false)
        expect(existsSync(target)).toBe(false)
      },
    )
  })

  describe('user-written denyRead glob', () => {
    it('control: denies reading a matched file under cwd', () => {
      const target = join(PROJ, 'secret.txt')

      const result = runSandboxed(`cat '${target}'`, {
        denyRead: ['**/secret.txt'],
      })

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })

    it('control: an absolute entry outside cwd is enforced', () => {
      const target = join(OUTSIDE, 'secret.txt')

      const result = runSandboxed(`cat '${target}'`, { denyRead: [target] })

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })

    it('control: a read outside cwd matching no deny entry succeeds', () => {
      // Positive control for the read side, same reasoning as the write one.
      const target = join(OUTSIDE, 'public.txt')
      writeFileSync(target, ORIGINAL)

      const result = runSandboxed(`cat '${target}'`, {
        denyRead: ['**/secret.txt'],
      })

      expect(result.executed).toBe(true)
      expect(result.success).toBe(true)
      expect(result.stdout).toContain(ORIGINAL)
    })

    it.failing('denies reading a matched file outside cwd', () => {
      const target = join(OUTSIDE, 'secret.txt')

      const result = runSandboxed(`cat '${target}'`, {
        denyRead: ['**/secret.txt'],
      })

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(result.stdout).not.toContain(ORIGINAL)
    })
  })

  describe('built-in mandatory deny (same normalization)', () => {
    it.failing('blocks an overwrite of .zshrc outside cwd', () => {
      const target = join(OUTSIDE, '.zshrc')
      writeFileSync(target, ORIGINAL)

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {})

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(readFileSync(target, 'utf8').trim()).toBe(ORIGINAL)
    })

    it.failing('blocks creating .git/hooks/pre-commit outside cwd', () => {
      const hooks = join(OUTSIDE, 'repo', '.git', 'hooks')
      mkdirSync(hooks, { recursive: true })
      const target = join(hooks, 'pre-commit')

      const result = runSandboxed(`echo '${MODIFIED}' > '${target}'`, {})

      expect(result.executed).toBe(true)

      expect(result.success).toBe(false)
      expect(existsSync(target)).toBe(false)
    })
  })
})
