import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  wrapCommandWithSandboxLinuxArgv,
  cleanupBwrapMountPoints,
  type LinuxSandboxParams,
} from '../../src/sandbox/linux-sandbox-utils.js'
import {
  describeBwrapArgv,
  describeBwrapStringOverflow,
  type BwrapArgvSummary,
} from '../../src/sandbox/bwrap-argv.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { quote } from '../../src/utils/shell-quote.js'
import { whichSync } from '../../src/utils/which.js'
import { isLinux } from '../helpers/platform.js'

/**
 * The bwrap invocation as a real argv vector, spawnable with {shell:false}:
 * one element per bwrap word, and the same invocation the string form runs.
 */
describe.if(isLinux)('wrapCommandWithSandboxLinuxArgv', () => {
  let BASE: string
  let AREA: string
  let SECRETS: string
  const savedCwd = process.cwd()

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'bwrap-argv-')))
    AREA = join(BASE, 'area')
    SECRETS = join(BASE, 'secrets')
    mkdirSync(join(AREA, 'sub'), { recursive: true })
    mkdirSync(SECRETS)
    writeFileSync(join(AREA, 'sub', 'locked.txt'), 'x\n')
    writeFileSync(join(AREA, '.env'), 'SECRET=1\n')
    writeFileSync(join(SECRETS, 'token'), 't\n')
    // cwd OUTSIDE the write allowlist keeps the mandatory-deny scan from
    // contributing creation-blocking stubs (their empty-dir sources are
    // mkdtemp'd, which would make two wraps of the same params differ).
    process.chdir(BASE)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  function params(
    command = `echo 'hello world' && ls "$HOME"`,
  ): LinuxSandboxParams {
    return {
      command,
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [SECRETS, join(AREA, '.env')] },
      writeConfig: {
        allowOnly: [AREA],
        denyWithinAllow: [join(AREA, 'sub', 'locked.txt')],
      },
      setEnvVars: { SRT_TEST_VAR: 'value with spaces' },
    }
  }

  it('returns null when the params call for no sandbox at all', async () => {
    const argv = await wrapCommandWithSandboxLinuxArgv({
      command: 'echo hi',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [] },
      writeConfig: undefined,
    })
    expect(argv).toBeNull()
    // The string form hands the command back untouched as well.
    expect(
      await wrapCommandWithSandboxLinux({
        command: 'echo hi',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [] },
        writeConfig: undefined,
      }),
    ).toBe('echo hi')
  })

  it('is one element per bwrap word with the shell trailer last', async () => {
    // No single quotes: the inner script may re-quote the command (the
    // apply-seccomp shim wraps it in another `bash -c '...'`), and a
    // single-quote-free command survives that as a verbatim substring.
    const command = `printf "%s\\n" word && true`
    const argv = (await wrapCommandWithSandboxLinuxArgv(params(command)))!

    expect(argv[0]).toBe(whichSync('bwrap') ?? 'bwrap')
    const separator = argv.indexOf('--')
    expect(separator).toBeGreaterThan(0)
    // Trailer: <resolved shell> -c <inner script>, and nothing after it.
    expect(argv.slice(separator + 1, separator + 3)).toEqual([
      whichSync('bash')!,
      '-c',
    ])
    expect(argv.length).toBe(separator + 4)
    // The user command lives only in the inner script (possibly behind the
    // apply-seccomp shim), never folded into an option word.
    expect(argv[separator + 3]).toContain(command)
    expect(argv.slice(0, separator).some(a => a.includes(command))).toBe(false)
    // Mount options are their own elements: no element other than the
    // option word itself mentions --ro-bind / --tmpfs.
    for (const word of ['--ro-bind', '--tmpfs', '--bind', '--setenv']) {
      expect(argv.filter(a => a.includes(word)).every(a => a === word)).toBe(
        true,
      )
    }
    // The configured policy made it in as discrete operands.
    expect(argv).toContain(SECRETS) // --tmpfs SECRETS
    expect(argv).toContain(join(AREA, 'sub', 'locked.txt')) // --ro-bind p p
    const setenvAt = argv.indexOf('SRT_TEST_VAR')
    expect(argv[setenvAt - 1]).toBe('--setenv')
    expect(argv[setenvAt + 1]).toBe('value with spaces')
  })

  it('honours bwrapPath as argv[0]', async () => {
    const argv = (await wrapCommandWithSandboxLinuxArgv({
      ...params(),
      bwrapPath: '/opt/custom/bin/bwrap',
    }))!
    expect(argv[0]).toBe('/opt/custom/bin/bwrap')
  })

  it('SandboxManager.wrapWithSandboxArgv returns the bwrap vector, not [shell, -c, string]', async () => {
    // Long enough that the inner script is unambiguously the largest word.
    const command = `echo from-manager ${'x'.repeat(256)}`
    const customConfig = {
      filesystem: {
        denyRead: [SECRETS],
        allowWrite: [AREA],
        denyWrite: [join(AREA, 'sub', 'locked.txt')],
      },
    }
    try {
      const { argv, env } = await SandboxManager.wrapWithSandboxArgv(
        command,
        undefined,
        customConfig,
      )
      const wrapped = await SandboxManager.wrapWithSandbox(
        command,
        undefined,
        customConfig,
      )

      expect(env).toBe(process.env)
      expect(argv[0]).toBe(whichSync('bwrap') ?? 'bwrap')
      expect(argv).toContain('--')
      expect(quote(argv)).toBe(wrapped)
      // The point of the vector: the largest single element is the inner
      // script, not the whole profile.
      const summary = describeBwrapArgv(argv)
      expect(summary.largestArgBytes).toBe(summary.innerCommandBytes)
      expect(summary.largestArgBytes).toBeLessThan(
        Buffer.byteLength(wrapped) + 1,
      )
    } finally {
      await SandboxManager.reset()
    }
  })
})

describe('describeBwrapArgv', () => {
  const nul = (s: string): number => Buffer.byteLength(s, 'utf8') + 1
  const countsOf = (summary: BwrapArgvSummary): Record<string, number> =>
    Object.fromEntries(
      Object.entries(summary.terms).map(([term, t]) => [term, t.count]),
    )
  const bytesAcrossTerms = (summary: BwrapArgvSummary): number =>
    Object.values(summary.terms).reduce((sum, t) => sum + t.bytes, 0)

  it('breaks a vector down by term with execve-style byte accounting', () => {
    const inner = `echo 'héllo'` // multi-byte on purpose
    const argv = [
      'bwrap',
      '--new-session',
      '--die-with-parent',
      '--setenv',
      'HTTP_PROXY',
      'http://localhost:3128',
      '--ro-bind',
      '/',
      '/',
      '--bind',
      '/work',
      '/work',
      '--tmpfs',
      '/home/u/.ssh',
      '--ro-bind',
      '/dev/null',
      '/work/.env',
      '--ro-bind',
      '/tmp/claude-empty-123',
      '/work/.claude',
      '--ro-bind',
      '/work/.git/hooks',
      '/work/.git/hooks',
      '--dev',
      '/dev',
      '--unshare-pid',
      '--',
      '/usr/bin/bash',
      '-c',
      inner,
    ]

    const summary = describeBwrapArgv(argv)

    expect(countsOf(summary)).toEqual({
      roBindSelf: 2, // '/' '/' and the hooks dir
      roBindDevNull: 1,
      roBindOther: 1, // the empty-dir stub
      bind: 1,
      tmpfs: 1,
      setenv: 1,
      // bwrap, --new-session, --die-with-parent, --dev, /dev, --unshare-pid,
      // --, /usr/bin/bash, -c, inner
      other: 10,
    })
    expect(summary.terms.setenv.bytes).toBe(
      nul('--setenv') + nul('HTTP_PROXY') + nul('http://localhost:3128'),
    )
    expect(summary.terms.tmpfs.bytes).toBe(nul('--tmpfs') + nul('/home/u/.ssh'))
    expect(summary.terms.roBindDevNull.bytes).toBe(
      nul('--ro-bind') + nul('/dev/null') + nul('/work/.env'),
    )
    expect(summary.innerCommandBytes).toBe(nul(inner))
    expect(summary.totalBytes).toBe(
      argv.reduce((sum, arg) => sum + nul(arg), 0),
    )
    // The terms partition the vector.
    expect(bytesAcrossTerms(summary)).toBe(summary.totalBytes)
    expect(summary.largestArgBytes).toBe(nul('/tmp/claude-empty-123'))
  })

  it('treats a [shell, -c, script] vector as its own trailer', () => {
    const summary = describeBwrapArgv(['/bin/bash', '-c', 'echo hi'])
    expect(summary.innerCommandBytes).toBe(nul('echo hi'))
    expect(summary.largestArgBytes).toBe(nul('/bin/bash'))
    expect(summary.terms.other.count).toBe(3)
    expect(bytesAcrossTerms(summary)).toBe(summary.totalBytes)
  })

  it('describeBwrapStringOverflow warns only past the per-argument cap', () => {
    // ~140 bytes per mask, the shape of a monorepo node_modules path.
    const mask = (i: number): string[] => [
      '--ro-bind',
      '/dev/null',
      `/home/user/monorepo/packages/service-${i}/node_modules/@scope/pkg/dist/esm/internal/generated/schema/types/index.js`,
    ]
    const vector = (masks: number): string[] => [
      'bwrap',
      ...Array.from({ length: masks }, (_, i) => mask(i)).flat(),
      '--',
      '/bin/bash',
      '-c',
      'echo',
    ]
    const under = vector(200)
    expect(describeBwrapStringOverflow(under, quote(under))).toBeUndefined()
    const over = vector(1200)
    const warning = describeBwrapStringOverflow(over, quote(over))
    expect(warning).toContain('E2BIG')
    expect(warning).toContain('/dev/null masks 1200')
    expect(warning).toContain('wrapWithSandboxArgv')
  })

  it('reports zero inner-command bytes for a vector without a -- trailer', () => {
    const summary = describeBwrapArgv(['bwrap', '--tmpfs', '/x'])
    expect(summary.innerCommandBytes).toBe(0)
    expect(summary.terms.tmpfs.count).toBe(1)
    expect(summary.terms.other.count).toBe(1)
  })

  it('tolerates an empty vector and a truncated trailing option', () => {
    expect(describeBwrapArgv([]).totalBytes).toBe(0)
    const truncated = describeBwrapArgv(['bwrap', '--ro-bind', '/dev/null'])
    expect(truncated.terms.roBindDevNull.count).toBe(1)
    expect(truncated.terms.roBindDevNull.bytes).toBe(
      nul('--ro-bind') + nul('/dev/null'),
    )
    expect(bytesAcrossTerms(truncated)).toBe(truncated.totalBytes)
  })

  it('is not fooled by an operand spelled like an Object.prototype member, nor by a bare --ro-bind', () => {
    // An option the table does not know leaves its operand in option
    // position; `constructor` must read as a bare word, not as a function.
    const summary = describeBwrapArgv([
      'bwrap',
      '--hostname',
      'constructor',
      '--tmpfs',
      '/x',
      '--',
      '/bin/bash',
      '-c',
      'echo',
    ])
    expect(summary.terms.tmpfs.count).toBe(1)
    expect(summary.innerCommandBytes).toBe(nul('echo'))
    expect(bytesAcrossTerms(summary)).toBe(summary.totalBytes)
    // No operands at all is not a self-bind.
    expect(
      describeBwrapArgv(['bwrap', '--ro-bind']).terms.roBindSelf.count,
    ).toBe(0)
  })
})
