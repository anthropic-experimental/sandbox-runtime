import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * A bwrap profile too large for one shell argument (Linux's 128 KiB
 * MAX_ARG_STRLEN) is handed to bwrap through `--args` from a file in a
 * per-process directory that every profile ro-binds over itself; a profile
 * that fits stays on the command line.
 */
describe.if(isLinux)('bwrap --args for over-long profiles', () => {
  let BASE: string
  const savedCwd = process.cwd()

  // Runtime arm, as in readonly-deny-dir-stubs.test.ts: only where bwrap can
  // run the namespace/proc surface the wrapped commands use.
  const BWRAP_CAN_NAMESPACE =
    spawnSync(
      'bwrap',
      [
        '--unshare-pid',
        '--unshare-user',
        '--cap-drop',
        'ALL',
        '--ro-bind',
        '/',
        '/',
        '--proc',
        '/proc',
        'true',
      ],
      { timeout: 5000 },
    ).status === 0

  beforeEach(() => {
    BASE = realpathSync(mkdtempSync(join(tmpdir(), 'bwrap-args-')))
    // cwd outside the write allowlist keeps the mandatory-deny scan from
    // adding mounts of its own.
    process.chdir(BASE)
  })

  afterEach(() => {
    process.chdir(savedCwd)
    cleanupBwrapMountPoints({ force: true })
    rmSync(BASE, { recursive: true, force: true })
  })

  // `count` files, each its own /dev/null mask, as the concrete list the
  // wrapper takes (glob expansion happens a layer up, in SandboxManager).
  function flatFiles(
    count: number,
    stem = 'a-reasonably-long-file-name-to-fill-the-profile-',
  ): string[] {
    const dir = join(BASE, 'many')
    mkdirSync(dir, { recursive: true })
    const files: string[] = []
    for (let i = 0; i < count; i++) {
      const file = join(dir, `${stem}${i}.log`)
      // Content, so a masked read of 0 bytes proves the mask applied.
      writeFileSync(file, 'secret\n')
      files.push(file)
    }
    return files
  }

  async function wrap(
    files: string[],
    opts: {
      command?: string
      allowOnly?: string[]
      setEnvVars?: Record<string, string>
      mandatoryDenySearchDepth?: number
    } = {},
  ): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command: opts.command ?? 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: files },
      writeConfig: { allowOnly: opts.allowOnly ?? [], denyWithinAllow: [] },
      setEnvVars: opts.setEnvVars,
      mandatoryDenySearchDepth: opts.mandatoryDenySearchDepth,
    })
  }

  // The per-process --args directory, from the trailing ro-bind every
  // profile that fits the command line carries (an over-long profile
  // carries it inside the file).
  function argsDirOf(wrapped: string): string {
    const bind = wrapped.match(/--ro-bind (\S*srt-bwrap-args-\S+) \1(?: |$)/)
    expect(bind).not.toBeNull()
    return bind![1]!
  }

  // The file an over-long profile was written to, from the redirect.
  function argsFileOf(wrapped: string): string {
    const redirect = wrapped.match(/ 3<(\S+)$/)
    expect(redirect).not.toBeNull()
    return redirect![1]!
  }

  it('keeps a profile that fits on the command line and still ro-binds the --args directory', async () => {
    const files = flatFiles(20)
    const wrapped = await wrap(files)
    expect(wrapped).not.toContain('--args')
    expect(wrapped).toContain(`--ro-bind /dev/null ${files[0]}`)
    // Ro-bound in every profile, not only the ones that use it: a sandbox
    // launched with a small profile may still be running when a later
    // over-long one is written there.
    const argsDir = argsDirOf(wrapped)
    expect(existsSync(argsDir)).toBe(true)
    expect(wrapped.lastIndexOf(`--ro-bind ${argsDir} ${argsDir}`)).toBe(
      wrapped.lastIndexOf('--ro-bind'),
    )
  })

  it('moves the options to a NUL-separated file bwrap reads through --args', async () => {
    // 2000 masks of ~80 bytes each: well past 128 KiB as one argument.
    const files = flatFiles(2000)
    const wrapped = await wrap(files, {
      setEnvVars: { SRT_TEST_VAR: "value with spaces and 'quotes'" },
    })

    expect(Buffer.byteLength(wrapped)).toBeLessThan(128 * 1024)
    // The shell opens the file on fd 3, unlinks it, and execs bwrap.
    expect(wrapped).toMatch(/^\{ rm -f (\S+); exec bwrap --args 3 -- \S+ -c /)
    const argsFile = argsFileOf(wrapped)
    expect(wrapped.match(/^\{ rm -f (\S+); /)![1]).toBe(argsFile)
    expect(existsSync(argsFile)).toBe(true)
    // Inside the per-process directory.
    const argsDir = dirname(argsFile)
    expect(argsDir).toMatch(/srt-bwrap-args-/)

    const words = readFileSync(argsFile, 'utf8').split('\0')
    expect(words[words.length - 1]).toBe('') // every word NUL-terminated
    const options = words.slice(0, -1)
    // The profile, one word per element, unquoted: 2000 masks between the
    // fixed plumbing at either end, and a value bwrap must receive verbatim.
    expect(options.slice(0, 2)).toEqual(['--new-session', '--die-with-parent'])
    expect(options.slice(-2)).toEqual(['--proc', '/proc'])
    // The directory's own ro-bind, last of the binds, rides in the file.
    const lastBind = options.lastIndexOf('--ro-bind')
    expect(options.slice(lastBind, lastBind + 3)).toEqual([
      '--ro-bind',
      argsDir,
      argsDir,
    ])
    expect(
      options.filter(w => w === '--ro-bind').length,
    ).toBeGreaterThanOrEqual(2000)
    expect(options).toContain(files[0])
    const setenv = options.indexOf('--setenv')
    expect(options.slice(setenv, setenv + 3)).toEqual([
      '--setenv',
      'SRT_TEST_VAR',
      "value with spaces and 'quotes'",
    ])
    // The trailer stays on the line, not in the file.
    expect(options).not.toContain('--')
    expect(options).not.toContain('-c')

    // A file never spawned goes with the other per-command artifacts; the
    // directory stays for the process (a sandbox launched earlier may still
    // have it bound) and goes at exit.
    cleanupBwrapMountPoints()
    expect(existsSync(argsFile)).toBe(false)
    expect(existsSync(argsDir)).toBe(true)
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(argsDir)).toBe(true)
  })

  it('switches to --args exactly where one argument would exceed 128 KiB', async () => {
    // The command is the last word on the line; a trailing two-byte
    // character keeps the shell quoter's output constant while every
    // added 'a' adds one byte, so the padding sets the rendered size byte
    // for byte — and a regression to string length (UTF-16 units) would
    // miscount it by one.
    const files = flatFiles(20)
    const base = await wrap(files, { command: 'é' })
    expect(base).not.toContain('--args')
    const renderedAt = (bytes: number) =>
      wrap(files, {
        command: 'a'.repeat(bytes - Buffer.byteLength(base)) + 'é',
      })

    const fits = await renderedAt(128 * 1024 - 1)
    expect(Buffer.byteLength(fits)).toBe(128 * 1024 - 1)
    expect(fits).not.toContain('--args')

    const overflows = await renderedAt(128 * 1024)
    expect(overflows).toMatch(/^\{ rm -f \S+; exec bwrap --args 3 -- /)
  })

  it.if(BWRAP_CAN_NAMESPACE)(
    'e2e: bwrap applies the profile from the file, and the command sees neither the fd nor a writable --args directory',
    async () => {
      // The directory is created by the first wrap of the process, so a
      // small one names it for the command below.
      const argsDir = argsDirOf(await wrap(flatFiles(1)))
      const probe = join(argsDir, 'srt-args-probe')
      // tmpdir writable inside the sandbox: the case the trailing ro-bind
      // exists for. Fewer, longer-named masks than the shape test: every
      // mount costs bwrap time, and the runner's tmpdir is scanned shallowly
      // for the same reason.
      const files = flatFiles(700, `${'a'.repeat(150)}-`)
      const wrapped = await wrap(files, {
        allowOnly: [tmpdir()],
        mandatoryDenySearchDepth: 1,
        command: [
          // The mask is a bind of /dev/null: a character device in place
          // of the file (opening a device node inside the user namespace
          // is not portable across hosts, so its type is the oracle).
          `[ -c ${files[0]} ] && echo MASKED || echo UNMASKED`,
          '[ -e /proc/self/fd/3 ] && echo FD3_OPEN || echo FD3_CLOSED',
          `touch ${probe} 2>/dev/null && echo ARGS_WRITABLE || echo ARGS_READONLY`,
        ].join('; '),
      })
      const argsFile = argsFileOf(wrapped)
      expect(dirname(argsFile)).toBe(argsDir)
      const run = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 60000,
        cwd: BASE,
      })
      expect(run.stderr ?? '').not.toMatch(/--args|Exceeded maximum/)
      expect(run.status).toBe(0)
      const lines = run.stdout.trim().split('\n')
      expect(lines[0]).toBe('MASKED') // the mask from the file applied
      expect(readFileSync(files[0]!, 'utf8')).toBe('secret\n') // host intact
      expect(lines[1]).toBe('FD3_CLOSED')
      expect(lines[2]).toBe('ARGS_READONLY')
      expect(existsSync(probe)).toBe(false)
      // Unlinked by the spawn itself.
      expect(existsSync(argsFile)).toBe(false)
    },
    60_000,
  )
})
