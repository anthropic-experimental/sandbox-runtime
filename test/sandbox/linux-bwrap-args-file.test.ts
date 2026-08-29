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
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

/**
 * A bwrap profile too large for one shell argument (Linux's 128 KiB
 * MAX_ARG_STRLEN) is handed to bwrap through `--args` from a temporary
 * file; a profile that fits stays on the command line.
 */
describe.if(isLinux)('bwrap --args for over-long profiles', () => {
  let BASE: string
  const savedCwd = process.cwd()

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

  // A flat directory of `count` files: each one is its own /dev/null mask,
  // nothing collapses.
  function flatFiles(count: number): string {
    const dir = join(BASE, 'many')
    mkdirSync(dir)
    const stem = 'a-reasonably-long-file-name-to-fill-the-profile-'
    for (let i = 0; i < count; i++) {
      writeFileSync(join(dir, `${stem}${i}.log`), '')
    }
    return dir
  }

  it('keeps a profile that fits on the command line', async () => {
    const dir = flatFiles(20)
    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [join(dir, '*.log')] },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    expect(wrapped).not.toContain('--args')
    expect(wrapped).toContain('--ro-bind /dev/null')
  })

  it('moves the options to a NUL-separated file bwrap reads through --args', async () => {
    // 2000 masks of ~80 bytes each: well past 128 KiB as one argument.
    const dir = flatFiles(2000)
    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [join(dir, '*.log')] },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })

    expect(Buffer.byteLength(wrapped)).toBeLessThan(128 * 1024)
    expect(wrapped).toMatch(/^bwrap --args 3 -- \S+ -c /)
    const redirect = wrapped.match(/ 3<(\S+)$/)
    expect(redirect).not.toBeNull()
    const argsFile = redirect![1]!
    expect(existsSync(argsFile)).toBe(true)

    const words = readFileSync(argsFile, 'utf8').split('\0')
    expect(words[words.length - 1]).toBe('') // every word NUL-terminated
    const options = words.slice(0, -1)
    // The profile, one word per element: 2000 masks plus the fixed plumbing.
    expect(
      options.filter(w => w === '--ro-bind').length,
    ).toBeGreaterThanOrEqual(2000)
    expect(options).toContain(
      join(dir, 'a-reasonably-long-file-name-to-fill-the-profile-0.log'),
    )
    // The trailer stays on the line, not in the file.
    expect(options).not.toContain('--')
    expect(options).not.toContain('-c')

    // The file goes with the other per-command artifacts.
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(argsFile)).toBe(false)
    expect(existsSync(dirname(argsFile))).toBe(false)
  })
})
