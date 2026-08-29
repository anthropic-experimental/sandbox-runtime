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

  // `count` files, each its own /dev/null mask, as the concrete list the
  // wrapper takes (glob expansion happens a layer up, in SandboxManager).
  function flatFiles(count: number): string[] {
    const dir = join(BASE, 'many')
    mkdirSync(dir)
    const stem = 'a-reasonably-long-file-name-to-fill-the-profile-'
    const files: string[] = []
    for (let i = 0; i < count; i++) {
      const file = join(dir, `${stem}${i}.log`)
      writeFileSync(file, '')
      files.push(file)
    }
    return files
  }

  it('keeps a profile that fits on the command line', async () => {
    const files = flatFiles(20)
    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: files },
      writeConfig: { allowOnly: [], denyWithinAllow: [] },
    })
    expect(wrapped).not.toContain('--args')
    expect(wrapped).toContain(`--ro-bind /dev/null ${files[0]}`)
  })

  it('moves the options to a NUL-separated file bwrap reads through --args', async () => {
    // 2000 masks of ~80 bytes each: well past 128 KiB as one argument.
    const files = flatFiles(2000)
    const wrapped = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: files },
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
    expect(options).toContain(files[0])
    // The trailer stays on the line, not in the file.
    expect(options).not.toContain('--')
    expect(options).not.toContain('-c')

    // The file goes with the other per-command artifacts.
    cleanupBwrapMountPoints({ force: true })
    expect(existsSync(argsFile)).toBe(false)
    expect(existsSync(dirname(argsFile))).toBe(false)
  })
})
