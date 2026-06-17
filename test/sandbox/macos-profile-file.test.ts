import { describe, it, expect, beforeEach, afterEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import shellquote from 'shell-quote'
import {
  getMacOSProfileFileDir,
  wrapCommandWithSandboxMacOS,
  writeMacOSProfileFile,
} from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS, isWindows } from '../helpers/platform.js'
import type { FsWriteRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'

/**
 * Tests for passing the seatbelt profile to sandbox-exec via a temp file (-f)
 * instead of inline argv (-p).
 *
 * Perf: the inline form makes the wrapped command string ~100KB, which the
 * outer shell has to re-parse and the kernel copies through argv twice.
 *
 * Security invariant: a sandboxed command must not be able to write under the
 * profile directory — a tampered profile file would control the policy applied
 * to the NEXT sandboxed command (sandbox escape). Every generated profile
 * therefore denies writes under getMacOSProfileFileDir(), even when the config
 * imposes no other write restrictions.
 */

const WRITE_CONFIG: FsWriteRestrictionConfig = {
  allowOnly: [tmpdir()],
  denyWithinAllow: [],
}

/** Extract the path passed to sandbox-exec -f from a wrapped command. */
function extractProfileFilePath(wrappedCommand: string): string | undefined {
  const args = shellquote.parse(wrappedCommand)
  const fIndex = args.indexOf('-f')
  return fIndex === -1 ? undefined : (args[fIndex + 1] as string)
}

// Profile generation works on any POSIX platform (CI runs these on Linux
// too), but not Windows: no `bash` in PATH for whichSync, and POSIX file
// modes/uids don't apply. The live sandbox-exec tests are macOS-only.
describe.if(!isWindows)('macOS sandbox profile file (-f)', () => {
  let savedTmpdir: string | undefined
  let testTmp: string

  beforeEach(() => {
    // Isolate the profile directory per test via TMPDIR (os.tmpdir() reads it
    // on every call).
    savedTmpdir = process.env.TMPDIR
    testTmp = mkdtempSync(join(tmpdir(), 'profile-file-test-'))
    process.env.TMPDIR = testTmp
  })

  afterEach(() => {
    if (savedTmpdir === undefined) {
      delete process.env.TMPDIR
    } else {
      process.env.TMPDIR = savedTmpdir
    }
    rmSync(testTmp, { recursive: true, force: true })
  })

  it('passes the profile via -f and writes a 0600 file in the profile dir', () => {
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: WRITE_CONFIG,
    })

    const profileFile = extractProfileFilePath(wrappedCommand)
    expect(profileFile).toBeDefined()
    expect(profileFile!.startsWith(getMacOSProfileFileDir())).toBe(true)
    expect(existsSync(profileFile!)).toBe(true)
    expect(statSync(profileFile!).mode & 0o777).toBe(0o600)

    const profile = readFileSync(profileFile!, 'utf8')
    expect(profile).toContain('(version 1)')
    expect(profile).toContain('(deny default')

    // The command string must not contain the inline profile
    expect(wrappedCommand).not.toContain('(version 1)')
    expect(wrappedCommand.length).toBeLessThan(4096)
  })

  it('denies writes under the profile dir in the generated profile', () => {
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: WRITE_CONFIG,
    })
    const profile = readFileSync(
      extractProfileFilePath(wrappedCommand)!,
      'utf8',
    )
    const denyRule = `(deny file-write*\n  (subpath ${JSON.stringify(getMacOSProfileFileDir())})`
    expect(profile).toContain(denyRule)
    // Move-blocking rules protect the directory from rename/replace tricks
    expect(profile).toContain(
      `(deny file-write-unlink\n  (subpath ${JSON.stringify(getMacOSProfileFileDir())})`,
    )
    expect(profile).toContain(
      `(deny file-write-create\n  (subpath ${JSON.stringify(getMacOSProfileFileDir())})`,
    )
  })

  it('denies writes under the profile dir even with no write restrictions', () => {
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [join(testTmp, 'denied')] },
      writeConfig: undefined,
    })
    const profile = readFileSync(
      extractProfileFilePath(wrappedCommand)!,
      'utf8',
    )
    expect(profile).toContain('(allow file-write*)')
    expect(profile).toContain(
      `(deny file-write*\n  (subpath ${JSON.stringify(getMacOSProfileFileDir())})`,
    )
  })

  it('writes unique files per command', () => {
    const wrap = () =>
      extractProfileFilePath(
        wrapCommandWithSandboxMacOS({
          command: 'echo hello',
          needsNetworkRestriction: false,
          readConfig: undefined,
          writeConfig: WRITE_CONFIG,
        }),
      )
    expect(wrap()).not.toBe(wrap())
  })

  it('sweeps stale profile files but keeps fresh and foreign files', () => {
    const profileDir = getMacOSProfileFileDir()
    mkdirSync(profileDir, { recursive: true, mode: 0o700 })

    const staleName = `srt-123-${Date.now() - 10 * 60 * 1000}-abcdef0123456789.sb`
    const freshName = `srt-123-${Date.now() - 60 * 1000}-abcdef0123456789.sb`
    const foreignName = 'unrelated.txt'
    writeFileSync(join(profileDir, staleName), 'stale')
    writeFileSync(join(profileDir, freshName), 'fresh')
    writeFileSync(join(profileDir, foreignName), 'foreign')

    writeMacOSProfileFile('(version 1)')

    const names = readdirSync(profileDir)
    expect(names).not.toContain(staleName)
    expect(names).toContain(freshName)
    expect(names).toContain(foreignName)
  })

  it('falls back to inline -p when the profile dir is not exclusively ours', () => {
    const profileDir = getMacOSProfileFileDir()
    mkdirSync(profileDir, { recursive: true })
    chmodSync(profileDir, 0o777) // group/other-writable → ownership check fails

    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'echo hello',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: WRITE_CONFIG,
    })

    expect(extractProfileFilePath(wrappedCommand)).toBeUndefined()
    const args = shellquote.parse(wrappedCommand)
    const pIndex = args.indexOf('-p')
    expect(pIndex).toBeGreaterThan(-1)
    expect(args[pIndex + 1] as string).toContain('(version 1)')
    expect(readdirSync(profileDir)).toEqual([])
  })

  describe.if(isMacOS)('live sandbox-exec', () => {
    it('executes the wrapped command via -f', () => {
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: 'echo profile-file-works',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testTmp], denyWithinAllow: [] },
      })
      expect(extractProfileFilePath(wrappedCommand)).toBeDefined()

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      expect(result.status).toBe(0)
      expect(result.stdout).toContain('profile-file-works')
    })

    it('blocks a sandboxed command from writing into the profile dir', () => {
      const profileDir = getMacOSProfileFileDir()
      // testTmp (which contains profileDir) is write-allowed, so only the
      // profile-dir deny rule stands between the sandboxed command and the
      // next command's policy file.
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "(version 1)(allow default)" > ${profileDir}/srt-evil.sb`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testTmp], denyWithinAllow: [] },
      })

      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      expect(result.status).not.toBe(0)
      expect(existsSync(join(profileDir, 'srt-evil.sb'))).toBe(false)
    })

    it('blocks overwriting an existing profile file', () => {
      // Wrap once so a real profile file exists, then try to clobber it from
      // inside a second sandboxed command.
      const first = wrapCommandWithSandboxMacOS({
        command: 'echo hi',
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testTmp], denyWithinAllow: [] },
      })
      const target = extractProfileFilePath(first)!

      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo "(version 1)(allow default)" > ${target}`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testTmp], denyWithinAllow: [] },
      })
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      expect(result.status).not.toBe(0)
      expect(readFileSync(target, 'utf8')).toContain('(deny default')
    })

    it('sanity: the same write succeeds outside the profile dir', () => {
      const wrappedCommand = wrapCommandWithSandboxMacOS({
        command: `echo ok > ${testTmp}/allowed.txt`,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [testTmp], denyWithinAllow: [] },
      })
      const result = spawnSync(wrappedCommand, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      expect(result.status).toBe(0)
      expect(existsSync(join(testTmp, 'allowed.txt'))).toBe(true)
    })
  })
})
