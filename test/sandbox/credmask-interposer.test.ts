import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  CREDMASK_ENTRY_SEP,
  CREDMASK_FIELD_SEP,
  CREDMASK_MAP_ENV,
  encodeCredmaskMap,
  getCredmaskDylibPath,
} from '../../src/sandbox/credmask-interposer.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { quote } from '../../src/utils/shell-quote.js'

/**
 * Unit tests for the macOS credential-mask interposer plumbing: the
 * CREDMASK_MAP encoding, the dylib resolver, and how
 * wrapCommandWithSandboxMacOS injects DYLD_INSERT_LIBRARIES. All
 * platform-agnostic (string assertions on the wrapped command / profile;
 * no sandbox-exec is executed), so they run on every CI leg. The actual
 * redirect behaviour is proven in macos-credmask-interposer.test.ts.
 */

const FIXTURE_DIR = join(tmpdir(), 'srt-credmask-interposer-' + Date.now())
// A stand-in dylib: the wrapper only checks existence, never loads it.
const DYLIB = join(FIXTURE_DIR, 'libcredmask.dylib')
const STORE_DIR = join(FIXTURE_DIR, 'store')
const FAKE = join(STORE_DIR, '0.fake')
const REAL = join(FIXTURE_DIR, 'gh-token')
const NO_DYLIB = join(FIXTURE_DIR, 'does-not-exist.dylib')

beforeAll(() => {
  mkdirSync(STORE_DIR, { recursive: true })
  writeFileSync(DYLIB, 'not a real dylib')
  writeFileSync(FAKE, 'SENTINEL')
  writeFileSync(REAL, 'real-secret')
})

afterAll(() => {
  rmSync(FIXTURE_DIR, { recursive: true, force: true })
})

describe('encodeCredmaskMap', () => {
  test('single bind: real and fake joined by the field separator', () => {
    expect(encodeCredmaskMap([{ realPath: REAL, fakePath: FAKE }])).toBe(
      REAL + CREDMASK_FIELD_SEP + FAKE,
    )
  })

  test('multiple binds joined by the entry separator', () => {
    const map = encodeCredmaskMap([
      { realPath: '/a/tok', fakePath: '/s/0.fake' },
      { realPath: '/b/tok', fakePath: '/s/1.fake' },
    ])
    expect(map).toBe(
      '/a/tok' +
        CREDMASK_FIELD_SEP +
        '/s/0.fake' +
        CREDMASK_ENTRY_SEP +
        '/b/tok' +
        CREDMASK_FIELD_SEP +
        '/s/1.fake',
    )
  })

  test('paths with spaces, quotes, and colons pass through verbatim', () => {
    const real = "/Users/o'brien/My Tokens/gh:token"
    const fake = '/store/with space/0.fake'
    expect(encodeCredmaskMap([{ realPath: real, fakePath: fake }])).toBe(
      real + CREDMASK_FIELD_SEP + fake,
    )
  })

  test('an entry containing a separator byte is skipped; siblings survive', () => {
    const map = encodeCredmaskMap([
      { realPath: `/evil${CREDMASK_FIELD_SEP}path`, fakePath: '/s/0.fake' },
      { realPath: '/ok/tok', fakePath: '/s/1.fake' },
      { realPath: '/also-evil', fakePath: `/s${CREDMASK_ENTRY_SEP}2.fake` },
    ])
    expect(map).toBe('/ok/tok' + CREDMASK_FIELD_SEP + '/s/1.fake')
  })

  test('an entry containing NUL is skipped (env vars cannot carry NUL)', () => {
    expect(
      encodeCredmaskMap([{ realPath: '/a\x00b', fakePath: '/s/0.fake' }]),
    ).toBe('')
  })
})

describe('getCredmaskDylibPath', () => {
  test('explicit existing path is returned as-is', () => {
    expect(getCredmaskDylibPath(DYLIB)).toBe(DYLIB)
  })

  test('explicit missing path returns null with no fallback', () => {
    // Deterministic even on a machine where the vendor dylib is built:
    // an explicit override never falls back to the standard locations.
    expect(getCredmaskDylibPath(NO_DYLIB)).toBeNull()
  })
})

describe('wrapCommandWithSandboxMacOS interposer injection', () => {
  function wrap(command: string, dylibPath: string = DYLIB) {
    return wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      maskedFileBinds: [{ realPath: REAL, fakePath: FAKE }],
      maskedFileStoreDir: STORE_DIR,
      credmaskDylibPath: dylibPath,
    })
  }

  test('DYLD vars are exported inside the shell -c string, not the env prefix', () => {
    const wrapped = wrap(`cat ${REAL}`)
    // macOS purges DYLD_* when loading the SIP-protected sandbox-exec,
    // so anything in the `env …` prefix would be lost. The prefix ends
    // at sandbox-exec; the -c payload follows it.
    const sandboxExecIdx = wrapped.indexOf('/usr/bin/sandbox-exec')
    expect(sandboxExecIdx).toBeGreaterThan(-1)
    const envPrefix = wrapped.slice(0, sandboxExecIdx)
    expect(envPrefix).not.toContain('DYLD_INSERT_LIBRARIES')
    expect(envPrefix).not.toContain(CREDMASK_MAP_ENV)

    const payload = wrapped.slice(sandboxExecIdx)
    expect(payload).toContain('export')
    expect(payload).toContain('DYLD_INSERT_LIBRARIES=')
    expect(payload).toContain(`${CREDMASK_MAP_ENV}=`)
    // The user command runs after the exports in the same -c string.
    expect(payload.indexOf(`cat ${REAL}`)).toBeGreaterThan(
      payload.indexOf('DYLD_INSERT_LIBRARIES='),
    )
  })

  test('CREDMASK_MAP carries the encoded binds', () => {
    const wrapped = wrap('true')
    expect(wrapped).toContain(REAL + CREDMASK_FIELD_SEP + FAKE)
  })

  test('SBPL still read-denies the real path (security boundary)', () => {
    const wrapped = wrap('true')
    expect(wrapped).toContain('(deny file-read*')
    expect(wrapped).toContain(JSON.stringify(realpathSync(REAL)))
  })

  test('profile allows reading the store dir and dylib, denies writing the store', () => {
    const wrapped = wrap('true')
    const store = JSON.stringify(realpathSync(STORE_DIR))
    expect(wrapped).toContain(`(allow file-read* (subpath ${store}))`)
    expect(wrapped).toContain(`(deny file-write*`)
    expect(wrapped).toContain(
      `(allow file-read* (literal ${JSON.stringify(realpathSync(DYLIB))}))`,
    )
    // The write-deny targets the store dir specifically.
    const denyWriteIdx = wrapped.lastIndexOf('(deny file-write*')
    expect(wrapped.indexOf(`(subpath ${store})`, denyWriteIdx)).toBeGreaterThan(
      -1,
    )
  })

  test('storeDirs fall back to the fake paths’ parent dirs when maskedFileStoreDir is omitted', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      maskedFileBinds: [{ realPath: REAL, fakePath: FAKE }],
      credmaskDylibPath: DYLIB,
    })
    expect(wrapped).toContain(
      `(allow file-read* (subpath ${JSON.stringify(realpathSync(dirname(FAKE)))}))`,
    )
  })

  test('dylib absent: degrade to deny, no DYLD injection, fake path unused', () => {
    const wrapped = wrap(`cat ${REAL}`, NO_DYLIB)
    expect(wrapped).not.toContain('DYLD_INSERT_LIBRARIES')
    expect(wrapped).not.toContain(CREDMASK_MAP_ENV)
    expect(wrapped).not.toContain(FAKE)
    expect(wrapped).not.toContain('export')
    // The security boundary is unchanged.
    expect(wrapped).toContain('(deny file-read*')
    expect(wrapped).toContain(JSON.stringify(realpathSync(REAL)))
  })

  test('a command with quotes and spaces survives the extra quoting layer', () => {
    const command = `echo 'a b' && awk '!seen[$0]++' ${REAL}`
    const wrapped = wrap(command)
    // The original command text must appear inside the -c payload after
    // outer-quote unescaping; assert on the distinctive fragments that
    // would corrupt first if quoting broke.
    expect(wrapped).toContain('awk ')
    expect(wrapped).toContain('!seen[$0]++')
  })

  test('the export assignments round-trip through a real shell', () => {
    // Proof of the quoting mechanics used for the inner
    // `export …; <command>` string: a map with spaces and quotes must
    // reach the child process byte-identical. A stand-in name replaces
    // DYLD_INSERT_LIBRARIES here — exporting a real DYLD_* var pointing
    // at this garbage fixture makes dyld abort any non-SIP shell it
    // spawns, and the quoting under test is name-agnostic.
    const map = encodeCredmaskMap([
      {
        realPath: "/Users/o'brien/My Tokens/token",
        fakePath: '/store/with space/0.fake',
      },
    ])
    const assignments = quote([
      `NOT_DYLD_INSERT_LIBRARIES=${DYLIB}`,
      `${CREDMASK_MAP_ENV}=${map}`,
    ])
    const r = spawnSync(
      'bash',
      ['-c', `export ${assignments}; printenv ${CREDMASK_MAP_ENV}`],
      { encoding: 'utf8' },
    )
    expect(r.status).toBe(0)
    expect(r.stdout).toBe(map + '\n')
  })
})
