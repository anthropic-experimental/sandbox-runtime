import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  MaskedFileStore,
  buildMaskedFileBinds,
} from '../../src/sandbox/credential-mask-files.js'
import { SentinelRegistry } from '../../src/sandbox/credential-sentinel.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * macOS end-to-end tests for the credential-mask DYLD interposer.
 *
 * beforeAll compiles libcredmask.dylib from source (vendor/credmask/
 * build.ts --native) plus a tiny NON-SIP probe binary. The probe is the
 * load-bearing trick: every convenient reader on macOS (/bin/cat,
 * /bin/bash and its builtins, /usr/bin/stat, …) is SIP-protected, and
 * dyld purges DYLD_INSERT_LIBRARIES when loading a SIP binary — so
 * system tools can never demonstrate the interposed (positive) path.
 * A just-compiled binary has no SIP protection, loads the interposer,
 * and shows the sentinel; /bin/cat doubles as the negative control
 * proving the SBPL deny still bites anything that bypasses the shim.
 *
 * Gated on clang availability so the suite skips cleanly on a Mac
 * without the Xcode Command Line Tools.
 */

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const DYLIB = join(ROOT, 'vendor', 'credmask', 'libcredmask.dylib')

const clangAvailable = isMacOS && spawnSync('clang', ['--version']).status === 0

if (isMacOS && !clangAvailable) {
  console.warn(
    '[macos-credmask-interposer] clang not available — skipping ' +
      'interposer integration tests (install the Xcode Command Line Tools)',
  )
}

describe.if(isMacOS && clangAvailable)('macOS credmask interposer', () => {
  // tmpdir() is /var/folders/… on macOS — a symlink into /private/var.
  // The host-side map keys are realpath'd and the interposer matches
  // exactly, so the probe paths must use the canonical /private form.
  const TEST_DIR_NAME = 'srt-credmask-macos-' + Date.now()
  const TEST_DIR = join(realpathSync(tmpdir()), TEST_DIR_NAME)
  const SECRET_FILE = join(TEST_DIR, 'gh-token')
  // The un-canonicalized /var spelling of the same file, covered by the
  // alias entries encodeCredmaskMap emits for /private symlink roots.
  const SECRET_FILE_ALIAS = join(tmpdir(), TEST_DIR_NAME, 'gh-token')
  const SECRET_CONTENT = 'ghp_macos_real_secret_0123456789'
  const CONTROL_FILE = join(TEST_DIR, 'control.txt')
  const PROBE = join(TEST_DIR, 'credmask-probe')

  const registry = new SentinelRegistry()
  const store = new MaskedFileStore()
  let binds: Array<{ realPath: string; fakePath: string }>
  let sentinel: string

  /**
   * Minimal non-SIP reader driving each hooked entry point. `read` uses
   * fopen/fread, `openread` uses open(2)/read(2), plus stat / access /
   * realpath modes.
   */
  const PROBE_SRC = `
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 3) return 2;
  const char *mode = argv[1], *path = argv[2];
  if (strcmp(mode, "read") == 0) {
    FILE *f = fopen(path, "r");
    if (f == NULL) { perror("fopen"); return 1; }
    char buf[65536];
    size_t n = fread(buf, 1, sizeof buf, f);
    fwrite(buf, 1, n, stdout);
    fclose(f);
    return 0;
  }
  if (strcmp(mode, "openread") == 0) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    char buf[65536];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n < 0) { perror("read"); return 1; }
    fwrite(buf, 1, (size_t)n, stdout);
    close(fd);
    return 0;
  }
  if (strcmp(mode, "stat") == 0) {
    struct stat st;
    if (stat(path, &st) != 0) { perror("stat"); return 1; }
    printf("%lld\\n", (long long)st.st_size);
    return 0;
  }
  if (strcmp(mode, "access") == 0) {
    return access(path, R_OK) == 0 ? 0 : 1;
  }
  if (strcmp(mode, "realpath") == 0) {
    char out[PATH_MAX];
    if (realpath(path, out) == NULL) { perror("realpath"); return 1; }
    printf("%s\\n", out);
    return 0;
  }
  return 2;
}
`

  function wrap(command: string, dylibPath: string = DYLIB): string {
    return wrapCommandWithSandboxMacOS({
      command,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: [TEST_DIR, '/tmp'], denyWithinAllow: [] },
      maskedFileBinds: binds,
      maskedFileStoreDir: store.dirPath,
      credmaskDylibPath: dylibPath,
    })
  }

  function runInSandbox(wrappedCommand: string) {
    return spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 30000,
    })
  }

  beforeAll(() => {
    // Build the interposer from source for the host arch. process.execPath
    // is the running bun binary.
    const build = spawnSync(
      process.execPath,
      [join(ROOT, 'vendor', 'credmask', 'build.ts'), '--native'],
      { cwd: ROOT, encoding: 'utf8' },
    )
    if (build.status !== 0 || !existsSync(DYLIB)) {
      throw new Error(
        `build:credmask --native failed:\n${build.stdout}\n${build.stderr}`,
      )
    }

    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(SECRET_FILE, SECRET_CONTENT)
    writeFileSync(CONTROL_FILE, 'control-ok')
    writeFileSync(join(TEST_DIR, 'probe.c'), PROBE_SRC)
    const cc = spawnSync(
      'clang',
      ['-O0', '-o', PROBE, join(TEST_DIR, 'probe.c')],
      { encoding: 'utf8' },
    )
    if (cc.status !== 0) {
      throw new Error(`probe compile failed:\n${cc.stdout}\n${cc.stderr}`)
    }

    const built = buildMaskedFileBinds(
      [{ path: SECRET_FILE, mode: 'mask' }],
      ['api.github.com'],
      registry,
      store,
    )
    binds = built.binds
    expect(binds).toHaveLength(1)
    // The fake file IS the sentinel in whole-file mode.
    sentinel = readFileSync(binds[0]!.fakePath, 'utf8')
  })

  afterAll(() => {
    store.dispose()
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  test('fopen/fread of the masked file returns the sentinel, not EPERM or the secret', () => {
    const r = runInSandbox(wrap(`${PROBE} read ${SECRET_FILE}`))
    expect(r.status).toBe(0)
    expect(r.stdout).toBe(sentinel)
    expect(r.stdout).not.toContain(SECRET_CONTENT)
  })

  test('open(2)/read(2) of the masked file returns the sentinel', () => {
    const r = runInSandbox(wrap(`${PROBE} openread ${SECRET_FILE}`))
    expect(r.status).toBe(0)
    expect(r.stdout).toBe(sentinel)
  })

  test('a SIP binary (/bin/cat) bypasses the interposer and hits the SBPL deny', () => {
    // dyld strips DYLD_INSERT_LIBRARIES when loading SIP-protected
    // /bin/cat, so it reads the REAL path — which the profile denies.
    // Fail-closed: EPERM, never the secret, never the sentinel.
    const r = runInSandbox(wrap(`/bin/cat ${SECRET_FILE}`))
    expect(r.status).not.toBe(0)
    expect(r.stdout).not.toContain(SECRET_CONTENT)
    expect(r.stdout).not.toContain(sentinel)
  })

  test('stat on the masked path succeeds and reports the fake (sentinel) size', () => {
    const r = runInSandbox(wrap(`${PROBE} stat ${SECRET_FILE}`))
    expect(r.status).toBe(0)
    expect(r.stdout.trim()).toBe(String(Buffer.byteLength(sentinel)))
  })

  test('access(R_OK) on the masked path succeeds', () => {
    const r = runInSandbox(wrap(`${PROBE} access ${SECRET_FILE}`))
    expect(r.status).toBe(0)
  })

  test('realpath on the masked path returns the canonical real path, not the fake', () => {
    const r = runInSandbox(wrap(`${PROBE} realpath ${SECRET_FILE}`))
    expect(r.status).toBe(0)
    expect(r.stdout.trim()).toBe(binds[0]!.realPath)
    expect(r.stdout).not.toContain(store.dirPath!)
  })

  test('the un-canonicalized /var alias of the masked path is redirected too', () => {
    const r = runInSandbox(wrap(`${PROBE} read ${SECRET_FILE_ALIAS}`))
    expect(r.status).toBe(0)
    expect(r.stdout).toBe(sentinel)
    expect(r.stdout).not.toContain(SECRET_CONTENT)
  })

  test('a relative path to the masked file is redirected too', () => {
    const dir = dirname(binds[0]!.realPath)
    const name = basename(binds[0]!.realPath)
    const r = runInSandbox(wrap(`cd ${dir} && ${PROBE} read ${name}`))
    expect(r.status).toBe(0)
    expect(r.stdout).toBe(sentinel)
  })

  test('non-masked sibling files are unaffected', () => {
    const r = runInSandbox(wrap(`${PROBE} read ${CONTROL_FILE}`))
    expect(r.status).toBe(0)
    expect(r.stdout).toBe('control-ok')
  })

  test('the fake store is immutable inside the sandbox', () => {
    const fake = binds[0]!.fakePath
    const r = runInSandbox(wrap(`sh -c 'echo pwned > ${fake}'`))
    expect(r.status).not.toBe(0)
    expect(readFileSync(fake, 'utf8')).toBe(sentinel)
  })

  test('without the dylib, masking degrades to deny (today’s behaviour)', () => {
    const noDylib = join(TEST_DIR, 'missing.dylib')
    const r = runInSandbox(wrap(`${PROBE} read ${SECRET_FILE}`, noDylib))
    expect(r.status).not.toBe(0)
    expect(r.stdout).not.toContain(SECRET_CONTENT)
    expect(r.stdout).not.toContain(sentinel)
  })

  test('the wrapped command never contains the real secret', () => {
    const wrapped = wrap(`${PROBE} read ${SECRET_FILE}`)
    expect(wrapped).not.toContain(SECRET_CONTENT)
  })
})
