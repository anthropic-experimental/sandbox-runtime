/**
 * Build libcredmask.dylib — the macOS DYLD interposer for credential file
 * masking — from vendor/credmask-src/interpose.c.
 *
 * Run via `npm run build:credmask` on a Mac (needs clang from the Xcode
 * Command Line Tools). The default build produces a UNIVERSAL dylib
 * (arm64 + x86_64) at vendor/credmask/libcredmask.dylib; that is the
 * artifact the release workflow builds on a macOS runner and bundles into
 * the published package (same story as the seccomp binaries: never
 * committed to git, always produced by CI or a local Mac).
 *
 * `--native` builds for the host architecture only. CI's macOS test legs
 * use this so the integration tests can compile the interposer from
 * source without needing both-arch toolchains.
 */
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { run } from '../build-common.js'

if (process.platform !== 'darwin') {
  console.error(`credmask build: macOS only (running on ${process.platform})`)
  process.exit(1)
}

const here = dirname(fileURLToPath(import.meta.url))
const SRC = join(here, '..', 'credmask-src', 'interpose.c')
const OUT = join(here, 'libcredmask.dylib')

const native = process.argv.includes('--native')
const archFlags = native
  ? [] // host arch only — fast path for CI test-leg compiles
  : ['-arch', 'arm64', '-arch', 'x86_64']

run([
  'clang',
  '-dynamiclib',
  ...archFlags,
  '-O2',
  '-Wall',
  '-Wextra',
  '-Werror',
  // Broad floor so the dylib loads into anything a supported host runs.
  '-mmacosx-version-min=11.0',
  '-o',
  OUT,
  SRC,
])

if (!existsSync(OUT)) {
  console.error(`credmask build: expected output missing: ${OUT}`)
  process.exit(1)
}
console.log(`built ${OUT}${native ? ' (host arch only)' : ' (universal)'}`)
