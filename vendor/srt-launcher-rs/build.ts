/* Build the vendored static `srt-launcher` helper binary.
 *
 * srt-launcher replaces bwrap, apply-seccomp, and socat with a single binary;
 * see vendor/srt-launcher-rs/src/run.rs for the architecture comment. The BPF
 * filter that blocks socket(AF_UNIX, ...) + io_uring is generated at build
 * time by the existing C generator (vendor/seccomp-src/seccomp-unix-block.c)
 * and baked into the Rust binary via include_bytes!().
 *
 * Usage: bun vendor/srt-launcher-rs/build.ts
 *
 * Prerequisites: rustup with the *-unknown-linux-musl target for the build
 * arch, and gcc + libseccomp-dev for the BPF generator.
 */
import { spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

if (process.platform !== 'linux') {
  console.error('srt-launcher build: Linux only')
  process.exit(1)
}

const HERE = dirname(fileURLToPath(import.meta.url))
const SECCOMP_SRC = join(HERE, '..', 'seccomp-src')
const VENDOR_OUT = join(HERE, '..', 'srt-launcher')

const archMap: Record<
  string,
  { dir: string; rustTarget: string; bpf: string }
> = {
  x64: { dir: 'x64', rustTarget: 'x86_64-unknown-linux-musl', bpf: 'x86_64' },
  arm64: {
    dir: 'arm64',
    rustTarget: 'aarch64-unknown-linux-musl',
    bpf: 'aarch64',
  },
}
const arch = archMap[process.arch]
if (!arch) {
  console.error('srt-launcher build: unsupported arch ' + process.arch)
  process.exit(1)
}

function run(argv: string[], opts?: { cwd?: string }): void {
  const [cmd, ...args] = argv
  const r = spawnSync(cmd, args, { stdio: 'inherit', cwd: opts?.cwd })
  if (r.status !== 0) {
    console.error(argv.join(' ') + ' exited ' + (r.status ?? r.signal))
    process.exit(1)
  }
}

// 1. Regenerate the BPF blobs (both arches; cheap and keeps them in sync).
const gen = join(HERE, 'bpf', 'gen')
mkdirSync(join(HERE, 'bpf'), { recursive: true })
run([
  'gcc',
  '-O2',
  '-o',
  gen,
  join(SECCOMP_SRC, 'seccomp-unix-block.c'),
  '-lseccomp',
])
for (const [, m] of Object.entries(archMap)) {
  run([gen, join(HERE, 'bpf', `${m.bpf}.bpf`), m.bpf])
}
rmSync(gen)

// 2. cargo build for the host arch. Cross-compiling arm64 from x64 (or vice
//    versa) needs a cross-musl linker; the npm publish workflow runs this
//    once per arch on native runners instead.
run(['cargo', 'build', '--release', '--target', arch.rustTarget], { cwd: HERE })

// 3. Copy out to vendor/srt-launcher/<arch>/srt-launcher (the path the TS
//    side resolves at runtime).
const out = join(VENDOR_OUT, arch.dir)
mkdirSync(out, { recursive: true })
copyFileSync(
  join(HERE, 'target', arch.rustTarget, 'release', 'srt-launcher'),
  join(out, 'srt-launcher'),
)
console.log('built ' + join(out, 'srt-launcher'))
