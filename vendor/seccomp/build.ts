import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { run, setup } from '../build-common.js'

const { SRC, OUT } = setup({
  importMetaUrl: import.meta.url,
  requirePlatform: 'linux',
  srcDirName: 'seccomp-src',
})

function toCArray(bytes: Buffer): string {
  const hex = Array.from(bytes, b => '0x' + b.toString(16).padStart(2, '0'))
  const lines: string[] = []
  for (let i = 0; i < hex.length; i += 8) {
    lines.push('    ' + hex.slice(i, i + 8).join(', ') + ',')
  }
  return lines.join('\n')
}

// Hardening: netns-config runs HOST-side; stack protector + FORTIFY are
// cheap insurance on all three binaries (static PIE is not portable
// across old glibc, so RELRO/PIE stay distro-default).
const cflags = [
  '-static',
  '-O2',
  '-Wall',
  '-Wextra',
  '-fstack-protector-strong',
  '-D_FORTIFY_SOURCE=2',
]

const gen = join(OUT, 'seccomp-unix-block')
run([
  'gcc',
  ...cflags,
  '-o',
  gen,
  join(SRC, 'seccomp-unix-block.c'),
  '-lseccomp',
])

const bpf: Record<string, Buffer> = {}
for (const target of ['x86_64', 'aarch64']) {
  const tmp = join(OUT, target + '.bpf')
  run([gen, tmp, target])
  bpf[target] = readFileSync(tmp)
  rmSync(tmp)
}
rmSync(gen)

const header = join(OUT, 'unix-block-bpf.h')
writeFileSync(
  header,
  '#if defined(__x86_64__)\n' +
    'static const unsigned char unix_block_bpf[] = {\n' +
    toCArray(bpf.x86_64) +
    '\n};\n' +
    '#elif defined(__aarch64__)\n' +
    'static const unsigned char unix_block_bpf[] = {\n' +
    toCArray(bpf.aarch64) +
    '\n};\n' +
    '#else\n' +
    '#error "unsupported architecture for unix-block BPF filter"\n' +
    '#endif\n',
)

run([
  'gcc',
  ...cflags,
  '-I',
  OUT,
  '-o',
  join(OUT, 'apply-seccomp'),
  join(SRC, 'apply-seccomp.c'),
])
run(['strip', join(OUT, 'apply-seccomp')])
rmSync(header)

run([
  'gcc',
  ...cflags,
  '-o',
  join(OUT, 'netns-config'),
  join(SRC, 'netns-config.c'),
])
run(['strip', join(OUT, 'netns-config')])

console.log('built ' + join(OUT, 'apply-seccomp'))
console.log('built ' + join(OUT, 'netns-config'))
