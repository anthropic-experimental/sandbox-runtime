import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

if (process.platform !== 'linux') {
  console.error('seccomp build: Linux only')
  process.exit(1)
}

const HERE = dirname(fileURLToPath(import.meta.url))
const SRC = join(HERE, '..', 'seccomp-src')

const nodeArchToDir: Record<string, string> = { x64: 'x64', arm64: 'arm64' }
const arch = nodeArchToDir[process.arch]
if (!arch) {
  console.error('seccomp build: unsupported arch ' + process.arch)
  process.exit(1)
}
const OUT = join(HERE, arch)

function run(argv: string[]): void {
  const [cmd, ...args] = argv
  const r = spawnSync(cmd, args, { stdio: 'inherit' })
  if (r.status !== 0) {
    console.error(argv.join(' ') + ' exited ' + (r.status ?? r.signal))
    process.exit(1)
  }
}

function toCArray(bytes: Buffer): string {
  const hex = Array.from(bytes, b => '0x' + b.toString(16).padStart(2, '0'))
  const lines: string[] = []
  for (let i = 0; i < hex.length; i += 8) {
    lines.push('    ' + hex.slice(i, i + 8).join(', ') + ',')
  }
  return lines.join('\n')
}

mkdirSync(OUT, { recursive: true })

const cflags = ['-static', '-O2', '-Wall', '-Wextra']

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

console.log('built ' + join(OUT, 'apply-seccomp'))
