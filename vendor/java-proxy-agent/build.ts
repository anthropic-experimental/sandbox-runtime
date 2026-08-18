/**
 * Build the JVM proxy agent (vendor/java-proxy-agent-src) and embed it as
 * base64 in src/sandbox/java-proxy-agent-jar.ts.
 *
 * Unlike the seccomp/srt-win helpers the output is committed: it is a few
 * KB of text, needs no per-arch build, and embedding it means consumers
 * that bundle srt into a single file (no `vendor/` on disk) still get it.
 * The jar is assembled here rather than with `jar(1)` so the bytes are
 * reproducible: STORED entries, fixed timestamps, sorted names.
 *
 *   npm run build:java-agent        (needs `javac` >= 9 on PATH or JAVA_HOME)
 */
import { spawnSync } from 'node:child_process'
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { run } from '../build-common.js'

const here = dirname(fileURLToPath(import.meta.url))
const SRC = join(here, '..', 'java-proxy-agent-src')
const OUT_TS = join(
  here,
  '..',
  '..',
  'src',
  'sandbox',
  'java-proxy-agent-jar.ts',
)
const AGENT_CLASS = 'com.anthropic.srt.ProxyAgent'

const javac = process.env.JAVA_HOME
  ? join(process.env.JAVA_HOME, 'bin', 'javac')
  : 'javac'
const version = spawnSync(javac, ['-version'], { encoding: 'utf8' })
if (version.error) {
  console.error(
    `java-proxy-agent build: cannot run ${javac}: ${version.error.message}`,
  )
  process.exit(1)
}

function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...walk(p))
    else out.push(p)
  }
  return out
}

const classesDir = mkdtempSync(join(tmpdir(), 'srt-java-agent-'))
try {
  const sources = walk(SRC).filter(f => f.endsWith('.java'))
  // --release 8: the agent runs inside whatever JVM the sandboxed tool
  // brings, and Java 8 is still common in build tooling.
  run([
    javac,
    '--release',
    '8',
    '-Xlint:all,-options',
    '-Werror',
    '-g:none',
    '-d',
    classesDir,
    ...sources,
  ])

  const entries: Array<{ name: string; data: Buffer }> = [
    {
      name: 'META-INF/MANIFEST.MF',
      data: Buffer.from(
        [
          'Manifest-Version: 1.0',
          `Premain-Class: ${AGENT_CLASS}`,
          `Agent-Class: ${AGENT_CLASS}`,
          '',
          '',
        ].join('\r\n'),
      ),
    },
  ]
  for (const f of walk(classesDir).sort()) {
    entries.push({
      name: relative(classesDir, f).split(sep).join('/'),
      data: readFileSync(f),
    })
  }
  const jar = buildStoredZip(entries)

  const banner =
    '// GENERATED FILE — do not edit. Rebuild with `npm run build:java-agent`.\n' +
    '// Source: vendor/java-proxy-agent-src/, built by vendor/java-proxy-agent/build.ts\n' +
    `// Compiler: ${(version.stderr || version.stdout).trim()}\n`
  const b64 = jar.toString('base64')
  const lines: string[] = []
  for (let i = 0; i < b64.length; i += 76)
    lines.push(`  '${b64.slice(i, i + 76)}',`)
  writeFileSync(
    OUT_TS,
    banner +
      '\n' +
      '/** srt-proxy-agent.jar (STORED zip, reproducible), base64. */\n' +
      'export const JAVA_PROXY_AGENT_JAR_BASE64: string = [\n' +
      lines.join('\n') +
      "\n].join('')\n" +
      '\n' +
      `export const JAVA_PROXY_AGENT_JAR_BYTES = ${jar.length}\n`,
  )
  console.log(
    `wrote ${OUT_TS} (${jar.length} bytes jar, ${entries.length} entries)`,
  )
} finally {
  rmSync(classesDir, { recursive: true, force: true })
}

// ---------------------------------------------------------------------------
// Minimal ZIP writer: STORED (no compression), fixed DOS timestamp, no extra
// fields. Enough for the JVM's jar reader and byte-for-byte reproducible.

function crc32(buf: Buffer): number {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i]
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1
  }
  return (c ^ 0xffffffff) >>> 0
}

function buildStoredZip(
  entries: Array<{ name: string; data: Buffer }>,
): Buffer {
  // 1980-01-01 00:00:00 in DOS date/time (the ZIP epoch).
  const DOS_TIME = 0
  const DOS_DATE = (1 << 5) | 1
  const locals: Buffer[] = []
  const centrals: Buffer[] = []
  let offset = 0
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, 'utf8')
    const crc = crc32(data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(10, 4) // version needed
    local.writeUInt16LE(0, 6) // flags
    local.writeUInt16LE(0, 8) // method: STORED
    local.writeUInt16LE(DOS_TIME, 10)
    local.writeUInt16LE(DOS_DATE, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBuf.length, 26)
    local.writeUInt16LE(0, 28)
    locals.push(local, nameBuf, data)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(10, 4) // version made by
    central.writeUInt16LE(10, 6) // version needed
    central.writeUInt16LE(0, 8)
    central.writeUInt16LE(0, 10)
    central.writeUInt16LE(DOS_TIME, 12)
    central.writeUInt16LE(DOS_DATE, 14)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(data.length, 20)
    central.writeUInt32LE(data.length, 24)
    central.writeUInt16LE(nameBuf.length, 28)
    central.writeUInt16LE(0, 30) // extra len
    central.writeUInt16LE(0, 32) // comment len
    central.writeUInt16LE(0, 34) // disk
    central.writeUInt16LE(0, 36) // internal attrs
    central.writeUInt32LE(0, 38) // external attrs
    central.writeUInt32LE(offset, 42)
    centrals.push(central, nameBuf)
    offset += local.length + nameBuf.length + data.length
  }
  const cdSize = centrals.reduce((n, b) => n + b.length, 0)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(0, 4)
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(cdSize, 12)
  eocd.writeUInt32LE(offset, 16)
  eocd.writeUInt16LE(0, 20)
  return Buffer.concat([...locals, ...centrals, eocd])
}
