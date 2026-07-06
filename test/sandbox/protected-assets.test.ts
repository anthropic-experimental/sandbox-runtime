import { describe, it, expect } from 'bun:test'
import * as fs from 'node:fs'
import { execFileSync } from 'node:child_process'
import { isLinux } from '../helpers/platform.js'
import {
  getTransparentAssetDir,
  getSandboxResolvConfPath,
  getProtectedHelperPath,
  getNetnsConfigBytes,
  writeProtectedTokensFile,
  getProtectedTokensFilePath,
  transparentAssetParentDir,
  checkTransparentDependencies,
} from '../../src/sandbox/transparent-net.js'
import {
  isBlockedResolvedAddress,
  vettedLookup,
} from '../../src/sandbox/parent-proxy.js'

/**
 * Regressions guarded here: the protected asset layer must (a) keep ONE
 * stable dir across the production call order — the historical bug was
 * dir churn that left the actually-used dir un-ro-bound; (b) trust
 * identity AND content — an in-place rewrite keeps the inode; (c) never
 * put the host-executed netns-config on disk at all.
 */
describe.if(isLinux)('protected asset identity', () => {
  it('keeps one stable dir across the production call order', () => {
    // Replay the per-wrap sequence: tokens → deps → resolv → dir(ro-bind)
    // → helper. Every artifact must live in the SAME dir, and a second
    // wrap must not churn it.
    writeProtectedTokensFile({ netns: 'n1', proxy: 'p1' })
    const seq1 = [
      getProtectedTokensFilePath()!,
      getSandboxResolvConfPath(),
      getTransparentAssetDir(),
      getProtectedHelperPath()!,
    ]
    const dir = getTransparentAssetDir()
    for (const p of seq1) {
      expect(p.startsWith(dir)).toBe(true)
    }
    // Second wrap: same dir throughout.
    const seq2 = [
      getProtectedTokensFilePath()!,
      getSandboxResolvConfPath(),
      getTransparentAssetDir(),
      getProtectedHelperPath()!,
    ]
    for (const p of seq2) {
      expect(p.startsWith(dir)).toBe(true)
    }
    // All session dirs live under the pinned parent, which is among the
    // candidates every wrap protects.
    expect(dir.startsWith(transparentAssetParentDir() + '/')).toBe(true)
    expect(fs.lstatSync(transparentAssetParentDir()).isDirectory()).toBe(true)
  })

  it('detects an IN-PLACE rewrite (same inode) of a protected file', () => {
    const helper1 = getProtectedHelperPath()!
    const original = fs.readFileSync(helper1)
    // Same-inode tamper: open for write and modify without replacing.
    fs.chmodSync(helper1, 0o644)
    const fd = fs.openSync(helper1, 'r+')
    fs.writeSync(fd, Buffer.from('EVIL'), 0, 4, 0)
    fs.closeSync(fd)
    // Content verification must reject and re-materialize pristine bytes.
    const helper2 = getProtectedHelperPath()!
    expect(fs.readFileSync(helper2).equals(original)).toBe(true)
    expect(fs.readFileSync(helper2).subarray(0, 4).toString()).not.toBe('EVIL')
  })

  it('never adopts an externally recreated dir', () => {
    const dir1 = getTransparentAssetDir()
    const helperName = getProtectedHelperPath()!.split('/').pop()!
    fs.rmSync(dir1, { recursive: true, force: true })
    fs.mkdirSync(dir1, { mode: 0o700 })
    fs.writeFileSync(`${dir1}/${helperName}`, 'EVIL', { mode: 0o755 })
    try {
      const helper2 = getProtectedHelperPath()!
      const dir2 = getTransparentAssetDir()
      expect(dir2).not.toBe(dir1)
      expect(helper2.startsWith(dir2)).toBe(true)
      expect(fs.readFileSync(helper2).toString()).not.toBe('EVIL')
    } finally {
      fs.rmSync(dir1, { recursive: true, force: true })
    }
  })

  it('netns-config never exists on disk in the asset layer', () => {
    const bytes = getNetnsConfigBytes()
    if (bytes === null) return // vendor binary not built in this checkout
    expect(bytes.length).toBeGreaterThan(1000)
    const dir = getTransparentAssetDir()
    expect(fs.existsSync(`${dir}/netns-config`)).toBe(false)
    // The dependency check reports availability without a disk path.
    const deps = checkTransparentDependencies()
    expect(deps.errors).toEqual([])
  })

  it('re-materializes the tokens file after asset-dir loss', () => {
    const p1 = writeProtectedTokensFile({ netns: 'aaa', proxy: 'bbb' })
    expect(fs.readFileSync(p1, 'utf8')).toBe('netns=aaa\nproxy=bbb\n')
    const dir = getTransparentAssetDir()
    fs.rmSync(dir, { recursive: true, force: true })
    const p2 = getProtectedTokensFilePath()!
    expect(p2).not.toBe(p1)
    expect(fs.readFileSync(p2, 'utf8')).toBe('netns=aaa\nproxy=bbb\n')
  })

  it('rejects token keys/values that could corrupt the file format', () => {
    expect(() => writeProtectedTokensFile({ 'a=b': 'x' })).toThrow()
    expect(() => writeProtectedTokensFile({ a: 'x\ny' })).toThrow()
  })
})

describe.if(isLinux)('session-dir GC (pidns-aware liveness)', () => {
  it("never treats 'unknown' pidns as same-namespace (guard is load-bearing)", () => {
    const parent = transparentAssetParentDir()
    getTransparentAssetDir()
    // A lock recorded by a process whose pidns readlink failed: even if
    // the pid is visible here with a mismatched starttime, the pid
    // number is uninterpretable — must be age-gated, not swept.
    const dir = `${parent}/session-gc-unknownns`
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
    fs.writeFileSync(`${dir}/lock`, `${process.pid} 1 unknown`)
    const own = getTransparentAssetDir()
    fs.rmSync(own, { recursive: true, force: true })
    getTransparentAssetDir() // triggers a sweep
    expect(fs.existsSync(dir)).toBe(true) // fresh + unknown ns: kept
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('refreshes the own lock mtime on wrap activity (age-gate escape)', () => {
    const own = getTransparentAssetDir()
    const lock = `${own}/lock`
    const old = new Date(Date.now() - 8 * 86_400_000)
    fs.utimesSync(lock, old, old)
    getTransparentAssetDir() // fast path refreshes stale lock mtimes
    expect(fs.statSync(lock).mtimeMs).toBeGreaterThan(
      Date.now() - 7 * 86_400_000,
    )
    // Skip direction: a fresh mtime must NOT be churned every wrap
    // (the hourly fstat gate is load-bearing for mtime diagnostics).
    const halfHour = new Date(Date.now() - 30 * 60_000)
    fs.utimesSync(lock, halfHour, halfHour)
    const before = fs.statSync(lock).mtimeMs
    getTransparentAssetDir()
    expect(fs.statSync(lock).mtimeMs).toBe(before)
  })

  it('sweeps provably-dead/recycled same-ns dirs, keeps live and foreign ones', () => {
    const parent = transparentAssetParentDir()
    getTransparentAssetDir() // ensure parent + own session exist
    const stat = fs.readFileSync(`/proc/${process.pid}/stat`, 'utf8')
    const start = stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19]!
    const ns = fs.readlinkSync('/proc/self/ns/pid')
    const mk = (name: string, lock: string) => {
      const d = `${parent}/session-${name}`
      fs.mkdirSync(d, { recursive: true, mode: 0o700 })
      fs.writeFileSync(`${d}/lock`, lock)
      return d
    }
    // live: our pid, our starttime, our pidns
    const live = mk('gc-live', `${process.pid} ${start} ${ns}`)
    // recycled: our pid, WRONG starttime, our pidns → provably recycled
    const recycled = mk('gc-recycled', `${process.pid} 1 ${ns}`)
    // dead: absent pid, our pidns → provably dead → swept immediately
    const dead = mk('gc-dead', `999999999 12345 ${ns}`)
    // foreign: LIVE-elsewhere semantics — our pid + wrong starttime but
    // a DIFFERENT pidns id: the pid number is uninterpretable → kept
    const foreign = mk('gc-foreign', `${process.pid} 1 pid:[999]`)
    // legacy two-field lock: ambiguous → kept while fresh
    const legacy = mk('gc-legacy', `999999999 12345`)
    // non-regular lock (FIFO): the sweep must neither block nor treat
    // it as parseable — fresh dir is age-gated (kept)
    const fifoDir = `${parent}/session-gc-fifo`
    fs.mkdirSync(fifoDir, { recursive: true, mode: 0o700 })
    execFileSync('mkfifo', [`${fifoDir}/lock`])
    // symlinked lock: refused by O_NOFOLLOW → age-gated (kept)
    const linkDir = `${parent}/session-gc-symlink`
    fs.mkdirSync(linkDir, { recursive: true, mode: 0o700 })
    fs.symlinkSync('/dev/zero', `${linkDir}/lock`)

    try {
      const own = getTransparentAssetDir()
      fs.rmSync(own, { recursive: true, force: true })
      getTransparentAssetDir() // triggers sweep

      expect(fs.existsSync(live)).toBe(true)
      expect(fs.existsSync(recycled)).toBe(false)
      expect(fs.existsSync(dead)).toBe(false) // no age-gate wait
      expect(fs.existsSync(foreign)).toBe(true)
      expect(fs.existsSync(legacy)).toBe(true)
      expect(fs.existsSync(fifoDir)).toBe(true) // and the sweep returned
      expect(fs.existsSync(linkDir)).toBe(true)
    } finally {
      for (const d of [
        live,
        recycled,
        dead,
        foreign,
        legacy,
        fifoDir,
        linkDir,
      ]) {
        fs.rmSync(d, { recursive: true, force: true })
      }
    }
  })
})

describe('DNS rebinding guard', () => {
  it('classifies blocked resolved ranges', () => {
    for (const bad of [
      '127.0.0.1',
      '127.9.9.9',
      '0.0.0.0',
      '169.254.169.254',
      '198.18.0.5',
      '198.19.1.1',
      '168.63.129.16', // Azure WireServer (fixed public metadata plane)
      '224.0.0.1',
      '239.255.255.255', // multicast upper bound
      '255.255.255.255',
      '::1',
      '::',
      'fe80::1',
      'ff02::1',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1', // hex-form v4-mapped loopback
      '::ffff:a9fe:a9fe', // hex-form v4-mapped 169.254.169.254
      '64:ff9b::7f00:1', // NAT64 loopback embedding
      '::127.0.0.1', // v4-compatible dotted embedding
      '100.100.100.200', // Alibaba metadata IP
      '100.100.0.1', // Alibaba internal-service /16 (whole block denied)
      'fd00:ec2::254', // AWS IMDSv6 (ULA fc00::/7)
      'fc00::1', // ULA
      'fec0::1', // deprecated site-local
      '2002:7f00:1::1', // 6to4 embedding
      '2001:0:53aa:64c:0:7f00:1:1', // Teredo
      '::7f00:1', // hex v4-compatible loopback
      '0:0:0:0:0:ffff:7f00:1', // fully uncompressed mapped loopback
      '0:0:0:0:0:FFFF:127.0.0.1', // uncompressed + dotted + case
      'FEC0::1', // case
      'not:a:valid::v6::x', // unparseable v6 → fail closed
      '::ffff:0:169.254.169.254', // SIIT IPv4-translated (RFC 2765)
      '0177.0.0.1', // leading-zero octal-style spelling → refuse
      '1e2.1.1.1', // exponent spelling → refuse
      '1:2:3:4:5:6:7:8::', // zero-group '::' — kernel-invalid → refuse
      '::1:2:3:4:5:6:7:8', // zero-group '::' (leading form)
      '::1:2:3:4:5:6:1.2.3.4', // zero-group '::' with embedded quad
      '::ffff:127.000.000.001', // leading-zero quad → refuse
    ]) {
      expect(isBlockedResolvedAddress(bad)).toBe(true)
    }
    for (const ok of [
      '93.184.216.34',
      // Class E 240/4 unicast: resolved-to-private policy (Kubernetes
      // fabrics use it as pod/service space) — only 255.255.255.255
      // stays refused.
      '240.0.0.1',
      '168.63.129.15', // WireServer neighbors are ordinary public space
      '168.63.129.17',
      '240.0.0.0', // Class E lower boundary
      '255.255.255.254', // Class E upper boundary (only .255 is refused)
      '254.254.190.115',
      '10.0.0.5',
      '172.16.1.1',
      '192.168.1.1',
      '2606:2800:220:1::1',
      '8.8.8.8',
      '::ffff:8.8.8.8',
      // CGNAT policy (deliberate, RFC1918-consistent): resolved tailnet
      // addresses allowed; only documented metadata /16 denied.
      '100.64.0.1',
      '100.127.255.254',
      '100.63.255.255', // below CGNAT
      '100.128.0.1', // above CGNAT
    ]) {
      expect(isBlockedResolvedAddress(ok)).toBe(false)
    }
  })

  it('localhost names are enforced loopback-only, not exempted', async () => {
    const resolve = (host: string) =>
      new Promise<string | Error>(r =>
        vettedLookup(host, {}, (err, addr) =>
          r(err ?? (Array.isArray(addr) ? addr[0]!.address : addr)),
        ),
      )
    const local = await resolve('localhost')
    // Must resolve AND be loopback (the exemption enforces intent).
    expect(typeof local).toBe('string')
    expect(isBlockedResolvedAddress(local as string)).toBe(true)
    // DNS names are case-insensitive: the exemption must fold case.
    const upper = await resolve('LOCALHOST')
    expect(typeof upper).toBe('string')
  })
})
