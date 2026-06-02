import { describe, it, expect, beforeAll } from 'bun:test'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import { existsSync, mkdtempSync, chmodSync, rmSync } from 'node:fs'
import * as net from 'node:net'
import { getSrtLauncherPath } from '../../src/sandbox/srt-launcher.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Tests for srt-launcher's isolation guarantees.
 *
 * srt-launcher uses a single PID namespace layer (it is PID 1 inside the
 * sandbox) and sets PR_SET_DUMPABLE=0 on itself before exec'ing the worker.
 * That means the worker (a) sees only its own process tree in /proc, (b)
 * cannot ptrace / open /proc/1/mem of the launcher init, and (c) when
 * --seccomp-unix-block is on, gets EPERM on socket(AF_UNIX, ...).
 *
 * These tests invoke srt-launcher directly so they don't depend on the rest
 * of the sandbox plumbing.
 */

let launcher: string | null = null

function runLauncherArgs(
  cmd: string[],
  opts: { timeout?: number } = {},
): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(
    launcher!,
    [
      'run',
      '--ro-bind',
      '/',
      '/',
      '--proc',
      '/proc',
      '--dev',
      '/dev',
      '--seccomp-unix-block',
      '--',
      ...cmd,
    ],
    { stdio: 'pipe', timeout: opts.timeout ?? 10000 },
  )
  return {
    status: r.status,
    stdout: r.stdout?.toString() ?? '',
    stderr: r.stderr?.toString() ?? '',
  }
}

function runLauncher(
  script: string,
  opts: { timeout?: number } = {},
): { status: number | null; stdout: string; stderr: string } {
  return runLauncherArgs(['/bin/sh', '-c', script], opts)
}

describe.if(isLinux)('srt-launcher isolation', () => {
  beforeAll(() => {
    launcher = getSrtLauncherPath()
    // On Linux CI with the vendor binary present this always resolves.
    // If null, every test below would silently no-op — fail here.
    expect(launcher).toBeTruthy()
    expect(existsSync(launcher!)).toBe(true)
  })

  // ------------------------------------------------------------------
  // PID namespace
  // ------------------------------------------------------------------

  it('shows only the inner namespace in /proc', () => {
    const r = runLauncher('ls /proc | grep -E "^[0-9]+$" | sort -n')
    expect(r.status).toBe(0)
    const pids = r.stdout
      .trim()
      .split('\n')
      .map(s => parseInt(s, 10))
    // PID 1 is srt-launcher init, PID 2 is sh; ls/grep/sort add a few more.
    // What matters is that none of the host's PIDs leak in.
    expect(pids[0]).toBe(1)
    expect(Math.max(...pids)).toBeLessThan(20)
  })

  it('forwards exit codes from the inner command', () => {
    expect(runLauncher('exit 0').status).toBe(0)
    expect(runLauncher('exit 1').status).toBe(1)
    expect(runLauncher('exit 42').status).toBe(42)
    expect(runLauncher('exit 127').status).toBe(127)
  })

  // ------------------------------------------------------------------
  // PID 1 is not controllable from the worker (PR_SET_DUMPABLE=0)
  // ------------------------------------------------------------------

  it('denies opening /proc/1/mem for writing', () => {
    const r = runLauncher(
      [
        'python3 -c "',
        'try:',
        '    open(\\"/proc/1/mem\\", \\"r+b\\")',
        '    print(\\"OPENED\\")',
        '    exit(1)',
        'except PermissionError:',
        '    print(\\"DENIED\\")',
        '    exit(0)',
        '"',
      ].join('\n'),
    )
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('DENIED')
  })

  it('denies ptrace(PTRACE_ATTACH) against PID 1', () => {
    const r = runLauncher(
      [
        'python3 -c "',
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'r = libc.ptrace(16, 1, 0, 0)  # PTRACE_ATTACH',
        'err = ctypes.get_errno()',
        'print(f\\"r={r} errno={err}\\")',
        'exit(0 if r != 0 else 1)',
        '"',
      ].join('\n'),
    )
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/r=-1 errno=(1|13)/) // EPERM or EACCES
  })

  // ------------------------------------------------------------------
  // Seccomp filter
  // ------------------------------------------------------------------

  it('blocks AF_UNIX socket creation', () => {
    const r = runLauncher(
      'python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"',
    )
    expect(r.status).not.toBe(0)
    expect(r.stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('allows AF_INET socket creation', () => {
    const r = runLauncher(
      'python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM); print(\\"ok\\")"',
    )
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('ok')
  })

  it('blocks io_uring_setup (IORING_OP_SOCKET bypass of socket() filter)', () => {
    const r = runLauncherArgs([
      'python3',
      '-c',
      [
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'p = (ctypes.c_byte * 256)()',
        'fd = libc.syscall(425, 4, p)  # __NR_io_uring_setup',
        'err = ctypes.get_errno()',
        'print(f"fd={fd} errno={err}")',
        'exit(1 if fd >= 0 else 0)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/fd=-1 errno=1\b/) // EPERM
  })

  it('blocks io_uring_enter (covers inherited ring fd)', () => {
    const r = runLauncherArgs([
      'python3',
      '-c',
      [
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'r = libc.syscall(426, 99, 0, 0, 0, 0, 0)  # __NR_io_uring_enter',
        'print(f"r={r} errno={ctypes.get_errno()}")',
      ].join('\n'),
    ])
    // EPERM (1) from seccomp, not EBADF (9) from a bad fd — seccomp runs first.
    expect(r.stdout).toMatch(/r=-1 errno=1\b/)
  })

  // ------------------------------------------------------------------
  // Process model
  // ------------------------------------------------------------------

  it('forwards signal exits as 128+signo', () => {
    expect(runLauncher('kill -TERM $$').status).toBe(128 + 15)
  })

  it('forwards SIGTERM from the outside through both inits to the command', () => {
    // PID 1 drops signals it has no handler for; the stub and PID 1 must
    // forward so SIGTERM from the caller reaches the workload.
    const r = spawnSync(
      'timeout',
      [
        '--preserve-status',
        '-s',
        'TERM',
        '1',
        launcher!,
        'run',
        '--ro-bind',
        '/',
        '/',
        '--proc',
        '/proc',
        '--dev',
        '/dev',
        '--',
        'sleep',
        '10',
      ],
      { stdio: 'pipe', timeout: 10000 },
    )
    expect(r.status).toBe(128 + 15)
  })

  it('reaps orphaned grandchildren without leaking zombies', () => {
    const r = runLauncher('(sleep 0.2 &) ; exit 7', { timeout: 5000 })
    expect(r.status).toBe(7)
  })

  it('exits when the main command exits, even with a long-running background process', () => {
    const r = runLauncher('sleep 100 & exit 5', { timeout: 3000 })
    expect(r.status).toBe(5)
  })

  // ------------------------------------------------------------------
  // Privilege surface
  // ------------------------------------------------------------------

  it('runs the user command with zero effective capabilities', () => {
    const r = runLauncherArgs(['grep', 'CapEff', '/proc/self/status'])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/CapEff:\s*0+$/m)
  })

  it('denies umount(/proc) from the user command', () => {
    const r = runLauncherArgs([
      'python3',
      '-c',
      [
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'r = libc.umount2(b"/proc", 0)',
        'print(f"r={r} errno={ctypes.get_errno()}")',
        'exit(0 if r < 0 else 1)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/r=-1 errno=1\b/) // EPERM
  })

  it('denies process_vm_writev against PID 1', () => {
    const r = runLauncherArgs([
      'python3',
      '-c',
      [
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'class iovec(ctypes.Structure):',
        '    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]',
        'buf = ctypes.create_string_buffer(b"x")',
        'local = iovec(ctypes.cast(buf, ctypes.c_void_p).value, 1)',
        'remote = iovec(0x1000, 1)',
        'r = libc.process_vm_writev(1, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)',
        'err = ctypes.get_errno()',
        'print(f"r={r} errno={err}")',
        'exit(0 if r < 0 and err in (1, 3, 13) else 1)',
      ].join('\n'),
    ])
    expect(r.status).toBe(0)
  })
})

describe.if(isLinux)('relay isolation (host pidns)', () => {
  let sockDir: string
  let hsock: string
  let proxy: net.Server

  beforeAll(() => {
    launcher = getSrtLauncherPath()
    if (!launcher || !existsSync(launcher)) {
      throw new Error(
        'srt-launcher binary not found; run `npm run build:launcher`',
      )
    }
    sockDir = mkdtempSync('/tmp/srt-relay-iso-')
    chmodSync(sockDir, 0o700)
    hsock = `${sockDir}/http.sock`
  })

  /** spawn (not spawnSync) — the proxy listeners are on this event loop. */
  async function runLauncherAsync(argv: string[]): Promise<string> {
    const p = spawn(launcher!, argv)
    let out = ''
    p.stdout.on('data', d => (out += d))
    await once(p, 'exit')
    return out.trim()
  }

  it('relay survives `kill -9 -1` from inside the sandbox pidns', async () => {
    proxy = net.createServer(c => c.once('data', d => c.end('via-relay:' + d)))
    await new Promise<void>(r => proxy.listen(hsock, () => r()))

    // Worker does `kill -9 -1` (every process in its pidns), then connects to
    // the relay. If the relay were inside the pidns, it would be dead.
    const out = await runLauncherAsync([
      'run',
      '--unshare-net',
      '--ro-bind',
      '/',
      '/',
      '--bind',
      '/tmp',
      '/tmp',
      '--proc',
      '/proc',
      '--dev',
      '/dev',
      '--relay',
      '3128',
      hsock,
      '--',
      '/bin/sh',
      '-c',
      'sleep 0.3; kill -9 -1 2>/dev/null; sleep 0.2; ' +
        "python3 -c \"import socket;c=socket.create_connection(('127.0.0.1',3128),timeout=3);c.sendall(b'hi');print(c.recv(64).decode())\"",
    ])
    proxy.close()
    rmSync(hsock, { force: true })
    expect(out).toBe('via-relay:hi')
  }, 10000)

  it('relay pins the bridge socket inode — workload cannot redirect it', async () => {
    const evil = `${sockDir}/evil.sock`
    rmSync(hsock, { force: true })
    rmSync(evil, { force: true })

    const good = net.createServer(c => c.end('GOOD'))
    const bad = net.createServer(c => c.end('PWNED'))
    await new Promise<void>(r => good.listen(hsock, () => r()))
    await new Promise<void>(r => bad.listen(evil, () => r()))

    // Worker swaps the socket path to a symlink at the "evil" socket. The
    // relay opened an O_PATH fd to the real socket before the worker existed,
    // so its connect goes to the original inode regardless.
    const out = await runLauncherAsync([
      'run',
      '--unshare-net',
      '--ro-bind',
      '/',
      '/',
      '--bind',
      '/tmp',
      '/tmp',
      '--proc',
      '/proc',
      '--dev',
      '/dev',
      '--relay',
      '3128',
      hsock,
      '--',
      '/bin/sh',
      '-c',
      `sleep 0.3; rm '${hsock}' && ln -s '${evil}' '${hsock}'; ` +
        'python3 -c "import socket;c=socket.create_connection((\'127.0.0.1\',3128),timeout=3);print(c.recv(64).decode())"',
    ])
    good.close()
    bad.close()
    rmSync(sockDir, { recursive: true, force: true })
    expect(out).toBe('GOOD')
  }, 10000)
})
