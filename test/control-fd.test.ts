import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { spawn, type ChildProcess } from 'child_process'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { type Writable } from 'stream'

// Get the path to the built CLI
const CLI_PATH = path.join(process.cwd(), 'dist', 'cli.js')

// srt is expected to exit on its own shortly after the wrapped command
// (which runs for well under a second) finishes; a hang is a failure, not
// something to wait out.
function waitForExit(child: ChildProcess): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () =>
        reject(new Error('srt did not exit within 2s of the wrapped command')),
      2000,
    )
    child.on('exit', code => {
      clearTimeout(timer)
      resolve(code)
    })
    child.on('error', err => {
      clearTimeout(timer)
      reject(err)
    })
  })
}

describe('--control-fd', () => {
  let tmpDir: string
  let child: ChildProcess | null = null

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'control-fd-test-'))
  })

  afterEach(async () => {
    if (child && !child.killed) {
      child.kill('SIGKILL')
    }
    fs.rmSync(tmpDir, { recursive: true, force: true })
    // Every test waits for srt to exit on its own; the SIGKILL above only
    // runs when one has already failed. Bun's node:child_process shim
    // implements extra stdio 'pipe' entries (fd 3 here) via a unix socket
    // torn down asynchronously after the child exits, and a spawn that
    // races that teardown throws `Failed to connect` (connect ENOENT), so
    // yield briefly before the next test's spawn either way.
    await new Promise(r => setTimeout(r, 50))
  })

  it('should update config when receiving valid JSON on control fd', async () => {
    // Create a test script that outputs the current network config
    // We'll use the debug output to verify config was updated
    const testScript = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(testScript, '#!/bin/bash\nsleep 0.3\necho "DONE"\n', {
      mode: 0o755,
    })

    // Spawn srt with --control-fd 3, passing fd 3 as a pipe
    child = spawn(
      'node',
      [CLI_PATH, '--debug', '--control-fd', '3', '--', testScript],
      {
        stdio: ['inherit', 'pipe', 'pipe', 'pipe'],
        env: { ...process.env, SRT_DEBUG: 'true' },
      },
    )

    const stdout: string[] = []
    const stderr: string[] = []

    child.stdout?.on('data', (data: Buffer) => {
      stdout.push(data.toString())
    })

    child.stderr?.on('data', (data: Buffer) => {
      stderr.push(data.toString())
    })

    // Wait a bit for srt to initialize, then send a config update
    await new Promise(r => setTimeout(r, 100))

    const controlFd = child.stdio[3] as Writable
    const configUpdate = JSON.stringify({
      network: { allowedDomains: ['updated-domain.com'], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    })
    controlFd.write(configUpdate + '\n')

    // srt must exit by itself once the wrapped command finishes, with the
    // control fd still open on our side.
    const exitCode = await waitForExit(child)
    expect(exitCode).toBe(0)

    // Check that config was updated - look for debug output
    const allStderr = stderr.join('')
    expect(allStderr).toContain('updated-domain.com')
  })

  it('should ignore invalid JSON on control fd and continue running', async () => {
    const testScript = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(testScript, '#!/bin/bash\nsleep 0.3\necho "COMPLETED"\n', {
      mode: 0o755,
    })

    child = spawn(
      'node',
      [CLI_PATH, '--debug', '--control-fd', '3', '--', testScript],
      {
        stdio: ['inherit', 'pipe', 'pipe', 'pipe'],
        env: { ...process.env, SRT_DEBUG: 'true' },
      },
    )

    const stdout: string[] = []

    child.stdout?.on('data', (data: Buffer) => {
      stdout.push(data.toString())
    })

    // Wait a bit for srt to initialize, then send invalid JSON
    await new Promise(r => setTimeout(r, 100))

    const controlFd = child.stdio[3] as Writable
    controlFd.write('{ invalid json }\n')

    // srt must exit by itself once the wrapped command finishes, with the
    // control fd still open on our side.
    const exitCode = await waitForExit(child)
    expect(exitCode).toBe(0)

    // Process should still complete successfully
    const allStdout = stdout.join('')
    expect(allStdout).toContain('COMPLETED')
  })

  it('should ignore empty lines on control fd', async () => {
    const testScript = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(testScript, '#!/bin/bash\nsleep 0.3\necho "DONE"\n', {
      mode: 0o755,
    })

    child = spawn('node', [CLI_PATH, '--control-fd', '3', '--', testScript], {
      stdio: ['inherit', 'pipe', 'pipe', 'pipe'],
    })

    const stdout: string[] = []

    child.stdout?.on('data', (data: Buffer) => {
      stdout.push(data.toString())
    })

    // Wait a bit for srt to initialize, then send empty lines
    await new Promise(r => setTimeout(r, 100))

    const controlFd = child.stdio[3] as Writable
    controlFd.write('\n')
    controlFd.write('   \n')
    controlFd.write('\t\n')

    // srt must exit by itself once the wrapped command finishes, with the
    // control fd still open on our side.
    const exitCode = await waitForExit(child)
    expect(exitCode).toBe(0)

    // Process should still complete successfully
    const allStdout = stdout.join('')
    expect(allStdout).toContain('DONE')
  })

  it('should work without --control-fd (backward compat)', async () => {
    const testScript = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(testScript, '#!/bin/bash\necho "NO_CONTROL_FD"\n', {
      mode: 0o755,
    })

    // Spawn without --control-fd
    child = spawn('node', [CLI_PATH, '--', testScript], {
      stdio: ['inherit', 'pipe', 'pipe'],
    })

    const stdout: string[] = []

    child.stdout?.on('data', (data: Buffer) => {
      stdout.push(data.toString())
    })

    const exitCode = await waitForExit(child)

    expect(exitCode).toBe(0)
    const allStdout = stdout.join('')
    expect(allStdout).toContain('NO_CONTROL_FD')
  })

  it('should allow stdin to pass through to child process', async () => {
    // Create a script that reads from stdin
    const testScript = path.join(tmpDir, 'test.sh')
    fs.writeFileSync(
      testScript,
      '#!/bin/bash\nread line\necho "GOT: $line"\n',
      { mode: 0o755 },
    )

    // Spawn with stdin as pipe (not inherit) so we can write to it
    child = spawn('node', [CLI_PATH, '--control-fd', '3', '--', testScript], {
      stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
    })

    const stdout: string[] = []

    child.stdout?.on('data', (data: Buffer) => {
      stdout.push(data.toString())
    })

    // Write to stdin (fd 0)
    const stdin = child.stdin as Writable
    stdin.write('hello from stdin\n')

    // srt must exit by itself once the wrapped command finishes, with the
    // control fd still open on our side.
    const exitCode = await waitForExit(child)
    expect(exitCode).toBe(0)

    const allStdout = stdout.join('')
    expect(allStdout).toContain('GOT: hello from stdin')
  })
})
