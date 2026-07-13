import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  setDefaultTimeout,
} from 'bun:test'
import { ChildProcess, spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import {
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isWindows } from '../helpers/platform.js'
import {
  grantWindowsAcl,
  revokeWindowsAcl,
  verifyWindowsWfpEgress,
  verifyWindowsWfpEgressWithAclBootstrap,
  type SrtWinSpawn,
} from '../../src/sandbox/windows-sandbox-utils.js'

setDefaultTimeout(15_000)

interface FakeInvocation {
  args: string[]
  pid: number
  prefixArgs: string[]
  cwd: string
  execPath: string
  stdin: string
}

interface FakeState {
  grantExit?: number
  grantDelayMs?: number
  verifyExit?: number
  revokeExit?: number
  revokeStatuses?: string[]
  userProvisioned?: boolean
  credentialPresent?: boolean
  omitUserSid?: boolean
  holdExitCode?: number
  holdExitBeforeReady?: number
  holdExitBeforeReadyDelayMs?: number
  holdExitDelayMs?: number
  holdReleaseExit?: number
  holdStderr?: string
  holdStderrAfterExit?: string
  holdStderrAfterExitDelayMs?: number
  holdReadyDelayMs?: number
  holdReadyLine?: string
  holdReadyPidOffset?: number
  holdReadyProcessCreateTime?: string
  verifyDelayMs?: number
  holds?: Record<string, string[]>
  holdCreateTimes?: Record<string, string>
}

async function rejectedError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise
  } catch (error) {
    if (error instanceof Error) return error
    return new Error(String(error))
  }
  throw new Error('Expected promise to reject')
}

describe.if(isWindows)('Windows WFP protected-runner bootstrap', () => {
  let tempDir = ''
  let logPath = ''
  let statePath = ''
  const fixture = fileURLToPath(
    new URL('../fixtures/fake-srt-win.mjs', import.meta.url),
  )
  const crashFixture = fileURLToPath(
    new URL('../fixtures/wfp-bootstrap-crash-child.ts', import.meta.url),
  )
  const sandboxUserSid = 'S-1-5-21-111-222-333-1007'
  const target = '127.0.0.1:49999'
  let nodeExe = ''
  let srtWin: SrtWinSpawn

  function bootstrap() {
    return verifyWindowsWfpEgressWithAclBootstrap({
      sandboxUserSid,
      target,
      srtWin,
    })
  }

  function publicVerify() {
    return verifyWindowsWfpEgress({ target, srtWin })
  }

  function invocations(): FakeInvocation[] {
    return readFileSync(logPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map(line => JSON.parse(line) as FakeInvocation)
  }

  function commandInvocations(): FakeInvocation[] {
    return invocations().filter(
      call => !(call.args[0] === 'acl' && call.args[1] === 'hold'),
    )
  }

  function fakeState(): FakeState {
    return JSON.parse(readFileSync(statePath, 'utf8')) as FakeState
  }

  function argValue(call: FakeInvocation, name: string): string | undefined {
    const index = call.args.indexOf(name)
    return index >= 0 ? call.args[index + 1] : undefined
  }

  async function waitFor(
    predicate: () => boolean,
    timeoutMs = 5_000,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      try {
        if (predicate()) return
      } catch {
        // The fake state file can be between truncate and rewrite.
      }
      await new Promise(resolve => setTimeout(resolve, 25))
    }
    throw new Error('timed out waiting for crash-recovery condition')
  }

  function processIsAlive(pid: number): boolean {
    try {
      process.kill(pid, 0)
      return true
    } catch {
      return false
    }
  }

  function setState(overrides: FakeState = {}) {
    writeFileSync(
      statePath,
      JSON.stringify({ logPath, sandboxUserSid, holds: {}, ...overrides }),
    )
  }

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'srt-wfp-bootstrap-'))
    logPath = join(tempDir, 'calls.jsonl')
    statePath = join(tempDir, 'state.json')
    // Spawning Bun from inside `bun test` inherits the test harness
    // mode and suppresses child stdout. Use the required Node runtime
    // for the fake CLI so spawnSync observes normal process I/O.
    const where = spawnSync('where.exe', ['node'], { encoding: 'utf8' })
    nodeExe = where.stdout
      .split(/\r?\n/)
      .map(line => line.trim())
      .find(Boolean)
    if (!nodeExe) throw new Error('node.exe is required for this test')
    srtWin = {
      exe: nodeExe,
      prependArgs: [fixture, '--state', statePath],
    }
  })

  beforeEach(() => {
    writeFileSync(logPath, '')
    setState()
  })

  afterAll(() => {
    rmSync(tempDir, { recursive: true, force: true })
  })

  it('grants only the canonical executable and preserves caller CWD', async () => {
    const result = await bootstrap()
    expect(result.target).toBe(target)

    const allCalls = invocations()
    const holder = allCalls.find(
      call => call.args[0] === 'acl' && call.args[1] === 'hold',
    )
    const grant = allCalls.find(
      call => call.args[0] === 'acl' && call.args[1] === 'grant',
    )
    const revoke = allCalls.find(
      call => call.args[0] === 'acl' && call.args[1] === 'revoke',
    )
    expect(argValue(holder!, '--sandbox-user-sid')).toBe(sandboxUserSid)
    expect(argValue(grant!, '--holder-pid')).toBe(String(holder!.pid))
    const createTime = argValue(grant!, '--holder-process-create-time')
    expect(createTime).toMatch(/^[1-9][0-9]+$/)
    expect(argValue(revoke!, '--holder-process-create-time')).toBe(createTime)

    const calls = commandInvocations()
    expect(calls.map(call => call.args.slice(0, 2).join(' '))).toEqual([
      'acl grant',
      'wfp verify',
      'acl revoke',
    ])

    const canonicalExe = realpathSync.native(srtWin.exe)
    expect(JSON.parse(calls[0].stdin)).toEqual({
      read: [canonicalExe],
      write: [],
    })
    expect(calls[1].execPath.toLowerCase()).toBe(canonicalExe.toLowerCase())

    expect(calls[1].cwd.toLowerCase()).toBe(process.cwd().toLowerCase())
    expect(dirname(canonicalExe).toLowerCase()).not.toBe(
      calls[1].cwd.toLowerCase(),
    )
  })

  it('preserves prepend arguments byte-for-byte in the caller CWD', async () => {
    const relativeDirectory = relative(process.cwd(), dirname(fixture))
    const extensionless = 'extensionless-runner-argument'
    const nonexistent = '.\\missing-prepend-argument'
    const relativeSrtWin: SrtWinSpawn = {
      exe: 'node.exe',
      prependArgs: [
        relative(process.cwd(), fixture),
        relativeDirectory,
        extensionless,
        nonexistent,
        '--state',
        relative(process.cwd(), statePath),
      ],
    }
    expect(
      await verifyWindowsWfpEgressWithAclBootstrap({
        sandboxUserSid,
        target,
        srtWin: relativeSrtWin,
      }),
    ).toMatchObject({ target })
    const verify = invocations().find(
      call => call.args[0] === 'wfp' && call.args[1] === 'verify',
    )
    expect(verify).toBeDefined()
    expect(verify!.args[0]).toBe('wfp')
    // Node consumes the script path as argv[1]; the fake observes every
    // remaining prepend argument exactly as received.
    expect(verify!.prefixArgs).toEqual(relativeSrtWin.prependArgs.slice(1))
    expect(verify!.cwd.toLowerCase()).toBe(process.cwd().toLowerCase())
  })

  it('waits for explicit parent HANDLE readiness before granting', async () => {
    setState({ holdReadyDelayMs: 500 })
    const pending = bootstrap()
    await waitFor(() =>
      invocations().some(
        call => call.args[0] === 'acl' && call.args[1] === 'hold',
      ),
    )
    await new Promise<void>(resolve => setTimeout(resolve, 100))
    expect(
      commandInvocations().some(
        call => call.args[0] === 'acl' && call.args[1] === 'grant',
      ),
    ).toBe(false)

    expect(await pending).toMatchObject({ target })
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual(['acl grant', 'wfp verify', 'acl revoke'])
  })

  it('protects the existing public verify API shape', async () => {
    expect(await publicVerify()).toMatchObject({ target })
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual(['user status', 'acl grant', 'wfp verify', 'acl revoke'])
  })

  it('fails actionably when the installed user has no SID', async () => {
    setState({ omitUserSid: true })
    expect((await rejectedError(publicVerify())).message).toMatch(
      /user SID is missing/i,
    )
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual(['user status'])
  })

  it('fails actionably when sandbox credentials are missing', async () => {
    setState({ credentialPresent: false })
    expect((await rejectedError(publicVerify())).message).toMatch(
      /not provisioned.*cred=false.*windows-install/is,
    )
  })

  it('shares one grant/verify/revoke sequence across concurrent callers', async () => {
    const first = bootstrap()
    const second = bootstrap()
    expect(second).toBe(first)

    await Promise.all([first, second])
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual(['acl grant', 'wfp verify', 'acl revoke'])
  })

  it('keeps differing concurrent targets isolated', async () => {
    const firstTarget = '127.0.0.1:50001'
    const secondTarget = '127.0.0.1:50002'
    const [first, second] = await Promise.all([
      verifyWindowsWfpEgressWithAclBootstrap({
        sandboxUserSid,
        target: firstTarget,
        srtWin,
      }),
      verifyWindowsWfpEgressWithAclBootstrap({
        sandboxUserSid,
        target: secondTarget,
        srtWin,
      }),
    ])

    expect(first.target).toBe(firstTarget)
    expect(second.target).toBe(secondTarget)
    const verifyTargets = invocations()
      .filter(call => call.args[0] === 'wfp' && call.args[1] === 'verify')
      .map(call => argValue(call, '--target'))
    expect(new Set(verifyTargets)).toEqual(new Set([firstTarget, secondTarget]))
    const holderPids = invocations()
      .filter(call => call.args[0] === 'acl' && call.args[1] === 'grant')
      .map(call => argValue(call, '--holder-pid'))
    expect(new Set(holderPids).size).toBe(2)
  })

  it('snapshots mutable inputs for both coalescing and execution', async () => {
    const originalPrepend = [fixture, '--state', statePath]
    const mutableRange: [number, number] = [1, 65_535]
    const mutableSrtWin: SrtWinSpawn = {
      exe: nodeExe,
      prependArgs: originalPrepend,
    }
    const mutableOpts: Parameters<
      typeof verifyWindowsWfpEgressWithAclBootstrap
    >[0] = {
      sandboxUserSid,
      proxyPortRange: mutableRange,
      srtWin: mutableSrtWin,
    }

    const first = verifyWindowsWfpEgressWithAclBootstrap(mutableOpts)
    mutableOpts.target = target
    mutableRange[0] = 40_000
    mutableRange[1] = 40_100
    mutableSrtWin.exe = 'missing-mutated-runner.exe'
    originalPrepend.splice(0, originalPrepend.length, 'mutated-prepend')

    const second = verifyWindowsWfpEgressWithAclBootstrap({
      sandboxUserSid,
      proxyPortRange: [1, 65_535],
      srtWin: {
        exe: nodeExe,
        prependArgs: [fixture, '--state', statePath],
      },
    })
    expect(second).toBe(first)
    expect((await rejectedError(first)).message).toMatch(
      /could not bind.*outside/i,
    )

    const calls = commandInvocations()
    expect(calls.map(call => call.args.slice(0, 2).join(' '))).toEqual([
      'acl grant',
      'acl revoke',
    ])
    for (const call of calls) {
      expect(call.prefixArgs).toEqual(['--state', statePath])
    }
  })

  it('revokes after a verify failure', async () => {
    setState({ verifyExit: 2 })
    expect((await rejectedError(bootstrap())).message).toMatch(
      /WFP egress fence/i,
    )
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual(['acl grant', 'wfp verify', 'acl revoke'])
  })

  it('allows a retry after a verify failure', async () => {
    setState({ verifyExit: 2 })
    expect((await rejectedError(bootstrap())).message).toMatch(
      /WFP egress fence/i,
    )

    setState()
    expect(await bootstrap()).toMatchObject({ target })
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual([
      'acl grant',
      'wfp verify',
      'acl revoke',
      'acl grant',
      'wfp verify',
      'acl revoke',
    ])
  }, 15_000)

  it('attempts strict cleanup after a partial grant failure', async () => {
    setState({ grantExit: 2 })
    expect((await rejectedError(bootstrap())).message).toMatch(
      /acl grant exited 2/i,
    )
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual(['acl grant', 'acl revoke'])
  })

  it('fails closed when revoke fails', async () => {
    setState({ revokeExit: 2 })
    expect((await rejectedError(bootstrap())).message).toMatch(
      /acl revoke exited non-zero/i,
    )
    expect(
      commandInvocations().map(call => call.args.slice(0, 2).join(' ')),
    ).toEqual(['acl grant', 'wfp verify', 'acl revoke'])
  })

  it('fails closed on a successful revoke process with an unsafe outcome', async () => {
    setState({ revokeStatuses: ['missing'] })
    expect((await rejectedError(bootstrap())).message).toMatch(
      /unsafe status 'missing'/i,
    )
  })

  it('accepts downgraded as a safe native revoke outcome', async () => {
    setState({ revokeStatuses: ['downgraded'] })
    expect(await bootstrap()).toMatchObject({ target })
  })

  it('fails closed on an invalid holder readiness line', async () => {
    setState({ holdReadyLine: 'not-the-holder-protocol' })
    const error = await bootstrap().then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-ready-invalid' })
    expect(error.message).toMatch(/invalid readiness/i)
    expect(commandInvocations()).toEqual([])
  })

  it('rejects a readiness identity for a different holder PID', async () => {
    setState({ holdReadyPidOffset: 1 })
    const error = await rejectedError(bootstrap())

    expect(error).toMatchObject({ code: 'acl-holder-ready-invalid' })
    expect(error.message).toMatch(/did not match spawned process/i)
    expect(commandInvocations()).toEqual([])
  })

  it('rejects a readiness creation time outside signed 64-bit range', async () => {
    setState({ holdReadyProcessCreateTime: '9223372036854775808' })
    const error = await rejectedError(bootstrap())

    expect(error).toMatchObject({ code: 'acl-holder-ready-invalid' })
    expect(error.message).toMatch(/signed 64-bit range/i)
    expect(commandInvocations()).toEqual([])
  })

  it('rejects trailing payload in the READY frame', async () => {
    setState({
      holdReadyLine: 'srt-win-acl-holder-ready-v1\ntrailing-payload',
    })
    const error = await bootstrap().then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-ready-invalid' })
    expect(error.message).toMatch(/invalid readiness/i)
    expect(commandInvocations()).toEqual([])
  })

  it('applies the READY bound to raw UTF-8 bytes', async () => {
    setState({ holdReadyLine: String.fromCodePoint(0xe9).repeat(200) })
    const error = await bootstrap().then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-ready-invalid' })
    expect(error.message).toMatch(/byte bound/i)
    expect(commandInvocations()).toEqual([])
  })

  it('times out readiness through the injected short test seam', async () => {
    setState({ holdReadyDelayMs: 1_000 })
    const error = await verifyWindowsWfpEgressWithAclBootstrap({
      sandboxUserSid,
      target,
      srtWin,
      holderReadyTimeoutMs: 25,
    }).then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-ready-timeout' })
    expect(error.message).toMatch(/did not confirm parent HANDLE readiness/i)
    expect(commandInvocations()).toEqual([])
  })

  it('preserves a bounded stderr tail when native init exits', async () => {
    setState({
      holdStderr: 'DROP-ME-' + 'x'.repeat(5_000) + '-NATIVE-TAIL',
      holdExitBeforeReady: 17,
    })
    const error = await bootstrap().then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-exited-early' })
    expect(error.message).toContain('NATIVE-TAIL')
    expect(error.message).not.toContain('DROP-ME')
    expect(error.message.length).toBeLessThan(4_500)
    expect(commandInvocations()).toEqual([])
  })

  it('waits for inherited stderr to close after holder exit', async () => {
    setState({
      holdStderrAfterExit:
        'DROP-ME-AFTER-EXIT-' + 'x'.repeat(5_000) + '-DELAYED-NATIVE-TAIL',
      holdStderrAfterExitDelayMs: 150,
      holdExitBeforeReady: 17,
      holdExitBeforeReadyDelayMs: 50,
    })
    const error = await bootstrap().then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-exited-early' })
    expect(error.message).toContain('DELAYED-NATIVE-TAIL')
    expect(error.message).not.toContain('DROP-ME-AFTER-EXIT')
    expect(error.message.length).toBeLessThan(4_500)
    expect(commandInvocations()).toEqual([])
  })

  it('reports a native ACL holder that exits during bootstrap', async () => {
    setState({ holdExitCode: 17, holdExitDelayMs: 10, verifyDelayMs: 500 })
    const error = await bootstrap().then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-exited-early' })
    expect(error.message).toMatch(/exited early.*code=17/i)
    expect(Object.keys(fakeState().holds ?? {})).toEqual([])
  })

  it('reports a holder spawn error without a false kill error', async () => {
    const invalidRunner = join(tempDir, 'not-an-executable.txt')
    writeFileSync(invalidRunner, 'not an executable')
    const error = await verifyWindowsWfpEgressWithAclBootstrap({
      sandboxUserSid,
      target,
      srtWin: { exe: invalidRunner, prependArgs: [] },
    }).then(
      () => undefined,
      reason => reason,
    )

    expect(error).toMatchObject({ code: 'acl-holder-spawn-error' })
    expect(error.message).toMatch(/failed to start/i)
    expect(commandInvocations()).toEqual([])
  })

  it('preserves both the probe and cleanup errors', async () => {
    setState({ verifyExit: 2, revokeExit: 2 })
    const error = await bootstrap().then(
      () => undefined,
      reason => reason,
    )

    expect(error).toBeInstanceOf(AggregateError)
    expect(error.errors).toHaveLength(2)
    expect(error.errors[0].message).toMatch(/WFP egress fence/i)
    expect(error.errors[1].message).toMatch(/acl revoke exited non-zero/i)
  })

  it('preserves the probe error when holder termination is refused', async () => {
    setState({ verifyExit: 2 })
    const originalKill = ChildProcess.prototype.kill
    let holderPid = 0
    try {
      ChildProcess.prototype.kill = function () {
        return false
      }
      const error = await bootstrap().then(
        () => undefined,
        reason => reason,
      )
      const holder = invocations().find(
        call => call.args[0] === 'acl' && call.args[1] === 'hold',
      )
      holderPid = holder?.pid ?? 0

      expect(error).toBeInstanceOf(AggregateError)
      expect(error.errors[0].message).toMatch(/WFP egress fence/i)
      expect(error.errors[1]).toMatchObject({
        code: 'acl-holder-kill-failed',
      })
    } finally {
      ChildProcess.prototype.kill = originalKill
      if (holderPid && processIsAlive(holderPid)) {
        process.kill(holderPid)
        await waitFor(() => !processIsAlive(holderPid))
      }
    }
  })

  it('never grants when the parent exits before holder readiness', async () => {
    setState({ holdReadyDelayMs: 2_000 })
    const child = spawn(
      process.execPath,
      [crashFixture, statePath, nodeExe, fixture, target],
      {
        cwd: process.cwd(),
        stdio: 'ignore',
        windowsHide: true,
      },
    )
    let holderPid = 0
    try {
      await waitFor(() => {
        const holder = invocations().find(
          call => call.args[0] === 'acl' && call.args[1] === 'hold',
        )
        holderPid = holder?.pid ?? 0
        return holderPid > 0
      })

      child.kill()
      if (child.exitCode === null && child.signalCode === null) {
        await once(child, 'exit')
      }
      await waitFor(() => !processIsAlive(holderPid))
      expect(
        commandInvocations().some(
          call => call.args[0] === 'acl' && call.args[1] === 'grant',
        ),
      ).toBe(false)
      expect(fakeState().holds ?? {}).toEqual({})
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill()
      if (holderPid && processIsAlive(holderPid)) process.kill(holderPid)
    }
  }, 10_000)

  it('self-releases ACL state immediately after parent crash', async () => {
    setState({ grantDelayMs: 2_000 })
    const child = spawn(
      process.execPath,
      [crashFixture, statePath, nodeExe, fixture, target],
      {
        cwd: process.cwd(),
        stdio: 'ignore',
        windowsHide: true,
      },
    )
    let holderPid = 0
    try {
      await waitFor(() => {
        const grant = invocations().find(
          call => call.args[0] === 'acl' && call.args[1] === 'grant',
        )
        const value = grant && argValue(grant, '--holder-pid')
        if (!value) return false
        holderPid = Number(value)
        return fakeState().holds?.[value] !== undefined
      })

      const killedAt = Date.now()
      child.kill()
      if (child.exitCode === null && child.signalCode === null) {
        await once(child, 'exit')
      }
      await waitFor(() => !processIsAlive(holderPid))
      await waitFor(() => fakeState().holds?.[String(holderPid)] === undefined)
      expect(Date.now() - killedAt).toBeLessThan(5_000)
      expect(fakeState().holdCreateTimes?.[String(holderPid)]).toBeUndefined()
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill()
      if (holderPid && processIsAlive(holderPid)) process.kill(holderPid)
    }
  }, 15_000)

  it('recovers retryable residue after holder self-release fails', async () => {
    setState({ grantDelayMs: 2_000, holdReleaseExit: 17 })
    const child = spawn(
      process.execPath,
      [crashFixture, statePath, nodeExe, fixture, target],
      {
        cwd: process.cwd(),
        stdio: 'ignore',
        windowsHide: true,
      },
    )
    let holderPid = 0
    try {
      await waitFor(() => {
        const grant = invocations().find(
          call => call.args[0] === 'acl' && call.args[1] === 'grant',
        )
        const value = grant && argValue(grant, '--holder-pid')
        if (!value) return false
        holderPid = Number(value)
        return fakeState().holds?.[value] !== undefined
      })

      child.kill()
      if (child.exitCode === null && child.signalCode === null) {
        await once(child, 'exit')
      }
      await waitFor(() => !processIsAlive(holderPid))
      expect(fakeState().holds?.[String(holderPid)]).toBeDefined()

      const recovered = fakeState()
      delete recovered.grantDelayMs
      delete recovered.holdReleaseExit
      writeFileSync(statePath, JSON.stringify(recovered))
      await bootstrap()
      expect(fakeState().holds?.[String(holderPid)]).toBeUndefined()
      expect(fakeState().holdCreateTimes?.[String(holderPid)]).toBeUndefined()
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill()
      if (holderPid && processIsAlive(holderPid)) process.kill(holderPid)
    }
  }, 15_000)

  it('preserves a pre-existing host-process grant during public verify', async () => {
    const sessionPath = 'C:\\session-read'
    grantWindowsAcl({
      sandboxUserSid,
      read: [sessionPath],
      write: [],
      srtWin,
    })
    try {
      await publicVerify()
      expect(fakeState().holds?.[String(process.pid)]).toEqual([sessionPath])

      const bootstrapGrant = invocations().find(call => {
        if (call.args[0] !== 'acl' || call.args[1] !== 'grant') return false
        return (JSON.parse(call.stdin).read as string[]).some(path =>
          /node\.exe$/i.test(path),
        )
      })
      expect(bootstrapGrant).toBeDefined()
      const bootstrapHolder = argValue(bootstrapGrant!, '--holder-pid')
      expect(bootstrapHolder).not.toBe(String(process.pid))
      const bootstrapRevoke = invocations().find(
        call =>
          call.args[0] === 'acl' &&
          call.args[1] === 'revoke' &&
          argValue(call, '--holder-pid') === bootstrapHolder,
      )
      expect(bootstrapRevoke).toBeDefined()
    } finally {
      revokeWindowsAcl({ sandboxUserSid, srtWin })
    }
  }, 15_000)

  it('finishes bootstrap revoke before a later normal session grant', async () => {
    await bootstrap()
    grantWindowsAcl({
      sandboxUserSid,
      read: ['C:\\session-read'],
      write: [],
      srtWin,
    })

    const calls = commandInvocations()
    expect(calls.map(call => call.args.slice(0, 2).join(' '))).toEqual([
      'acl grant',
      'wfp verify',
      'acl revoke',
      'acl grant',
    ])
    expect(JSON.parse(calls[3].stdin)).toEqual({
      read: ['C:\\session-read'],
      write: [],
    })
  }, 10_000)
})
