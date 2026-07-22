import { spawn } from 'node:child_process'
import { appendFileSync, readFileSync, writeFileSync, writeSync } from 'node:fs'

const rawArgs = process.argv.slice(2)
const stateIndex = rawArgs.indexOf('--state')
if (stateIndex < 0 || !rawArgs[stateIndex + 1]) {
  throw new Error('fake srt-win requires --state <path>')
}
const prefixArgs = rawArgs.slice(0, stateIndex)
const statePath = rawArgs[stateIndex + 1]
const state = JSON.parse(readFileSync(statePath, 'utf8'))
const args = rawArgs.slice(stateIndex + 2)
const isGrant = args[0] === 'acl' && args[1] === 'grant'
// Only grant receives JSON stdin. Reading fd 0 for the other fake
// commands can block under Bun's spawnSync implementation.
const stdin = isGrant ? readFileSync(0, 'utf8') : ''
const logPath = state.logPath
if (!logPath) throw new Error('fake srt-win state requires logPath')

function persistState() {
  writeFileSync(statePath, JSON.stringify(state))
}

function argValue(name) {
  const index = args.indexOf(name)
  return index >= 0 ? args[index + 1] : undefined
}

function holderPid() {
  const value = argValue('--holder-pid')
  if (!value) throw new Error('fake ACL command requires --holder-pid')
  return value
}

function holderProcessCreateTime() {
  return argValue('--holder-process-create-time')
}

appendFileSync(
  logPath,
  JSON.stringify({
    args,
    pid: process.pid,
    prefixArgs: [...prefixArgs, '--state', statePath],
    cwd: process.cwd(),
    execPath: process.execPath,
    stdin,
  }) + '\n',
)

let exitCode
if (args[0] === 'acl' && args[1] === 'hold') {
  const parentPid = Number(argValue('--parent-pid'))
  const holderSid = argValue('--sandbox-user-sid')
  if (!Number.isInteger(parentPid)) {
    throw new Error('fake acl hold requires --parent-pid')
  }
  if (!holderSid || holderSid !== state.sandboxUserSid) {
    throw new Error('fake acl hold requires the configured --sandbox-user-sid')
  }
  const holderCreateTime = String(
    state.holdReadyProcessCreateTime ??
      134_123_456_789_000_000n + BigInt(process.pid),
  )
  const releaseHolder = () => {
    const releaseExit = Number(state.holdReleaseExit ?? 0)
    if (releaseExit === 0) {
      const latest = JSON.parse(readFileSync(statePath, 'utf8'))
      const pid = String(process.pid)
      if (latest.holdCreateTimes?.[pid] === holderCreateTime) {
        delete latest.holds?.[pid]
        delete latest.holdCreateTimes[pid]
        writeFileSync(statePath, JSON.stringify(latest))
      }
    }
    process.exit(releaseExit)
  }
  const startHolder = () => {
    try {
      process.kill(parentPid, 0)
    } catch {
      releaseHolder()
    }
    if (state.holdStderr !== undefined) {
      writeSync(2, String(state.holdStderr))
    }
    if (state.holdStderrAfterExit !== undefined) {
      const delayedStderr = JSON.stringify(String(state.holdStderrAfterExit))
      const delayMs = Number(state.holdStderrAfterExitDelayMs ?? 0)
      const writer = spawn(
        process.execPath,
        [
          '-e',
          `setTimeout(() => process.stderr.write(${delayedStderr}), ${delayMs})`,
        ],
        {
          stdio: ['ignore', 'ignore', 'inherit'],
          windowsHide: true,
          detached: true,
        },
      )
      writer.unref()
    }
    if (state.holdExitBeforeReady !== undefined) {
      const exitCode = Number(state.holdExitBeforeReady)
      const delayMs = Number(state.holdExitBeforeReadyDelayMs ?? 0)
      if (delayMs > 0) {
        setTimeout(() => process.exit(exitCode), delayMs)
        return
      }
      process.exit(exitCode)
    }
    const readyHolderPid = process.pid + Number(state.holdReadyPidOffset ?? 0)
    const readyLine =
      state.holdReadyLine ??
      JSON.stringify({
        protocol: 'srt-win-acl-holder-ready-v2',
        holderPid: readyHolderPid,
        holderProcessCreateTime: holderCreateTime,
      })
    writeSync(1, String(readyLine) + '\n')
    if (state.holdExitCode !== undefined) {
      setTimeout(
        () => process.exit(Number(state.holdExitCode)),
        Number(state.holdExitDelayMs ?? 0),
      )
    }
    const timer = setInterval(() => {
      try {
        process.kill(parentPid, 0)
      } catch {
        clearInterval(timer)
        releaseHolder()
      }
    }, 25)
  }
  process.once('SIGTERM', releaseHolder)
  setTimeout(startHolder, Number(state.holdReadyDelayMs ?? 0))
} else if (args[0] === 'user' && args[1] === 'status') {
  const userExists = state.userProvisioned ?? true
  writeSync(
    1,
    JSON.stringify({
      user: {
        exists: userExists,
        ...(userExists && !state.omitUserSid
          ? { sid: state.sandboxUserSid }
          : {}),
        group_exists: userExists,
        in_builtin_users: false,
        in_sandbox_group: userExists,
        hidden_from_logon: userExists,
      },
      cred_present: state.credentialPresent ?? userExists,
      real_user_sid: 'S-1-5-21-111-222-333-1001',
    }) + '\n',
  )
  exitCode = 0
} else if (args[0] === 'acl' && args[1] === 'grant') {
  const pid = holderPid()
  const access = JSON.parse(stdin)
  state.holds ??= {}
  state.holdCreateTimes ??= {}
  for (const existingPid of Object.keys(state.holds)) {
    try {
      process.kill(Number(existingPid), 0)
    } catch {
      delete state.holds[existingPid]
      delete state.holdCreateTimes[existingPid]
    }
  }
  state.holds[pid] = [
    ...new Set([
      ...(state.holds[pid] ?? []),
      ...(access.read ?? []),
      ...(access.write ?? []),
    ]),
  ]
  const createTime = holderProcessCreateTime()
  if (createTime !== undefined) state.holdCreateTimes[pid] = createTime
  persistState()
  if (state.grantDelayMs) {
    Atomics.wait(
      new Int32Array(new SharedArrayBuffer(4)),
      0,
      0,
      state.grantDelayMs,
    )
  }
  exitCode = Number(state.grantExit ?? 0)
} else if (args[0] === 'acl' && args[1] === 'revoke') {
  const pid = holderPid()
  const held = state.holds?.[pid] ?? []
  const createTime = holderProcessCreateTime()
  const identityMatches =
    createTime === undefined || state.holdCreateTimes?.[pid] === createTime
  const statuses = identityMatches
    ? (state.revokeStatuses ?? held.map(() => 'revoked'))
    : held.map(() => 'identityMismatch')
  exitCode = Number(state.revokeExit ?? 0)
  const safe = new Set([
    'revoked',
    'stillHeld',
    'downgraded',
    'restored',
    'alreadyOriginal',
  ])
  if (
    exitCode === 0 &&
    identityMatches &&
    statuses.every(status => safe.has(status))
  ) {
    delete state.holds?.[pid]
    delete state.holdCreateTimes?.[pid]
    persistState()
  }
  writeSync(
    1,
    JSON.stringify(
      statuses.map((status, index) => ({
        path: held[index] ?? process.execPath,
        status,
      })),
    ) + '\n',
  )
} else if (args[0] === 'wfp' && args[1] === 'verify') {
  if (state.verifyDelayMs) {
    Atomics.wait(
      new Int32Array(new SharedArrayBuffer(4)),
      0,
      0,
      state.verifyDelayMs,
    )
  }
  const targetIndex = args.indexOf('--target')
  const target = targetIndex >= 0 ? args[targetIndex + 1] : ''
  exitCode = Number(state.verifyExit ?? 0)
  writeSync(
    1,
    JSON.stringify({
      egress_probe: exitCode === 0 ? 'blocked' : 'unreachable',
      target,
    }) + '\n',
  )
} else {
  throw new Error('unexpected fake srt-win argv: ' + args.join(' '))
}

if (exitCode !== undefined) process.exitCode = exitCode
