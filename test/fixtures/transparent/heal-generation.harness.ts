// Child-process harness (run explicitly: bun test ./<this file>). Kept
// out of the *.test.* discovery pattern on purpose: mock.module is
// process-global in bun, so this interception must never share a
// process with the rest of the suite. Driven by
// test/sandbox/heal-generation.test.ts.
import { describe, it, expect, mock } from 'bun:test'
import * as fs from 'node:fs'
import { connect } from 'node:net'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dir, '../../..')
const real = await import(`${ROOT}/src/sandbox/linux-sandbox-utils.js`)
const realInit = real.initializeNetnsRendezvous
const created: Array<{ socketPath: string; close: () => Promise<void> }> = []
let delayNext = false

void mock.module(`${ROOT}/src/sandbox/linux-sandbox-utils.js`, () => ({
  ...real,
  initializeNetnsRendezvous: async (token: string) => {
    if (delayNext) {
      delayNext = false
      await new Promise(r => setTimeout(r, 600))
    }
    const ctx = await realInit(token)
    created.push(ctx)
    return ctx
  },
}))

const { SandboxManager } = await import(
  `${ROOT}/src/sandbox/sandbox-manager.js`
)

const config = {
  network: { allowedDomains: ['example.com'], deniedDomains: [] },
  filesystem: { denyRead: [], allowWrite: ['/tmp'], denyWrite: [] },
}

function canConnect(path: string): Promise<boolean> {
  return new Promise(resolvePromise => {
    const s = connect(path)
    s.once('connect', () => {
      s.destroy()
      resolvePromise(true)
    })
    s.once('error', () => resolvePromise(false))
  })
}

describe('re-initialize during rendezvous recovery', () => {
  it('a recovery started under a previous lifecycle generation does not complete', async () => {
    await SandboxManager.initialize(config)
    expect(created.length).toBe(1)
    const original = created[0]!

    // External deletion of the socket triggers recovery at next wrap.
    fs.rmSync(original.socketPath, { force: true })
    delayNext = true // widen the recovery window

    const wrapP = SandboxManager.wrapWithSandbox('true').then(
      () => 'wrap-ok',
      (e: Error) => `wrap-error: ${e.message}`,
    )
    await new Promise(r => setTimeout(r, 150))

    // Full lifecycle swap while the recovery is in flight.
    await SandboxManager.reset()
    await SandboxManager.initialize(config)

    const wrapOutcome = await wrapP
    expect(wrapOutcome).toContain('reset during rendezvous recovery')

    // After tearing down the current generation nothing may still be
    // listening: every rendezvous ever created must be closed.
    await SandboxManager.reset()
    let open = 0
    for (const c of created) {
      if (await canConnect(c.socketPath)) open++
    }
    expect(open).toBe(0)
  }, 30000)
})
