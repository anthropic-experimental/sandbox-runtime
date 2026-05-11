import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Regression test: ensure allowRead (--ro-bind) is emitted before write re-bind (--bind)
describe.if(isLinux)('bwrap mount ordering for allowRead vs write re-bind', () => {
  const TEST_BASE = join(tmpdir(), 'bwrap-order-' + Date.now())
  const PARENT = join(TEST_BASE, 'parent')
  const CHILD = join(PARENT, 'child')
  const GRANDCHILD = join(CHILD, 'grandchild')

  beforeAll(() => {
    mkdirSync(GRANDCHILD, { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE)) rmSync(TEST_BASE, { recursive: true, force: true })
  })

  it('emits --ro-bind for allowRead before --bind for write re-bind', async () => {
    const cmd = await wrapCommandWithSandboxLinux({
      command: 'echo ok',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [PARENT], allowWithinDeny: [CHILD] },
      writeConfig: { allowOnly: [GRANDCHILD], denyWithinAllow: [] },
    })

    const ro = 
    const bind = 
    const roIndex = cmd.indexOf(ro)
    const bindIndex = cmd.indexOf(bind)
    expect(roIndex).toBeGreaterThanOrEqual(0)
    expect(bindIndex).toBeGreaterThanOrEqual(0)
    // ro-bind must appear before bind
    expect(roIndex).toBeLessThan(bindIndex)
  })
})

