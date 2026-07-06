import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import {
  hasTransparentPrereqs,
  canListenUnixSockets,
} from '../helpers/transparent.js'

/**
 * Lifecycle test for the rendezvous recovery path: reset() followed by a
 * fresh initialize() while a recovery is in flight must fail the stale
 * wrap and leave no stray listeners. Runs in a child process because the
 * harness intercepts module loading (process-global in bun).
 */
describe.if(hasTransparentPrereqs() && canListenUnixSockets())(
  'rendezvous recovery across lifecycle generations',
  () => {
    it('child harness passes', () => {
      const harness = resolve(
        import.meta.dir,
        '../fixtures/transparent/heal-generation.harness.ts',
      )
      const r = spawnSync(process.execPath, ['test', harness], {
        encoding: 'utf8',
        timeout: 60000,
      })
      if (r.status !== 0) console.log(r.stdout, r.stderr)
      expect(r.status).toBe(0)
    }, 90000)
  },
)
