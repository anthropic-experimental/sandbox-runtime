import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Only meaningful inside an unprivileged container where bwrap --proc /proc
// fails. The docker CI job sets SANDBOX_RUNTIME_DOCKER_TEST=1.
const inDockerTarget =
  isLinux && process.env.SANDBOX_RUNTIME_DOCKER_TEST === '1'

describe.if(inDockerTarget)(
  'enableWeakerNestedSandbox in unprivileged container',
  () => {
    let scratch: string

    beforeAll(() => {
      scratch = mkdtempSync(join(tmpdir(), 'weak-sandbox-'))
    })

    afterAll(() => {
      rmSync(scratch, { recursive: true, force: true })
    })

    async function runWeak(command: string, allowAllUnixSockets = false) {
      const wrapped = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig: { allowOnly: [scratch], denyWithinAllow: [] },
        enableWeakerNestedSandbox: true,
        allowAllUnixSockets,
      })
      const r = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })
      if (r.status !== 0 && r.status !== null) {
        // Surface the actual failure in CI logs — most useful line first.
        console.error('stderr:', r.stderr)
        console.error('wrapped:', wrapped)
      }
      return { ...r, wrapped }
    }

    it('apply-seccomp can set up its nested userns with /proc ro-bound', async () => {
      const r = await runWeak('echo hello')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('hello')
    })

    it('inner /proc is isolated — user command cannot see host PIDs', async () => {
      // apply-seccomp remounts /proc in its inner namespace regardless of
      // enableWeakerNestedSandbox. If it didn't, this would report dozens+
      // of PIDs from the container.
      const r = await runWeak('ls -d /proc/[0-9]* | wc -l')
      expect(r.status).toBe(0)
      const pidCount = parseInt(r.stdout.trim(), 10)
      expect(pidCount).toBeLessThanOrEqual(5)
    })

    it('seccomp filter is still applied — AF_UNIX blocked', async () => {
      const r = await runWeak(
        `python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"`,
      )
      expect(r.status).not.toBe(0)
      expect(r.stderr.toLowerCase()).toMatch(
        /permission denied|operation not permitted/,
      )
    })

    it('allowAllUnixSockets skips apply-seccomp and the /proc bind', async () => {
      const r = await runWeak('echo no-seccomp', true)
      expect(r.wrapped).not.toContain('apply-seccomp')
      expect(r.wrapped).not.toContain('--bind /proc')
      expect(r.status).toBe(0)
      expect(r.stdout).toContain('no-seccomp')
    })
  },
)
