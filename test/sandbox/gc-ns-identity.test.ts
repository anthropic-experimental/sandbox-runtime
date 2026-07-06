import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { isLinux } from '../helpers/platform.js'
import { whichSync } from '../../src/utils/which.js'

/**
 * Session-dir GC when the process's own pid-namespace identity is
 * unavailable (/proc not readable): a lock that also recorded an
 * unavailable identity is ambiguous, and a fresh ambiguous dir must be
 * age-gated, not reclaimed immediately. Runs the sweep in a child with
 * /proc masked, since the identity readlink cannot fail in-process.
 */
const nodePath = whichSync('node')
describe.if(isLinux && whichSync('bwrap') !== null && nodePath !== null)(
  'session-dir GC without namespace identity',
  () => {
    it('keeps a fresh dir whose lock lacks a usable namespace id', async () => {
      const src = resolve(
        import.meta.dir,
        '../fixtures/transparent/gc-ns-identity.ts',
      )
      const outDir = fs.mkdtempSync(join(tmpdir(), 'srt-gc-ns-'))
      try {
        const build = await Bun.build({
          entrypoints: [src],
          target: 'node',
          outdir: outDir,
        })
        expect(build.success).toBe(true)
        const bundle = build.outputs[0]!.path
        const r = spawnSync(
          'bwrap',
          [
            '--bind',
            '/',
            '/',
            '--dev',
            '/dev',
            // Mask /proc: the namespace-identity readlink fails in the
            // child, exercising the ambiguous-lock path. A private /tmp
            // and /run keep the sweep away from real session dirs.
            '--tmpfs',
            '/proc',
            '--tmpfs',
            '/run',
            '--tmpfs',
            '/tmp',
            '--bind',
            outDir,
            outDir,
            '--die-with-parent',
            '--',
            nodePath!,
            bundle,
          ],
          { encoding: 'utf8', timeout: 15000 },
        )
        expect(r.stderr ?? '').not.toContain('Error')
        expect(r.stdout).toContain('victim-survives=true')
      } finally {
        fs.rmSync(outDir, { recursive: true, force: true })
      }
    }, 30000)
  },
)
