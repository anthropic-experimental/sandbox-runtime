import { describe, it, expect, afterEach, spyOn } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as fs from 'fs'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// The ancestor-pin walk distinguishes absence (ENOENT/ENOTDIR) from other
// errnos: an unreadable ancestor is still pinned, while a pin whose path
// component cannot be lstat'ed is dropped without aborting the wrap. Errnos
// are injected via fs spies (a root container sees no real EACCES); each spy
// asserts its own hit count so a non-intercepting mock cannot pass
// vacuously. Nothing here executes bwrap.
describe.if(isLinux)(
  'Linux sandbox — ancestor-pin errno discrimination',
  () => {
    const errnoError = (code: string, message: string) =>
      Object.assign(new Error(message), { code })
    const EACCES = () => errnoError('EACCES', 'EACCES: permission denied')

    const created: string[] = []
    const spies: Array<{ mockRestore: () => void }> = []
    afterEach(() => {
      for (const spy of spies.splice(0)) spy.mockRestore()
      for (const dir of created.splice(0)) {
        rmSync(dir, { recursive: true, force: true })
      }
    })

    function makeTree(): string {
      // proj/a/b/.git/config — pins expected for a, a/b, a/b/.git
      const proj = realpathSync(mkdtempSync(join(tmpdir(), 'pin-errno-')))
      created.push(proj)
      mkdirSync(join(proj, 'a', 'b', '.git'), { recursive: true })
      writeFileSync(join(proj, 'a', 'b', '.git', 'config'), '[core]\n')
      return proj
    }

    async function wrap(
      proj: string,
      extra: Partial<Parameters<typeof wrapCommandWithSandboxLinux>[0]> = {},
    ): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        allowAllUnixSockets: true,
        writeConfig: {
          allowOnly: [proj],
          denyWithinAllow: [join(proj, 'a', 'b', '.git', 'config')],
        },
        ...extra,
      })
    }

    it('baseline: ancestors of a denyWrite target are pinned', async () => {
      const proj = makeTree()
      const wrapped = await wrap(proj)
      const pin = join(proj, 'a', 'b')
      expect(wrapped).toContain(`--ro-bind ${pin} ${pin}`)
    })

    it('pins an ancestor whose stat fails with EACCES', async () => {
      const proj = makeTree()
      const target = join(proj, 'a', 'b')
      const realStat = fs.statSync
      const realExists = fs.existsSync
      let statHits = 0
      let existsHits = 0
      spies.push(
        spyOn(fs, 'statSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) => {
          if (String(p) === target) {
            statHits++
            throw EACCES()
          }
          return (realStat as (...a: unknown[]) => unknown)(p, ...rest)
        }) as typeof fs.statSync),
      )
      spies.push(
        spyOn(fs, 'existsSync').mockImplementation(((p: fs.PathLike) => {
          if (String(p) === target) {
            existsHits++
            return false
          }
          return realExists(p)
        }) as typeof fs.existsSync),
      )
      const wrapped = await wrap(proj)
      expect(statHits + existsHits).toBeGreaterThan(0)
      expect(wrapped).toContain(`--ro-bind ${target} ${target}`)
    })

    it('skips the pin of a genuinely absent (ENOENT) ancestor', async () => {
      const proj = makeTree()
      const missingParent = join(proj, 'a', 'missing')
      const wrapped = await wrap(proj, {
        writeConfig: {
          allowOnly: [proj],
          denyWithinAllow: [join(missingParent, 'leaf')],
        },
      })
      expect(wrapped).not.toContain(
        `--ro-bind ${missingParent} ${missingParent}`,
      )
    })

    it('does not abort on an unverifiable (EACCES) pin component; drops every pin through it', async () => {
      const proj = makeTree()
      const component = join(proj, 'a')
      const realLstat = fs.lstatSync
      let lstatHits = 0
      spies.push(
        spyOn(fs, 'lstatSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) => {
          if (String(p) === component) {
            lstatHits++
            throw EACCES()
          }
          return (realLstat as (...a: unknown[]) => unknown)(p, ...rest)
        }) as typeof fs.lstatSync),
      )
      const wrapped = await wrap(proj)
      expect(lstatHits).toBeGreaterThan(0)
      expect(wrapped).toContain('bwrap')
      // Every pin on the chain passes through the unverifiable component.
      for (const dir of [
        component,
        join(proj, 'a', 'b'),
        join(proj, 'a', 'b', '.git'),
      ]) {
        expect(wrapped).not.toContain(`--ro-bind ${dir} ${dir}`)
      }
      // The deny bind itself is unaffected.
      const cfg = join(proj, 'a', 'b', '.git', 'config')
      expect(wrapped).toContain(`--ro-bind ${cfg} ${cfg}`)
    })

    it('drops only the pin when a component vanished (ENOENT) and still builds the wrap', async () => {
      const proj = makeTree()
      const component = join(proj, 'a')
      const realLstat = fs.lstatSync
      spies.push(
        spyOn(fs, 'lstatSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) => {
          if (String(p) === component) {
            throw errnoError('ENOENT', 'ENOENT: no such file or directory')
          }
          return (realLstat as (...a: unknown[]) => unknown)(p, ...rest)
        }) as typeof fs.lstatSync),
      )
      const wrapped = await wrap(proj)
      expect(wrapped).not.toContain(`--ro-bind ${component} ${component}`)
      expect(wrapped).toContain('bwrap')
    })

    it('seeds ancestors of a denyRead file whose first stat fails with EACCES', async () => {
      const proj = makeTree()
      mkdirSync(join(proj, 'secrets'))
      const denyReadFile = join(proj, 'secrets', 'token')
      writeFileSync(denyReadFile, 'x')
      const realStat = fs.statSync
      let statHits = 0
      // Permission flip: unreadable while the seed walk stats (first), readable
      // again when the denyRead loop stats and emits the mask.
      let failedOnce = false
      spies.push(
        spyOn(fs, 'statSync').mockImplementation(((
          p: fs.PathLike,
          ...rest: unknown[]
        ) => {
          if (String(p) === denyReadFile && !failedOnce) {
            failedOnce = true
            statHits++
            throw EACCES()
          }
          return (realStat as (...a: unknown[]) => unknown)(p, ...rest)
        }) as typeof fs.statSync),
      )
      const wrapped = await wrap(proj, {
        readConfig: { denyOnly: [denyReadFile], allowWithinDeny: [] },
      })
      const seedAncestor = join(proj, 'secrets')
      expect(statHits).toBeGreaterThan(0)
      expect(wrapped).toContain(`--ro-bind ${seedAncestor} ${seedAncestor}`)
    })

    it('seeds ancestors of a FIFO denyRead entry (every non-directory is masked)', async () => {
      const proj = makeTree()
      mkdirSync(join(proj, 'secrets'))
      const fifoPath = join(proj, 'secrets', 'pipe.fifo')
      const mk = spawnSync('mkfifo', [fifoPath])
      if (mk.status !== 0) {
        throw new Error('mkfifo unavailable')
      }
      const wrapped = await wrap(proj, {
        readConfig: { denyOnly: [fifoPath], allowWithinDeny: [] },
      })
      const seedAncestor = join(proj, 'secrets')
      expect(wrapped).toContain(`--ro-bind ${seedAncestor} ${seedAncestor}`)
      expect(wrapped).toContain(`--ro-bind /dev/null ${fifoPath}`)
    })

    it('seeds nothing for a genuinely absent denyRead file', async () => {
      const proj = makeTree()
      const absent = join(proj, 'secrets', 'gone')
      const wrapped = await wrap(proj, {
        readConfig: { denyOnly: [absent], allowWithinDeny: [] },
      })
      const seedAncestor = join(proj, 'secrets')
      expect(wrapped).not.toContain(`--ro-bind ${seedAncestor} ${seedAncestor}`)
    })
  },
)
