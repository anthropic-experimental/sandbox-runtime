import { describe, it, expect, afterEach } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// Arg-level checks of the read-section record the emission filter replays:
// the restore veto counts only mounts already emitted, the filter reads the
// record of restores actually made, and symlink-spelled file masks seed pins
// at their canonical location and are re-applied when a pin buries them.
describe.if(isLinux)('Linux sandbox — mount-plan record and ordering', () => {
  const baseParams = {
    command: 'true',
    needsNetworkRestriction: false,
    allowAllUnixSockets: true,
  }

  const created: string[] = []
  afterEach(() => {
    for (const dir of created.splice(0)) {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  function tempTree(files: Record<string, string>): string {
    const proj = realpathSync(mkdtempSync(join(tmpdir(), 'mount-plan-')))
    created.push(proj)
    for (const [rel, content] of Object.entries(files)) {
      mkdirSync(dirname(join(proj, rel)), { recursive: true })
      writeFileSync(join(proj, rel), content)
    }
    return proj
  }

  it('preserves a carve-out under a denyRead dir when the inner deny mounts later', async () => {
    const proj = tempTree({ 'data/build/logs/keep.txt': 'x' })
    const data = join(proj, 'data')
    const build = join(proj, 'data', 'build')
    const logs = join(proj, 'data', 'build', 'logs')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [data, logs], allowWithinDeny: [] },
      writeConfig: { allowOnly: [build], denyWithinAllow: [] },
    })
    // The restore is a second occurrence of the allowWrite bind, after the
    // outer tmpfs; the deeper tmpfs mounts after the restore and on top.
    const bind = `--bind ${build} ${build}`
    const restoreIdx = wrapped.lastIndexOf(bind)
    expect(restoreIdx).toBeGreaterThan(wrapped.indexOf(`--tmpfs ${data}`))
    expect(wrapped.indexOf(`--tmpfs ${logs}`)).toBeGreaterThan(restoreIdx)
  })

  it('drops ancestor pins whose carve-out restore was vetoed', async () => {
    const proj = tempTree({
      'a/t/w/secret-dir/s.txt': 'x',
      'a/t/w/deep/file.txt': 'x',
    })
    // Raw spelling sorts shallow; canonical target is deep inside the
    // carve-out, so the carve-out's restore would bury it.
    symlinkSync(join(proj, 'a/t/w/secret-dir'), join(proj, 's'))
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'a/t')],
        allowWithinDeny: [],
      },
      writeConfig: {
        allowOnly: [join(proj, 'a/t/w')],
        denyWithinAllow: [join(proj, 'a/t/w/deep/file.txt')],
      },
    })
    const wBind = `--bind ${join(proj, 'a/t/w')} ${join(proj, 'a/t/w')}`
    expect(wrapped.lastIndexOf(wBind)).toBeLessThan(
      wrapped.indexOf(`--tmpfs ${join(proj, 'a/t')}`),
    )
    expect(wrapped).not.toContain(
      `--bind ${join(proj, 'a/t/w/deep')} ${join(proj, 'a/t/w/deep')}`,
    )
  })

  it('emits a deny bind whose region a later unit re-exposed', async () => {
    const proj = tempTree({ 'p/q/w/.git/config': 'x' })
    const W = join(proj, 'p/q/w')
    const cfg = join(proj, 'p/q/w/.git/config')
    // s hides W first; p/q hides it again with its restore vetoed; W's own
    // unit then re-binds W host content, so the deny bind is still needed.
    symlinkSync(W, join(proj, 's'))
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'p/q'), W],
        allowWithinDeny: [],
      },
      writeConfig: { allowOnly: [W], denyWithinAllow: [cfg] },
    })
    const wBind = `--bind ${W} ${W}`
    expect(wrapped.lastIndexOf(wBind)).toBeGreaterThan(
      wrapped.indexOf(`--tmpfs ${W}`),
    )
    expect(wrapped).toContain(`--ro-bind ${cfg} ${cfg}`)
    expect(wrapped).toContain(
      `--bind ${join(proj, 'p/q/w/.git')} ${join(proj, 'p/q/w/.git')}`,
    )
  })

  it('keeps a symlink-spelled file mask when a denyWrite names its canonical location', async () => {
    const proj = tempTree({ 'data/secrets/key.pem': 'SECRET' })
    symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'))
    const rawSpelling = join(proj, 'secrets', 'key.pem')
    const canonical = join(proj, 'data', 'secrets', 'key.pem')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [rawSpelling], allowWithinDeny: [] },
      writeConfig: { allowOnly: [proj], denyWithinAllow: [canonical] },
    })
    expect(wrapped).toContain(`--ro-bind /dev/null ${rawSpelling}`)
    expect(wrapped).not.toContain(`--ro-bind ${canonical} ${canonical}`)
  })

  it('emits a deny bind whose raw route is buried but whose canonical location is exposed', async () => {
    const proj = tempTree({ 'x/W/secret': 'SECRET', 'z/foo': 'host-content' })
    // W's restore is vetoed (an earlier-sorted mask sits inside it), so the
    // raw route reads as covered, but the bind mounts at the canonical dest.
    symlinkSync(join(proj, 'x/W/secret'), join(proj, 's'))
    symlinkSync(join(proj, 'z'), join(proj, 'x/W/link2'))
    const canonicalFoo = join(proj, 'z', 'foo')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: {
        denyOnly: [join(proj, 's'), join(proj, 'x')],
        allowWithinDeny: [],
      },
      writeConfig: {
        allowOnly: [proj, join(proj, 'x/W')],
        denyWithinAllow: [join(proj, 'x/W/link2/foo')],
      },
    })
    expect(wrapped).toContain(`--ro-bind /dev/null ${join(proj, 'x/W/secret')}`)
    expect(wrapped).toContain(`--ro-bind ${canonicalFoo} ${canonicalFoo}`)
  })

  it('pins the canonical parents of a symlink-spelled denyRead file mask and re-applies the buried mask', async () => {
    const proj = tempTree({
      'data/secrets/key.pem': 'SECRET',
      'data/other/thing.txt': 'x',
    })
    symlinkSync(join(proj, 'data/secrets'), join(proj, 'secrets'))
    const rawSpelling = join(proj, 'secrets', 'key.pem')
    const canonicalParent = join(proj, 'data', 'secrets')
    const wrapped = await wrapCommandWithSandboxLinux({
      ...baseParams,
      readConfig: { denyOnly: [rawSpelling], allowWithinDeny: [] },
      writeConfig: {
        allowOnly: [proj],
        denyWithinAllow: [join(proj, 'data/other/thing.txt')],
      },
    })
    expect(wrapped).toContain(`--bind ${canonicalParent} ${canonicalParent}`)
    expect(wrapped).toContain(
      `--bind ${join(proj, 'data')} ${join(proj, 'data')}`,
    )
    const maskBind = `--ro-bind /dev/null ${rawSpelling}`
    const first = wrapped.indexOf(maskBind)
    expect(first).toBeGreaterThan(-1)
    expect(wrapped.lastIndexOf(maskBind)).toBeGreaterThan(first)
  })
})
