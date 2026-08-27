import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  collapseReadDenyMounts,
  expandReadDenyGlobLinux,
  READ_DENY_GLOB_MOUNT_WARN_THRESHOLD,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { expandGlobPattern } from '../../src/sandbox/sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { isLinux } from '../helpers/platform.js'

/**
 * On Linux a denyRead glob is expanded into one bwrap mount per match. A
 * pattern like `**\/build/**` over a monorepo used to produce a
 * `--ro-bind /dev/null <file>` for every build artefact — hundreds of mounts
 * that deny nothing a single `--tmpfs <build dir>` doesn't already. The
 * expansion is now collapsed to the covering directories, except where an
 * allowRead / allowWrite re-bind in between would re-expose the descendant.
 */

describe('collapseReadDenyMounts (pure)', () => {
  it('drops matches beneath a matched directory, shallow-first, and dedups', () => {
    const kept = collapseReadDenyMounts(
      [
        '/r/pkg/a/build/1.out',
        '/r/pkg/a/build',
        '/r/pkg/a/build/sub/2.out',
        '/r/pkg/a/build/sub',
        '/r/pkg/b/build/1.out',
        '/r/pkg/b/build',
        '/r/pkg/b/build',
        '/r/top.log',
      ],
      [],
    )
    expect(kept).toEqual(['/r/top.log', '/r/pkg/a/build', '/r/pkg/b/build'])
  })

  it('does not treat a string-prefix sibling as an ancestor', () => {
    // '/r/build' must not swallow '/r/build-cache/x'.
    const kept = collapseReadDenyMounts(
      ['/r/build', '/r/build-cache/x', '/r/build/y'],
      [],
    )
    expect(kept).toEqual(['/r/build', '/r/build-cache/x'])
  })

  it('keeps a descendant that an allowRead/allowWrite re-bind between it and the covering dir would re-expose', () => {
    const kept = collapseReadDenyMounts(
      [
        '/r/secrets',
        '/r/secrets/public/key', // under the re-exposed /r/secrets/public
        '/r/secrets/private/key', // no re-exposer in between
        '/r/secrets/public', // AT the re-exposer: the loop re-binds it anyway
      ],
      ['/r/secrets/public', '/elsewhere'],
    )
    expect(kept).toEqual([
      '/r/secrets',
      '/r/secrets/public',
      '/r/secrets/public/key',
    ])
  })

  it('treats a re-exposer AT the covering dir as re-exposing everything beneath it', () => {
    // denyRead and allowRead naming the same dir: the tmpfs is immediately
    // re-bound, so descendants need their own mounts exactly as before.
    const kept = collapseReadDenyMounts(
      ['/r/d', '/r/d/a', '/r/d/b/c'],
      ['/r/d'],
    )
    expect(kept).toEqual(['/r/d', '/r/d/a', '/r/d/b/c'])
  })

  it('ignores re-exposers that are below the candidate or unrelated', () => {
    const kept = collapseReadDenyMounts(
      ['/r/d', '/r/d/a'],
      ['/r/d/a/deeper', '/r/dx', '/q'],
    )
    expect(kept).toEqual(['/r/d'])
  })

  it('is a no-op for a flat list of files', () => {
    const files = ['/r/a.log', '/r/x/b.log', '/r/x/y/c.log']
    expect(collapseReadDenyMounts(files, [])).toEqual(files)
  })

  it('exposes a named warning threshold', () => {
    expect(READ_DENY_GLOB_MOUNT_WARN_THRESHOLD).toBe(256)
  })
})

describe.if(isLinux)('expandReadDenyGlobLinux (filesystem)', () => {
  let ROOT: string
  const PKGS = ['a', 'b', 'c']

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-collapse-')))
    // pkg/{a,b,c}/build/{1..5}.out plus a nested dir and a source file each
    for (const pkg of PKGS) {
      const build = join(ROOT, 'pkg', pkg, 'build')
      mkdirSync(join(build, 'nested'), { recursive: true })
      for (let i = 1; i <= 5; i++) writeFileSync(join(build, `${i}.out`), '')
      writeFileSync(join(build, 'nested', 'deep.out'), '')
      writeFileSync(join(ROOT, 'pkg', pkg, 'index.ts'), '')
    }
    // A FILE named build must not be swept up by the directory form.
    writeFileSync(join(ROOT, 'pkg', 'build'), '')
    // Something for an allowRead carve-out to re-expose.
    mkdirSync(join(ROOT, 'pkg', 'a', 'build', 'public'))
    writeFileSync(join(ROOT, 'pkg', 'a', 'build', 'public', 'ok.txt'), '')
  })

  afterAll(() => {
    rmSync(ROOT, { recursive: true, force: true })
  })

  it('collapses <root>/**/build/** to one mount per build directory', () => {
    const pattern = join(ROOT, '**/build/**')
    // Baseline: the raw expansion is every entry beneath every build dir.
    expect(expandGlobPattern(pattern).length).toBeGreaterThanOrEqual(15)

    const mounts = expandReadDenyGlobLinux(pattern, [])

    expect(mounts).toEqual(PKGS.map(pkg => join(ROOT, 'pkg', pkg, 'build')))
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'build'))
  })

  it('keeps per-entry mounts under an allowRead carve-out inside a collapsed dir', () => {
    const pattern = join(ROOT, '**/build/**')
    const carveOut = join(ROOT, 'pkg', 'a', 'build', 'public')

    const mounts = expandReadDenyGlobLinux(pattern, [carveOut])

    // The three build dirs still collapse everything else...
    for (const pkg of PKGS) {
      expect(mounts).toContain(join(ROOT, 'pkg', pkg, 'build'))
    }
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'a', 'build', '1.out'))
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'b', 'build', 'nested'))
    // ...but what the carve-out re-binds keeps its own masks, exactly as
    // before the collapse existed.
    expect(mounts).toContain(carveOut)
    expect(mounts).toContain(join(carveOut, 'ok.txt'))
  })

  it('accepts re-exposers in un-normalized spellings', () => {
    const pattern = join(ROOT, '**/build/**')
    const carveOut = join(ROOT, 'pkg', 'a', 'build', 'public')

    const mounts = expandReadDenyGlobLinux(pattern, [carveOut + '/'])

    expect(mounts).toContain(join(carveOut, 'ok.txt'))
  })

  it('leaves a pattern without a trailing /** to collapse only among its own matches', () => {
    // **/*.out matches files only — nothing to collapse under.
    const pattern = join(ROOT, '**/*.out')
    const mounts = expandReadDenyGlobLinux(pattern, [])
    expect(mounts.length).toBe(expandGlobPattern(pattern).length)
    expect(mounts.length).toBe(PKGS.length * 6)
  })

  it('reaches bwrap as directory tmpfs mounts, and a non-glob deny is untouched', async () => {
    const literalFile = join(ROOT, 'pkg', 'a', 'index.ts')
    try {
      const wrapped = await SandboxManager.wrapWithSandbox(
        'echo hello',
        undefined,
        {
          filesystem: {
            denyRead: [join(ROOT, '**/build/**'), literalFile],
            allowWrite: [],
            denyWrite: [],
          },
        },
      )

      for (const pkg of PKGS) {
        expect(wrapped).toContain(`--tmpfs ${join(ROOT, 'pkg', pkg, 'build')}`)
      }
      // No per-artefact masks under the collapsed dirs.
      for (const pkg of PKGS) {
        expect(wrapped).not.toContain(
          `--ro-bind /dev/null ${join(ROOT, 'pkg', pkg, 'build')}/`,
        )
      }
      // The literal entry is passed through as-is: one file mask.
      expect(wrapped).toContain(`--ro-bind /dev/null ${literalFile}`)
    } finally {
      await SandboxManager.reset()
    }
  })
})
