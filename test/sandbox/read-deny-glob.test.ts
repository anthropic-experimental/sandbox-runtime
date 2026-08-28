import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  collapseReadDenyMounts,
  expandReadDenyGlobLinux,
  READ_DENY_GLOB_MOUNT_WARN_THRESHOLD,
} from '../../src/sandbox/read-deny-glob.js'
import { expandGlobPattern } from '../../src/sandbox/sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * Invariant pinned here: a denyRead glob match beneath a kept covering
 * directory gets no mount of its own (the directory's tmpfs already hides
 * it) unless an allowRead / allowWrite re-bind between the two would leave
 * it readable. A match reached through a symlink is first resolved to the
 * inode it names: a mount under the link spelling would be created inside
 * the covering tmpfs and hide nothing.
 */

describe('collapseReadDenyMounts (pure)', () => {
  it('drops matches beneath a matched directory and dedups', () => {
    const kept = collapseReadDenyMounts({
      matches: [
        '/r/pkg/a/build/1.out',
        '/r/pkg/a/build',
        '/r/pkg/a/build/sub/2.out',
        '/r/pkg/a/build/sub',
        '/r/pkg/b/build/1.out',
        '/r/pkg/b/build',
        '/r/pkg/b/build',
        '/r/top.log',
      ],
      reExposedPaths: [],
    })
    expect(kept).toEqual(['/r/pkg/a/build', '/r/pkg/b/build', '/r/top.log'])
  })

  it('does not treat a string-prefix sibling as an ancestor', () => {
    // '/r/build' must not swallow '/r/build-cache/x'.
    const kept = collapseReadDenyMounts({
      matches: ['/r/build', '/r/build-cache/x', '/r/build/y'],
      reExposedPaths: [],
    })
    expect(kept).toEqual(['/r/build', '/r/build-cache/x'])
  })

  it('keeps a descendant that an allowRead/allowWrite re-bind between it and the covering dir would re-expose', () => {
    const kept = collapseReadDenyMounts({
      matches: [
        '/r/secrets',
        '/r/secrets/public/key', // under the re-exposed /r/secrets/public
        '/r/secrets/private/key', // no re-exposer in between
        '/r/secrets/public', // AT the re-exposer: the loop re-binds it anyway
      ],
      reExposedPaths: ['/r/secrets/public', '/elsewhere'],
    })
    expect(kept).toEqual([
      '/r/secrets',
      '/r/secrets/public',
      '/r/secrets/public/key',
    ])
  })

  it('treats a re-exposer AT the covering dir as re-exposing everything beneath it', () => {
    // denyRead and allowRead naming the same dir: the tmpfs is immediately
    // re-bound, so descendants need their own mounts exactly as before.
    const kept = collapseReadDenyMounts({
      matches: ['/r/d', '/r/d/a', '/r/d/b/c'],
      reExposedPaths: ['/r/d'],
    })
    expect(kept).toEqual(['/r/d', '/r/d/a', '/r/d/b/c'])
  })

  it('ignores re-exposers that are below the candidate or unrelated', () => {
    const kept = collapseReadDenyMounts({
      matches: ['/r/d', '/r/d/a'],
      reExposedPaths: ['/r/d/a/deeper', '/r/dx', '/q'],
    })
    expect(kept).toEqual(['/r/d'])
  })

  it('is a no-op for a flat list of files', () => {
    const files = ['/r/a.log', '/r/x/b.log', '/r/x/y/c.log']
    expect(
      collapseReadDenyMounts({
        matches: files,
        reExposedPaths: [],
      }),
    ).toEqual(files)
  })
})

describe.if(!isWindows)('expandReadDenyGlobLinux (warn threshold)', () => {
  let ROOT: string
  const savedDebug = process.env.SRT_DEBUG

  beforeAll(() => {
    ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-warn-')))
    // logForDebugging only speaks under SRT_DEBUG.
    process.env.SRT_DEBUG = '1'
  })

  afterAll(() => {
    if (savedDebug === undefined) delete process.env.SRT_DEBUG
    else process.env.SRT_DEBUG = savedDebug
    rmSync(ROOT, { recursive: true, force: true })
  })

  // A flat directory of `count` files: nothing collapses into anything.
  function flatDir(name: string, count: number): string {
    const dir = join(ROOT, name)
    mkdirSync(dir)
    for (let i = 0; i < count; i++) writeFileSync(join(dir, `${i}.log`), '')
    return dir
  }

  function warningsWhile(run: () => string[]): {
    mounts: string[]
    warnings: string[]
  } {
    const warn = spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const mounts = run()
      return {
        mounts,
        warnings: warn.mock.calls.map(call => String(call[0])),
      }
    } finally {
      warn.mockRestore()
    }
  }

  it('warns when a glob still needs more mounts than the threshold after collapsing', () => {
    const dir = flatDir('over', READ_DENY_GLOB_MOUNT_WARN_THRESHOLD + 1)
    const { mounts, warnings } = warningsWhile(() =>
      expandReadDenyGlobLinux(join(dir, '*.log'), []),
    )
    expect(mounts.length).toBe(READ_DENY_GLOB_MOUNT_WARN_THRESHOLD + 1)
    expect(
      warnings.some(line =>
        line.includes(`still needs ${mounts.length} mounts`),
      ),
    ).toBe(true)
  })

  it('stays quiet at the threshold', () => {
    const dir = flatDir('at', READ_DENY_GLOB_MOUNT_WARN_THRESHOLD)
    const { mounts, warnings } = warningsWhile(() =>
      expandReadDenyGlobLinux(join(dir, '*.log'), []),
    )
    expect(mounts.length).toBe(READ_DENY_GLOB_MOUNT_WARN_THRESHOLD)
    expect(warnings).toEqual([])
  })
})

describe.if(!isWindows)(
  'expandReadDenyGlobLinux (symlinks and empty directories)',
  () => {
    let ROOT: string
    let OUTSIDE: string

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-symlink-')))
      OUTSIDE = join(ROOT, 'outside')
      mkdirSync(OUTSIDE)
      writeFileSync(join(OUTSIDE, 'secret.txt'), '')
      writeFileSync(join(OUTSIDE, 'key.pem'), '')
      // pkg/a/build: a real file plus a directory symlink and a file symlink
      // that both point outside the tree.
      mkdirSync(join(ROOT, 'pkg', 'a', 'build'), { recursive: true })
      writeFileSync(join(ROOT, 'pkg', 'a', 'build', '1.out'), '')
      symlinkSync(OUTSIDE, join(ROOT, 'pkg', 'a', 'build', 'link'))
      symlinkSync(
        join(OUTSIDE, 'key.pem'),
        join(ROOT, 'pkg', 'a', 'build', 'key.pem'),
      )
      // pkg/c/build/rel: the same target through a RELATIVE link.
      mkdirSync(join(ROOT, 'pkg', 'c', 'build'), { recursive: true })
      writeFileSync(join(ROOT, 'pkg', 'c', 'build', '1.out'), '')
      symlinkSync(
        join('..', '..', '..', 'outside'),
        join(ROOT, 'pkg', 'c', 'build', 'rel'),
      )
      // pkg/empty/build: exists but holds nothing.
      mkdirSync(join(ROOT, 'pkg', 'empty', 'build'), { recursive: true })
      // pkg/linked/build: a symlink NAMED build, to a real build dir.
      mkdirSync(join(ROOT, 'pkg', 'linked'))
      symlinkSync(
        join(ROOT, 'pkg', 'a', 'build'),
        join(ROOT, 'pkg', 'linked', 'build'),
      )
    })

    afterAll(() => {
      rmSync(ROOT, { recursive: true, force: true })
    })

    it('resolves a symlink inside a collapsed directory to its target', () => {
      // The denyRead loop emits the covering directory's tmpfs first, which
      // replaces the link with an empty directory inside the sandbox, so a
      // mount kept under the link spelling would land there and hide
      // nothing. The mount goes on the inode the link names instead.
      const build = join(ROOT, 'pkg', 'a', 'build')
      const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])

      expect(mounts).toContain(build)
      expect(mounts).not.toContain(join(build, '1.out'))
      // Directory symlink: its target is the mount, and what the listing
      // found beneath the link collapses under it.
      expect(mounts).toContain(OUTSIDE)
      expect(mounts).not.toContain(join(build, 'link'))
      expect(mounts).not.toContain(join(build, 'link', 'secret.txt'))
      // File symlink: its target, already under the resolved directory.
      expect(mounts).not.toContain(join(build, 'key.pem'))
      expect(mounts).not.toContain(join(OUTSIDE, 'key.pem'))
    })

    it('resolves a relative directory symlink the same way', () => {
      const build = join(ROOT, 'pkg', 'c', 'build')
      const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])

      expect(mounts).toContain(build)
      expect(mounts).toContain(OUTSIDE)
      expect(mounts).not.toContain(join(build, 'rel'))
      expect(mounts).not.toContain(join(build, 'rel', 'secret.txt'))
    })

    it('gives an empty matched directory no mount', () => {
      const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])
      expect(mounts).not.toContain(join(ROOT, 'pkg', 'empty', 'build'))
    })

    it('follows a link named like the pattern segment to a target listed earlier', () => {
      // proj/config/secrets -> ../vault: the target is a real directory the
      // walk reaches first by its own name, which matches nothing; the link
      // is the only spelling the pattern matches, so the walk must list
      // through it (a global visited set would not) and the mount must land
      // on the target.
      const shal = join(ROOT, 'shal')
      mkdirSync(join(shal, 'proj', 'vault'), { recursive: true })
      writeFileSync(join(shal, 'proj', 'vault', 'secret.out'), '')
      mkdirSync(join(shal, 'proj', 'config'))
      symlinkSync(join('..', 'vault'), join(shal, 'proj', 'config', 'secrets'))

      const mounts = expandReadDenyGlobLinux(join(shal, '**/secrets/**'), [])

      expect(mounts).toEqual([join(shal, 'proj', 'vault')])
    })

    it('denies through a link back to the tree and warns about it', () => {
      // build/up -> ..: a bind mount covers the inode, so the pattern denies
      // the whole tree the link reaches (as it did before the collapse); the
      // walk stops at the link, and the surprise is said out loud.
      const esc = join(ROOT, 'esc')
      mkdirSync(join(esc, 'build'), { recursive: true })
      writeFileSync(join(esc, 'build', '1.out'), '')
      symlinkSync('..', join(esc, 'build', 'up'))
      const warn = spyOn(console, 'warn').mockImplementation(() => {})
      try {
        const mounts = expandReadDenyGlobLinux(join(esc, '**/build/**'), [])

        expect(mounts).toEqual([esc])
        const warnings = warn.mock.calls.map(call => String(call[0]))
        expect(
          warnings.some(
            line =>
              line.includes('[sandbox-runtime] WARNING') &&
              line.includes(join(esc, 'build', 'up')) &&
              line.includes(`symlink to ${esc}`),
          ),
        ).toBe(true)
      } finally {
        warn.mockRestore()
      }
    })

    it('resolves a symlink named like the directory form to its target', () => {
      const linked = join(ROOT, 'pkg', 'linked', 'build')
      const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])

      expect(mounts).not.toContain(linked)
      // Its entries name inodes under the real build directory, whose own
      // mount covers them.
      expect(mounts).not.toContain(join(linked, '1.out'))
      expect(mounts).toContain(join(ROOT, 'pkg', 'a', 'build'))
    })
  },
)

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

    // The three build dirs still collapse everything else.
    for (const pkg of PKGS) {
      expect(mounts).toContain(join(ROOT, 'pkg', pkg, 'build'))
    }
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'a', 'build', '1.out'))
    expect(mounts).not.toContain(join(ROOT, 'pkg', 'b', 'build', 'nested'))
    // What the carve-out re-binds keeps its own masks, exactly as before
    // the collapse existed.
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
    // **/*.out matches files only: nothing to collapse under.
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
