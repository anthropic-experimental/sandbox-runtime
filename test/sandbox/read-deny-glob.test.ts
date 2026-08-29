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
 * it readable, or a symlink between the two would leave the covering tmpfs
 * short of the inode.
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
      collapseReadDenyMounts({ matches: files, reExposedPaths: [] }),
    ).toEqual(files)
  })

  it('matches a re-exposer against the resolved spelling of a match reached through a link', () => {
    // /r/link -> /real. The carve-out is written in the resolved spelling;
    // the match under the link must still keep its own mount.
    const kept = collapseReadDenyMounts({
      matches: ['/r/link', '/r/link/public', '/r/link/public/x', '/r/link/y'],
      reExposedPaths: ['/real/public'],
      canonical: new Map([
        ['/r/link', '/real'],
        ['/r/link/public', '/real/public'],
        ['/r/link/public/x', '/real/public/x'],
        ['/r/link/y', '/real/y'],
      ]),
    })
    expect(kept).toEqual(['/r/link', '/r/link/public', '/r/link/public/x'])
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

describe.if(!isWindows)('expandReadDenyGlobLinux (symlinks)', () => {
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

  it('mounts a symlink beneath a collapsed directory at its target', () => {
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

  it('keeps a directory symlink that is itself the covering directory on its spelling', () => {
    // pkg/linked/build -> pkg/a/build: nothing above the link is denied, so
    // its own tmpfs resolves through it and covers what lies beneath. The
    // spelling stays, as it does for a literal directory deny, so carve-outs
    // written against the link still match.
    const linked = join(ROOT, 'pkg', 'linked', 'build')
    const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])

    expect(mounts).toContain(linked)
    expect(mounts).not.toContain(join(linked, '1.out'))
    expect(mounts).toContain(join(ROOT, 'pkg', 'a', 'build'))
  })

  it('keeps a link named like the pattern segment on its spelling', () => {
    // proj/config/secrets -> ../vault: the target is a real directory the
    // walk reaches first by its own name, which matches nothing; the link
    // is the only spelling the pattern matches, so the walk must list
    // through it (a global visited set would not), and the mount lands on
    // the link, which bwrap resolves.
    const shal = join(ROOT, 'shal')
    mkdirSync(join(shal, 'proj', 'vault'), { recursive: true })
    writeFileSync(join(shal, 'proj', 'vault', 'secret.out'), '')
    mkdirSync(join(shal, 'proj', 'config'))
    symlinkSync(join('..', 'vault'), join(shal, 'proj', 'config', 'secrets'))

    const mounts = expandReadDenyGlobLinux(join(shal, '**/secrets/**'), [])

    expect(mounts).toEqual([join(shal, 'proj', 'config', 'secrets')])
  })

  it('denies through a link back to the tree', () => {
    // build/up -> ..: the link sits beneath the covering build tmpfs, so its
    // target is mounted instead, which is the whole tree the link reaches;
    // the walk itself stops at the link.
    const esc = join(ROOT, 'esc')
    mkdirSync(join(esc, 'build'), { recursive: true })
    writeFileSync(join(esc, 'build', '1.out'), '')
    symlinkSync('..', join(esc, 'build', 'up'))

    const mounts = expandReadDenyGlobLinux(join(esc, '**/build/**'), [])

    expect(mounts).toEqual([esc])
  })

  describe('carve-out through a symlink (pnpm layout)', () => {
    // node_modules/foo -> ../.pnpm/foo@1/node_modules/foo, the shape pnpm
    // installs; the glob matches both the link and the real tree.
    let P: string
    let real: string
    let link: string
    beforeAll(() => {
      P = join(ROOT, 'pnpm')
      real = join(P, '.pnpm', 'foo@1', 'node_modules', 'foo')
      link = join(P, 'node_modules', 'foo')
      mkdirSync(join(real, 'public'), { recursive: true })
      writeFileSync(join(real, 'index.js'), '')
      writeFileSync(join(real, 'public', 'ok.txt'), '')
      mkdirSync(join(P, 'node_modules'))
      symlinkSync(join('..', '.pnpm', 'foo@1', 'node_modules', 'foo'), link)
    })

    it('keeps the carve-out written against the link spelling', () => {
      const mounts = expandReadDenyGlobLinux(
        join(P, '**/node_modules/foo/**'),
        [join(link, 'public')],
      )

      expect(mounts).toContain(link)
      expect(mounts).not.toContain(join(link, 'index.js'))
      expect(mounts).toContain(join(link, 'public'))
      expect(mounts).toContain(join(link, 'public', 'ok.txt'))
      // The real tree, matched in its own right, keeps its carve-out too.
      expect(mounts).toContain(real)
      expect(mounts).toContain(join(real, 'public', 'ok.txt'))
    })

    it('keeps the carve-out written against the resolved spelling', () => {
      const mounts = expandReadDenyGlobLinux(
        join(P, '**/node_modules/foo/**'),
        [join(real, 'public')],
      )

      expect(mounts).toContain(link)
      expect(mounts).not.toContain(join(link, 'index.js'))
      expect(mounts).toContain(join(link, 'public'))
      expect(mounts).toContain(join(link, 'public', 'ok.txt'))
    })
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

  it('normalizes an allowRead carve-out spelling before collapsing against it', async () => {
    // Re-exposers reach expandReadDenyGlobLinux already normalized; the
    // wrapper strips the trailing slash, so the carve-out still keeps the
    // file's own mask beneath the collapsed build tmpfs.
    const carveOut = join(ROOT, 'pkg', 'a', 'build', 'public')
    try {
      const wrapped = await SandboxManager.wrapWithSandbox(
        'echo hello',
        undefined,
        {
          filesystem: {
            denyRead: [join(ROOT, '**/build/**')],
            allowRead: [carveOut + '/'],
            allowWrite: [],
            denyWrite: [],
          },
        },
      )

      expect(wrapped).toContain(`--tmpfs ${join(ROOT, 'pkg', 'a', 'build')}`)
      expect(wrapped).toContain(
        `--ro-bind /dev/null ${join(carveOut, 'ok.txt')}`,
      )
      expect(wrapped).not.toContain(
        `--ro-bind /dev/null ${join(ROOT, 'pkg', 'b', 'build')}/`,
      )
    } finally {
      await SandboxManager.reset()
    }
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
