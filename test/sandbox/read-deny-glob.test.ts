import { describe, it, expect, beforeAll, afterAll, spyOn } from 'bun:test'
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  collapseReadDenyMounts,
  expandReadDenyGlobLinux,
  READ_DENY_GLOB_MOUNT_WARN_THRESHOLD,
} from '../../src/sandbox/read-deny-glob.js'
import { expandGlobPattern } from '../../src/sandbox/sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import {
  wrapCommandWithSandboxLinux,
  cleanupBwrapMountPoints,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux, isWindows } from '../helpers/platform.js'

/**
 * Invariant pinned here: a denyRead glob match beneath a kept covering
 * directory gets no mount of its own (the directory's tmpfs already hides
 * it) unless an allowRead / allowWrite re-bind between the two would leave
 * it readable. A match reached through a symlink is listed in its resolved
 * spelling too, so the inode stays denied where the link itself vanishes,
 * and the deny loop mounts every directory at its resolved path.
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
    // nothing. The target is listed in its own right and kept instead.
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

  it('keeps the resolved carve-out beneath a link strictly below the covering directory', () => {
    // pkg/a/build/link -> outside, with allowRead written against the
    // target: outside/ is denied as a whole, its carve-out and the
    // entries beneath keep their own mounts, and nothing else beneath it.
    mkdirSync(join(OUTSIDE, 'pub'))
    writeFileSync(join(OUTSIDE, 'pub', 'x.txt'), '')
    const mounts = expandReadDenyGlobLinux(
      join(ROOT, 'pkg', 'a', '**/build/**'),
      [join(OUTSIDE, 'pub')],
    )

    expect(mounts).toContain(join(ROOT, 'pkg', 'a', 'build'))
    expect(mounts).toContain(OUTSIDE)
    expect(mounts).toContain(join(OUTSIDE, 'pub'))
    expect(mounts).toContain(join(OUTSIDE, 'pub', 'x.txt'))
    expect(mounts).not.toContain(join(OUTSIDE, 'secret.txt'))
    rmSync(join(OUTSIDE, 'pub'), { recursive: true })
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

  it('lists a directory symlink that is itself the covering directory in both spellings', () => {
    // pkg/linked/build -> pkg/a/build: the link spelling stays, as it does
    // for a literal directory deny, so carve-outs written against the link
    // still match; the deny loop mounts it at the target and drops the
    // second spelling of the same inode.
    const linked = join(ROOT, 'pkg', 'linked', 'build')
    const mounts = expandReadDenyGlobLinux(join(ROOT, '**/build/**'), [])

    expect(mounts).toContain(linked)
    expect(mounts).not.toContain(join(linked, '1.out'))
    expect(mounts).toContain(join(ROOT, 'pkg', 'a', 'build'))
  })

  it('lists a link named like the pattern segment with its target', () => {
    // proj/config/secrets -> ../vault: the target is a real directory the
    // walk reaches first by its own name, which matches nothing; the link
    // is the only spelling the pattern matches, so the walk must list
    // through it (a global visited set would not). The target is where the
    // mount lands.
    const shal = join(ROOT, 'shal')
    mkdirSync(join(shal, 'proj', 'vault'), { recursive: true })
    writeFileSync(join(shal, 'proj', 'vault', 'secret.out'), '')
    mkdirSync(join(shal, 'proj', 'config'))
    symlinkSync(join('..', 'vault'), join(shal, 'proj', 'config', 'secrets'))

    const mounts = expandReadDenyGlobLinux(join(shal, '**/secrets/**'), [])

    expect(mounts).toEqual([
      join(shal, 'proj', 'config', 'secrets'),
      join(shal, 'proj', 'vault'),
    ])
  })

  it('lists every match in its resolved spelling too when the base is a symlink', () => {
    // alias -> ROOT, sideways: normalizePathForSandbox keeps the link
    // spelling for the pattern, so a carve-out written in ROOT spelling
    // would match nothing without the resolved twins.
    const alias = join(
      ROOT,
      '..',
      `alias-${Math.random().toString(36).slice(2)}`,
    )
    symlinkSync(ROOT, alias)
    try {
      const build = join('pkg', 'a', 'build')
      const carveOut = join(ROOT, build, 'public')
      mkdirSync(carveOut, { recursive: true })
      writeFileSync(join(carveOut, 'ok.txt'), '')
      const mounts = expandReadDenyGlobLinux(join(alias, '**/build/**'), [
        carveOut,
      ])

      expect(mounts).toContain(join(alias, build))
      expect(mounts).toContain(join(ROOT, build))
      expect(mounts).toContain(carveOut)
      expect(mounts).toContain(join(carveOut, 'ok.txt'))
      expect(mounts).not.toContain(join(alias, build, '1.out'))
    } finally {
      rmSync(alias)
      rmSync(join(ROOT, 'pkg', 'a', 'build', 'public'), { recursive: true })
    }
  })

  it('never denies the root through a link to it', () => {
    // build/root -> /: the resolved spelling would expand to a tmpfs over
    // every top-level directory. The link keeps its spelling; bwrap refuses
    // to mount on it.
    const rooted = join(ROOT, 'rooted')
    mkdirSync(join(rooted, 'build'), { recursive: true })
    writeFileSync(join(rooted, 'build', '1.out'), '')
    symlinkSync('/', join(rooted, 'build', 'root'))

    const mounts = expandReadDenyGlobLinux(join(rooted, '**/build/**'), [])

    expect(mounts).toEqual([join(rooted, 'build')])
  })

  it('denies the target of a directory-form link the walk did not descend', () => {
    // u/x/y/build -> u/x names a directory on its own descent chain, so the
    // walk lists nothing beneath it; it is still a match, and its target is
    // what a literal deny of the link would deny.
    const u = join(ROOT, 'u')
    mkdirSync(join(u, 'x', 'y'), { recursive: true })
    writeFileSync(join(u, 'x', 'src.ts'), '')
    symlinkSync(join('..'), join(u, 'x', 'y', 'build'))

    const mounts = expandReadDenyGlobLinux(join(u, '**/build/**'), [])

    expect(mounts).toContain(join(u, 'x'))
  })

  it('denies through a link back to the tree', () => {
    // build/up -> ..: the target is the whole tree the link reaches, as a
    // literal deny of the link would have it; the walk itself stops at the
    // link.
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
      expect(mounts).toContain(real)
      expect(mounts).toContain(join(real, 'public'))
      expect(mounts).toContain(join(real, 'public', 'ok.txt'))
    })

    it('is not defeated by a re-exposer above the covering directory', () => {
      // allowWrite ['.'] (the README's example) names the project root,
      // which re-exposes nothing beneath a tmpfs, so the package still
      // collapses to its two spellings.
      const mounts = expandReadDenyGlobLinux(
        join(P, '**/node_modules/foo/**'),
        [P],
      )

      expect(mounts).toEqual([real, link])
    })
  })
})

describe.if(isLinux)(
  'expandReadDenyGlobLinux (bwrap wiring through a symlink)',
  () => {
    // The pnpm layout again, driven through the real Linux wrapper: no tmpfs
    // may land on a symlink (bubblewrap 0.12 refuses to start), and the
    // carve-out must be the last word on the package's inode.
    let ROOT: string
    let P: string
    let real: string
    let link: string
    const savedCwd = process.cwd()
    const hasBwrap = spawnSync('bwrap', ['--version']).status === 0

    beforeAll(() => {
      ROOT = realpathSync(mkdtempSync(join(tmpdir(), 'deny-glob-bwrap-')))
      P = join(ROOT, 'pnpm')
      real = join(P, '.pnpm', 'foo@1', 'node_modules', 'foo')
      link = join(P, 'node_modules', 'foo')
      mkdirSync(join(real, 'public'), { recursive: true })
      writeFileSync(join(real, 'index.js'), 'secret')
      writeFileSync(join(real, 'public', 'ok.txt'), 'public')
      mkdirSync(join(P, 'node_modules'))
      symlinkSync(join('..', '.pnpm', 'foo@1', 'node_modules', 'foo'), link)
      process.chdir(ROOT)
    })

    afterAll(() => {
      process.chdir(savedCwd)
      cleanupBwrapMountPoints({ force: true })
      rmSync(ROOT, { recursive: true, force: true })
    })

    async function wrap(command: string, carveOut: string): Promise<string> {
      return wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(join(P, '**/node_modules/foo/**'), [
            carveOut,
          ]),
          allowWithinDeny: [carveOut],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
    }

    for (const spelling of ['link', 'target'] as const) {
      it(`mounts no tmpfs on a symlink and re-binds the carve-out last (allowRead in ${spelling} spelling)`, async () => {
        const carveOut = join(spelling === 'link' ? link : real, 'public')
        const wrapped = await wrap('echo hello', carveOut)
        const ops = wrapped.split(' --').map(op => op.trim())

        const tmpfsDests = ops
          .filter(op => op.startsWith('tmpfs '))
          .map(op => op.slice('tmpfs '.length))
        expect(tmpfsDests).toContain(real)
        expect(tmpfsDests).not.toContain(link)
        for (const dest of tmpfsDests) {
          expect(lstatSync(dest).isSymbolicLink()).toBe(false)
        }
        // One tmpfs per inode, and the carve-out's bind after the last one
        // that covers it.
        expect(tmpfsDests.filter(d => d === real)).toHaveLength(1)
        const lastTmpfs = Math.max(
          ...ops.flatMap((op, i) => (op.startsWith('tmpfs ') ? [i] : [])),
        )
        const reBind = ops.lastIndexOf(
          `ro-bind ${carveOut} ${join(real, 'public')}`,
        )
        expect(reBind).toBeGreaterThan(lastTmpfs)

        if (hasBwrap) {
          // Inside: the package is empty but for the carve-out, in both
          // spellings; the entries beneath the carve-out keep their masks.
          const run = spawnSync(
            await wrap(
              [
                `ls ${link}`,
                `ls ${real}`,
                `cat ${join(link, 'public', 'ok.txt')} | wc -c`,
                `[ -e ${join(link, 'index.js')} ] && echo INDEX_VISIBLE || echo INDEX_HIDDEN`,
              ].join('; '),
              carveOut,
            ),
            { shell: true, encoding: 'utf8', timeout: 15000, cwd: ROOT },
          )
          expect(run.stderr ?? '').not.toContain('symlink destination')
          expect(run.status).toBe(0)
          expect(run.stdout.trim().split('\n')).toEqual([
            'public',
            'public',
            '0',
            'INDEX_HIDDEN',
          ])
        }
      })
    }

    it('honours a file carve-out written in the link spelling', async () => {
      // The glob lists index.js under both spellings; only the link spelling
      // is in allowRead. Neither twin may be masked, and the carve-out is
      // bound back over the package tmpfs.
      const carveOut = join(link, 'index.js')
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(join(P, '**/node_modules/foo/**'), [
            carveOut,
          ]),
          allowWithinDeny: [carveOut],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      expect(wrapped).toContain(
        `--ro-bind ${carveOut} ${join(real, 'index.js')}`,
      )
      expect(wrapped).not.toContain(`/dev/null ${join(real, 'index.js')}`)
      expect(wrapped).not.toContain(`/dev/null ${carveOut}`)
    })

    it('re-applies the tmpfs after a denyWrite bind that contains its target', async () => {
      // denyWrite names the pnpm store, which contains the package's real
      // location but not its link spelling; the bind lands after the tmpfs
      // and would re-expose the package read-only without a re-application.
      const store = join(P, '.pnpm')
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: expandReadDenyGlobLinux(
            join(P, '**/node_modules/foo/**'),
            [],
          ),
        },
        writeConfig: { allowOnly: [P], denyWithinAllow: [store] },
      })

      const storeBind = wrapped.lastIndexOf(`--ro-bind ${store} ${store}`)
      expect(storeBind).toBeGreaterThan(-1)
      expect(wrapped.lastIndexOf(`--tmpfs ${real}`)).toBeGreaterThan(storeBind)
    })

    it('does not re-apply a tmpfs over its carve-out when a denyWrite bind covers only the link spelling', async () => {
      // w/d/link -> realdir (outside the write root w). denyWrite [w/d]
      // contains the link's spelling but not where the tmpfs landed
      // (realdir), so the bind re-exposes nothing; re-applying the tmpfs
      // there anyway would re-bind realdir/pub over the mask on
      // realdir/pub/secret.txt and leave the file readable.
      const R = join(ROOT, 'f4')
      const realdir = join(R, 'realdir')
      const W = join(R, 'w')
      const S = join(W, 'd', 'link')
      mkdirSync(join(realdir, 'pub'), { recursive: true })
      writeFileSync(join(realdir, 'pub', 'secret.txt'), 'secret')
      mkdirSync(join(W, 'd'), { recursive: true })
      symlinkSync(realdir, S)

      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [S, join(realdir, 'pub', 'secret.txt')],
          allowWithinDeny: [join(realdir, 'pub')],
        },
        writeConfig: { allowOnly: [W], denyWithinAllow: [join(W, 'd')] },
        mandatoryDenySearchDepth: 1,
      })

      const mask = `--ro-bind /dev/null ${join(realdir, 'pub', 'secret.txt')}`
      const carveOut = `--ro-bind ${join(realdir, 'pub')} ${join(realdir, 'pub')}`
      expect(wrapped).toContain(mask)
      // One tmpfs on the target, and the mask is the last word on the file:
      // no carve-out re-bind after it.
      expect(wrapped.split(`--tmpfs ${realdir} `)).toHaveLength(2)
      expect(wrapped.lastIndexOf(mask)).toBeGreaterThan(
        wrapped.lastIndexOf(carveOut),
      )
    })

    it('binds a carve-out that is itself a symlink at its target', async () => {
      // allowRead names the link; the tmpfs is on the target, so the re-bind
      // goes there too (bwrap refuses a symlink destination) and the link,
      // still present, leads to it.
      const wrapped = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [real], allowWithinDeny: [link] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })

      expect(wrapped).toContain(`--tmpfs ${real}`)
      expect(wrapped).toContain(`--ro-bind ${link} ${real}`)
      expect(wrapped).not.toContain(`--ro-bind ${link} ${link}`)
    })

    it('re-binds a literal carve-out written in the other spelling', async () => {
      // Literal denies, no glob: denyRead names the link and allowRead its
      // target's subdirectory, and the mirror.
      const viaLink = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [link],
          allowWithinDeny: [join(real, 'public')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(viaLink).toContain(`--tmpfs ${real}`)
      expect(viaLink).toContain(
        `--ro-bind ${join(real, 'public')} ${join(real, 'public')}`,
      )

      const viaTarget = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [real],
          allowWithinDeny: [join(link, 'public')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(viaTarget).toContain(`--tmpfs ${real}`)
      expect(viaTarget).toContain(
        `--ro-bind ${join(link, 'public')} ${join(real, 'public')}`,
      )
    })

    it('mounts a deny beneath a recreated symlinked carve-out where the carve-out was recreated', async () => {
      // denyRead [D, D/lnk/sub] + allowRead [D/lnk], D/lnk -> ../e: D's tmpfs
      // wipes the link, the carve-out re-bind recreates D/lnk as a plain
      // directory showing e, so the deny must land at D/lnk/sub — a tmpfs
      // at e/sub (the host realpath) would leave D/lnk/sub/secret readable.
      const D = join(ROOT, 's1', 'D')
      const e = join(ROOT, 's1', 'e')
      mkdirSync(D, { recursive: true })
      mkdirSync(join(e, 'sub'), { recursive: true })
      writeFileSync(join(e, 'sub', 'secret'), 'secret')
      symlinkSync(join('..', 'e'), join(D, 'lnk'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `cat ${join(D, 'lnk', 'sub', 'secret')} || echo HIDDEN`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [D, join(D, 'lnk', 'sub')],
          allowWithinDeny: [join(D, 'lnk')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(wrapped).toContain(`--tmpfs ${join(D, 'lnk', 'sub')}`)
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.stdout).not.toContain('secret')
        expect(run.stdout).toContain('HIDDEN')
      }
    })

    it('binds a symlinked carve-out nested in another carve-out at its target', async () => {
      // denyRead [D] + allowRead [D/x, D/x/lnk]: D/x is re-bound from the
      // host, so D/x/lnk is a live symlink inside the sandbox and bwrap 0.12
      // refuses it as a destination.
      const D = join(ROOT, 's3', 'D')
      const t = join(ROOT, 's3', 't')
      mkdirSync(join(D, 'x'), { recursive: true })
      mkdirSync(t, { recursive: true })
      writeFileSync(join(t, 'f'), 'T')
      symlinkSync(join('..', '..', 't'), join(D, 'x', 'lnk'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `cat ${join(D, 'x', 'lnk', 'f')}`,
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [D],
          allowWithinDeny: [join(D, 'x'), join(D, 'x', 'lnk')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(wrapped).not.toContain(` ${join(D, 'x', 'lnk')} --`)
      expect(wrapped).toContain(`--ro-bind ${join(D, 'x', 'lnk')} ${t}`)
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.stderr ?? '').not.toContain('symlink destination')
        expect(run.stdout).toBe('T')
      }
    })

    it('re-binds a carve-out through an absolute intermediate symlink without a symlink in the destination', async () => {
      // denyRead [T] + allowRead [P/L/sub], P/L -> T absolute: bubblewrap
      // before 0.12 aborts on an absolute link inside a destination.
      const T = join(ROOT, 's4', 'T')
      const P = join(ROOT, 's4', 'P')
      mkdirSync(join(T, 'sub'), { recursive: true })
      mkdirSync(P, { recursive: true })
      writeFileSync(join(T, 'sub', 'f'), 'F')
      symlinkSync(T, join(P, 'L'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `cat ${join(P, 'L', 'sub', 'f')}`,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [T], allowWithinDeny: [join(P, 'L', 'sub')] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(wrapped).toContain(
        `--ro-bind ${join(P, 'L', 'sub')} ${join(T, 'sub')}`,
      )
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.status).toBe(0)
        expect(run.stdout).toBe('F')
      }
    })

    it('still masks the target of a file symlink listed beneath a denied directory', async () => {
      // denyRead [cfg, cfg/token], cfg/token -> ../secrets/token: the link
      // vanishes with cfg's tmpfs, but the file it named is the target, and
      // main masked it there (resolveSymlinkDenyDest); it must stay masked.
      const cfg = join(ROOT, 's9', 'cfg')
      const secrets = join(ROOT, 's9', 'secrets')
      mkdirSync(cfg, { recursive: true })
      mkdirSync(secrets, { recursive: true })
      writeFileSync(join(secrets, 'token'), 'TOKEN')
      symlinkSync(join('..', 'secrets', 'token'), join(cfg, 'token'))
      const wrapped = await wrapCommandWithSandboxLinux({
        command: `cat ${join(secrets, 'token')}; echo`,
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [cfg, join(cfg, 'token')] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(wrapped).toContain(`--ro-bind /dev/null ${join(secrets, 'token')}`)
      if (hasBwrap) {
        const run = spawnSync(wrapped, {
          shell: true,
          encoding: 'utf8',
          timeout: 15000,
        })
        expect(run.stdout).not.toContain('TOKEN')
      }
    })

    it('emits one tmpfs for a directory and the files a glob lists beneath it', async () => {
      // The cross-entry dedup: a directory deny plus per-file entries under
      // it cost one mount, unless a carve-out keeps the masks beneath it
      // meaningful.
      const big = join(ROOT, 'big')
      mkdirSync(join(big, 'keep'), { recursive: true })
      const keys = ['a.key', 'b.key', 'keep/c.key'].map(k => join(big, k))
      for (const k of keys) writeFileSync(k, '')

      const collapsed = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: { denyOnly: [big, ...keys] },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(collapsed.split(`--tmpfs ${big}`)).toHaveLength(2)
      expect(collapsed).not.toContain(`/dev/null ${big}/`)

      const carved = await wrapCommandWithSandboxLinux({
        command: 'true',
        needsNetworkRestriction: false,
        readConfig: {
          denyOnly: [big, ...keys],
          allowWithinDeny: [join(big, 'keep')],
        },
        writeConfig: { allowOnly: [], denyWithinAllow: [] },
      })
      expect(carved).toContain(
        `--ro-bind /dev/null ${join(big, 'keep', 'c.key')}`,
      )
      expect(carved).not.toContain(`/dev/null ${join(big, 'a.key')}`)
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
