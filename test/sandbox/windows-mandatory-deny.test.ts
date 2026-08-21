import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { mkdirSync, rmSync, writeFileSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expandGlobPattern } from '../../src/sandbox/sandbox-utils.js'
import { windowsGetMandatoryDenyPatterns } from '../../src/sandbox/windows-sandbox-utils.js'

describe('windowsGetMandatoryDenyPatterns', () => {
  const cwd = join('C:', 'proj')

  it('covers git hooks and config at the root and nested, plus dangerous files', () => {
    const pats = windowsGetMandatoryDenyPatterns(cwd, false)
    expect(pats).toContain(join(cwd, '**', '.git', 'hooks'))
    expect(pats).toContain(join(cwd, '**', '.git', 'config'))
    expect(pats).toContain(join(cwd, '**', '.gitconfig'))
    expect(pats).toContain(join(cwd, '**', '.bashrc'))
    expect(pats).toContain(join(cwd, '**', '.vscode'))
    expect(pats).toContain(join(cwd, '**', '.claude', 'commands'))
    expect(pats).not.toContain(join(cwd, '**', '.git'))
    expect(pats).not.toContain(join(cwd, '.git'))
  })

  it('drops .git/config when allowGitConfig is set, keeps hooks', () => {
    const pats = windowsGetMandatoryDenyPatterns(cwd, true)
    expect(pats).not.toContain(join(cwd, '**', '.git', 'config'))
    expect(pats).toContain(join(cwd, '**', '.git', 'hooks'))
  })
})

describe('expandGlobPattern maxDepth', () => {
  const base = join(realpathSync(tmpdir()), 'glob-depth-' + Date.now())

  beforeAll(() => {
    for (const d of ['', 'a', join('a', 'b', 'c')]) {
      mkdirSync(join(base, d, '.git', 'hooks'), { recursive: true })
      writeFileSync(join(base, d, '.git', 'config'), '')
    }
    mkdirSync(join(base, 'node_modules', 'x', 'y'), { recursive: true })
    writeFileSync(join(base, 'node_modules', 'x', 'y', '.bashrc'), '')
  })

  afterAll(() => rmSync(base, { recursive: true, force: true }))

  it('finds matches at every depth when unbounded', () => {
    const r = expandGlobPattern(join(base, '**', '.git', 'config')).sort()
    expect(r).toEqual(
      [
        join(base, '.git', 'config'),
        join(base, 'a', '.git', 'config'),
        join(base, 'a', 'b', 'c', '.git', 'config'),
      ].sort(),
    )
  })

  it('stops descending at maxDepth (the Linux ripgrep default is 3)', () => {
    const r = expandGlobPattern(join(base, '**', '.git', 'config'), {
      maxDepth: 3,
    }).sort()
    expect(r).toEqual(
      [join(base, '.git', 'config'), join(base, 'a', '.git', 'config')].sort(),
    )
    expect(
      expandGlobPattern(join(base, '**', '.bashrc'), { maxDepth: 3 }),
    ).toEqual([])
    expect(
      expandGlobPattern(join(base, '**', '.bashrc'), { maxDepth: 4 }),
    ).toEqual([join(base, 'node_modules', 'x', 'y', '.bashrc')])
  })

  it('does not descend into skipDirNames', () => {
    expect(
      expandGlobPattern(join(base, '**', '.bashrc'), {
        maxDepth: 4,
        skipDirNames: ['node_modules'],
      }),
    ).toEqual([])
  })

  it('matches directories too (hooks is a directory target)', () => {
    const r = expandGlobPattern(join(base, '**', '.git', 'hooks'), {
      maxDepth: 3,
    }).sort()
    expect(r).toEqual(
      [join(base, '.git', 'hooks'), join(base, 'a', '.git', 'hooks')].sort(),
    )
  })
})
