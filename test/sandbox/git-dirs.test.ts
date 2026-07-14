import { describe, it, expect } from 'bun:test'
import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createLinkedWorktreeFixture,
  createMainWorktreeFixture,
} from '../helpers/git-fixtures.js'
import { getGitDirs } from '../../src/sandbox/sandbox-utils.js'

describe('getGitDirs', () => {
  it('returns the same gitDir and commonDir for the main worktree', () => {
    const baseDir = mkdtempSync(join(tmpdir(), 'git-dirs-main-'))
    const { worktreeDir, commonDir } = createMainWorktreeFixture(
      baseDir,
      'main-worktree',
      'ORIGINAL',
    )

    try {
      const gitDirs = getGitDirs(worktreeDir)

      expect(gitDirs).toBeDefined()
      expect(gitDirs?.gitDir).toBe(realpathSync(commonDir))
      expect(gitDirs?.commonDir).toBe(realpathSync(commonDir))
    } finally {
      rmSync(baseDir, { recursive: true, force: true })
    }
  })

  it('ignores commondir in the main worktree', () => {
    const baseDir = mkdtempSync(join(tmpdir(), 'git-dirs-main-commondir-'))
    const { worktreeDir, commonDir } = createMainWorktreeFixture(
      baseDir,
      'main-worktree',
      'ORIGINAL',
    )
    const fakeCommonDir = join(baseDir, 'outside-common-dir')

    mkdirSync(fakeCommonDir, { recursive: true })
    writeFileSync(join(commonDir, 'commondir'), '../../outside-common-dir')

    try {
      const gitDirs = getGitDirs(worktreeDir)

      expect(gitDirs).toBeDefined()
      expect(gitDirs?.gitDir).toBe(realpathSync(commonDir))
      expect(gitDirs?.commonDir).toBe(realpathSync(commonDir))
    } finally {
      rmSync(baseDir, { recursive: true, force: true })
    }
  })

  it('returns distinct gitDir and commonDir for a linked worktree', () => {
    const baseDir = mkdtempSync(join(tmpdir(), 'git-dirs-linked-'))
    const { worktreeDir, commonDir, worktreeGitDir } =
      createLinkedWorktreeFixture(baseDir, 'linked-worktree', 'ORIGINAL')

    try {
      const gitDirs = getGitDirs(worktreeDir)

      expect(gitDirs).toBeDefined()
      expect(gitDirs?.gitDir).toBe(realpathSync(worktreeGitDir))
      expect(gitDirs?.commonDir).toBe(realpathSync(commonDir))
    } finally {
      rmSync(baseDir, { recursive: true, force: true })
    }
  })

  it('falls back to a single gitDir when .git points to a separate git dir', () => {
    const baseDir = mkdtempSync(join(tmpdir(), 'git-dirs-separate-'))
    const worktreeDir = join(baseDir, 'worktree')
    const gitDir = join(baseDir, 'separate-git-dir')

    mkdirSync(worktreeDir, { recursive: true })
    mkdirSync(gitDir, { recursive: true })
    writeFileSync(join(worktreeDir, '.git'), `gitdir: ${gitDir}`)

    try {
      const gitDirs = getGitDirs(worktreeDir)

      expect(gitDirs).toBeDefined()
      expect(gitDirs?.gitDir).toBe(realpathSync(gitDir))
      expect(gitDirs?.commonDir).toBe(realpathSync(gitDir))
    } finally {
      rmSync(baseDir, { recursive: true, force: true })
    }
  })

  it('ignores unverified linked-worktree metadata', () => {
    const baseDir = mkdtempSync(join(tmpdir(), 'git-dirs-unverified-'))
    const worktreeDir = join(baseDir, 'worktree')
    const gitDir = join(baseDir, 'separate-git-dir')
    const fakeCommonDir = join(baseDir, 'fake-common-dir')

    mkdirSync(worktreeDir, { recursive: true })
    mkdirSync(gitDir, { recursive: true })
    mkdirSync(fakeCommonDir, { recursive: true })
    writeFileSync(join(gitDir, 'commondir'), '../fake-common-dir')
    writeFileSync(join(worktreeDir, '.git'), `gitdir: ${gitDir}`)

    try {
      const gitDirs = getGitDirs(worktreeDir)

      expect(gitDirs).toBeDefined()
      expect(gitDirs?.gitDir).toBe(realpathSync(gitDir))
      expect(gitDirs?.commonDir).toBe(realpathSync(gitDir))
    } finally {
      rmSync(baseDir, { recursive: true, force: true })
    }
  })

  it('rejects linked-worktree metadata without a backlink to the current worktree', () => {
    const baseDir = mkdtempSync(join(tmpdir(), 'git-dirs-foreign-worktree-'))
    const { worktreeGitDir: foreignWorktreeGitDir } = createLinkedWorktreeFixture(
      baseDir,
      'foreign-worktree',
      'ORIGINAL',
    )
    const attackerWorktreeDir = join(baseDir, 'attacker-worktree')

    mkdirSync(attackerWorktreeDir, { recursive: true })
    writeFileSync(
      join(attackerWorktreeDir, '.git'),
      `gitdir: ${foreignWorktreeGitDir}`,
    )

    try {
      expect(getGitDirs(attackerWorktreeDir)).toBeUndefined()
    } finally {
      rmSync(baseDir, { recursive: true, force: true })
    }
  })

  it('returns undefined outside a git checkout', () => {
    const rootDir = mkdtempSync(join(tmpdir(), 'git-dirs-none-'))

    try {
      expect(getGitDirs(rootDir)).toBeUndefined()
    } finally {
      rmSync(rootDir, { recursive: true, force: true })
    }
  })
})
