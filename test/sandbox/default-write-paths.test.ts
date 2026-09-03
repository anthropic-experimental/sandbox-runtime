import { describe, it, expect } from 'bun:test'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { getDefaultWritePaths } from '../../src/sandbox/sandbox-utils.js'

/**
 * The default write paths are conveniences the caller never asked for; one
 * that lies at or under a directory the caller read-denies must not be bound
 * back over that deny.
 */
describe('getDefaultWritePaths', () => {
  const npmLogs = join(homedir(), '.npm/_logs')
  const claudeDebug = join(homedir(), '.claude/debug')

  it('includes the home conveniences by default', () => {
    expect(getDefaultWritePaths()).toContain(npmLogs)
    expect(getDefaultWritePaths([])).toContain(claudeDebug)
  })

  it('drops a convenience under a read-denied directory', () => {
    const underDeniedHome = getDefaultWritePaths([homedir()])
    expect(underDeniedHome).not.toContain(npmLogs)
    expect(underDeniedHome).not.toContain(claudeDebug)
    expect(underDeniedHome).toContain('/dev/null')

    // Tilde and trailing-slash spellings name the same directory.
    expect(getDefaultWritePaths(['~/'])).not.toContain(npmLogs)
    // The denied directory itself, exactly.
    expect(getDefaultWritePaths([join(homedir(), '.npm', '_logs')])).toEqual(
      getDefaultWritePaths().filter(p => p !== npmLogs),
    )
  })

  it('keeps a convenience beside, not beneath, a read-denied directory', () => {
    const kept = getDefaultWritePaths([
      join(homedir(), '.npmrc'),
      join(homedir(), '.np'),
    ])
    expect(kept).toContain(npmLogs)
    expect(kept).toContain(claudeDebug)
  })

  it('ignores glob entries, which name no directory to compare against', () => {
    expect(getDefaultWritePaths([join(homedir(), '**/*.log')])).toContain(
      npmLogs,
    )
  })
})
