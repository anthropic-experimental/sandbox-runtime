import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as srtLauncher from '../../src/sandbox/srt-launcher.js'
import {
  checkLinuxDependencies,
  getLinuxDependencyStatus,
} from '../../src/sandbox/linux-sandbox-utils.js'

// spyOn patches the export binding, so linux-sandbox-utils' own import sees
// the replacement. Each test overrides the return value it needs.
let launcherSpy: ReturnType<typeof spyOn>

beforeEach(() => {
  launcherSpy = spyOn(srtLauncher, 'getSrtLauncherPath').mockReturnValue(
    '/path/to/srt-launcher',
  )
})

afterEach(() => {
  launcherSpy.mockRestore()
})

describe('checkLinuxDependencies', () => {
  test('returns no errors or warnings when launcher is present', () => {
    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([])
  })

  test('returns one error when launcher is missing', () => {
    launcherSpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.errors.length).toBe(1)
    expect(result.errors[0]).toContain('srt-launcher')
  })

  test('explicit path: errors when not executable', () => {
    // Restore so the real resolver runs against a bogus path.
    launcherSpy.mockRestore()

    const result = checkLinuxDependencies({ path: '/no/such/srt-launcher' })

    expect(result.errors.length).toBe(1)
    expect(result.errors[0]).toContain('/no/such/srt-launcher')
  })

  test('explicit path: ok when path is executable', () => {
    launcherSpy.mockRestore()

    // /bin/sh exists and is executable on every Linux system
    const result = checkLinuxDependencies({ path: '/bin/sh' })

    expect(result.errors).toEqual([])
  })

  test('relative path throws', () => {
    launcherSpy.mockRestore()

    expect(() => checkLinuxDependencies({ path: 'srt-launcher' })).toThrow(
      'launcher.path must be an absolute path',
    )
  })
})

describe('getLinuxDependencyStatus', () => {
  test('reports launcher available when present', () => {
    const status = getLinuxDependencyStatus()

    expect(status.hasLauncher).toBe(true)
  })

  test('reports launcher unavailable when missing', () => {
    launcherSpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus()

    expect(status.hasLauncher).toBe(false)
  })

  test('explicit path bypasses default lookup', () => {
    launcherSpy.mockRestore()

    expect(getLinuxDependencyStatus({ path: '/bin/sh' }).hasLauncher).toBe(true)
    expect(
      getLinuxDependencyStatus({ path: '/no/such/launcher' }).hasLauncher,
    ).toBe(false)
  })
})
