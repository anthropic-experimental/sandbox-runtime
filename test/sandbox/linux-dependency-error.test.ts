import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import * as which from '../../src/utils/which.js'
import * as seccomp from '../../src/sandbox/generate-seccomp-filter.js'
import {
  checkLinuxDependencies,
  getLinuxDependencyStatus,
} from '../../src/sandbox/linux-sandbox-utils.js'

// Spies set up in beforeEach, torn down in afterEach. Each test overrides
// just the piece it's exercising. spyOn patches the export binding, so
// linux-sandbox-utils' own imports see the replacement.
let whichSpy: ReturnType<typeof spyOn>
let applySpy: ReturnType<typeof spyOn>

beforeEach(() => {
  whichSpy = spyOn(which, 'whichSync').mockImplementation(
    (bin: string) => `/usr/bin/${bin}`,
  )
  applySpy = spyOn(seccomp, 'getApplySeccompBinaryPath').mockReturnValue(
    '/path/to/apply-seccomp',
  )
})

afterEach(() => {
  whichSpy.mockRestore()
  applySpy.mockRestore()
})

describe('checkLinuxDependencies', () => {
  test('returns no errors or warnings when all dependencies present', () => {
    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([])
  })

  test('returns error when bwrap missing', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'bwrap' ? null : `/usr/bin/${bin}`,
    )

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns error when socat missing', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'socat' ? null : `/usr/bin/${bin}`,
    )

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns multiple errors when both bwrap and socat missing', () => {
    whichSpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(2)
  })

  test('returns warning when apply-seccomp missing', () => {
    applySpy.mockReturnValue(null)

    const result = checkLinuxDependencies()

    expect(result.warnings).toContain(
      'seccomp not available - unix socket access not restricted',
    )
  })

  test('passes custom applyPath through to the resolver', () => {
    checkLinuxDependencies({ seccompConfig: { applyPath: '/custom/apply' } })

    expect(applySpy).toHaveBeenCalledWith('/custom/apply')
  })

  test('argv0 mode: no seccomp warning even when binary lookup would fail', () => {
    applySpy.mockReturnValue(null)

    const result = checkLinuxDependencies({
      seccompConfig: {
        argv0: 'apply-seccomp',
        applyPath: '/proc/self/fd/3',
      },
    })

    expect(result.warnings).toEqual([])
    expect(applySpy).not.toHaveBeenCalled()
  })

  test('explicit bwrapPath: skips PATH lookup, errors when not executable', () => {
    const result = checkLinuxDependencies({ bwrapPath: '/no/such/bwrap' })

    expect(result.errors).toContain(
      'bubblewrap (bwrap) not executable at /no/such/bwrap',
    )
    // socat still falls back to PATH
    expect(result.errors.length).toBe(1)
    expect(whichSpy).not.toHaveBeenCalledWith('bwrap')
  })

  test('explicit socatPath: skips PATH lookup, errors when not executable', () => {
    const result = checkLinuxDependencies({ socatPath: '/no/such/socat' })

    expect(result.errors).toContain('socat not executable at /no/such/socat')
    expect(whichSpy).not.toHaveBeenCalledWith('socat')
  })

  test('explicit bwrapPath: ok when path is executable', () => {
    // /bin/sh exists and is executable on every Linux system
    const result = checkLinuxDependencies({ bwrapPath: '/bin/sh' })

    expect(result.errors).toEqual([])
    expect(whichSpy).not.toHaveBeenCalledWith('bwrap')
  })
})

describe('getLinuxDependencyStatus', () => {
  test('reports all available when everything installed', () => {
    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(true)
    expect(status.hasSeccompApply).toBe(true)
  })

  test('reports bwrap unavailable when not installed', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'bwrap' ? null : `/usr/bin/${bin}`,
    )

    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(false)
    expect(status.hasSocat).toBe(true)
  })

  test('reports socat unavailable when not installed', () => {
    whichSpy.mockImplementation((bin: string) =>
      bin === 'socat' ? null : `/usr/bin/${bin}`,
    )

    const status = getLinuxDependencyStatus()

    expect(status.hasSocat).toBe(false)
    expect(status.hasBwrap).toBe(true)
  })

  test('reports seccomp unavailable when apply binary missing', () => {
    applySpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus()

    expect(status.hasSeccompApply).toBe(false)
    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(true)
  })

  test('argv0 mode: hasSeccompApply is true without touching disk', () => {
    applySpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus({
      seccompConfig: {
        argv0: 'apply-seccomp',
        applyPath: '/does/not/exist',
      },
    })

    expect(status.hasSeccompApply).toBe(true)
    expect(applySpy).not.toHaveBeenCalled()
  })

  test('explicit binary paths bypass PATH lookup', () => {
    whichSpy.mockReturnValue(null)

    const status = getLinuxDependencyStatus({
      bwrapPath: '/bin/sh',
      socatPath: '/no/such/socat',
    })

    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(false)
    expect(whichSpy).not.toHaveBeenCalledWith('bwrap')
    expect(whichSpy).not.toHaveBeenCalledWith('socat')
  })
})
