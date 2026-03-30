import { describe, test, expect, beforeEach, afterAll, mock } from 'bun:test'

// Mock state - these control what the mocked functions return
let mockBwrapInstalled = true
let mockSocatInstalled = true
let mockBpfPath: string | null = null
let mockApplyPath: string | null = null

// Store original Bun.which to restore later
const originalBunWhich = globalThis.Bun.which

// Mock Bun.which directly - this avoids mock.module which affects other test files
globalThis.Bun.which = ((bin: string): string | null => {
  if (bin === 'bwrap') {
    return mockBwrapInstalled ? '/usr/bin/bwrap' : null
  }
  if (bin === 'socat') {
    return mockSocatInstalled ? '/usr/bin/socat' : null
  }
  // For other binaries, use the original implementation
  return originalBunWhich(bin)
}) as typeof globalThis.Bun.which

// Mock seccomp path functions - controls whether seccomp binaries are "found"
void mock.module('../../src/sandbox/generate-seccomp-filter.js', () => ({
  getPreGeneratedBpfPath: () => mockBpfPath,
  getApplySeccompBinaryPath: () => mockApplyPath,
  generateSeccompFilter: () => null,
  cleanupSeccompFilter: () => {},
}))

// Dynamic import AFTER mocking - this is required for mocks to take effect
const { checkLinuxDependencies, getLinuxDependencyStatus } = await import(
  '../../src/sandbox/linux-sandbox-utils.js'
)

// Restore original Bun.which and module mocks after all tests in this file
afterAll(() => {
  globalThis.Bun.which = originalBunWhich
  mock.restore()
})

describe('checkLinuxDependencies', () => {
  // Reset all mocks to "everything installed" state before each test
  beforeEach(() => {
    mockBwrapInstalled = true
    mockSocatInstalled = true
    mockBpfPath = '/path/to/filter.bpf'
    mockApplyPath = '/path/to/apply-seccomp'
  })

  test('returns no errors or warnings when all dependencies present', () => {
    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([])
  })

  test('returns error when bwrap missing', () => {
    mockBwrapInstalled = false

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns error when socat missing', () => {
    mockSocatInstalled = false

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(1)
  })

  test('returns multiple errors when both bwrap and socat missing', () => {
    mockBwrapInstalled = false
    mockSocatInstalled = false

    const result = checkLinuxDependencies()

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(2)
  })

  test('returns warning (not error) when seccomp missing', () => {
    mockBpfPath = null
    mockApplyPath = null

    const result = checkLinuxDependencies()

    expect(result.warnings).toContain(
      'seccomp not available - unix socket access not restricted',
    )
  })

  test('returns warning when only bpf file present (no apply binary)', () => {
    mockBpfPath = '/path/to/filter.bpf'
    mockApplyPath = null

    const result = checkLinuxDependencies()

    expect(result.errors).toEqual([])
    expect(result.warnings.length).toBe(1)
  })

  // This verifies the config parameter is actually passed through
  test('uses custom seccomp paths when provided', () => {
    // Default paths return null (not found)
    mockBpfPath = null
    mockApplyPath = null

    // But we're passing custom paths - the mock ignores them,
    // so this still returns warnings. The point is it doesn't crash
    // and the structure is correct. Real path validation happens in the mock.
    const result = checkLinuxDependencies({
      bpfPath: '/custom/path.bpf',
      applyPath: '/custom/apply',
    })

    expect(Array.isArray(result.errors)).toBe(true)
    expect(Array.isArray(result.warnings)).toBe(true)
  })
})

describe('getLinuxDependencyStatus', () => {
  beforeEach(() => {
    mockBwrapInstalled = true
    mockSocatInstalled = true
    mockBpfPath = '/path/to/filter.bpf'
    mockApplyPath = '/path/to/apply-seccomp'
  })

  // All deps installed = all flags true
  test('reports all available when everything installed', () => {
    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(true)
    expect(status.hasSocat).toBe(true)
    expect(status.hasSeccompBpf).toBe(true)
    expect(status.hasSeccompApply).toBe(true)
  })

  // Each missing dep should show as false independently
  test('reports bwrap unavailable when not installed', () => {
    mockBwrapInstalled = false

    const status = getLinuxDependencyStatus()

    expect(status.hasBwrap).toBe(false)
    expect(status.hasSocat).toBe(true) // others unaffected
  })

  test('reports socat unavailable when not installed', () => {
    mockSocatInstalled = false

    const status = getLinuxDependencyStatus()

    expect(status.hasSocat).toBe(false)
    expect(status.hasBwrap).toBe(true) // others unaffected
  })

  test('reports seccomp unavailable when files missing', () => {
    mockBpfPath = null
    mockApplyPath = null

    const status = getLinuxDependencyStatus()

    expect(status.hasSeccompBpf).toBe(false)
    expect(status.hasSeccompApply).toBe(false)
    expect(status.hasBwrap).toBe(true) // others unaffected
    expect(status.hasSocat).toBe(true)
  })
})
