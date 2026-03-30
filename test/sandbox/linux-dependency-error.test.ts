import { describe, test, expect } from 'bun:test'
import {
  dependencyStatusToCheck,
  type LinuxDependencyStatus,
} from '../../src/sandbox/linux-sandbox-utils.js'

const allPresent: LinuxDependencyStatus = {
  hasBwrap: true,
  hasSocat: true,
  hasSeccompBpf: true,
  hasSeccompApply: true,
}

describe('dependencyStatusToCheck', () => {
  test('returns no errors or warnings when all dependencies present', () => {
    const result = dependencyStatusToCheck(allPresent)

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([])
  })

  test('returns error when bwrap missing', () => {
    const result = dependencyStatusToCheck({ ...allPresent, hasBwrap: false })

    expect(result.errors).toEqual(['bubblewrap (bwrap) not installed'])
    expect(result.warnings).toEqual([])
  })

  test('returns error when socat missing', () => {
    const result = dependencyStatusToCheck({ ...allPresent, hasSocat: false })

    expect(result.errors).toEqual(['socat not installed'])
    expect(result.warnings).toEqual([])
  })

  test('returns multiple errors when both bwrap and socat missing', () => {
    const result = dependencyStatusToCheck({
      ...allPresent,
      hasBwrap: false,
      hasSocat: false,
    })

    expect(result.errors).toContain('bubblewrap (bwrap) not installed')
    expect(result.errors).toContain('socat not installed')
    expect(result.errors.length).toBe(2)
  })

  test('returns warning (not error) when seccomp bpf missing', () => {
    const result = dependencyStatusToCheck({
      ...allPresent,
      hasSeccompBpf: false,
    })

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([
      'seccomp not available - unix socket access not restricted',
    ])
  })

  test('returns warning when seccomp apply binary missing', () => {
    const result = dependencyStatusToCheck({
      ...allPresent,
      hasSeccompApply: false,
    })

    expect(result.errors).toEqual([])
    expect(result.warnings).toEqual([
      'seccomp not available - unix socket access not restricted',
    ])
  })

  test('returns single warning when both seccomp pieces missing', () => {
    const result = dependencyStatusToCheck({
      ...allPresent,
      hasSeccompBpf: false,
      hasSeccompApply: false,
    })

    expect(result.errors).toEqual([])
    expect(result.warnings.length).toBe(1)
  })

  test('reports both errors and warnings when everything missing', () => {
    const result = dependencyStatusToCheck({
      hasBwrap: false,
      hasSocat: false,
      hasSeccompBpf: false,
      hasSeccompApply: false,
    })

    expect(result.errors.length).toBe(2)
    expect(result.warnings.length).toBe(1)
  })
})
