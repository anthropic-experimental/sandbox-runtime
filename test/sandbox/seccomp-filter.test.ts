import { describe, it, expect } from 'bun:test'
import { existsSync } from 'node:fs'
import { whichSync } from '../../src/utils/which.js'
import { getApplySeccompBinaryPath } from '../../src/sandbox/generate-seccomp-filter.js'
import {
  wrapCommandWithSandboxLinux,
  checkLinuxDependencies,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

describe.if(isLinux)('Linux Sandbox Dependencies', () => {
  it('checkLinuxDependencies reports no errors with bwrap + socat + apply-seccomp', () => {
    const depCheck = checkLinuxDependencies()
    expect(depCheck).toHaveProperty('errors')
    expect(depCheck).toHaveProperty('warnings')

    if (depCheck.errors.length === 0) {
      expect(whichSync('bwrap')).not.toBeNull()
      expect(whichSync('socat')).not.toBeNull()
    }
  })
})

describe.if(isLinux)('Apply Seccomp Binary', () => {
  it('resolves the built apply-seccomp binary on x64/arm64', () => {
    const arch = process.arch
    if (arch !== 'x64' && arch !== 'arm64') {
      expect(getApplySeccompBinaryPath()).toBeNull()
      return
    }

    const binaryPath = getApplySeccompBinaryPath()
    expect(binaryPath).toBeTruthy()
    expect(existsSync(binaryPath!)).toBe(true)
    expect(binaryPath).toContain('vendor/seccomp')
  })

  it('prefers an explicit valid path over the default', () => {
    const real = getApplySeccompBinaryPath()
    if (!real) return
    expect(getApplySeccompBinaryPath(real)).toBe(real)
  })

  it('falls back to the default when an explicit path does not exist', () => {
    const result = getApplySeccompBinaryPath('/tmp/nonexistent-apply-seccomp')
    const arch = process.arch
    if (arch === 'x64' || arch === 'arm64') {
      expect(result).toBeTruthy()
      expect(result).toContain('vendor/seccomp')
    } else {
      expect(result).toBeNull()
    }
  })
})

describe.if(isLinux)('Sandbox Integration', () => {
  it('wraps filesystem-restricted commands with bwrap', async () => {
    if (checkLinuxDependencies().errors.length > 0) return

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'ls /',
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    })

    expect(wrappedCommand).toBeTruthy()
    expect(wrappedCommand).toContain('bwrap')
  })

  it('threads a custom apply-seccomp path through seccompConfig', async () => {
    if (checkLinuxDependencies().errors.length > 0) return

    const real = getApplySeccompBinaryPath()
    if (!real) return

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'echo test',
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      seccompConfig: { applyPath: real },
    })

    expect(wrappedCommand).toContain(real)
  })

  it('argv0 mode: builds ARGV0 prefix and uses applyPath verbatim', async () => {
    if (checkLinuxDependencies().errors.length > 0) return

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'echo test',
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      seccompConfig: { argv0: 'apply-seccomp', applyPath: '/proc/self/fd/3' },
    })

    expect(wrappedCommand).toContain("ARGV0='apply-seccomp' '/proc/self/fd/3' ")
    expect(wrappedCommand).not.toContain('vendor/seccomp')
  })

  it('argv0 mode: shell-quotes argv0 and applyPath', async () => {
    if (checkLinuxDependencies().errors.length > 0) return

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'echo test',
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      seccompConfig: { argv0: 'x; rm -rf /', applyPath: '/path with space' },
    })

    expect(wrappedCommand).toContain("ARGV0='x; rm -rf /' '/path with space' ")
  })

  it('argv0 mode: rejects argv0 without applyPath', () => {
    if (checkLinuxDependencies().errors.length > 0) return

    expect(
      wrapCommandWithSandboxLinux({
        command: 'echo test',
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        seccompConfig: { argv0: 'apply-seccomp' },
      }),
    ).rejects.toThrow('seccompConfig.argv0 requires seccompConfig.applyPath')
  })
})
