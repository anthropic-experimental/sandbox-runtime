import { describe, it, expect, beforeEach } from 'bun:test'
import { existsSync } from 'node:fs'
import {
  getSrtLauncherPath,
  _resetSrtLauncherCache,
} from '../../src/sandbox/srt-launcher.js'
import {
  wrapCommandWithSandboxLinux,
  checkLinuxDependencies,
} from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

describe('getSrtLauncherPath', () => {
  beforeEach(() => {
    _resetSrtLauncherCache()
  })

  it.if(isLinux)(
    'resolves the vendored binary on x64/arm64 (Linux only — the binary is not built or shipped on macOS)',
    () => {
      const arch = process.arch
      if (arch !== 'x64' && arch !== 'arm64') {
        expect(getSrtLauncherPath()).toBeNull()
        return
      }

      const binaryPath = getSrtLauncherPath()
      expect(binaryPath).toBeTruthy()
      expect(existsSync(binaryPath!)).toBe(true)
      expect(binaryPath).toContain(`vendor/srt-launcher/${arch}/`)
    },
  )

  it('returns an explicit valid path verbatim', () => {
    const real = getSrtLauncherPath()
    if (!real) return
    expect(getSrtLauncherPath({ path: real })).toBe(real)
  })

  it('returns null for an explicit absolute path that does not exist', () => {
    // An override that doesn't resolve is an error, not a hint to fall back.
    expect(getSrtLauncherPath({ path: '/tmp/nonexistent-srt-launcher' })).toBe(
      null,
    )
  })

  it('throws on a relative path', () => {
    expect(() => getSrtLauncherPath({ path: 'srt-launcher' })).toThrow(
      'launcher.path must be an absolute path',
    )
  })
})

describe.if(isLinux)('wrapCommandWithSandboxLinux integration', () => {
  it('emits an srt-launcher run command with --seccomp-unix-block', async () => {
    if (checkLinuxDependencies().errors.length > 0) return

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'ls /',
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    })

    expect(wrappedCommand).toBeTruthy()
    expect(wrappedCommand).toContain('srt-launcher')
    expect(wrappedCommand).toContain('run')
    expect(wrappedCommand).toContain('--seccomp-unix-block')
  })

  it('argv0 mode: builds ARGV0= prefix and uses path verbatim', async () => {
    if (checkLinuxDependencies().errors.length > 0) return

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'echo test',
      needsNetworkRestriction: false,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
      launcher: { argv0: 'srt-launcher', path: '/proc/self/exe' },
    })

    expect(wrappedCommand).toContain('ARGV0=srt-launcher /proc/self/exe ')
    expect(wrappedCommand).not.toContain('vendor/srt-launcher')
  })

  it('argv0 mode: rejects argv0 without path', () => {
    if (checkLinuxDependencies().errors.length > 0) return

    expect(
      wrapCommandWithSandboxLinux({
        command: 'echo test',
        needsNetworkRestriction: false,
        writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
        launcher: { argv0: 'srt-launcher' },
      }),
    ).rejects.toThrow('launcher.argv0 requires launcher.path')
  })
})
