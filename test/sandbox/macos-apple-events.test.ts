import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * Tests for the opt-in allowAppleEvents option (macOS only).
 *
 * By default the Seatbelt profile's (deny default) blocks appleevent-send and
 * the com.apple.coreservices.appleevents mach-lookup, so commands like `open`
 * and `osascript` fail with AppleScript error -600 ("Application isn't
 * running") inside the sandbox. allowAppleEvents: true re-enables them.
 * It is opt-in because Apple Events let sandboxed commands script other
 * applications (e.g. Terminal), weakening sandbox isolation.
 */

function wrapCommand(command: string, allowAppleEvents?: boolean): string {
  return wrapCommandWithSandboxMacOS({
    command,
    needsNetworkRestriction: true,
    allowAppleEvents,
    readConfig: undefined,
    writeConfig: undefined,
  })
}

describe.if(isMacOS)(
  'macOS Seatbelt allowAppleEvents profile generation',
  () => {
    it('omits Apple Events rules by default', () => {
      const wrapped = wrapCommand('echo test')

      expect(wrapped).not.toContain('appleevent-send')
      expect(wrapped).not.toContain('com.apple.coreservices.appleevents')
    })

    it('generates an identical command when unset and when explicitly false', () => {
      const unset = wrapCommand('echo test')
      const explicitFalse = wrapCommand('echo test', false)

      expect(explicitFalse).toBe(unset)
    })

    it('includes Apple Events rules when enabled', () => {
      const wrapped = wrapCommand('echo test', true)

      // The wrapped command is shell-quoted, so quotes inside the profile are
      // escaped — match the rule fragments rather than the exact profile lines.
      expect(wrapped).toContain('(allow appleevent-send)')
      expect(wrapped).toContain('com.apple.coreservices.appleevents')
    })

    it('produces a profile that sandbox-exec accepts when enabled', () => {
      const wrapped = wrapCommand('echo APPLE_EVENTS_OK', true)
      const result = spawnSync(wrapped, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toContain('APPLE_EVENTS_OK')
    })
  },
)

// `open -g -a Finder .` requires sending an Apple Event to Finder via
// appleeventsd, so it probes the Seatbelt layer. Some CI runners cannot run
// it at all (no usable GUI session / TCC automation grant for the runner
// user) — there the failure sits in front of Seatbelt, so only assert the
// sandbox's behavior when the probe works outside the sandbox.
const openCommand = 'open -g -a Finder .'
const baselineOpenWorks =
  isMacOS &&
  spawnSync(openCommand, { shell: true, encoding: 'utf8', timeout: 15000 })
    .status === 0

describe.if(isMacOS && baselineOpenWorks)(
  'macOS Seatbelt allowAppleEvents end to end',
  () => {
    it('blocks `open` by default', () => {
      const result = spawnSync(wrapCommand(openCommand), {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })

      expect(result.status).not.toBe(0)
    })

    it('allows `open` when allowAppleEvents is true', () => {
      const result = spawnSync(wrapCommand(openCommand, true), {
        shell: true,
        encoding: 'utf8',
        timeout: 15000,
      })

      if (result.status !== 0) {
        // Surface what failed: open's own error plus any Seatbelt denials
        // (deny messages carry the profile's CMD64_ log tag).
        console.error(
          `open probe failed (status ${result.status})\nstdout: ${result.stdout}\nstderr: ${result.stderr}`,
        )
        const denials = spawnSync(
          `log show --last 1m --style compact --predicate 'eventMessage CONTAINS "CMD64_"'`,
          { shell: true, encoding: 'utf8', timeout: 30000 },
        )
        console.error(
          `sandbox denials:\n${(denials.stdout ?? '').slice(-6000)}`,
        )
      }

      expect(result.status).toBe(0)
    })
  },
)

describe.if(isMacOS && !baselineOpenWorks)(
  'macOS Seatbelt allowAppleEvents end to end (environment cannot send Apple Events)',
  () => {
    it.skip('skipped: `open -g -a Finder .` fails outside the sandbox in this environment', () => {})
  },
)
