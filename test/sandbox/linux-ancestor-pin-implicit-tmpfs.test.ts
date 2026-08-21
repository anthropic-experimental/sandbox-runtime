import { describe, it, expect } from 'bun:test'
import { existsSync } from 'node:fs'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// The read section mounts an implicit tmpfs at /etc/ssh/ssh_config.d whenever
// readConfig is defined, even with an empty denyOnly, so the pin walk's tmpfs
// exclusion must key on readConfig itself or it pins /etc/ssh above it.
const HOST_SHAPE_PRESENT =
  isLinux &&
  existsSync('/etc/ssh/ssh_config.d') &&
  existsSync('/etc/ssh/ssh_config')

describe.if(HOST_SHAPE_PRESENT)(
  'Linux sandbox — implicit ssh_config.d tmpfs vs ancestor-pin exclusion',
  () => {
    const baseParams = {
      command: 'true',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
    }

    it('does not pin /etc/ssh above the implicit ssh_config.d tmpfs', async () => {
      const wrapped = await wrapCommandWithSandboxLinux({
        ...baseParams,
        readConfig: { denyOnly: [], allowWithinDeny: [] },
        writeConfig: {
          allowOnly: ['/etc'],
          denyWithinAllow: ['/etc/ssh/ssh_config'],
        },
      })
      expect(wrapped).toMatch(/--tmpfs \/etc\/ssh\/ssh_config\.d(?: |$)/)
      expect(wrapped).not.toMatch(/--bind \/etc\/ssh \/etc\/ssh(?: |$)/)
    })

    it('pins /etc/ssh when there is no readConfig and hence no implicit tmpfs', async () => {
      const wrapped = await wrapCommandWithSandboxLinux({
        ...baseParams,
        readConfig: undefined,
        writeConfig: {
          allowOnly: ['/etc'],
          denyWithinAllow: ['/etc/ssh/ssh_config'],
        },
      })
      expect(wrapped).not.toContain('--tmpfs /etc/ssh/ssh_config.d')
      expect(wrapped).toMatch(/--bind \/etc\/ssh \/etc\/ssh(?: |$)/)
    })
  },
)
