import { describe, it, expect } from 'bun:test'
import { existsSync } from 'node:fs'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import { isLinux } from '../helpers/platform.js'

// The read section mounts an implicit tmpfs at /etc/ssh/ssh_config.d whenever
// readConfig is defined, even with an empty denyOnly. /etc/ssh above it is
// pinned either way: the pin is emitted straight after the read-only root, so
// the tmpfs still lands on top of it.
const HOST_SHAPE_PRESENT =
  isLinux &&
  existsSync('/etc/ssh/ssh_config.d') &&
  existsSync('/etc/ssh/ssh_config')

describe.if(HOST_SHAPE_PRESENT)(
  'Linux sandbox — ancestor pin beneath the implicit ssh_config.d tmpfs',
  () => {
    const baseParams = {
      command: 'true',
      needsNetworkRestriction: false,
      allowAllUnixSockets: true,
    }
    const PIN = /--ro-bind \/etc\/ssh \/etc\/ssh(?: |$)/
    const TMPFS = /--tmpfs \/etc\/ssh\/ssh_config\.d(?: |$)/

    it('pins /etc/ssh and the implicit ssh_config.d tmpfs still lands on top', async () => {
      const wrapped = await wrapCommandWithSandboxLinux({
        ...baseParams,
        readConfig: { denyOnly: [], allowWithinDeny: [] },
        writeConfig: {
          allowOnly: ['/etc'],
          denyWithinAllow: ['/etc/ssh/ssh_config'],
        },
      })
      expect(wrapped).toMatch(PIN)
      expect(wrapped).toMatch(TMPFS)
      expect(wrapped.search(PIN)).toBeLessThan(wrapped.search(TMPFS))
      // The pin sits beneath the allow root's writable bind too.
      expect(wrapped.search(PIN)).toBeLessThan(
        wrapped.indexOf('--bind /etc /etc'),
      )
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
      expect(wrapped).not.toMatch(TMPFS)
      expect(wrapped).toMatch(PIN)
    })
  },
)
