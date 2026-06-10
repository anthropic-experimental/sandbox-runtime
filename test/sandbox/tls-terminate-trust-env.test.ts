import { describe, it, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { CA_TRUST_VARS } from '../../src/sandbox/sandbox-utils.js'
import { isMacOS } from '../helpers/platform.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')

describe.if(isMacOS)('tls-terminate trust env injection (macOS)', () => {
  function wrap(cmd: string, caCertPath?: string): string {
    return wrapCommandWithSandboxMacOS({
      command: cmd,
      needsNetworkRestriction: true,
      httpProxyPort: 3128,
      socksProxyPort: 1080,
      caCertPath,
      readConfig: { denyOnly: [], allowWithinDeny: [] },
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    })
  }

  it('wrapped command contains all trust env vars', () => {
    const wrapped = wrap('env', CA_CERT)
    for (const v of CA_TRUST_VARS) {
      // shellquote escapes '=' so the env arg is VAR\=value
      expect(wrapped).toContain(`${v}\\=${CA_CERT}`)
    }
  })

  it('wrapped command omits trust env vars when caCertPath unset', () => {
    const wrapped = wrap('env')
    for (const v of CA_TRUST_VARS) {
      expect(wrapped).not.toContain(v)
    }
  })

  it('child process sees the trust env vars and can read the cert', () => {
    const wrapped = wrap(
      `printf '%s\\n' "$SSL_CERT_FILE" && head -1 "$SSL_CERT_FILE"`,
      CA_CERT,
    )
    const r = spawnSync('bash', ['-c', wrapped], { encoding: 'utf8' })
    expect(r.status).toBe(0)
    const lines = r.stdout.trim().split('\n')
    expect(lines[0]).toBe(CA_CERT)
    expect(lines[1]).toBe('-----BEGIN CERTIFICATE-----')
  })
})
