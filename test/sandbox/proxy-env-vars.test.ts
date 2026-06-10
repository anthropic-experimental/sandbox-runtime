import { describe, it, expect } from 'bun:test'
import {
  generateProxyEnvVars,
  CA_TRUST_VARS,
} from '../../src/sandbox/sandbox-utils.js'

describe('generateProxyEnvVars', () => {
  it('sets CLOUDSDK_PROXY_TYPE to http (gcloud rejects "https")', () => {
    // gcloud's proxy/type only accepts http, http_no_tunnel, socks4, socks5.
    // Our local proxy is an HTTP CONNECT proxy regardless of the traffic it
    // tunnels, so the value must be "http" — see issue #151.
    const env = generateProxyEnvVars(3128, 1080)

    expect(env).toContain('CLOUDSDK_PROXY_TYPE=http')
    expect(env).toContain('CLOUDSDK_PROXY_ADDRESS=localhost')
    expect(env).toContain('CLOUDSDK_PROXY_PORT=3128')
    expect(env).not.toContain('CLOUDSDK_PROXY_TYPE=https')
  })

  it('omits CLOUDSDK_PROXY_* when no HTTP proxy port is configured', () => {
    const env = generateProxyEnvVars(undefined, 1080)

    expect(env.some(v => v.startsWith('CLOUDSDK_PROXY_'))).toBe(false)
  })

  describe('caCertPath', () => {
    it('sets all trust env vars to the CA path when provided', () => {
      const env = generateProxyEnvVars(3128, 1080, '/etc/srt/ca.crt')
      for (const v of CA_TRUST_VARS) {
        expect(env).toContain(`${v}=/etc/srt/ca.crt`)
      }
    })

    it('sets trust env vars even when no proxy ports are configured', () => {
      // tlsTerminate implies network restriction in practice, but the env-var
      // helper should not couple the two.
      const env = generateProxyEnvVars(undefined, undefined, '/etc/srt/ca.crt')
      for (const v of CA_TRUST_VARS) {
        expect(env).toContain(`${v}=/etc/srt/ca.crt`)
      }
    })

    it('omits trust env vars when caCertPath is not provided', () => {
      const env = generateProxyEnvVars(3128, 1080)
      for (const v of CA_TRUST_VARS) {
        expect(env.some(e => e.startsWith(`${v}=`))).toBe(false)
      }
    })
  })
})
