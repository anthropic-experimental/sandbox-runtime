import { describe, it, expect } from 'bun:test'
import { generateProxyEnvVars } from '../../src/sandbox/sandbox-utils.js'

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
})
