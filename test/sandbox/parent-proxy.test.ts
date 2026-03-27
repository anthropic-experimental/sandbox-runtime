import { describe, test, expect, beforeEach, afterEach } from 'bun:test'
import {
  resolveParentProxy,
  shouldBypassParentProxy,
  selectParentProxyUrl,
} from '../../src/sandbox/parent-proxy.js'

describe('parent-proxy: resolveParentProxy', () => {
  const saved: Record<string, string | undefined> = {}
  const vars = [
    'HTTP_PROXY',
    'http_proxy',
    'HTTPS_PROXY',
    'https_proxy',
    'NO_PROXY',
    'no_proxy',
  ]

  beforeEach(() => {
    for (const v of vars) {
      saved[v] = process.env[v]
      delete process.env[v]
    }
  })
  afterEach(() => {
    for (const v of vars) {
      if (saved[v] === undefined) delete process.env[v]
      else process.env[v] = saved[v]
    }
  })

  test('returns undefined when nothing is set', () => {
    expect(resolveParentProxy(undefined)).toBeUndefined()
  })

  test('explicit config takes precedence over env', () => {
    process.env.HTTP_PROXY = 'http://env-proxy:8080'
    const r = resolveParentProxy({ http: 'http://cfg-proxy:3128' })
    expect(r?.httpUrl?.href).toBe('http://cfg-proxy:3128/')
  })

  test('falls back to HTTP_PROXY env', () => {
    process.env.HTTP_PROXY = 'http://env-proxy:8080'
    const r = resolveParentProxy(undefined)
    expect(r?.httpUrl?.hostname).toBe('env-proxy')
    // HTTPS falls back to HTTP when HTTPS_PROXY unset
    expect(r?.httpsUrl?.hostname).toBe('env-proxy')
  })

  test('lowercase env vars are honoured', () => {
    process.env.http_proxy = 'http://lower:8080'
    const r = resolveParentProxy(undefined)
    expect(r?.httpUrl?.hostname).toBe('lower')
  })

  test('HTTPS_PROXY distinct from HTTP_PROXY', () => {
    process.env.HTTP_PROXY = 'http://plain:8080'
    process.env.HTTPS_PROXY = 'http://secure:8443'
    const r = resolveParentProxy(undefined)
    expect(r?.httpUrl?.hostname).toBe('plain')
    expect(r?.httpsUrl?.hostname).toBe('secure')
  })
})

describe('parent-proxy: NO_PROXY matching', () => {
  const mk = (noProxy: string) =>
    resolveParentProxy({ http: 'http://p:1', noProxy })!

  test('exact hostname match', () => {
    const r = mk('example.com')
    expect(shouldBypassParentProxy(r, 'example.com', 443)).toBe(true)
    expect(shouldBypassParentProxy(r, 'other.com', 443)).toBe(false)
  })

  test('bare hostname also matches subdomains (golang semantics)', () => {
    const r = mk('example.com')
    expect(shouldBypassParentProxy(r, 'api.example.com', 443)).toBe(true)
  })

  test('leading-dot suffix match', () => {
    const r = mk('.example.com')
    expect(shouldBypassParentProxy(r, 'api.example.com', 443)).toBe(true)
    expect(shouldBypassParentProxy(r, 'example.com', 443)).toBe(true)
    expect(shouldBypassParentProxy(r, 'notexample.com', 443)).toBe(false)
  })

  test('wildcard *. prefix is normalised to leading-dot', () => {
    const r = mk('*.local')
    expect(shouldBypassParentProxy(r, 'foo.local', 443)).toBe(true)
  })

  test('wildcard * matches everything', () => {
    const r = mk('*')
    expect(shouldBypassParentProxy(r, 'anything.com', 443)).toBe(true)
  })

  test('CIDR v4 match', () => {
    const r = mk('10.0.0.0/8,192.168.0.0/16')
    expect(shouldBypassParentProxy(r, '10.1.2.3', 80)).toBe(true)
    expect(shouldBypassParentProxy(r, '192.168.99.1', 80)).toBe(true)
    expect(shouldBypassParentProxy(r, '172.16.0.1', 80)).toBe(false)
    expect(shouldBypassParentProxy(r, '11.0.0.1', 80)).toBe(false)
  })

  test('CIDR v4 /32 exact', () => {
    const r = mk('1.2.3.4/32')
    expect(shouldBypassParentProxy(r, '1.2.3.4', 80)).toBe(true)
    expect(shouldBypassParentProxy(r, '1.2.3.5', 80)).toBe(false)
  })

  test('link-local CIDR', () => {
    const r = mk('169.254.0.0/16')
    expect(shouldBypassParentProxy(r, '169.254.169.254', 80)).toBe(true)
  })

  test('localhost always bypasses regardless of NO_PROXY', () => {
    const r = mk('')
    expect(shouldBypassParentProxy(r, 'localhost', 8080)).toBe(true)
    expect(shouldBypassParentProxy(r, '127.0.0.1', 8080)).toBe(true)
    expect(shouldBypassParentProxy(r, '::1', 8080)).toBe(true)
  })

  test('case-insensitive hostname matching', () => {
    const r = mk('Example.COM')
    expect(shouldBypassParentProxy(r, 'EXAMPLE.com', 443)).toBe(true)
  })

  test('port suffix in NO_PROXY entry is stripped', () => {
    const r = mk('example.com:8080')
    expect(shouldBypassParentProxy(r, 'example.com', 443)).toBe(true)
  })

  test('comma-separated list with whitespace', () => {
    const r = mk(' foo.com , bar.com ,  10.0.0.0/8 ')
    expect(shouldBypassParentProxy(r, 'foo.com', 443)).toBe(true)
    expect(shouldBypassParentProxy(r, 'bar.com', 443)).toBe(true)
    expect(shouldBypassParentProxy(r, '10.1.1.1', 443)).toBe(true)
    expect(shouldBypassParentProxy(r, 'baz.com', 443)).toBe(false)
  })
})

describe('parent-proxy: selectParentProxyUrl', () => {
  test('picks https proxy for https, http for http', () => {
    const r = resolveParentProxy({
      http: 'http://plain:1',
      https: 'http://secure:2',
    })!
    expect(selectParentProxyUrl(r, { isHttps: true })?.hostname).toBe('secure')
    expect(selectParentProxyUrl(r, { isHttps: false })?.hostname).toBe('plain')
  })

  test('falls back when only one is set', () => {
    const r = resolveParentProxy({ http: 'http://only:1' })!
    expect(selectParentProxyUrl(r, { isHttps: true })?.hostname).toBe('only')
  })
})
