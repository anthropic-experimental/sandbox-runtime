import { describe, test, expect } from 'bun:test'
import {
  JWT_DEFAULT_EXTRACT_PATTERN,
  maskJwtClaims,
  mintFakeJwt,
  verifyJwt,
} from '../../src/sandbox/credential-decode.js'
import {
  SentinelRegistry,
  SENTINEL_PREFIX,
} from '../../src/sandbox/credential-sentinel.js'

/** base64url-encode a string, as test-fixture shorthand. */
function b64u(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url')
}

// The classic HS256 example token (header {"alg":"HS256","typ":"JWT"}).
const REAL_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.' +
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

describe('JWT_DEFAULT_EXTRACT_PATTERN', () => {
  test('captures a whole JWT as group 1', () => {
    const content = `{"access_token": "${REAL_JWT}", "expires": 9}`
    const m = content.match(new RegExp(JWT_DEFAULT_EXTRACT_PATTERN))
    expect(m).not.toBeNull()
    expect(m![1]).toBe(REAL_JWT)
  })

  test('does not match a two-segment or non-eyJ string', () => {
    const re = new RegExp(JWT_DEFAULT_EXTRACT_PATTERN)
    expect('abc.def.ghi').not.toMatch(re)
    expect('eyJhbGci.eyJzdWIi').not.toMatch(re)
  })
})

describe('verifyJwt', () => {
  test('a real JWT passes', () => {
    expect(verifyJwt(REAL_JWT)).toBe(true)
  })

  test('a random base64 blob fails (no segments)', () => {
    expect(verifyJwt(b64u('this is not a jwt'))).toBe(false)
  })

  test('a two-segment candidate fails', () => {
    const [h, p] = REAL_JWT.split('.')
    expect(verifyJwt(`${h}.${p}`)).toBe(false)
  })

  test('a four-segment candidate fails', () => {
    expect(verifyJwt(`${REAL_JWT}.extra`)).toBe(false)
  })

  test('a non-JSON header fails', () => {
    // Decodes to `{"oops` — truncated JSON, parse error.
    expect(verifyJwt(`${b64u('{"oops')}.${b64u('{}')}.c2ln`)).toBe(false)
  })

  test('a JSON header without an alg property fails', () => {
    expect(
      verifyJwt(`${b64u('{"typ":"JWT"}')}.${b64u('{"sub":"x"}')}.c2ln`),
    ).toBe(false)
  })

  test('a non-JSON payload fails', () => {
    expect(
      verifyJwt(`${b64u('{"alg":"HS256"}')}.${b64u('not json')}.c2ln`),
    ).toBe(false)
  })
})

describe('mintFakeJwt', () => {
  test('deterministic given the uuid', () => {
    expect(mintFakeJwt('u-1')).toBe(mintFakeJwt('u-1'))
    expect(mintFakeJwt('u-1')).not.toBe(mintFakeJwt('u-2'))
  })

  test('mints a structurally valid JWT', () => {
    expect(verifyJwt(mintFakeJwt('u'))).toBe(true)
  })

  test('header is exactly {"alg":"HS256","typ":"JWT"} — never alg:none', () => {
    // alg:none tokens are accepted by misconfigured validators; an HS256
    // header forces signature verification, which the garbage signature
    // always fails — so an unswapped fake is rejected by every validator.
    const header = JSON.parse(
      Buffer.from(mintFakeJwt('u').split('.')[0]!, 'base64url').toString(
        'utf8',
      ),
    ) as Record<string, unknown>
    expect(header).toEqual({ alg: 'HS256', typ: 'JWT' })
  })

  test('signature segment is the fixed filler', () => {
    expect(mintFakeJwt('u').split('.')[2]).toBe('c3J0LWZha2U')
  })

  test('payload carries the sentinel identity and a fixed far-future exp', () => {
    const payload = JSON.parse(
      Buffer.from(mintFakeJwt('abc').split('.')[1]!, 'base64url').toString(
        'utf8',
      ),
    ) as { sub: string; exp: number }
    expect(payload.sub).toBe(`${SENTINEL_PREFIX}abc`)
    expect(payload.exp).toBe(9999999999)
  })

  test('the minted fake matches the default extraction pattern', () => {
    // A re-run over an already-masked file must still see the fake as a
    // JWT candidate (idempotent registry handles re-registration).
    expect(mintFakeJwt('u')).toMatch(
      new RegExp(`^${JWT_DEFAULT_EXTRACT_PATTERN}$`),
    )
  })
})

describe('maskJwtClaims', () => {
  // Header with a kid, so header reuse is observable (mintFakeJwt's
  // header has no kid).
  const HEADER = b64u('{"alg":"RS256","typ":"JWT","kid":"key-7"}')
  const PAYLOAD = {
    sub: 'user-1',
    api_key: 'real-secret',
    aud: 'https://api.example.com',
    n: 42,
    naïve: 'café', // non-ASCII survives JSON.stringify re-encoding
  }
  const TOKEN = `${HEADER}.${b64u(JSON.stringify(PAYLOAD))}.cmVhbC1zaWc`

  const sentinelFor = (claim: string, _real: string) => `fake_value_${claim}`

  test('the named claim is replaced; every other claim decodes verbatim', () => {
    const result = maskJwtClaims(TOKEN, ['api_key'], sentinelFor)
    expect(result).not.toBeNull()
    const payload = JSON.parse(
      Buffer.from(result!.fakeToken.split('.')[1]!, 'base64url').toString(
        'utf8',
      ),
    ) as Record<string, unknown>
    expect(payload).toEqual({ ...PAYLOAD, api_key: 'fake_value_api_key' })
    expect(result!.claimSentinels).toEqual(
      new Map([['api_key', 'fake_value_api_key']]),
    )
    expect(result!.fakeToken).not.toContain(b64u(JSON.stringify(PAYLOAD)))
  })

  test('the header segment is reused byte-identical', () => {
    const result = maskJwtClaims(TOKEN, ['api_key'], sentinelFor)
    expect(result!.fakeToken.split('.')[0]).toBe(HEADER)
  })

  test('the signature is the fixed filler, never the real signature', () => {
    // The real signature over a modified payload would give the sandbox
    // a public-key brute-force oracle for a low-entropy masked claim.
    const result = maskJwtClaims(TOKEN, ['api_key'], sentinelFor)
    expect(result!.fakeToken.split('.')[2]).toBe('c3J0LWZha2U')
    expect(result!.fakeToken.split('.')[2]).toBe(mintFakeJwt('u').split('.')[2])
  })

  test('the rebuilt token still verifies as a JWT', () => {
    // A re-run over an already-masked file must see the fake as a
    // candidate again (idempotent registry handles re-registration).
    expect(
      verifyJwt(maskJwtClaims(TOKEN, ['api_key'], sentinelFor)!.fakeToken),
    ).toBe(true)
  })

  test('an absent claim is skipped; present ones still mask', () => {
    const result = maskJwtClaims(TOKEN, ['nope', 'api_key'], sentinelFor)
    expect(result).not.toBeNull()
    expect([...result!.claimSentinels.keys()]).toEqual(['api_key'])
  })

  test('a non-string claim is skipped; present ones still mask', () => {
    const result = maskJwtClaims(TOKEN, ['n', 'api_key'], sentinelFor)
    expect(result).not.toBeNull()
    expect([...result!.claimSentinels.keys()]).toEqual(['api_key'])
    const payload = JSON.parse(
      Buffer.from(result!.fakeToken.split('.')[1]!, 'base64url').toString(
        'utf8',
      ),
    ) as Record<string, unknown>
    expect(payload.n).toBe(42)
  })

  test('no named claim matching → null, sentinelFor never invoked', () => {
    let calls = 0
    const counting = (claim: string) => {
      calls++
      return `fake_value_${claim}`
    }
    expect(maskJwtClaims(TOKEN, ['nope', 'n'], counting)).toBeNull()
    expect(calls).toBe(0)
  })

  test('a non-object JSON payload → null', () => {
    // verifyJwt only requires the payload to parse as JSON — a scalar or
    // array payload has no claims to mask.
    const scalar = `${HEADER}.${b64u('"just-a-string"')}.c2ln`
    const array = `${HEADER}.${b64u('["a","b"]')}.c2ln`
    expect(maskJwtClaims(scalar, ['api_key'], sentinelFor)).toBeNull()
    expect(maskJwtClaims(array, ['api_key'], sentinelFor)).toBeNull()
  })

  test('deterministic given the sentinels', () => {
    expect(maskJwtClaims(TOKEN, ['api_key'], sentinelFor)!.fakeToken).toBe(
      maskJwtClaims(TOKEN, ['api_key'], sentinelFor)!.fakeToken,
    )
  })
})

describe('SentinelRegistry.registerWithSentinel', () => {
  const eq = (h: string, p: string) => h === p

  test('roundtrip: JWT-shaped sentinel maps back to the real JWT', () => {
    const reg = new SentinelRegistry()
    const fake = mintFakeJwt('u')
    const got = reg.registerWithSentinel('cred', fake, REAL_JWT, ['api.x.com'])
    expect(got).toBe(fake)
    expect(reg.lookupReal(fake)).toBe(REAL_JWT)
  })

  test('substituteInHeaders swaps a sentinel that lacks the fake_value_ prefix', () => {
    // The JWT fake does not contain the literal SENTINEL_PREFIX (it is
    // base64url-encoded inside the payload), so this exercises the
    // disabled fast path in substituteInString.
    const reg = new SentinelRegistry()
    const fake = mintFakeJwt('u')
    expect(fake).not.toContain(SENTINEL_PREFIX)
    reg.registerWithSentinel('cred', fake, REAL_JWT, ['api.x.com'])

    const headers = { authorization: `Bearer ${fake}` }
    reg.substituteInHeaders(headers, 'api.x.com', eq)
    expect(headers.authorization).toBe(`Bearer ${REAL_JWT}`)
  })

  test('a JWT sentinel does not substitute at a non-injectHost', () => {
    const reg = new SentinelRegistry()
    const fake = mintFakeJwt('u')
    reg.registerWithSentinel('cred', fake, REAL_JWT, ['api.x.com'])

    const headers = { authorization: `Bearer ${fake}` }
    reg.substituteInHeaders(headers, 'evil.example.com', eq)
    expect(headers.authorization).toBe(`Bearer ${fake}`)
  })

  test('idempotent on name: repeat call keeps the first sentinel, updates the value', () => {
    const reg = new SentinelRegistry()
    const first = reg.registerWithSentinel('n', mintFakeJwt('a'), 'real-1', [])
    const second = reg.registerWithSentinel('n', mintFakeJwt('b'), 'real-2', [])
    expect(second).toBe(first)
    expect(reg.lookupReal(first)).toBe('real-2')
    expect(reg.size).toBe(1)
  })

  test('prefixed register() fast path still works alongside JWT sentinels', () => {
    const reg = new SentinelRegistry()
    const plain = reg.register('env', 'real-plain', ['api.x.com'])
    reg.registerWithSentinel('jwt', mintFakeJwt('u'), REAL_JWT, ['api.x.com'])

    const headers = { 'x-api-key': plain }
    reg.substituteInHeaders(headers, 'api.x.com', eq)
    expect(headers['x-api-key']).toBe('real-plain')
  })

  test('clear() restores the fast path state', () => {
    const reg = new SentinelRegistry()
    reg.registerWithSentinel('jwt', mintFakeJwt('u'), REAL_JWT, ['api.x.com'])
    reg.clear()
    expect(reg.size).toBe(0)
    // After clear, a fresh prefixed credential still substitutes.
    const plain = reg.register('env', 'real-plain', ['api.x.com'])
    const headers = { authorization: plain }
    reg.substituteInHeaders(headers, 'api.x.com', eq)
    expect(headers.authorization).toBe('real-plain')
  })
})
