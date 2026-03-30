import { describe, test, expect } from 'bun:test'
import {
  matchesDomainPattern,
  evaluateNetworkRules,
} from '../../src/sandbox/sandbox-manager.js'

describe('matchesDomainPattern', () => {
  describe('exact match', () => {
    test.each([
      ['example.com', 'example.com', true],
      ['example.com', 'other.com', false],
      ['EXAMPLE.com', 'example.com', true], // case-insensitive hostname
      ['example.com', 'EXAMPLE.COM', true], // case-insensitive pattern
      ['Example.Com', 'eXaMpLe.CoM', true],
      ['example.com', 'example.co', false], // no prefix match
      ['example.co', 'example.com', false], // no suffix match
      ['sub.example.com', 'example.com', false], // exact means exact
      ['example.com', 'sub.example.com', false],
      ['', '', true], // degenerate but consistent
      ['example.com.', 'example.com', false], // trailing dot distinguishes (matched pre-canonicalize)
    ])('%p vs pattern %p → %p', (host, pattern, expected) => {
      expect(matchesDomainPattern(host, pattern)).toBe(expected)
    })
  })

  describe('wildcard match', () => {
    test.each([
      // Basic subdomain matching
      ['api.example.com', '*.example.com', true],
      ['www.example.com', '*.example.com', true],
      ['a.b.example.com', '*.example.com', true], // multi-level subdomains match via suffix
      ['a.b.c.example.com', '*.example.com', true],

      // Wildcard does NOT match the apex — requires at least one subdomain label
      ['example.com', '*.example.com', false],

      // Wildcard does NOT match a different apex
      ['example.org', '*.example.com', false],
      ['api.example.org', '*.example.com', false],

      // The dot in .endsWith('.' + base) is load-bearing: these are one
      // typo away from a bypass if suffix matching were naive.
      ['evilexample.com', '*.example.com', false],
      ['notexample.com', '*.example.com', false],
      ['example.com.evil.com', '*.evil.com', true], // this DOES match — the suffix is .evil.com
      ['example.com.evil.com', '*.example.com', false],

      // Case folding
      ['API.Example.COM', '*.example.com', true],
      ['api.example.com', '*.EXAMPLE.COM', true],

      // Dangerous patterns a config author might write by accident
      ['anything.com', '*.com', true], // *.com allows essentially all of .com
      ['a.b.c.d.com', '*.com', true],
    ])('%p vs pattern %p → %p', (host, pattern, expected) => {
      expect(matchesDomainPattern(host, pattern)).toBe(expected)
    })
  })

  describe('wildcard refuses IP literals', () => {
    // An IPv6 zone-ID payload like ::ffff:1.2.3.4%x.allowed.com would pass
    // naive .endsWith() while the OS dials the bare IP. isValidHost already
    // rejects % upstream; the predicate defends too.
    test.each([
      ['192.168.1.1', '*.168.1.1', false],
      ['10.0.0.1', '*.0.0.1', false],
      ['127.0.0.1', '*.0.0.1', false],
      ['::1', '*.1', false],
      // Bracketed IPv6 — stripBrackets in the isIP guard handles these
      ['[::1]', '*.1', false],
      ['[fe80::1]', '*.1', false],
    ])('IP %p never matches wildcard %p', (host, pattern) => {
      expect(matchesDomainPattern(host, pattern)).toBe(false)
    })

    test('IP literals still match exact patterns', () => {
      expect(matchesDomainPattern('192.168.1.1', '192.168.1.1')).toBe(true)
      expect(matchesDomainPattern('10.0.0.1', '10.0.0.1')).toBe(true)
    })
  })
})

describe('evaluateNetworkRules', () => {
  describe('deny precedence', () => {
    test('deny wins when host matches both lists', () => {
      const result = evaluateNetworkRules('example.com', {
        allowedDomains: ['example.com'],
        deniedDomains: ['example.com'],
      })
      expect(result).toBe('deny')
    })

    test('deny wins when allow is wildcard but deny is exact', () => {
      const result = evaluateNetworkRules('internal.example.com', {
        allowedDomains: ['*.example.com'],
        deniedDomains: ['internal.example.com'],
      })
      expect(result).toBe('deny')
    })

    test('deny wins when deny is wildcard but allow is exact', () => {
      const result = evaluateNetworkRules('api.example.com', {
        allowedDomains: ['api.example.com'],
        deniedDomains: ['*.example.com'],
      })
      expect(result).toBe('deny')
    })

    test('list order within deniedDomains does not matter (first match wins, but any match denies)', () => {
      const a = evaluateNetworkRules('x.com', {
        allowedDomains: [],
        deniedDomains: ['y.com', 'x.com', 'z.com'],
      })
      const b = evaluateNetworkRules('x.com', {
        allowedDomains: [],
        deniedDomains: ['x.com', 'y.com', 'z.com'],
      })
      expect(a).toBe('deny')
      expect(b).toBe('deny')
    })
  })

  describe('allow path', () => {
    test('returns allow for exact match with empty deny list', () => {
      const result = evaluateNetworkRules('example.com', {
        allowedDomains: ['example.com'],
        deniedDomains: [],
      })
      expect(result).toBe('allow')
    })

    test('returns allow for wildcard match with empty deny list', () => {
      const result = evaluateNetworkRules('api.example.com', {
        allowedDomains: ['*.example.com'],
        deniedDomains: [],
      })
      expect(result).toBe('allow')
    })

    test('allow wildcard with a non-matching exact deny', () => {
      const result = evaluateNetworkRules('api.example.com', {
        allowedDomains: ['*.example.com'],
        deniedDomains: ['internal.example.com'], // different subdomain
      })
      expect(result).toBe('allow')
    })
  })

  describe('no-match', () => {
    test('empty lists → no-match (caller decides: ask or deny)', () => {
      const result = evaluateNetworkRules('example.com', {
        allowedDomains: [],
        deniedDomains: [],
      })
      expect(result).toBe('no-match')
    })

    test('host in neither list → no-match', () => {
      const result = evaluateNetworkRules('other.com', {
        allowedDomains: ['example.com'],
        deniedDomains: ['bad.com'],
      })
      expect(result).toBe('no-match')
    })

    test('wildcard apex miss → no-match (apex does not match *.apex)', () => {
      const result = evaluateNetworkRules('example.com', {
        allowedDomains: ['*.example.com'],
        deniedDomains: [],
      })
      expect(result).toBe('no-match')
    })
  })

  describe('host validation (runs before rule evaluation)', () => {
    test.each([
      ['evil.com\x00.allowed.com', 'null byte (libc DNS truncates at \\x00)'],
      ['evil.com\r\n.allowed.com', 'CRLF injection'],
      ['::ffff:127.0.0.1%x.allowed.com', 'IPv6 zone-ID bypass'],
      ['a'.repeat(256), 'host exceeds 255 chars'],
      ['', 'empty host'],
    ])('rejects %p (%s) before consulting rules', host => {
      // Even with *.allowed.com in the allow list, these must not pass.
      // They'd match naive suffix comparison while the OS dials something else.
      const result = evaluateNetworkRules(host, {
        allowedDomains: ['*.allowed.com'],
        deniedDomains: [],
      })
      expect(result).toBe('invalid')
    })
  })

  describe('canonicalization (runs before rule evaluation)', () => {
    // inet_aton shorthand: getaddrinfo() dials the expanded form, so
    // string comparison must match the expanded form too.
    test('inet_aton decimal 2130706433 matches 127.0.0.1 in deny list', () => {
      const result = evaluateNetworkRules('2130706433', {
        allowedDomains: [],
        deniedDomains: ['127.0.0.1'],
      })
      expect(result).toBe('deny')
    })

    test('inet_aton shorthand 127.1 matches 127.0.0.1 in deny list', () => {
      const result = evaluateNetworkRules('127.1', {
        allowedDomains: [],
        deniedDomains: ['127.0.0.1'],
      })
      expect(result).toBe('deny')
    })

    test('metadata endpoint 169.254.169.254 as decimal cannot slip past denylist', () => {
      // 169.254.169.254 = 2852039166 decimal. Classic SSRF target.
      const result = evaluateNetworkRules('2852039166', {
        allowedDomains: ['*.example.com'],
        deniedDomains: ['169.254.169.254'],
      })
      expect(result).toBe('deny')
    })

    test('case-folding: uppercase host matches lowercase allow entry', () => {
      const result = evaluateNetworkRules('EXAMPLE.COM', {
        allowedDomains: ['example.com'],
        deniedDomains: [],
      })
      expect(result).toBe('allow')
    })

    test('trailing dot is stripped: example.com. matches example.com', () => {
      const result = evaluateNetworkRules('example.com.', {
        allowedDomains: ['example.com'],
        deniedDomains: [],
      })
      expect(result).toBe('allow')
    })
  })
})
