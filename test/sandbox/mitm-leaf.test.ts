import { describe, test, expect } from 'bun:test'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { X509Certificate } from 'node:crypto'
import { createSecureContext } from 'node:tls'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'
import { mintLeafCert, secureContextFor } from '../../src/sandbox/mitm-leaf.js'
import { whichSync } from '../../src/utils/which.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const CA_CERT = join(FIXTURE_DIR, 'ca.crt')
const CA_KEY = join(FIXTURE_DIR, 'ca.key')

describe('mitm-leaf: mintLeafCert', () => {
  // One CA per describe — createMitmCA is pure, leaf cache is per-CA.
  const ca = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })

  test('mints a leaf with CN, DNS SAN, and serverAuth EKU', () => {
    const leaf = mintLeafCert(ca, 'example.com')
    // certPem is leaf+CA chain — split off the first PEM block.
    const leafOnly = firstPemBlock(leaf.certPem)
    const x = new X509Certificate(leafOnly)
    expect(x.subject).toContain('CN=example.com')
    expect(x.subjectAltName).toContain('DNS:example.com')
    expect(x.keyUsage).toContain('1.3.6.1.5.5.7.3.1') // serverAuth OID
    expect(x.ca).toBe(false)
    // Issuer matches the fixture CA's subject.
    expect(x.issuer).toContain('CN=srt-test-ca DO NOT TRUST')
  })

  test('uses an IP SAN for IP-literal hostnames', () => {
    const leaf = mintLeafCert(ca, '127.0.0.1')
    const x = new X509Certificate(firstPemBlock(leaf.certPem))
    expect(x.subjectAltName).toContain('IP Address:127.0.0.1')
  })

  test('Node tls accepts the cert+key as a SecureContext', () => {
    const leaf = mintLeafCert(ca, 'example.com')
    expect(() =>
      createSecureContext({ cert: leaf.certPem, key: leaf.keyPem }),
    ).not.toThrow()
  })

  test('caches per (CA instance, hostname)', () => {
    const a = secureContextFor(ca, 'cached.example')
    expect(secureContextFor(ca, 'cached.example')).toBe(a)
    expect(secureContextFor(ca, 'other.example')).not.toBe(a)
    // A different CA instance gets its own cache.
    const ca2 = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    expect(secureContextFor(ca2, 'cached.example')).not.toBe(a)
  })

  test('mintLeafCert caches per (CA instance, hostname)', () => {
    const a = mintLeafCert(ca, 'mint-cache.example')
    expect(mintLeafCert(ca, 'mint-cache.example')).toBe(a)
    const ca2 = createMitmCA({ caCertPath: CA_CERT, caKeyPath: CA_KEY })
    expect(mintLeafCert(ca2, 'mint-cache.example')).not.toBe(a)
  })

  test('leaf validity is clamped to ≤825 days', () => {
    const leaf = mintLeafCert(ca, 'validity.example')
    const x = new X509Certificate(firstPemBlock(leaf.certPem))
    const days =
      (Date.parse(x.validTo) - Date.parse(x.validFrom)) / (1000 * 60 * 60 * 24)
    expect(days).toBeGreaterThan(800)
    expect(days).toBeLessThanOrEqual(827) // 825 + 1-day notBefore backdating + slop
  })

  // Chain verification via openssl — the strongest correctness signal.
  // Skipped only if openssl is unavailable.
  const verifyTest = whichSync('openssl') !== null ? test : test.skip
  verifyTest('leaf verifies against the CA via `openssl verify`', () => {
    const leaf = mintLeafCert(ca, 'verify.example')
    const dir = mkdtempSync(join(tmpdir(), 'srt-mitm-leaf-'))
    try {
      const leafPath = join(dir, 'leaf.crt')
      writeFileSync(leafPath, firstPemBlock(leaf.certPem))
      const out = execFileSync(
        'openssl',
        ['verify', '-CAfile', CA_CERT, leafPath],
        { encoding: 'utf8' },
      )
      expect(out.trim()).toMatch(/: OK$/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

function firstPemBlock(pem: string): string {
  const m = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----\r?\n?/,
  )
  if (!m) throw new Error('no PEM CERTIFICATE block found')
  return m[0]
}
