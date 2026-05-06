import { describe, test, expect, beforeEach, afterAll } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  loadMitmCA,
  getMitmCA,
  resetMitmCA,
} from '../../src/sandbox/mitm-ca.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const certPath = join(FIXTURE_DIR, 'ca.crt')
const keyPath = join(FIXTURE_DIR, 'ca.key')
const certPem = readFileSync(certPath, 'utf8')
const keyPem = readFileSync(keyPath, 'utf8')

describe('mitm-ca: loadMitmCA', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'srt-mitm-ca-'))
  const junkPath = join(scratch, 'junk.txt')
  writeFileSync(junkPath, 'not pem\n')

  beforeEach(() => {
    resetMitmCA()
  })

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  test('loads a real cert+key pair and exposes it via getMitmCA', () => {
    const ca = loadMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(ca.certPath).toBe(certPath)
    expect(ca.keyPath).toBe(keyPath)
    expect(ca.certPem).toBe(certPem)
    expect(ca.keyPem).toBe(keyPem)
    expect(ca.certPem).toContain('-----BEGIN CERTIFICATE-----')
    // openssl req -nodes emits PKCS8 ("PRIVATE KEY"); the loader's regex also
    // accepts PKCS1 "RSA PRIVATE KEY" / "EC PRIVATE KEY".
    expect(ca.keyPem).toMatch(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/)
    expect(getMitmCA()).toBe(ca)
  })

  test('caches: second call returns the same instance', () => {
    const a = loadMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    const b = loadMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(b).toBe(a)
  })

  test('resetMitmCA clears the cache', () => {
    loadMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(getMitmCA()).toBeDefined()
    resetMitmCA()
    expect(getMitmCA()).toBeUndefined()
  })

  test('throws with field+path+code when cert path is missing', () => {
    const missing = join(scratch, 'nope.crt')
    expect(() =>
      loadMitmCA({ caCertPath: missing, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: cannot read .*nope\.crt \(ENOENT\)/)
    expect(getMitmCA()).toBeUndefined()
  })

  test('throws with field+path+code when key path is missing', () => {
    const missing = join(scratch, 'nope.key')
    expect(() =>
      loadMitmCA({ caCertPath: certPath, caKeyPath: missing }),
    ).toThrow(/tlsTerminate\.caKeyPath: cannot read .*nope\.key \(ENOENT\)/)
  })

  test('throws when cert file is not PEM', () => {
    expect(() =>
      loadMitmCA({ caCertPath: junkPath, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: .* is not a PEM CERTIFICATE/)
  })

  test('throws when key file is not PEM', () => {
    expect(() =>
      loadMitmCA({ caCertPath: certPath, caKeyPath: junkPath }),
    ).toThrow(/tlsTerminate\.caKeyPath: .* is not a PEM PRIVATE KEY/)
  })

  test('throws when cert and key are swapped', () => {
    expect(() =>
      loadMitmCA({ caCertPath: keyPath, caKeyPath: certPath }),
    ).toThrow(/is not a PEM CERTIFICATE/)
  })
})
