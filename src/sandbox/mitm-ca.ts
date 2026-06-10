/**
 * MITM CA loader/generator for the in-process TLS-terminating proxy.
 *
 * The CA is supplied via `network.tlsTerminate.{caCertPath,caKeyPath}` (see
 * sandbox-config.ts). If both paths are omitted, SRT generates an ephemeral
 * RSA-2048 self-signed CA into a temp directory; the cert path is what the
 * trust env vars point at. The caller is responsible for cleaning up via
 * `disposeMitmCA()` (SandboxManager.reset() does this).
 */

import forge from 'node-forge'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import type { SecureContext } from 'node:tls'
import { logForDebugging } from '../utils/debug.js'
import type { LeafCert } from './mitm-leaf.js'

const { pki, md, random, util } = forge

export type MitmCA = {
  certPath: string
  keyPath: string
  certPem: string
  keyPem: string
  /** Parsed CA certificate (issuer for minted leaf certs). */
  cert: forge.pki.Certificate
  /** Parsed CA private key. RSA only. */
  key: forge.pki.rsa.PrivateKey
  /** Per-hostname cache of leaf certs minted against this CA. */
  leafCerts: Map<string, LeafCert>
  /** Per-hostname cache of TLS SecureContexts wrapping the leaf certs. */
  secureContexts: Map<string, SecureContext>
  /**
   * True when SRT generated this CA into a temp directory. disposeMitmCA()
   * removes that directory; user-supplied CAs are left alone.
   */
  ephemeral: boolean
}

/**
 * Create a MitmCA. If `caCertPath`/`caKeyPath` are provided, load from disk
 * (throws if either file is missing, unreadable, not PEM, fails to parse, or
 * the key is not RSA). If both are omitted, generate an ephemeral CA into a
 * fresh temp directory.
 *
 * Pure factory: no module-level state. The caller (SandboxManager) owns the
 * returned object and its lifetime.
 */
export function createMitmCA(opts: {
  caCertPath?: string
  caKeyPath?: string
}): MitmCA {
  if (opts.caCertPath && opts.caKeyPath) {
    return loadCA(opts.caCertPath, opts.caKeyPath)
  }
  if (opts.caCertPath || opts.caKeyPath) {
    throw new Error(
      'tlsTerminate: caCertPath and caKeyPath must be provided together',
    )
  }
  return generateEphemeralCA()
}

/** Remove the temp directory for an SRT-generated CA. No-op for user CAs. */
export async function disposeMitmCA(ca: MitmCA): Promise<void> {
  if (!ca.ephemeral) return
  try {
    await rm(dirname(ca.certPath), { recursive: true, force: true })
  } catch (err) {
    logForDebugging(`[mitm-ca] cleanup failed: ${(err as Error).message}`, {
      level: 'warn',
    })
  }
}

function loadCA(certPath: string, keyPath: string): MitmCA {
  const certPem = readPem(certPath, 'CERTIFICATE', 'tlsTerminate.caCertPath')
  const keyPem = readPem(keyPath, 'PRIVATE KEY', 'tlsTerminate.caKeyPath')

  let cert: forge.pki.Certificate
  let key: forge.pki.PrivateKey
  try {
    cert = pki.certificateFromPem(certPem)
    key = pki.privateKeyFromPem(keyPem)
  } catch (err) {
    throw new Error(
      `tlsTerminate: failed to parse CA from ${certPath}: ` +
        (err as Error).message,
    )
  }
  if (!('n' in key) || !('d' in key)) {
    // node-forge can only sign with RSA private keys.
    throw new Error(`tlsTerminate.caKeyPath: CA key at ${keyPath} must be RSA`)
  }

  logForDebugging(`[mitm-ca] loaded CA from ${certPath}`)
  return {
    certPath,
    keyPath,
    certPem,
    keyPem,
    cert,
    key: key as forge.pki.rsa.PrivateKey,
    leafCerts: new Map(),
    secureContexts: new Map(),
    ephemeral: false,
  }
}

function generateEphemeralCA(): MitmCA {
  const keys = pki.rsa.generateKeyPair(2048)
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = randomSerial()
  cert.validity.notBefore = daysFromNow(-1)
  cert.validity.notAfter = daysFromNow(825)
  const subject = [
    { name: 'commonName', value: 'sandbox-runtime ephemeral CA' },
    { name: 'organizationName', value: 'sandbox-runtime' },
  ]
  cert.setSubject(subject)
  cert.setIssuer(subject)
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
    },
    { name: 'subjectKeyIdentifier' },
  ])
  cert.sign(keys.privateKey, md.sha256.create())

  const certPem = pki.certificateToPem(cert)
  const keyPem = pki.privateKeyToPem(keys.privateKey)

  // Write to disk so trust env vars (NODE_EXTRA_CA_CERTS etc.) can point at
  // a real path. mkdtemp gives us an unguessable per-process directory.
  const dir = mkdtempSync(join(tmpdir(), 'srt-ca-'))
  const certPath = join(dir, 'ca.crt')
  const keyPath = join(dir, 'ca.key')
  writeFileSync(certPath, certPem, { mode: 0o644 })
  writeFileSync(keyPath, keyPem, { mode: 0o600 })

  logForDebugging(`[mitm-ca] generated ephemeral CA at ${certPath}`)
  return {
    certPath,
    keyPath,
    certPem,
    keyPem,
    cert,
    key: keys.privateKey,
    leafCerts: new Map(),
    secureContexts: new Map(),
    ephemeral: true,
  }
}

function readPem(path: string, label: string, field: string): string {
  let pem: string
  try {
    pem = readFileSync(path, 'utf8')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? String(err)
    throw new Error(`${field}: cannot read ${path} (${code})`)
  }
  // Accept either the exact label or a prefixed variant (e.g. "RSA PRIVATE KEY",
  // "EC PRIVATE KEY") for the key case.
  if (!new RegExp(`-----BEGIN [A-Z ]*${label}-----`).test(pem)) {
    throw new Error(`${field}: ${path} is not a PEM ${label}`)
  }
  return pem
}

function randomSerial(): string {
  // 16 random bytes, high bit cleared so the DER INTEGER stays positive.
  const bytes = random.getBytesSync(16)
  const hex = util.bytesToHex(bytes)
  const firstNibble = parseInt(hex[0]!, 16) & 0x7
  return firstNibble.toString(16) + hex.slice(1)
}

function daysFromNow(days: number): Date {
  const d = new Date()
  d.setDate(d.getDate() + days)
  return d
}
