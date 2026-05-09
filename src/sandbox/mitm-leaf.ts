/**
 * Per-host leaf certificate minter for the in-process TLS-terminating proxy.
 *
 * Given a MitmCA (see mitm-ca.ts), mints a leaf certificate for a specific
 * hostname on first use and caches it for the lifetime of that CA instance.
 * The leaf is signed by the CA and carries SAN=DNS:<host> (or IP:<addr>),
 * so a client that trusts the CA will accept it for that host.
 */

import forge from 'node-forge'
import { isIP } from 'node:net'
import { createSecureContext, type SecureContext } from 'node:tls'
import { logForDebugging } from '../utils/debug.js'
import type { MitmCA } from './mitm-ca.js'

const { pki, md, random, util } = forge

export type LeafCert = {
  /** Leaf cert PEM followed by the CA cert PEM (full chain). */
  certPem: string
  /** Leaf private key PEM. */
  keyPem: string
}

/**
 * Mint (or return cached) an RSA-2048 leaf cert for `hostname`, signed by `ca`.
 * The cache lives on `ca.leafCerts`.
 */
export function mintLeafCert(ca: MitmCA, hostname: string): LeafCert {
  const cached = ca.leafCerts.get(hostname)
  if (cached) return cached

  const keys = pki.rsa.generateKeyPair(2048)
  const cert = pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = randomSerial()
  cert.validity.notBefore = daysFromNow(-1)
  cert.validity.notAfter = clampValidity(ca.cert)
  cert.setSubject([{ name: 'commonName', value: hostname }])
  cert.setIssuer(ca.cert.subject.attributes)
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    {
      name: 'keyUsage',
      critical: true,
      digitalSignature: true,
      keyEncipherment: true,
    },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [sanFor(hostname)] },
    {
      name: 'authorityKeyIdentifier',
      keyIdentifier:
        (
          ca.cert.getExtension('subjectKeyIdentifier') as {
            subjectKeyIdentifier?: string
          } | null
        )?.subjectKeyIdentifier ?? true,
    },
  ])
  cert.sign(ca.key, md.sha256.create())

  const leaf: LeafCert = {
    certPem: pki.certificateToPem(cert) + ca.certPem,
    keyPem: pki.privateKeyToPem(keys.privateKey),
  }
  ca.leafCerts.set(hostname, leaf)
  logForDebugging(`[mitm-leaf] minted RSA leaf for ${hostname}`)
  return leaf
}

/**
 * Mint-or-cache a Node TLS SecureContext for `hostname`. Intended as the
 * SNICallback target in the terminating proxy. The cache lives on
 * `ca.secureContexts`.
 */
export function secureContextFor(ca: MitmCA, hostname: string): SecureContext {
  const cached = ca.secureContexts.get(hostname)
  if (cached) return cached
  const { certPem, keyPem } = mintLeafCert(ca, hostname)
  const ctx = createSecureContext({ cert: certPem, key: keyPem })
  ca.secureContexts.set(hostname, ctx)
  return ctx
}

function sanFor(hostname: string): {
  type: number
  value?: string
  ip?: string
} {
  // RFC 5280 GeneralName tags: 2 = dNSName, 7 = iPAddress.
  return isIP(hostname) !== 0
    ? { type: 7, ip: hostname }
    : { type: 2, value: hostname }
}

/** Leaf validity capped at min(CA notAfter, now+825d) per CA/B baseline. */
function clampValidity(caCert: forge.pki.Certificate): Date {
  const caEnd = caCert.validity.notAfter
  const max = daysFromNow(825)
  return caEnd < max ? new Date(caEnd) : max
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
