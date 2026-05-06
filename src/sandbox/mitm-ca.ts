/**
 * MITM CA loader for the in-process TLS-terminating proxy.
 *
 * Loads a user-provided CA cert + key from disk. The CA is supplied via
 * `network.tlsTerminate.{caCertPath,caKeyPath}` (see sandbox-config.ts).
 * SRT does not generate the CA itself — TLS termination is opt-in and
 * requires the caller to provide both paths.
 */

import { readFileSync } from 'node:fs'
import { logForDebugging } from '../utils/debug.js'

export type MitmCA = {
  certPath: string
  keyPath: string
  certPem: string
  keyPem: string
}

let ca: MitmCA | undefined

/**
 * Load the MITM CA from the given paths. Throws if either file is missing,
 * unreadable, or not PEM — TLS termination is explicit opt-in, so a bad
 * config is a hard error (same posture as checkDependencies()).
 *
 * Idempotent: subsequent calls return the cached CA.
 */
export function loadMitmCA(opts: {
  caCertPath: string
  caKeyPath: string
}): MitmCA {
  if (ca) return ca

  const { caCertPath: certPath, caKeyPath: keyPath } = opts

  const certPem = readPem(certPath, 'CERTIFICATE', 'tlsTerminate.caCertPath')
  const keyPem = readPem(keyPath, 'PRIVATE KEY', 'tlsTerminate.caKeyPath')

  ca = { certPath, keyPath, certPem, keyPem }
  logForDebugging(`[mitm-ca] loaded CA from ${certPath}`)
  return ca
}

/** Return the cached CA, or undefined if tlsTerminate was not configured. */
export function getMitmCA(): MitmCA | undefined {
  return ca
}

/** Clear the cached CA — for tests / config reload. */
export function resetMitmCA(): void {
  ca = undefined
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
