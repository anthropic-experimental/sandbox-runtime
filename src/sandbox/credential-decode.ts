/**
 * Decoding support for encoded credential formats (`decode` on a
 * `credentials.files` entry). Currently JWT only.
 *
 * Pure helpers: the default extraction pattern for finding JWT candidates
 * in a file, the verification predicate that confirms a candidate actually
 * is a JWT before it gets masked, and the minting of a JWT-shaped fake to
 * stand in for the real token inside the sandbox.
 */

import { SENTINEL_PREFIX } from './credential-sentinel.js'

/**
 * Default `extract` pattern for `decode: "jwt"` entries.
 *
 * A JWT's first segment is the base64url encoding of a JSON header that
 * starts `{"` (it always declares `alg`/`typ`), and base64url of `{"` is
 * `eyJ` — so every JWT starts with `eyJ`. Capture group 1 is the whole
 * three-segment token. The pattern over-matches (any eyJ-prefixed
 * base64url triple); {@link verifyJwt} filters the false positives.
 */
export const JWT_DEFAULT_EXTRACT_PATTERN =
  '(eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)'

/** Parse a base64url segment as JSON, or undefined if either step fails. */
function decodeSegment(segment: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'))
  } catch {
    return undefined
  }
}

/**
 * True when `candidate` is structurally a JWT: three dot-separated
 * segments, the first two base64url-decoding to JSON, and the header
 * (segment 1) declaring an `alg` property.
 *
 * Used to filter extraction candidates before masking — a regex match
 * that fails this check (e.g. a random base64 blob the default pattern
 * over-matched) is left untouched rather than masked.
 */
export function verifyJwt(candidate: string): boolean {
  const parts = candidate.split('.')
  if (parts.length !== 3) return false
  const header = decodeSegment(parts[0]!)
  if (typeof header !== 'object' || header === null || !('alg' in header)) {
    return false
  }
  return decodeSegment(parts[1]!) !== undefined
}

/**
 * Fixed far-future `exp` claim for fake JWTs (2286-11-20). A constant, not
 * an offset from now, so the fake is fully deterministic given the uuid.
 */
const FAKE_JWT_EXP = 9999999999

/** Fixed signature filler: base64url("srt-fake"). Never a valid signature. */
const FAKE_JWT_SIGNATURE = 'c3J0LWZha2U'

function base64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url')
}

/**
 * Mint a structurally valid fake JWT carrying the sentinel identity
 * `fake_value_<uuid>` in its `sub` claim. Deterministic given `uuid`.
 *
 * The fake is parseable by client-side JWT handling (three segments, JSON
 * header/payload, far-future `exp`), so a tool inside the sandbox that
 * inspects the token before sending it doesn't break. The header says
 * `alg: HS256` — NOT `alg: none` — deliberately: misconfigured validators
 * accept `alg: none` tokens as valid, whereas an HS256 header forces every
 * validator to attempt signature verification and reject the garbage
 * signature. So if the fake ever reaches a verifier unswapped (e.g. sent
 * to a non-injectHosts destination, the designed fail-closed pass-through),
 * it is cryptographically rejected.
 */
export function mintFakeJwt(uuid: string): string {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = base64url(
    JSON.stringify({ sub: SENTINEL_PREFIX + uuid, exp: FAKE_JWT_EXP }),
  )
  return `${header}.${payload}.${FAKE_JWT_SIGNATURE}`
}

/** Result of {@link maskJwtClaims}. */
export interface MaskedClaimsResult {
  /**
   * The rebuilt token: the original header segment verbatim, the modified
   * payload re-encoded, and the fixed filler signature.
   */
  fakeToken: string
  /** Claim name → the sentinel now carried in the fake payload. */
  claimSentinels: Map<string, string>
}

/**
 * Claim-level masking for a verified JWT: replace each named top-level
 * payload claim that is present with a string value by a caller-provided
 * sentinel, and rebuild the token around the modified payload.
 *
 * The rebuilt token is `header.payload'.signature-filler`:
 *
 * - **Header**: the original base64url segment is reused verbatim, so the
 *   token still advertises the real `alg`/`typ`/`kid` and client-side
 *   header inspection sees exactly what it would outside the sandbox.
 * - **Payload**: the decoded object with the named claims swapped for
 *   sentinels, re-encoded with `JSON.stringify`. Key order and whitespace
 *   inside the payload segment may differ from the original encoding —
 *   irrelevant to any JSON consumer, and the segment bytes change anyway
 *   because a claim value changed.
 * - **Signature**: the fixed filler from {@link mintFakeJwt}, NOT the real
 *   signature. For RS/ES algorithms signature verification needs only the
 *   public key, so shipping the real signature over a modified payload
 *   would hand the sandbox an offline brute-force oracle for a low-entropy
 *   masked claim (guess the claim, re-encode, verify). The filler also
 *   keeps the fake a non-credential end to end, consistent with the
 *   garbage-signature rationale in {@link mintFakeJwt}.
 *
 * Claims that are absent from the payload, or present with a non-string
 * value, are skipped (the caller logs them). Returns `null` — without
 * invoking `sentinelFor` — when no named claim matched, or when the
 * payload does not decode to a JSON object; the caller routes that
 * through its no-match policy.
 *
 * Pure on `token`/`claims`; the callback may close over a registry.
 */
export function maskJwtClaims(
  token: string,
  claims: readonly string[],
  sentinelFor: (claim: string, realValue: string) => string,
): MaskedClaimsResult | null {
  const [headerSeg, payloadSeg] = token.split('.')
  const payload = decodeSegment(payloadSeg ?? '')
  // verifyJwt only guarantees the payload is JSON — it could still be a
  // scalar or array, which has no claims to mask.
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload))
    return null
  const record = payload as Record<string, unknown>

  // Collect matches before minting any sentinel, so a null return never
  // leaves an orphaned registration behind in the caller's registry.
  const matched: Array<[claim: string, value: string]> = []
  for (const claim of claims) {
    const value = record[claim]
    if (typeof value === 'string') matched.push([claim, value])
  }
  if (matched.length === 0) return null

  const claimSentinels = new Map<string, string>()
  for (const [claim, value] of matched) {
    const sentinel = sentinelFor(claim, value)
    record[claim] = sentinel
    claimSentinels.set(claim, sentinel)
  }
  return {
    fakeToken: `${headerSeg}.${base64url(JSON.stringify(record))}.${FAKE_JWT_SIGNATURE}`,
    claimSentinels,
  }
}
