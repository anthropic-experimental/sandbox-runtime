import { timingSafeEqual } from 'node:crypto'

/**
 * Constant-time buffer comparison with the length guard built in.
 * `crypto.timingSafeEqual` THROWS on length mismatch, so every call
 * site must pre-check lengths — centralizing the pair prevents a
 * future site from turning a failed auth attempt into an uncaught
 * RangeError in a long-lived process. Length itself is not secret.
 */
export function timingSafeTokenEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b)
}
