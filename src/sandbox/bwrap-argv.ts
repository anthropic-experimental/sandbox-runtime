/**
 * Size diagnostics for a bwrap argv, for an embedder that hits E2BIG or wants
 * to warn before it does. Pure; never touches the filesystem.
 */

/** Mount/env categories {@link describeBwrapArgv} breaks a bwrap argv into. */
export type BwrapArgvTerm =
  | 'roBindSelf'
  | 'roBindDevNull'
  | 'roBindOther'
  | 'bind'
  | 'tmpfs'
  | 'setenv'
  | 'other'

/**
 * Size breakdown of a bwrap argv; see {@link describeBwrapArgv}. Every byte
 * count is what execve() charges: UTF-8 length + 1 (the NUL) per element.
 */
export interface BwrapArgvSummary {
  /** The whole vector. */
  totalBytes: number
  /** The largest single element: the number to compare against Linux's
   *  per-argument MAX_ARG_STRLEN (128 KiB on 4 KiB-page kernels). */
  largestArgBytes: number
  /** The inner shell script: the last element after `--`, or after the
   *  `-c` of the `[shell, '-c', script]` vector wrapWithSandboxArgv returns
   *  when no sandbox applies; 0 without either trailer. */
  innerCommandBytes: number
  /** Per term, its occurrences and the bytes of its words. A mount/env
   *  option and its operands count once; under `other` every remaining
   *  element counts on its own. The terms partition the vector. */
  terms: Record<BwrapArgvTerm, { count: number; bytes: number }>
}

type BwrapOptionSpec = { arity: number; term: BwrapArgvTerm }

/**
 * The bwrap options that get a term of their own: operand count and term.
 * Every other `--option` is a bare flag under `other` and its operands are
 * re-read as bare words (`--dev /dev` is two `other` elements) — the same
 * accounting, unless an operand is itself spelled like one of these options
 * or `--`, which nothing this package emits does. A Map, so an operand
 * spelled like an Object.prototype member (`constructor`) cannot resolve to
 * one.
 */
const BWRAP_OPTIONS: ReadonlyMap<string, BwrapOptionSpec> = new Map<
  string,
  BwrapOptionSpec
>([
  ['--ro-bind', { arity: 2, term: 'roBindOther' }], // refined by its operands
  ['--bind', { arity: 2, term: 'bind' }],
  ['--tmpfs', { arity: 1, term: 'tmpfs' }],
  ['--setenv', { arity: 2, term: 'setenv' }],
])
const BARE_FLAG: BwrapOptionSpec = { arity: 0, term: 'other' }

/** Linux's per-argument cap (MAX_ARG_STRLEN, 32 pages) on 4 KiB-page kernels. */
export const LINUX_MAX_ARG_STRLEN = 128 * 1024

/**
 * Break a bwrap argv (as returned by wrapCommandWithSandboxLinuxArgv) down
 * by mount/env term with execve()-style byte accounting.
 */
export function describeBwrapArgv(argv: readonly string[]): BwrapArgvSummary {
  const argBytes = (s: string): number => Buffer.byteLength(s, 'utf8') + 1
  const terms: BwrapArgvSummary['terms'] = {
    roBindSelf: { count: 0, bytes: 0 },
    roBindDevNull: { count: 0, bytes: 0 },
    roBindOther: { count: 0, bytes: 0 },
    bind: { count: 0, bytes: 0 },
    tmpfs: { count: 0, bytes: 0 },
    setenv: { count: 0, bytes: 0 },
    other: { count: 0, bytes: 0 },
  }
  let totalBytes = 0
  let largestArgBytes = 0

  // Every element is accounted exactly once, so the totals ride along. A
  // mount/env option and its operands count once; `other` counts per element.
  const account = (term: BwrapArgvTerm, from: number, to: number): void => {
    terms[term].count += term === 'other' ? to - from : 1
    for (let k = from; k < to; k++) {
      const byteCount = argBytes(argv[k]!)
      terms[term].bytes += byteCount
      totalBytes += byteCount
      if (byteCount > largestArgBytes) largestArgBytes = byteCount
    }
  }

  let innerCommandBytes = 0
  let i = 0 // argv[0], the executable, falls through to BARE_FLAG
  while (i < argv.length) {
    const option = argv[i]!
    // bwrap has no `-c` option, so one right after argv[0] marks the
    // `[shell, '-c', script]` form (no sandbox needed), not a bwrap vector.
    if (option === '--' || (i === 1 && option === '-c')) {
      // Trailer: shell, '-c', inner script.
      account('other', i, argv.length)
      if (argv.length - 1 > i) {
        innerCommandBytes = argBytes(argv[argv.length - 1]!)
      }
      break
    }
    const spec = BWRAP_OPTIONS.get(option) ?? BARE_FLAG
    const end = Math.min(i + 1 + spec.arity, argv.length)
    let term = spec.term
    if (option === '--ro-bind') {
      const src = argv[i + 1]
      const dest = argv[i + 2]
      term =
        src === '/dev/null'
          ? 'roBindDevNull'
          : src !== undefined && src === dest
            ? 'roBindSelf'
            : 'roBindOther'
    }
    account(term, i, end)
    i = end
  }

  return { totalBytes, largestArgBytes, innerCommandBytes, terms }
}

/**
 * The warning to raise when `wrapped` — `argv` rendered for `sh -c` — would
 * exceed Linux's per-argument cap as that one argument, or undefined when it
 * fits. A warning rather than a refusal: 16 KiB-page kernels allow 512 KiB,
 * and the kernel already fails such a spawn loudly (E2BIG); the package's
 * job is to say which mounts did it and which output form avoids it.
 */
export function describeBwrapStringOverflow(
  argv: readonly string[],
  wrapped: string,
): string | undefined {
  const bytes = Buffer.byteLength(wrapped, 'utf8') + 1
  if (bytes <= LINUX_MAX_ARG_STRLEN) return undefined
  const { terms, innerCommandBytes } = describeBwrapArgv(argv)
  const t = (term: BwrapArgvTerm): string =>
    `${terms[term].count} (${terms[term].bytes} B)`
  return (
    `[sandbox-runtime] WARNING: the bwrap command line is ${bytes} bytes as a single sh -c argument, ` +
    `over Linux MAX_ARG_STRLEN (${LINUX_MAX_ARG_STRLEN} on 4 KiB-page kernels); spawn will fail with E2BIG. ` +
    `/dev/null masks ${t('roBindDevNull')}, tmpfs ${t('tmpfs')}, other ro-binds ${t('roBindOther')}, ` +
    `self ro-binds ${t('roBindSelf')}, binds ${t('bind')}, setenv ${t('setenv')}, inner script ${innerCommandBytes} B. ` +
    `Use SandboxManager.wrapWithSandboxArgv() (one element per word) or deny enclosing directories instead of file globs.`
  )
}
