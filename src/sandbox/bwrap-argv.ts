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
  /** The inner shell script (the last element after `--`); 0 without a
   *  `--` trailer. */
  innerCommandBytes: number
  /** Per term, its occurrences and the bytes of its words. A mount/env
   *  option and its operands count once; under `other` every remaining
   *  element counts on its own. The terms partition the vector. */
  terms: Record<BwrapArgvTerm, { count: number; bytes: number }>
}

type BwrapOptionSpec = { arity: number; term: BwrapArgvTerm }

/**
 * The bwrap options this package emits (plus close relatives): operand count
 * and the term they are accounted under. Unknown `--options` are bare flags
 * under `other`. A Map, so an operand spelled like an Object.prototype
 * member (`constructor`) cannot resolve to one.
 */
const BWRAP_OPTIONS: ReadonlyMap<string, BwrapOptionSpec> = new Map<
  string,
  BwrapOptionSpec
>([
  ['--ro-bind', { arity: 2, term: 'roBindOther' }], // refined by its operands
  ['--bind', { arity: 2, term: 'bind' }],
  ['--tmpfs', { arity: 1, term: 'tmpfs' }],
  ['--setenv', { arity: 2, term: 'setenv' }],
  ['--dev-bind', { arity: 2, term: 'other' }],
  ['--ro-bind-try', { arity: 2, term: 'other' }],
  ['--bind-try', { arity: 2, term: 'other' }],
  ['--dev-bind-try', { arity: 2, term: 'other' }],
  ['--symlink', { arity: 2, term: 'other' }],
  ['--unsetenv', { arity: 1, term: 'other' }],
  ['--dev', { arity: 1, term: 'other' }],
  ['--proc', { arity: 1, term: 'other' }],
  ['--dir', { arity: 1, term: 'other' }],
  ['--chdir', { arity: 1, term: 'other' }],
  ['--cap-add', { arity: 1, term: 'other' }],
  ['--cap-drop', { arity: 1, term: 'other' }],
  ['--remount-ro', { arity: 1, term: 'other' }],
])
const BARE_FLAG: BwrapOptionSpec = { arity: 0, term: 'other' }

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

  // Every element is accounted exactly once, so the totals ride along.
  const account = (term: BwrapArgvTerm, from: number, to: number): void => {
    terms[term].count++
    for (let k = from; k < to; k++) {
      const byteCount = argBytes(argv[k]!)
      terms[term].bytes += byteCount
      totalBytes += byteCount
      if (byteCount > largestArgBytes) largestArgBytes = byteCount
    }
  }

  let innerCommandBytes = 0
  let i = 0
  if (argv.length > 0) {
    account('other', 0, 1) // the bwrap executable itself
    i = 1
  }
  while (i < argv.length) {
    const option = argv[i]!
    if (option === '--') {
      // Trailer: shell, '-c', inner script. Each word is its own `other`.
      for (let k = i; k < argv.length; k++) account('other', k, k + 1)
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
    if (term === 'other') {
      for (let k = i; k < end; k++) account('other', k, k + 1)
    } else {
      account(term, i, end)
    }
    i = end
  }

  return { totalBytes, largestArgBytes, innerCommandBytes, terms }
}
