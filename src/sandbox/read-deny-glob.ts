import * as fs from 'node:fs'
import * as path from 'node:path'
import { logForDebugging } from '../utils/debug.js'
import {
  isAtOrUnder,
  normalizePathForSandbox,
  removeTrailingGlobSuffix,
  walkGlobPattern,
} from './sandbox-utils.js'

/**
 * A read-deny glob still needing more than this many mounts after collapsing
 * is logged at warn level (SRT_DEBUG) as a hint that the pattern is broad.
 * The expansion is never truncated, which would silently un-deny paths. This
 * is not the argument-size guard — that is byte-based, over the whole
 * rendered command line, in describeBwrapStringOverflow.
 */
export const READ_DENY_GLOB_MOUNT_WARN_THRESHOLD = 256

/**
 * Reduce a read-deny glob's matches to the mounts that change what the
 * sandbox can read; ancestors precede descendants in the result. A match is
 * dropped only when a kept proper ancestor's tmpfs already hides it — which
 * is why every match must name the inode it hides (see
 * {@link canonicalizeThroughSymlinks}): the denyRead loop emits the
 * ancestor's tmpfs first, so a mount under a symlink spelling beneath it is
 * created inside that tmpfs and never reaches the link's target.
 */
export function collapseReadDenyMounts({
  matches,
  reExposedPaths,
}: {
  /** Absolute, normalized, trailing-slash-free, symlink-free paths. */
  matches: readonly string[]
  /** allowRead/allowWrite paths (same spelling) the denyRead loop re-binds
   *  over a tmpfs; one between a match and its ancestor, inclusive, keeps
   *  the match's own mount. */
  reExposedPaths: readonly string[]
}): string[] {
  const reExposed = new Set(reExposedPaths)
  // A proper ancestor is a proper string prefix, so lexicographic order
  // visits every ancestor before its descendants.
  const sorted = [...new Set(matches)].sort()
  const kept = new Set<string>()
  for (const candidate of sorted) {
    // Walk the candidate's prefixes once, longest first, up to the nearest
    // kept ancestor (proper prefixes only: slash > 0 skips the candidate
    // itself and the root, which the walk never yields). A re-exposer at
    // any prefix from the candidate down to that ancestor, both inclusive,
    // keeps the candidate's own mount.
    let ancestor: string | undefined
    let reExposedBetween = reExposed.has(candidate)
    for (
      let slash = candidate.lastIndexOf('/');
      slash > 0;
      slash = candidate.lastIndexOf('/', slash - 1)
    ) {
      const prefix = candidate.slice(0, slash)
      if (reExposed.has(prefix)) reExposedBetween = true
      if (kept.has(prefix)) {
        ancestor = prefix
        break
      }
    }
    if (ancestor === undefined || reExposedBetween) kept.add(candidate)
  }
  return [...kept]
}

/**
 * Rewrite every path that is, or lies beneath, a symlink the walk recorded
 * to the path it really names, and dedup. A mount kept under a link spelling
 * denies nothing once a covering directory collapses it: the denyRead loop
 * stats through the link (a directory symlink takes the --tmpfs branch,
 * never resolveSymlinkDenyDest) and, shallow-first, emits the covering
 * directory's tmpfs BEFORE the link's own mount — which bwrap then creates
 * as a fresh empty directory inside that tmpfs, leaving the target readable.
 * A dangling or vanished link keeps its spelling; the loop's existence check
 * skips it, as it always did.
 */
function canonicalizeThroughSymlinks(
  paths: readonly string[],
  symlinks: ReadonlySet<string>,
  globPattern: string,
): string[] {
  if (symlinks.size === 0) return [...new Set(paths)]
  // The static directory prefix the glob walks, in its normalized spelling
  // (the same one walkGlobPattern derives), so an escaping target can be
  // told from one under the tree.
  const normalizedPattern = normalizePathForSandbox(globPattern)
  const staticPrefix = normalizedPattern.split(/[*?[\]]/)[0] ?? ''
  const baseDir = staticPrefix.endsWith('/')
    ? staticPrefix.slice(0, -1)
    : path.dirname(staticPrefix)
  const reachedThroughSymlink = (candidate: string): boolean => {
    if (symlinks.has(candidate)) return true
    for (
      let slash = candidate.lastIndexOf('/');
      slash > 0;
      slash = candidate.lastIndexOf('/', slash - 1)
    ) {
      if (symlinks.has(candidate.slice(0, slash))) return true
    }
    return false
  }
  const canonical = new Set<string>()
  for (const p of paths) {
    if (!reachedThroughSymlink(p)) {
      canonical.add(p)
      continue
    }
    let target: string
    try {
      target = fs.realpathSync(p)
    } catch {
      canonical.add(p)
      continue
    }
    canonical.add(target)
    // Denying through a link that escapes the tree is what the glob asks for
    // on Linux (a bind mount covers an inode, whatever its spelling), but a
    // link to an ancestor or to a top-level directory turns the pattern into
    // a tmpfs over far more than the user pictured — the project, or /usr —
    // so say so, once per link, outside SRT_DEBUG.
    if (isAtOrUnder(baseDir, target) || target.split('/').length <= 2) {
      const key = `${p} -> ${target}`
      if (!warnedEscapingLinks.has(key)) {
        warnedEscapingLinks.add(key)
        console.warn(
          `[sandbox-runtime] WARNING: denyRead glob "${globPattern}" reaches ${p}, a symlink to ${target}; ` +
            `that whole directory will be read-denied inside the sandbox. Deny a narrower path, or exclude the link.`,
        )
      }
    }
  }
  return [...canonical]
}

/** Escaping links already warned about, so a per-command wrap warns once. */
const warnedEscapingLinks = new Set<string>()

/**
 * Expand a read-deny glob into the paths bwrap should mount over, collapsed
 * with {@link collapseReadDenyMounts} against `reExposedPaths` (the caller's
 * allowRead and allowWrite entries, already put through
 * normalizePathForSandbox so they compare by prefix exactly as the denyRead
 * loop's do). A pattern ending in `/**` also takes its directory form, so
 * `**\/build/**` yields one mount per `build/` directory. An entry reached
 * through a symlink is mounted at the path the link resolves to.
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
): string[] {
  const directoryForm = removeTrailingGlobSuffix(globPattern)
  const walk = walkGlobPattern(globPattern, {
    directoryPattern: directoryForm === globPattern ? undefined : directoryForm,
  })
  const matches = canonicalizeThroughSymlinks(
    walk.matches,
    walk.symlinks,
    globPattern,
  )
  if (walk.directoryMatches.length > 0) {
    // Everything beneath a directory-form match is itself a match (the
    // pattern ends in /**), so a directory with something to deny is some
    // match's parent. An empty one gets no mount: it has nothing to deny,
    // and as a tmpfs it would swallow later writes.
    const parents = new Set(matches.map(m => m.slice(0, m.lastIndexOf('/'))))
    for (const dir of canonicalizeThroughSymlinks(
      walk.directoryMatches,
      walk.symlinks,
      globPattern,
    )) {
      if (parents.has(dir)) matches.push(dir)
    }
  }

  const mounts = collapseReadDenyMounts({ matches, reExposedPaths })

  logForDebugging(
    `[Sandbox Linux] Expanded denyRead glob "${globPattern}": ${walk.matches.length} matches -> ${mounts.length} mounts`,
  )
  if (mounts.length > READ_DENY_GLOB_MOUNT_WARN_THRESHOLD) {
    logForDebugging(
      `[Sandbox Linux] denyRead glob "${globPattern}" still needs ${mounts.length} mounts after collapsing ` +
        `(threshold ${READ_DENY_GLOB_MOUNT_WARN_THRESHOLD}); each is a separate bwrap bind and a very ` +
        `large set can exceed the kernel argument-size limits. Prefer denying the enclosing directories.`,
      { level: 'warn' },
    )
  }
  return mounts
}
