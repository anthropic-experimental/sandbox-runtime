import * as fs from 'node:fs'
import { logForDebugging } from '../utils/debug.js'
import { removeTrailingGlobSuffix, walkGlobPattern } from './sandbox-utils.js'

/**
 * A read-deny glob still needing more than this many mounts after collapsing
 * is logged at warn level (SRT_DEBUG) as a hint that the pattern is broad.
 * The expansion is never truncated, which would silently un-deny paths.
 */
export const READ_DENY_GLOB_MOUNT_WARN_THRESHOLD = 256

/** The nearest proper prefix of `p` (at a segment boundary) found in `set`. */
function nearestPrefixIn(
  set: ReadonlySet<string>,
  p: string,
): string | undefined {
  // Proper prefixes only: slash > 0 skips p itself and the root, which the
  // walk never yields.
  for (
    let slash = p.lastIndexOf('/');
    slash > 0;
    slash = p.lastIndexOf('/', slash - 1)
  ) {
    const prefix = p.slice(0, slash)
    if (set.has(prefix)) return prefix
  }
  return undefined
}

/**
 * Reduce a read-deny glob's matches to the mounts that change what the
 * sandbox can read; ancestors precede descendants in the result. A match is
 * dropped only when a kept proper ancestor's tmpfs already hides it and no
 * re-exposer sits between the two (one at the ancestor counts: the deny
 * loop re-binds it over the tmpfs, so everything beneath needs its own).
 */
export function collapseReadDenyMounts({
  matches,
  reExposedPaths,
}: {
  /** Absolute, normalized, trailing-slash-free paths; a match reached
   *  through a symlink appears in both its spellings. */
  matches: readonly string[]
  /** allowRead/allowWrite paths the denyRead loop re-binds over a tmpfs, in
   *  every spelling that can name them. */
  reExposedPaths: readonly string[]
}): string[] {
  const reExposed = new Set(reExposedPaths)
  // A proper ancestor is a proper string prefix, so lexicographic order
  // visits every ancestor before its descendants.
  const sorted = [...new Set(matches)].sort()
  const kept = new Set<string>()
  for (const candidate of sorted) {
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
 * Expand a read-deny glob into the paths bwrap should mount over, collapsed
 * with {@link collapseReadDenyMounts} against `reExposedPaths` (the caller's
 * allowRead and allowWrite entries, already put through
 * normalizePathForSandbox). A pattern ending in `/**` also takes its
 * directory form, so `**\/build/**` yields one mount per `build/` directory.
 *
 * Symlinks: a match keeps its spelling, so a carve-out written against a
 * link still matches, and a match that reaches its inode through a link
 * (one the walk descended, or one above the walk) is listed in its resolved
 * spelling as well, so a carve-out written against the target matches too
 * and the target stays denied where the link itself vanishes (a covering
 * directory's tmpfs replaces the links beneath it with nothing). The deny
 * loop mounts each entry at its resolved path, compares re-exposers in both
 * spellings, and skips the second spelling of an inode it has covered.
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
): string[] {
  const directoryForm = removeTrailingGlobSuffix(globPattern)
  const walk = walkGlobPattern(globPattern, {
    directoryPattern: directoryForm === globPattern ? undefined : directoryForm,
  })
  const candidates = new Set(walk.matches)
  if (walk.directoryMatches.length > 0) {
    // Everything beneath a directory-form match is itself a match (the
    // pattern ends in /**), so a directory with something to deny is some
    // match's parent. An empty one gets no mount: it has nothing to deny,
    // and as a tmpfs it would swallow later writes.
    const parents = new Set(
      walk.matches.map(m => m.slice(0, m.lastIndexOf('/'))),
    )
    for (const dir of walk.directoryMatches) {
      // A directory-form match that is a symlink counts in its own right:
      // one the walk did not descend (a link back into its own ancestry)
      // has no match beneath it, yet denies everything it reaches.
      if (parents.has(dir) || walk.symlinks.has(dir)) candidates.add(dir)
    }
  }

  const realpathOf = (p: string): string | undefined => {
    try {
      return fs.realpathSync(p)
    } catch {
      return undefined // dangling or vanished: keep the spelling
    }
  }
  // Re-exposers in both spellings, as the deny loop compares them.
  const reExposedBothForms = new Set<string>()
  for (const p of reExposedPaths) {
    reExposedBothForms.add(p)
    const resolved = realpathOf(p)
    if (resolved !== undefined) reExposedBothForms.add(resolved)
  }
  // Resolved spellings: a realpath for a match under a link the walk
  // descended, a string swap for one under a symlinked base.
  const throughWalkLink = (p: string): boolean =>
    walk.symlinks.has(p) || nearestPrefixIn(walk.symlinks, p) !== undefined
  const baseSwapped = walk.baseReal !== walk.baseDir
  for (const m of [...candidates]) {
    let resolved: string | undefined
    if (throughWalkLink(m)) resolved = realpathOf(m)
    else if (baseSwapped)
      resolved = walk.baseReal + m.slice(walk.baseDir.length)
    if (resolved === '/') {
      // A link to the root: a tmpfs there would hide everything. The
      // spelling stays, and bwrap refuses to mount on the link.
      logForDebugging(
        `[Sandbox Linux] denyRead glob "${globPattern}": ${m} resolves to /, not denied at its target`,
      )
      continue
    }
    if (resolved !== undefined) candidates.add(resolved)
  }

  const mounts = collapseReadDenyMounts({
    matches: [...candidates],
    reExposedPaths: [...reExposedBothForms],
  })

  logForDebugging(
    `[Sandbox Linux] Expanded denyRead glob "${globPattern}": ${walk.matches.length} matches -> ${mounts.length} mounts`,
  )
  if (mounts.length > READ_DENY_GLOB_MOUNT_WARN_THRESHOLD) {
    logForDebugging(
      `[Sandbox Linux] denyRead glob "${globPattern}" still needs ${mounts.length} mounts after collapsing ` +
        `(threshold ${READ_DENY_GLOB_MOUNT_WARN_THRESHOLD}); each is a separate bwrap mount at sandbox start. ` +
        `Prefer denying the enclosing directories.`,
      { level: 'warn' },
    )
  }
  return mounts
}
