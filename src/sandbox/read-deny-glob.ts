import { logForDebugging } from '../utils/debug.js'
import {
  normalizePathForSandbox,
  removeTrailingGlobSuffix,
  walkGlobPattern,
} from './sandbox-utils.js'

/**
 * A read-deny glob still needing more than this many mounts after collapsing
 * is logged at warn level (SRT_DEBUG). The expansion is never truncated,
 * which would silently un-deny paths; a broad pattern is only surfaced.
 */
export const READ_DENY_GLOB_MOUNT_WARN_THRESHOLD = 256

/**
 * Reduce a read-deny glob's matches to the mounts that change what the
 * sandbox can read; ancestors precede descendants in the result. A match is
 * dropped only when a kept proper ancestor's tmpfs already hides it.
 */
export function collapseReadDenyMounts({
  matches,
  reExposedPaths,
  symlinks,
}: {
  /** Absolute, normalized, trailing-slash-free paths. */
  matches: readonly string[]
  /** allowRead/allowWrite paths (same spelling) the denyRead loop re-binds
   *  over a tmpfs; one between a match and its ancestor, inclusive, keeps
   *  the match's own mount. */
  reExposedPaths: readonly string[]
  /** Symlinks the walk saw; the loop mounts over a link's target, outside
   *  the ancestor, so one below the ancestor up to the match keeps the
   *  match's own mount. */
  symlinks: ReadonlySet<string>
}): string[] {
  const isAtOrUnder = ({ path, dir }: { path: string; dir: string }): boolean =>
    path === dir || path.startsWith(dir === '/' ? '/' : dir + '/')
  // A proper ancestor is a proper string prefix, so lexicographic order
  // visits every ancestor before its descendants.
  const sorted = [...new Set(matches)].sort()

  const kept: string[] = []
  const keptSet = new Set<string>()
  // Proper ancestors only (slash > 0 skips both the candidate itself and
  // the root, which the walk never yields).
  const nearestKeptAncestor = (candidate: string): string | undefined => {
    for (
      let slash = candidate.lastIndexOf('/');
      slash > 0;
      slash = candidate.lastIndexOf('/', slash - 1)
    ) {
      const prefix = candidate.slice(0, slash)
      if (keptSet.has(prefix)) return prefix
    }
    return undefined
  }
  // Every prefix of the candidate strictly longer than the ancestor, the
  // candidate itself included.
  const symlinkBetween = ({
    ancestor,
    candidate,
  }: {
    ancestor: string
    candidate: string
  }): boolean => {
    if (symlinks.size === 0) return false
    for (
      let end = candidate.length;
      end > ancestor.length;
      end = candidate.lastIndexOf('/', end - 1)
    ) {
      if (symlinks.has(candidate.slice(0, end))) return true
    }
    return false
  }

  for (const candidate of sorted) {
    const ancestor = nearestKeptAncestor(candidate)
    const covered =
      ancestor !== undefined &&
      !reExposedPaths.some(
        reExposed =>
          isAtOrUnder({ path: reExposed, dir: ancestor }) &&
          isAtOrUnder({ path: candidate, dir: reExposed }),
      ) &&
      !symlinkBetween({ ancestor, candidate })
    if (!covered) {
      kept.push(candidate)
      keptSet.add(candidate)
    }
  }
  return kept
}

/**
 * Expand a read-deny glob into the paths bwrap should mount over, collapsed
 * with {@link collapseReadDenyMounts} against `reExposedPaths` (the caller's
 * allowRead and allowWrite entries). A pattern ending in `/**` also takes its
 * directory form, so `**\/build/**` yields one mount per `build/` directory.
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
): string[] {
  const directoryForm = removeTrailingGlobSuffix(globPattern)
  const walk = walkGlobPattern(globPattern, {
    directoryPattern: directoryForm === globPattern ? undefined : directoryForm,
  })
  const matches = [...walk.matches]
  if (walk.directoryMatches.length > 0) {
    // A directory-form match counts only as a real, non-symlink directory
    // with a match beneath it: an empty one has nothing to deny (and as a
    // tmpfs would swallow later writes), and a symlink named like one is
    // left to its own entries.
    const matchAncestors = new Set<string>()
    for (const match of walk.matches) {
      for (
        let slash = match.lastIndexOf('/');
        slash > 0;
        slash = match.lastIndexOf('/', slash - 1)
      ) {
        const ancestor = match.slice(0, slash)
        if (matchAncestors.has(ancestor)) break // and so is everything above
        matchAncestors.add(ancestor)
      }
    }
    for (const dir of walk.directoryMatches) {
      if (matchAncestors.has(dir) && !walk.symlinks.has(dir)) {
        matches.push(dir)
      }
    }
  }

  const mounts = collapseReadDenyMounts({
    matches,
    // normalizePathForSandbox strips a trailing slash from a non-glob POSIX
    // spelling, so these compare by prefix exactly as the loop's do.
    reExposedPaths: reExposedPaths.map(p => normalizePathForSandbox(p)),
    symlinks: walk.symlinks,
  })

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
