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
 * re-exposer sits between the two.
 */
export function collapseReadDenyMounts({
  matches,
  reExposedPaths,
  canonical,
}: {
  /** Absolute, normalized, trailing-slash-free paths, in the spelling the
   *  denyRead loop will mount (a symlink stays a symlink). */
  matches: readonly string[]
  /** allowRead/allowWrite paths the denyRead loop re-binds over a tmpfs, in
   *  every spelling that can name them; one at or between a match and its
   *  ancestor keeps the match's own mount. */
  reExposedPaths: readonly string[]
  /** The resolved path of each match that is, or lies beneath, a symlink.
   *  A re-exposer at or above that resolved path keeps the mount too, so a
   *  carve-out written in either spelling counts. */
  canonical?: ReadonlyMap<string, string>
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
    const resolved = canonical?.get(candidate)
    if (resolved !== undefined && !reExposedBetween) {
      // Conservative on purpose: any re-exposer at or above the resolved
      // path keeps the mount, at worst one redundant mount.
      for (
        let end = resolved.length;
        end > 0;
        end = resolved.lastIndexOf('/', end - 1)
      ) {
        if (reExposed.has(resolved.slice(0, end))) {
          reExposedBetween = true
          break
        }
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
 * Matches keep their spelling, symlinks included, so a carve-out written
 * against a link still matches; only a match a covering directory's tmpfs
 * cannot reach (see below) is mounted at its resolved path instead.
 */
export function expandReadDenyGlobLinux(
  globPattern: string,
  reExposedPaths: readonly string[],
): string[] {
  const directoryForm = removeTrailingGlobSuffix(globPattern)
  const walk = walkGlobPattern(globPattern, {
    directoryPattern: directoryForm === globPattern ? undefined : directoryForm,
  })
  const matchSet = new Set(walk.matches)
  if (walk.directoryMatches.length > 0) {
    // Everything beneath a directory-form match is itself a match (the
    // pattern ends in /**), so a directory with something to deny is some
    // match's parent. An empty one gets no mount: it has nothing to deny,
    // and as a tmpfs it would swallow later writes.
    const parents = new Set(
      walk.matches.map(m => m.slice(0, m.lastIndexOf('/'))),
    )
    for (const dir of walk.directoryMatches) {
      if (parents.has(dir)) matchSet.add(dir)
    }
  }
  const matches = [...matchSet]

  const realpathOf = (p: string): string | undefined => {
    try {
      return fs.realpathSync(p)
    } catch {
      return undefined // dangling or vanished: keep the spelling
    }
  }
  // Re-exposers in both spellings, as the write-deny pre-pass compares them.
  const reExposedBothForms = new Set<string>()
  for (const p of reExposedPaths) {
    reExposedBothForms.add(p)
    const resolved = realpathOf(p)
    if (resolved !== undefined) reExposedBothForms.add(resolved)
  }
  const throughSymlink = (p: string): boolean =>
    walk.symlinks.has(p) || nearestPrefixIn(walk.symlinks, p) !== undefined
  const canonical = new Map<string, string>()
  for (const m of matches) {
    if (!throughSymlink(m)) continue
    const resolved = realpathOf(m)
    if (resolved !== undefined) canonical.set(m, resolved)
  }

  let mounts = collapseReadDenyMounts({
    matches,
    reExposedPaths: [...reExposedBothForms],
    canonical,
  })

  // A dropped match whose spelling passes through a symlink STRICTLY BELOW
  // its covering directory names an inode that directory's tmpfs does not
  // hide: the denyRead loop emits the covering tmpfs first, which replaces
  // the link with an empty directory inside the sandbox. Mount its resolved
  // path instead. A link at or above the covering directory is fine, since
  // that directory's own mount already resolves through it.
  const kept = new Set(mounts)
  const resolvedExtras: string[] = []
  for (const m of matches) {
    if (kept.has(m)) continue
    const ancestor = nearestPrefixIn(kept, m)
    if (ancestor === undefined) continue
    let linkBetween = false
    for (
      let end = m.length;
      end > ancestor.length;
      end = m.lastIndexOf('/', end - 1)
    ) {
      if (walk.symlinks.has(m.slice(0, end))) {
        linkBetween = true
        break
      }
    }
    if (!linkBetween) continue
    const resolved = canonical.get(m)
    if (resolved !== undefined) resolvedExtras.push(resolved)
  }
  if (resolvedExtras.length > 0) {
    mounts = collapseReadDenyMounts({
      matches: [...mounts, ...resolvedExtras],
      reExposedPaths: [...reExposedBothForms],
    })
  }

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
