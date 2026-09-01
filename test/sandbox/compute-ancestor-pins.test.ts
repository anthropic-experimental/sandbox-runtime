import { describe, it, expect } from 'bun:test'
import { computeAncestorPins } from '../../src/sandbox/linux-sandbox-utils.js'

// Pure walk over the deny-dest seeds; probes are injected so this runs on
// every platform.
describe('computeAncestorPins', () => {
  const under = (root: string) => (dir: string) =>
    dir === root || dir.startsWith(root + '/')
  const none = () => false
  const probes = (
    roots: string[],
    overrides: Partial<Parameters<typeof computeAncestorPins>[1]> = {},
  ) => ({
    isWithinAllowedWrite: (dir: string) => roots.some(r => under(r)(dir)),
    isAllowedWriteRoot: (dir: string) => roots.includes(dir),
    isAbsent: none,
    ...overrides,
  })

  it('pins every directory strictly between the dest and the write root', () => {
    expect(computeAncestorPins(['/w/a/b/.git/config'], probes(['/w']))).toEqual(
      ['/w/a', '/w/a/b', '/w/a/b/.git'],
    )
  })

  it('pins nothing for a dest outside every write root', () => {
    expect(computeAncestorPins(['/x/a/leaf'], probes(['/w']))).toEqual([])
  })

  it('pins directories at and below another deny dest on the same chain', () => {
    // A directory that is itself a deny dest, or sits below one, is still an
    // ancestor of the deeper seed; later mounts decide its permissions.
    const pins = computeAncestorPins(
      ['/w/app', '/w/app/repo/.git/config'],
      probes(['/w']),
    )
    expect(pins).toEqual(['/w/app', '/w/app/repo', '/w/app/repo/.git'])
  })

  it('skips absent directories', () => {
    const pins = computeAncestorPins(
      ['/w/a/missing/leaf'],
      probes(['/w'], { isAbsent: dir => dir === '/w/a/missing' }),
    )
    expect(pins).toEqual(['/w/a'])
  })

  it('continues past a nested write root up to the outermost one', () => {
    const pins = computeAncestorPins(
      ['/w/x/y/z/.git/config'],
      probes(['/w', '/w/x/y/z']),
    )
    expect(pins).toEqual(['/w/x', '/w/x/y', '/w/x/y/z/.git'])
  })

  it('orders pins shallow-first across seeds and dedupes shared prefixes', () => {
    const pins = computeAncestorPins(
      ['/w/a/b/c/leaf', '/w/a/d/leaf', '/w/e/leaf'],
      probes(['/w']),
    )
    expect(pins).toEqual(['/w/a', '/w/e', '/w/a/b', '/w/a/d', '/w/a/b/c'])
  })

  it('terminates on a relative seed instead of walking dirname(".") forever', () => {
    // path.dirname('a') is '.', and dirname('.') is '.' again; a probe that
    // answers true for everything must not spin the walk.
    const always = () => true
    const pins = computeAncestorPins(
      ['a/b/leaf'],
      probes([], { isWithinAllowedWrite: always, isAllowedWriteRoot: none }),
    )
    expect(pins).toEqual(['a', 'a/b'])
  })
})
