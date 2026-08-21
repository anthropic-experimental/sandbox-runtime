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
    isExcluded: none,
    containsReadDenyTmpfs: none,
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

  it('skips directories at or below a deny dest via isExcluded', () => {
    const pins = computeAncestorPins(
      ['/w/app', '/w/app/repo/.git/config'],
      probes(['/w'], { isExcluded: under('/w/app') }),
    )
    expect(pins).toEqual([])
  })

  it('skips a directory at or above a read-deny tmpfs', () => {
    const tmpfs = '/w/x/y'
    const pins = computeAncestorPins(
      ['/w/x/y/z/.git/config'],
      probes(['/w'], {
        containsReadDenyTmpfs: dir => under(dir)(tmpfs),
      }),
    )
    expect(pins).toEqual(['/w/x/y/z', '/w/x/y/z/.git'])
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
})
