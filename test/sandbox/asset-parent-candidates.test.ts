import { describe, it, expect, afterEach } from 'bun:test'
import * as fs from 'node:fs'
import { isLinux } from '../helpers/platform.js'
import { transparentAssetParentCandidates } from '../../src/sandbox/transparent-net.js'

/**
 * TMPDIR handling in the asset parent candidate list: a symlinked TMPDIR
 * is a normal, working configuration and must yield a usable candidate;
 * TMPDIR shapes the mount stack cannot host (root, relative) must fail
 * with the branded configuration error instead of surfacing later as a
 * raw mount failure.
 */
describe.if(isLinux)('asset parent candidates: TMPDIR handling', () => {
  const savedTmpdir = process.env.TMPDIR

  afterEach(() => {
    if (savedTmpdir === undefined) delete process.env.TMPDIR
    else process.env.TMPDIR = savedTmpdir
  })

  it('accepts a TMPDIR that is a symlink to a real directory', () => {
    const real = fs.mkdtempSync('/tmp/srt-tmpbase-')
    const link = `${real}-link`
    fs.symlinkSync(real, link)
    try {
      process.env.TMPDIR = link
      const uid = process.getuid!()
      const candidates = transparentAssetParentCandidates()
      // The emitted mount path must be canonical (bwrap cannot create
      // mount destinations through a symlinked component), so the
      // candidate is derived from the RESOLVED directory.
      const resolved = fs.realpathSync(real)
      expect(candidates).toContain(`${resolved}/srt-tp-assets-${uid}`)
      expect(candidates).not.toContain(`${link}/srt-tp-assets-${uid}`)
    } finally {
      fs.rmSync(link, { force: true })
      fs.rmSync(real, { recursive: true, force: true })
    }
  })

  it('rejects TMPDIR=/ with the configuration error', () => {
    process.env.TMPDIR = '/'
    expect(() => transparentAssetParentCandidates()).toThrow(/TMPDIR/)
  })

  it('rejects a relative TMPDIR even when the directory exists', () => {
    const rel = `srt-rel-tmp-${process.pid}`
    fs.mkdirSync(rel, { recursive: true })
    try {
      process.env.TMPDIR = rel
      expect(() => transparentAssetParentCandidates()).toThrow(/TMPDIR/)
    } finally {
      fs.rmdirSync(rel)
    }
  })

  it('rejects a TMPDIR pointing at a missing path with the configuration error', () => {
    process.env.TMPDIR = `/nonexistent-srt-tmpbase-${process.pid}`
    expect(() => transparentAssetParentCandidates()).toThrow(/TMPDIR/)
  })
})
