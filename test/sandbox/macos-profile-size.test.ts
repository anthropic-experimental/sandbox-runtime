import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type { FsWriteRestrictionConfig } from '../../src/sandbox/sandbox-schemas.js'
import { isMacOS } from '../helpers/platform.js'

/**
 * The Seatbelt profile is passed to sandbox-exec in argv, so its size counts
 * against ARG_MAX (1 MiB on macOS) for every sandboxed exec. These tests pin
 * that a configuration with several hundred denied paths stays under half of
 * that limit, and that the resulting profile still spawns and enforces each
 * kind of path filter it contains (subpath, literal ancestor, regex).
 */
describe.if(isMacOS)('macOS Seatbelt profile size', () => {
  const MACOS_ARG_MAX = 1024 * 1024
  const GROUPS = 200

  const TEST_BASE_DIR = join(
    realpathSync(tmpdir()),
    'seatbelt-size-test-' + Date.now(),
  )
  const ALLOWED_DIR = join(TEST_BASE_DIR, 'allowed')
  const groupDir = (i: number) =>
    join(ALLOWED_DIR, 'nested', 'groups', `g${String(i).padStart(4, '0')}`)
  // One group dir exists on disk so a denied write reaches the sandbox
  // check instead of failing with ENOENT on the parent.
  const PROBED_GROUP = groupDir(150)

  const denyWithinAllow: string[] = []
  for (let i = 0; i < GROUPS; i++) {
    denyWithinAllow.push(
      join(groupDir(i), 'a.conf'),
      join(groupDir(i), 'a.conf.lock'),
      join(groupDir(i), 'b'),
    )
  }
  denyWithinAllow.push(join(ALLOWED_DIR, '**', '*.key'))
  const writeConfig: FsWriteRestrictionConfig = {
    allowOnly: [ALLOWED_DIR],
    denyWithinAllow,
  }

  beforeAll(() => {
    mkdirSync(PROBED_GROUP, { recursive: true })
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  it(`fits ${GROUPS * 3} deny paths in under half of ARG_MAX`, () => {
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig,
    })

    expect(Buffer.byteLength(wrappedCommand)).toBeLessThan(MACOS_ARG_MAX / 2)
  })

  it('spawns and enforces subpath, literal-ancestor and regex filters', () => {
    const allowedFile = join(PROBED_GROUP, 'other')
    const deniedFile = join(PROBED_GROUP, 'a.conf')
    const deniedByGlob = join(PROBED_GROUP, 'x.key')
    const wrappedCommand = wrapCommandWithSandboxMacOS({
      command: `touch ${allowedFile}; touch ${deniedFile}; touch ${deniedByGlob}; mv ${PROBED_GROUP} ${PROBED_GROUP}.moved`,
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig,
    })

    const result = spawnSync('/bin/bash', ['-c', wrappedCommand], {
      encoding: 'utf8',
      timeout: 30000,
    })

    expect(result.error).toBeUndefined()
    expect(existsSync(allowedFile)).toBe(true)
    expect(existsSync(deniedFile)).toBe(false)
    expect(existsSync(deniedByGlob)).toBe(false)
    expect(existsSync(`${PROBED_GROUP}.moved`)).toBe(false)
    expect(result.stderr).toContain(`${deniedFile}: Operation not permitted`)
    expect(result.stderr).toContain(`${deniedByGlob}: Operation not permitted`)
    expect(result.stderr).toContain(
      `${PROBED_GROUP}.moved: Operation not permitted`,
    )
  })
})
