import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isSupportedPlatform } from '../helpers/platform.js'

/**
 * Tests for filesystem.disabled.
 *
 * When true, no filesystem policy is enforced: every path is readable
 * and writable, denyRead/allowRead/allowWrite/denyWrite are ignored,
 * and the mandatory deny patterns (.git/hooks, .bashrc, etc.) are not
 * applied. Network/credential-env restrictions are unaffected.
 */
describe.if(isSupportedPlatform)('filesystem.disabled', () => {
  const TEST_DIR = join(tmpdir(), 'srt-fs-disabled-' + Date.now())
  const TEST_WRITE_FILE = join(TEST_DIR, 'write.txt')
  const TEST_READ_FILE = join(TEST_DIR, 'read.txt')
  const TEST_CONTENT = 'disabled-ok'

  // allowWrite deliberately points somewhere ELSE so TEST_DIR is not
  // covered by any configured write rule. Without disabled, writing
  // to TEST_WRITE_FILE would be blocked.
  //
  // denyRead is NOT set on the shared base config: on Linux a directory
  // read-deny mounts a writable tmpfs over the path, which would let the
  // control test's redirect succeed (exit 0) inside the namespace. The
  // 'ignores denyRead' test supplies its own denyRead.
  const baseConfig = (disabled: boolean): SandboxRuntimeConfig => ({
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: {
      disabled,
      denyRead: [],
      allowWrite: ['/nonexistent-allow-write'],
      denyWrite: [],
    },
  })

  beforeAll(() => {
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(TEST_READ_FILE, TEST_CONTENT)
  })

  afterAll(async () => {
    await SandboxManager.reset()
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true })
    }
  })

  it('getter shapes reflect no enforcement', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize(baseConfig(true))

    expect(SandboxManager.getFsReadConfig()).toEqual({
      denyOnly: [],
      allowWithinDeny: [],
    })
    expect(SandboxManager.getFsWriteConfig()).toEqual({
      allowOnly: ['/'],
      denyWithinAllow: [],
    })
  })

  it('blocks writes outside allowWrite when disabled is false (control)', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize(baseConfig(false))

    const wrapped = await SandboxManager.wrapWithSandbox(
      `printf %s ${TEST_CONTENT} > ${TEST_WRITE_FILE}`,
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    // Write must fail (path is not in allowWrite or default write paths).
    expect(existsSync(TEST_WRITE_FILE)).toBe(false)
    expect(result.status).not.toBe(0)
  })

  it('allows writes anywhere when disabled is true', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize(baseConfig(true))

    const wrapped = await SandboxManager.wrapWithSandbox(
      `printf %s ${TEST_CONTENT} > ${TEST_WRITE_FILE}`,
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).toBe(0)
    expect(existsSync(TEST_WRITE_FILE)).toBe(true)
    expect(readFileSync(TEST_WRITE_FILE, 'utf8')).toBe(TEST_CONTENT)
  })

  it('ignores denyRead when disabled is true', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize({
      ...baseConfig(true),
      filesystem: {
        ...baseConfig(true).filesystem,
        denyRead: [TEST_DIR],
      },
    })

    // TEST_READ_FILE is created in beforeAll; TEST_DIR is in denyRead.
    const wrapped = await SandboxManager.wrapWithSandbox(
      `cat ${TEST_READ_FILE}`,
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout).toContain(TEST_CONTENT)
  })

  it('per-call customConfig.filesystem overrides global disabled', async () => {
    await SandboxManager.reset()
    await SandboxManager.initialize(baseConfig(true))

    // Global has disabled=true, but the per-call override supplies a
    // restrictive filesystem block (without the disabled key). The
    // override must win — TEST_DIR is not in its allowWrite, so the write
    // must be blocked.
    const target = join(TEST_DIR, 'override.txt')
    const wrapped = await SandboxManager.wrapWithSandbox(
      `printf %s x > ${target}`,
      undefined,
      {
        filesystem: {
          denyRead: [],
          allowWrite: ['/nonexistent-allow-write'],
          denyWrite: [],
        },
      },
    )
    const result = spawnSync(wrapped, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    expect(existsSync(target)).toBe(false)
    expect(result.status).not.toBe(0)
  })
})
