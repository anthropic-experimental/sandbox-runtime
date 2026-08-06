import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from '../../src/sandbox/sandbox-schemas.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

/**
 * Tests for denyReadAlways and its exception layer denyReadAlwaysExcept.
 *
 * denyReadAlways is a final-deny pass that beats allowRead (allowWithinDeny);
 * denyReadAlwaysExcept re-allows specific known-safe names that a broad
 * credential glob catches (e.g. "/**\/.env.example" alongside "/**\/.env*").
 * Priority: denyAlwaysExcept > denyAlways > allowWithinDeny > denyOnly.
 */
describe.if(isMacOS)('macOS denyReadAlways / denyReadAlwaysExcept', () => {
  const TEST_BASE_DIR = join(tmpdir(), 'deny-always-test-' + Date.now())
  const TEST_SECRET_FILE = join(TEST_BASE_DIR, '.env')
  const TEST_TEMPLATE_FILE = join(TEST_BASE_DIR, '.env.example')
  const TEST_SECRET_CONTENT = 'SECRET=real_value'
  const TEST_TEMPLATE_CONTENT = 'SECRET=fill_me_in'

  beforeAll(() => {
    mkdirSync(TEST_BASE_DIR, { recursive: true })
    writeFileSync(TEST_SECRET_FILE, TEST_SECRET_CONTENT)
    writeFileSync(TEST_TEMPLATE_FILE, TEST_TEMPLATE_CONTENT)
  })

  afterAll(() => {
    if (existsSync(TEST_BASE_DIR)) {
      rmSync(TEST_BASE_DIR, { recursive: true, force: true })
    }
  })

  const readConfig: FsReadRestrictionConfig = {
    denyOnly: [],
    allowWithinDeny: [],
    denyAlways: ['/**/.env*'],
    denyAlwaysExcept: ['/**/.env.example'],
  }

  it('emits the exception allow after the denyAlways deny (last-match-wins)', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig,
      writeConfig: undefined,
    })

    // globToRegex('/**/.env*') → ^/(.*/)?\.env[^/]*$
    // globToRegex('/**/.env.example') → ^/(.*/)?\.env\.example$
    const denyAt = wrapped.indexOf('.env[^/]*')
    const exceptAt = wrapped.indexOf('.env\\\\.example')
    expect(denyAt).toBeGreaterThan(-1)
    expect(exceptAt).toBeGreaterThan(-1)
    expect(exceptAt).toBeGreaterThan(denyAt)
  })

  it('wraps the command when only denyAlways is configured (empty denyOnly)', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig: { denyOnly: [], denyAlways: ['/**/.env*'] },
      writeConfig: undefined,
    })

    expect(wrapped).not.toBe('true')
    expect(wrapped).toContain('sandbox-exec')
  })

  it('keeps denyAlways rules when file masking folds paths into denyOnly', () => {
    // Regression: the maskedFileBinds readConfig reconstruction used to drop
    // denyAlways (and would have dropped denyAlwaysExcept), silently erasing
    // every credential glob whenever credentials.files was configured.
    const wrapped = wrapCommandWithSandboxMacOS({
      command: 'true',
      needsNetworkRestriction: false,
      readConfig,
      writeConfig: undefined,
      maskedFileBinds: [
        { realPath: join(TEST_BASE_DIR, 'cred'), fakePath: '/dev/null' },
      ],
    })

    expect(wrapped).toContain('.env[^/]*')
    expect(wrapped).toContain('.env\\\\.example')
  })

  it('denies the credential file but allows the excepted template', () => {
    const wrapped = wrapCommandWithSandboxMacOS({
      command: `cat ${TEST_SECRET_FILE}; cat ${TEST_TEMPLATE_FILE}`,
      needsNetworkRestriction: false,
      readConfig,
      writeConfig: undefined,
    })

    const result = spawnSync(wrapped, { shell: true, encoding: 'utf8' })

    expect(result.stdout).not.toContain(TEST_SECRET_CONTENT)
    expect(result.stdout).toContain(TEST_TEMPLATE_CONTENT)
  })

  it('supports creating an excepted file in a write-allowed dir and reading it back', () => {
    // Creation inside a write-allowed dir is governed by the writeAllowPaths
    // re-allow (upstream behavior, applies to any name); what denyAlwaysExcept
    // adds is that the excepted file is *readable* afterwards, while a
    // denied name written the same way stays unreadable.
    const writeConfig: FsWriteRestrictionConfig = {
      allowOnly: [TEST_BASE_DIR],
      denyWithinAllow: [],
    }
    const subDir = join(TEST_BASE_DIR, 'sub')
    const newTemplate = join(subDir, '.env.example')
    const newSecret = join(subDir, '.env')

    const wrapped = wrapCommandWithSandboxMacOS({
      command: `mkdir -p ${subDir}; echo NEW_TEMPLATE > ${newTemplate} && cat ${newTemplate}; echo NEW_SECRET > ${newSecret}; cat ${newSecret} || echo SECRET_READBACK_BLOCKED`,
      needsNetworkRestriction: false,
      readConfig,
      writeConfig,
    })

    const result = spawnSync(wrapped, { shell: true, encoding: 'utf8' })

    expect(result.stdout).toContain('NEW_TEMPLATE')
    expect(result.stdout).not.toContain('NEW_SECRET')
    expect(result.stdout).toContain('SECRET_READBACK_BLOCKED')
  })
})

describe.if(isLinux)('Linux denyReadAlwaysExcept set-subtraction', () => {
  const RAW_BASE_DIR = join(tmpdir(), 'deny-always-linux-' + Date.now())

  beforeAll(() => {
    mkdirSync(RAW_BASE_DIR, { recursive: true })
    writeFileSync(join(RAW_BASE_DIR, 'secret.env'), 'SECRET=value')
    writeFileSync(join(RAW_BASE_DIR, 'example.env'), 'SECRET=fill_me_in')
  })

  afterAll(() => {
    if (existsSync(RAW_BASE_DIR)) {
      rmSync(RAW_BASE_DIR, { recursive: true, force: true })
    }
  })

  it('removes excepted concrete paths from the expanded denyAlways list', async () => {
    const { SandboxManager } = await import(
      '../../src/sandbox/sandbox-manager.js'
    )

    await SandboxManager.reset()
    await SandboxManager.initialize({
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowWrite: ['/tmp'],
        denyWrite: [],
        denyReadAlways: [join(RAW_BASE_DIR, '*.env')],
        denyReadAlwaysExcept: [join(RAW_BASE_DIR, 'example.env')],
      },
    })

    try {
      const readConfig = SandboxManager.getFsReadConfig()
      const denyAlways = readConfig.denyAlways ?? []
      expect(denyAlways.some((p: string) => p.endsWith('secret.env'))).toBe(
        true,
      )
      expect(denyAlways.some((p: string) => p.endsWith('example.env'))).toBe(
        false,
      )
    } finally {
      await SandboxManager.reset()
    }
  })
})
