import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getPlatform } from '../../src/utils/platform.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'

/**
 * Integration tests for mandatory deny paths.
 *
 * These tests verify that dangerous files (.bashrc, .gitconfig, etc.) and
 * directories (.git/hooks, .vscode, etc.) are blocked from writes even when
 * they're within an allowed write path.
 *
 * IMPORTANT: The mandatory deny patterns are relative to process.cwd().
 * Tests must chdir to TEST_DIR before generating sandbox commands.
 */

function skipIfUnsupportedPlatform(): boolean {
  const platform = getPlatform()
  return platform !== 'linux' && platform !== 'macos'
}

describe('Mandatory Deny Paths - Integration Tests', () => {
  const TEST_DIR = join(tmpdir(), `mandatory-deny-integration-${Date.now()}`)
  const ORIGINAL_CONTENT = 'ORIGINAL'
  const MODIFIED_CONTENT = 'MODIFIED'
  let originalCwd: string

  beforeAll(() => {
    if (skipIfUnsupportedPlatform()) return

    originalCwd = process.cwd()
    mkdirSync(TEST_DIR, { recursive: true })

    // Create ALL dangerous files from DANGEROUS_FILES
    writeFileSync(join(TEST_DIR, '.bashrc'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.bash_profile'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.gitconfig'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.gitmodules'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.zshrc'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.zprofile'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.profile'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.ripgreprc'), ORIGINAL_CONTENT)
    writeFileSync(join(TEST_DIR, '.mcp.json'), ORIGINAL_CONTENT)

    // Create .git with hooks and config
    mkdirSync(join(TEST_DIR, '.git', 'hooks'), { recursive: true })
    writeFileSync(join(TEST_DIR, '.git', 'config'), ORIGINAL_CONTENT)
    writeFileSync(
      join(TEST_DIR, '.git', 'hooks', 'pre-commit'),
      ORIGINAL_CONTENT,
    )
    writeFileSync(join(TEST_DIR, '.git', 'HEAD'), 'ref: refs/heads/main')

    // Create .vscode
    mkdirSync(join(TEST_DIR, '.vscode'), { recursive: true })
    writeFileSync(join(TEST_DIR, '.vscode', 'settings.json'), ORIGINAL_CONTENT)

    // Create .idea
    mkdirSync(join(TEST_DIR, '.idea'), { recursive: true })
    writeFileSync(join(TEST_DIR, '.idea', 'workspace.xml'), ORIGINAL_CONTENT)

    // Create .claude/commands and .claude/agents (should be blocked)
    mkdirSync(join(TEST_DIR, '.claude', 'commands'), { recursive: true })
    mkdirSync(join(TEST_DIR, '.claude', 'agents'), { recursive: true })
    writeFileSync(
      join(TEST_DIR, '.claude', 'commands', 'test.md'),
      ORIGINAL_CONTENT,
    )
    writeFileSync(
      join(TEST_DIR, '.claude', 'agents', 'test-agent.md'),
      ORIGINAL_CONTENT,
    )

    // Create a safe file that SHOULD be writable
    writeFileSync(join(TEST_DIR, 'safe-file.txt'), ORIGINAL_CONTENT)

    // Create safe files within .git that SHOULD be writable (not hooks/config)
    mkdirSync(join(TEST_DIR, '.git', 'objects'), { recursive: true })
    mkdirSync(join(TEST_DIR, '.git', 'refs', 'heads'), { recursive: true })
    writeFileSync(
      join(TEST_DIR, '.git', 'objects', 'test-obj'),
      ORIGINAL_CONTENT,
    )
    writeFileSync(
      join(TEST_DIR, '.git', 'refs', 'heads', 'main'),
      ORIGINAL_CONTENT,
    )
    writeFileSync(join(TEST_DIR, '.git', 'index'), ORIGINAL_CONTENT)

    // Create safe file within .claude that SHOULD be writable (not commands/agents)
    writeFileSync(
      join(TEST_DIR, '.claude', 'some-other-file.txt'),
      ORIGINAL_CONTENT,
    )
  })

  afterAll(() => {
    if (skipIfUnsupportedPlatform()) return
    process.chdir(originalCwd)
    rmSync(TEST_DIR, { recursive: true, force: true })
  })

  beforeEach(() => {
    if (skipIfUnsupportedPlatform()) return
    // Must be in TEST_DIR for mandatory deny patterns to apply correctly
    process.chdir(TEST_DIR)
  })

  async function runSandboxedWrite(
    filePath: string,
    content: string,
  ): Promise<{ success: boolean; stderr: string }> {
    const platform = getPlatform()
    const command = `echo '${content}' > '${filePath}'`

    // Allow writes to current directory, but mandatory denies should still block dangerous files
    const writeConfig = {
      allowOnly: ['.'],
      denyWithinAllow: [], // Empty - relying on mandatory denies
    }

    let wrappedCommand: string
    if (platform === 'macos') {
      wrappedCommand = wrapCommandWithSandboxMacOS({
        command,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })
    } else {
      wrappedCommand = await wrapCommandWithSandboxLinux({
        command,
        needsNetworkRestriction: false,
        readConfig: undefined,
        writeConfig,
      })
    }

    const result = spawnSync(wrappedCommand, {
      shell: true,
      encoding: 'utf8',
      timeout: 10000,
    })

    return {
      success: result.status === 0,
      stderr: result.stderr || '',
    }
  }

  describe('Dangerous files should be blocked', () => {
    it('blocks writes to .bashrc', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.bashrc', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.bashrc', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .gitconfig', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.gitconfig', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.gitconfig', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .zshrc', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.zshrc', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.zshrc', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .mcp.json', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.mcp.json', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.mcp.json', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .bash_profile', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.bash_profile', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.bash_profile', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .zprofile', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.zprofile', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.zprofile', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .profile', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.profile', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.profile', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .gitmodules', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.gitmodules', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.gitmodules', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .ripgreprc', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.ripgreprc', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.ripgreprc', 'utf8')).toBe(ORIGINAL_CONTENT)
    })
  })

  describe('Git hooks and config should be blocked', () => {
    it('blocks writes to .git/config', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.git/config', MODIFIED_CONTENT)

      expect(result.success).toBe(false)
      expect(readFileSync('.git/config', 'utf8')).toBe(ORIGINAL_CONTENT)
    })

    it('blocks writes to .git/hooks/pre-commit', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.git/hooks/pre-commit',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(false)
      expect(readFileSync('.git/hooks/pre-commit', 'utf8')).toBe(
        ORIGINAL_CONTENT,
      )
    })
  })

  describe('Dangerous directories should be blocked', () => {
    it('blocks writes to .vscode/', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.vscode/settings.json',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(false)
      expect(readFileSync('.vscode/settings.json', 'utf8')).toBe(
        ORIGINAL_CONTENT,
      )
    })

    it('blocks writes to .claude/commands/', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.claude/commands/test.md',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(false)
      expect(readFileSync('.claude/commands/test.md', 'utf8')).toBe(
        ORIGINAL_CONTENT,
      )
    })

    it('blocks writes to .claude/agents/', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.claude/agents/test-agent.md',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(false)
      expect(readFileSync('.claude/agents/test-agent.md', 'utf8')).toBe(
        ORIGINAL_CONTENT,
      )
    })

    it('blocks writes to .idea/', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.idea/workspace.xml',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(false)
      expect(readFileSync('.idea/workspace.xml', 'utf8')).toBe(ORIGINAL_CONTENT)
    })
  })

  describe('Safe files should still be writable', () => {
    it('allows writes to regular files', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('safe-file.txt', MODIFIED_CONTENT)

      expect(result.success).toBe(true)
      expect(readFileSync('safe-file.txt', 'utf8').trim()).toBe(
        MODIFIED_CONTENT,
      )
    })

    it('allows writes to .git/objects (not hooks/config)', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.git/objects/test-obj',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(true)
      expect(readFileSync('.git/objects/test-obj', 'utf8').trim()).toBe(
        MODIFIED_CONTENT,
      )
    })

    it('allows writes to .git/refs/heads (not hooks/config)', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.git/refs/heads/main',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(true)
      expect(readFileSync('.git/refs/heads/main', 'utf8').trim()).toBe(
        MODIFIED_CONTENT,
      )
    })

    it('allows writes to .git/index (not hooks/config)', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite('.git/index', MODIFIED_CONTENT)

      expect(result.success).toBe(true)
      expect(readFileSync('.git/index', 'utf8').trim()).toBe(MODIFIED_CONTENT)
    })

    it('allows writes to .claude/ files outside commands/agents', async () => {
      if (skipIfUnsupportedPlatform()) return

      const result = await runSandboxedWrite(
        '.claude/some-other-file.txt',
        MODIFIED_CONTENT,
      )

      expect(result.success).toBe(true)
      expect(readFileSync('.claude/some-other-file.txt', 'utf8').trim()).toBe(
        MODIFIED_CONTENT,
      )
    })
  })
})
