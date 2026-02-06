import { describe, test, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import { join } from 'node:path'

/**
 * Get the path to the CLI entry point
 */
function getCliPath(): string {
  return join(process.cwd(), 'src', 'cli.ts')
}

/**
 * Run the CLI with given arguments and return the result
 */
function runCli(args: string[], options?: { input?: string; debug?: boolean }) {
  const result = spawnSync('bun', ['run', getCliPath(), ...args], {
    encoding: 'utf-8',
    input: options?.input,
    env: {
      ...process.env,
      // Use a non-existent config to get default behavior
      HOME: '/tmp/cli-test-nonexistent',
      // Enable SRT_DEBUG if debug option is set
      ...(options?.debug ? { SRT_DEBUG: 'true' } : {}),
    },
  })
  return {
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status,
  }
}

describe('CLI', () => {
  describe('-c flag (command string mode)', () => {
    test('executes simple command with -c flag', () => {
      const result = runCli(['-c', 'echo hello'])
      expect(result.stdout.trim()).toBe('hello')
      expect(result.status).toBe(0)
    })

    test('passes command string directly without escaping', () => {
      const result = runCli(['-c', 'echo "hello world"'])
      expect(result.stdout.trim()).toBe('hello world')
      expect(result.status).toBe(0)
    })

    test('handles JSON arguments correctly', () => {
      // This is the main use case - JSON with quotes and special chars
      const result = runCli(['-c', 'echo \'{"key": "value"}\''])
      expect(result.stdout.trim()).toBe('{"key": "value"}')
      expect(result.status).toBe(0)
    })

    test('handles complex JSON with nested objects', () => {
      const json = '{"servers":{"name":"test","type":"sdk"}}'
      const result = runCli(['-c', `echo '${json}'`])
      expect(result.stdout.trim()).toBe(json)
      expect(result.status).toBe(0)
    })

    test('handles shell expansion in -c mode', () => {
      const result = runCli(['-c', 'echo $HOME'])
      // $HOME should be expanded by the shell
      expect(result.stdout.trim()).not.toBe('$HOME')
      expect(result.status).toBe(0)
    })

    test('handles pipes in -c mode', () => {
      const result = runCli(['-c', 'echo "hello world" | wc -w'])
      expect(result.stdout.trim()).toBe('2')
      expect(result.status).toBe(0)
    })

    test('handles command substitution in -c mode', () => {
      const result = runCli(['-c', 'echo "count: $(echo 1 2 3 | wc -w)"'])
      expect(result.stdout.trim()).toContain('3')
      expect(result.status).toBe(0)
    })
  })

  describe('default mode (positional arguments)', () => {
    test('executes simple command with positional args', () => {
      const result = runCli(['echo', 'hello'])
      expect(result.stdout.trim()).toBe('hello')
      expect(result.status).toBe(0)
    })

    test('joins multiple positional arguments with spaces', () => {
      const result = runCli(['echo', 'hello', 'world'])
      expect(result.stdout.trim()).toBe('hello world')
      expect(result.status).toBe(0)
    })

    test('handles arguments with flags', () => {
      const result = runCli(['echo', '-n', 'no newline'])
      // -n flag to echo suppresses newline
      expect(result.stdout).toBe('no newline')
      expect(result.status).toBe(0)
    })
  })

  describe('option passthrough to wrapped commands', () => {
    test('does not consume -s flag from wrapped command', () => {
      // Regression: -s is SRT's --settings shorthand, but after the command
      // name it should pass through to the wrapped command, not be parsed
      const result = runCli(['echo', '-s', 'silent'])
      expect(result.stdout.trim()).toBe('-s silent')
      expect(result.status).toBe(0)
    })

    test('does not consume -d flag from wrapped command', () => {
      // -d is SRT's --debug shorthand, but after the command name it should
      // pass through
      const result = runCli(['echo', '-d', 'debug'])
      expect(result.stdout.trim()).toBe('-d debug')
      expect(result.status).toBe(0)
    })

    test('SRT -s/--settings still works before command', () => {
      // SRT's own -s should still be parsed when it appears before the
      // wrapped command. Use a real config file to avoid silent-fallback issues.
      const tmpDir = fs.mkdtempSync(join(os.tmpdir(), 'srt-test-'))
      const configPath = join(tmpDir, 'config.json')
      const validConfig = {
        network: { allowedDomains: [], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }
      fs.writeFileSync(configPath, JSON.stringify(validConfig))

      try {
        const result = runCli(['-s', configPath, 'echo', 'hello'])
        expect(result.stdout.trim()).toBe('hello')
        expect(result.status).toBe(0)
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true })
      }
    })

    test('-- separator still works for backwards compatibility', () => {
      const result = runCli(['--', 'echo', '-s', 'test'])
      expect(result.stdout.trim()).toBe('-s test')
      expect(result.status).toBe(0)
    })
  })

  describe('error handling', () => {
    test('shows error when no command specified', () => {
      const result = runCli([])
      expect(result.stderr).toContain('No command specified')
      expect(result.status).toBe(1)
    })

    test('shows error when only options provided without command', () => {
      const result = runCli(['-d'])
      expect(result.stderr).toContain('No command specified')
      expect(result.status).toBe(1)
    })
  })

  describe('debug output', () => {
    test('SRT_DEBUG enables debug output for positional args', () => {
      const result = runCli(['echo', 'test'], { debug: true })
      // Debug mode should show additional logging to stderr
      expect(result.stderr).toContain('[SandboxDebug]')
      expect(result.stderr).toContain('Original command')
      expect(result.status).toBe(0)
    })

    test('SRT_DEBUG enables debug output for -c mode', () => {
      const result = runCli(['-c', 'echo test'], { debug: true })
      expect(result.stderr).toContain('[SandboxDebug]')
      expect(result.stderr).toContain('Command string mode')
      expect(result.status).toBe(0)
    })

    test('no debug output without SRT_DEBUG', () => {
      const result = runCli(['echo', 'test'], { debug: false })
      expect(result.stderr).not.toContain('[SandboxDebug]')
      expect(result.status).toBe(0)
    })
  })
})
