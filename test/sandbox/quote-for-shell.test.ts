import { describe, test, expect } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { quoteForShell } from '../../src/sandbox/sandbox-utils.js'
import { wrapCommandWithSandboxMacOS } from '../../src/sandbox/macos-sandbox-utils.js'

describe('quoteForShell', () => {
  test('single-quotes elements shell-quote would double-quote', () => {
    // shell-quote alone returns "it's a\!b" — and `\!` inside double
    // quotes has no portable meaning: POSIX shells and bash keep the
    // backslash, interactive zsh removes it. Single quotes make `!`
    // inert in every mode of every POSIX-family shell.
    expect(quoteForShell(["it's a!b"])).toBe("'it'\\''s a!b'")
  })

  test('caller-supplied backslashes survive untouched', () => {
    // Inside single quotes every byte is literal: input \! comes back as
    // \! after one shell parse, input \\! as \\!, never as !.
    expect(quoteForShell(["it's a\\!b"])).toBe("'it'\\''s a\\!b'")
    expect(quoteForShell(["it's a\\\\!b"])).toBe("'it'\\''s a\\\\!b'")
    expect(quoteForShell(['it\'s "!'])).toBe("'it'\\''s \"!'")
  })

  test('leaves single-quote and bare strategies untouched', () => {
    expect(quoteForShell(['a!b plain'])).toBe("'a!b plain'")
    expect(quoteForShell(['env', 'A=b c', 'x'])).toBe("env 'A=b c' x")
  })

  test('escapes a bare leading ~ so it cannot tilde-expand', () => {
    expect(quoteForShell(['~/x'])).toBe('\\~/x')
    expect(quoteForShell(['~root'])).toBe('\\~root')
    expect(quoteForShell(['a~b'])).toBe('a~b')
  })

  test('round-trips hostile arguments through a real shell parse', () => {
    const args = [
      "it's a!b", // single quote + whitespace + ! — the trigger combination
      'x != y',
      "don't stop!now",
      'pre-escaped a\\!b',
      'double-escaped a\\\\!b',
      'quote-then-bang \'"!',
      'backslash-quote-bang \'\\"!',
      "runs '\\\\\\!!\\!",
      '!hist',
      'a!b',
      "many'!'quotes !",
      'new\nline!',
      '~/path',
      '$HOME `tick` "dq" \\',
      '',
    ]
    // printf '%s\0' emits each argv element NUL-terminated so argv can be
    // recovered exactly even when args contain newlines.
    const cmd = quoteForShell(['printf', '%s\\0', ...args])
    for (const shell of ['bash', 'zsh', 'sh']) {
      const r = spawnSync(shell, ['-c', cmd], { encoding: 'utf8' })
      if (r.error) continue // shell not installed on this host
      expect(r.status).toBe(0)
      expect(r.stdout.split('\0').slice(0, -1)).toEqual(args)
    }
  })

  test('wrapCommandWithSandboxMacOS does not corrupt ! in the command', () => {
    // The wrapped command element contains a single quote, so the
    // serializer picks its double-quote strategy; before the fix every
    // `!` in the command came out as `\!`.
    const wrapped = wrapCommandWithSandboxMacOS({
      command: "echo 'x != y'",
      needsNetworkRestriction: false,
      readConfig: undefined,
      writeConfig: { allowOnly: ['/tmp'], denyWithinAllow: [] },
    })
    expect(wrapped).toContain('x != y')
    expect(wrapped).not.toContain('\\!')
  })

  test('exhaustive: every string ≤5 chars over {\\ ! \' " space a} round-trips', () => {
    const ALPHABET = ['\\', '!', "'", '"', ' ', 'a']
    const all: string[] = []
    let layer = ['']
    for (let len = 1; len <= 5; len++) {
      const next: string[] = []
      for (const prefix of layer) {
        for (const ch of ALPHABET) {
          next.push(prefix + ch)
        }
      }
      all.push(...next)
      layer = next
    }
    // Batch through a single shell parse per chunk to keep spawn count low.
    const BATCH = 1000
    for (const shell of ['bash', 'sh', 'zsh']) {
      for (let i = 0; i < all.length; i += BATCH) {
        const batch = all.slice(i, i + BATCH)
        const cmd = quoteForShell(['printf', '%s\\0', ...batch])
        const r = spawnSync(shell, ['-c', cmd], { encoding: 'utf8' })
        if (r.error) break // shell not installed on this host
        expect(r.status).toBe(0)
        expect(r.stdout.split('\0').slice(0, -1)).toEqual(batch)
      }
    }
  })

  test('round-trips through two nested shell parses (Linux wrap shape)', () => {
    // buildSandboxCommand layers quoting: the user command is embedded in
    // an inner script which is itself quoted into the bwrap argv string.
    const args = ["it's a!b", 'x != y', '!both~']
    const payload = quoteForShell(['printf', '%s\\0', ...args])
    const inner = `eval ${quoteForShell([payload])}`
    const outer = quoteForShell(['sh', '-c', inner])
    for (const shell of ['bash', 'zsh', 'sh']) {
      const r = spawnSync(shell, ['-c', outer], { encoding: 'utf8' })
      if (r.error) continue
      expect(r.status).toBe(0)
      expect(r.stdout.split('\0').slice(0, -1)).toEqual(args)
    }
  })
})
