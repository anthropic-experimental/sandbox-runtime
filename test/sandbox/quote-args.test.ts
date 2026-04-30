import { describe, it, expect } from 'bun:test'
import { execFileSync } from 'node:child_process'
import { quoteArgs } from '../../src/sandbox/sandbox-utils.js'

describe('quoteArgs', () => {
  it('quotes simple and empty args', () => {
    expect(quoteArgs(['hello'])).toBe("'hello'")
    expect(quoteArgs([''])).toBe("''")
    expect(quoteArgs(['a', 'b c'])).toBe("'a' 'b c'")
  })

  it('escapes embedded single quotes', () => {
    expect(quoteArgs(["it's"])).toBe(`'it'\\''s'`)
  })

  it('leaves ! literal', () => {
    expect(quoteArgs(['a!b'])).toBe("'a!b'")
    expect(quoteArgs([`'a!b'`])).toBe(`''\\''a!b'\\'''`)
  })

  // Two nested bash -c layers, mirroring how linux-sandbox-utils wraps
  // commands; the quoted string must reproduce the original argv exactly.
  describe('bash -c round-trip', () => {
    const cases: [string, string[]][] = [
      ['bang', ['a!b']],
      ['json bang', ['--params', '{"k":"a!b"}']],
      ['prequoted bang', [`'a!b'`]],
      ['squote', ["it's"]],
      ['squote+bang', ["it's!"]],
      ['metachars', ['a!b\'c"d$e`f\\g h*?;|&<>()']],
      ['newline', ['a\nb']],
    ]

    const dump = (args: string[]): string[] => {
      const inner = quoteArgs([
        'node',
        '-e',
        'for (const a of process.argv.slice(1)) process.stdout.write(a + "\\0")',
        '--',
        ...args,
      ])
      const outer = quoteArgs(['bash', '-c', inner])
      const out = execFileSync('bash', ['-c', outer]).toString()
      return out.split('\0').slice(0, -1)
    }

    for (const [name, args] of cases) {
      it(name, () => {
        expect(dump(args)).toEqual(args)
      })
    }
  })
})
