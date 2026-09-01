import { describe, expect, it } from 'bun:test'
import {
  registerCommandText,
  resolveCommandText,
} from '../../src/sandbox/sandbox-manager.js'
import {
  decodeSandboxedCommand,
  encodeSandboxedCommand,
} from '../../src/sandbox/sandbox-utils.js'

const keyFor = (id: string): string =>
  decodeSandboxedCommand(encodeSandboxedCommand(id))

describe('violation command-text attribution', () => {
  it('resolves a registered commandId to the embedder text verbatim, control characters included', () => {
    const text = 'printf "a\\n"\n# second line\tkept'
    registerCommandText('ignored', { commandId: 'id-1', commandText: text })
    expect(resolveCommandText(keyFor('id-1'))).toBe(text)
  })

  it('registers an id that equals its text so the raw text is what resolves', () => {
    const text = 'echo one\necho two'
    registerCommandText(text, { commandId: text })
    expect(resolveCommandText(keyFor(text))).toBe(text)
  })

  it('collapses control characters in an unregistered key', () => {
    const forged = 'curl x\n\x1bspoofed\tline\x7f'
    expect(resolveCommandText(forged)).toBe('curl x spoofed line')
  })

  it('skips registration only when no id is given', () => {
    const text = 'never-registered-command'
    registerCommandText(text, undefined)
    expect(resolveCommandText(keyFor(text))).toBe(text)
    registerCommandText(`${text}\nwith-newline`, {})
    expect(resolveCommandText(keyFor(`${text}\nwith-newline`))).toBe(
      `${text} with-newline`,
    )
  })
})
