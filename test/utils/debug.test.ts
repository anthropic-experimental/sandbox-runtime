import { describe, test, expect, spyOn } from 'bun:test'
import { logProxyDeny, logForDebugging } from '../../src/utils/debug.js'

describe('logProxyDeny', () => {
  // The key contract: proxy-deny messages must NOT go to stderr.
  // Writing to stderr from the srt host process corrupts TUI rendering
  // in the sandboxed child (e.g. Claude Code CLI).
  // Instead, on macOS the message is sent to the unified log via logger.
  test('does not write to stderr for HTTPS-CONNECT', () => {
    const saved = process.env.SRT_DEBUG
    delete process.env.SRT_DEBUG

    const writes: string[] = []
    const spy = spyOn(process.stderr, 'write').mockImplementation(
      (chunk: string | Uint8Array) => {
        writes.push(typeof chunk === 'string' ? chunk : chunk.toString())
        return true
      },
    )

    logProxyDeny('HTTPS-CONNECT', 'api.example.com', 443)

    expect(writes).toHaveLength(0)
    spy.mockRestore()
    if (saved !== undefined) process.env.SRT_DEBUG = saved
  })

  test('does not write to stderr for HTTP', () => {
    const writes: string[] = []
    const spy = spyOn(process.stderr, 'write').mockImplementation(
      (chunk: string | Uint8Array) => {
        writes.push(typeof chunk === 'string' ? chunk : chunk.toString())
        return true
      },
    )

    logProxyDeny('HTTP', 'example.com', 80)

    expect(writes).toHaveLength(0)
    spy.mockRestore()
  })

  test('does not write to stderr for SOCKS', () => {
    const writes: string[] = []
    const spy = spyOn(process.stderr, 'write').mockImplementation(
      (chunk: string | Uint8Array) => {
        writes.push(typeof chunk === 'string' ? chunk : chunk.toString())
        return true
      },
    )

    logProxyDeny('SOCKS', 'internal.corp', 1080)

    expect(writes).toHaveLength(0)
    spy.mockRestore()
  })

  test('does not write to stderr even when SRT_DEBUG is set', () => {
    const saved = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'

    const writes: string[] = []
    const spy = spyOn(process.stderr, 'write').mockImplementation(
      (chunk: string | Uint8Array) => {
        writes.push(typeof chunk === 'string' ? chunk : chunk.toString())
        return true
      },
    )

    logProxyDeny('HTTPS-CONNECT', 'blocked.example.com', 443)

    expect(writes).toHaveLength(0)
    spy.mockRestore()

    process.env.SRT_DEBUG = saved ?? ''
    if (saved === undefined) delete process.env.SRT_DEBUG
  })
})

describe('logForDebugging', () => {
  test('is silent when SRT_DEBUG is not set', () => {
    const saved = process.env.SRT_DEBUG
    delete process.env.SRT_DEBUG

    const spy = spyOn(console, 'error').mockImplementation(() => {})
    logForDebugging('should not appear', { level: 'error' })
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()

    if (saved !== undefined) process.env.SRT_DEBUG = saved
  })

  test('logs when SRT_DEBUG is set', () => {
    const saved = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'

    const messages: string[] = []
    const spy = spyOn(console, 'error').mockImplementation(
      (...args: unknown[]) => {
        messages.push(String(args[0]))
      },
    )
    logForDebugging('test message', { level: 'error' })
    expect(messages.some(m => m.includes('test message'))).toBe(true)
    spy.mockRestore()

    process.env.SRT_DEBUG = saved ?? ''
    if (saved === undefined) delete process.env.SRT_DEBUG
  })
})
