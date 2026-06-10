import { describe, test, expect, beforeEach, afterEach } from 'bun:test'
import { initializeLinuxNetworkBridge } from '../../src/sandbox/linux-sandbox-utils.js'

// When spawn() cannot start socat (e.g. the binary is missing or not
// executable), the ChildProcess gets no pid and emits an asynchronous
// 'error' event. initializeLinuxNetworkBridge must have an 'error'
// listener attached before it throws on the missing pid — otherwise the
// queued event fires with no listener and escalates to an
// uncaughtException, crashing the host process even though the caller
// handled the rejection.
describe('initializeLinuxNetworkBridge spawn failure', () => {
  const uncaught: Error[] = []
  const onUncaught = (err: Error): void => {
    uncaught.push(err)
  }

  beforeEach(() => {
    uncaught.length = 0
    process.on('uncaughtException', onUncaught)
  })

  afterEach(() => {
    process.off('uncaughtException', onUncaught)
  })

  test('rejects without an unhandled error event when socat cannot be spawned', async () => {
    await expect(
      initializeLinuxNetworkBridge(0, 0, '/nonexistent-for-test/socat'),
    ).rejects.toThrow('Failed to start HTTP bridge process')

    // Give the queued 'error' event a tick to fire so we can assert it was
    // absorbed by the bridge's own listener.
    await new Promise(r => setTimeout(r, 50))

    expect(uncaught).toEqual([])
  })
})
