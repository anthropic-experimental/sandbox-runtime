import type { Readable, Writable } from 'node:stream'

/**
 * Relay `src` into `dst` with paused-mode reads (`'readable'` + `read()`)
 * instead of `src.pipe(dst)`.
 *
 * `pipe()` throttles a flowing source with `pause()`/`resume()`, and under
 * Bun a socket delivered by an http server's `'connect'` event corrupts its
 * byte stream across those pause/resume cycles once writes queue (reliably
 * reproducible with multi-megabyte uploads through a plain CONNECT tunnel;
 * a TLS peer behind the relay then fails record MAC verification and the
 * client sees `bad_record_mac` / a mid-upload reset). Pull-mode reads never
 * call `pause()` and provide the same flow control: `read()` is only called
 * while `dst` has buffer space, so the kernel backpressures the peer
 * identically. Do not replace this with `pipe()` — under Node both are
 * equivalent, but under Bun only this form is safe for CONNECT-upgraded
 * sockets.
 *
 * Like `pipe()`, this ends `dst` when `src` ends and does nothing on
 * `src`/`dst` errors — callers keep their existing error/close teardown.
 */
export function relayPullMode(src: Readable, dst: Writable): void {
  const pump = (): void => {
    let chunk: Buffer | string | null
    while ((chunk = src.read() as Buffer | string | null) !== null) {
      if (!dst.write(chunk)) {
        dst.once('drain', pump)
        return
      }
    }
    src.once('readable', pump)
  }
  pump()
  src.once('end', () => dst.end())
}
