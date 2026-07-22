import { connect } from 'node:net'

/**
 * Send raw HTTP bytes to a server on 127.0.0.1 and return the raw response.
 * For request shapes higher-level clients cannot produce (HEAD with a body,
 * chunked GET, an explicit `Content-Length: 0` on GET).
 *
 * Resolves when the connection closes — denials destroy the inbound
 * socket; include `Connection: close` in the request so successes close
 * too. The timeout is a backstop. Rejects on a transport error or timeout
 * that arrives before any response bytes, so a reset connection surfaces
 * as the underlying failure rather than an empty-string assertion diff.
 */
export function rawHttpRequest(port: number, bytes: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect(port, '127.0.0.1', () => sock.write(bytes))
    let resp = ''
    sock.setEncoding('latin1')
    sock.on('data', (c: string) => {
      resp += c
    })
    const settle = (err?: Error) => {
      if (resp || err === undefined) resolve(resp)
      else reject(err)
    }
    sock.on('error', (err: Error) => settle(err))
    sock.on('close', () => settle())
    sock.setTimeout(5000, () => {
      const timedOut = !resp
      sock.destroy()
      if (timedOut) reject(new Error('rawHttpRequest: no response in 5s'))
    })
  })
}
