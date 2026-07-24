/**
 * Request-level filter hook for the forward proxy.
 *
 * Library consumers supply a `filterRequest` callback via
 * `network.filterRequest`. It receives the parsed HTTP request (web-standard
 * `Request`) and returns a decision. Applies to plain HTTP through the proxy
 * and, when `tlsTerminate` is configured, to terminated HTTPS. The proxy
 * enforces the decision; the library does not bless any matching DSL.
 */

import type {
  IncomingHttpHeaders,
  IncomingMessage,
  ServerResponse,
} from 'node:http'
import { PassThrough, Readable } from 'node:stream'
import { logForDebugging } from '../utils/debug.js'

export type RequestDecision = {
  action: 'allow' | 'deny'
  /**
   * Human-readable reason. For denials this is surfaced to the sandboxed
   * client in the response body so the agent can tell a policy block from a
   * network failure.
   */
  reason?: string
}

/**
 * Called once per HTTP request that the proxy parses.
 *
 * - `request` is a web-standard `Request`: method, URL, headers, and a lazy
 *   `request.body` stream (one branch of a tee — reading it does not consume
 *   the bytes that get forwarded upstream). `request.signal` aborts when the
 *   client disconnects.
 * - **Throwing or rejecting denies the request.** This is the failure
 *   contract for a security boundary: a buggy policy fails closed.
 */
export type FilterRequestCallback = (
  request: Request,
) => Promise<RequestDecision>

/**
 * Mutate the headers that will be sent upstream, in place.
 *
 * Runs after the allow/deny decision and hop-by-hop stripping, immediately
 * before the upstream request is built. `destHost` is the canonical
 * destination host (the CONNECT target on the TLS-terminated path, or the
 * absolute-URI host on the plain-HTTP path) — never the client-supplied
 * Host header, which is spoofable.
 */
export type MutateForwardedHeaders = (
  headers: IncomingHttpHeaders,
  destHost: string,
) => void

/**
 * How much of a denied request body the proxy discards to let the client
 * read the 403 before the connection drops. The response is tiny, so this
 * only needs to cover what a well-behaved client has in flight.
 */
const MAX_DENIED_BODY_DRAIN_BYTES = 1024 * 1024

/** Companion time bound for {@link drainThenDestroy} — a slow-drip body
 * under the byte cap must not pin the socket indefinitely. */
const MAX_DENIED_BODY_DRAIN_MS = 5_000

/**
 * Discard a denied request's remaining body — bounded by bytes AND time —
 * then destroy the connection.
 *
 * Destroying a socket that still has unread inbound data emits a TCP RST,
 * which can discard the client's receive queue before it reads the 403 —
 * the exact ambiguity the response body exists to prevent. Draining to
 * stream end removes the unread data so teardown sends a clean FIN. The
 * caps bound a hostile endless or slow-drip upload; tripping them destroys
 * mid-stream (best-effort delivery is acceptable against a hostile peer).
 * The connection is always torn down: the drained request was denied, and
 * its byte stream must never be reused as a keep-alive prelude.
 */
export function drainThenDestroy(
  source: Readable,
  req: IncomingMessage,
  capBytes: number = MAX_DENIED_BODY_DRAIN_BYTES,
  timeoutMs: number = MAX_DENIED_BODY_DRAIN_MS,
): void {
  let drained = 0
  const finish = (): void => {
    clearTimeout(timer)
    req.destroy()
    // Bun's IncomingMessage.destroy() does not tear down the underlying
    // socket (verified empirically; Node's does) — close it explicitly so
    // the denied connection actually dies on both runtimes.
    req.socket?.destroy()
  }
  const timer = setTimeout(finish, timeoutMs)
  if (typeof timer.unref === 'function') timer.unref()
  source.on('data', (chunk: Buffer | string) => {
    drained += chunk.length
    if (drained > capBytes) finish()
  })
  source.once('end', finish)
  source.once('error', finish)
  source.once('close', finish)
}

/**
 * True when the request's framing headers declare a body (RFC 9112 §6):
 * a Transfer-Encoding is present, or a non-zero Content-Length.
 *
 * Body presence is a property of FRAMING, not of the method — GET, HEAD,
 * and OPTIONS requests can all carry a body on the wire, and both runtimes'
 * HTTP servers parse and expose it. Any body gate keyed on the method
 * instead of these headers lets those bodies through unexamined.
 */
export function requestDeclaresBody(req: IncomingMessage): boolean {
  // Truthiness, not presence: an empty Content-Length/Transfer-Encoding
  // value declares nothing and must not trigger teeing, denial, or
  // re-framing.
  if (req.headers['transfer-encoding']) return true
  const cl = req.headers['content-length']
  // `Content-Length: 0` declares that there is no body. A malformed value
  // counts as declaring one (fail closed); the HTTP parser normally rejects
  // those before we ever see them.
  return Boolean(cl) && Number(cl) !== 0
}

/**
 * Build a `Request`, run the callback, and if denied write the 403 response
 * and return `null`. On allow, returns the body stream the caller must pipe
 * upstream — this is the original `IncomingMessage` when no tee was needed
 * (no body declared), or the upstream-side branch of the tee otherwise.
 * Callers must pipe the returned stream (not `req`) to the outbound request.
 *
 * For requests that declare a body, `req` is converted to a web stream and
 * `tee()`'d: one branch goes to the callback's `Request.body`, the other is
 * returned for the caller to forward. If the callback never reads its
 * branch, we cancel it after the decision so the tee does not buffer the
 * entire upload.
 *
 * GET and HEAD requests that declare a body are denied outright: the web
 * `Request` constructor cannot represent them, so the callback could never
 * inspect the body — forwarding it would bypass any body-inspecting policy.
 * Fail closed instead; only non-standard clients send GET/HEAD bodies, and
 * this path only runs when a `filterRequest` policy is configured.
 */
export async function decideAndRespond(
  filterRequest: FilterRequestCallback,
  req: IncomingMessage,
  res: ServerResponse,
  url: string,
  signal: AbortSignal,
): Promise<Readable | null> {
  const method = req.method ?? 'GET'
  const declaresBody = requestDeclaresBody(req)
  if (declaresBody && (method === 'GET' || method === 'HEAD')) {
    deny(res, {
      action: 'deny',
      reason: `${method} request with a body cannot be inspected by filterRequest`,
    })
    // NOT keyed on `res` events: ServerResponse 'close' fires on response
    // COMPLETION in Node, so destroying there would preempt the drain and
    // RST-clobber the 403 it protects.
    drainThenDestroy(req, req)
    return null
  }

  let forCallback: ReadableStream<Uint8Array> | undefined
  let forUpstream: Readable = req
  if (declaresBody) {
    // Never hand toWeb a stream that can error: when its source errors,
    // the toWeb/tee/fromWeb bridge leaks the error as internal promise
    // rejections (and, under Bun, uncaught exceptions) that no userland
    // listener can catch. A client abort mid-body becomes a clean EOF on
    // the shim instead, and the abort is propagated by destroying the
    // upstream branch directly — a truncated body must never be forwarded
    // framed as complete (chunked framing would otherwise emit a valid
    // terminator; on the SigV4 path a truncated buffer would be signed).
    // The shim's own error listener covers the tee cancelling it while
    // the client is still piping.
    const shim = new PassThrough()
    shim.on('error', () => {})
    req.pipe(shim)
    const web = Readable.toWeb(shim) as ReadableStream<Uint8Array>
    const [a, b] = web.tee()
    forCallback = a
    forUpstream = Readable.fromWeb(b)
    const upstreamBranch = forUpstream
    // The caller only wires its own 'error' handler after this function
    // resolves; a client abort during the filterRequest await must not
    // land on a listener-less stream.
    upstreamBranch.on('error', () => {})
    req.on('error', err => {
      shim.end()
      upstreamBranch.destroy(err)
    })
  } else if (method !== 'GET' && method !== 'HEAD') {
    // No body on the wire, but keep the pre-framing-gate contract for the
    // callback: methods that CAN carry a body get an empty stream rather
    // than `body: null`, so a policy that unconditionally reads
    // `request.body` keeps working. Nothing extra is forwarded — there is
    // no body. GET/HEAD stay null (the Request constructor forbids them).
    forCallback = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.close()
      },
    })
  }

  let webReq: Request
  try {
    webReq = new Request(url, {
      method: req.method,
      headers: incomingHeaders(req),
      signal,
      ...(forCallback ? { body: forCallback, duplex: 'half' as const } : {}),
    })
  } catch (err) {
    // Malformed URL/headers from the client — deny rather than crash.
    deny(res, {
      action: 'deny',
      reason: `malformed request: ${(err as Error).message}`,
    })
    forCallback?.cancel().catch(() => {})
    forUpstream.destroy()
    // The shim breaks the fromWeb→tee→toWeb cancel cascade that used to
    // destroy req — without a teardown a denied client keeps uploading
    // into a stalled pipe and holds the connection open. Same bounded
    // drain-then-teardown as every other deny.
    drainThenDestroy(req, req)
    return null
  }

  let decision: RequestDecision
  try {
    decision = await filterRequest(webReq)
  } catch (err) {
    decision = {
      action: 'deny',
      reason: `filterRequest threw: ${(err as Error).message}`,
    }
  }

  // If the callback didn't read its branch, cancel it so tee() stops
  // buffering bytes nobody will consume. If it did, the tee already buffered
  // whatever was read; the upstream branch sees the same bytes.
  if (forCallback && !webReq.bodyUsed) {
    // cancel() rejects with the stream's stored error if it already
    // failed; that rejection must not escape.
    forCallback.cancel().catch(() => {})
  }

  if (decision.action === 'allow') {
    logForDebugging(`[request-filter] allow ${req.method} ${url}`)
    return forUpstream
  }

  deny(res, decision)
  // Same discipline as the GET/HEAD-with-body deny above: discard whatever
  // body remains (bounded) so the 403 is readable, then tear the
  // connection down. Draining forUpstream pulls the underlying request
  // through the tee; destroying `req` closes the socket.
  drainThenDestroy(forUpstream, req)
  return null
}

function deny(res: ServerResponse, decision: RequestDecision): void {
  respondDenied(res, decision.reason ?? 'denied by filterRequest')
}

/**
 * Write the proxy's standard policy-denial response: 403 with the reason
 * in the body, so the sandboxed client can tell a policy block from a
 * network failure. Shared by filterRequest denials and other in-proxy
 * policy decisions (e.g. SigV4 shapes that cannot be re-signed).
 */
export function respondDenied(res: ServerResponse, reason: string): void {
  logForDebugging(`[request-filter] deny: ${reason}`)
  if (res.headersSent) {
    res.destroy()
    return
  }
  res.writeHead(403, {
    'Content-Type': 'text/plain',
    'X-Proxy-Error': 'blocked-by-sandbox-runtime',
  })
  res.end(reason + '\n')
}

function incomingHeaders(req: IncomingMessage): Headers {
  const h = new Headers()
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue
    if (Array.isArray(v)) {
      for (const vv of v) h.append(k, vv)
    } else {
      h.append(k, v)
    }
  }
  return h
}
