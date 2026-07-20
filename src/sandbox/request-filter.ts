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
import { Readable } from 'node:stream'
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

export const BODYLESS_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/**
 * Build a `Request`, run the callback, and if denied write the 403 response
 * and return `null`. On allow, returns the body stream the caller must pipe
 * upstream — this is the original `IncomingMessage` when no tee was needed
 * (GET/HEAD/OPTIONS), or the upstream-side branch of the tee otherwise.
 * Callers must pipe the returned stream (not `req`) to the outbound request.
 *
 * For methods that carry a body, `req` is converted to a web stream and
 * `tee()`'d: one branch goes to the callback's `Request.body`, the other is
 * returned for the caller to forward. If the callback never reads its
 * branch, we cancel it after the decision so the tee does not buffer the
 * entire upload.
 */
export async function decideAndRespond(
  filterRequest: FilterRequestCallback,
  req: IncomingMessage,
  res: ServerResponse,
  url: string,
  signal: AbortSignal,
): Promise<Readable | null> {
  let forCallback: ReadableStream<Uint8Array> | undefined
  let forUpstream: Readable = req
  if (!BODYLESS_METHODS.has(req.method ?? 'GET')) {
    const web = Readable.toWeb(req) as ReadableStream<Uint8Array>
    const [a, b] = web.tee()
    forCallback = a
    forUpstream = Readable.fromWeb(b)
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
    void forCallback?.cancel()
    forUpstream.destroy()
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
    void forCallback.cancel()
  }

  if (decision.action === 'allow') {
    logForDebugging(`[request-filter] allow ${req.method} ${url}`)
    return forUpstream
  }

  deny(res, decision)
  forUpstream.destroy()
  return null
}

function deny(res: ServerResponse, decision: RequestDecision): void {
  const reason = decision.reason ?? 'denied by filterRequest'
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
