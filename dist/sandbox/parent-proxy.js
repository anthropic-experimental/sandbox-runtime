/**
 * Parent/upstream HTTP proxy support.
 *
 * When SRT runs in an environment that requires an HTTP proxy for outbound
 * internet access (e.g. inside a VM on a host behind a corporate proxy),
 * SRT's own proxies must chain through that upstream rather than connecting
 * directly.
 *
 * This module provides:
 *   - config resolution (explicit config -> HTTP_PROXY/HTTPS_PROXY/NO_PROXY env)
 *   - NO_PROXY matching (hostname suffix + CIDR via net.BlockList). Follows
 *     golang.org/x/net/http/httpproxy semantics for suffix matching. Note:
 *     port-specific NO_PROXY entries (e.g. `host:8080`) are matched by host
 *     only; the port is ignored.
 *   - a generic CONNECT-tunnel helper that works over Unix socket, TCP, or TLS
 */
import { BlockList, connect as netConnect, isIP } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { URL } from 'node:url';
import { logForDebugging } from '../utils/debug.js';
const CONNECT_TIMEOUT_MS = 30000;
/**
 * Hop-by-hop headers per RFC 7230 §6.1, plus proxy-specific headers that
 * MUST NOT be forwarded to the upstream. `transfer-encoding` is included
 * because we re-frame bodies via Node's client; Content-Length is preserved
 * end-to-end (Node's llhttp already rejects the TE+CL smuggling vector).
 */
const HOP_BY_HOP = new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'proxy-connection',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
]);
/**
 * Resolve the parent proxy config, falling back to the SRT process's own
 * environment. Note: SRT later overwrites HTTP_PROXY etc. in the *sandboxed
 * child's* environment to point at itself — but process.env here reflects the
 * environment SRT itself was launched with, which is what we want.
 */
export function resolveParentProxy(cfg) {
    const http = cfg?.http ?? process.env.HTTP_PROXY ?? process.env.http_proxy ?? undefined;
    const https = cfg?.https ??
        process.env.HTTPS_PROXY ??
        process.env.https_proxy ??
        // Fall back to HTTP_PROXY for HTTPS if HTTPS_PROXY is unset — this is
        // the de-facto behaviour of curl and most tooling.
        http;
    const noProxyRaw = cfg?.noProxy ?? process.env.NO_PROXY ?? process.env.no_proxy ?? '';
    if (!http && !https)
        return undefined;
    const parse = (u) => {
        if (!u)
            return undefined;
        // Accept schemeless `host:port` like curl does, but reject any scheme
        // other than http/https.
        const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(u);
        const withScheme = hasScheme ? u : `http://${u}`;
        try {
            const parsed = new URL(withScheme);
            if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
                !parsed.hostname) {
                throw new Error('unsupported scheme or empty host');
            }
            return parsed;
        }
        catch {
            logForDebugging(`Invalid parent proxy URL, ignoring: ${redactUserinfo(u)}`, { level: 'error' });
            return undefined;
        }
    };
    const httpUrl = parse(http);
    const httpsUrl = parse(https);
    // If both parsed to undefined, behave as if no parent proxy was configured
    // rather than returning a husk object that makes callers do bypass checks
    // for nothing.
    if (!httpUrl && !httpsUrl)
        return undefined;
    return { httpUrl, httpsUrl, noProxy: parseNoProxy(noProxyRaw) };
}
function parseNoProxy(raw) {
    const rules = {
        all: false,
        suffixes: [],
        cidr: new BlockList(),
    };
    for (let entry of raw.split(',')) {
        entry = entry.trim();
        if (!entry)
            continue;
        if (entry === '*') {
            rules.all = true;
            continue;
        }
        // CIDR?
        const slash = entry.indexOf('/');
        if (slash !== -1) {
            const ip = entry.slice(0, slash);
            const prefixStr = entry.slice(slash + 1);
            const fam = isIP(ip);
            if (fam && prefixStr !== '' && /^\d+$/.test(prefixStr)) {
                const prefix = Number(prefixStr);
                const max = fam === 6 ? 128 : 32;
                if (prefix >= 0 && prefix <= max) {
                    try {
                        rules.cidr.addSubnet(ip, prefix, fam === 6 ? 'ipv6' : 'ipv4');
                    }
                    catch {
                        // BlockList rejected it — ignore this entry.
                    }
                    continue;
                }
            }
            // malformed CIDR → ignore (do NOT treat as suffix; `/` isn't a valid
            // hostname char)
            continue;
        }
        // Hostname suffix. Normalise: lowercase, strip brackets (handling the
        // `[v6]:port` form), strip leading `*.`, strip a trailing `:port` (unless
        // the entry is an IP literal — IPv6 addresses contain colons).
        let v = entry.toLowerCase();
        const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(v);
        if (bracketed)
            v = bracketed[1];
        if (v.startsWith('*.'))
            v = v.slice(1);
        const bareFam = isIP(v);
        if (!bareFam) {
            const colon = v.lastIndexOf(':');
            if (colon !== -1 && /^\d+$/.test(v.slice(colon + 1))) {
                v = v.slice(0, colon);
            }
        }
        else {
            // Bare IP literal — store as an exact-match /32 or /128 CIDR so that
            // lookups go through BlockList rather than string suffix matching.
            try {
                rules.cidr.addAddress(v, bareFam === 6 ? 'ipv6' : 'ipv4');
                continue;
            }
            catch {
                // fall through to suffix push
            }
        }
        rules.suffixes.push(v);
    }
    return rules;
}
/**
 * Returns true if the given host should bypass the parent proxy and connect
 * directly. Always bypasses loopback.
 *
 * NB: the port is not consulted. NO_PROXY entries of the form `host:port` are
 * matched by host only (the port suffix is stripped during parsing).
 */
export function shouldBypassParentProxy(resolved, host) {
    const h = stripBrackets(host.toLowerCase().replace(/\.$/, ''));
    // Always bypass loopback — chaining localhost through an upstream proxy is
    // never what you want. Covers the whole 127/8 block and IPv4-mapped forms.
    if (h === 'localhost')
        return true;
    const fam = isIP(h);
    if (fam) {
        if (LOOPBACK.check(h, fam === 6 ? 'ipv6' : 'ipv4'))
            return true;
    }
    if (resolved.noProxy.all)
        return true;
    if (fam) {
        if (resolved.noProxy.cidr.check(h, fam === 6 ? 'ipv6' : 'ipv4'))
            return true;
    }
    for (const v of resolved.noProxy.suffixes) {
        if (v.startsWith('.')) {
            // .example.com matches foo.example.com and example.com
            if (h === v.slice(1) || h.endsWith(v))
                return true;
        }
        else {
            // example.com matches example.com and foo.example.com (golang semantics)
            if (h === v || h.endsWith('.' + v))
                return true;
        }
    }
    return false;
}
const LOOPBACK = (() => {
    const bl = new BlockList();
    bl.addSubnet('127.0.0.0', 8, 'ipv4');
    bl.addAddress('::1', 'ipv6');
    bl.addSubnet('::ffff:127.0.0.0', 104, 'ipv6'); // v4-mapped loopback
    return bl;
})();
/**
 * Pick which parent proxy URL to use for a given destination.
 */
export function selectParentProxyUrl(resolved, opts) {
    if (opts.isHttps)
        return resolved.httpsUrl ?? resolved.httpUrl;
    // For plain HTTP we only fall back to HTTPS_PROXY if it was explicitly set
    // — matches curl's behaviour where HTTP requests go direct if only
    // HTTPS_PROXY is configured.
    return resolved.httpUrl;
}
/**
 * Generic CONNECT-tunnel: dial a proxy transport (unix/tcp/tls), send
 * `CONNECT host:port`, wait for a 2xx, and resolve with the tunnelled socket.
 * Validates destHost to prevent CRLF injection from untrusted callers.
 */
export function openConnectTunnel(opts) {
    const { destHost, destPort } = opts;
    // CRLF-injection guard: destHost may originate from an untrusted SOCKS5
    // DOMAINNAME field. Reject anything that isn't a plain hostname or IP.
    const bare = stripBrackets(destHost);
    if (!isValidHost(bare)) {
        return Promise.reject(new Error(`Invalid destination host for CONNECT: ${JSON.stringify(destHost)}`));
    }
    if (!Number.isInteger(destPort) || destPort < 1 || destPort > 65535) {
        return Promise.reject(new Error(`Invalid destination port: ${destPort}`));
    }
    const authority = isIP(bare) === 6 ? `[${bare}]:${destPort}` : `${bare}:${destPort}`;
    return new Promise((resolve, reject) => {
        const sock = opts.dial();
        let settled = false;
        const fail = (err) => {
            if (settled)
                return;
            settled = true;
            sock.destroy();
            reject(err);
        };
        const onClose = () => fail(new Error('Proxy closed during CONNECT handshake'));
        sock.setTimeout(opts.timeoutMs ?? CONNECT_TIMEOUT_MS, () => fail(new Error('CONNECT handshake timed out')));
        sock.once('error', fail);
        sock.once('close', onClose);
        sock.once(opts.readyEvent, () => {
            sock.write(`CONNECT ${authority} HTTP/1.1\r\n` +
                `Host: ${authority}\r\n` +
                (opts.authHeader
                    ? `Proxy-Authorization: ${opts.authHeader}\r\n`
                    : '') +
                '\r\n');
            let buf = '';
            const onData = (chunk) => {
                buf += chunk.toString('latin1');
                const end = buf.indexOf('\r\n\r\n');
                if (end === -1) {
                    // Cap header size to avoid unbounded buffering on a misbehaving proxy.
                    if (buf.length > 16 * 1024)
                        fail(new Error('CONNECT response header too large'));
                    return;
                }
                // Pause before detaching the data listener so the stream stops
                // flowing — otherwise the unshift below (or any bytes arriving
                // between now and the caller's pipe()) would be dropped.
                sock.pause();
                sock.removeListener('data', onData);
                const statusLine = buf.slice(0, buf.indexOf('\r\n'));
                if (!/^HTTP\/1\.[01] 2\d\d(?:\s|$)/.test(statusLine)) {
                    return fail(new Error(`Proxy refused CONNECT: ${statusLine.trim()}`));
                }
                // Re-emit any bytes that arrived after the header terminator.
                const rest = buf.slice(end + 4);
                if (rest.length)
                    sock.unshift(Buffer.from(rest, 'latin1'));
                settled = true;
                sock.setTimeout(0);
                sock.removeListener('error', fail);
                sock.removeListener('close', onClose);
                resolve(sock);
            };
            sock.on('data', onData);
        });
    });
}
/**
 * Open a CONNECT tunnel through a parent HTTP(S) proxy specified by URL.
 * Thin wrapper around openConnectTunnel that dials TCP or TLS based on the
 * proxy URL scheme.
 */
export function connectViaParentProxy(proxyUrl, destHost, destPort) {
    const proxyHost = stripBrackets(proxyUrl.hostname);
    const proxyPort = Number(proxyUrl.port) || (proxyUrl.protocol === 'https:' ? 443 : 80);
    const useTls = proxyUrl.protocol === 'https:';
    return openConnectTunnel({
        destHost,
        destPort,
        authHeader: proxyAuthHeader(proxyUrl),
        readyEvent: useTls ? 'secureConnect' : 'connect',
        dial: () => useTls
            ? tlsConnect({
                host: proxyHost,
                port: proxyPort,
                // SNI must be a hostname, never an IP literal (RFC 6066 §3).
                ...(isIP(proxyHost) ? {} : { servername: proxyHost }),
            })
            : netConnect(proxyPort, proxyHost),
    });
}
// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
export function proxyAuthHeader(proxyUrl) {
    if (!proxyUrl.username && !proxyUrl.password)
        return undefined;
    try {
        const creds = `${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`;
        return `Basic ${Buffer.from(creds).toString('base64')}`;
    }
    catch {
        // Malformed percent-encoding in userinfo — fall back to raw values
        // rather than throwing synchronously into the caller.
        const creds = `${proxyUrl.username}:${proxyUrl.password}`;
        return `Basic ${Buffer.from(creds).toString('base64')}`;
    }
}
/**
 * Strip hop-by-hop and proxy-specific headers before forwarding upstream.
 * Also strips any headers named in the incoming `Connection` header, per
 * RFC 7230 §6.1.
 */
export function stripHopByHop(h) {
    const extra = new Set();
    const connHeader = h.connection;
    if (connHeader) {
        for (const tok of String(connHeader).split(',')) {
            extra.add(tok.trim().toLowerCase());
        }
    }
    const out = {};
    for (const [k, v] of Object.entries(h)) {
        const lk = k.toLowerCase();
        if (!HOP_BY_HOP.has(lk) && !extra.has(lk))
            out[k] = v;
    }
    return out;
}
/** Remove surrounding square brackets from an IPv6 literal. */
export function stripBrackets(host) {
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}
/** Redact userinfo from a URL for safe logging. */
export function redactUrl(u) {
    if (!u)
        return '-';
    if (!u.username && !u.password)
        return u.href;
    const c = new URL(u.href);
    c.username = '***';
    c.password = '***';
    return c.href;
}
function redactUserinfo(raw) {
    // Best-effort redaction for unparseable URLs.
    return raw.replace(/\/\/[^@/]*@/, '//***:***@');
}
/**
 * Hostname validation: accepts DNS names and IP literals (without zone IDs).
 * Primary purpose is to block control characters (CRLF injection, null-byte
 * DNS truncation) and zone-identifier allowlist bypasses from reaching the
 * wire or the allowlist matcher.
 *
 * IPv6 zone IDs (`fe80::1%eth0`) are rejected because `isIP` accepts a very
 * permissive zone charset including dots — `::ffff:1.2.3.4%x.allowed.com`
 * would pass `isIP`, pass a `.endsWith('.allowed.com')` wildcard check, and
 * then connect to 1.2.3.4 when the OS discards the bogus scope.
 */
export function isValidHost(h) {
    if (!h || h.length > 255)
        return false;
    const bare = stripBrackets(h);
    // Reject zone identifiers outright (see doc comment).
    if (bare.includes('%'))
        return false;
    if (isIP(bare))
        return true;
    // DNS label charset. Underscore is permitted for compatibility with real-
    // world DNS records (_dmarc, _acme-challenge, etc.).
    return /^[A-Za-z0-9._-]+$/.test(bare);
}
/**
 * Canonicalize a host string via the WHATWG URL parser so that string
 * comparisons in the allowlist agree with what `net.connect()`/`getaddrinfo()`
 * will actually dial. This normalizes:
 *   - inet_aton shorthand (`127.1` → `127.0.0.1`, `2130706433` → `127.0.0.1`)
 *   - hex/octal octets (`0x7f.0.0.1` → `127.0.0.1`)
 *   - IPv6 compression (`0:0:0:0:0:0:0:1` → `::1`)
 *   - trailing dots, case, brackets
 *
 * Returns undefined if the input is not a valid URL host.
 */
export function canonicalizeHost(h) {
    try {
        const bare = stripBrackets(h);
        // WHATWG URL rejects zone IDs and most garbage; it normalizes inet_aton
        // forms and IPv6 compression. It does NOT strip trailing dots or IPv6
        // brackets from the output, so we do that ourselves.
        const bracketed = isIP(bare) === 6 ? `[${bare}]` : bare;
        const out = new URL(`http://${bracketed}/`).hostname;
        return stripBrackets(out).replace(/\.$/, '');
    }
    catch {
        return undefined;
    }
}
/**
 * Dial `host:port` directly with a bounded timeout. Shared by the HTTP and
 * SOCKS direct-connect paths so they get the same timeout behaviour as the
 * CONNECT-tunnelled paths.
 */
export function dialDirect(host, port, timeoutMs = CONNECT_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
        const s = netConnect(port, host);
        let settled = false;
        const done = (err) => {
            if (settled)
                return;
            settled = true;
            s.setTimeout(0);
            if (err) {
                s.destroy();
                reject(err);
            }
            else {
                resolve(s);
            }
        };
        s.setTimeout(timeoutMs, () => done(new Error('connect timed out')));
        s.once('connect', () => done());
        s.once('error', done);
        s.once('close', () => done(new Error('socket closed before connect')));
    });
}
//# sourceMappingURL=parent-proxy.js.map