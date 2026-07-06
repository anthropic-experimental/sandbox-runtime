import { describe, it, expect } from 'bun:test'
import {
  FakeIpPool,
  extractDnsTcpFrames,
  handleDnsQuery,
  isFakePoolIp,
  isForwardableDestination,
  parseDnsQuery,
  buildDnsResponse,
  buildDnsFormErr,
  normalizeCaptureAddress,
  formatConnectHost,
  buildConnectRequest,
  parseProxyResponseHead,
  parseBridgeSpec,
  QTYPE_A,
  QTYPE_AAAA,
} from '../../src/sandbox/transparent-net-helper.js'

/** Build a wire-format DNS query for `name`. */
function makeQuery(
  name: string,
  qtype: number,
  id = 0x1234,
  flags = 0x0100,
): Buffer {
  const labels = name.split('.').filter(Boolean)
  const qname = Buffer.concat([
    ...labels.map(l =>
      Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]),
    ),
    Buffer.from([0]),
  ])
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(flags, 2)
  header.writeUInt16BE(1, 4) // QDCOUNT
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(qtype, 0)
  tail.writeUInt16BE(1, 2) // IN
  return Buffer.concat([header, qname, tail])
}

describe('FakeIpPool', () => {
  it('allocates stable, distinct pool IPs per hostname', () => {
    const pool = new FakeIpPool()
    const a = pool.ipForHost('example.com')!
    const b = pool.ipForHost('github.com')!
    expect(a).not.toBe(b)
    expect(pool.ipForHost('example.com')).toBe(a)
    expect(isFakePoolIp(a)).toBe(true)
    expect(isFakePoolIp(b)).toBe(true)
  })

  it('is case-insensitive and reverse-maps', () => {
    const pool = new FakeIpPool()
    const ip = pool.ipForHost('Example.COM')!
    expect(pool.ipForHost('example.com')).toBe(ip)
    expect(pool.hostForIp(ip)).toBe('example.com')
    expect(pool.hostForIp('198.18.200.200')).toBeUndefined()
  })

  it('never reuses slots: fails closed on exhaustion', () => {
    // Mappings must be stable for the helper's lifetime — a reused slot
    // would let a stale cached fake IP connect as a different hostname.
    // (Brute-filling all 131071 hash-probed slots is O(n²) near
    // saturation; the counter is the fail-closed gate, so exercise it
    // directly plus a realistic-scale uniqueness sweep.)
    const pool = new FakeIpPool()
    const first = pool.ipForHost('first.example')!
    for (let i = 0; i < 5000; i++)
      pool.ipForHost(`h${i}.example`)
      // Force the exhaustion gate (private counter — test-only reach).
    ;(pool as unknown as { allocated: number }).allocated = 131071
    expect(pool.ipForHost('one-too-many.example')).toBeNull()
    // Existing mappings survive exhaustion untouched.
    expect(pool.ipForHost('first.example')).toBe(first)
    expect(pool.hostForIp(first)).toBe('first.example')
  })
})

describe('isFakePoolIp', () => {
  it('matches exactly 198.18.0.0/15', () => {
    expect(isFakePoolIp('198.18.0.1')).toBe(true)
    expect(isFakePoolIp('198.19.255.254')).toBe(true)
    expect(isFakePoolIp('198.17.255.255')).toBe(false)
    expect(isFakePoolIp('198.20.0.0')).toBe(false)
    expect(isFakePoolIp('not-an-ip')).toBe(false)
    expect(isFakePoolIp('::1')).toBe(false)
  })
})

describe('DNS codec', () => {
  it('parses an A query', () => {
    const q = parseDnsQuery(makeQuery('Example.Com', QTYPE_A))
    expect(q).not.toBeNull()
    expect(q!.id).toBe(0x1234)
    expect(q!.name).toBe('example.com')
    expect(q!.qtype).toBe(QTYPE_A)
    expect(q!.qclass).toBe(1)
  })

  it('builds an answer with the fake IP and echoes the question', () => {
    const raw = makeQuery('example.com', QTYPE_A)
    const q = parseDnsQuery(raw)!
    const resp = buildDnsResponse(q, '198.18.0.42')
    expect(resp.readUInt16BE(0)).toBe(0x1234) // id copied
    expect(resp.readUInt16BE(2) & 0x8000).toBe(0x8000) // QR
    expect(resp.readUInt16BE(2) & 0x0100).toBe(0x0100) // RD echoed
    expect(resp.readUInt16BE(2) & 0x000f).toBe(0) // NOERROR
    expect(resp.readUInt16BE(6)).toBe(1) // ANCOUNT
    // question echoed byte-for-byte
    expect(resp.subarray(12, 12 + q.questionBytes.length)).toEqual(
      q.questionBytes,
    )
    // answer: last 4 bytes are the IP
    expect([...resp.subarray(resp.length - 4)]).toEqual([198, 18, 0, 42])
  })

  it('returns empty NOERROR for AAAA', () => {
    const q = parseDnsQuery(makeQuery('example.com', QTYPE_AAAA))!
    const resp = buildDnsResponse(q, null)
    expect(resp.readUInt16BE(6)).toBe(0) // ANCOUNT 0
    expect(resp.readUInt16BE(2) & 0x000f).toBe(0) // NOERROR
  })

  it('rejects labels outside the LDH+underscore set (CRLF smuggling)', () => {
    // DNS labels are 8-bit clean on the wire; the stub must refuse bytes
    // that could later be interpolated into a CONNECT request line.
    const evil = makeQuery('safe.com', QTYPE_A)
    // Rewrite the first label ("safe") to contain CR/LF bytes.
    evil.write('a\r\nb', 13, 'latin1')
    expect(parseDnsQuery(evil)).toBeNull()
    const spaced = makeQuery('ok.com', QTYPE_A)
    spaced.write('a b', 13, 'latin1')
    expect(parseDnsQuery(spaced)).toBeNull()
    // Plain LDH names still parse.
    expect(
      parseDnsQuery(makeQuery('xn--bcher-kva.example', QTYPE_A)),
    ).not.toBeNull()
  })

  it('rejects malformed input', () => {
    expect(parseDnsQuery(Buffer.alloc(4))).toBeNull()
    // QR bit set (a response)
    expect(parseDnsQuery(makeQuery('x.com', QTYPE_A, 1, 0x8000))).toBeNull()
    // truncated name
    const truncated = makeQuery('example.com', QTYPE_A).subarray(0, 16)
    expect(parseDnsQuery(truncated)).toBeNull()
    // compression pointer in question
    const ptr = makeQuery('example.com', QTYPE_A)
    ptr[12] = 0xc0
    expect(parseDnsQuery(ptr)).toBeNull()
  })

  it('builds FORMERR with the original id', () => {
    const bad = Buffer.from([0xab, 0xcd, 0x01])
    const resp = buildDnsFormErr(bad)!
    expect(resp.readUInt16BE(0)).toBe(0xabcd)
    expect(resp.readUInt16BE(2) & 0x000f).toBe(1)
    expect(buildDnsFormErr(Buffer.alloc(1))).toBeNull()
  })
})

describe('DNS wire-limit and opcode gates', () => {
  function nameOf(totalLabelBytes: number): string {
    // Build labels of 63 chars until the target label-byte total
    // (each label costs len+1 wire bytes).
    const labels: string[] = []
    let wire = 0
    while (wire < totalLabelBytes) {
      const take = Math.min(63, totalLabelBytes - wire - 1)
      labels.push('a'.repeat(take))
      wire += take + 1
    }
    return labels.join('.')
  }

  it('accepts a 254-label-byte name and rejects one octet more', () => {
    const ok = parseDnsQuery(makeQuery(nameOf(254), QTYPE_A))
    expect(ok).not.toBeNull()
    const over = parseDnsQuery(makeQuery(nameOf(255), QTYPE_A))
    expect(over).toBeNull()
  })

  it('rejects non-QUERY opcodes (IQUERY, STATUS)', () => {
    for (const opcode of [1, 2]) {
      const q = makeQuery('opcode.test', QTYPE_A)
      q.writeUInt16BE(opcode << 11, 2)
      expect(parseDnsQuery(q)).toBeNull()
    }
  })
})

describe('DNS-over-TCP framing (pasta UDP-only regret — hard-close)', () => {
  function frame(payload: Buffer): Buffer {
    const out = Buffer.alloc(2 + payload.length)
    out.writeUInt16BE(payload.length, 0)
    payload.copy(out, 2)
    return out
  }

  it('reassembles frames split at every byte boundary', () => {
    const q = makeQuery('tcp-split.test', QTYPE_A)
    const wire = Buffer.concat([frame(q), frame(q)])
    for (let split = 1; split < wire.length; split++) {
      const r1 = extractDnsTcpFrames(wire.subarray(0, split))
      const r2 = extractDnsTcpFrames(
        Buffer.concat([r1.rest, wire.subarray(split)]),
      )
      expect(r1.frames.length + r2.frames.length).toBe(2)
      expect(r2.rest.length).toBe(0)
      for (const f of [...r1.frames, ...r2.frames]) {
        expect(f.equals(q)).toBe(true)
      }
    }
  })

  it('holds incomplete frames and zero-length prefixes safely', () => {
    expect(extractDnsTcpFrames(Buffer.from([0x00])).frames.length).toBe(0)
    const zero = extractDnsTcpFrames(Buffer.from([0x00, 0x00, 0x01]))
    expect(zero.frames.length).toBe(1) // zero-length frame extracted
    expect(zero.frames[0]!.length).toBe(0)
    expect(zero.rest.length).toBe(1)
  })
})

describe('fake-IP determinism', () => {
  it('maps the same hostname to the same fake IP across pool instances', () => {
    const a = new FakeIpPool()
    const b = new FakeIpPool()
    // Different query orders — mappings must still agree.
    const ipsA = ['example.com', 'api.test', 'registry.npmjs.org'].map(h =>
      a.ipForHost(h),
    )
    const ipsB = ['registry.npmjs.org', 'example.com', 'api.test'].map(h =>
      b.ipForHost(h),
    )
    expect(ipsA[0]).toBe(ipsB[1]!)
    expect(ipsA[1]).toBe(ipsB[2]!)
    expect(ipsA[2]).toBe(ipsB[0]!)
  })

  it('probes on collision without ever remapping within a pool', () => {
    const pool = new FakeIpPool()
    const seen = new Set<string>()
    for (let i = 0; i < 500; i++) {
      const ip = pool.ipForHost(`host-${i}.test`)!
      expect(seen.has(ip)).toBe(false)
      seen.add(ip)
      expect(pool.ipForHost(`host-${i}.test`)).toBe(ip)
    }
  })
})

describe('handleDnsQuery decision branches', () => {
  it('answers localhost with 127.0.0.1 (stays in-namespace)', () => {
    const pool = new FakeIpPool()
    const resp = handleDnsQuery(makeQuery('localhost', QTYPE_A), pool)!
    expect([...resp.subarray(resp.length - 4)]).toEqual([127, 0, 0, 1])
  })

  it('echoes IP-literal names back as themselves', () => {
    const pool = new FakeIpPool()
    const resp = handleDnsQuery(makeQuery('8.8.8.8', QTYPE_A), pool)!
    expect([...resp.subarray(resp.length - 4)]).toEqual([8, 8, 8, 8])
  })

  it('answers fake-pool IP-literal names empty (no slot aliasing)', () => {
    const pool = new FakeIpPool()
    const resp = handleDnsQuery(makeQuery('198.18.0.7', QTYPE_A), pool)!
    expect(resp.readUInt16BE(6)).toBe(0) // ANCOUNT 0
    expect(resp.readUInt16BE(2) & 0x000f).toBe(0) // NOERROR
  })

  it('drops QR=1 packets instead of answering FORMERR (no reply loop)', () => {
    const pool = new FakeIpPool()
    const response = makeQuery('x.com', QTYPE_A, 1, 0x8180)
    expect(handleDnsQuery(response, pool)).toBeNull()
  })

  it('answers FORMERR for non-response garbage', () => {
    const pool = new FakeIpPool()
    const resp = handleDnsQuery(Buffer.from([0xab, 0xcd, 0, 0, 0, 9]), pool)!
    expect(resp.readUInt16BE(2) & 0x000f).toBe(1) // FORMERR
  })
})

describe('isForwardableDestination', () => {
  it('refuses loopback and link-local (must never leave the namespace)', () => {
    expect(isForwardableDestination('127.0.0.1')).toBe(false)
    expect(isForwardableDestination('127.255.0.9')).toBe(false)
    expect(isForwardableDestination('::1')).toBe(false)
    expect(isForwardableDestination('169.254.169.254')).toBe(false)
    expect(isForwardableDestination('fe80::1')).toBe(false)
  })

  it('refuses unspecified, v4-compatible v6, broadcast, multicast', () => {
    // 0.0.0.0 (and `::`) dial HOST loopback when connect()ed host-side.
    expect(isForwardableDestination('0.0.0.0')).toBe(false)
    expect(isForwardableDestination('0.1.2.3')).toBe(false)
    expect(isForwardableDestination('::')).toBe(false)
    expect(isForwardableDestination('::7f00:1')).toBe(false) // ::127.0.0.1
    expect(isForwardableDestination('255.255.255.255')).toBe(false)
    expect(isForwardableDestination('224.0.0.1')).toBe(false)
    expect(isForwardableDestination('239.255.255.250')).toBe(false)
    expect(isForwardableDestination('ff02::1')).toBe(false)
  })

  it('allows ordinary destinations', () => {
    expect(isForwardableDestination('203.0.113.9')).toBe(true)
    expect(isForwardableDestination('10.1.2.3')).toBe(true)
    expect(isForwardableDestination('2001:db8::1')).toBe(true)
    expect(isForwardableDestination('223.255.255.1')).toBe(true) // not multicast
  })

  it('destroys deprecated site-local destinations', () => {
    expect(isForwardableDestination('fec0::1')).toBe(false) // fec0::/10
    expect(isForwardableDestination('feff::1')).toBe(false)
  })
})

describe('capture address handling', () => {
  it('strips the v4-mapped prefix', () => {
    expect(normalizeCaptureAddress('::ffff:198.18.0.5')).toBe('198.18.0.5')
    expect(normalizeCaptureAddress('198.18.0.5')).toBe('198.18.0.5')
    expect(normalizeCaptureAddress('2001:db8::1')).toBe('2001:db8::1')
  })

  it('brackets IPv6 CONNECT targets', () => {
    expect(formatConnectHost('example.com')).toBe('example.com')
    expect(formatConnectHost('2001:db8::1')).toBe('[2001:db8::1]')
  })
})

describe('CONNECT exchange', () => {
  it('builds the request the srt proxy expects', () => {
    const req = buildConnectRequest('example.com', 443, 'tok123')
    expect(req).toStartWith('CONNECT example.com:443 HTTP/1.1\r\n')
    expect(req).toContain('Host: example.com:443\r\n')
    const auth = Buffer.from('srt:tok123').toString('base64')
    expect(req).toContain(`Proxy-Authorization: Basic ${auth}\r\n`)
    expect(req).toEndWith('\r\n\r\n')
  })

  it('omits auth without a token', () => {
    expect(buildConnectRequest('h.com', 80, undefined)).not.toContain(
      'Proxy-Authorization',
    )
  })

  it('marks captured plaintext tunnels with the routing header', () => {
    expect(buildConnectRequest('h.com', 80, 'tok', true)).toContain(
      'X-SRT-Captured-Plaintext: 1\r\n',
    )
    expect(buildConnectRequest('h.com', 443, 'tok', false)).not.toContain(
      'X-SRT-Captured-Plaintext',
    )
    expect(buildConnectRequest('h.com', 443, 'tok')).not.toContain(
      'X-SRT-Captured-Plaintext',
    )
  })

  it('refuses hosts that could inject into the request line', () => {
    expect(() => buildConnectRequest('a\r\nX: y', 80, undefined)).toThrow()
    expect(() => buildConnectRequest('a b', 80, undefined)).toThrow()
  })

  it('parses proxy response heads', () => {
    expect(parseProxyResponseHead(Buffer.from('HTTP/1.1 200 Conn'))).toBeNull()
    const ok = parseProxyResponseHead(
      Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\nEXTRA'),
    )!
    expect(ok.statusCode).toBe(200)
    expect(ok.headLength).toBe(
      'HTTP/1.1 200 Connection Established\r\n\r\n'.length,
    )
    const denied = parseProxyResponseHead(
      Buffer.from('HTTP/1.1 403 Forbidden\r\nX: y\r\n\r\n'),
    )!
    expect(denied.statusCode).toBe(403)
    expect(() =>
      parseProxyResponseHead(Buffer.from('garbage\r\n\r\n')),
    ).toThrow()
  })
})

describe('parseBridgeSpec', () => {
  it('parses unix and tcp forms', () => {
    expect(parseBridgeSpec('unix:/tmp/x.sock')).toEqual({
      kind: 'unix',
      path: '/tmp/x.sock',
    })
    expect(parseBridgeSpec('tcp:127.0.0.1:18080')).toEqual({
      kind: 'tcp',
      host: '127.0.0.1',
      port: 18080,
    })
    expect(() => parseBridgeSpec('bogus')).toThrow()
    expect(() => parseBridgeSpec('tcp:nohost')).toThrow()
  })
})
