import { afterEach, beforeEach, describe, expect, it } from 'bun:test'
import {
  createServer as createTcpServer,
  connect,
  type Server,
  type Socket,
} from 'node:net'
import { createSocksProxyServer } from '../../src/sandbox/socks-proxy.js'
import type { SocksProxyWrapper } from '../../src/sandbox/socks-proxy.js'

const TOKEN = 'a'.repeat(32)

/** Echo server standing in for the destination. */
function startEchoServer(): Promise<{ server: Server; port: number }> {
  return new Promise(resolve => {
    const server = createTcpServer(socket => socket.pipe(socket))
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address()
      resolve({
        server,
        port: addr && typeof addr === 'object' ? addr.port : 0,
      })
    })
  })
}

function greeting(...methods: number[]): Buffer {
  return Buffer.from([0x05, methods.length, ...methods])
}

function userPass(username: string, password: string): Buffer {
  return Buffer.from([
    0x01,
    username.length,
    ...Buffer.from(username),
    password.length,
    ...Buffer.from(password),
  ])
}

function connectRequest(host: string, port: number): Buffer {
  const hostBytes = Buffer.from(host)
  const head = Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length])
  const portBytes = Buffer.alloc(2)
  portBytes.writeUInt16BE(port)
  return Buffer.concat([head, hostBytes, portBytes])
}

/** Read exactly n bytes from the socket. */
function readN(socket: Socket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    const onData = (c: Buffer): void => {
      chunks.push(c)
      total += c.length
      if (total >= n) {
        socket.removeListener('data', onData)
        const all = Buffer.concat(chunks)
        if (all.length > n) socket.unshift(all.subarray(n))
        resolve(all.subarray(0, n))
      }
    }
    socket.on('data', onData)
    socket.once('close', () =>
      reject(new Error(`socket closed after ${total}/${n} bytes`)),
    )
    socket.once('error', reject)
  })
}

function waitClose(socket: Socket): Promise<void> {
  return new Promise(resolve => socket.once('close', () => resolve()))
}

describe('SOCKS destination-token auth', () => {
  let proxy: SocksProxyWrapper
  let listener: Server
  let proxyPort: number
  let echo: { server: Server; port: number }
  let filterCalls: Array<{ port: number; host: string }>

  beforeEach(async () => {
    echo = await startEchoServer()
    filterCalls = []
    proxy = createSocksProxyServer({
      filter: (port, host) => {
        filterCalls.push({ port, host })
        return host === '127.0.0.1'
      },
      proxyAuthToken: TOKEN,
    })
    listener = createTcpServer(s => proxy.handleConnection(s))
    await new Promise<void>(resolve =>
      listener.listen(0, '127.0.0.1', () => resolve()),
    )
    const addr = listener.address()
    proxyPort = addr && typeof addr === 'object' ? addr.port : 0
  })

  afterEach(async () => {
    await proxy.close()
    await new Promise<void>(resolve => listener.close(() => resolve()))
    await new Promise<void>(resolve => echo.server.close(() => resolve()))
  })

  function dial(): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const s = connect(proxyPort, '127.0.0.1', () => resolve(s))
      s.once('error', reject)
    })
  }

  it('no-auth client with token-prefixed destination tunnels (the nc/git-over-ssh path)', async () => {
    const client = await dial()
    client.write(greeting(0x00))
    expect([...(await readN(client, 2))]).toEqual([0x05, 0x00])
    client.write(connectRequest(`${TOKEN}.127.0.0.1`, echo.port))
    const reply = await readN(client, 10)
    expect(reply[1]).toBe(0x00) // succeeded
    client.write('ssh banner')
    const echoed = await readN(client, 'ssh banner'.length)
    expect(echoed.toString()).toBe('ssh banner')
    // The filter saw the STRIPPED host — the token never reaches the
    // allowlist matcher.
    expect(filterCalls).toEqual([{ port: echo.port, host: '127.0.0.1' }])
    client.destroy()
  })

  it('no-auth client without the prefix is refused before filtering', async () => {
    const client = await dial()
    client.write(greeting(0x00))
    await readN(client, 2)
    client.write(connectRequest('127.0.0.1', echo.port))
    const reply = await readN(client, 10)
    expect(reply[1]).toBe(0x02) // connection not allowed
    await waitClose(client)
    expect(filterCalls).toEqual([])
  })

  it('no-auth client with a WRONG token prefix is refused, not dialed with the prefix stripped', async () => {
    const client = await dial()
    client.write(greeting(0x00))
    await readN(client, 2)
    client.write(connectRequest(`${'b'.repeat(32)}.127.0.0.1`, echo.port))
    const reply = await readN(client, 10)
    expect(reply[1]).toBe(0x02)
    await waitClose(client)
    expect(filterCalls).toEqual([])
  })

  it('username/password client authenticates and needs no prefix (curl/FTP path)', async () => {
    const client = await dial()
    client.write(greeting(0x00, 0x02))
    expect([...(await readN(client, 2))]).toEqual([0x05, 0x02])
    client.write(userPass('srt', TOKEN))
    expect([...(await readN(client, 2))]).toEqual([0x01, 0x00])
    client.write(connectRequest('127.0.0.1', echo.port))
    const reply = await readN(client, 10)
    expect(reply[1]).toBe(0x00)
    client.write('ftp data')
    expect((await readN(client, 'ftp data'.length)).toString()).toBe('ftp data')
    expect(filterCalls).toEqual([{ port: echo.port, host: '127.0.0.1' }])
    client.destroy()
  })

  it('wrong password is rejected at sub-negotiation', async () => {
    const client = await dial()
    client.write(greeting(0x02))
    await readN(client, 2)
    client.write(userPass('srt', 'wrong'))
    const reply = await readN(client, 2)
    expect([...reply]).toEqual([0x01, 0x01])
    await waitClose(client)
    expect(filterCalls).toEqual([])
  })

  it('an authed client dialing a destination that happens to start with the token is NOT stripped', async () => {
    const client = await dial()
    client.write(greeting(0x02))
    await readN(client, 2)
    client.write(userPass('srt', TOKEN))
    await readN(client, 2)
    client.write(connectRequest(`${TOKEN}.example.com`, 443))
    const reply = await readN(client, 10)
    expect(reply[1]).toBe(0x02) // filter denied the literal host
    expect(filterCalls).toEqual([{ port: 443, host: `${TOKEN}.example.com` }])
  })

  it('filter denial after a valid prefix still refuses', async () => {
    const client = await dial()
    client.write(greeting(0x00))
    await readN(client, 2)
    client.write(connectRequest(`${TOKEN}.evil.example`, 22))
    const reply = await readN(client, 10)
    expect(reply[1]).toBe(0x02)
    expect(filterCalls).toEqual([{ port: 22, host: 'evil.example' }])
  })

  it('with no token configured, no-auth connections pass straight to the filter', async () => {
    const open = createSocksProxyServer({
      filter: (port, host) => {
        filterCalls.push({ port, host })
        return host === '127.0.0.1'
      },
    })
    const srv = createTcpServer(s => open.handleConnection(s))
    await new Promise<void>(resolve =>
      srv.listen(0, '127.0.0.1', () => resolve()),
    )
    const addr = srv.address()
    const port = addr && typeof addr === 'object' ? addr.port : 0
    const client = await new Promise<Socket>((resolve, reject) => {
      const s = connect(port, '127.0.0.1', () => resolve(s))
      s.once('error', reject)
    })
    client.write(greeting(0x00))
    expect([...(await readN(client, 2))]).toEqual([0x05, 0x00])
    client.write(connectRequest('127.0.0.1', echo.port))
    const reply = await readN(client, 10)
    expect(reply[1]).toBe(0x00)
    client.destroy()
    await open.close()
    await new Promise<void>(resolve => srv.close(() => resolve()))
  })

  it('rejects a client offering no acceptable method', async () => {
    const client = await dial()
    client.write(Buffer.from([0x05, 0x01, 0x01])) // GSSAPI only
    const reply = await readN(client, 2)
    expect([...reply]).toEqual([0x05, 0xff])
    await waitClose(client)
  })

  it('destroys non-SOCKS5 clients', async () => {
    const client = await dial()
    client.write(Buffer.from([0x04, 0x01]))
    await waitClose(client)
  })

  // --- TCP framing: the parser must be indifferent to how the kernel
  // chunks the byte stream. These two tests pin the extremes; everything
  // real lands in between.

  it('handles the entire handshake drip-fed one byte per write', async () => {
    const client = await dial()
    // Collector attached BEFORE any reply can arrive: replies land
    // interleaved with our writes here, and Bun sockets drop segments that
    // arrive while no 'data' listener exists (readN-after-write is safe in
    // the other tests only because they attach in the same tick as the
    // write).
    const collected: Buffer[] = []
    client.on('data', c => collected.push(c))
    const full = Buffer.concat([
      greeting(0x00),
      connectRequest(`${TOKEN}.127.0.0.1`, echo.port),
    ])
    for (const byte of full) {
      client.write(Buffer.from([byte]))
      // Yield so each byte arrives as its own data event.
      await new Promise(resolve => setTimeout(resolve, 0))
    }
    client.write('drip')
    const want = 2 + 10 + 'drip'.length
    const deadline = Date.now() + 4000
    while (Buffer.concat(collected).length < want && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 5))
    }
    const all = Buffer.concat(collected)
    expect([...all.subarray(0, 2)]).toEqual([0x05, 0x00]) // greeting reply
    expect(all[3]).toBe(0x00) // request reply REP byte
    expect(all.subarray(12).toString()).toBe('drip') // echoed payload
    client.destroy()
  })

  it('handles the entire handshake plus payload coalesced into one write', async () => {
    const client = await dial()
    client.write(
      Buffer.concat([
        greeting(0x00),
        connectRequest(`${TOKEN}.127.0.0.1`, echo.port),
        Buffer.from('early payload'),
      ]),
    )
    const replies = await readN(client, 12)
    expect([...replies.subarray(0, 2)]).toEqual([0x05, 0x00])
    expect(replies[3]).toBe(0x00)
    // The payload bytes that rode in with the handshake must reach the
    // destination, not be swallowed by the parser.
    expect((await readN(client, 'early payload'.length)).toString()).toBe(
      'early payload',
    )
    client.destroy()
  })

  it('never grants a tunnel on random garbage (fuzz)', async () => {
    // Random byte salads must end in refusal or teardown — never in a
    // REPLY_SUCCEEDED and never in a filter call that could dial out.
    // Seeded LCG so a failure is reproducible from the log line.
    let seed = 0x2f6e2b1
    const rand = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff
      return seed
    }
    for (let i = 0; i < 200; i++) {
      const len = (rand() % 64) + 1
      const bytes = Buffer.alloc(len)
      for (let j = 0; j < len; j++) bytes[j] = rand() % 256
      // Half the runs start with a valid-looking greeting so the fuzz
      // reaches the request parser instead of dying at the version byte.
      const payload =
        i % 2 === 0 ? bytes : Buffer.concat([greeting(0x00), bytes])
      const client = await dial()
      const received: Buffer[] = []
      client.on('data', c => received.push(c))
      client.write(payload)
      client.end()
      await waitClose(client)
      const all = Buffer.concat(received)
      // Scan every reply-shaped position: no REPLY_SUCCEEDED may appear.
      for (let j = 0; j + 1 < all.length; j += 2) {
        if (all[j] === 0x05 && j > 0) {
          expect(all[j + 1]).not.toBe(0x00 /* REPLY_SUCCEEDED */)
        }
      }
    }
    // The filter only ever saw hosts that survived the token gate — and
    // random bytes cannot contain the 33-byte prefix.
    expect(filterCalls).toEqual([])
  }, 20_000)
})
