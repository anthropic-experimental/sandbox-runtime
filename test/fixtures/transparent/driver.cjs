// In-sandbox e2e driver for transparent networking.
//
// Runs inside bwrap's netns. The netns is configured by the TEST process
// (the host) via netns-config --pid: the driver writes its netns inode to
// SRT_TP_RDV_DIR/inode and waits for SRT_TP_RDV_DIR/done — a file-based
// stand-in for the production rendezvous, whose unix-socket form needs
// AF_UNIX listeners some dev sandboxes deny (CI integration covers it).
// The helper's OWN hello is served by a local TCP stub that answers OK
// (the configuration already happened), so the helper's rendezvous code
// path still runs.
//
// Then stands in for the host-side proxy with a tiny CONNECT server on
// 127.0.0.1:18080 — every tunnel gets a canned HTTP response naming the
// CONNECT target, so the test can assert exactly what destination the
// helper recovered — and launches the real transparent-net-helper with
// the client as its child command.
//
// Env:
//   SRT_TP_HELPER   path to transparent-net-helper (.ts under bun, .js under node)
//   SRT_TP_CLIENT   path to client.cjs
//   SRT_TP_URL      URL the client should fetch
//   SRT_TP_RDV_DIR  shared dir for the inode/done file handshake
'use strict'
const net = require('net')
const fs = require('fs')
const path = require('path')
const { spawn } = require('child_process')

const PROXY_PORT = 18080
const RDV_PORT = 18099
const TOKEN = 'e2e-test-token'

// ---- host netns-configuration handshake (before anything binds) ----
const rdvDir = process.env.SRT_TP_RDV_DIR
const inode = /^net:\[(\d+)\]$/.exec(
  fs.readlinkSync('/proc/self/ns/net'),
)[1]
fs.writeFileSync(path.join(rdvDir, 'inode'), inode)
const deadline = Date.now() + 10000
while (!fs.existsSync(path.join(rdvDir, 'done'))) {
  if (Date.now() > deadline) {
    console.error('DRIVER-ERR netns configuration handshake timed out')
    process.exit(3)
  }
  // sleepSync via Atomics — no busy spin
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50)
}

// The helper's rendezvous stub: reads the hello line, answers OK (the
// test already configured this netns).
const rdvStub = net.createServer(sock => {
  sock.on('error', () => {})
  sock.on('data', () => sock.end('OK\n'))
})

// allowHalfOpen matches the real srt proxy (http.Server sockets allow
// half-open): a client FIN after the request must not kill the response.
const proxy = net.createServer({ allowHalfOpen: true }, sock => {
  let buf = Buffer.alloc(0)
  let target = null
  let authUser = ''
  let capturedFlag = 0
  sock.on('error', () => {})
  sock.on('data', chunk => {
    buf = Buffer.concat([buf, chunk])
    if (!target) {
      const i = buf.indexOf('\r\n\r\n')
      if (i === -1) return
      const head = buf.subarray(0, i).toString()
      const m = /^CONNECT (\S+) HTTP\/1\.1/.exec(head)
      if (!m) {
        sock.end('HTTP/1.1 400 Bad Request\r\n\r\n')
        return
      }
      const auth = /Proxy-Authorization: Basic (\S+)/i.exec(head)
      authUser = auth ? Buffer.from(auth[1], 'base64').toString() : '(none)'
      capturedFlag = /X-SRT-Captured-Plaintext: 1/i.test(head) ? 1 : 0
      target = m[1]
      buf = buf.subarray(i + 4)
      if (/^refused\.test:/.test(target)) {
        // Exercise the helper's non-200 abort path.
        sock.end('HTTP/1.1 403 Forbidden\r\n\r\n')
        return
      }
      sock.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    }
    // Wait for the tunnelled plain-HTTP request, then answer it.
    if (target && buf.indexOf('\r\n\r\n') !== -1) {
      const body = `tunnel-ok target=${target} auth=${authUser} cp=${capturedFlag}`
      sock.end(
        `HTTP/1.1 200 OK\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`,
      )
    }
  })
})

rdvStub.listen(RDV_PORT, '127.0.0.1', () => {
  proxy.listen(PROXY_PORT, '127.0.0.1', () => {
    const child = spawn(
      process.execPath,
      [
        process.env.SRT_TP_HELPER,
        '--',
        process.execPath,
        process.env.SRT_TP_CLIENT,
        process.env.SRT_TP_URL,
      ],
      {
        stdio: 'inherit',
        env: {
          ...process.env,
          SRT_TP_BRIDGE: `tcp:127.0.0.1:${PROXY_PORT}`,
          SRT_TP_NETNS: `tcp:127.0.0.1:${RDV_PORT}`,
          SRT_TP_NETNS_TOKEN: 'e2e-netns-token',
          SRT_TP_PORTS: '80,443',
          SRT_TP_TOKEN: TOKEN,
        },
      },
    )
    child.on('exit', code => process.exit(code ?? 1))
  })
})
