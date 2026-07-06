// Half-closing client: sends its request, immediately FINs the write side
// (like `nc -N` / shutdown(SHUT_WR) protocols), then still expects the
// full response on the read side. Exercises allowHalfOpen handling in the
// transparent capture path — including the FIN-before-tunnel-established
// race.
'use strict'
const net = require('net')
const { URL } = require('url')

const u = new URL(process.argv[2])
const sock = net.connect({ host: u.hostname, port: Number(u.port || 80) })
let body = ''
sock.on('connect', () => {
  sock.write(`GET ${u.pathname} HTTP/1.0\r\nHost: ${u.hostname}\r\n\r\n`)
  sock.end() // FIN right behind the request
})
sock.on('data', d => (body += d))
sock.on('end', () => {
  console.log(`CLIENT-OK halfclose body=${body.slice(body.indexOf('\r\n\r\n') + 4)}`)
  process.exit(0)
})
sock.on('error', e => {
  console.error(`CLIENT-ERR ${e.code ?? ''} ${e.message}`)
  process.exit(1)
})
setTimeout(() => {
  console.error('CLIENT-TIMEOUT')
  process.exit(2)
}, 15000).unref?.()
