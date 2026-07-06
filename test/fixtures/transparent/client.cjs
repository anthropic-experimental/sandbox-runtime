// Proxy-UNAWARE HTTP(S) client — exactly the client class transparent mode
// exists for. node's http/https.get ignores proxy env vars, but bun's
// implementation honors them, so strip them up front to force a direct
// dial under either runtime. Prints `CLIENT-OK ...` on success.
'use strict'
for (const k of Object.keys(process.env)) {
  if (/^(https?_proxy|all_proxy|no_proxy)$/i.test(k)) delete process.env[k]
}
const url = process.argv[2]
const mod = url.startsWith('https:') ? require('https') : require('http')

const req = mod.get(url, res => {
  let body = ''
  res.on('data', d => (body += d))
  res.on('end', () => {
    console.log(`CLIENT-OK status=${res.statusCode} body=${body.slice(0, 200)}`)
    process.exit(0)
  })
})
req.on('error', e => {
  console.error(`CLIENT-ERR ${e.code ?? ''} ${e.message}`)
  process.exit(1)
})
setTimeout(() => {
  console.error('CLIENT-TIMEOUT')
  process.exit(2)
}, 15000).unref?.()
