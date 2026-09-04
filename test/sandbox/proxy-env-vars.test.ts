import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { createServer } from 'node:http'
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  generateProxyEnvVars,
  CA_TRUST_VARS,
} from '../../src/sandbox/sandbox-utils.js'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { spawnAsync } from '../helpers/spawn.js'
import { isLinux } from '../helpers/platform.js'
import * as platform from '../../src/utils/platform.js'

describe('generateProxyEnvVars', () => {
  it('sets CLOUDSDK_PROXY_TYPE to http (gcloud rejects "https")', () => {
    // gcloud's proxy/type only accepts http, http_no_tunnel, socks4, socks5.
    // Our local proxy is an HTTP CONNECT proxy regardless of the traffic it
    // tunnels, so the value must be "http" — see issue #151.
    const env = generateProxyEnvVars(3128, 1080)

    expect(env).toContain('CLOUDSDK_PROXY_TYPE=http')
    expect(env).toContain('CLOUDSDK_PROXY_ADDRESS=localhost')
    expect(env).toContain('CLOUDSDK_PROXY_PORT=3128')
    expect(env).not.toContain('CLOUDSDK_PROXY_TYPE=https')
  })

  it('omits CLOUDSDK_PROXY_* when no HTTP proxy port is configured', () => {
    const env = generateProxyEnvVars(undefined, 1080)

    expect(env.some(v => v.startsWith('CLOUDSDK_PROXY_'))).toBe(false)
  })

  describe('GRPC_PROXY', () => {
    const grpcNames = ['GRPC_PROXY', 'grpc_proxy']

    it('advertises the HTTP CONNECT proxy, and never SOCKS alongside it', () => {
      // gRPC C-core rejects socks5h:// ("scheme not supported in proxy URI"),
      // ignores the var, and resolves directly via c-ares — which the sandbox
      // blocks. It must get an http:// URL, and must not also get a socks one:
      // two values for the same var in the child env is a coin flip.
      const env = generateProxyEnvVars(3128, 1080)

      for (const name of grpcNames) {
        expect(env).toContain(`${name}=http://localhost:3128`)
        expect(env.filter(v => v.startsWith(`${name}=`))).toHaveLength(1)
      }
    })

    it('carries proxy credentials in the URL', () => {
      const env = generateProxyEnvVars(3128, 1080, undefined, 'tok')

      for (const name of grpcNames) {
        expect(env).toContain(`${name}=http://srt:tok@localhost:3128`)
      }
    })

    it('is emitted when only an HTTP proxy port is configured', () => {
      // The value does not depend on the SOCKS port, and a gRPC client in an
      // HTTP-only sandbox needs it just as much.
      const env = generateProxyEnvVars(3128, undefined)

      for (const name of grpcNames) {
        expect(env).toContain(`${name}=http://localhost:3128`)
      }
    })

    it('falls back to SOCKS when no HTTP proxy port is configured', () => {
      const env = generateProxyEnvVars(undefined, 1080)

      for (const name of grpcNames) {
        expect(env).toContain(`${name}=socks5h://localhost:1080`)
      }
    })
  })

  describe('caCertPath', () => {
    it('sets all trust env vars to the CA path when provided', () => {
      const env = generateProxyEnvVars(3128, 1080, '/etc/srt/ca.crt')
      for (const v of CA_TRUST_VARS) {
        expect(env).toContain(`${v}=/etc/srt/ca.crt`)
      }
    })

    it('sets trust env vars even when no proxy ports are configured', () => {
      // tlsTerminate implies network restriction in practice, but the env-var
      // helper should not couple the two.
      const env = generateProxyEnvVars(undefined, undefined, '/etc/srt/ca.crt')
      for (const v of CA_TRUST_VARS) {
        expect(env).toContain(`${v}=/etc/srt/ca.crt`)
      }
    })

    it('omits trust env vars when caCertPath is not provided', () => {
      const env = generateProxyEnvVars(3128, 1080)
      for (const v of CA_TRUST_VARS) {
        expect(env.some(e => e.startsWith(`${v}=`))).toBe(false)
      }
    })
  })

  describe('GIT_SSH_COMMAND on macOS', () => {
    // Regression for anthropics/claude-code#70684. BSD nc speaks SOCKS5 but
    // has no authentication of any kind, so `nc -X 5` cannot reach a proxy
    // that requires a credential — every sandboxed git-over-ssh operation
    // died at the handshake. When a token is set, macOS uses HTTP CONNECT
    // with a Basic header instead, the same transport Linux already uses.
    let platformSpy: ReturnType<typeof spyOn>

    beforeEach(() => {
      platformSpy = spyOn(platform, 'getPlatform')
      platformSpy.mockReturnValue('macos')
    })
    afterEach(() => platformSpy.mockRestore())

    const sshCommand = (...args: Parameters<typeof generateProxyEnvVars>) =>
      generateProxyEnvVars(...args).find(v =>
        v.startsWith('GIT_SSH_COMMAND='),
      )!

    it('authenticates via HTTP CONNECT when a proxy auth token is set', () => {
      const cmd = sshCommand(3128, 1080, undefined, 'deadbeef')
      const cred = Buffer.from('srt:deadbeef').toString('base64')

      expect(cmd).toContain('CONNECT %h:%p HTTP/1.1')
      expect(cmd).toContain(`Proxy-Authorization: Basic ${cred}`)
      // CONNECT is the HTTP proxy's port, not the SOCKS one.
      expect(cmd).toContain('/usr/bin/nc 127.0.0.1 3128')
      expect(cmd).not.toContain('nc -X 5')
    })

    it('keeps the SOCKS form when no token is set', () => {
      // An externally-configured proxy handles its own auth, so unadorned
      // `nc -X 5` is correct there and needs no shell wrapper.
      const cmd = sshCommand(3128, 1080)

      expect(cmd).toContain('nc -X 5 -x localhost:1080')
      expect(cmd).not.toContain('CONNECT')
    })

    it('carries the encoded command in the Basic username', () => {
      // The proxy decodes this suffix to attribute a denial to the specific
      // invocation that caused it (see encodedCommandFromProxyUser).
      const cmd = sshCommand(3128, 1080, undefined, 'deadbeef', undefined, 'YWJj')
      const cred = Buffer.from('srt.YWJj:deadbeef').toString('base64')

      expect(cmd).toContain(`Proxy-Authorization: Basic ${cred}`)
    })

    it('dials 127.0.0.1 rather than localhost', () => {
      // The mux binds 127.0.0.1; a client that resolves localhost to ::1
      // first gets ECONNREFUSED.
      const cmd = sshCommand(3128, 1080, undefined, 'deadbeef')

      expect(cmd).not.toContain('localhost')
    })

    it('pins absolute paths for the shell and netcat', () => {
      // PATH inside the sandbox is the user's own and may shadow either.
      const cmd = sshCommand(3128, 1080, undefined, 'deadbeef')

      expect(cmd).toContain('/bin/sh -c')
      expect(cmd).toContain('/usr/bin/nc')
    })

    it('closes its copy of stdout so a refused CONNECT reaches ssh as EOF', () => {
      // Without this the shell keeps ssh's stdout pipe open after nc exits,
      // and ssh hangs forever instead of reporting the failure.
      const cmd = sshCommand(3128, 1080, undefined, 'deadbeef')

      expect(cmd).toContain('& exec 1>&- 3<&-; wait')
    })

    it('reads ssh stdin from a saved descriptor', () => {
      // POSIX gives a background command stdin from /dev/null (dash and
      // /bin/sh do this); saving fd 0 first makes the rule irrelevant.
      const cmd = sshCommand(3128, 1080, undefined, 'deadbeef')

      expect(cmd).toContain('exec 3<&0;')
      expect(cmd).toContain('cat <&3')
    })
  })

  describe('NO_PROXY', () => {
    it('does not exclude .local hostnames from the proxy', () => {
      // Under network restriction the child has no usable resolver, so a
      // NO_PROXY match on *.local makes clients attempt direct getaddrinfo()
      // and fail before any request is sent. .local must go through the
      // proxy so the parent resolves it (e.g. k8s *.svc.cluster.local).
      const env = generateProxyEnvVars(3128, 1080)
      for (const name of ['NO_PROXY', 'no_proxy']) {
        const entry = env.find(e => e.startsWith(`${name}=`))
        expect(entry).toBeDefined()
        const tokens = entry!.slice(name.length + 1).split(',')
        expect(tokens).not.toContain('.local')
        expect(tokens).not.toContain('*.local')
      }
    })

    it.if(isLinux)(
      'sandboxed curl to a .local hostname reaches the parent proxy',
      async () => {
        let proxy: Server | undefined
        const received: string[] = []
        try {
          proxy = createServer((req, res) => {
            received.push(req.url ?? '')
            res.writeHead(200)
            res.end('ok')
          })
          proxy.on('connect', (req, sock) => {
            received.push(req.url ?? '')
            sock.end('HTTP/1.1 200 OK\r\n\r\n')
          })
          const proxyPort = await new Promise<number>((resolve, reject) => {
            proxy!.on('error', reject)
            proxy!.listen(0, '127.0.0.1', () =>
              resolve((proxy!.address() as AddressInfo).port),
            )
          })

          const config: SandboxRuntimeConfig = {
            network: {
              allowedDomains: ['srt-test.local'],
              deniedDomains: [],
              httpProxyPort: proxyPort,
            },
            filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
          }
          await SandboxManager.initialize(config)
          expect(SandboxManager.getProxyPort()).toBe(proxyPort)

          const wrapped = await SandboxManager.wrapWithSandbox(
            'curl -s --max-time 5 http://srt-test.local:8080/',
          )
          const result = await spawnAsync(wrapped, {
            shell: true,
            encoding: 'utf8',
            timeout: 10000,
          })

          expect(result.status).toBe(0)
          // Plain HTTP via proxy → absolute-form request line.
          expect(received).toContain('http://srt-test.local:8080/')
        } finally {
          await SandboxManager.reset()
          if (proxy) {
            await new Promise<void>(r => proxy!.close(() => r()))
          }
        }
      },
    )
  })
})
