import { describe, it, expect, afterAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import * as http from 'node:http'
import * as net from 'node:net'
import { SandboxManager } from '../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../src/sandbox/sandbox-config.js'
import { getPlatform } from '../src/utils/platform.js'
import { generateProxyEnvVars } from '../src/sandbox/sandbox-utils.js'

/**
 * Integration tests for configurable proxy ports feature
 * Tests that external proxy ports can be specified in config,
 * and that the library skips starting proxies when external ports are provided
 */
describe('Configurable Proxy Ports Integration Tests', () => {
  afterAll(async () => {
    // Always reset after tests
    await SandboxManager.reset()
  })

  describe('External HTTP proxy + local SOCKS', () => {
    it('should use external HTTP proxy when httpProxyPort is provided', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          httpProxyPort: 8888, // External HTTP proxy
          // socksProxyPort not specified - should start locally
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config)

      // Verify HTTP proxy port matches what was configured
      const httpProxyPort = SandboxManager.getProxyPort()
      expect(httpProxyPort).toBe(8888)

      // SOCKS proxy should have been started locally with dynamic port
      const socksProxyPort = SandboxManager.getSocksProxyPort()
      expect(socksProxyPort).toBeDefined()
      expect(socksProxyPort).not.toBe(8888)
      expect(socksProxyPort).toBeGreaterThan(0)

      await SandboxManager.reset()
    })
  })

  describe('External SOCKS proxy + local HTTP', () => {
    it('should use external SOCKS proxy when socksProxyPort is provided', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          // httpProxyPort not specified - should start locally
          socksProxyPort: 1080, // External SOCKS proxy
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config)

      // Verify SOCKS proxy port matches what was configured
      const socksProxyPort = SandboxManager.getSocksProxyPort()
      expect(socksProxyPort).toBe(1080)

      // HTTP proxy should have been started locally with dynamic port
      const httpProxyPort = SandboxManager.getProxyPort()
      expect(httpProxyPort).toBeDefined()
      expect(httpProxyPort).not.toBe(1080)
      expect(httpProxyPort).toBeGreaterThan(0)

      await SandboxManager.reset()
    })
  })

  describe('Both external proxies', () => {
    it('should use both external proxies when both ports are provided', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          httpProxyPort: 9090, // External HTTP proxy
          socksProxyPort: 9091, // External SOCKS proxy
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config)

      // Verify both proxy ports match what was configured
      const httpProxyPort = SandboxManager.getProxyPort()
      expect(httpProxyPort).toBe(9090)

      const socksProxyPort = SandboxManager.getSocksProxyPort()
      expect(socksProxyPort).toBe(9091)

      await SandboxManager.reset()
    })
  })

  describe('Both local proxies (baseline)', () => {
    it('should start both proxies locally when no ports are configured', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          // No httpProxyPort or socksProxyPort - both should start locally
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config)

      // Both proxies should have been started locally with dynamic ports
      const httpProxyPort = SandboxManager.getProxyPort()
      expect(httpProxyPort).toBeDefined()
      expect(httpProxyPort).toBeGreaterThan(0)
      expect(httpProxyPort).toBeLessThan(65536)

      const socksProxyPort = SandboxManager.getSocksProxyPort()
      expect(socksProxyPort).toBeDefined()
      expect(socksProxyPort).toBeGreaterThan(0)
      expect(socksProxyPort).toBeLessThan(65536)

      // Should be different ports
      expect(httpProxyPort).not.toBe(socksProxyPort)

      await SandboxManager.reset()
    })
  })

  describe('Multiple initialize/reset cycles', () => {
    it('should handle multiple initialize and reset cycles with different configs', async () => {
      // First: both local
      const config1: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config1)
      const httpPort1 = SandboxManager.getProxyPort()
      const socksPort1 = SandboxManager.getSocksProxyPort()
      expect(httpPort1).toBeDefined()
      expect(socksPort1).toBeDefined()
      await SandboxManager.reset()

      // Second: both external
      const config2: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          httpProxyPort: 7777,
          socksProxyPort: 7778,
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config2)
      expect(SandboxManager.getProxyPort()).toBe(7777)
      expect(SandboxManager.getSocksProxyPort()).toBe(7778)
      await SandboxManager.reset()

      // Third: mixed (external HTTP, local SOCKS)
      const config3: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          httpProxyPort: 6666,
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config3)
      expect(SandboxManager.getProxyPort()).toBe(6666)
      const socksPort3 = SandboxManager.getSocksProxyPort()
      expect(socksPort3).toBeDefined()
      expect(socksPort3).not.toBe(6666)
      await SandboxManager.reset()
    })
  })

  describe('Port validation', () => {
    it('should accept valid port numbers (1-65535)', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          httpProxyPort: 1,
          socksProxyPort: 65535,
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config)
      expect(SandboxManager.getProxyPort()).toBe(1)
      expect(SandboxManager.getSocksProxyPort()).toBe(65535)
      await SandboxManager.reset()
    })

    it('should accept standard proxy ports', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          httpProxyPort: 3128, // Standard HTTP proxy port
          socksProxyPort: 1080, // Standard SOCKS proxy port
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      await SandboxManager.initialize(config)
      expect(SandboxManager.getProxyPort()).toBe(3128)
      expect(SandboxManager.getSocksProxyPort()).toBe(1080)
      await SandboxManager.reset()
    })
  })

  describe('Idempotent initialization', () => {
    it('should handle calling initialize multiple times without reset', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
          httpProxyPort: 5555,
          socksProxyPort: 5556,
        },
        filesystem: {
          denyRead: [],
          allowWrite: [],
          denyWrite: [],
        },
      }

      // Initialize once
      await SandboxManager.initialize(config)
      const httpPort1 = SandboxManager.getProxyPort()
      const socksPort1 = SandboxManager.getSocksProxyPort()

      // Initialize again without reset (should be idempotent)
      await SandboxManager.initialize(config)
      const httpPort2 = SandboxManager.getProxyPort()
      const socksPort2 = SandboxManager.getSocksProxyPort()

      // Should return the same ports
      expect(httpPort2).toBe(httpPort1)
      expect(socksPort2).toBe(socksPort1)
      expect(httpPort2).toBe(5555)
      expect(socksPort2).toBe(5556)

      await SandboxManager.reset()
    })
  })

  describe('End-to-end: External proxy actually handles requests', () => {
    it('should route requests through external allow-all proxy, bypassing SRT filtering', async () => {
      // Skip if not on Linux (where we have full sandbox integration)
      if (getPlatform() !== 'linux') {
        console.log('Skipping end-to-end test on non-Linux platform')
        return
      }

      // Create a simple HTTP CONNECT proxy that allows ALL connections (no filtering)
      let externalProxyServer: http.Server | undefined
      let externalProxyPort: number | undefined

      try {
        externalProxyServer = http.createServer()

        // Handle HTTP CONNECT method for HTTPS tunneling
        externalProxyServer.on('connect', (req, clientSocket, head) => {
          const { port, hostname } = new URL(`http://${req.url}`)

          // Connect to target (allow everything - no filtering)
          const serverSocket = net.connect(
            parseInt(port) || 80,
            hostname,
            () => {
              clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
              serverSocket.write(head)
              serverSocket.pipe(clientSocket)
              clientSocket.pipe(serverSocket)
            },
          )

          serverSocket.on('error', _err => {
            clientSocket.end()
          })

          clientSocket.on('error', _err => {
            serverSocket.end()
          })
        })

        // Handle regular HTTP requests
        externalProxyServer.on('request', (req, res) => {
          const url = new URL(req.url!)
          const options = {
            hostname: url.hostname,
            port: url.port || 80,
            path: url.pathname + url.search,
            method: req.method,
            headers: req.headers,
          }

          const proxyReq = http.request(options, proxyRes => {
            res.writeHead(proxyRes.statusCode!, proxyRes.headers)
            proxyRes.pipe(res)
          })

          proxyReq.on('error', _err => {
            res.writeHead(502)
            res.end('Bad Gateway')
          })

          req.pipe(proxyReq)
        })

        // Start the external proxy on a random port
        await new Promise<void>((resolve, reject) => {
          externalProxyServer!.listen(0, '127.0.0.1', () => {
            const addr = externalProxyServer!.address()
            if (addr && typeof addr === 'object') {
              externalProxyPort = addr.port
              console.log(
                `External allow-all proxy started on port ${externalProxyPort}`,
              )
              resolve()
            } else {
              reject(new Error('Failed to get proxy address'))
            }
          })
          externalProxyServer!.on('error', reject)
        })

        // Initialize SandboxManager with restrictive config but external proxy
        const config: SandboxRuntimeConfig = {
          network: {
            allowedDomains: ['example.com'], // Only allow example.com
            deniedDomains: [],
            httpProxyPort: externalProxyPort, // Use our allow-all external proxy
          },
          filesystem: {
            denyRead: [],
            allowWrite: [],
            denyWrite: [],
          },
        }

        await SandboxManager.initialize(config)

        // Verify the external proxy port is being used
        expect(SandboxManager.getProxyPort()).toBe(externalProxyPort)

        // Try to access example.com (in allowlist)
        // This verifies that requests are routed through the external proxy
        const command = await SandboxManager.wrapWithSandbox(
          'curl -s --max-time 5 http://example.com',
        )

        const result = spawnSync(command, {
          shell: true,
          encoding: 'utf8',
          timeout: 10000,
        })

        // The request should succeed
        expect(result.status).toBe(0)

        // Should NOT contain SRT's block message
        const output = (result.stderr || result.stdout || '').toLowerCase()
        expect(output).not.toContain('blocked by network allowlist')

        console.log('✓ Request to example.com succeeded through external proxy')
        console.log(
          '✓ This verifies SRT used the external proxy on the configured port',
        )
      } finally {
        // Clean up
        await SandboxManager.reset()

        if (externalProxyServer) {
          await new Promise<void>(resolve => {
            externalProxyServer!.close(() => {
              console.log('External proxy server closed')
              resolve()
            })
          })
        }
      }
    })
  })
})

/**
 * Tests for custom environment variables feature
 */
describe('Custom Environment Variables Tests', () => {
  afterAll(async () => {
    await SandboxManager.reset()
  })

  describe('generateProxyEnvVars with customEnv', () => {
    it('should include custom env vars when customEnv is provided', () => {
      const customEnv = {
        SSL_CERT_FILE: '/tmp/ca-bundle.crt',
        MY_CUSTOM_VAR: 'my-value',
      }

      const envVars = generateProxyEnvVars(3128, 1080, customEnv)

      // Should include standard proxy env vars
      expect(envVars).toContain('HTTP_PROXY=http://localhost:3128')
      expect(envVars).toContain('HTTPS_PROXY=http://localhost:3128')

      // Should include custom env vars
      expect(envVars).toContain('SSL_CERT_FILE=/tmp/ca-bundle.crt')
      expect(envVars).toContain('MY_CUSTOM_VAR=my-value')
    })

    it('should include custom env vars even without proxy ports', () => {
      const customEnv = {
        SSL_CERT_FILE: '/tmp/ca-bundle.crt',
      }

      const envVars = generateProxyEnvVars(undefined, undefined, customEnv)

      // Should include minimal env vars
      expect(envVars).toContain('SANDBOX_RUNTIME=1')
      expect(envVars).toContain('TMPDIR=/tmp/claude')

      // Should include custom env vars
      expect(envVars).toContain('SSL_CERT_FILE=/tmp/ca-bundle.crt')

      // Should NOT include proxy env vars
      expect(envVars.some(v => v.startsWith('HTTP_PROXY='))).toBe(false)
    })

    it('should allow custom env vars to override defaults', () => {
      const customEnv = {
        TMPDIR: '/my/custom/tmp', // Override the default
      }

      const envVars = generateProxyEnvVars(3128, 1080, customEnv)

      // Custom TMPDIR should appear after the default, effectively overriding it
      const tmpDirEntries = envVars.filter(v => v.startsWith('TMPDIR='))
      expect(tmpDirEntries.length).toBe(2)
      // The custom one should come last (later entries override earlier in most shells)
      expect(tmpDirEntries[tmpDirEntries.length - 1]).toBe(
        'TMPDIR=/my/custom/tmp',
      )
    })
  })

  describe('SandboxManager env config', () => {
    it('should store and retrieve env config', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        env: {
          SSL_CERT_FILE: '/tmp/ca-bundle.crt',
          NODE_EXTRA_CA_CERTS: '/tmp/ca-bundle.crt',
        },
      }

      await SandboxManager.initialize(config)

      const env = SandboxManager.getEnv()
      expect(env).toBeDefined()
      expect(env?.SSL_CERT_FILE).toBe('/tmp/ca-bundle.crt')
      expect(env?.NODE_EXTRA_CA_CERTS).toBe('/tmp/ca-bundle.crt')

      await SandboxManager.reset()
    })

    it('should return undefined when env is not configured', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        // No env configured
      }

      await SandboxManager.initialize(config)

      const env = SandboxManager.getEnv()
      expect(env).toBeUndefined()

      await SandboxManager.reset()
    })
  })
})

/**
 * Tests for preCommand feature
 */
describe('PreCommand Tests', () => {
  afterAll(async () => {
    await SandboxManager.reset()
  })

  describe('SandboxManager preCommand config', () => {
    it('should store and retrieve preCommand config', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        preCommand: 'echo "Initializing sandbox"',
      }

      await SandboxManager.initialize(config)

      const preCommand = SandboxManager.getPreCommand()
      expect(preCommand).toBe('echo "Initializing sandbox"')

      await SandboxManager.reset()
    })

    it('should return undefined when preCommand is not configured', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        // No preCommand configured
      }

      await SandboxManager.initialize(config)

      const preCommand = SandboxManager.getPreCommand()
      expect(preCommand).toBeUndefined()

      await SandboxManager.reset()
    })
  })

  describe('preCommand execution in sandbox (Linux only)', () => {
    it('should execute preCommand before main command', async () => {
      // Skip if not on Linux
      if (getPlatform() !== 'linux') {
        console.log('Skipping preCommand execution test on non-Linux platform')
        return
      }

      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'], // Need network to trigger full sandbox wrapping
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        preCommand: 'echo "PRE_COMMAND_EXECUTED" > /tmp/precommand-test.txt',
        enableWeakerNestedSandbox: true, // Needed for containerized test environments
      }

      await SandboxManager.initialize(config)

      // Wrap a command that reads the file created by preCommand
      const command = await SandboxManager.wrapWithSandbox(
        'cat /tmp/precommand-test.txt',
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      // The preCommand should have created the file, and main command should read it
      expect(result.stdout).toContain('PRE_COMMAND_EXECUTED')

      await SandboxManager.reset()
    })

    it('should fail if preCommand fails', async () => {
      // Skip if not on Linux
      if (getPlatform() !== 'linux') {
        console.log('Skipping preCommand failure test on non-Linux platform')
        return
      }

      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: ['example.com'],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        preCommand: 'exit 1', // This should cause the sandbox to fail
        enableWeakerNestedSandbox: true, // Needed for containerized test environments
      }

      await SandboxManager.initialize(config)

      const command = await SandboxManager.wrapWithSandbox(
        'echo "Should not reach here"',
      )

      const result = spawnSync(command, {
        shell: true,
        encoding: 'utf8',
        timeout: 10000,
      })

      // The command should fail because preCommand failed
      expect(result.status).not.toBe(0)

      await SandboxManager.reset()
    })
  })
})

/**
 * Tests for combined env and preCommand features
 */
describe('Combined env and preCommand Tests', () => {
  afterAll(async () => {
    await SandboxManager.reset()
  })

  describe('Using both env and preCommand together', () => {
    it('should support both env and preCommand in config', async () => {
      const config: SandboxRuntimeConfig = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
        },
        filesystem: {
          denyRead: [],
          allowWrite: ['/tmp'],
          denyWrite: [],
        },
        env: {
          MY_VAR: 'my-value',
        },
        preCommand: 'echo "Setup complete"',
      }

      await SandboxManager.initialize(config)

      expect(SandboxManager.getEnv()).toEqual({ MY_VAR: 'my-value' })
      expect(SandboxManager.getPreCommand()).toBe('echo "Setup complete"')

      await SandboxManager.reset()
    })
  })
})
