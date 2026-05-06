import { describe, test, expect } from 'bun:test'
import { SandboxRuntimeConfigSchema } from '../src/sandbox/sandbox-config.js'

describe('Config Validation', () => {
  test('should validate a valid minimal config', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should validate a config with valid domains', () => {
    const config = {
      network: {
        allowedDomains: ['example.com', '*.github.com', 'localhost'],
        deniedDomains: ['evil.com'],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should reject invalid domain patterns', () => {
    const config = {
      network: {
        allowedDomains: ['not-a-domain'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should reject domain with protocol', () => {
    const config = {
      network: {
        allowedDomains: ['https://example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should reject empty filesystem paths', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [''],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should validate config with optional fields', () => {
    const config = {
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
        allowUnixSockets: ['/var/run/docker.sock'],
        allowAllUnixSockets: false,
        allowLocalBinding: true,
      },
      filesystem: {
        denyRead: ['/etc/shadow'],
        allowWrite: ['/tmp'],
        denyWrite: ['/etc'],
      },
      ignoreViolations: {
        '*': ['/usr/bin'],
        'git push': ['/usr/bin/nc'],
      },
      enableWeakerNestedSandbox: true,
      enableWeakerNetworkIsolation: false,
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test('should reject missing required fields', () => {
    const config = {
      network: {
        allowedDomains: [],
      },
      filesystem: {
        denyRead: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(false)
  })

  test('should validate wildcard domains correctly', () => {
    const validWildcards = ['*.example.com', '*.github.io', '*.co.uk']

    const invalidWildcards = [
      '*example.com', // Missing dot after asterisk
      '*.com', // No subdomain
      '*.', // Invalid format
    ]

    for (const domain of validWildcards) {
      const config = {
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(true)
    }

    for (const domain of invalidWildcards) {
      const config = {
        network: { allowedDomains: [domain], deniedDomains: [] },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }
      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(false)
    }
  })

  test('should validate config with enableWeakerNetworkIsolation', () => {
    const config = {
      network: {
        allowedDomains: ['example.com'],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      enableWeakerNetworkIsolation: true,
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.enableWeakerNetworkIsolation).toBe(true)
    }
  })

  test('should validate config with custom ripgrep command', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      ripgrep: {
        command: '/usr/local/bin/rg',
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep?.command).toBe('/usr/local/bin/rg')
    }
  })

  test('should validate config with custom ripgrep command and args', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
      ripgrep: {
        command: 'claude',
        args: ['--ripgrep'],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep?.command).toBe('claude')
      expect(result.data.ripgrep?.args).toEqual(['--ripgrep'])
    }
  })

  test('should accept valid allowMachLookup entries', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
        allowMachLookup: [
          '2BUA8C4S2C.com.1password.*',
          'com.apple.CoreSimulator.CoreSimulatorService',
          '*',
        ],
      },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
  })

  test.each(['com.*.foo', 'com.example.**'])(
    'should reject allowMachLookup entry with non-trailing wildcard: %s',
    entry => {
      const config = {
        network: {
          allowedDomains: [],
          deniedDomains: [],
          allowMachLookup: [entry],
        },
        filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
      }

      const result = SandboxRuntimeConfigSchema.safeParse(config)
      expect(result.success).toBe(false)
    },
  )

  test('should use default ripgrep command when not specified', () => {
    const config = {
      network: {
        allowedDomains: [],
        deniedDomains: [],
      },
      filesystem: {
        denyRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }

    const result = SandboxRuntimeConfigSchema.safeParse(config)
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.ripgrep).toBeUndefined()
    }
  })

  describe('bwrapPath / socatPath', () => {
    const base = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    test('accepts absolute paths', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        bwrapPath: '/usr/local/bin/bwrap',
        socatPath: '/opt/tools/socat',
      })
      expect(result.success).toBe(true)
    })

    test('rejects relative bwrapPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        bwrapPath: 'bwrap',
      })
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.issues[0]?.message).toContain('must be absolute')
      }
    })

    test('rejects relative socatPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        socatPath: './bin/socat',
      })
      expect(result.success).toBe(false)
    })

    test('rejects empty bwrapPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        bwrapPath: '',
      })
      expect(result.success).toBe(false)
    })
  })

  describe('network.tlsTerminate', () => {
    const base = {
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: { denyRead: [], allowWrite: [], denyWrite: [] },
    }

    test('is optional — config without it validates', () => {
      expect(SandboxRuntimeConfigSchema.safeParse(base).success).toBe(true)
    })

    test('accepts caCertPath + caKeyPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          ...base.network,
          tlsTerminate: { caCertPath: '/etc/ca.crt', caKeyPath: '/etc/ca.key' },
        },
      })
      expect(result.success).toBe(true)
    })

    test('rejects when caKeyPath is missing', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          ...base.network,
          tlsTerminate: { caCertPath: '/etc/ca.crt' },
        },
      })
      expect(result.success).toBe(false)
    })

    test('rejects empty caCertPath', () => {
      const result = SandboxRuntimeConfigSchema.safeParse({
        ...base,
        network: {
          ...base.network,
          tlsTerminate: { caCertPath: '', caKeyPath: '/etc/ca.key' },
        },
      })
      expect(result.success).toBe(false)
    })
  })
})
