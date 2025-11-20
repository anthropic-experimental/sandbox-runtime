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
})
