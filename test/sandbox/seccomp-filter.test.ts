import { describe, it, expect, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { whichSync } from '../../src/utils/which.js'
import { isLinux } from '../helpers/platform.js'
import {
  generateSeccompFilter,
  cleanupSeccompFilter,
  getPreGeneratedBpfPath,
  getApplySeccompBinaryPath,
} from '../../src/sandbox/generate-seccomp-filter.js'
import {
  wrapCommandWithSandboxLinux,
  checkLinuxDependencies,
} from '../../src/sandbox/linux-sandbox-utils.js'

// wrapCommandWithSandboxLinux early-returns the raw command when no restrictions
// are requested. Tests that want to verify seccomp enforcement need to request
// at least one restriction so the sandbox actually wraps.
const TRIGGER_SANDBOX_WRITE_CONFIG = {
  allowOnly: [tmpdir()],
  denyWithinAllow: [],
}

describe.if(isLinux)('Linux Sandbox Dependencies', () => {
  it('should check for Linux sandbox dependencies', () => {
    const depCheck = checkLinuxDependencies()
    expect(depCheck).toHaveProperty('errors')
    expect(depCheck).toHaveProperty('warnings')

    // If no errors, bwrap and socat should be available
    if (depCheck.errors.length === 0) {
      expect(whichSync('bwrap')).not.toBeNull()
      expect(whichSync('socat')).not.toBeNull()
    }
  })
})

describe.if(isLinux)('Pre-generated BPF Support', () => {
  it('should detect pre-generated BPF files on x64/arm64', () => {
    // Check if current architecture supports pre-generated BPF
    const arch = process.arch
    const preGeneratedBpf = getPreGeneratedBpfPath()

    if (arch === 'x64' || arch === 'arm64') {
      // Should have pre-generated BPF for these architectures
      expect(preGeneratedBpf).toBeTruthy()
      if (preGeneratedBpf) {
        expect(existsSync(preGeneratedBpf)).toBe(true)
        expect(preGeneratedBpf).toContain('vendor/seccomp')
        expect(preGeneratedBpf).toMatch(/unix-block\.bpf$/)
      }
    } else {
      // Other architectures should not have pre-generated BPF
      expect(preGeneratedBpf).toBeNull()
    }
  })

  it('should have sandbox dependencies on x64/arm64 with bwrap and socat', () => {
    const preGeneratedBpf = getPreGeneratedBpfPath()

    // Only test on architectures with pre-generated BPF
    if (!preGeneratedBpf) {
      return
    }

    // checkLinuxDependencies should report no errors on x64/arm64
    // with bwrap and socat installed (pre-built binaries included)
    const depCheck = checkLinuxDependencies()

    // On x64/arm64 with pre-built binaries, we should have no errors
    const hasBwrap = whichSync('bwrap') !== null
    const hasSocat = whichSync('socat') !== null
    const hasApplySeccomp = getApplySeccompBinaryPath() !== null

    if (hasBwrap && hasSocat && hasApplySeccomp) {
      // Basic deps available - on x64/arm64 this should be sufficient
      // (pre-built apply-seccomp binaries and BPF filters are included)
      const arch = process.arch
      if (arch === 'x64' || arch === 'arm64') {
        expect(depCheck.errors).toHaveLength(0)
        expect(depCheck.warnings).toHaveLength(0)
      }
    }
  })

  it('should not allow seccomp on unsupported architectures', () => {
    const preGeneratedBpf = getPreGeneratedBpfPath()

    // Only test on architectures WITHOUT pre-generated BPF
    if (preGeneratedBpf !== null) {
      return
    }

    // On architectures without pre-built apply-seccomp binaries,
    // checkLinuxDependencies() should return warnings about missing seccomp
    const depCheck = checkLinuxDependencies()

    // Unsupported architectures should have seccomp warnings
    expect(depCheck.warnings.length).toBeGreaterThan(0)

    // But bwrap+socat should still be available (no errors) if installed
    const hasBwrap = whichSync('bwrap') !== null
    const hasSocat = whichSync('socat') !== null

    if (hasBwrap && hasSocat) {
      expect(depCheck.errors).toHaveLength(0)
    }
  })
})

describe.if(isLinux)('Seccomp Filter (Pre-generated)', () => {
  it('should return pre-generated BPF filter on x64/arm64', () => {
    const arch = process.arch
    if (arch !== 'x64' && arch !== 'arm64') {
      // Not a supported architecture
      return
    }

    const filterPath = generateSeccompFilter()

    expect(filterPath).toBeTruthy()
    expect(filterPath).toMatch(/\.bpf$/)
    expect(filterPath).toContain('vendor/seccomp')

    // Verify the file exists
    expect(existsSync(filterPath!)).toBe(true)

    // Verify the file has content (BPF bytecode)
    const stats = statSync(filterPath!)
    expect(stats.size).toBeGreaterThan(0)

    // BPF programs should be a multiple of 8 bytes (struct sock_filter is 8 bytes)
    expect(stats.size % 8).toBe(0)
  })

  it('should return same path on repeated calls (pre-generated)', () => {
    const arch = process.arch
    if (arch !== 'x64' && arch !== 'arm64') {
      return
    }

    const filter1 = generateSeccompFilter()
    const filter2 = generateSeccompFilter()

    expect(filter1).toBeTruthy()
    expect(filter2).toBeTruthy()

    // Should return same pre-generated file path
    expect(filter1).toBe(filter2)
  })

  it('should return null on unsupported architectures', () => {
    const arch = process.arch
    if (arch === 'x64' || arch === 'arm64') {
      // This test is for unsupported architectures only
      return
    }

    const filter = generateSeccompFilter()
    expect(filter).toBeNull()
  })

  it('should handle cleanup gracefully (no-op for pre-generated files)', () => {
    // Cleanup should not throw for any path (it's a no-op)
    expect(() => cleanupSeccompFilter('/tmp/test.bpf')).not.toThrow()
    expect(() =>
      cleanupSeccompFilter('/vendor/seccomp/x64/unix-block.bpf'),
    ).not.toThrow()
    expect(() => cleanupSeccompFilter('')).not.toThrow()
  })
})

describe.if(isLinux)('Apply Seccomp Binary', () => {
  it('should find pre-built apply-seccomp binary on x64/arm64', () => {
    const arch = process.arch
    if (arch !== 'x64' && arch !== 'arm64') {
      return
    }

    const binaryPath = getApplySeccompBinaryPath()
    expect(binaryPath).toBeTruthy()

    // Verify the file exists
    expect(existsSync(binaryPath!)).toBe(true)

    // Should be in vendor directory
    expect(binaryPath).toContain('vendor/seccomp')
  })

  it('should return null on unsupported architectures', () => {
    const arch = process.arch
    if (arch === 'x64' || arch === 'arm64') {
      return
    }

    const binaryPath = getApplySeccompBinaryPath()
    expect(binaryPath).toBeNull()
  })
})

describe.if(isLinux)('Architecture Support', () => {
  it('should allow bypassing architecture requirement with allowAllUnixSockets', async () => {
    // When allowAllUnixSockets is true, architecture check should not matter
    const testCommand = 'echo "test"'

    // This should NOT throw even on unsupported architecture (when allowAllUnixSockets=true)
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      allowAllUnixSockets: true, // Bypass seccomp
    })

    // Command should not contain apply-seccomp binary
    expect(wrappedCommand).not.toContain('apply-seccomp')
    expect(wrappedCommand).toContain('echo "test"')
  })
})

describe.if(isLinux)('Socket Filtering Behavior', () => {
  beforeAll(() => {
    // On Linux CI with vendor/seccomp files present this always succeeds.
    // If it returns null we want the suite to fail loudly, not silently
    // skip — a missing BPF filter means seccomp isn't protecting anything.
    expect(generateSeccompFilter()).not.toBeNull()
  })

  it('should block Unix socket creation (SOCK_STREAM)', async () => {
    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('Unix socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      writeConfig: TRIGGER_SANDBOX_WRITE_CONFIG,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).not.toBe(0)
    const stderr = result.stderr?.toString() || ''
    expect(stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('should block Unix socket creation (SOCK_DGRAM)', async () => {
    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); print('Unix datagram created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      writeConfig: TRIGGER_SANDBOX_WRITE_CONFIG,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).not.toBe(0)
    const stderr = result.stderr?.toString() || ''
    expect(stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('should allow TCP socket creation (IPv4)', async () => {
    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); print('TCP socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      writeConfig: TRIGGER_SANDBOX_WRITE_CONFIG,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout?.toString()).toContain('TCP socket created')
  })

  it('should allow UDP socket creation (IPv4)', async () => {
    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); print('UDP socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      writeConfig: TRIGGER_SANDBOX_WRITE_CONFIG,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout?.toString()).toContain('UDP socket created')
  })

  it('should allow IPv6 socket creation', async () => {
    const testCommand = `python3 -c "import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); print('IPv6 socket created')"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      writeConfig: TRIGGER_SANDBOX_WRITE_CONFIG,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout?.toString()).toContain('IPv6 socket created')
  })
})

describe.if(isLinux)('Two-Stage Seccomp Application', () => {
  it('should include apply-seccomp in wrapped command when filesystem restricted', async () => {
    if (checkLinuxDependencies().errors.length > 0) {
      return
    }

    // With filesystem restriction and no network, the no-socat branch at
    // linux-sandbox-utils.ts:1197 should apply seccomp directly.
    // Socat-before-seccomp ordering (the network-restricted branch) is
    // covered implicitly by integration.test.ts — if socat ran after
    // seccomp, its AF_UNIX socket would be blocked and every network
    // test there would fail.
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'echo "test"',
      needsNetworkRestriction: false,
      writeConfig: TRIGGER_SANDBOX_WRITE_CONFIG,
    })

    expect(wrappedCommand).toContain('bwrap')
    expect(wrappedCommand).toContain('apply-seccomp')

    const bwrapIndex = wrappedCommand.indexOf('bwrap')
    const seccompIndex = wrappedCommand.indexOf('apply-seccomp')
    const commandIndex = wrappedCommand.indexOf('echo')
    expect(bwrapIndex).toBeLessThan(seccompIndex)
    expect(seccompIndex).toBeLessThan(commandIndex)
  })

  it('should execute user command with filter applied', async () => {
    if (checkLinuxDependencies().errors.length > 0) {
      return
    }

    // User command tries to create Unix socket - should fail
    const testCommand = `python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"`

    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      writeConfig: TRIGGER_SANDBOX_WRITE_CONFIG,
    })

    const result = spawnSync('bash', ['-c', wrappedCommand], {
      stdio: 'pipe',
      timeout: 5000,
    })

    // Should fail due to seccomp filter
    expect(result.status).not.toBe(0)
  })
})

describe.if(isLinux)('Sandbox Integration', () => {
  it('should handle commands without network or filesystem restrictions', async () => {
    if (checkLinuxDependencies().errors.length > 0) {
      return
    }

    const testCommand = 'echo "hello world"'
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
    })

    // Should still wrap the command even without restrictions
    expect(wrappedCommand).toBeTruthy()
    expect(typeof wrappedCommand).toBe('string')
  })

  it('should wrap commands with filesystem restrictions', async () => {
    if (checkLinuxDependencies().errors.length > 0) {
      return
    }

    const testCommand = 'ls /'
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: testCommand,
      needsNetworkRestriction: false,
      writeConfig: {
        allowOnly: ['/tmp'],
        denyWithinAllow: [],
      },
    })

    expect(wrappedCommand).toBeTruthy()
    expect(wrappedCommand).toContain('bwrap')
  })
})

describe.if(isLinux)('Error Handling', () => {
  it('should handle cleanup calls gracefully (no-op)', () => {
    // Cleanup is a no-op for pre-generated files, should never throw
    expect(() => cleanupSeccompFilter('')).not.toThrow()
    expect(() => cleanupSeccompFilter('/invalid/path/filter.bpf')).not.toThrow()
    expect(() => cleanupSeccompFilter('/tmp/nonexistent.bpf')).not.toThrow()
    expect(() =>
      cleanupSeccompFilter('/vendor/seccomp/x64/unix-block.bpf'),
    ).not.toThrow()
  })
})

describe.if(isLinux)('Custom Seccomp Paths (expectedPath parameter)', () => {
  it('should use expectedPath for BPF when provided and file exists', () => {
    const realPath = getPreGeneratedBpfPath()
    if (!realPath) {
      // Skip if no real BPF available on this architecture
      return
    }

    // Use the real path as expectedPath - should return it directly
    const result = getPreGeneratedBpfPath(realPath)
    expect(result).toBe(realPath)
  })

  it('should use expectedPath for apply-seccomp when provided and file exists', () => {
    const realPath = getApplySeccompBinaryPath()
    if (!realPath) {
      // Skip if no real binary available on this architecture
      return
    }

    // Use the real path as expectedPath - should return it directly
    const result = getApplySeccompBinaryPath(realPath)
    expect(result).toBe(realPath)
  })

  it('should fall back to default paths when expectedPath for BPF does not exist', () => {
    const nonExistentPath = '/tmp/nonexistent-seccomp.bpf'
    const result = getPreGeneratedBpfPath(nonExistentPath)

    // Should fall back to vendor path (or null if arch not supported)
    const arch = process.arch
    if (arch === 'x64' || arch === 'arm64') {
      expect(result).toBeTruthy()
      expect(result).toContain('vendor/seccomp')
    } else {
      expect(result).toBeNull()
    }
  })

  it('should fall back to default paths when expectedPath for apply-seccomp does not exist', () => {
    const nonExistentPath = '/tmp/nonexistent-apply-seccomp'
    const result = getApplySeccompBinaryPath(nonExistentPath)

    // Should fall back to vendor path (or null if arch not supported)
    const arch = process.arch
    if (arch === 'x64' || arch === 'arm64') {
      expect(result).toBeTruthy()
      expect(result).toContain('vendor/seccomp')
    } else {
      expect(result).toBeNull()
    }
  })

  it('should pass seccompConfig through wrapCommandWithSandboxLinux', async () => {
    if (checkLinuxDependencies().errors.length > 0) {
      return
    }

    // Pass custom paths that don't exist - should fall back to defaults
    // Need filesystem restriction so command actually gets wrapped
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'echo test',
      needsNetworkRestriction: false,
      writeConfig: {
        allowOnly: ['/tmp'],
        denyWithinAllow: [],
      },
      seccompConfig: {
        bpfPath: '/custom/nonexistent/path.bpf',
        applyPath: '/custom/nonexistent/apply-seccomp',
      },
    })

    // Should still work (falls back to defaults since custom paths don't exist)
    expect(wrappedCommand).toBeTruthy()
    expect(wrappedCommand).toContain('bwrap')
  })

  it('should use custom seccompConfig paths when they exist', async () => {
    if (checkLinuxDependencies().errors.length > 0) {
      return
    }

    // Get the real paths
    const realBpfPath = getPreGeneratedBpfPath()
    const realApplyPath = getApplySeccompBinaryPath()

    if (!realBpfPath || !realApplyPath) {
      return
    }

    // Pass the real paths as custom config - should use them
    // Need filesystem restriction so command actually gets wrapped
    const wrappedCommand = await wrapCommandWithSandboxLinux({
      command: 'echo test',
      needsNetworkRestriction: false,
      writeConfig: {
        allowOnly: ['/tmp'],
        denyWithinAllow: [],
      },
      seccompConfig: {
        bpfPath: realBpfPath,
        applyPath: realApplyPath,
      },
    })

    expect(wrappedCommand).toBeTruthy()
    // The command should contain bwrap and the apply-seccomp binary path
    expect(wrappedCommand).toContain('bwrap')
    expect(wrappedCommand).toContain('apply-seccomp')
  })
})
