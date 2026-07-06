import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import { writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isLinux } from '../helpers/platform.js'
import { wrapCommandWithSandboxLinux } from '../../src/sandbox/linux-sandbox-utils.js'
import {
  getSandboxResolvConfPath,
  getTransparentAssetDir,
  transparentAssetParentDir,
  transparentAssetParentCandidates,
  checkTransparentDependencies,
} from '../../src/sandbox/transparent-net.js'

/**
 * Shape tests for the wrapper string: no bwrap execution, just assertions
 * on the generated command. Networked sandboxing has exactly ONE shape on
 * Linux — the transparent script (socat env-var listeners + the helper,
 * which rendezvouses with the host for netns configuration). There is no
 * classic variant and no fallback: missing components fail the wrap.
 */
describe.if(isLinux)('network command generation (single shape)', () => {
  const httpSocketPath = join(tmpdir(), 'srt-tp-wrap-test-http.sock')
  const socksSocketPath = join(tmpdir(), 'srt-tp-wrap-test-socks.sock')
  const netnsSocketPath = join(tmpdir(), 'srt-tp-wrap-test-netns.sock')
  const depsAvailable = checkTransparentDependencies().errors.length === 0

  beforeAll(() => {
    // The wrapper verifies the sockets exist; plain files suffice.
    writeFileSync(httpSocketPath, '')
    writeFileSync(socksSocketPath, '')
    writeFileSync(netnsSocketPath, '')
  })

  afterAll(() => {
    rmSync(httpSocketPath, { force: true })
    rmSync(socksSocketPath, { force: true })
    rmSync(netnsSocketPath, { force: true })
  })

  async function wrap(): Promise<string> {
    return wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: true,
      httpSocketPath,
      socksSocketPath,
      netnsSocketPath,
      tokensFilePath: '/protected/tokens',
      httpProxyPort: 12345,
      socksProxyPort: 12345,
      proxyAuthToken: 'test-token',
    })
  }

  it.if(depsAvailable)(
    'emits the single network shape: helper + host rendezvous, no in-sandbox namespace tooling',
    async () => {
      const cmd = await wrap()
      expect(cmd).toContain('--unshare-net')
      // The netns is configured by the HOST (netns-config via the
      // rendezvous socket) — nothing namespace-related runs in-sandbox.
      expect(cmd).not.toContain('netns-setup')
      expect(cmd).not.toContain('netns-config')
      expect(cmd).toContain(`--bind ${netnsSocketPath} ${netnsSocketPath}`)
      expect(cmd).toContain(`SRT_TP_NETNS=unix:${netnsSocketPath}`)
      expect(cmd).toContain('SRT_TP_TOKEN_FILE=/protected/tokens')
      // Raw secrets must never ride the (cmdline-visible) script.
      expect(cmd).not.toContain('SRT_TP_NETNS_TOKEN=')
      expect(cmd).toContain(`SRT_TP_BRIDGE=unix:${httpSocketPath}`)
      expect(cmd).toContain('SRT_TP_PORTS=80,443')
      expect(cmd).not.toContain('SRT_TP_TOKEN=test-token')
      expect(cmd).toContain('transparent-net-helper')
      // The script execs into the helper (pid 1 reaps the socats).
      expect(cmd).toContain('exec')
      // env-var proxy front door is part of the same single shape
      expect(cmd).toContain('TCP-LISTEN:3128')
      expect(cmd).toContain('HTTP_PROXY')
    },
  )

  it.if(depsAvailable)(
    'binds the stub resolv.conf from the protected asset dir',
    async () => {
      const cmd = await wrap()
      const resolvSrc = getSandboxResolvConfPath()
      const assetDir = getTransparentAssetDir()
      expect(resolvSrc.startsWith(assetDir + '/')).toBe(true)
      expect(cmd).toContain(`--ro-bind ${resolvSrc} `)
      expect(readFileSync(resolvSrc, 'utf8')).toBe('nameserver 127.0.0.1\n')
      // EVERY candidate parent gets a tmpfs (write-block + sibling-hide +
      // pre-shadow for parents that do not exist yet), and the OWN
      // session dir is rebound read-only AFTER its parent's tmpfs — the
      // ordering is load-bearing.
      const parent = transparentAssetParentDir()
      expect(assetDir.startsWith(parent + '/')).toBe(true)
      for (const candidate of transparentAssetParentCandidates()) {
        expect(cmd).toContain(`--tmpfs ${candidate}`)
      }
      expect(cmd.indexOf(`--tmpfs ${parent}`)).toBeLessThan(
        cmd.indexOf(`--ro-bind ${assetDir} ${assetDir}`),
      )
      // The dead ro-bind of the parent must NOT come back.
      expect(cmd).not.toContain(`--ro-bind ${parent} ${parent}`)
      // Pre-seccomp outer shell: canonical path, --norc, no startup env.
      expect(cmd).toContain('--unsetenv BASH_ENV')
      expect(cmd).toContain('--unsetenv SHELLOPTS')
      expect(cmd).toMatch(
        /-- \/(usr\/)?bin\/bash --norc -c |-- \/(usr\/)?bin\/sh -c /,
      )
      // The executed helper is the protected copy, not the repo file.
      expect(cmd).toContain(`${assetDir}/transparent-net-helper`)
    },
  )

  it.if(depsAvailable)(
    'keeps the user command clear of quote amplification (MAX_ARG_STRLEN)',
    async () => {
      // The user command crosses exactly two quote() layers; a
      // single-quote-heavy command must stay far below the kernel's
      // 128 KiB per-argument cap (the old nested shape amplified 81x).
      const nasty = `echo ${"'".repeat(1000)}`
      const cmd = await wrapCommandWithSandboxLinux({
        command: nasty,
        needsNetworkRestriction: true,
        httpSocketPath,
        socksSocketPath,
        netnsSocketPath,
      })
      // 2 layers → each quote becomes at most 5^2 = 25 chars.
      expect(cmd.length).toBeLessThan(1000 * 30 + 20_000)
    },
  )

  it.if(depsAvailable)(
    'routes secrets through SRT_TP_TOKEN_FILE when a tokens file is provided',
    async () => {
      const cmd = await wrapCommandWithSandboxLinux({
        command: 'echo hello',
        needsNetworkRestriction: true,
        httpSocketPath,
        socksSocketPath,
        netnsSocketPath,
        tokensFilePath: '/protected/tokens',
        proxyAuthToken: 'test-token',
      })
      expect(cmd).toContain('SRT_TP_TOKEN_FILE=/protected/tokens')
      // The raw secrets must NOT ride the (cmdline-visible) script.
      expect(cmd).not.toContain('SRT_TP_NETNS_TOKEN=')
      expect(cmd).not.toContain('SRT_TP_TOKEN=test-token')
    },
  )

  it('throws when the rendezvous socket is missing (no fallback)', async () => {
    // eslint-disable-next-line @typescript-eslint/await-thenable
    await expect(
      wrapCommandWithSandboxLinux({
        command: 'echo hello',
        needsNetworkRestriction: true,
        httpSocketPath,
        socksSocketPath,
      }),
    ).rejects.toThrow(/netnsSocketPath is required/)
  })

  it('blocked-network config (no bridge) has no helper and no resolv bind', async () => {
    // No proxy sockets = fully blocked network: that is a CONFIG (block
    // everything), not a fallback — no helper, no rendezvous, no resolv.
    const cmd = await wrapCommandWithSandboxLinux({
      command: 'echo hello',
      needsNetworkRestriction: true,
    })
    expect(cmd).toContain('--unshare-net')
    expect(cmd).not.toContain('SRT_TP_BRIDGE')
    expect(cmd).not.toContain('transparent-net-helper')
    expect(cmd).not.toContain('resolv')
  })
})
