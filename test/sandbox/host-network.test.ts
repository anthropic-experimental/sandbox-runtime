import { afterEach, describe, expect, it } from 'bun:test'
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import dgram from 'node:dgram'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SandboxManager } from '../../src/sandbox/sandbox-manager.js'
import type { SandboxRuntimeConfig } from '../../src/sandbox/sandbox-config.js'
import { isLinux, isMacOS } from '../helpers/platform.js'

function quote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function hostConfig(
  overrides: Partial<SandboxRuntimeConfig['filesystem']> = {},
): SandboxRuntimeConfig {
  return {
    network: {
      hostNetwork: true,
      allowedDomains: [],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
      ...overrides,
    },
  }
}

async function run(
  command: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const wrapped = await SandboxManager.wrapWithSandbox(command)
  const child = spawn(wrapped, {
    shell: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', chunk => {
    stdout += chunk.toString()
  })
  child.stderr.on('data', chunk => {
    stderr += chunk.toString()
  })
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once('error', reject)
    child.once('close', resolve)
  })
  return { code, stdout, stderr }
}

async function listenTcp(): Promise<{ server: net.Server; port: number }> {
  const server = net.createServer(socket => socket.end('tcp-ok'))
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const address = server.address()
  if (!address || typeof address === 'string')
    throw new Error('missing TCP address')
  return { server, port: address.port }
}

describe.if(isLinux || isMacOS)('explicit host networking', () => {
  afterEach(async () => {
    await SandboxManager.reset()
  })

  it('rejects contradictory policy through the public manager APIs', async () => {
    const contradictory = {
      ...hostConfig(),
      network: {
        hostNetwork: true,
        allowedDomains: ['example.com'],
        deniedDomains: [],
      },
    } as SandboxRuntimeConfig
    await expect(SandboxManager.initialize(contradictory)).rejects.toThrow(
      'cannot be combined with network.hostNetwork',
    )

    await SandboxManager.initialize(hostConfig())
    expect(() => SandboxManager.updateConfig(contradictory)).toThrow(
      'cannot be combined with network.hostNetwork',
    )
  })

  it('uses raw host TCP/UDP/loopback without starting proxies', async () => {
    await SandboxManager.initialize(hostConfig())
    expect(SandboxManager.getProxyPort()).toBeUndefined()
    expect(SandboxManager.getSocksProxyPort()).toBeUndefined()

    const tcp = await listenTcp()
    try {
      const script = `const net=require('node:net');const s=net.createConnection(${tcp.port},'127.0.0.1');s.on('data',d=>process.stdout.write(d));s.on('end',()=>process.exit(0));s.on('error',()=>process.exit(2));setTimeout(()=>process.exit(3),3000)`
      const result = await run(`node -e ${quote(script)}`)
      expect(result.code).toBe(0)
      expect(result.stdout).toBe('tcp-ok')
    } finally {
      await new Promise<void>(resolve => tcp.server.close(() => resolve()))
    }

    const udp = dgram.createSocket('udp4')
    await new Promise<void>((resolve, reject) => {
      udp.once('error', reject)
      udp.bind(0, '127.0.0.1', resolve)
    })
    const udpAddress = udp.address()
    if (typeof udpAddress === 'string') throw new Error('missing UDP address')
    const received = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('UDP timeout')), 3000)
      udp.once('message', message => {
        clearTimeout(timer)
        resolve(message.toString())
      })
    })
    const udpScript = `const d=require('node:dgram').createSocket('udp4');d.send(Buffer.from('udp-ok'),${udpAddress.port},'127.0.0.1',e=>{d.close();process.exit(e?2:0)})`
    const udpResult = await run(`node -e ${quote(udpScript)}`)
    expect(udpResult.code).toBe(0)
    expect(await received).toBe('udp-ok')
    udp.close()
  })

  it('allows a sandboxed process to bind a host-visible TCP listener', async () => {
    await SandboxManager.initialize(hostConfig())
    const script = `const net=require('node:net');const s=net.createServer(c=>c.end('listener-ok'));s.listen(0,'127.0.0.1',()=>console.log(s.address().port));s.on('connection',()=>setTimeout(()=>s.close(()=>process.exit(0)),10));setTimeout(()=>process.exit(3),4000)`
    const wrapped = await SandboxManager.wrapWithSandbox(
      `node -e ${quote(script)}`,
    )
    const child = spawn(wrapped, {
      shell: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const exit = new Promise<number | null>((resolve, reject) => {
      child.once('error', reject)
      child.once('close', resolve)
    })
    const port = await new Promise<number>((resolve, reject) => {
      let output = ''
      const timer = setTimeout(
        () => reject(new Error('listener startup timeout')),
        3000,
      )
      child.stdout.on('data', chunk => {
        output += chunk.toString()
        const line = output.split('\n')[0]
        if (!/^\d+$/.test(line)) return
        clearTimeout(timer)
        resolve(Number(line))
      })
      child.once('error', reject)
    })
    const body = await new Promise<string>((resolve, reject) => {
      const socket = net.createConnection(port, '127.0.0.1')
      let value = ''
      socket.on('data', chunk => {
        value += chunk.toString()
      })
      socket.once('end', () => resolve(value))
      socket.once('error', reject)
    })
    expect(body).toBe('listener-ok')
    expect(await exit).toBe(0)
  })

  it('retains filesystem read denials and Unix-socket blocking', async () => {
    const root = mkdtempSync(join(tmpdir(), 'srt-host-network-'))
    const denied = join(root, 'denied.txt')
    const writable = join(root, 'writable')
    const socketPath = join(writable, 'blocked.sock')
    writeFileSync(denied, 'denied')
    mkdirSync(writable)
    try {
      await SandboxManager.initialize(
        hostConfig({
          denyRead: [denied],
          allowWrite: [writable],
        }),
      )
      const readResult = await run(`cat ${quote(denied)}`)
      expect(readResult.code).not.toBe(0)

      const socketScript = `const net=require('node:net');const s=net.createServer();s.on('error',()=>process.exit(0));s.listen(${JSON.stringify(socketPath)},()=>s.close(()=>process.exit(4)));setTimeout(()=>process.exit(5),2000)`
      const socketResult = await run(`node -e ${quote(socketScript)}`)
      expect(socketResult.code).toBe(0)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
