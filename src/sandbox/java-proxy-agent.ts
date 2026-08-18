/**
 * JVM proxy agent: makes Java tools inside the sandbox honour the proxy.
 *
 * The JVM ignores HTTPS_PROXY/NO_PROXY — proxy selection is driven by the
 * `https.proxyHost` family of system properties, and the credential the
 * proxy requires can only be supplied through `java.net.Authenticator`,
 * which needs code running inside the JVM. Env vars alone can't do that,
 * so gRPC-Java (Bazel's remote cache), Gradle, Maven, etc. either dial the
 * target directly (no route out of the sandbox) or hit the proxy without
 * the token and get a 407.
 *
 * The fix is a tiny `-javaagent` (source in vendor/java-proxy-agent-src,
 * embedded as base64 by vendor/java-proxy-agent/build.ts) that, at JVM
 * start-up, translates the proxy env vars into system properties and
 * installs an Authenticator for the proxy endpoint. This module writes that
 * jar to a temp dir once per session and builds the JAVA_TOOL_OPTIONS value
 * that points every JVM in the sandbox at it. The env var carries only the
 * jar path — the credential stays in HTTPS_PROXY, which the agent reads
 * itself — so the JVM's "Picked up JAVA_TOOL_OPTIONS: …" stderr line
 * leaks nothing.
 */
import { mkdtempSync, writeFileSync } from 'node:fs'
import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { logForDebugging } from '../utils/debug.js'
import { JAVA_PROXY_AGENT_JAR_BASE64 } from './java-proxy-agent-jar.js'

export const JAVA_PROXY_AGENT_JAR_NAME = 'srt-proxy-agent.jar'

/**
 * Write the embedded agent jar to a fresh temp directory and return its
 * path. Mode 0644 so the sandboxed child (same uid) can read it; the dir
 * is srt-owned and removed by {@link disposeJavaProxyAgentJar}.
 */
export function materializeJavaProxyAgentJar(): string {
  const dir = mkdtempSync(join(tmpdir(), 'srt-java-'))
  const jarPath = join(dir, JAVA_PROXY_AGENT_JAR_NAME)
  writeFileSync(jarPath, Buffer.from(JAVA_PROXY_AGENT_JAR_BASE64, 'base64'), {
    mode: 0o644,
  })
  return jarPath
}

export async function disposeJavaProxyAgentJar(jarPath: string): Promise<void> {
  try {
    await rm(dirname(jarPath), { recursive: true, force: true })
  } catch (err) {
    logForDebugging(
      `[java-proxy-agent] cleanup failed: ${(err as Error).message}`,
      { level: 'warn' },
    )
  }
}

/**
 * Compose the JAVA_TOOL_OPTIONS value for a sandboxed child.
 *
 * `-javaagent:<jar>` is prepended when a jar path is given; `flags` are
 * appended (e.g. macOS's -Djava.net.preferIPv4Stack=true). The parent's
 * own JAVA_TOOL_OPTIONS is preserved unless that var is on the
 * credential-deny list, in which case it is dropped so the deny holds.
 * Flags already present in the inherited value are not duplicated.
 * Returns undefined when there is nothing to set.
 */
export function buildJavaToolOptions(opts: {
  agentJarPath?: string
  flags?: string[]
  unsetEnvVars?: string[]
  inherited?: string
}): string | undefined {
  const denied = (opts.unsetEnvVars ?? []).includes('JAVA_TOOL_OPTIONS')
  const inherited = denied ? '' : (opts.inherited ?? '')
  const parts: string[] = []
  if (opts.agentJarPath) {
    parts.push(javaAgentFlag(opts.agentJarPath))
  }
  if (inherited) parts.push(inherited)
  for (const flag of opts.flags ?? []) {
    if (!inherited.includes(flag) && !parts.includes(flag)) parts.push(flag)
  }
  return parts.length > 0 ? parts.join(' ') : undefined
}

/**
 * The JVM tokenizes JAVA_TOOL_OPTIONS on whitespace but honours double
 * quotes, so a jar path containing whitespace is wrapped in them.
 */
function javaAgentFlag(jarPath: string): string {
  const flag = `-javaagent:${jarPath}`
  return /\s/.test(jarPath) ? `"${flag}"` : flag
}
