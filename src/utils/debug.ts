import { spawn } from 'node:child_process'

/**
 * Log a proxy deny via the system logger so it is visible in system logs
 * without writing to stderr.
 *
 * Writing to stderr is avoided because the srt host process shares a terminal
 * with the sandboxed child, and stderr output interrupts TUI rendering in
 * applications such as Claude Code CLI.
 *
 * On macOS the message is written via `logger`, which emits to the unified
 * log. The message is suffixed with `_SBX` - the same tag srt uses in its
 * seatbelt deny rules - so it can be captured alongside other srt violations:
 *
 *   log stream --predicate 'eventMessage ENDSWITH "_SBX"' --style compact
 *
 * Example output:
 *   srt proxy-blocked: HTTPS-CONNECT api.example.com:443_SBX
 *
 * On Linux the message is written via `logger` to syslog, without the _SBX
 * suffix (which is macOS seatbelt-specific). Monitor with:
 *
 *   journalctl -f    (systemd systems)
 *   tail -f /var/log/syslog    (syslog-ng / rsyslog systems)
 *
 * Example output:
 *   srt proxy-blocked: HTTPS-CONNECT api.example.com:443
 */
export function logProxyDeny(
  protocol: 'HTTPS-CONNECT' | 'HTTP' | 'SOCKS',
  hostname: string,
  port: number,
): void {
  if (process.platform === 'darwin') {
    // Suffix _SBX matches the seatbelt deny tag used throughout the srt
    // profile, making proxy-blocks visible in the same log stream as
    // filesystem and mach-lookup denials:
    //   log stream --predicate 'eventMessage ENDSWITH "_SBX"'
    const message = `srt proxy-blocked: ${protocol} ${hostname}:${port}_SBX`
    spawn('logger', [message], { detached: true, stdio: 'ignore' }).unref()
  } else if (process.platform === 'linux') {
    // No _SBX suffix on Linux - that convention is macOS seatbelt-specific.
    const message = `srt proxy-blocked: ${protocol} ${hostname}:${port}`
    spawn('logger', [message], { detached: true, stdio: 'ignore' }).unref()
  }
  // Also surface in SRT_DEBUG stream for users with verbose logging enabled
  logForDebugging(
    `proxy-blocked: ${protocol} ${hostname}:${port} - not in allowedDomains`,
    { level: 'error' },
  )
}

/**
 * Simple debug logging for standalone sandbox
 */
export function logForDebugging(
  message: string,
  options?: { level?: 'info' | 'error' | 'warn' },
): void {
  // Only log if SRT_DEBUG environment variable is set
  // Using SRT_DEBUG instead of DEBUG to avoid conflicts with other tools
  // (DEBUG is commonly used by Node.js debug libraries and VS Code)
  if (!process.env.SRT_DEBUG) {
    return
  }

  const level = options?.level || 'info'
  const prefix = '[SandboxDebug]'

  // Always use stderr to avoid corrupting stdout JSON streams
  switch (level) {
    case 'error':
      console.error(`${prefix} ${message}`)
      break
    case 'warn':
      console.warn(`${prefix} ${message}`)
      break
    default:
      console.error(`${prefix} ${message}`)
  }
}
