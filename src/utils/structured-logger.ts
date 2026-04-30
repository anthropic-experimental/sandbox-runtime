/**
 * Structured JSON logger for CLI output.
 *
 * When enabled via --json flag, emits one JSON object per line to stderr.
 * All methods are no-ops when disabled, adding negligible overhead.
 */

// ============================================================================
// Event Types
// ============================================================================

interface BaseEvent {
  timestamp: string
  version: 1
  pid: number
}

type EventWithoutBase =
  | {
      type: 'cli_error'
      message: string
      code:
        | 'no_command'
        | 'spawn_failure'
        | 'config_error'
        | 'signal'
        | 'init_error'
        | 'fatal'
    }
  | {
      type: 'network_blocked'
      host: string
      port: number
      reason:
        | 'denied_by_rule'
        | 'no_matching_allow'
        | 'malformed_host'
        | 'no_config'
      matchingRule?: string
    }
  | { type: 'fs_violation'; detail: string }
  | {
      type: 'sandbox_summary'
      exitCode: number | null
      signal?: string
      totalNetworkBlocks: number
      durationMs: number
    }

export type StructuredLogEvent = EventWithoutBase & BaseEvent

// ============================================================================
// Logger Singleton
// ============================================================================

class StructuredLogger {
  private enabled = false
  private networkBlockCount = 0
  private startTime = 0

  enable(): void {
    this.enabled = true
    this.startTime = Date.now()
  }

  isEnabled(): boolean {
    return this.enabled
  }

  cliError(
    message: string,
    code:
      | 'no_command'
      | 'spawn_failure'
      | 'config_error'
      | 'signal'
      | 'init_error'
      | 'fatal',
  ): void {
    if (!this.enabled) return
    this.emit({ type: 'cli_error', message, code })
  }

  networkBlocked(
    host: string,
    port: number,
    reason:
      | 'denied_by_rule'
      | 'no_matching_allow'
      | 'malformed_host'
      | 'no_config',
    matchingRule?: string,
  ): void {
    if (!this.enabled) return
    this.networkBlockCount++
    const event: EventWithoutBase = {
      type: 'network_blocked',
      host,
      port,
      reason,
    }
    if (matchingRule) event.matchingRule = matchingRule
    this.emit(event)
  }

  fsViolation(detail: string): void {
    if (!this.enabled) return
    this.emit({ type: 'fs_violation', detail })
  }

  sandboxSummary(exitCode: number | null, signal?: string): void {
    if (!this.enabled) return
    const event: EventWithoutBase = {
      type: 'sandbox_summary',
      exitCode,
      totalNetworkBlocks: this.networkBlockCount,
      durationMs: Date.now() - this.startTime,
    }
    if (signal) event.signal = signal
    this.emit(event)
  }

  private emit(event: EventWithoutBase): void {
    const fullEvent: StructuredLogEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      version: 1,
      pid: process.pid,
    }
    process.stderr.write(JSON.stringify(fullEvent) + '\n')
  }
}

export const structuredLogger = new StructuredLogger()
