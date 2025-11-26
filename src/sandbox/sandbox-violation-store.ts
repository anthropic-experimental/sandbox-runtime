import { type SandboxViolationEvent } from './macos-sandbox-utils.js'
import { encodeSandboxedCommand } from './sandbox-utils.js'

/**
 * In-memory tail for sandbox violations
 */
export class SandboxViolationStore {
  private violations: SandboxViolationEvent[] = []
  private totalCount = 0
  private readonly maxSize = 500
  private listeners: Set<(violations: SandboxViolationEvent[]) => void> =
    new Set()
  private executionListeners: Map<
    string,
    Set<(violation: SandboxViolationEvent) => void>
  > = new Map()

  addViolation(violation: SandboxViolationEvent): void {
    this.violations.push(violation)
    this.totalCount++
    if (this.violations.length > this.maxSize) {
      this.violations = this.violations.slice(-this.maxSize)
    }
    this.notifyListeners()

    // Notify execution-specific listeners
    if (violation.executionId) {
      const listeners = this.executionListeners.get(violation.executionId)
      if (listeners) {
        listeners.forEach(listener => listener(violation))
      }
    }
  }

  getViolations(limit?: number): SandboxViolationEvent[] {
    if (limit === undefined) {
      return [...this.violations]
    }
    return this.violations.slice(-limit)
  }

  getCount(): number {
    return this.violations.length
  }

  getTotalCount(): number {
    return this.totalCount
  }

  getViolationsForCommand(command: string): SandboxViolationEvent[] {
    const commandBase64 = encodeSandboxedCommand(command)
    return this.violations.filter(v => v.encodedCommand === commandBase64)
  }

  getViolationsForExecution(executionId: string): SandboxViolationEvent[] {
    return this.violations.filter(v => v.executionId === executionId)
  }

  clear(): void {
    this.violations = []
    // Don't reset totalCount when clearing
    this.notifyListeners()
  }

  subscribe(
    listener: (violations: SandboxViolationEvent[]) => void,
  ): () => void {
    this.listeners.add(listener)
    listener(this.getViolations())
    return () => {
      this.listeners.delete(listener)
    }
  }

  subscribeToExecution(
    executionId: string,
    listener: (violation: SandboxViolationEvent) => void,
  ): () => void {
    if (!this.executionListeners.has(executionId)) {
      this.executionListeners.set(executionId, new Set())
    }
    this.executionListeners.get(executionId)!.add(listener)
    return () => {
      const listeners = this.executionListeners.get(executionId)
      if (listeners) {
        listeners.delete(listener)
        if (listeners.size === 0) {
          this.executionListeners.delete(executionId)
        }
      }
    }
  }

  private notifyListeners(): void {
    // Always notify with all violations so listeners can track the full count
    const violations = this.getViolations()
    this.listeners.forEach(listener => listener(violations))
  }
}
