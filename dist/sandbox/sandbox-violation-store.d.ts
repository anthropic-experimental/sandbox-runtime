import { type SandboxViolationEvent } from './macos-sandbox-utils.js'
/**
 * In-memory tail for sandbox violations
 */
export declare class SandboxViolationStore {
  private violations
  private totalCount
  private readonly maxSize
  private listeners
  addViolation(violation: SandboxViolationEvent): void
  getViolations(limit?: number): SandboxViolationEvent[]
  getCount(): number
  getTotalCount(): number
  getViolationsForCommand(command: string): SandboxViolationEvent[]
  clear(): void
  subscribe(listener: (violations: SandboxViolationEvent[]) => void): () => void
  private notifyListeners
}
//# sourceMappingURL=sandbox-violation-store.d.ts.map
