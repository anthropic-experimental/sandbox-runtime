import { encodeSandboxedCommand } from './sandbox-utils.js';
/**
 * In-memory tail for sandbox violations
 */
export class SandboxViolationStore {
    constructor() {
        this.violations = [];
        this.totalCount = 0;
        this.maxSize = 100;
        this.listeners = new Set();
    }
    addViolation(violation) {
        this.violations.push(violation);
        this.totalCount++;
        if (this.violations.length > this.maxSize) {
            this.violations = this.violations.slice(-this.maxSize);
        }
        this.notifyListeners();
    }
    getViolations(limit) {
        if (limit === undefined) {
            return [...this.violations];
        }
        return this.violations.slice(-limit);
    }
    getCount() {
        return this.violations.length;
    }
    getTotalCount() {
        return this.totalCount;
    }
    getViolationsForCommand(command) {
        const commandBase64 = encodeSandboxedCommand(command);
        return this.violations.filter(v => v.encodedCommand === commandBase64);
    }
    clear() {
        this.violations = [];
        // Don't reset totalCount when clearing
        this.notifyListeners();
    }
    subscribe(listener) {
        this.listeners.add(listener);
        listener(this.getViolations());
        return () => {
            this.listeners.delete(listener);
        };
    }
    notifyListeners() {
        // Always notify with all violations so listeners can track the full count
        const violations = this.getViolations();
        this.listeners.forEach(listener => listener(violations));
    }
}
//# sourceMappingURL=sandbox-violation-store.js.map