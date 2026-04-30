import { spawnSync } from 'node:child_process';
/**
 * Find the path to an executable, similar to the `which` command.
 * Uses Bun.which when running in Bun, falls back to spawnSync for Node.js.
 *
 * @param bin - The name of the executable to find
 * @returns The full path to the executable, or null if not found
 */
export function whichSync(bin) {
    // Check if we're running in Bun
    if (typeof globalThis.Bun !== 'undefined') {
        return globalThis.Bun.which(bin);
    }
    // Fallback to Node.js implementation
    const result = spawnSync('which', [bin], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 1000,
    });
    if (result.status === 0 && result.stdout) {
        return result.stdout.trim();
    }
    return null;
}
//# sourceMappingURL=which.js.map