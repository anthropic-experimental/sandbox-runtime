import { spawn } from 'child_process';
import { text } from 'node:stream/consumers';
import { whichSync } from './which.js';
/**
 * Check if ripgrep (rg) is available synchronously
 * Returns true if rg is installed, false otherwise
 */
export function hasRipgrepSync() {
    return whichSync('rg') !== null;
}
/**
 * Execute ripgrep with the given arguments
 * @param args Command-line arguments to pass to rg
 * @param target Target directory or file to search
 * @param abortSignal AbortSignal to cancel the operation
 * @param config Ripgrep configuration (command and optional args)
 * @returns Array of matching lines (one per line of output)
 * @throws Error if ripgrep exits with non-zero status (except exit code 1 which means no matches)
 */
export async function ripGrep(args, target, abortSignal, config = { command: 'rg' }) {
    const { command, args: commandArgs = [], argv0 } = config;
    const child = spawn(command, [...commandArgs, ...args, target], {
        argv0,
        signal: abortSignal,
        timeout: 10000,
        windowsHide: true,
    });
    const [stdout, stderr, code] = await Promise.all([
        text(child.stdout),
        text(child.stderr),
        new Promise((resolve, reject) => {
            child.on('close', resolve);
            child.on('error', reject);
        }),
    ]);
    if (code === 0) {
        return stdout.trim().split('\n').filter(Boolean);
    }
    if (code === 1) {
        // Exit code 1 means "no matches found" - this is normal
        return [];
    }
    throw new Error(`ripgrep failed with exit code ${code}: ${stderr}`);
}
//# sourceMappingURL=ripgrep.js.map