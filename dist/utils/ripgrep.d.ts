export interface RipgrepConfig {
  command: string
  args?: string[]
  /** Override argv[0] when spawning (for multicall binaries that dispatch on argv[0]) */
  argv0?: string
}
/**
 * Check if ripgrep (rg) is available synchronously
 * Returns true if rg is installed, false otherwise
 */
export declare function hasRipgrepSync(): boolean
/**
 * Execute ripgrep with the given arguments
 * @param args Command-line arguments to pass to rg
 * @param target Target directory or file to search
 * @param abortSignal AbortSignal to cancel the operation
 * @param config Ripgrep configuration (command and optional args)
 * @returns Array of matching lines (one per line of output)
 * @throws Error if ripgrep exits with non-zero status (except exit code 1 which means no matches)
 */
export declare function ripGrep(
  args: string[],
  target: string,
  abortSignal: AbortSignal,
  config?: RipgrepConfig,
): Promise<string[]>
//# sourceMappingURL=ripgrep.d.ts.map
