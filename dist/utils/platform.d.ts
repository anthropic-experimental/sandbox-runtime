/**
 * Platform detection utilities
 */
export type Platform = 'macos' | 'linux' | 'windows' | 'unknown'
/**
 * Get the WSL version (1 or 2+) if running in WSL.
 * Returns undefined if not running in WSL.
 */
export declare function getWslVersion(): string | undefined
/**
 * Detect the current platform.
 * Note: All Linux including WSL returns 'linux'. Use getWslVersion() to detect WSL1 (unsupported).
 */
export declare function getPlatform(): Platform
//# sourceMappingURL=platform.d.ts.map
