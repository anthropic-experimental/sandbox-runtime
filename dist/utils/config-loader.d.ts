import { type SandboxRuntimeConfig } from '../sandbox/sandbox-config.js'
/**
 * Parse and validate sandbox configuration from a string
 * Used for parsing config from control fd (JSON lines protocol)
 */
export declare function loadConfigFromString(
  content: string,
): SandboxRuntimeConfig | null
/**
 * Load and validate sandbox configuration from a file
 */
export declare function loadConfig(
  filePath: string,
): SandboxRuntimeConfig | null
//# sourceMappingURL=config-loader.d.ts.map
