import * as fs from 'fs';
import { SandboxRuntimeConfigSchema, } from '../sandbox/sandbox-config.js';
/**
 * Parse and validate sandbox configuration from a string
 * Used for parsing config from control fd (JSON lines protocol)
 */
export function loadConfigFromString(content) {
    if (!content.trim()) {
        return null;
    }
    try {
        const parsed = JSON.parse(content);
        const result = SandboxRuntimeConfigSchema.safeParse(parsed);
        if (!result.success) {
            return null;
        }
        return result.data;
    }
    catch {
        return null;
    }
}
/**
 * Load and validate sandbox configuration from a file
 */
export function loadConfig(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            return null;
        }
        const content = fs.readFileSync(filePath, 'utf-8');
        if (content.trim() === '') {
            return null;
        }
        // Parse JSON
        const parsed = JSON.parse(content);
        // Validate with zod schema
        const result = SandboxRuntimeConfigSchema.safeParse(parsed);
        if (!result.success) {
            console.error(`Invalid configuration in ${filePath}:`);
            result.error.issues.forEach(issue => {
                const path = issue.path.join('.');
                console.error(`  - ${path}: ${issue.message}`);
            });
            return null;
        }
        return result.data;
    }
    catch (error) {
        // Log parse errors to help users debug invalid config files
        if (error instanceof SyntaxError) {
            console.error(`Invalid JSON in config file ${filePath}: ${error.message}`);
        }
        else {
            console.error(`Failed to load config from ${filePath}: ${error}`);
        }
        return null;
    }
}
//# sourceMappingURL=config-loader.js.map