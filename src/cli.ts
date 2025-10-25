#!/usr/bin/env node
import { Command } from 'commander'
import { SandboxManager } from './index.js'
import { SandboxRuntimeConfigSchema, type SandboxRuntimeConfig } from './sandbox/sandbox-config.js'
import { spawn } from 'child_process'
import { logForDebugging } from './utils/debug.js'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'

/**
 * Load and validate sandbox configuration from a file
 */
function loadConfig(filePath: string): SandboxRuntimeConfig | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null
    }
    const content = fs.readFileSync(filePath, 'utf-8')
    if (content.trim() === '') {
      return null
    }

    // Parse JSON
    const parsed = JSON.parse(content)

    // Validate with zod schema
    const result = SandboxRuntimeConfigSchema.safeParse(parsed)

    if (!result.success) {
      console.error(`Invalid configuration in ${filePath}:`)
      result.error.issues.forEach((issue) => {
        const path = issue.path.join('.')
        console.error(`  - ${path}: ${issue.message}`)
      })
      return null
    }

    return result.data
  } catch (error) {
    // Log parse errors to help users debug invalid config files
    if (error instanceof SyntaxError) {
      console.error(`Invalid JSON in config file ${filePath}: ${error.message}`)
    } else {
      console.error(`Failed to load config from ${filePath}: ${error}`)
    }
    return null
  }
}

/**
 * Get default config path
 */
function getDefaultConfigPath(): string {
  return path.join(os.homedir(), '.srt-settings.json')
}

/**
 * Create a minimal default config if no config file exists
 */
function getDefaultConfig(): SandboxRuntimeConfig {
  return {
    network: {
      allowedDomains: [],
      deniedDomains: [],
    },
    filesystem: {
      denyRead: [],
      allowWrite: [],
      denyWrite: [],
    },
  }
}

async function main(): Promise<void> {
  const program = new Command()

  program
    .name('srt')
    .description(
      'Run commands in a sandbox with network and filesystem restrictions',
    )
    .version(process.env.npm_package_version || '1.0.0')

  // Default command - run command in sandbox
  program
    .argument('<command...>', 'command to run in the sandbox')
    .option('-d, --debug', 'enable debug logging')
    .option(
      '-s, --settings <path>',
      'path to config file (default: ~/.srt-settings.json)',
    )
    .allowUnknownOption()
    .action(
      async (
        commandArgs: string[],
        options: { debug?: boolean; settings?: string },
      ) => {
        try {
          // Enable debug logging if requested
          if (options.debug) {
            process.env.DEBUG = 'true'
          }

          // Load config from file
          const configPath = options.settings || getDefaultConfigPath()
          let runtimeConfig = loadConfig(configPath)

          if (!runtimeConfig) {
            logForDebugging(`No config found at ${configPath}, using default config`)
            runtimeConfig = getDefaultConfig()
          }

          // Initialize sandbox with config
          logForDebugging('Initializing sandbox...')
          await SandboxManager.initialize(runtimeConfig)

          // Join command arguments into a single command string
          const command = commandArgs.join(' ')
          logForDebugging(`Original command: ${command}`)

          logForDebugging(
            JSON.stringify(
              SandboxManager.getNetworkRestrictionConfig(),
              null,
              2,
            ),
          )

          // Wrap the command with sandbox restrictions
          const sandboxedCommand = await SandboxManager.wrapWithSandbox(command)

          // Execute the sandboxed command
          console.log(`Running: ${command}`)
          const child = spawn(sandboxedCommand, {
            shell: true,
            stdio: 'inherit',
          })

          // Handle process exit
          child.on('exit', (code, signal) => {
            if (signal) {
              console.error(`Process killed by signal: ${signal}`)
              process.exit(1)
            }
            process.exit(code ?? 0)
          })

          child.on('error', error => {
            console.error(`Failed to execute command: ${error.message}`)
            process.exit(1)
          })

          // Handle cleanup on interrupt
          process.on('SIGINT', () => {
            child.kill('SIGINT')
          })

          process.on('SIGTERM', () => {
            child.kill('SIGTERM')
          })
        } catch (error) {
          console.error(
            `Error: ${error instanceof Error ? error.message : String(error)}`,
          )
          process.exit(1)
        }
      },
    )

  program.parse()
}

main().catch(error => {
  console.error('Fatal error:', error)
  process.exit(1)
})
