#!/usr/bin/env node
import { Command } from 'commander'
import shellquote from 'shell-quote'
import { SandboxManager } from './index.js'
import type { SandboxRuntimeConfig } from './sandbox/sandbox-config.js'
import { spawn } from 'child_process'
import { logForDebugging } from './utils/debug.js'
import { loadConfig, loadConfigFromString } from './utils/config-loader.js'
import * as readline from 'readline'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'

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
      allowRead: [],
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
    .argument('[command...]', 'command to run in the sandbox')
    .option('-d, --debug', 'enable debug logging')
    .option(
      '-s, --settings <path>',
      'path to config file (default: ~/.srt-settings.json)',
    )
    .option(
      '-c <command>',
      'run command string directly (like sh -c), no escaping applied',
    )
    .option(
      '--control-fd <fd>',
      'read config updates from file descriptor (JSON lines protocol)',
      parseInt,
    )
    .allowUnknownOption()
    .action(
      async (
        commandArgs: string[],
        options: {
          debug?: boolean
          settings?: string
          c?: string
          controlFd?: number
        },
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
            logForDebugging(
              `No config found at ${configPath}, using default config`,
            )
            runtimeConfig = getDefaultConfig()
          }

          // Initialize sandbox with config
          logForDebugging('Initializing sandbox...')
          await SandboxManager.initialize(
            runtimeConfig,
            undefined,
            !!process.env.SRT_DEBUG,
          )

          // Set up control fd for dynamic config updates if specified
          let controlReader: readline.Interface | null = null
          if (options.controlFd !== undefined) {
            try {
              const controlStream = fs.createReadStream('', {
                fd: options.controlFd,
              })
              controlReader = readline.createInterface({
                input: controlStream,
                crlfDelay: Infinity,
              })

              controlReader.on('line', line => {
                const newConfig = loadConfigFromString(line)
                if (newConfig) {
                  logForDebugging(
                    `Config updated from control fd: ${JSON.stringify(newConfig)}`,
                  )
                  SandboxManager.updateConfig(newConfig)
                } else if (line.trim()) {
                  // Only log non-empty lines that failed to parse
                  logForDebugging(
                    `Invalid config on control fd (ignored): ${line}`,
                  )
                }
              })

              controlReader.on('error', err => {
                logForDebugging(`Control fd error: ${err.message}`)
              })

              logForDebugging(
                `Listening for config updates on fd ${options.controlFd}`,
              )
            } catch (err) {
              logForDebugging(
                `Failed to open control fd ${options.controlFd}: ${err instanceof Error ? err.message : String(err)}`,
              )
            }
          }

          // Cleanup control reader on exit
          process.on('exit', () => {
            controlReader?.close()
          })

          // Determine command string based on mode
          let command: string
          if (options.c) {
            // -c mode: use command string directly, no escaping
            command = options.c
            logForDebugging(`Command string mode (-c): ${command}`)
          } else if (commandArgs.length > 0) {
            // Default mode: shell-quote each argv so metacharacters like
            // parentheses, quotes, backticks, and $ survive the
            // `spawn(cmd, { shell: true })` re-parse below.
            command = shellquote.quote(commandArgs)
            logForDebugging(`Original command: ${command}`)
          } else {
            console.error(
              'Error: No command specified. Use -c <command> or provide command arguments.',
            )
            process.exit(1)
          }

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
          const child = spawn(sandboxedCommand, {
            shell: true,
            stdio: 'inherit',
          })

          // Handle process exit
          child.on('exit', (code, signal) => {
            // Clean up bwrap mount point artifacts before exiting.
            // On Linux, bwrap creates empty files on the host when protecting
            // non-existent deny paths. This removes them.
            SandboxManager.cleanupAfterCommand()

            if (signal) {
              if (signal === 'SIGINT' || signal === 'SIGTERM') {
                process.exit(0)
              } else {
                console.error(`Process killed by signal: ${signal}`)
                process.exit(1)
              }
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
