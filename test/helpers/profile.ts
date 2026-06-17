import { readFileSync } from 'node:fs'
import shellquote from 'shell-quote'

/**
 * Extract the seatbelt profile from a wrapped macOS sandbox command.
 * Handles both forms: a profile file passed via `sandbox-exec -f <path>`
 * (the default) and an inline profile passed via `sandbox-exec -p <profile>`
 * (the fallback when the profile file cannot be written).
 */
export function getProfileFromWrappedCommand(wrappedCommand: string): string {
  const args = shellquote.parse(wrappedCommand)
  const fIndex = args.indexOf('-f')
  if (fIndex !== -1) {
    return readFileSync(args[fIndex + 1] as string, 'utf8')
  }
  const pIndex = args.indexOf('-p')
  if (pIndex !== -1) {
    return args[pIndex + 1] as string
  }
  throw new Error('No -f or -p argument found in wrapped command')
}
