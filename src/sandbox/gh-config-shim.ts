import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { logForDebugging } from '../utils/debug.js'

/**
 * gh config shim: point the sandboxed `gh` at srt's host-header unix
 * socket (host-header-proxy.ts) without touching the user's real config.
 *
 * `http_unix_socket` is config-file only — gh has no env var for it — so
 * the sandboxed child gets `GH_CONFIG_DIR` set to a private directory:
 *
 *   config.yml  copy of the user's config with `http_unix_socket` set
 *   hosts.yml   symlink to the user's hosts.yml
 *
 * The symlink keeps auth state shared in both directions: `gh auth login`
 * inside the sandbox writes through it to the real file (go-gh writes with
 * os.WriteFile on the path, which follows symlinks). Only config.yml
 * changes made inside the sandbox (`gh config set`, `gh alias set`) land
 * in the copy and are lost when the sandbox shuts down.
 *
 * gh's data/state/cache dirs are resolved independently of GH_CONFIG_DIR
 * (XDG_DATA_HOME / ~/.local/share/gh etc.), so extensions and caches are
 * unaffected.
 */

/** The directory gh itself would read, per go-gh's ConfigDir(). */
export function resolveGhConfigDir(
  env: Readonly<Record<string, string | undefined>> = process.env,
): string {
  if (env.GH_CONFIG_DIR) return env.GH_CONFIG_DIR
  if (env.XDG_CONFIG_HOME) return join(env.XDG_CONFIG_HOME, 'gh')
  return join(homedir(), '.config', 'gh')
}

/**
 * Return `existing` (the user's config.yml, or undefined if absent) with
 * `http_unix_socket` set to `socketPath`.
 *
 * gh's default config.yml already carries an empty `http_unix_socket:`
 * line, and its YAML parser keeps the FIRST occurrence of a key — so the
 * key must be replaced in place, never appended below the existing one.
 * Top-level keys in gh's config are unindented, which is what the anchored
 * regex relies on; a nested `http_unix_socket` (there is none in gh's
 * schema) would be indented and left alone.
 */
export function buildGhConfigYaml(
  existing: string | undefined,
  socketPath: string,
): string {
  const line = `http_unix_socket: ${yamlQuote(socketPath)}`
  if (existing === undefined) return `${line}\n`
  if (/^http_unix_socket:/m.test(existing)) {
    // Replace every top-level occurrence so the file has one answer.
    return existing.replace(/^http_unix_socket:.*$/gm, line)
  }
  const sep = existing.length === 0 || existing.endsWith('\n') ? '' : '\n'
  return `${existing}${sep}${line}\n`
}

function yamlQuote(s: string): string {
  // Double-quoted YAML scalar: backslash and double-quote are the only
  // characters that need escaping for a filesystem path.
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

/**
 * Create the shim directory for `socketPath` and return its path, or
 * undefined if it could not be created (logged; the caller then simply
 * does not set GH_CONFIG_DIR and gh keeps today's behaviour).
 *
 * `sourceDir` is the user's real gh config dir; defaults to what gh would
 * resolve from this process's environment.
 */
export function prepareGhConfigDir(
  socketPath: string,
  sourceDir: string = resolveGhConfigDir(),
  parentDir: string = tmpdir(),
): string | undefined {
  const dir = join(
    parentDir,
    `srt-ghcfg-${process.pid}-${randomBytes(4).toString('hex')}`,
  )
  try {
    mkdirSync(dir, { mode: 0o700 })
    const userConfig = join(sourceDir, 'config.yml')
    const existing = existsSync(userConfig)
      ? readFileSync(userConfig, 'utf8')
      : undefined
    writeFileSync(
      join(dir, 'config.yml'),
      buildGhConfigYaml(existing, socketPath),
      { mode: 0o600 },
    )
    // Always link, even if the user has no hosts.yml yet: a dangling
    // symlink still lets `gh auth login` create the real file.
    symlinkSync(join(sourceDir, 'hosts.yml'), join(dir, 'hosts.yml'))
    return dir
  } catch (err) {
    logForDebugging(
      `gh config shim: could not prepare ${dir}: ${(err as Error).message}`,
      { level: 'error' },
    )
    rmSync(dir, { recursive: true, force: true })
    return undefined
  }
}

export function removeGhConfigDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true })
}
