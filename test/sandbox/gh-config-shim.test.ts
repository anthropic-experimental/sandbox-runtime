import { describe, test, expect } from 'bun:test'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildGhConfigYaml,
  prepareGhConfigDir,
  removeGhConfigDir,
  resolveGhConfigDir,
} from '../../src/sandbox/gh-config-shim.js'

// What `gh` writes on first run: every key present, http_unix_socket empty.
const DEFAULT_CONFIG = `# The current version of the config schema
version: 1
# What protocol to use when performing git operations. Supported values: ssh, https
git_protocol: https
# Aliases allow you to create nicknames for gh commands
aliases:
  co: pr checkout
# The path to a unix socket through which to send HTTP connections. If blank, HTTP traffic will be handled by net/http.DefaultTransport.
http_unix_socket:
# What web browser gh should use when opening URLs. If blank, will refer to environment.
browser:
`

describe('buildGhConfigYaml', () => {
  test('replaces the existing empty key in place (gh keeps the FIRST occurrence)', () => {
    const out = buildGhConfigYaml(DEFAULT_CONFIG, '/run/srt-gh.sock')
    const lines = out.split('\n')
    const idx = lines.findIndex(l => l.startsWith('http_unix_socket:'))
    expect(lines[idx]).toBe('http_unix_socket: "/run/srt-gh.sock"')
    // Exactly one occurrence, at the original position — not appended.
    expect(lines.filter(l => l.startsWith('http_unix_socket:'))).toHaveLength(1)
    expect(lines[idx + 1]).toMatch(/^# What web browser/)
    // Everything else untouched.
    expect(out.replace(lines[idx]!, 'http_unix_socket:')).toBe(DEFAULT_CONFIG)
  })

  test('replaces a user-set value too', () => {
    const cfg = 'version: 1\nhttp_unix_socket: /their/own.sock\n'
    expect(buildGhConfigYaml(cfg, '/ours.sock')).toBe(
      'version: 1\nhttp_unix_socket: "/ours.sock"\n',
    )
  })

  test('appends when the key is absent (with and without trailing newline)', () => {
    expect(buildGhConfigYaml('version: 1\n', '/s.sock')).toBe(
      'version: 1\nhttp_unix_socket: "/s.sock"\n',
    )
    expect(buildGhConfigYaml('version: 1', '/s.sock')).toBe(
      'version: 1\nhttp_unix_socket: "/s.sock"\n',
    )
    expect(buildGhConfigYaml('', '/s.sock')).toBe(
      'http_unix_socket: "/s.sock"\n',
    )
  })

  test('no user config at all → single-key file', () => {
    expect(buildGhConfigYaml(undefined, '/s.sock')).toBe(
      'http_unix_socket: "/s.sock"\n',
    )
  })

  test('leaves an indented (nested) key alone', () => {
    const cfg = 'hosts:\n  github.com:\n    http_unix_socket: nested\n'
    expect(buildGhConfigYaml(cfg, '/s.sock')).toBe(
      cfg + 'http_unix_socket: "/s.sock"\n',
    )
  })

  test('quotes YAML-significant characters in the path', () => {
    expect(buildGhConfigYaml(undefined, '/a "b"/c\\d.sock')).toBe(
      'http_unix_socket: "/a \\"b\\"/c\\\\d.sock"\n',
    )
  })
})

describe('resolveGhConfigDir', () => {
  test('GH_CONFIG_DIR > XDG_CONFIG_HOME/gh > ~/.config/gh', () => {
    expect(
      resolveGhConfigDir({ GH_CONFIG_DIR: '/x', XDG_CONFIG_HOME: '/y' }),
    ).toBe('/x')
    expect(resolveGhConfigDir({ XDG_CONFIG_HOME: '/y' })).toBe('/y/gh')
    expect(resolveGhConfigDir({})).toMatch(/\/\.config\/gh$/)
  })
})

describe('prepareGhConfigDir', () => {
  test('copies config with the socket set and symlinks hosts.yml', () => {
    const parent = mkdtempSync(join(tmpdir(), 'srt-ghshim-'))
    const source = join(parent, 'real')
    try {
      mkdirSync(source)
      writeFileSync(join(source, 'config.yml'), DEFAULT_CONFIG)
      writeFileSync(join(source, 'hosts.yml'), 'github.com:\n  user: me\n')

      const dir = prepareGhConfigDir('/run/gh.sock', source, parent)
      expect(dir).toBeDefined()
      expect(readFileSync(join(dir!, 'config.yml'), 'utf8')).toContain(
        'http_unix_socket: "/run/gh.sock"',
      )
      expect(lstatSync(join(dir!, 'hosts.yml')).isSymbolicLink()).toBe(true)
      expect(readlinkSync(join(dir!, 'hosts.yml'))).toBe(
        join(source, 'hosts.yml'),
      )
      // Reads through the link see the real file…
      expect(readFileSync(join(dir!, 'hosts.yml'), 'utf8')).toContain(
        'user: me',
      )
      // …and writes through it land in the real file (gh auth login).
      writeFileSync(join(dir!, 'hosts.yml'), 'github.com:\n  user: other\n')
      expect(readFileSync(join(source, 'hosts.yml'), 'utf8')).toContain(
        'user: other',
      )

      removeGhConfigDir(dir!)
      expect(existsSync(dir!)).toBe(false)
      // Removing the shim never touches the real config.
      expect(existsSync(join(source, 'hosts.yml'))).toBe(true)
    } finally {
      rmSync(parent, { recursive: true, force: true })
    }
  })

  test('works when the user has no gh config at all (dangling hosts.yml link)', () => {
    const parent = mkdtempSync(join(tmpdir(), 'srt-ghshim-'))
    try {
      const dir = prepareGhConfigDir(
        '/run/gh.sock',
        join(parent, 'nope'),
        parent,
      )
      expect(dir).toBeDefined()
      expect(readFileSync(join(dir!, 'config.yml'), 'utf8')).toBe(
        'http_unix_socket: "/run/gh.sock"\n',
      )
      expect(lstatSync(join(dir!, 'hosts.yml')).isSymbolicLink()).toBe(true)
      expect(existsSync(join(dir!, 'hosts.yml'))).toBe(false)
    } finally {
      rmSync(parent, { recursive: true, force: true })
    }
  })

  test('returns undefined (no throw) when the parent dir is not writable', () => {
    expect(
      prepareGhConfigDir('/run/gh.sock', '/nonexistent', '/nonexistent/parent'),
    ).toBeUndefined()
  })
})
