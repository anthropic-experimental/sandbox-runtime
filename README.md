# Anthropic Sandbox Runtime (srt)

A lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container.

`srt` uses native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) and proxy-based network filtering. It can be used to sandbox the behaviour of agents, local MCP servers, bash commands and arbitrary processes.

> **Beta Research Preview**
>
> The Sandbox Runtime is a research preview developed for [Claude Code](https://www.claude.com/product/claude-code) to enable safer AI agents. It's being made available as an early open source preview to help the broader ecosystem build more secure agentic systems. As this is an early research preview, APIs and configuration formats may evolve. We welcome feedback and contributions to make AI agents safer by default!

## Installation

```bash
npm install -g @anthropic-ai/sandbox-runtime
```

## Basic Usage

```bash
# Network restrictions
$ srt "curl anthropic.com"
Running: curl anthropic.com
<html>...</html>  # Request succeeds

$ srt "curl example.com"
Running: curl example.com
Connection blocked by network allowlist  # Request blocked

# Filesystem restrictions
$ srt "cat README.md"
Running: cat README.md
# Anthropic Sandb...  # Current directory access allowed

$ srt "cat ~/.ssh/id_rsa"
Running: cat ~/.ssh/id_rsa
cat: /Users/ollie/.ssh/id_rsa: Operation not permitted  # Specific file blocked
```


## Overview

This package provides a standalone sandbox implementation that can be used as both a CLI tool and a library. It's designed with a **secure-by-default** philosophy tailored for common developer use cases: processes start with minimal access, and you explicitly poke only the holes you need.

**Key capabilities:**

- **Network restrictions**: Control which hosts/domains can be accessed via HTTP/HTTPS and other protocols
- **Filesystem restrictions**: Control which files/directories can be read/written (defaulting to allowing writes to the current working directory)
- **Unix socket restrictions**: Control access to local IPC sockets
- **Violation monitoring**: On macOS, tap into the system's sandbox violation log store for real-time alerts

### Example Use Case: Sandboxing MCP Servers

A key use case is sandboxing Model Context Protocol (MCP) servers to restrict their capabilities. For example, to sandbox the filesystem MCP server:

**Without sandboxing** (`.mcp.json`):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

**With sandboxing** (`.mcp.json`):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "srt",
      "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

Then configure restrictions in `~/.claude/settings.json`:
```json
{
  "permissions": {
    "deny": [
      "Edit(~/sensitive-folder)"
    ]
  }
}
```

Now the MCP server will be blocked from writing to the denied path:
```
> Write a file to ~/sensitive-folder
✗ Error: EPERM: operation not permitted, open '/Users/ollie/sensitive-folder/test.txt'
```

## How It Works

The sandbox uses OS-level primitives to enforce restrictions that apply to the entire process tree:

- **macOS**: Uses `sandbox-exec` with dynamically generated [Seatbelt profiles](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
- **Linux**: Uses [bubblewrap](https://github.com/containers/bubblewrap) for containerization with network namespace isolation

![0d1c612947c798aef48e6ab4beb7e8544da9d41a-4096x2305](https://github.com/user-attachments/assets/76c838a9-19ef-4d0b-90bb-cbe1917b3551)


### Dual Isolation Model

Both filesystem and network isolation are required for effective sandboxing. Without network isolation, a compromised process could exfiltrate SSH keys or other sensitive files. Without filesystem isolation, a process could escape the sandbox and gain unrestricted network access.

**Filesystem Isolation** enforces read and write restrictions:

- **Read**: By default, read access is allowed everywhere. You can deny specific paths (e.g., `Read(~/.ssh)`)
- **Write**: By default, write access is only allowed in the current working directory. You can allow additional paths (e.g., `Edit(/tmp)`), and deny within allowed paths (e.g., deny `Edit(./secret)` even though `.` is allowed)

**Network Isolation** routes all traffic through proxy servers running on the host:

- **Linux**: Requests are routed via the filesystem over a Unix domain socket. The network namespace of the sandboxed process is removed entirely, so all network traffic must go through the proxies running on the host (listening on Unix sockets that are bind-mounted into the sandbox)

- **macOS**: The Seatbelt profile allows communication only to a specific localhost port. The proxies listen on this port, creating a controlled channel for all network access

Both HTTP/HTTPS (via HTTP proxy) and other TCP traffic (via SOCKS5 proxy) are mediated by these proxies, which enforce your domain allowlists and denylists.

For more details on sandboxing in Claude Code, see:
- [Claude Code Sandboxing Documentation](https://docs.claude.com/en/docs/claude-code/sandboxing)
- [Beyond Permission Prompts: Making Claude Code More Secure and Autonomous](https://www.anthropic.com/engineering/claude-code-sandboxing)

## Architecture

```
src/
├── index.ts                  # Library exports
├── cli.ts                    # CLI entrypoint (srt command)
├── utils/                    # Shared utilities
│   ├── debug.ts             # Debug logging
│   ├── settings.ts          # Settings reader (permissions + sandbox config)
│   ├── platform.ts          # Platform detection
│   └── exec.ts              # Command execution utilities
└── sandbox/                  # Sandbox implementation
    ├── sandbox-manager.ts    # Main sandbox manager
    ├── sandbox-schemas.ts    # Zod schemas for validation
    ├── sandbox-violation-store.ts # Violation tracking
    ├── sandbox-utils.ts      # Shared sandbox utilities
    ├── http-proxy.ts         # HTTP/HTTPS proxy for network filtering
    ├── socks-proxy.ts        # SOCKS5 proxy for network filtering
    ├── linux-sandbox-utils.ts # Linux bubblewrap sandboxing
    └── macos-sandbox-utils.ts # macOS sandbox-exec sandboxing
```

## Usage

### As a CLI tool

The `srt` command (Anthropic Sandbox Runtime) wraps any command with security boundaries:

```bash
# Run a command in the sandbox
srt echo "hello world"

# With debug logging
srt --debug curl https://example.com

# Specify custom settings file
srt --settings /path/to/settings.json npm install
```

### As a library

```typescript
import { SandboxManager } from '@anthropic-ai/sandbox-runtime'
import { spawn } from 'child_process'

// Initialize the sandbox (starts proxy servers, etc.)
await SandboxManager.initialize()

// Wrap a command with sandbox restrictions
const sandboxedCommand = await SandboxManager.wrapWithSandbox('curl https://example.com')

// Execute the sandboxed command
const child = spawn(sandboxedCommand, { shell: true, stdio: 'inherit' })

// Handle exit
child.on('exit', (code) => {
  console.log(`Command exited with code ${code}`)
})

// Cleanup when done (optional, happens automatically on process exit)
await SandboxManager.reset()
```

#### Available exports

```typescript
// Main sandbox manager
export { SandboxManager } from '@anthropic-ai/sandbox-runtime'

// Violation tracking
export { SandboxViolationStore } from '@anthropic-ai/sandbox-runtime'

// TypeScript types
export type {
  SandboxAskCallback,
  IgnoreViolationsConfig,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  NetworkRestrictionConfig,
} from '@anthropic-ai/sandbox-runtime'
```

## Configuration

**NOTE: Configuration format is provisional and subject to change.** The current configuration system is borrowed from Claude Code's permission model and uses Claude Code settings files. This format may evolve as the sandbox runtime matures as a standalone tool.

### Settings File Locations

Settings are loaded and merged in priority order from:

1. **User settings**: `~/.claude/settings.json`
2. **Project settings**: `$CWD/.claude/settings.json`
3. **Local settings**: `$CWD/.claude/settings.local.json`
4. **Policy settings**: Platform-specific managed settings
   - macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
   - Linux: `/etc/claude-code/managed-settings.json`
5. **Flag settings**: Custom path via `--settings` flag

### Complete Configuration Example

```json
{
  "sandbox": {
    "enabled": true,
    "network": {
      "allowUnixSockets": ["/var/run/docker.sock"],
      "allowLocalBinding": false,
      "httpProxyPort": 8888,
      "socksProxyPort": 1080
    }
  },
  "permissions": {
    "allow": [
      "WebFetch(domain:github.com)",
      "WebFetch(domain:lfs.github.com)",
      "WebFetch(domain:api.github.com)",
      "WebFetch(domain:npmjs.org)",
      "Edit(src/)",
      "Edit(test/)",
      "Read(.)"
    ],
    "deny": [
      "Edit(.env)",
      "Edit(config/production.json)",
      "Read(~/.ssh)",
      "WebFetch(domain:malicious.com)"
    ]
  }
}
```

### Configuration Options

#### Sandbox Settings

- `sandbox.enabled` - Enable/disable sandboxing (boolean)
- `sandbox.network.allowUnixSockets` - Unix sockets that can be accessed (array of paths)
- `sandbox.network.allowLocalBinding` - Allow binding to local ports (boolean)
- `sandbox.network.httpProxyPort` - Port for your own HTTP proxy (default: uses built-in proxy)
- `sandbox.network.socksProxyPort` - Port for your own SOCKS5 proxy (default: uses built-in proxy)

#### Permission Rules

Permission rules provide fine-grained control and use Claude Code's permission syntax:

- `WebFetch(domain:example.com)` - Allow/deny network access to a domain
- `Edit(path)` - Allow/deny file write access
- `Read(path)` - Allow/deny file read access

**Path Syntax (macOS):**

Paths support git-style glob patterns on macOS, similar to `.gitignore` syntax:

- `*` - Matches any characters except `/` (e.g., `*.ts` matches `foo.ts` but not `foo/bar.ts`)
- `**` - Matches any characters including `/` (e.g., `src/**/*.ts` matches all `.ts` files in `src/`)
- `?` - Matches any single character except `/` (e.g., `file?.txt` matches `file1.txt`)
- `[abc]` - Matches any character in the set (e.g., `file[0-9].txt` matches `file3.txt`)

Examples:
- `Edit(src/)` - Allow write to entire `src/` directory
- `Edit(src/**/*.ts)` - Allow write to all `.ts` files in `src/` and subdirectories
- `Read(~/.ssh)` - Deny read to SSH directory
- `Edit(.env)` - Deny write to `.env` file (even if current directory is allowed)

**Path Syntax (Linux):**

**Linux currently does not support glob matching.** Use literal paths only:
- `Edit(src/)` - Allow write to `src/` directory
- `Read(/home/user/.ssh)` - Deny read to SSH directory

**All platforms:**
- Paths can be absolute (e.g., `/home/user/.ssh`) or relative to the current working directory (e.g., `./src`)
- `~` expands to the user's home directory

### Common Configuration Recipes

**Allow GitHub access** (all necessary endpoints):
```json
{
  "permissions": {
    "allow": [
      "WebFetch(domain:github.com)",
      "WebFetch(domain:lfs.github.com)",
      "WebFetch(domain:api.github.com)"
    ]
  }
}
```

**Restrict to specific directories:**
```json
{
  "permissions": {
    "allow": [
      "Edit(src/)",
      "Edit(test/)",
      "Read(.)"
    ],
    "deny": [
      "Edit(.env)",
      "Edit(secrets/)",
      "Read(~/.ssh)"
    ]
  }
}
```

### Common Issues and Tips

**Running Jest:** Use `--no-watchman` flag to avoid sandbox violations:
```bash
srt "jest --no-watchman"
```

Watchman accesses files outside the sandbox boundaries, which will trigger permission errors. Disabling it allows Jest to run with the built-in file watcher instead.

## Platform Support

- **macOS**: Uses `sandbox-exec` with custom profiles (no additional dependencies)
- **Linux**: Uses `bubblewrap` (bwrap) for containerization
- **Windows**: Not yet supported

### Platform-Specific Dependencies

**Linux requires:**
- `bubblewrap` - Container runtime
  - Ubuntu/Debian: `apt-get install bubblewrap`
  - Fedora: `dnf install bubblewrap`
  - Arch: `pacman -S bubblewrap`
- `socat` - Socket relay for proxy bridging
  - Ubuntu/Debian: `apt-get install socat`
  - Fedora: `dnf install socat`
  - Arch: `pacman -S socat`
- `ripgrep` - Fast search tool for deny path detection
  - Ubuntu/Debian: `apt-get install ripgrep`
  - Fedora: `dnf install ripgrep`
  - Arch: `pacman -S ripgrep`

**macOS requires:**
- `ripgrep` - Fast search tool for deny path detection
  - Install via Homebrew: `brew install ripgrep`
  - Or download from: https://github.com/BurntSushi/ripgrep/releases

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Type checking
npm run typecheck

# Lint code
npm run lint

# Format code
npm run format
```

## Implementation Details

### Network Isolation Architecture

The sandbox runs HTTP and SOCKS5 proxy servers on the host machine that filter all network requests based on permission rules:

1. **HTTP/HTTPS Traffic**: An HTTP proxy server intercepts requests and validates them against allowed/denied domains
2. **Other Network Traffic**: A SOCKS5 proxy handles all other TCP connections (SSH, database connections, etc.)
3. **Permission Enforcement**: The proxies enforce the `permissions` rules from your configuration

**Platform-specific proxy communication:**

- **Linux**: Requests are routed via the filesystem over Unix domain sockets (using `socat` for bridging). The network namespace is removed from the bubblewrap container, ensuring all network traffic must go through the proxies.

- **macOS**: The Seatbelt profile allows communication only to specific localhost ports where the proxies listen. All other network access is blocked.

### Filesystem Isolation

Filesystem restrictions are enforced at the OS level:

- **macOS**: Uses `sandbox-exec` with dynamically generated Seatbelt profiles that specify allowed read/write paths
- **Linux**: Uses `bubblewrap` with bind mounts, marking directories as read-only or read-write based on configuration

**Default filesystem permissions:**

- **Read**: Allowed everywhere by default. You can deny specific paths using `Read(path)` deny rules
  - Example: Deny `Read(~/.ssh)` to block access to SSH keys

- **Write**: Only allowed in the current working directory by default. You can:
  - Allow additional paths using `Edit(path)` allow rules (e.g., `Edit(/tmp)`)
  - Deny specific paths within allowed directories (e.g., deny `Edit(.env)` even though `.` is allowed)

This model lets you start with broad read access but tightly controlled write access, then refine both as needed.

### Violation Detection and Monitoring

When a sandboxed process attempts to access a restricted resource:

1. **Blocks the operation** at the OS level (returns `EPERM` error)
2. **Logs the violation** (platform-specific mechanisms)
3. **Notifies the user** (in Claude Code, this triggers a permission prompt)

**macOS**: The sandbox runtime taps into macOS's system sandbox violation log store. This provides real-time notifications with detailed information about what was attempted and why it was blocked. This is the same mechanism Claude Code uses for violation detection.

```bash
# View sandbox violations in real-time
log stream --predicate 'process == "sandbox-exec"' --style syslog
```

**Linux**: Bubblewrap doesn't provide built-in violation reporting. Use `strace` to trace system calls and identify blocked operations:

```bash
# Trace all denied operations
strace -f srt <your-command> 2>&1 | grep EPERM

# Trace specific file operations
strace -f -e trace=open,openat,stat,access srt <your-command> 2>&1 | grep EPERM

# Trace network operations
strace -f -e trace=network srt <your-command> 2>&1 | grep EPERM
```

### Advanced: Bring Your Own Proxy

For more sophisticated network filtering, you can configure the sandbox to use your own proxy instead of the built-in ones. This enables:

- **Traffic inspection**: Use tools like [mitmproxy](https://mitmproxy.org/) to inspect and modify traffic
- **Custom filtering logic**: Implement complex rules beyond simple domain allowlists
- **Audit logging**: Log all network requests for compliance or debugging

**Example with mitmproxy:**

```bash
# Start mitmproxy with custom filtering script
mitmproxy -s custom_filter.py --listen-port 8888

# Configure sandbox to use your proxy
{
  "sandbox": {
    "network": {
      "httpProxyPort": 8888
    }
  }
}
```

**Important security consideration:** Even with domain allowlists, exfiltration vectors may exist. For example, allowing `github.com` lets a process push to any repository. With a custom MITM proxy and proper certificate setup, you can inspect and filter specific API calls to prevent this.

### Security Limitations

* Network Sandboxing Limitations: The network filtering system operates by restricting the domains that processes are allowed to connect to. It does not otherwise inspect the traffic passing through the proxy and users are responsible for ensuring they only allow trusted domains in their policy. 

<Warning>
Users should be aware of potential risks that come from allowing broad domains like `github.com` that may allow for data exfiltration. Also, in some cases it may be possible to bypass the network filtering through [domain fronting](https://en.wikipedia.org/wiki/Domain_fronting).   
</Warning>

* Privilege Escalation via Unix Sockets: The `allowUnixSockets` configuration can inadvertently grant access to powerful system services that could lead to sandbox bypasses. For example, if it is used to allow access to `/var/run/docker.sock` this would effectively grant access to the host system through exploiting the docker socket. Users are encouraged to carefully consider any unix sockets that they allow through the sandbox. 
* Filesystem Permission Escalation: Overly broad filesystem write permissions can enable privilege escalation attacks. Allowing writes to directories containing executables in `$PATH`, system configuration directories, or user shell configuration files (`.bashrc`, `.zshrc`) can lead to code execution in different security contexts when other users or system processes access these files.
* Linux Sandbox Strength: The Linux implementation provides strong filesystem and network isolation but includes an `enableWeakerNestedSandbox` mode that enables it to work inside of Docker environments without privileged namespaces. This option considerably weakens security and should only be used incases where additional isolation is otherwise enforced.

### Known Limitations and Future Work

**Linux proxy bypass**: Currently uses environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) to direct traffic through proxies. This works for most applications but may be ignored by programs that don't respect these variables, leading to them being unable to connect to the internet.

**Future improvements:**

- **Proxychains support**: Add support for `proxychains` with `LD_PRELOAD` on Linux to intercept network calls at a lower level, making bypass more difficult

- **Linux violation monitoring**: Implement automatic `strace`-based violation detection for Linux, integrated with the violation store. Currently, Linux users must manually run `strace` to see violations, unlike macOS which has automatic violation monitoring via the system log store
