# Development Setup Guide

> Generated: 2024-11-06

## Prerequisites

### Required Software

#### All Platforms
- **Node.js**: Version 18.0.0 or higher
- **npm**: Package manager (comes with Node.js)
- **Git**: Version control

#### macOS Specific
- **macOS**: 10.15 (Catalina) or later
- **Xcode Command Line Tools**: For compilation
- **ripgrep** (optional): For faster file searching
  ```bash
  brew install ripgrep
  ```

#### Linux Specific
- **bubblewrap**: Container runtime (required)
  ```bash
  # Ubuntu/Debian
  sudo apt-get install bubblewrap

  # Fedora/RHEL
  sudo dnf install bubblewrap

  # Arch
  sudo pacman -S bubblewrap
  ```

- **socat**: Socket relay (required)
  ```bash
  # Ubuntu/Debian
  sudo apt-get install socat

  # Fedora/RHEL
  sudo dnf install socat

  # Arch
  sudo pacman -S socat
  ```

- **ripgrep** (optional): For faster file searching
  ```bash
  # Ubuntu/Debian
  sudo apt-get install ripgrep

  # Other distributions
  cargo install ripgrep  # If Rust is installed
  ```

### Development Tools (Optional)
- **Bun**: For running tests (alternative to npm test)
- **Docker**: For building seccomp binaries
- **VS Code**: Recommended IDE with TypeScript support

## Setup Steps

### 1. Clone the Repository

```bash
git clone https://github.com/anthropic-experimental/sandbox-runtime.git
cd sandbox-runtime
```

### 2. Install Dependencies

```bash
npm install
```

This will install all required Node.js packages:
- commander (CLI framework)
- zod (validation)
- lodash-es (utilities)
- shell-quote (shell parsing)
- @pondwader/socks5-server (SOCKS proxy)

### 3. Build the Project

```bash
npm run build
```

This compiles TypeScript to JavaScript in the `dist/` directory.

### 4. Verify Installation

```bash
# Run a simple test command
npm run srt -- echo "Hello from sandbox!"

# Check version
npm run srt -- --version
```

## Configuration

### 1. Default Configuration Location

The sandbox looks for configuration at `~/.srt-settings.json`

### 2. Create Configuration File

Create `~/.srt-settings.json` with your desired settings:

```json
{
  "network": {
    "allowedDomains": [
      "api.github.com",
      "*.githubusercontent.com",
      "registry.npmjs.org"
    ],
    "deniedDomains": [
      "malicious.com"
    ],
    "allowedUnixSockets": []
  },
  "filesystem": {
    "allowWrite": [
      "./output",
      "/tmp"
    ],
    "denyWrite": [
      "/etc",
      "/usr"
    ],
    "denyRead": [
      "~/.ssh",
      "~/.aws"
    ]
  },
  "ignoreViolations": {
    "filesystem": [],
    "network": []
  },
  "httpProxyPort": 8080,
  "socksProxyPort": 8081
}
```

### 3. Custom Configuration Path

Use a custom configuration file:

```bash
npm run srt -- --settings ./my-config.json echo "test"
```

## Running the Application

### Development Mode

```bash
# Run with TypeScript directly (requires ts-node)
npm run dev -- echo "Hello"

# Run with debug output
npm run srt -- --debug curl https://example.com

# Run with custom settings
npm run srt -- --settings ./custom.json ls -la
```

### Production Mode

```bash
# Build first
npm run build

# Run the built version
node dist/cli.js echo "Hello"

# Or use npm script
npm run srt -- [command]
```

### Global Installation

```bash
# Install globally
npm install -g .

# Now use directly
srt echo "Hello from global install"
```

## Testing

### Run All Tests

```bash
npm test
```

### Run Specific Test Files

```bash
# Using Bun directly
bun test test/config-validation.test.ts

# Run integration tests only
bun test test/sandbox/integration.test.ts
```

### Test Categories

1. **Unit Tests**
   - Configuration validation
   - Schema parsing
   - Utility functions

2. **Integration Tests**
   - End-to-end sandbox execution
   - Proxy functionality
   - Violation detection

3. **Platform Tests**
   - macOS Seatbelt profiles
   - Linux seccomp filters

## Building Seccomp Binaries

### Prerequisites
- Docker installed and running

### Build Process

```bash
# Build for all architectures
npm run build:seccomp

# This creates:
# - vendor/seccomp/apply-seccomp-x64
# - vendor/seccomp/apply-seccomp-arm64
```

### Manual Build (Advanced)

```bash
# x86-64
docker run --rm -v $(pwd):/workspace -w /workspace gcc:latest \
  gcc -static -O2 vendor/seccomp-src/apply-seccomp.c \
  -o vendor/seccomp/apply-seccomp-x64

# ARM64
docker run --rm -v $(pwd):/workspace -w /workspace arm64v8/gcc:latest \
  gcc -static -O2 vendor/seccomp-src/apply-seccomp.c \
  -o vendor/seccomp/apply-seccomp-arm64
```

## Development Workflow

### 1. Making Changes

```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Make changes to TypeScript files
vim src/sandbox/my-component.ts

# 3. Build to verify compilation
npm run build

# 4. Run tests
npm test

# 5. Test manually
npm run srt -- echo "Testing my changes"
```

### 2. Code Quality

```bash
# Format code
npm run format

# Lint code
npm run lint

# Type check
npm run type-check
```

### 3. Debugging

Enable debug output:

```bash
# Via flag
npm run srt -- --debug [command]

# Via environment variable
DEBUG=1 npm run srt -- [command]
```

Add debug statements in code:

```typescript
import { debug } from './utils/debug.js'

debug('My debug message', { data: value })
```

### 4. Platform-Specific Development

#### macOS Development

Test Seatbelt profiles:

```bash
# Generate profile only
node -e "
  const { generateSeatbeltProfile } = require('./dist/sandbox/macos-sandbox-utils.js');
  const profile = generateSeatbeltProfile(config);
  console.log(profile);
"

# Test directly with sandbox-exec
sandbox-exec -f profile.sb echo "test"
```

#### Linux Development

Test bubblewrap configuration:

```bash
# Test bwrap directly
bwrap --ro-bind / / --dev /dev --proc /proc echo "test"

# Test with network namespace
bwrap --unshare-net --ro-bind / / echo "isolated"
```

## Troubleshooting

### Common Issues

#### 1. Build Errors

```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
npm run build
```

#### 2. Permission Errors (Linux)

```bash
# Ensure bubblewrap has correct permissions
which bwrap
ls -la $(which bwrap)

# May need user namespaces enabled
sudo sysctl kernel.unprivileged_userns_clone=1
```

#### 3. Proxy Port Conflicts

```bash
# Check if ports are in use
lsof -i :8080
lsof -i :8081

# Use custom ports in config
{
  "httpProxyPort": 9080,
  "socksProxyPort": 9081
}
```

#### 4. macOS Sandbox Violations

```bash
# Monitor violations in real-time
log stream --predicate 'sender == "sandboxd"'
```

#### 5. Missing ripgrep

```bash
# Install ripgrep or disable deny path checking
# The sandbox will work without it but with reduced functionality
```

## IDE Setup

### VS Code

1. Install extensions:
   - TypeScript and JavaScript Language Features
   - ESLint
   - Prettier

2. Settings (`.vscode/settings.json`):
```json
{
  "typescript.tsdk": "node_modules/typescript/lib",
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "eslint.enable": true
}
```

3. Debug configuration (`.vscode/launch.json`):
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug CLI",
      "program": "${workspaceFolder}/dist/cli.js",
      "args": ["--debug", "echo", "test"],
      "preLaunchTask": "npm: build"
    }
  ]
}
```

## Publishing (Maintainers Only)

```bash
# 1. Update version
npm version patch|minor|major

# 2. Build everything
npm run build
npm run build:seccomp

# 3. Test package
npm pack
tar -xzf *.tgz
cd package && npm install -g .

# 4. Publish to npm
npm publish --access public
```

## Additional Resources

- [README](https://github.com/anthropic-experimental/sandbox-runtime/blob/main/README.md)
- [Architecture Documentation](./architecture-overview.md)
- [Component Details](./components-detail.md)
- [API Reference](https://github.com/anthropic-experimental/sandbox-runtime#api)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Ensure all tests pass
5. Submit a pull request

For detailed contribution guidelines, see the repository's CONTRIBUTING.md file.