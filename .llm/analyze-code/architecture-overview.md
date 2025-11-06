# Architecture Overview

> Generated: 2024-11-06
> Repository: sandbox-runtime

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Technology Stack](#technology-stack)
3. [Architecture Pattern](#architecture-pattern)
4. [Core Components](#core-components)
5. [Data Layer](#data-layer)
6. [Infrastructure](#infrastructure)
7. [Development Workflow](#development-workflow)

---

## Executive Summary

The **Anthropic Sandbox Runtime (srt)** is a lightweight sandboxing tool designed to enforce filesystem and network restrictions on arbitrary processes at the OS level without requiring containers. Built primarily in TypeScript, it provides a research preview for Claude Code to enable safer AI agent execution through dual isolation layers: filesystem restrictions and network filtering.

Key capabilities:
- Cross-platform support (macOS and Linux)
- Filesystem isolation with configurable read/write permissions
- Network traffic filtering through proxy servers
- Real-time violation detection and monitoring
- CLI tool and library API for integration

## Project Structure

```
sandbox-runtime/
├── src/                     # TypeScript source code
│   ├── sandbox/            # Core sandbox implementation
│   ├── utils/              # Shared utilities
│   ├── cli.ts              # CLI entrypoint
│   └── index.ts            # Library exports
├── test/                    # Test suite
├── vendor/                  # Pre-built binaries
│   ├── seccomp/            # BPF filters
│   └── seccomp-src/        # C source
├── scripts/                 # Build scripts
└── config files            # Package, TypeScript, linting
```

## Technology Stack

### Core Technologies
- **Language**: TypeScript 5.6.3
- **Runtime**: Node.js >= 18.0.0
- **Module System**: ECMAScript Modules (ESM)
- **Target**: ES2020

### Main Dependencies
```json
{
  "commander": "^12.1.0",        // CLI argument parsing
  "zod": "^3.24.1",              // Schema validation
  "lodash-es": "^4.17.21",       // Utility functions
  "shell-quote": "^1.8.3",       // Shell command parsing
  "@pondwader/socks5-server": "^1.0.10"  // SOCKS proxy
}
```

### Development Tools
- **Build**: TypeScript Compiler (tsc)
- **Test**: Bun test runner
- **Lint**: ESLint 9.14.0
- **Format**: Prettier 3.3.3
- **CI/CD**: GitHub Actions

### Platform Dependencies
**Linux**:
- bubblewrap (bwrap) - Container runtime
- socat - Socket relay
- ripgrep (rg) - Fast file search

**macOS**:
- sandbox-exec - System sandboxing
- ripgrep (rg) - Fast file search

## Architecture Pattern

The codebase follows several architectural patterns:

### 1. **Dual-Layer Security Architecture**
Two independent isolation mechanisms:
- **Filesystem Layer**: Platform-specific sandbox (sandbox-exec on macOS, bubblewrap on Linux)
- **Network Layer**: Proxy-based filtering (HTTP and SOCKS5)

### 2. **Platform Abstraction Pattern**
```
SandboxManager (orchestrator)
    ├── macOS Implementation
    │   └── sandbox-exec + Seatbelt
    └── Linux Implementation
        └── bubblewrap + seccomp
```

### 3. **Proxy Pattern for Network Filtering**
All network traffic routed through local proxies that enforce domain rules:
```
Application → HTTP/SOCKS Proxy → Domain Validation → External Network
```

### 4. **Configuration-Driven Design**
Zod schemas define and validate all configuration:
- Runtime configuration
- Network restrictions
- Filesystem permissions

## Core Components

### 1. SandboxManager (`src/sandbox/sandbox-manager.ts`)
**Responsibility**: Main orchestrator for sandbox operations
- Initializes and manages proxy servers
- Delegates to platform-specific implementations
- Handles cleanup on process termination
- ~400 lines of code

### 2. Platform-Specific Implementations

#### macOS (`src/sandbox/macos-sandbox-utils.ts`)
**Responsibility**: macOS sandboxing via sandbox-exec
- Generates Seatbelt profiles dynamically
- Converts glob patterns to regex rules
- Monitors sandbox violations
- ~700 lines of code

#### Linux (`src/sandbox/linux-sandbox-utils.ts`)
**Responsibility**: Linux sandboxing via bubblewrap
- Configures bubblewrap container
- Applies seccomp BPF filters
- Bridges network via Unix sockets
- ~600 lines of code

### 3. Network Proxies

#### HTTP Proxy (`src/sandbox/http-proxy.ts`)
**Responsibility**: Filter HTTP/HTTPS traffic
- Handles CONNECT method for HTTPS
- Validates domains against allowlist
- ~150 lines of code

#### SOCKS5 Proxy (`src/sandbox/socks-proxy.ts`)
**Responsibility**: Filter SOCKS5 connections
- Wraps third-party SOCKS server
- Applies domain filtering
- ~100 lines of code

### 4. Configuration System (`src/sandbox/sandbox-config.ts`)
**Responsibility**: Define and validate configuration
- Zod schemas for type safety
- Default configuration values
- Runtime validation
- ~200 lines of code

### 5. Violation Store (`src/sandbox/sandbox-violation-store.ts`)
**Responsibility**: Track and report violations
- Collects filesystem/network violations
- Provides violation summary
- Integrates with platform monitors

### 6. CLI Interface (`src/cli.ts`)
**Responsibility**: Command-line interface
- Parses command arguments
- Loads configuration
- Wraps commands with sandbox
- ~150 lines of code

## Data Layer

### Configuration Storage
- **Primary**: `~/.srt-settings.json` (user home directory)
- **Override**: Via `--settings` flag
- **Format**: JSON validated against Zod schemas

### Runtime State
- No persistent database
- In-memory violation tracking
- Module-level singleton state in SandboxManager

### Pre-built Assets
```
vendor/
├── seccomp/
│   ├── apply-seccomp-x64     # x86-64 binary
│   └── apply-seccomp-arm64   # ARM64 binary
└── seccomp-src/
    └── apply-seccomp.c        # Source code
```

## Infrastructure

### Build Pipeline
```bash
npm run build          # TypeScript compilation
npm run postbuild      # Copy vendor files
npm run build:seccomp  # Cross-compile binaries (Docker)
```

### Testing Infrastructure
- **Framework**: Bun test runner
- **Coverage**: Unit and integration tests
- **CI Platforms**:
  - Ubuntu (x86-64, arm64)
  - macOS 13 (x86-64)
  - macOS 14 (arm64)

### Package Distribution
- **Registry**: npm (@anthropic-ai/sandbox-runtime)
- **Entry Points**:
  - Library: `dist/index.js`
  - CLI: `dist/cli.js`
  - Types: `dist/index.d.ts`

## Development Workflow

### 1. Local Development
```bash
# Install dependencies
npm install

# Build project
npm run build

# Run tests
npm test

# Lint code
npm run lint

# Format code
npm run format
```

### 2. Testing Sandbox
```bash
# Test with simple command
npm run srt -- echo "Hello World"

# Test with network restrictions
npm run srt -- --debug curl https://example.com
```

### 3. Configuration Development
Edit `~/.srt-settings.json`:
```json
{
  "network": {
    "allowedDomains": ["api.example.com"],
    "deniedDomains": ["malicious.com"]
  },
  "filesystem": {
    "allowWrite": ["./output"],
    "denyRead": ["./secrets"]
  }
}
```

### 4. Platform-Specific Development

**macOS Development**:
- Modify Seatbelt profile generation in `macos-sandbox-utils.ts`
- Test with `sandbox-exec` directly

**Linux Development**:
- Modify bubblewrap configuration in `linux-sandbox-utils.ts`
- Test with `bwrap` directly
- Regenerate seccomp filters if needed

### 5. Release Process
1. Update version in `package.json`
2. Run full test suite
3. Build project and seccomp binaries
4. Publish to npm registry

## Security Considerations

1. **Network Filtering Limitations**:
   - Operates at domain level only
   - Does not inspect packet contents
   - Relies on proxy compliance

2. **Filesystem Restrictions**:
   - Platform-dependent enforcement
   - Glob pattern support varies
   - Symbolic link handling differences

3. **Unix Socket Risks**:
   - Can provide access to powerful services
   - Requires careful allowlist configuration

4. **Docker Compatibility**:
   - Weaker sandbox in nested environments
   - Limited seccomp support

## Performance Characteristics

- **Startup Overhead**: ~100-200ms for proxy initialization
- **Runtime Impact**: Minimal for filesystem, proxy adds network latency
- **Memory Usage**: ~50-100MB for proxy processes
- **Violation Detection**: Real-time on macOS, post-execution on Linux