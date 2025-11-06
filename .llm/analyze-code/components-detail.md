# Components Detail

> Generated: 2024-11-06

## Overview
This document provides detailed information about each component in the sandbox-runtime codebase.

---

## Entry Points

### CLI Entry (`src/cli.ts`)
```typescript
// Main CLI executable entry point
// Provides the 'srt' command
```
- **Purpose**: Command-line interface for sandbox-runtime
- **Lines**: ~150
- **Key Functions**:
  - Argument parsing with Commander
  - Configuration loading from settings file
  - Command wrapping with sandbox restrictions
  - Error handling and user feedback

### Library Entry (`src/index.ts`)
```typescript
// Public API exports for library usage
```
- **Purpose**: Exports for programmatic usage
- **Exports**:
  - `SandboxManager` class
  - Configuration types and schemas
  - Utility types and interfaces
  - Violation store

## Source Code Organization

### `/src/sandbox` Directory
Core sandbox implementation components:

#### `sandbox-manager.ts` (400 lines)
> Main orchestrator for sandbox operations
- **Responsibilities**:
  - Initialize HTTP and SOCKS5 proxy servers
  - Determine and apply platform-specific sandbox
  - Manage proxy lifecycle
  - Handle cleanup on exit
- **Key Methods**:
  - `static async runCommand()` - Main entry point
  - `static async initialize()` - Setup proxies
  - `static cleanup()` - Teardown resources

#### `sandbox-config.ts` (200 lines)
> Configuration schemas and validation
- **Schemas**:
  - `SandboxRuntimeConfigSchema` - Main config
  - `NetworkConfigSchema` - Network restrictions
  - `FilesystemConfigSchema` - Filesystem rules
  - `IgnoreViolationsConfigSchema` - Violation filters
- **Validation**: Zod-based runtime validation

#### `macos-sandbox-utils.ts` (700 lines)
> macOS-specific sandbox implementation
- **Key Features**:
  - Dynamic Seatbelt profile generation
  - Glob pattern to regex conversion (.gitignore style)
  - Real-time violation monitoring via log streaming
  - Unix socket allowlist support
- **Profile Generation**:
  - Filesystem rules (read/write permissions)
  - Network restrictions (proxy-only connections)
  - Process permissions

#### `linux-sandbox-utils.ts` (600 lines)
> Linux-specific sandbox implementation
- **Technologies**:
  - Bubblewrap (bwrap) for containerization
  - Seccomp BPF for system call filtering
  - Socat for Unix socket bridging
- **Features**:
  - Bind mount configuration
  - Network namespace isolation
  - Weaker sandbox mode for Docker

#### `http-proxy.ts` (150 lines)
> HTTP/HTTPS proxy server
- **Protocol Support**: HTTP/1.1, HTTPS via CONNECT
- **Domain Validation**: Regex-based allowlist/denylist
- **Connection Handling**: Stream piping for tunneling

#### `socks-proxy.ts` (100 lines)
> SOCKS5 proxy server
- **Based On**: `@pondwader/socks5-server`
- **Features**:
  - Domain-level filtering
  - Connection validation
  - Error handling

#### `sandbox-violation-store.ts` (100 lines)
> Violation tracking and reporting
- **Tracks**:
  - Filesystem read/write violations
  - Network connection violations
- **Methods**:
  - `addViolation()` - Record violation
  - `getViolationSummary()` - Generate report
  - `hasViolations()` - Check status

#### `generate-seccomp-filter.ts` (150 lines)
> Seccomp BPF filter generation
- **Purpose**: Create architecture-specific BPF programs
- **Architectures**: x86-64, ARM64
- **System Calls**: Blocks Unix socket creation

#### `sandbox-schemas.ts` (50 lines)
> Internal type definitions
- **Types**:
  - Platform detection enums
  - Internal configuration shapes
  - Validation helpers

#### `sandbox-utils.ts` (100 lines)
> Shared utility functions
- **Functions**:
  - Path normalization
  - Pattern matching
  - Configuration merging
  - Error formatting

### `/src/utils` Directory
General utility modules:

#### `debug.ts` (50 lines)
> Debug logging utilities
- **Features**:
  - Conditional logging based on DEBUG flag
  - Formatted output
  - Performance timing

#### `platform.ts` (50 lines)
> Platform detection and helpers
- **Detects**:
  - Operating system (macOS, Linux)
  - Architecture (x64, arm64)
  - Environment variables

#### `ripgrep.ts` (100 lines)
> Fast search integration
- **Purpose**: Detect denied paths efficiently
- **Features**:
  - Glob pattern support
  - Parallel search
  - Result parsing

## Test Organization

### `/test` Directory

#### `config-validation.test.ts`
> Configuration schema validation tests
- Validates Zod schemas
- Tests edge cases
- Ensures defaults

#### `configurable-proxy-ports.test.ts`
> Proxy port configuration tests
- Dynamic port allocation
- Port conflict handling
- Configuration override

### `/test/sandbox` Directory

#### `integration.test.ts`
> End-to-end sandbox tests
- Command execution
- Violation detection
- Proxy functionality

#### `macos-seatbelt.test.ts`
> macOS-specific profile tests
- Seatbelt syntax validation
- Rule generation
- Pattern conversion

#### `seccomp-filter.test.ts`
> Linux BPF filter tests
- Filter generation
- Architecture compatibility
- System call blocking

## Vendor Components

### `/vendor/seccomp` Directory
Pre-compiled seccomp binaries:
- `apply-seccomp-x64` - x86-64 binary (7KB)
- `apply-seccomp-arm64` - ARM64 binary (7KB)

### `/vendor/seccomp-src` Directory
Source code for seccomp binaries:
- `apply-seccomp.c` - C implementation
- Cross-compiled via Docker

## File Type Distribution

```
TypeScript (.ts)     - 85% (main implementation)
JSON (.json)         - 5%  (configuration)
JavaScript (.js)     - 3%  (config files)
Shell (.sh)          - 2%  (build scripts)
C (.c)              - 2%  (seccomp source)
Markdown (.md)       - 2%  (documentation)
YAML (.yml)         - 1%  (CI/CD)
```

## Component Dependencies

### Internal Dependencies
```
cli.ts
  └── sandbox-manager.ts
      ├── macos-sandbox-utils.ts
      ├── linux-sandbox-utils.ts
      ├── http-proxy.ts
      ├── socks-proxy.ts
      └── sandbox-violation-store.ts

sandbox-config.ts
  └── Used by all components

utils/*
  └── Used throughout codebase
```

### External Dependencies
```
Platform Tools:
  macOS:
    └── sandbox-exec (system)
    └── ripgrep (optional)

  Linux:
    └── bubblewrap (required)
    └── socat (required)
    └── ripgrep (optional)

Node Modules:
  └── commander (CLI)
  └── zod (validation)
  └── lodash-es (utilities)
  └── shell-quote (parsing)
  └── @pondwader/socks5-server (proxy)
```

## Component Complexity Analysis

| Component | Lines | Complexity | Critical |
|-----------|-------|------------|----------|
| macos-sandbox-utils.ts | 700 | High | Yes |
| linux-sandbox-utils.ts | 600 | High | Yes |
| sandbox-manager.ts | 400 | Medium | Yes |
| sandbox-config.ts | 200 | Low | Yes |
| http-proxy.ts | 150 | Medium | Yes |
| generate-seccomp-filter.ts | 150 | Medium | No |
| cli.ts | 150 | Low | Yes |
| socks-proxy.ts | 100 | Low | Yes |
| sandbox-violation-store.ts | 100 | Low | No |
| ripgrep.ts | 100 | Low | No |

## Component Responsibilities

### Security Components
- **macos-sandbox-utils.ts**: macOS security enforcement
- **linux-sandbox-utils.ts**: Linux security enforcement
- **generate-seccomp-filter.ts**: System call filtering
- **http-proxy.ts**: Network traffic filtering
- **socks-proxy.ts**: SOCKS protocol filtering

### Configuration Components
- **sandbox-config.ts**: Schema definitions
- **sandbox-schemas.ts**: Type definitions
- **cli.ts**: User configuration interface

### Monitoring Components
- **sandbox-violation-store.ts**: Violation tracking
- **debug.ts**: Debug logging

### Utility Components
- **sandbox-utils.ts**: Shared helpers
- **platform.ts**: Platform detection
- **ripgrep.ts**: File searching