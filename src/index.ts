// Library exports
export { SandboxManager } from './sandbox/sandbox-manager.js'
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js'

// Configuration types and schemas
export type {
  SandboxRuntimeConfig,
  NetworkConfig,
  FilesystemConfig,
  CredentialsConfig,
  CredentialFileConfig,
  CredentialEnvVarConfig,
  CredentialMode,
  IgnoreViolationsConfig,
} from './sandbox/sandbox-config.js'

export {
  SandboxRuntimeConfigSchema,
  NetworkConfigSchema,
  FilesystemConfigSchema,
  CredentialsConfigSchema,
  IgnoreViolationsConfigSchema,
  RipgrepConfigSchema,
} from './sandbox/sandbox-config.js'

// Schema types and utilities
export type {
  SandboxAskCallback,
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
  CredentialRestrictionConfig,
  NetworkRestrictionConfig,
  NetworkHostPattern,
} from './sandbox/sandbox-schemas.js'

// Per-request filter
export type {
  FilterRequestCallback,
  RequestDecision,
  MutateForwardedHeaders,
} from './sandbox/request-filter.js'

// Platform-specific utilities
export type { SandboxViolationEvent } from './sandbox/macos-sandbox-utils.js'
export { type SandboxDependencyCheck } from './sandbox/linux-sandbox-utils.js'

// Windows install/status API
export {
  getSrtWinPath,
  resolveSrtWin,
  getWindowsWfpStatus,
  verifyWindowsWfpEgress,
  getWindowsSandboxUserStatus,
  getWindowsSandboxCaCert,
  windowsTrustCa,
  installWindowsSandbox,
  uninstallWindowsSandbox,
  windowsInstallInstructions,
  stampWindowsAcl,
  restoreWindowsAcl,
  grantWindowsAcl,
  revokeWindowsAcl,
  expandWindowsFsPaths,
  buildGitConfigEnv,
  parseWindowsBinShell,
  DEFAULT_WINDOWS_PROXY_PORT_RANGE,
  SRT_WIN_DISPATCH_ARG1,
} from './sandbox/windows-sandbox-utils.js'
export type {
  WindowsBinShell,
  WindowsInstallOptions,
  WindowsInstallResult,
  WindowsWfpStatus,
  WindowsAclStampOptions,
  WindowsAclGrantOptions,
  WindowsAclAceOutcome,
  WindowsWfpStatusResult,
  WindowsWfpVerifyResult,
  WindowsSandboxUserStatus,
  SrtWinSpawn,
} from './sandbox/windows-sandbox-utils.js'
export type { WindowsConfig, SrtWinConfig } from './sandbox/sandbox-config.js'
export {
  WindowsConfigSchema,
  SrtWinConfigSchema,
} from './sandbox/sandbox-config.js'

// Utility functions
export { getDefaultWritePaths } from './sandbox/sandbox-utils.js'

// Platform utilities
export { getWslVersion } from './utils/platform.js'
export type { Platform } from './utils/platform.js'
