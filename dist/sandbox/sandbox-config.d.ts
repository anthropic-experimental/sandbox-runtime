/**
 * Configuration for Sandbox Runtime
 * This is the main configuration interface that consumers pass to SandboxManager.initialize()
 */
import { z } from 'zod'
/**
 * Schema for MITM proxy configuration
 * Allows routing specific domains through an upstream MITM proxy via Unix socket
 */
declare const MitmProxyConfigSchema: z.ZodObject<
  {
    socketPath: z.ZodString
    domains: z.ZodArray<z.ZodEffects<z.ZodString, string, string>, 'many'>
  },
  'strip',
  z.ZodTypeAny,
  {
    socketPath: string
    domains: string[]
  },
  {
    socketPath: string
    domains: string[]
  }
>
/**
 * Schema for upstream/parent HTTP proxy configuration.
 * Used when SRT itself runs behind a corporate proxy and cannot make direct
 * outbound connections.
 */
declare const ParentProxyConfigSchema: z.ZodObject<
  {
    http: z.ZodOptional<z.ZodString>
    https: z.ZodOptional<z.ZodString>
    noProxy: z.ZodOptional<z.ZodString>
  },
  'strip',
  z.ZodTypeAny,
  {
    http?: string | undefined
    https?: string | undefined
    noProxy?: string | undefined
  },
  {
    http?: string | undefined
    https?: string | undefined
    noProxy?: string | undefined
  }
>
/**
 * Network configuration schema for validation
 */
export declare const NetworkConfigSchema: z.ZodObject<
  {
    allowedDomains: z.ZodArray<
      z.ZodEffects<z.ZodString, string, string>,
      'many'
    >
    deniedDomains: z.ZodArray<z.ZodEffects<z.ZodString, string, string>, 'many'>
    allowAllDomains: z.ZodOptional<z.ZodBoolean>
    allowUnixSockets: z.ZodOptional<z.ZodArray<z.ZodString, 'many'>>
    allowAllUnixSockets: z.ZodOptional<z.ZodBoolean>
    allowLocalBinding: z.ZodOptional<z.ZodBoolean>
    allowMachLookup: z.ZodOptional<
      z.ZodArray<z.ZodEffects<z.ZodString, string, string>, 'many'>
    >
    httpProxyPort: z.ZodOptional<z.ZodNumber>
    socksProxyPort: z.ZodOptional<z.ZodNumber>
    mitmProxy: z.ZodOptional<
      z.ZodObject<
        {
          socketPath: z.ZodString
          domains: z.ZodArray<z.ZodEffects<z.ZodString, string, string>, 'many'>
        },
        'strip',
        z.ZodTypeAny,
        {
          socketPath: string
          domains: string[]
        },
        {
          socketPath: string
          domains: string[]
        }
      >
    >
    parentProxy: z.ZodOptional<
      z.ZodObject<
        {
          http: z.ZodOptional<z.ZodString>
          https: z.ZodOptional<z.ZodString>
          noProxy: z.ZodOptional<z.ZodString>
        },
        'strip',
        z.ZodTypeAny,
        {
          http?: string | undefined
          https?: string | undefined
          noProxy?: string | undefined
        },
        {
          http?: string | undefined
          https?: string | undefined
          noProxy?: string | undefined
        }
      >
    >
  },
  'strip',
  z.ZodTypeAny,
  {
    allowedDomains: string[]
    deniedDomains: string[]
    allowAllDomains?: boolean | undefined
    allowUnixSockets?: string[] | undefined
    allowAllUnixSockets?: boolean | undefined
    allowLocalBinding?: boolean | undefined
    allowMachLookup?: string[] | undefined
    httpProxyPort?: number | undefined
    socksProxyPort?: number | undefined
    mitmProxy?:
      | {
          socketPath: string
          domains: string[]
        }
      | undefined
    parentProxy?:
      | {
          http?: string | undefined
          https?: string | undefined
          noProxy?: string | undefined
        }
      | undefined
  },
  {
    allowedDomains: string[]
    deniedDomains: string[]
    allowAllDomains?: boolean | undefined
    allowUnixSockets?: string[] | undefined
    allowAllUnixSockets?: boolean | undefined
    allowLocalBinding?: boolean | undefined
    allowMachLookup?: string[] | undefined
    httpProxyPort?: number | undefined
    socksProxyPort?: number | undefined
    mitmProxy?:
      | {
          socketPath: string
          domains: string[]
        }
      | undefined
    parentProxy?:
      | {
          http?: string | undefined
          https?: string | undefined
          noProxy?: string | undefined
        }
      | undefined
  }
>
/**
 * Filesystem configuration schema for validation
 */
export declare const FilesystemConfigSchema: z.ZodObject<
  {
    denyRead: z.ZodArray<z.ZodString, 'many'>
    allowRead: z.ZodOptional<z.ZodArray<z.ZodString, 'many'>>
    allowWrite: z.ZodArray<z.ZodString, 'many'>
    denyWrite: z.ZodArray<z.ZodString, 'many'>
    allowGitConfig: z.ZodOptional<z.ZodBoolean>
  },
  'strip',
  z.ZodTypeAny,
  {
    denyRead: string[]
    allowWrite: string[]
    denyWrite: string[]
    allowRead?: string[] | undefined
    allowGitConfig?: boolean | undefined
  },
  {
    denyRead: string[]
    allowWrite: string[]
    denyWrite: string[]
    allowRead?: string[] | undefined
    allowGitConfig?: boolean | undefined
  }
>
/**
 * Configuration schema for ignoring specific sandbox violations
 * Maps command patterns to filesystem paths to ignore violations for.
 */
export declare const IgnoreViolationsConfigSchema: z.ZodRecord<
  z.ZodString,
  z.ZodArray<z.ZodString, 'many'>
>
/**
 * Ripgrep configuration schema
 */
export declare const RipgrepConfigSchema: z.ZodObject<
  {
    command: z.ZodString
    args: z.ZodOptional<z.ZodArray<z.ZodString, 'many'>>
    argv0: z.ZodOptional<z.ZodString>
  },
  'strip',
  z.ZodTypeAny,
  {
    command: string
    args?: string[] | undefined
    argv0?: string | undefined
  },
  {
    command: string
    args?: string[] | undefined
    argv0?: string | undefined
  }
>
/**
 * Seccomp configuration schema (Linux only)
 */
export declare const SeccompConfigSchema: z.ZodObject<
  {
    applyPath: z.ZodOptional<z.ZodString>
    argv0: z.ZodOptional<z.ZodString>
  },
  'strip',
  z.ZodTypeAny,
  {
    argv0?: string | undefined
    applyPath?: string | undefined
  },
  {
    argv0?: string | undefined
    applyPath?: string | undefined
  }
>
/**
 * Main configuration schema for Sandbox Runtime validation
 */
export declare const SandboxRuntimeConfigSchema: z.ZodObject<
  {
    network: z.ZodObject<
      {
        allowedDomains: z.ZodArray<
          z.ZodEffects<z.ZodString, string, string>,
          'many'
        >
        deniedDomains: z.ZodArray<
          z.ZodEffects<z.ZodString, string, string>,
          'many'
        >
        allowAllDomains: z.ZodOptional<z.ZodBoolean>
        allowUnixSockets: z.ZodOptional<z.ZodArray<z.ZodString, 'many'>>
        allowAllUnixSockets: z.ZodOptional<z.ZodBoolean>
        allowLocalBinding: z.ZodOptional<z.ZodBoolean>
        allowMachLookup: z.ZodOptional<
          z.ZodArray<z.ZodEffects<z.ZodString, string, string>, 'many'>
        >
        httpProxyPort: z.ZodOptional<z.ZodNumber>
        socksProxyPort: z.ZodOptional<z.ZodNumber>
        mitmProxy: z.ZodOptional<
          z.ZodObject<
            {
              socketPath: z.ZodString
              domains: z.ZodArray<
                z.ZodEffects<z.ZodString, string, string>,
                'many'
              >
            },
            'strip',
            z.ZodTypeAny,
            {
              socketPath: string
              domains: string[]
            },
            {
              socketPath: string
              domains: string[]
            }
          >
        >
        parentProxy: z.ZodOptional<
          z.ZodObject<
            {
              http: z.ZodOptional<z.ZodString>
              https: z.ZodOptional<z.ZodString>
              noProxy: z.ZodOptional<z.ZodString>
            },
            'strip',
            z.ZodTypeAny,
            {
              http?: string | undefined
              https?: string | undefined
              noProxy?: string | undefined
            },
            {
              http?: string | undefined
              https?: string | undefined
              noProxy?: string | undefined
            }
          >
        >
      },
      'strip',
      z.ZodTypeAny,
      {
        allowedDomains: string[]
        deniedDomains: string[]
        allowAllDomains?: boolean | undefined
        allowUnixSockets?: string[] | undefined
        allowAllUnixSockets?: boolean | undefined
        allowLocalBinding?: boolean | undefined
        allowMachLookup?: string[] | undefined
        httpProxyPort?: number | undefined
        socksProxyPort?: number | undefined
        mitmProxy?:
          | {
              socketPath: string
              domains: string[]
            }
          | undefined
        parentProxy?:
          | {
              http?: string | undefined
              https?: string | undefined
              noProxy?: string | undefined
            }
          | undefined
      },
      {
        allowedDomains: string[]
        deniedDomains: string[]
        allowAllDomains?: boolean | undefined
        allowUnixSockets?: string[] | undefined
        allowAllUnixSockets?: boolean | undefined
        allowLocalBinding?: boolean | undefined
        allowMachLookup?: string[] | undefined
        httpProxyPort?: number | undefined
        socksProxyPort?: number | undefined
        mitmProxy?:
          | {
              socketPath: string
              domains: string[]
            }
          | undefined
        parentProxy?:
          | {
              http?: string | undefined
              https?: string | undefined
              noProxy?: string | undefined
            }
          | undefined
      }
    >
    filesystem: z.ZodObject<
      {
        denyRead: z.ZodArray<z.ZodString, 'many'>
        allowRead: z.ZodOptional<z.ZodArray<z.ZodString, 'many'>>
        allowWrite: z.ZodArray<z.ZodString, 'many'>
        denyWrite: z.ZodArray<z.ZodString, 'many'>
        allowGitConfig: z.ZodOptional<z.ZodBoolean>
      },
      'strip',
      z.ZodTypeAny,
      {
        denyRead: string[]
        allowWrite: string[]
        denyWrite: string[]
        allowRead?: string[] | undefined
        allowGitConfig?: boolean | undefined
      },
      {
        denyRead: string[]
        allowWrite: string[]
        denyWrite: string[]
        allowRead?: string[] | undefined
        allowGitConfig?: boolean | undefined
      }
    >
    ignoreViolations: z.ZodOptional<
      z.ZodRecord<z.ZodString, z.ZodArray<z.ZodString, 'many'>>
    >
    enableWeakerNestedSandbox: z.ZodOptional<z.ZodBoolean>
    enableWeakerNetworkIsolation: z.ZodOptional<z.ZodBoolean>
    ripgrep: z.ZodOptional<
      z.ZodObject<
        {
          command: z.ZodString
          args: z.ZodOptional<z.ZodArray<z.ZodString, 'many'>>
          argv0: z.ZodOptional<z.ZodString>
        },
        'strip',
        z.ZodTypeAny,
        {
          command: string
          args?: string[] | undefined
          argv0?: string | undefined
        },
        {
          command: string
          args?: string[] | undefined
          argv0?: string | undefined
        }
      >
    >
    mandatoryDenySearchDepth: z.ZodOptional<z.ZodNumber>
    allowPty: z.ZodOptional<z.ZodBoolean>
    seccomp: z.ZodOptional<
      z.ZodObject<
        {
          applyPath: z.ZodOptional<z.ZodString>
          argv0: z.ZodOptional<z.ZodString>
        },
        'strip',
        z.ZodTypeAny,
        {
          argv0?: string | undefined
          applyPath?: string | undefined
        },
        {
          argv0?: string | undefined
          applyPath?: string | undefined
        }
      >
    >
  },
  'strip',
  z.ZodTypeAny,
  {
    network: {
      allowedDomains: string[]
      deniedDomains: string[]
      allowAllDomains?: boolean | undefined
      allowUnixSockets?: string[] | undefined
      allowAllUnixSockets?: boolean | undefined
      allowLocalBinding?: boolean | undefined
      allowMachLookup?: string[] | undefined
      httpProxyPort?: number | undefined
      socksProxyPort?: number | undefined
      mitmProxy?:
        | {
            socketPath: string
            domains: string[]
          }
        | undefined
      parentProxy?:
        | {
            http?: string | undefined
            https?: string | undefined
            noProxy?: string | undefined
          }
        | undefined
    }
    filesystem: {
      denyRead: string[]
      allowWrite: string[]
      denyWrite: string[]
      allowRead?: string[] | undefined
      allowGitConfig?: boolean | undefined
    }
    ignoreViolations?: Record<string, string[]> | undefined
    enableWeakerNestedSandbox?: boolean | undefined
    enableWeakerNetworkIsolation?: boolean | undefined
    ripgrep?:
      | {
          command: string
          args?: string[] | undefined
          argv0?: string | undefined
        }
      | undefined
    mandatoryDenySearchDepth?: number | undefined
    allowPty?: boolean | undefined
    seccomp?:
      | {
          argv0?: string | undefined
          applyPath?: string | undefined
        }
      | undefined
  },
  {
    network: {
      allowedDomains: string[]
      deniedDomains: string[]
      allowAllDomains?: boolean | undefined
      allowUnixSockets?: string[] | undefined
      allowAllUnixSockets?: boolean | undefined
      allowLocalBinding?: boolean | undefined
      allowMachLookup?: string[] | undefined
      httpProxyPort?: number | undefined
      socksProxyPort?: number | undefined
      mitmProxy?:
        | {
            socketPath: string
            domains: string[]
          }
        | undefined
      parentProxy?:
        | {
            http?: string | undefined
            https?: string | undefined
            noProxy?: string | undefined
          }
        | undefined
    }
    filesystem: {
      denyRead: string[]
      allowWrite: string[]
      denyWrite: string[]
      allowRead?: string[] | undefined
      allowGitConfig?: boolean | undefined
    }
    ignoreViolations?: Record<string, string[]> | undefined
    enableWeakerNestedSandbox?: boolean | undefined
    enableWeakerNetworkIsolation?: boolean | undefined
    ripgrep?:
      | {
          command: string
          args?: string[] | undefined
          argv0?: string | undefined
        }
      | undefined
    mandatoryDenySearchDepth?: number | undefined
    allowPty?: boolean | undefined
    seccomp?:
      | {
          argv0?: string | undefined
          applyPath?: string | undefined
        }
      | undefined
  }
>
export type MitmProxyConfig = z.infer<typeof MitmProxyConfigSchema>
export type ParentProxyConfig = z.infer<typeof ParentProxyConfigSchema>
export type NetworkConfig = z.infer<typeof NetworkConfigSchema>
export type FilesystemConfig = z.infer<typeof FilesystemConfigSchema>
export type IgnoreViolationsConfig = z.infer<
  typeof IgnoreViolationsConfigSchema
>
export type RipgrepConfig = z.infer<typeof RipgrepConfigSchema>
export type SeccompConfig = z.infer<typeof SeccompConfigSchema>
export type SandboxRuntimeConfig = z.infer<typeof SandboxRuntimeConfigSchema>
export {}
//# sourceMappingURL=sandbox-config.d.ts.map
