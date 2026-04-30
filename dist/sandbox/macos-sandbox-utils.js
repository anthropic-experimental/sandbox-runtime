import shellquote from 'shell-quote';
import { spawn } from 'child_process';
import * as path from 'path';
import { logForDebugging } from '../utils/debug.js';
import { whichSync } from '../utils/which.js';
import { normalizePathForSandbox, generateProxyEnvVars, encodeSandboxedCommand, decodeSandboxedCommand, containsGlobChars, globToRegex, DANGEROUS_FILES, getDangerousDirectories, } from './sandbox-utils.js';
/**
 * Get mandatory deny patterns as glob patterns (no filesystem scanning).
 * macOS sandbox profile supports regex/glob matching directly via globToRegex().
 */
export function macGetMandatoryDenyPatterns(allowGitConfig = false) {
    const cwd = process.cwd();
    const denyPaths = [];
    // Dangerous files - static paths in CWD + glob patterns for subtree
    for (const fileName of DANGEROUS_FILES) {
        denyPaths.push(path.resolve(cwd, fileName));
        denyPaths.push(`**/${fileName}`);
    }
    // Dangerous directories
    for (const dirName of getDangerousDirectories()) {
        denyPaths.push(path.resolve(cwd, dirName));
        denyPaths.push(`**/${dirName}/**`);
    }
    // Git hooks are always blocked for security
    denyPaths.push(path.resolve(cwd, '.git/hooks'));
    denyPaths.push('**/.git/hooks/**');
    // Git config - conditionally blocked based on allowGitConfig setting
    if (!allowGitConfig) {
        denyPaths.push(path.resolve(cwd, '.git/config'));
        denyPaths.push('**/.git/config');
    }
    return [...new Set(denyPaths)];
}
const sessionSuffix = `_${Math.random().toString(36).slice(2, 11)}_SBX`;
/**
 * Generate a unique log tag for sandbox monitoring
 * @param command - The command being executed (will be base64 encoded)
 */
function generateLogTag(command) {
    const encodedCommand = encodeSandboxedCommand(command);
    return `CMD64_${encodedCommand}_END_${sessionSuffix}`;
}
/**
 * Get all ancestor directories for a path, up to (but not including) root
 * Example: /private/tmp/test/file.txt -> ["/private/tmp/test", "/private/tmp", "/private"]
 */
function getAncestorDirectories(pathStr) {
    const ancestors = [];
    let currentPath = path.dirname(pathStr);
    // Walk up the directory tree until we reach root
    while (currentPath !== '/' && currentPath !== '.') {
        ancestors.push(currentPath);
        const parentPath = path.dirname(currentPath);
        // Break if we've reached the top (path.dirname returns the same path for root)
        if (parentPath === currentPath) {
            break;
        }
        currentPath = parentPath;
    }
    return ancestors;
}
/**
 * Generate deny rules for file movement (file-write-unlink) to protect paths
 * This prevents bypassing read or write restrictions by moving files/directories
 *
 * @param pathPatterns - Array of path patterns to protect (can include globs)
 * @param logTag - Log tag for sandbox violations
 * @returns Array of sandbox profile rule lines
 */
function generateMoveBlockingRules(pathPatterns, logTag) {
    const rules = [];
    for (const pathPattern of pathPatterns) {
        const normalizedPath = normalizePathForSandbox(pathPattern);
        if (containsGlobChars(normalizedPath)) {
            // Use regex matching for glob patterns
            const regexPattern = globToRegex(normalizedPath);
            // Block moving/renaming files matching this pattern
            rules.push(`(deny file-write-unlink`, `  (regex ${escapePath(regexPattern)})`, `  (with message "${logTag}"))`);
            // For glob patterns, extract the static prefix and block ancestor moves
            // Remove glob characters to get the directory prefix
            const staticPrefix = normalizedPath.split(/[*?[\]]/)[0];
            if (staticPrefix && staticPrefix !== '/') {
                // Get the directory containing the glob pattern
                const baseDir = staticPrefix.endsWith('/')
                    ? staticPrefix.slice(0, -1)
                    : path.dirname(staticPrefix);
                // Block moves of the base directory itself
                rules.push(`(deny file-write-unlink`, `  (literal ${escapePath(baseDir)})`, `  (with message "${logTag}"))`);
                // Block moves of ancestor directories
                for (const ancestorDir of getAncestorDirectories(baseDir)) {
                    rules.push(`(deny file-write-unlink`, `  (literal ${escapePath(ancestorDir)})`, `  (with message "${logTag}"))`);
                }
            }
        }
        else {
            // Use subpath matching for literal paths
            // Block moving/renaming the denied path itself
            rules.push(`(deny file-write-unlink`, `  (subpath ${escapePath(normalizedPath)})`, `  (with message "${logTag}"))`);
            // Block moves of ancestor directories
            for (const ancestorDir of getAncestorDirectories(normalizedPath)) {
                rules.push(`(deny file-write-unlink`, `  (literal ${escapePath(ancestorDir)})`, `  (with message "${logTag}"))`);
            }
        }
    }
    return rules;
}
/**
 * Generate filesystem read rules for sandbox profile
 *
 * Supports two layers:
 * 1. denyOnly: deny reads from these paths (broad regions like /Users)
 * 2. allowWithinDeny: re-allow reads within denied regions (like CWD)
 *    allowWithinDeny takes precedence over denyOnly.
 *
 * In Seatbelt profiles, later rules take precedence, so we emit:
 *   (allow file-read*)        ← default: allow everything
 *   (deny file-read* ...)     ← deny broad regions
 *   (allow file-read* ...)    ← re-allow specific paths within denied regions
 */
function generateReadRules(config, logTag, writeAllowPaths) {
    if (!config) {
        return [`(allow file-read*)`];
    }
    const rules = [];
    let deniesRoot = false;
    // Start by allowing everything
    rules.push(`(allow file-read*)`);
    // Then deny specific paths
    for (const pathPattern of config.denyOnly || []) {
        const normalizedPath = normalizePathForSandbox(pathPattern);
        if (normalizedPath === '/')
            deniesRoot = true;
        if (containsGlobChars(normalizedPath)) {
            // Use regex matching for glob patterns
            const regexPattern = globToRegex(normalizedPath);
            rules.push(`(deny file-read*`, `  (regex ${escapePath(regexPattern)})`, `  (with message "${logTag}"))`);
        }
        else {
            // Use subpath matching for literal paths
            rules.push(`(deny file-read*`, `  (subpath ${escapePath(normalizedPath)})`, `  (with message "${logTag}"))`);
        }
    }
    // (subpath "/") denies the root inode itself; allowWithinDeny subpaths don't
    // cover "/", so dyld aborts before exec. Re-allow the literal root so path
    // traversal works. This exposes `ls /` dirent names but no subtree contents.
    if (deniesRoot) {
        rules.push(`(allow file-read* (literal "/"))`);
    }
    // Re-allow specific paths within denied regions (allowWithinDeny takes precedence)
    for (const pathPattern of config.allowWithinDeny || []) {
        const normalizedPath = normalizePathForSandbox(pathPattern);
        if (containsGlobChars(normalizedPath)) {
            const regexPattern = globToRegex(normalizedPath);
            rules.push(`(allow file-read*`, `  (regex ${escapePath(regexPattern)})`, `  (with message "${logTag}"))`);
        }
        else {
            rules.push(`(allow file-read*`, `  (subpath ${escapePath(normalizedPath)})`, `  (with message "${logTag}"))`);
        }
    }
    // Allow stat/lstat on all directories so that realpath() can traverse
    // path components within denied regions. Without this, C realpath() fails
    // when resolving symlinks because it needs to lstat every intermediate
    // directory (e.g. /Users, /Users/chris) even if only a subdirectory like
    // ~/.local is in allowWithinDeny. This only allows metadata reads on
    // directories — not listing contents (readdir) or reading files.
    if (config.denyOnly.length > 0) {
        rules.push(`(allow file-read-metadata`, `  (vnode-type DIRECTORY))`);
    }
    // Block file movement to prevent bypass via mv/rename
    rules.push(...generateMoveBlockingRules(config.denyOnly || [], logTag));
    // Re-allow file-write-unlink for paths that are explicitly write-allowed.
    // The move-blocking rules above emit broad (deny file-write-unlink (subpath "/Users"))
    // to prevent bypassing read restrictions by moving files out of denied regions.
    // However, in macOS Seatbelt, a specific (deny file-write-unlink) is not overridden
    // by a later (allow file-write*) wildcard — the specific operation deny wins.
    // This means file deletions are blocked even in write-allowed directories like
    // the project directory. We fix this by explicitly re-allowing file-write-unlink
    // for write-allowed paths after the move-blocking deny rules.
    //
    // Note: denyWithinAllow paths are not excluded here because the write section's
    // generateMoveBlockingRules() runs later in the profile and re-denies
    // file-write-unlink for those paths (Seatbelt uses last-match-wins). This
    // depends on read rules being emitted before write rules in generateSandboxProfile().
    if (writeAllowPaths && writeAllowPaths.length > 0) {
        for (const pathPattern of writeAllowPaths) {
            const normalizedPath = normalizePathForSandbox(pathPattern);
            if (containsGlobChars(normalizedPath)) {
                const regexPattern = globToRegex(normalizedPath);
                rules.push(`(allow file-write-unlink`, `  (regex ${escapePath(regexPattern)})`, `  (with message "${logTag}"))`);
            }
            else {
                rules.push(`(allow file-write-unlink`, `  (subpath ${escapePath(normalizedPath)})`, `  (with message "${logTag}"))`);
            }
        }
    }
    return rules;
}
/**
 * Generate filesystem write rules for sandbox profile
 */
function generateWriteRules(config, logTag, allowGitConfig = false) {
    if (!config) {
        return [`(allow file-write*)`];
    }
    const rules = [];
    // Generate allow rules
    for (const pathPattern of config.allowOnly || []) {
        const normalizedPath = normalizePathForSandbox(pathPattern);
        if (containsGlobChars(normalizedPath)) {
            // Use regex matching for glob patterns
            const regexPattern = globToRegex(normalizedPath);
            rules.push(`(allow file-write*`, `  (regex ${escapePath(regexPattern)})`, `  (with message "${logTag}"))`);
        }
        else {
            // Use subpath matching for literal paths
            rules.push(`(allow file-write*`, `  (subpath ${escapePath(normalizedPath)})`, `  (with message "${logTag}"))`);
        }
    }
    // Combine user-specified and mandatory deny patterns (no ripgrep needed on macOS)
    const denyPaths = [
        ...(config.denyWithinAllow || []),
        ...macGetMandatoryDenyPatterns(allowGitConfig),
    ];
    for (const pathPattern of denyPaths) {
        const normalizedPath = normalizePathForSandbox(pathPattern);
        if (containsGlobChars(normalizedPath)) {
            // Use regex matching for glob patterns
            const regexPattern = globToRegex(normalizedPath);
            rules.push(`(deny file-write*`, `  (regex ${escapePath(regexPattern)})`, `  (with message "${logTag}"))`);
        }
        else {
            // Use subpath matching for literal paths
            rules.push(`(deny file-write*`, `  (subpath ${escapePath(normalizedPath)})`, `  (with message "${logTag}"))`);
        }
    }
    // Block file movement to prevent bypass via mv/rename
    rules.push(...generateMoveBlockingRules(denyPaths, logTag));
    return rules;
}
/**
 * Generate complete sandbox profile
 */
function generateSandboxProfile({ readConfig, writeConfig, httpProxyPort, socksProxyPort, needsNetworkRestriction, allowUnixSockets, allowAllUnixSockets, allowLocalBinding, allowMachLookup, allowPty, allowGitConfig = false, enableWeakerNetworkIsolation = false, logTag, }) {
    const profile = [
        '(version 1)',
        `(deny default (with message "${logTag}"))`,
        '',
        `; LogTag: ${logTag}`,
        '',
        '; Essential permissions - based on Chrome sandbox policy',
        '; Process permissions',
        '(allow process-exec)',
        '(allow process-fork)',
        '(allow process-info* (target same-sandbox))',
        '(allow signal (target same-sandbox))',
        '(allow mach-priv-task-port (target same-sandbox))',
        '',
        '; User preferences',
        '(allow user-preference-read)',
        '',
        '; Mach IPC - specific services only (no wildcard)',
        '(allow mach-lookup',
        '  (global-name "com.apple.audio.systemsoundserver")',
        '  (global-name "com.apple.distributed_notifications@Uv3")',
        '  (global-name "com.apple.FontObjectsServer")',
        '  (global-name "com.apple.fonts")',
        '  (global-name "com.apple.logd")',
        '  (global-name "com.apple.lsd.mapdb")',
        '  (global-name "com.apple.PowerManagement.control")',
        '  (global-name "com.apple.system.logger")',
        '  (global-name "com.apple.system.notification_center")',
        '  (global-name "com.apple.system.opendirectoryd.libinfo")',
        '  (global-name "com.apple.system.opendirectoryd.membership")',
        '  (global-name "com.apple.bsd.dirhelper")',
        '  (global-name "com.apple.securityd.xpc")',
        '  (global-name "com.apple.coreservices.launchservicesd")',
        ')',
        '',
        ...(enableWeakerNetworkIsolation
            ? [
                '; trustd.agent - needed for Go TLS certificate verification (weaker network isolation)',
                '(allow mach-lookup (global-name "com.apple.trustd.agent"))',
            ]
            : []),
        ...(allowMachLookup && allowMachLookup.length > 0
            ? [
                '; User-specified XPC/Mach services',
                ...allowMachLookup.map(name => name.endsWith('*')
                    ? `(allow mach-lookup (global-name-prefix ${escapePath(name.slice(0, -1))}))`
                    : `(allow mach-lookup (global-name ${escapePath(name)}))`),
            ]
            : []),
        '',
        '; POSIX IPC - shared memory',
        '(allow ipc-posix-shm)',
        '',
        '; POSIX IPC - semaphores for Python multiprocessing',
        '(allow ipc-posix-sem)',
        '',
        '; IOKit - specific operations only',
        '(allow iokit-open',
        '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
        '  (iokit-registry-entry-class "RootDomainUserClient")',
        '  (iokit-user-client-class "IOSurfaceSendRight")',
        ')',
        '',
        '; IOKit properties',
        '(allow iokit-get-properties)',
        '',
        "; Specific safe system-sockets, doesn't allow network access",
        '(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))',
        '',
        '; sysctl - specific sysctls only',
        '(allow sysctl-read',
        '  (sysctl-name "hw.activecpu")',
        '  (sysctl-name "hw.busfrequency_compat")',
        '  (sysctl-name "hw.byteorder")',
        '  (sysctl-name "hw.cacheconfig")',
        '  (sysctl-name "hw.cachelinesize_compat")',
        '  (sysctl-name "hw.cpufamily")',
        '  (sysctl-name "hw.cpufrequency")',
        '  (sysctl-name "hw.cpufrequency_compat")',
        '  (sysctl-name "hw.cputype")',
        '  (sysctl-name "hw.l1dcachesize_compat")',
        '  (sysctl-name "hw.l1icachesize_compat")',
        '  (sysctl-name "hw.l2cachesize_compat")',
        '  (sysctl-name "hw.l3cachesize_compat")',
        '  (sysctl-name "hw.logicalcpu")',
        '  (sysctl-name "hw.logicalcpu_max")',
        '  (sysctl-name "hw.machine")',
        '  (sysctl-name "hw.memsize")',
        '  (sysctl-name "hw.ncpu")',
        '  (sysctl-name "hw.nperflevels")',
        '  (sysctl-name "hw.packages")',
        '  (sysctl-name "hw.pagesize_compat")',
        '  (sysctl-name "hw.pagesize")',
        '  (sysctl-name "hw.physicalcpu")',
        '  (sysctl-name "hw.physicalcpu_max")',
        '  (sysctl-name "hw.tbfrequency_compat")',
        '  (sysctl-name "hw.vectorunit")',
        '  (sysctl-name "kern.argmax")',
        '  (sysctl-name "kern.bootargs")',
        '  (sysctl-name "kern.hostname")',
        '  (sysctl-name "kern.maxfiles")',
        '  (sysctl-name "kern.maxfilesperproc")',
        '  (sysctl-name "kern.maxproc")',
        '  (sysctl-name "kern.ngroups")',
        '  (sysctl-name "kern.osproductversion")',
        '  (sysctl-name "kern.osrelease")',
        '  (sysctl-name "kern.ostype")',
        '  (sysctl-name "kern.osvariant_status")',
        '  (sysctl-name "kern.osversion")',
        '  (sysctl-name "kern.secure_kernel")',
        '  (sysctl-name "kern.tcsm_available")',
        '  (sysctl-name "kern.tcsm_enable")',
        '  (sysctl-name "kern.usrstack64")',
        '  (sysctl-name "kern.version")',
        '  (sysctl-name "kern.willshutdown")',
        '  (sysctl-name "machdep.cpu.brand_string")',
        '  (sysctl-name "machdep.ptrauth_enabled")',
        '  (sysctl-name "security.mac.lockdown_mode_state")',
        '  (sysctl-name "sysctl.proc_cputype")',
        '  (sysctl-name "vm.loadavg")',
        '  (sysctl-name-prefix "hw.optional.arm")',
        '  (sysctl-name-prefix "hw.optional.arm.")',
        '  (sysctl-name-prefix "hw.optional.armv8_")',
        '  (sysctl-name-prefix "hw.perflevel")',
        '  (sysctl-name-prefix "kern.proc.all")',
        '  (sysctl-name-prefix "kern.proc.pgrp.")',
        '  (sysctl-name-prefix "kern.proc.pid.")',
        '  (sysctl-name-prefix "machdep.cpu.")',
        '  (sysctl-name-prefix "net.routetable.")',
        ')',
        '',
        '; V8 thread calculations',
        '(allow sysctl-write',
        '  (sysctl-name "kern.tcsm_enable")',
        ')',
        '',
        '; Distributed notifications',
        '(allow distributed-notification-post)',
        '',
        '; Specific mach-lookup permissions for security operations',
        '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
        '',
        '; File I/O on device files',
        '(allow file-ioctl (literal "/dev/null"))',
        '(allow file-ioctl (literal "/dev/zero"))',
        '(allow file-ioctl (literal "/dev/random"))',
        '(allow file-ioctl (literal "/dev/urandom"))',
        '(allow file-ioctl (literal "/dev/dtracehelper"))',
        '(allow file-ioctl (literal "/dev/tty"))',
        '',
        '(allow file-ioctl file-read-data file-write-data',
        '  (require-all',
        '    (literal "/dev/null")',
        '    (vnode-type CHARACTER-DEVICE)',
        '  )',
        ')',
        '',
    ];
    // Network rules
    profile.push('; Network');
    if (!needsNetworkRestriction) {
        profile.push('(allow network*)');
    }
    else {
        // Allow local binding if requested
        // Use "*:*" instead of "localhost:*" because modern runtimes (Java, etc.) create
        // IPv6 dual-stack sockets by default. When binding such a socket to 127.0.0.1,
        // the kernel represents it as ::ffff:127.0.0.1 (IPv4-mapped IPv6). Seatbelt's
        // "localhost" filter only matches 127.0.0.1 and ::1, NOT ::ffff:127.0.0.1.
        // Using (local ip "*:*") is safe because it only matches the LOCAL endpoint —
        // internet-bound connections originate from non-loopback interfaces, so they
        // remain blocked by (deny default).
        if (allowLocalBinding) {
            profile.push('(allow network-bind (local ip "*:*"))');
            profile.push('(allow network-inbound (local ip "*:*"))');
            profile.push('(allow network-outbound (local ip "*:*"))');
        }
        // Unix domain sockets for local IPC (SSH agent, Docker, Gradle, etc.)
        // Three separate operations must be allowed:
        // 1. system-socket: socket(AF_UNIX, ...) syscall — creates the socket fd (no path context)
        // 2. network-bind: bind() to a local Unix socket path
        // 3. network-outbound: connect() to a remote Unix socket path
        // Note: (subpath ...) and (path-regex ...) are path-based filters that can only match
        // bind/connect operations — socket() creation has no path, so it requires system-socket.
        if (allowAllUnixSockets) {
            // Allow creating AF_UNIX sockets and all Unix socket paths
            profile.push('(allow system-socket (socket-domain AF_UNIX))');
            profile.push('(allow network-bind (local unix-socket (path-regex #"^/")))');
            profile.push('(allow network-outbound (remote unix-socket (path-regex #"^/")))');
        }
        else if (allowUnixSockets && allowUnixSockets.length > 0) {
            // Allow creating AF_UNIX sockets (required for any Unix socket use)
            profile.push('(allow system-socket (socket-domain AF_UNIX))');
            // Allow specific Unix socket paths
            for (const socketPath of allowUnixSockets) {
                const normalizedPath = normalizePathForSandbox(socketPath);
                profile.push(`(allow network-bind (local unix-socket (subpath ${escapePath(normalizedPath)})))`);
                profile.push(`(allow network-outbound (remote unix-socket (subpath ${escapePath(normalizedPath)})))`);
            }
        }
        // If both allowAllUnixSockets and allowUnixSockets are false/undefined/empty, Unix sockets are blocked by default
        // Allow localhost TCP operations for the HTTP proxy
        if (httpProxyPort !== undefined) {
            profile.push(`(allow network-bind (local ip "localhost:${httpProxyPort}"))`);
            profile.push(`(allow network-inbound (local ip "localhost:${httpProxyPort}"))`);
            profile.push(`(allow network-outbound (remote ip "localhost:${httpProxyPort}"))`);
        }
        // Allow localhost TCP operations for the SOCKS proxy
        if (socksProxyPort !== undefined) {
            profile.push(`(allow network-bind (local ip "localhost:${socksProxyPort}"))`);
            profile.push(`(allow network-inbound (local ip "localhost:${socksProxyPort}"))`);
            profile.push(`(allow network-outbound (remote ip "localhost:${socksProxyPort}"))`);
        }
    }
    profile.push('');
    // Read rules
    // Pass write-allowed paths so that move-blocking deny rules in the read section
    // can be overridden for paths where file deletion should be permitted.
    const writeAllowPaths = writeConfig?.allowOnly;
    profile.push('; File read');
    profile.push(...generateReadRules(readConfig, logTag, writeAllowPaths));
    profile.push('');
    // Write rules
    profile.push('; File write');
    profile.push(...generateWriteRules(writeConfig, logTag, allowGitConfig));
    // Pseudo-terminal (pty) support
    if (allowPty) {
        profile.push('');
        profile.push('; Pseudo-terminal (pty) support');
        profile.push('(allow pseudo-tty)');
        profile.push('(allow file-ioctl');
        profile.push('  (literal "/dev/ptmx")');
        profile.push('  (regex #"^/dev/ttys")');
        profile.push(')');
        profile.push('(allow file-read* file-write*');
        profile.push('  (literal "/dev/ptmx")');
        profile.push('  (regex #"^/dev/ttys")');
        profile.push(')');
    }
    return profile.join('\n');
}
/**
 * Escape path for sandbox profile using JSON.stringify for proper escaping
 */
function escapePath(pathStr) {
    return JSON.stringify(pathStr);
}
/**
 * Wrap command with macOS sandbox
 */
export function wrapCommandWithSandboxMacOS(params) {
    const { command, needsNetworkRestriction, httpProxyPort, socksProxyPort, allowUnixSockets, allowAllUnixSockets, allowLocalBinding, allowMachLookup, readConfig, writeConfig, allowPty, allowGitConfig = false, enableWeakerNetworkIsolation = false, binShell, } = params;
    // Determine if we have restrictions to apply
    // Read: denyOnly pattern - empty array means no restrictions
    // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
    const hasReadRestrictions = readConfig && readConfig.denyOnly.length > 0;
    const hasWriteRestrictions = writeConfig !== undefined;
    // No sandboxing needed
    if (!needsNetworkRestriction &&
        !hasReadRestrictions &&
        !hasWriteRestrictions) {
        return command;
    }
    const logTag = generateLogTag(command);
    const profile = generateSandboxProfile({
        readConfig,
        writeConfig,
        httpProxyPort,
        socksProxyPort,
        needsNetworkRestriction,
        allowUnixSockets,
        allowAllUnixSockets,
        allowLocalBinding,
        allowMachLookup,
        allowPty,
        allowGitConfig,
        enableWeakerNetworkIsolation,
        logTag,
    });
    // Generate proxy environment variables using shared utility
    const proxyEnvArgs = generateProxyEnvVars(httpProxyPort, socksProxyPort);
    // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
    // Resolve the full path to the shell binary
    const shellName = binShell || 'bash';
    const shell = whichSync(shellName);
    if (!shell) {
        throw new Error(`Shell '${shellName}' not found in PATH`);
    }
    // Use `env` command to set environment variables - each VAR=value is a separate
    // argument that shellquote handles properly, avoiding shell quoting issues
    const wrappedCommand = shellquote.quote([
        'env',
        ...proxyEnvArgs,
        'sandbox-exec',
        '-p',
        profile,
        shell,
        '-c',
        command,
    ]);
    logForDebugging(`[Sandbox macOS] Applied restrictions - network: ${!!(httpProxyPort || socksProxyPort)}, read: ${readConfig
        ? 'allowAllExcept' in readConfig
            ? 'allowAllExcept'
            : 'denyAllExcept'
        : 'none'}, write: ${writeConfig
        ? 'allowAllExcept' in writeConfig
            ? 'allowAllExcept'
            : 'denyAllExcept'
        : 'none'}`);
    return wrappedCommand;
}
/**
 * Start monitoring macOS system logs for sandbox violations
 * Look for sandbox-related kernel deny events ending in {logTag}
 */
export function startMacOSSandboxLogMonitor(callback, ignoreViolations) {
    // Pre-compile regex patterns for better performance
    const cmdExtractRegex = /CMD64_(.+?)_END/;
    const sandboxExtractRegex = /Sandbox:\s+(.+)$/;
    // Pre-process ignore patterns for faster lookup
    const wildcardPaths = ignoreViolations?.['*'] || [];
    const commandPatterns = ignoreViolations
        ? Object.entries(ignoreViolations).filter(([pattern]) => pattern !== '*')
        : [];
    // Stream and filter kernel logs for all sandbox violations
    // We can't filter by specific logTag since it's dynamic per command
    const logProcess = spawn('log', [
        'stream',
        '--predicate',
        `(eventMessage ENDSWITH "${sessionSuffix}")`,
        '--style',
        'compact',
    ]);
    logProcess.stdout?.on('data', (data) => {
        const lines = data.toString().split('\n');
        // Get violation and command lines
        const violationLine = lines.find(line => line.includes('Sandbox:') && line.includes('deny'));
        const commandLine = lines.find(line => line.startsWith('CMD64_'));
        if (!violationLine)
            return;
        // Extract violation details
        const sandboxMatch = violationLine.match(sandboxExtractRegex);
        if (!sandboxMatch?.[1])
            return;
        const violationDetails = sandboxMatch[1];
        // Try to get command
        let command;
        let encodedCommand;
        if (commandLine) {
            const cmdMatch = commandLine.match(cmdExtractRegex);
            encodedCommand = cmdMatch?.[1];
            if (encodedCommand) {
                try {
                    command = decodeSandboxedCommand(encodedCommand);
                }
                catch {
                    // Failed to decode, continue without command
                }
            }
        }
        // Always filter out noisey violations
        if (violationDetails.includes('mDNSResponder') ||
            violationDetails.includes('mach-lookup com.apple.diagnosticd') ||
            violationDetails.includes('mach-lookup com.apple.analyticsd')) {
            return;
        }
        // Check if we should ignore this violation
        if (ignoreViolations && command) {
            // Check wildcard patterns first
            if (wildcardPaths.length > 0) {
                const shouldIgnore = wildcardPaths.some(path => violationDetails.includes(path));
                if (shouldIgnore)
                    return;
            }
            // Check command-specific patterns
            for (const [pattern, paths] of commandPatterns) {
                if (command.includes(pattern)) {
                    const shouldIgnore = paths.some(path => violationDetails.includes(path));
                    if (shouldIgnore)
                        return;
                }
            }
        }
        // Not ignored - report the violation
        callback({
            line: violationDetails,
            command,
            encodedCommand,
            timestamp: new Date(), // We could parse the timestamp from the log but this feels more reliable
        });
        logForDebugging(`fs_deny: ${violationDetails}`);
    });
    logProcess.stderr?.on('data', (data) => {
        logForDebugging(`[Sandbox Monitor] Log stream stderr: ${data.toString()}`);
    });
    logProcess.on('error', (error) => {
        logForDebugging(`[Sandbox Monitor] Failed to start log stream: ${error.message}`);
    });
    logProcess.on('exit', (code) => {
        logForDebugging(`[Sandbox Monitor] Log stream exited with code: ${code}`);
    });
    return () => {
        logForDebugging('[Sandbox Monitor] Stopping log monitor');
        logProcess.kill('SIGTERM');
    };
}
//# sourceMappingURL=macos-sandbox-utils.js.map