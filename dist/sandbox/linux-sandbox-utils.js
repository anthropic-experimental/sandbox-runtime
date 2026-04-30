import shellquote from 'shell-quote';
import { logForDebugging } from '../utils/debug.js';
import { whichSync } from '../utils/which.js';
import { randomBytes } from 'node:crypto';
import * as fs from 'fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import path, { join } from 'node:path';
import { ripGrep } from '../utils/ripgrep.js';
import { generateProxyEnvVars, normalizePathForSandbox, normalizeCaseForComparison, isSymlinkOutsideBoundary, DANGEROUS_FILES, getDangerousDirectories, } from './sandbox-utils.js';
import { getApplySeccompBinaryPath } from './generate-seccomp-filter.js';
/** Default max depth for searching dangerous files */
const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3;
/**
 * Find if any component of the path is a symlink within the allowed write paths.
 * Returns the symlink path if found, or null if no symlinks.
 *
 * This is used to detect and block symlink replacement attacks where an attacker
 * could delete a symlink and create a real directory with malicious content.
 */
function findSymlinkInPath(targetPath, allowedWritePaths) {
    const parts = targetPath.split(path.sep);
    let currentPath = '';
    for (const part of parts) {
        if (!part)
            continue; // Skip empty parts (leading /)
        const nextPath = currentPath + path.sep + part;
        try {
            const stats = fs.lstatSync(nextPath);
            if (stats.isSymbolicLink()) {
                // Check if this symlink is within an allowed write path
                const isWithinAllowedPath = allowedWritePaths.some(allowedPath => nextPath.startsWith(allowedPath + '/') || nextPath === allowedPath);
                if (isWithinAllowedPath) {
                    return nextPath;
                }
            }
        }
        catch {
            // Path doesn't exist - no symlink issue here
            break;
        }
        currentPath = nextPath;
    }
    return null;
}
/**
 * Check if any existing component in the path is a file (not a directory).
 * If so, the target path can never be created because you can't mkdir under a file.
 *
 * This handles the git worktree case: .git is a file, so .git/hooks can never
 * exist and there's nothing to deny.
 */
function hasFileAncestor(targetPath) {
    const parts = targetPath.split(path.sep);
    let currentPath = '';
    for (const part of parts) {
        if (!part)
            continue; // Skip empty parts (leading /)
        const nextPath = currentPath + path.sep + part;
        try {
            const stat = fs.statSync(nextPath);
            if (stat.isFile() || stat.isSymbolicLink()) {
                // This component exists as a file — nothing below it can be created
                return true;
            }
        }
        catch {
            // Path doesn't exist — stop checking
            break;
        }
        currentPath = nextPath;
    }
    return false;
}
/**
 * Find the first non-existent path component.
 * E.g., for "/existing/parent/nonexistent/child/file.txt" where /existing/parent exists,
 * returns "/existing/parent/nonexistent"
 *
 * This is used to block creation of non-existent deny paths by mounting /dev/null
 * at the first missing component, preventing mkdir from creating the parent directories.
 */
function findFirstNonExistentComponent(targetPath) {
    const parts = targetPath.split(path.sep);
    let currentPath = '';
    for (const part of parts) {
        if (!part)
            continue; // Skip empty parts (leading /)
        const nextPath = currentPath + path.sep + part;
        if (!fs.existsSync(nextPath)) {
            return nextPath;
        }
        currentPath = nextPath;
    }
    return targetPath; // Shouldn't reach here if called correctly
}
/**
 * Get mandatory deny paths using ripgrep (Linux only).
 * Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
 * With --max-depth limiting, this is fast enough to run on each command without memoization.
 */
async function linuxGetMandatoryDenyPaths(ripgrepConfig = { command: 'rg' }, maxDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH, allowGitConfig = false, abortSignal) {
    const cwd = process.cwd();
    // Use provided signal or create a fallback controller
    const fallbackController = new AbortController();
    const signal = abortSignal ?? fallbackController.signal;
    const dangerousDirectories = getDangerousDirectories();
    // Note: Settings files are added at the callsite in sandbox-manager.ts
    const denyPaths = [
        // Dangerous files in CWD
        ...DANGEROUS_FILES.map(f => path.resolve(cwd, f)),
        // Dangerous directories in CWD
        ...dangerousDirectories.map(d => path.resolve(cwd, d)),
    ];
    // Git hooks and config are only denied when .git exists as a directory.
    // In git worktrees, .git is a file (e.g., "gitdir: /path/..."), so
    // .git/hooks can never exist — denying it would cause bwrap to fail.
    // When .git doesn't exist at all, mounting at .git would block its
    // creation and break git init.
    const dotGitPath = path.resolve(cwd, '.git');
    let dotGitIsDirectory = false;
    try {
        dotGitIsDirectory = fs.statSync(dotGitPath).isDirectory();
    }
    catch {
        // .git doesn't exist
    }
    if (dotGitIsDirectory) {
        // Git hooks always blocked for security
        denyPaths.push(path.resolve(cwd, '.git/hooks'));
        // Git config conditionally blocked based on allowGitConfig setting
        if (!allowGitConfig) {
            denyPaths.push(path.resolve(cwd, '.git/config'));
        }
    }
    // Build iglob args for all patterns in one ripgrep call
    const iglobArgs = [];
    for (const fileName of DANGEROUS_FILES) {
        iglobArgs.push('--iglob', fileName);
    }
    for (const dirName of dangerousDirectories) {
        iglobArgs.push('--iglob', `**/${dirName}/**`);
    }
    // Git hooks always blocked in nested repos
    iglobArgs.push('--iglob', '**/.git/hooks/**');
    // Git config conditionally blocked in nested repos
    if (!allowGitConfig) {
        iglobArgs.push('--iglob', '**/.git/config');
    }
    // Single ripgrep call to find all dangerous paths in subdirectories
    // Limit depth for performance - deeply nested dangerous files are rare
    // and the security benefit doesn't justify the traversal cost
    let matches = [];
    try {
        matches = await ripGrep([
            '--files',
            '--hidden',
            '--max-depth',
            String(maxDepth),
            ...iglobArgs,
            '-g',
            '!**/node_modules/**',
        ], cwd, signal, ripgrepConfig);
    }
    catch (error) {
        logForDebugging(`[Sandbox] ripgrep scan failed: ${error}`);
    }
    // Process matches
    for (const match of matches) {
        const absolutePath = path.resolve(cwd, match);
        // File inside a dangerous directory -> add the directory path
        let foundDir = false;
        for (const dirName of [...dangerousDirectories, '.git']) {
            const normalizedDirName = normalizeCaseForComparison(dirName);
            const segments = absolutePath.split(path.sep);
            const dirIndex = segments.findIndex(s => normalizeCaseForComparison(s) === normalizedDirName);
            if (dirIndex !== -1) {
                // For .git, we want hooks/ or config, not the whole .git dir
                if (dirName === '.git') {
                    const gitDir = segments.slice(0, dirIndex + 1).join(path.sep);
                    if (match.includes('.git/hooks')) {
                        denyPaths.push(path.join(gitDir, 'hooks'));
                    }
                    else if (match.includes('.git/config')) {
                        denyPaths.push(path.join(gitDir, 'config'));
                    }
                }
                else {
                    denyPaths.push(segments.slice(0, dirIndex + 1).join(path.sep));
                }
                foundDir = true;
                break;
            }
        }
        // Dangerous file match
        if (!foundDir) {
            denyPaths.push(absolutePath);
        }
    }
    return [...new Set(denyPaths)];
}
// Track mount points created by bwrap for non-existent deny paths.
// When bwrap does --ro-bind /dev/null /nonexistent/path, it creates an empty
// file on the host as a mount point. These persist after bwrap exits and must
// be cleaned up explicitly.
const bwrapMountPoints = new Set();
// Number of wrapped commands that have been generated but whose cleanup has
// not yet run. cleanupBwrapMountPoints() defers file deletion while this is
// positive, because deleting a mount point file on the host while another
// bwrap instance is still running detaches that instance's bind mount and
// the deny rule stops applying inside it.
let activeSandboxCount = 0;
let exitHandlerRegistered = false;
/**
 * Register cleanup handler for bwrap mount points
 */
function registerExitCleanupHandler() {
    if (exitHandlerRegistered) {
        return;
    }
    process.on('exit', () => {
        cleanupBwrapMountPoints({ force: true });
    });
    exitHandlerRegistered = true;
}
/**
 * Clean up mount point files created by bwrap for non-existent deny paths.
 *
 * When protecting non-existent deny paths, bwrap creates empty files on the
 * host filesystem as mount points for --ro-bind. These files persist after
 * bwrap exits. This function removes them.
 *
 * This should be called after each sandboxed command completes to prevent
 * ghost dotfiles (e.g. .bashrc, .gitconfig) from appearing in the working
 * directory. It is also called automatically on process exit as a safety net.
 *
 * Each call decrements the active-sandbox counter that was incremented by
 * wrapCommandWithSandboxLinux(). File deletion is deferred until the counter
 * reaches zero. Deleting a mount point file on the host while another bwrap
 * instance is still running detaches that instance's bind mount (the dentry
 * is unhashed, so path lookup no longer finds the mount) and the deny rule
 * stops applying inside that sandbox.
 *
 * Pass `{ force: true }` to delete unconditionally — used by the process-exit
 * handler and reset() where deferral is not meaningful.
 */
export function cleanupBwrapMountPoints(opts) {
    if (!opts?.force) {
        if (activeSandboxCount > 0) {
            activeSandboxCount--;
        }
        if (activeSandboxCount > 0) {
            logForDebugging(`[Sandbox Linux] Deferring mount point cleanup — ${activeSandboxCount} sandbox(es) still active`);
            return;
        }
    }
    else {
        activeSandboxCount = 0;
    }
    for (const mountPoint of bwrapMountPoints) {
        try {
            // Only remove if it's still the empty file/directory bwrap created.
            // If something else has written real content, leave it alone.
            const stat = fs.statSync(mountPoint);
            if (stat.isFile() && stat.size === 0) {
                fs.unlinkSync(mountPoint);
                logForDebugging(`[Sandbox Linux] Cleaned up bwrap mount point (file): ${mountPoint}`);
            }
            else if (stat.isDirectory()) {
                // Empty directory mount points are created for intermediate
                // components (Fix 2). Only remove if still empty.
                const entries = fs.readdirSync(mountPoint);
                if (entries.length === 0) {
                    fs.rmdirSync(mountPoint);
                    logForDebugging(`[Sandbox Linux] Cleaned up bwrap mount point (dir): ${mountPoint}`);
                }
            }
        }
        catch {
            // Ignore cleanup errors — the file may have already been removed
        }
    }
    bwrapMountPoints.clear();
}
/**
 * Get detailed status of Linux sandbox dependencies
 */
export function getLinuxDependencyStatus(seccompConfig) {
    // argv0 mode: apply-seccomp is compiled into the caller's binary — skip
    // the on-disk lookup and trust that applyPath resolves inside bwrap.
    return {
        hasBwrap: whichSync('bwrap') !== null,
        hasSocat: whichSync('socat') !== null,
        hasSeccompApply: seccompConfig?.argv0
            ? true
            : getApplySeccompBinaryPath(seccompConfig?.applyPath) !== null,
    };
}
/**
 * Check sandbox dependencies and return structured result
 */
export function checkLinuxDependencies(seccompConfig) {
    const errors = [];
    const warnings = [];
    if (whichSync('bwrap') === null)
        errors.push('bubblewrap (bwrap) not installed');
    if (whichSync('socat') === null)
        errors.push('socat not installed');
    if (!seccompConfig?.argv0 &&
        getApplySeccompBinaryPath(seccompConfig?.applyPath) === null) {
        warnings.push('seccomp not available - unix socket access not restricted');
    }
    return { warnings, errors };
}
/**
 * Initialize the Linux network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * Linux network sandboxing uses bwrap --unshare-net which creates a completely isolated
 * network namespace with NO network access. To enable network access, we:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Sandbox side: Bind the Unix sockets into the isolated namespace and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - GIT_SSH_COMMAND with socat for SSH through SOCKS5
 *
 * LIMITATION: Unlike macOS sandbox which can enforce domain-based allowlists at the kernel level,
 * Linux's --unshare-net provides only all-or-nothing network isolation. Domain filtering happens
 * at the host proxy level, not the sandbox boundary. This means network restrictions on Linux
 * depend on the proxy's filtering capabilities.
 *
 * DEPENDENCIES: Requires bwrap (bubblewrap) and socat
 */
export async function initializeLinuxNetworkBridge(httpProxyPort, socksProxyPort) {
    const socketId = randomBytes(8).toString('hex');
    const httpSocketPath = join(tmpdir(), `claude-http-${socketId}.sock`);
    const socksSocketPath = join(tmpdir(), `claude-socks-${socketId}.sock`);
    // Start HTTP bridge
    const httpSocatArgs = [
        `UNIX-LISTEN:${httpSocketPath},fork,reuseaddr`,
        `TCP:localhost:${httpProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
    ];
    logForDebugging(`Starting HTTP bridge: socat ${httpSocatArgs.join(' ')}`);
    const httpBridgeProcess = spawn('socat', httpSocatArgs, {
        stdio: 'ignore',
    });
    if (!httpBridgeProcess.pid) {
        throw new Error('Failed to start HTTP bridge process');
    }
    // Add error and exit handlers to monitor bridge health
    httpBridgeProcess.on('error', err => {
        logForDebugging(`HTTP bridge process error: ${err}`, { level: 'error' });
    });
    httpBridgeProcess.on('exit', (code, signal) => {
        logForDebugging(`HTTP bridge process exited with code ${code}, signal ${signal}`, { level: code === 0 ? 'info' : 'error' });
    });
    // Start SOCKS bridge
    const socksSocatArgs = [
        `UNIX-LISTEN:${socksSocketPath},fork,reuseaddr`,
        `TCP:localhost:${socksProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
    ];
    logForDebugging(`Starting SOCKS bridge: socat ${socksSocatArgs.join(' ')}`);
    const socksBridgeProcess = spawn('socat', socksSocatArgs, {
        stdio: 'ignore',
    });
    if (!socksBridgeProcess.pid) {
        // Clean up HTTP bridge
        if (httpBridgeProcess.pid) {
            try {
                process.kill(httpBridgeProcess.pid, 'SIGTERM');
            }
            catch {
                // Ignore errors
            }
        }
        throw new Error('Failed to start SOCKS bridge process');
    }
    // Add error and exit handlers to monitor bridge health
    socksBridgeProcess.on('error', err => {
        logForDebugging(`SOCKS bridge process error: ${err}`, { level: 'error' });
    });
    socksBridgeProcess.on('exit', (code, signal) => {
        logForDebugging(`SOCKS bridge process exited with code ${code}, signal ${signal}`, { level: code === 0 ? 'info' : 'error' });
    });
    // Wait for both sockets to be ready
    const maxAttempts = 5;
    for (let i = 0; i < maxAttempts; i++) {
        if (!httpBridgeProcess.pid ||
            httpBridgeProcess.killed ||
            !socksBridgeProcess.pid ||
            socksBridgeProcess.killed) {
            throw new Error('Linux bridge process died unexpectedly');
        }
        try {
            // fs already imported
            if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSocketPath)) {
                logForDebugging(`Linux bridges ready after ${i + 1} attempts`);
                break;
            }
        }
        catch (err) {
            logForDebugging(`Error checking sockets (attempt ${i + 1}): ${err}`, {
                level: 'error',
            });
        }
        if (i === maxAttempts - 1) {
            // Clean up both processes
            if (httpBridgeProcess.pid) {
                try {
                    process.kill(httpBridgeProcess.pid, 'SIGTERM');
                }
                catch {
                    // Ignore errors
                }
            }
            if (socksBridgeProcess.pid) {
                try {
                    process.kill(socksBridgeProcess.pid, 'SIGTERM');
                }
                catch {
                    // Ignore errors
                }
            }
            throw new Error(`Failed to create bridge sockets after ${maxAttempts} attempts`);
        }
        await new Promise(resolve => setTimeout(resolve, i * 100));
    }
    return {
        httpSocketPath,
        socksSocketPath,
        httpBridgeProcess,
        socksBridgeProcess,
        httpProxyPort,
        socksProxyPort,
    };
}
/**
 * Resolve how to invoke apply-seccomp: either a standalone binary path, or a
 * multicall-binary prefix that dispatches on the ARGV0 env var.
 *
 * Returns a shell-ready string ending in a trailing space — callers append
 * shellquote.quote([shell, '-c', cmd]). Returns undefined when seccomp is
 * unavailable (no argv0, no binary found).
 *
 * When argv0 is set, applyPath is used verbatim (no existence check); the
 * caller is responsible for ensuring it resolves inside the bwrap namespace.
 */
function resolveApplySeccompPrefix(applyPath, argv0) {
    if (argv0) {
        if (!applyPath) {
            throw new Error('seccompConfig.argv0 requires seccompConfig.applyPath');
        }
        return `ARGV0=${shellquote.quote([argv0])} ${shellquote.quote([applyPath])} `;
    }
    const binary = getApplySeccompBinaryPath(applyPath);
    return binary ? `${shellquote.quote([binary])} ` : undefined;
}
/**
 * Build the command that runs inside the sandbox.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 */
function buildSandboxCommand(httpSocketPath, socksSocketPath, userCommand, applySeccompPrefix, shell) {
    // Default to bash for backward compatibility
    const shellPath = shell || 'bash';
    const socatCommands = [
        `socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:${httpSocketPath} >/dev/null 2>&1 &`,
        `socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:${socksSocketPath} >/dev/null 2>&1 &`,
        'trap "kill %1 %2 2>/dev/null; exit" EXIT',
    ];
    // apply-seccomp runs after socat so socat can still create Unix sockets.
    if (applySeccompPrefix) {
        const applySeccompCmd = applySeccompPrefix + shellquote.quote([shellPath, '-c', userCommand]);
        const innerScript = [...socatCommands, applySeccompCmd].join('\n');
        return `${shellPath} -c ${shellquote.quote([innerScript])}`;
    }
    else {
        const innerScript = [
            ...socatCommands,
            `eval ${shellquote.quote([userCommand])}`,
        ].join('\n');
        return `${shellPath} -c ${shellquote.quote([innerScript])}`;
    }
}
/**
 * Generate filesystem bind mount arguments for bwrap
 */
async function generateFilesystemArgs(readConfig, writeConfig, ripgrepConfig = { command: 'rg' }, mandatoryDenySearchDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH, allowGitConfig = false, abortSignal) {
    const args = [];
    // fs already imported
    // Collect normalized allowed write paths. Populated in the writeConfig
    // block, read again in the denyRead loop to re-bind writes under tmpfs.
    const allowedWritePaths = [];
    // denyWrite binds are buffered and emitted after denyRead processing so that
    // a denyRead tmpfs over an ancestor directory doesn't wipe them out.
    const denyWriteArgs = [];
    // Determine initial root mount based on write restrictions
    if (writeConfig) {
        // Write restrictions: Start with read-only root, then allow writes to specific paths
        args.push('--ro-bind', '/', '/');
        // Allow writes to specific paths
        for (const pathPattern of writeConfig.allowOnly || []) {
            const normalizedPath = normalizePathForSandbox(pathPattern);
            logForDebugging(`[Sandbox Linux] Processing write path: ${pathPattern} -> ${normalizedPath}`);
            // Skip /dev/* paths since --dev /dev already handles them
            if (normalizedPath.startsWith('/dev/')) {
                logForDebugging(`[Sandbox Linux] Skipping /dev path: ${normalizedPath}`);
                continue;
            }
            if (!fs.existsSync(normalizedPath)) {
                logForDebugging(`[Sandbox Linux] Skipping non-existent write path: ${normalizedPath}`);
                continue;
            }
            // Check if path is a symlink pointing outside expected boundaries
            // bwrap follows symlinks, so --bind on a symlink makes the target writable
            // This could unexpectedly expose paths the user didn't intend to allow
            try {
                const resolvedPath = fs.realpathSync(normalizedPath);
                // Trim trailing slashes before comparing: realpathSync never returns
                // a trailing slash, but normalizedPath may have one, which would cause
                // a false mismatch and incorrectly treat the path as a symlink.
                const normalizedForComparison = normalizedPath.replace(/\/+$/, '');
                if (resolvedPath !== normalizedForComparison &&
                    isSymlinkOutsideBoundary(normalizedPath, resolvedPath)) {
                    logForDebugging(`[Sandbox Linux] Skipping symlink write path pointing outside expected location: ${pathPattern} -> ${resolvedPath}`);
                    continue;
                }
            }
            catch {
                // realpathSync failed - path might not exist or be accessible, skip it
                logForDebugging(`[Sandbox Linux] Skipping write path that could not be resolved: ${normalizedPath}`);
                continue;
            }
            args.push('--bind', normalizedPath, normalizedPath);
            allowedWritePaths.push(normalizedPath);
        }
        // Deny writes within allowed paths (user-specified + mandatory denies)
        const denyPaths = [
            ...(writeConfig.denyWithinAllow || []),
            ...(await linuxGetMandatoryDenyPaths(ripgrepConfig, mandatoryDenySearchDepth, allowGitConfig, abortSignal)),
        ];
        // Dedup post-normalization: entries like ['~/.foo', '/home/user/.foo']
        // converge to the same path here. A duplicate --ro-bind /dev/null <dest>
        // hits a char device on the second pass and bwrap's ensure_file() falls
        // through to creat() on a read-only mount.
        const seenDenyWrite = new Set();
        for (const pathPattern of denyPaths) {
            const normalizedPath = normalizePathForSandbox(pathPattern);
            if (seenDenyWrite.has(normalizedPath))
                continue;
            seenDenyWrite.add(normalizedPath);
            // Skip /dev/* paths since --dev /dev already handles them
            if (normalizedPath.startsWith('/dev/')) {
                continue;
            }
            // Check for symlinks in the path - if any parent component is a symlink,
            // mount /dev/null there to prevent symlink replacement attacks.
            // Attack scenario: .claude is a symlink to ./decoy/, attacker deletes
            // symlink and creates real .claude/settings.json with malicious hooks.
            const symlinkInPath = findSymlinkInPath(normalizedPath, allowedWritePaths);
            if (symlinkInPath) {
                denyWriteArgs.push('--ro-bind', '/dev/null', symlinkInPath);
                logForDebugging(`[Sandbox Linux] Mounted /dev/null at symlink ${symlinkInPath} to prevent symlink replacement attack`);
                continue;
            }
            // Handle non-existent paths by mounting /dev/null to block creation.
            // Without this, a sandboxed process could mkdir+write a denied path that
            // doesn't exist yet, bypassing the deny rule entirely.
            //
            // bwrap creates empty files on the host as mount points for these binds.
            // We track them in bwrapMountPoints so cleanupBwrapMountPoints() can
            // remove them after the command exits.
            if (!fs.existsSync(normalizedPath)) {
                // Fix 1 (worktree): If any existing component in the deny path is a
                // file (not a directory), skip the deny entirely. You can't mkdir
                // under a file, so the deny path can never be created. This handles
                // git worktrees where .git is a file.
                if (hasFileAncestor(normalizedPath)) {
                    logForDebugging(`[Sandbox Linux] Skipping deny path with file ancestor (cannot create paths under a file): ${normalizedPath}`);
                    continue;
                }
                // Find the deepest existing ancestor directory
                let ancestorPath = path.dirname(normalizedPath);
                while (ancestorPath !== '/' && !fs.existsSync(ancestorPath)) {
                    ancestorPath = path.dirname(ancestorPath);
                }
                // Only protect if the existing ancestor is within an allowed write path.
                // If not, the path is already read-only from --ro-bind / /.
                const ancestorIsWithinAllowedPath = allowedWritePaths.some(allowedPath => ancestorPath.startsWith(allowedPath + '/') ||
                    ancestorPath === allowedPath ||
                    normalizedPath.startsWith(allowedPath + '/'));
                if (ancestorIsWithinAllowedPath) {
                    const firstNonExistent = findFirstNonExistentComponent(normalizedPath);
                    // Fix 2: If firstNonExistent is an intermediate component (not the
                    // leaf deny path itself), mount a read-only empty directory instead
                    // of /dev/null. This prevents the component from appearing as a file
                    // which breaks tools that expect to traverse it as a directory.
                    if (firstNonExistent !== normalizedPath) {
                        const emptyDir = fs.mkdtempSync(path.join(tmpdir(), 'claude-empty-'));
                        denyWriteArgs.push('--ro-bind', emptyDir, firstNonExistent);
                        bwrapMountPoints.add(firstNonExistent);
                        registerExitCleanupHandler();
                        logForDebugging(`[Sandbox Linux] Mounted empty dir at ${firstNonExistent} to block creation of ${normalizedPath}`);
                    }
                    else {
                        denyWriteArgs.push('--ro-bind', '/dev/null', firstNonExistent);
                        bwrapMountPoints.add(firstNonExistent);
                        registerExitCleanupHandler();
                        logForDebugging(`[Sandbox Linux] Mounted /dev/null at ${firstNonExistent} to block creation of ${normalizedPath}`);
                    }
                }
                else {
                    logForDebugging(`[Sandbox Linux] Skipping non-existent deny path not within allowed paths: ${normalizedPath}`);
                }
                continue;
            }
            // Only add deny binding if this path is within an allowed write path
            // Otherwise it's already read-only from the initial --ro-bind / /
            const isWithinAllowedPath = allowedWritePaths.some(allowedPath => normalizedPath.startsWith(allowedPath + '/') ||
                normalizedPath === allowedPath);
            if (isWithinAllowedPath) {
                denyWriteArgs.push('--ro-bind', normalizedPath, normalizedPath);
            }
            else {
                logForDebugging(`[Sandbox Linux] Skipping deny path not within allowed paths: ${normalizedPath}`);
            }
        }
    }
    else {
        // No write restrictions: Allow all writes
        args.push('--bind', '/', '/');
    }
    // denyWriteArgs is emitted after the denyRead loop below.
    // Handle read restrictions by mounting tmpfs over denied paths
    const readDenyPaths = [];
    const readAllowPaths = (readConfig?.allowWithinDeny || []).map(p => normalizePathForSandbox(p));
    // Files masked by --ro-bind /dev/null below. Used to filter denyWriteArgs so
    // that --ro-bind <host> <host> doesn't undo the mask.
    const maskedFiles = new Set();
    // --tmpfs / would wipe all prior mounts (ro-bind /, write binds, deny binds).
    // Expand a root deny into its direct children so the existing per-dir tmpfs
    // + re-bind logic applies. Skip /proc and /dev: they're remounted by the
    // caller after this function returns. Skip /sys: kernel interface, tmpfs
    // over it breaks tooling and the host /sys is already read-only via ro-bind.
    const rootSkip = new Set(['proc', 'dev', 'sys']);
    for (const p of readConfig?.denyOnly || []) {
        if (normalizePathForSandbox(p) === '/') {
            for (const child of fs.readdirSync('/')) {
                if (!rootSkip.has(child))
                    readDenyPaths.push('/' + child);
            }
        }
        else {
            readDenyPaths.push(p);
        }
    }
    // Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
    // SSH is very strict about config file permissions and ownership, and they can
    // appear wrong inside the sandbox causing "Bad owner or permissions" errors
    if (fs.existsSync('/etc/ssh/ssh_config.d')) {
        readDenyPaths.push('/etc/ssh/ssh_config.d');
    }
    // Normalize then sort shallow-first so tmpfs over ancestor dirs lands before
    // /dev/null masks on descendant files. Otherwise a file-deny listed before
    // a dir-deny in denyRead gets wiped when the ancestor tmpfs is applied.
    const normalizedDenyPaths = readDenyPaths
        .map(p => normalizePathForSandbox(p))
        .sort((a, b) => a.split('/').length - b.split('/').length);
    for (const normalizedPath of normalizedDenyPaths) {
        if (!fs.existsSync(normalizedPath)) {
            logForDebugging(`[Sandbox Linux] Skipping non-existent read deny path: ${normalizedPath}`);
            continue;
        }
        const denySep = normalizedPath === '/' ? '/' : normalizedPath + '/';
        const readDenyStat = fs.statSync(normalizedPath);
        if (readDenyStat.isDirectory()) {
            args.push('--tmpfs', normalizedPath);
            // tmpfs wiped any earlier write binds under this path — restore them.
            for (const writePath of allowedWritePaths) {
                if (writePath.startsWith(denySep) || writePath === normalizedPath) {
                    args.push('--bind', writePath, writePath);
                    logForDebugging(`[Sandbox Linux] Re-bound write path wiped by denyRead tmpfs: ${writePath}`);
                }
            }
            // Re-allow specific paths within the denied directory (allowRead overrides denyRead).
            // After mounting tmpfs over the denied dir, bind back the allowed subdirectories
            // so they are readable again.
            for (const allowPath of readAllowPaths) {
                if (allowPath.startsWith(denySep) || allowPath === normalizedPath) {
                    if (!fs.existsSync(allowPath)) {
                        logForDebugging(`[Sandbox Linux] Skipping non-existent read allow path: ${allowPath}`);
                        continue;
                    }
                    // Skip only if a write path was re-bound just above AND covers
                    // allowPath. A write path that's an ancestor of the deny dir isn't
                    // re-bound (it wasn't wiped), so allowPath under it still needs
                    // its own ro-bind here.
                    if (allowedWritePaths.some(w => (w.startsWith(denySep) || w === normalizedPath) &&
                        (allowPath === w || allowPath.startsWith(w + '/')))) {
                        continue;
                    }
                    // Bind the allowed path back over the tmpfs so it's readable
                    args.push('--ro-bind', allowPath, allowPath);
                    logForDebugging(`[Sandbox Linux] Re-allowed read access within denied region: ${allowPath}`);
                }
            }
        }
        else {
            // For files, only an exact allowRead match overrides the deny. A
            // directory allowRead does not un-deny a file specifically listed in
            // denyRead — otherwise denyRead: ['.env'] + allowRead: ['.'] silently
            // drops the .env deny.
            if (readAllowPaths.includes(normalizedPath)) {
                logForDebugging(`[Sandbox Linux] Skipping read deny for re-allowed path: ${normalizedPath}`);
                continue;
            }
            // For files, bind /dev/null instead of tmpfs
            args.push('--ro-bind', '/dev/null', normalizedPath);
            maskedFiles.add(normalizedPath);
        }
    }
    // Emitting denyWrite last means these ro-binds layer on top of any write
    // paths the denyRead loop just re-bound. Before this ordering, tmpfs over
    // an ancestor of cwd would wipe the .git/hooks protection. But skip any
    // dest already masked by denyRead — --ro-bind <host> <host> for denyWrite
    // would undo --ro-bind /dev/null <host> from denyRead, which landed first.
    for (let i = 0; i < denyWriteArgs.length; i += 3) {
        const dest = denyWriteArgs[i + 2];
        if (maskedFiles.has(dest))
            continue;
        args.push(denyWriteArgs[i], denyWriteArgs[i + 1], dest);
    }
    return args;
}
/**
 * Wrap a command with sandbox restrictions on Linux
 *
 * UNIX SOCKET BLOCKING (APPLY-SECCOMP):
 * This implementation uses a custom apply-seccomp binary to block Unix domain socket
 * creation for user commands while allowing network infrastructure:
 *
 * Stage 1: Outer bwrap - Network and filesystem isolation (NO seccomp)
 *   - Bubblewrap starts with isolated network namespace (--unshare-net)
 *   - Bubblewrap applies PID namespace isolation (--unshare-pid and --proc)
 *   - Filesystem restrictions are applied (read-only mounts, bind mounts, etc.)
 *   - Socat processes start and connect to Unix socket bridges (can use socket(AF_UNIX, ...))
 *
 * Stage 2: apply-seccomp - Nested PID namespace + seccomp filter
 *   - apply-seccomp creates a nested user+PID+mount namespace and remounts /proc
 *   - Inside, apply-seccomp becomes PID 1 (non-dumpable init/reaper)
 *   - Forks, sets PR_SET_NO_NEW_PRIVS, applies seccomp via prctl(PR_SET_SECCOMP)
 *   - Execs user command with seccomp active (cannot create new Unix sockets)
 *   - User command cannot see or ptrace bwrap/bash/socat (separate PID namespace)
 *
 * This solves the conflict between:
 * - Security: Blocking arbitrary Unix socket creation in user commands
 * - Functionality: Network sandboxing requires socat to call socket(AF_UNIX, ...) for bridge connections
 *
 * The seccomp-bpf filter blocks socket(AF_UNIX, ...) syscalls, preventing:
 * - Creating new Unix domain socket file descriptors
 *
 * Security limitations:
 * - Does NOT block operations (bind, connect, sendto, etc.) on inherited Unix socket FDs
 * - Does NOT prevent passing Unix socket FDs via SCM_RIGHTS
 * - For most sandboxing use cases, blocking socket creation is sufficient
 *
 * The filter allows:
 * - All TCP/UDP sockets (AF_INET, AF_INET6) for normal network operations
 * - All other syscalls
 *
 * PLATFORM NOTE:
 * The allowUnixSockets configuration is not path-based on Linux (unlike macOS)
 * because seccomp-bpf cannot inspect user-space memory to read socket paths.
 *
 * Requirements for seccomp filtering:
 * - Pre-built apply-seccomp binaries are included for x64 and ARM64
 * - Pre-generated BPF filters are included for x64 and ARM64
 * - Other architectures are not currently supported (no apply-seccomp binary available)
 * - To use sandboxing without Unix socket blocking on unsupported architectures,
 *   set allowAllUnixSockets: true in your configuration
 * Dependencies are checked by checkLinuxDependencies() before enabling the sandbox.
 */
export async function wrapCommandWithSandboxLinux(params) {
    const { command, needsNetworkRestriction, httpSocketPath, socksSocketPath, httpProxyPort, socksProxyPort, readConfig, writeConfig, enableWeakerNestedSandbox, allowAllUnixSockets, binShell, ripgrepConfig = { command: 'rg' }, mandatoryDenySearchDepth = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH, allowGitConfig = false, seccompConfig, abortSignal, } = params;
    // Determine if we have restrictions to apply
    // Read: denyOnly pattern - empty array means no restrictions
    // Write: allowOnly pattern - undefined means no restrictions, any config means restrictions
    const hasReadRestrictions = readConfig && readConfig.denyOnly.length > 0;
    const hasWriteRestrictions = writeConfig !== undefined;
    // Check if we need any sandboxing
    if (!needsNetworkRestriction &&
        !hasReadRestrictions &&
        !hasWriteRestrictions) {
        return command;
    }
    // Mark this sandbox invocation as active. cleanupBwrapMountPoints() will
    // defer file deletion until this (and every other concurrent) invocation
    // has been cleaned up. The matching decrement happens in
    // cleanupBwrapMountPoints(), which the caller must invoke after the
    // spawned command exits. If wrapping fails below, the catch block
    // decrements so the count does not leak.
    activeSandboxCount++;
    const bwrapArgs = ['--new-session', '--die-with-parent'];
    let applySeccompPrefix;
    try {
        // ========== SECCOMP FILTER (Unix Socket Blocking) ==========
        // apply-seccomp wraps the workload and applies the baked-in BPF filter
        // that blocks socket(AF_UNIX, ...). Skipped when allowAllUnixSockets is true.
        if (!allowAllUnixSockets) {
            applySeccompPrefix = resolveApplySeccompPrefix(seccompConfig?.applyPath, seccompConfig?.argv0);
            if (!applySeccompPrefix) {
                logForDebugging('[Sandbox Linux] apply-seccomp binary not available - unix socket blocking disabled. ' +
                    'Install @anthropic-ai/sandbox-runtime globally for full protection.', { level: 'warn' });
            }
            else {
                logForDebugging('[Sandbox Linux] Applying seccomp filter for Unix socket blocking');
            }
        }
        else {
            logForDebugging('[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled');
        }
        // ========== NETWORK RESTRICTIONS ==========
        if (needsNetworkRestriction) {
            // Always unshare network namespace to isolate network access
            // This removes all network interfaces, effectively blocking all network
            bwrapArgs.push('--unshare-net');
            // If proxy sockets are provided, bind them into the sandbox to allow
            // filtered network access through the proxy. If not provided, network
            // is completely blocked (empty allowedDomains = block all)
            if (httpSocketPath && socksSocketPath) {
                // Verify socket files still exist before trying to bind them
                if (!fs.existsSync(httpSocketPath)) {
                    throw new Error(`Linux HTTP bridge socket does not exist: ${httpSocketPath}. ` +
                        'The bridge process may have died. Try reinitializing the sandbox.');
                }
                if (!fs.existsSync(socksSocketPath)) {
                    throw new Error(`Linux SOCKS bridge socket does not exist: ${socksSocketPath}. ` +
                        'The bridge process may have died. Try reinitializing the sandbox.');
                }
                // Bind both sockets into the sandbox
                bwrapArgs.push('--bind', httpSocketPath, httpSocketPath);
                bwrapArgs.push('--bind', socksSocketPath, socksSocketPath);
                // Add proxy environment variables
                // HTTP_PROXY points to the socat listener inside the sandbox (port 3128)
                // which forwards to the Unix socket that bridges to the host's proxy server
                const proxyEnv = generateProxyEnvVars(3128, // Internal HTTP listener port
                1080);
                bwrapArgs.push(...proxyEnv.flatMap((env) => {
                    const firstEq = env.indexOf('=');
                    const key = env.slice(0, firstEq);
                    const value = env.slice(firstEq + 1);
                    return ['--setenv', key, value];
                }));
                // Add host proxy port environment variables for debugging/transparency
                // These show which host ports the Unix socket bridges connect to
                if (httpProxyPort !== undefined) {
                    bwrapArgs.push('--setenv', 'CLAUDE_CODE_HOST_HTTP_PROXY_PORT', String(httpProxyPort));
                }
                if (socksProxyPort !== undefined) {
                    bwrapArgs.push('--setenv', 'CLAUDE_CODE_HOST_SOCKS_PROXY_PORT', String(socksProxyPort));
                }
            }
            // If no sockets provided, network is completely blocked (--unshare-net without proxy)
        }
        // ========== FILESYSTEM RESTRICTIONS ==========
        const fsArgs = await generateFilesystemArgs(readConfig, writeConfig, ripgrepConfig, mandatoryDenySearchDepth, allowGitConfig, abortSignal);
        bwrapArgs.push(...fsArgs);
        // Always bind /dev
        bwrapArgs.push('--dev', '/dev');
        // ========== PID NAMESPACE ISOLATION ==========
        // IMPORTANT: These must come AFTER filesystem binds for nested bwrap to work
        // By default, always unshare PID namespace and mount fresh /proc.
        // If we don't have --unshare-pid, it is possible to escape the sandbox.
        // If we don't have --proc, it is possible to read host /proc and leak information about code running
        // outside the sandbox. But, --proc is not available when running in unprivileged docker containers
        // so we support running without it if explicitly requested.
        bwrapArgs.push('--unshare-pid');
        if (!enableWeakerNestedSandbox) {
            // Mount fresh /proc if PID namespace is isolated (secure mode)
            bwrapArgs.push('--proc', '/proc');
        }
        else {
            // --unshare-user: bwrap only auto-adds this when EUID != 0. In an
            // unprivileged container (Docker's default: EUID=0 without
            // CAP_SYS_ADMIN), bwrap assumes it has caps, tries direct clone,
            // and EPERMs. Force the userns path so bwrap starts at all.
            //
            // --bind /proc /proc: apply-seccomp's nested-userns path writes
            // /proc/self/setgroups and uid_map. Without --proc above, the
            // --ro-bind / / leaves /proc read-only and those writes EROFS.
            bwrapArgs.push('--unshare-user', '--bind', '/proc', '/proc');
        }
        // apply-seccomp obtains CAP_SYS_ADMIN for its nested PID+mount unshare
        // by creating a nested user namespace. This requires the host to permit
        // capability-bearing unprivileged user namespaces (the same requirement
        // bwrap itself has when not installed setuid). See README for the
        // Ubuntu 24.04 sysctl if AppArmor restricts this.
        // ========== COMMAND ==========
        // Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
        // Resolve the full path to the shell binary since bwrap doesn't use $PATH
        const shellName = binShell || 'bash';
        const shell = whichSync(shellName);
        if (!shell) {
            throw new Error(`Shell '${shellName}' not found in PATH`);
        }
        bwrapArgs.push('--', shell, '-c');
        // With network restrictions, route the command through buildSandboxCommand
        // so socat starts before seccomp is applied. Otherwise invoke apply-seccomp
        // directly if we have a binary.
        if (needsNetworkRestriction && httpSocketPath && socksSocketPath) {
            const sandboxCommand = buildSandboxCommand(httpSocketPath, socksSocketPath, command, applySeccompPrefix, shell);
            bwrapArgs.push(sandboxCommand);
        }
        else if (applySeccompPrefix) {
            const applySeccompCmd = applySeccompPrefix + shellquote.quote([shell, '-c', command]);
            bwrapArgs.push(applySeccompCmd);
        }
        else {
            bwrapArgs.push(command);
        }
        const wrappedCommand = shellquote.quote(['bwrap', ...bwrapArgs]);
        const restrictions = [];
        if (needsNetworkRestriction)
            restrictions.push('network');
        if (hasReadRestrictions || hasWriteRestrictions)
            restrictions.push('filesystem');
        if (applySeccompPrefix)
            restrictions.push('seccomp(unix-block)');
        logForDebugging(`[Sandbox Linux] Wrapped command with bwrap (${restrictions.join(', ')} restrictions)`);
        return wrappedCommand;
    }
    catch (error) {
        // Undo the activeSandboxCount increment — the caller won't call
        // cleanupBwrapMountPoints() for a wrap that threw.
        if (activeSandboxCount > 0) {
            activeSandboxCount--;
        }
        throw error;
    }
}
//# sourceMappingURL=linux-sandbox-utils.js.map