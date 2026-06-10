//! `srt-win exec`: build the deny-only-group restricted token,
//! self-protect the broker, spawn the target suspended under a
//! locked-down job + non-interactive desktop + mitigation-policy
//! stack + explicit handle whitelist, resume, wait, propagate exit
//! code.
//!
//! Stateless — no marker file, no proxy thread, no FS-deny
//! handling here. Network egress for the child reaches the host's
//! JS-side proxies (whose ports the caller passes) via the WFP
//! loopback permit installed by `srt-win wfp install`.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::Path;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    WAIT_OBJECT_0,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, STARTUPINFOEXW, STARTUPINFOW,
};

use crate::job::Job;
use crate::self_protect;
use crate::sid::{self, GroupState};
use crate::token::{self, open_self_token, to_primary};
use crate::util::{pcwstr, wstr};
use crate::winsta::WinStaDesk;

// ─── RAII handle wrappers ───────────────────────────────────────────

/// Owns a kernel `HANDLE`; `CloseHandle` on drop. For tokens and
/// the like — anything where the only cleanup is `CloseHandle`.
struct OwnedHandle(HANDLE);
impl OwnedHandle {
    fn raw(&self) -> HANDLE { self.0 }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { let _ = CloseHandle(self.0); }
        }
    }
}

/// Owns a freshly-spawned (suspended) child. If dropped before
/// [`defuse`] is called, terminates the child — so an error
/// between `CreateProcessAsUserW` and `WaitForSingleObject`
/// can't orphan a suspended process that's not yet in the job.
/// Always closes both handles on drop.
struct SpawnedChild {
    pi: PROCESS_INFORMATION,
    armed: bool,
}
impl SpawnedChild {
    fn new(pi: PROCESS_INFORMATION) -> Self {
        Self { pi, armed: true }
    }
    fn process(&self) -> HANDLE { self.pi.hProcess }
    fn thread(&self) -> HANDLE { self.pi.hThread }
    /// Disarm the terminate-on-drop. Call after the child has been
    /// assigned to the job AND resumed — past that point
    /// `KILL_ON_JOB_CLOSE` covers cleanup.
    fn defuse(&mut self) { self.armed = false; }
}
impl Drop for SpawnedChild {
    fn drop(&mut self) {
        unsafe {
            if self.armed {
                let _ = TerminateProcess(self.pi.hProcess, 1);
            }
            let _ = CloseHandle(self.pi.hThread);
            let _ = CloseHandle(self.pi.hProcess);
        }
    }
}

// ─── Process-creation mitigation-policy bits ────────────────────────
//
// The `windows` crate exposes `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`
// but not the per-bit DWORD64 macros (they're winnt.h preprocessor
// `#define`s, still absent as of 0.62). Each policy occupies a 4-bit
// slot in the u64; `..._ALWAYS_ON` flips bit 0 of its slot.
//
// Only mitigations that don't break Node/Python JIT or mingw-built
// shells are enabled here. Specifically NOT enabled:
//   - `IMAGE_LOAD_PREFER_SYSTEM32` — flips DLL search-order so System32
//     wins over the EXE's directory; breaks the cygwin1.dll /
//     msys-2.0.dll resolution model.
//   - `CONTROL_FLOW_GUARD_ALWAYS_ON` — forces CFG even when the EXE
//     wasn't built with `/guard:cf`; stock mingw-built `bash.exe`
//     dies in `dofork`. CFG is defense-in-depth, not a primary
//     boundary.

/// Bit 32 — block legacy AppInit / IME / Winsock-LSP DLL injection
/// and `SetWindowsHookEx`.
const MITIGATION_EXTENSION_POINT_DISABLE: u64 = 1u64 << 32;
/// Bit 48 — block GDI from loading non-system fonts (historic
/// kernel font-parser RCE surface; sandbox children are
/// console/network workloads).
const MITIGATION_FONT_DISABLE: u64 = 1u64 << 48;
/// Bit 52 — refuse `LoadLibrary` from UNC / network paths.
const MITIGATION_IMAGE_LOAD_NO_REMOTE: u64 = 1u64 << 52;
/// Bit 56 — refuse `LoadLibrary` of any image whose mandatory label
/// is Low IL.
const MITIGATION_IMAGE_LOAD_NO_LOW_LABEL: u64 = 1u64 << 56;

/// Inputs to a single `srt-win exec` invocation.
pub struct ExecSpec<'a> {
    /// Discriminator group SID (already resolved by the caller from
    /// `--name` / `--group-sid`).
    pub group_sid: &'a str,
    /// Skip the "is `group_sid` enabled in the broker's token"
    /// pre-flight check. **Fail-open** — the WFP fence relies on
    /// the broker having the group enabled; with this set the
    /// child may run with weaker isolation if the install was
    /// incomplete. Surfaced as an explicit CLI flag (not an env
    /// var) so the bypass is intentional and not accidentally
    /// inherited from a parent's environment. Used only by CI
    /// runners that create the group in-job and cannot
    /// logout/login mid-run.
    pub skip_group_check: bool,
    /// Target executable.
    pub target_exe: &'a Path,
    /// Target argv (everything after the target).
    pub target_args: &'a [String],
}

/// Run the target under the sandbox and return its exit code.
pub fn run(spec: &ExecSpec<'_>) -> Result<u32> {
    // 1) Pre-flight: the group must be enabled in the broker's
    //    token. `Absent` means the user hasn't logged out + back
    //    in since `group create`. `DenyOnly` means we're already
    //    inside a sandbox child — refuse.
    match sid::group_state_for_self(spec.group_sid)? {
        GroupState::Enabled => {}
        GroupState::Absent if spec.skip_group_check => {
            eprintln!(
                "srt-win: WARNING: --skip-group-check is set and \
                 group {} is absent from the broker's TokenGroups. \
                 The WFP fence may not be in effect for this \
                 process tree. This bypass is intended ONLY for \
                 ephemeral CI runners.",
                spec.group_sid
            );
        }
        GroupState::Absent => {
            return Err(anyhow!(
                "group {} is not present in the broker's \
                 TokenGroups. Log out and back in to refresh group \
                 membership, then retry. (Run `srt-win group status` \
                 to confirm.) Pass --skip-group-check to bypass in CI.",
                spec.group_sid
            ));
        }
        GroupState::DenyOnly => {
            return Err(anyhow!(
                "group {} is deny-only in this token — the broker \
                 itself is running inside a sandbox child. Refusing \
                 to launch.",
                spec.group_sid
            ));
        }
        GroupState::Present => {
            return Err(anyhow!(
                "group {} is present but neither enabled nor \
                 deny-only (unexpected token attribute state).",
                spec.group_sid
            ));
        }
    }

    // 2) Self-protect: rewrite the broker process DACL so the
    //    child can't `OpenProcess` us. Best-effort — log on
    //    failure but don't abort, since a broker without
    //    self-protect is still strictly safer than no sandbox.
    if let Err(e) = self_protect::install_broker_dacl(spec.group_sid) {
        eprintln!("srt-win: WARNING: install_broker_dacl: {e:#}");
    }

    // 3) Restricted token. Each handle is RAII-owned so any `?`
    //    below closes whatever was already opened.
    let self_tok = OwnedHandle(open_self_token()?);
    let restricted = OwnedHandle(
        token::make_sandbox_token(self_tok.raw(), spec.group_sid)
            .context("make_sandbox_token")?,
    );
    let primary = OwnedHandle(
        to_primary(restricted.raw()).context("to_primary")?,
    );

    // 4) Job.
    let job = Job::new().context("Job::new")?;

    // 5) Window station + desktop.
    let mut winsta = WinStaDesk::new().context("WinStaDesk::new")?;

    // 6) Env block — verbatim passthrough of the broker's own
    //    environment (the TS caller populates it with the full proxy
    //    set; see `build_env_block`).
    let mut env = build_env_block();

    // 7) Command line + application name.
    let cmdline = build_cmdline(spec.target_exe, spec.target_args);
    let mut cmdline_w = wstr(&cmdline);
    let app_w = wstr(&spec.target_exe.display().to_string());

    // 8) PROC_THREAD_ATTRIBUTE_LIST: mitigation policy + explicit
    //    handle whitelist.
    let mitigation: u64 = MITIGATION_EXTENSION_POINT_DISABLE
        | MITIGATION_FONT_DISABLE
        | MITIGATION_IMAGE_LOAD_NO_REMOTE
        | MITIGATION_IMAGE_LOAD_NO_LOW_LABEL;
    let mut handle_list = collect_inheritable_std_handles();
    if handle_list.is_empty() {
        return Err(anyhow!(
            "no std handle is inheritable; refusing to spawn. \
             srt-win exec requires the broker have at least one \
             console-attached stdio stream."
        ));
    }
    let mut attrs = ProcThreadAttrs::new(2)?;
    attrs.set_mitigation_policy(&mitigation)?;
    attrs.set_handle_list(&mut handle_list)?;

    // 9) STARTUPINFOEXW.
    let mut six: STARTUPINFOEXW = unsafe { zeroed() };
    six.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    six.lpAttributeList = attrs.list();
    six.StartupInfo.lpDesktop = PWSTR(winsta.desktop_name_ptr());

    // 10) Spawn suspended.
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    unsafe {
        CreateProcessAsUserW(
            Some(primary.raw()),
            pcwstr(&app_w),
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            None,
            None,
            // Must be TRUE for `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
            // to take effect (documented Vista-era quirk: with
            // FALSE the kernel ignores the attribute entirely).
            true,
            CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            Some(env.as_mut_ptr() as *const c_void),
            // Inherit cwd.
            PCWSTR::null(),
            // STARTUPINFOEXW is layout-compatible (StartupInfo is
            // first member); EXTENDED_STARTUPINFO_PRESENT tells the
            // kernel to read past it for lpAttributeList.
            &six.StartupInfo as *const STARTUPINFOW,
            &mut pi,
        )
        .with_context(|| {
            format!(
                "CreateProcessAsUserW({})",
                spec.target_exe.display()
            )
        })?;
    }

    // The child exists, suspended, NOT yet in the job. Wrap it
    // in a guard so any `?` from here to `defuse()` terminates
    // it — `KILL_ON_JOB_CLOSE` can't help until after `assign`.
    let mut child = SpawnedChild::new(pi);

    // 11) Assign to job → resume. ResumeThread returns the
    //     previous suspend count, or u32::MAX on failure — a
    //     failure here would leave the child suspended in the
    //     job and `WaitForSingleObject(INFINITE)` below would
    //     hang the broker forever. Check before defusing the
    //     terminate-on-drop guard.
    job.assign(child.process())?;
    let prev_suspend = unsafe { ResumeThread(child.thread()) };
    if prev_suspend == u32::MAX {
        return Err(anyhow!(
            "ResumeThread: {}",
            std::io::Error::last_os_error()
        ));
    }
    // From here the job owns lifetime; disarm terminate-on-drop.
    child.defuse();

    // 12) Wait + collect exit code.
    let rc = unsafe { WaitForSingleObject(child.process(), INFINITE) };
    if rc != WAIT_OBJECT_0 {
        eprintln!("srt-win: WaitForSingleObject returned 0x{:x}", rc.0);
    }
    let mut code: u32 = 0;
    unsafe {
        GetExitCodeProcess(child.process(), &mut code)
            .context("GetExitCodeProcess")?;
    }
    // `child` (closes hProcess/hThread), `primary`/`restricted`/
    // `self_tok` (CloseHandle) all drop here.
    // Keep `attrs` (its backing buffer + the borrowed `mitigation`
    // and `handle_list`), `winsta`, and `job` alive until here.
    // The kernel snapshots the attribute list at CreateProcess
    // time, but DeleteProcThreadAttributeList (in attrs.drop) may
    // re-read pointers; and the WS+desktop must outlive the
    // child's attach during process creation.
    drop(attrs);
    drop(handle_list);
    drop(winsta);
    drop(job);
    Ok(code)
}

// ─── Environment block ──────────────────────────────────────────────

/// Build a `CREATE_UNICODE_ENVIRONMENT` block from the broker's own
/// environment, **verbatim**.
///
/// `srt-win exec` is a dumb passthrough for proxy configuration: it
/// does NOT synthesize `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` and has
/// no `--http-proxy` / `--socks-proxy` flags. The single source of
/// proxy env is the TS `generateProxyEnvVars`, which the caller merges
/// into the environment it spawns `srt-win exec` with; this function
/// just forwards that environment to the child. No proxy value is
/// invented, no inherited var is stripped or blanked.
///
/// Entries are sorted case-insensitively by name for block ordering —
/// not the strict case-insensitive Unicode collation the
/// `CreateProcess` docs describe, but in practice the loader and
/// `GetEnvironmentVariableW` don't enforce ordering; `cmd /c set` and
/// every consumer we've tested work regardless. Names are NOT folded
/// or deduplicated, so if both `HTTP_PROXY` and `http_proxy` are
/// present both survive into the child.
///
/// The only adjustment on top of the verbatim copy is restoring the
/// missing-case variants of `*_PROXY` variables (see
/// [`add_proxy_case_twins`]) — casing repair of caller-provided
/// values, not proxy synthesis. Nothing else is added: consumers that
/// need the broker's identity (e.g. the self-protect probe) discover
/// it by walking the parent-process chain rather than via an
/// environment variable.
fn build_env_block() -> Vec<u16> {
    let mut entries: Vec<(String, String)> = std::env::vars().collect();

    add_proxy_case_twins(&mut entries);

    // Order the block case-insensitively by name; values pass through
    // verbatim. No dedup — case-variant duplicates are preserved.
    entries.sort_by_cached_key(|(k, _)| k.to_ascii_uppercase());

    // Encode: `KEY=VALUE\0`… `\0`.
    let mut out: Vec<u16> = Vec::new();
    for (k, v) in entries {
        out.extend(k.encode_utf16());
        out.push(b'=' as u16);
        out.extend(v.encode_utf16());
        out.push(0);
    }
    out.push(0);
    out
}

/// Re-add the missing-case variants of `*_PROXY` variables (the host
/// spawn layer collapses case-duplicate keys) so that Cygwin/MSYS2
/// programs — which see a case-sensitive environment — still find
/// them. For every entry whose name ends with `_PROXY`
/// (case-insensitively), the all-uppercase and all-lowercase forms of
/// that name are appended where missing, with the same value. Existing
/// keys are never overwritten and nothing is added for names that are
/// not `*_PROXY`.
fn add_proxy_case_twins(entries: &mut Vec<(String, String)>) {
    let mut names: std::collections::HashSet<String> =
        entries.iter().map(|(k, _)| k.clone()).collect();
    let mut twins: Vec<(String, String)> = Vec::new();
    for (k, v) in entries.iter() {
        if !k.to_ascii_uppercase().ends_with("_PROXY") {
            continue;
        }
        for form in [k.to_ascii_uppercase(), k.to_ascii_lowercase()] {
            if !names.contains(&form) {
                names.insert(form.clone());
                twins.push((form, v.clone()));
            }
        }
    }
    entries.extend(twins);
}

// ─── Command-line quoting ───────────────────────────────────────────

/// MSVCRT / `CommandLineToArgvW` quoting for one argument.
/// Public so `main.rs`'s self-elevate path can rebuild
/// `lpParameters` from `std::env::args()`.
pub fn quote_arg(a: &str) -> String {
    if !a.is_empty()
        && !a
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '"' | '\\'))
    {
        return a.to_string();
    }
    let mut out = String::with_capacity(a.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in a.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                // Double the run of backslashes, then escape the
                // quote.
                for _ in 0..backslashes {
                    out.push('\\');
                }
                out.push('\\');
                out.push('"');
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Trailing backslash run before the closing quote must double.
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}

fn target_is_cmd(exe: &Path) -> bool {
    exe.file_name()
        .and_then(|n| n.to_str())
        .map(|s| {
            s.eq_ignore_ascii_case("cmd.exe") || s.eq_ignore_ascii_case("cmd")
        })
        .unwrap_or(false)
}

/// Build the full command line.
///
/// **Non-cmd targets:** every arg is MSVCRT-quoted via
/// [`quote_arg`] so `CommandLineToArgvW` in the child recovers
/// the exact argv.
///
/// **`cmd.exe` targets:** cmd does NOT use `CommandLineToArgvW`;
/// it parses `lpCommandLine` itself. With `/s`, it strips the
/// first and last `"` of the post-`/c` portion and runs what's
/// between *verbatim* under cmd's own rules. The caller is
/// expected to include `/s`; without it cmd falls back to the
/// legacy "if exactly two quotes and they wrap a runnable
/// command, strip them; otherwise leave alone" heuristic, and
/// the wrapper quote may not strip cleanly. (Batch 03's
/// `wrapWithSandboxArgv` always passes `/d /s /c`.) So we:
///   1. Emit the exe + flags up to and including `/c|/k|/r`
///      using `quote_arg` (these are simple tokens; quoting is
///      a no-op unless the exe path has spaces).
///   2. Join the remaining argv elements with single spaces —
///      this is the user's cmd command string, reconstructed.
///   3. Wrap that in ONE outer `"…"` pair for `/s` to strip.
///
/// The post-`/c` content is **passed through unmodified**. We
/// do NOT caret-escape `& | < > ^ ( )` and do NOT touch `"` —
/// the contract is "this is a cmd.exe command string" and the
/// caller (batch-03's `wrapWithSandboxArgv`) supplies it as
/// such. `&` chains commands, `"…"` quotes — exactly as the
/// user typed. The child IS the sandbox, so cmd metachars here
/// are the user's tool, not an escape vector. (The Phase-6 N1
/// host-shell injection concern was about the OUTER spawn,
/// which is solved by argv-mode in batch 03; this is the inner
/// sandboxed cmd.)
///
/// An earlier revision per-arg-doubled `"` → `""`, which cmd
/// treats as a quote-state *toggle*, not a literal — that
/// mis-parsed payloads containing `&` and was reverted.
pub fn build_cmdline(exe: &Path, args: &[String]) -> String {
    let cmd_split = if target_is_cmd(exe) {
        args.iter().position(|a| {
            matches!(a.to_ascii_lowercase().as_str(), "/c" | "/k" | "/r")
        })
    } else {
        None
    };
    let mut s = quote_arg(&exe.display().to_string());
    match cmd_split {
        Some(p) => {
            for a in &args[..=p] {
                s.push(' ');
                s.push_str(&quote_arg(a));
            }
            // One outer pair of quotes around the whole post-/c
            // command for `/s` to strip; contents verbatim.
            s.push_str(" \"");
            s.push_str(&args[p + 1..].join(" "));
            s.push('"');
        }
        None => {
            for a in args {
                s.push(' ');
                s.push_str(&quote_arg(a));
            }
        }
    }
    s
}

// ─── PROC_THREAD_ATTRIBUTE_LIST helper ──────────────────────────────

/// RAII wrapper over an opaque `LPPROC_THREAD_ATTRIBUTE_LIST`.
/// `Drop` calls `DeleteProcThreadAttributeList`. The values passed
/// to [`set_*`] must outlive `self` — the kernel reads them by
/// pointer at `CreateProcess` time.
struct ProcThreadAttrs {
    storage: Vec<u8>,
}

impl ProcThreadAttrs {
    fn new(count: u32) -> Result<Self> {
        let mut size = 0usize;
        // Sizing call — expected to fail with
        // ERROR_INSUFFICIENT_BUFFER and write the required size.
        unsafe {
            let _ = InitializeProcThreadAttributeList(
                None, count, None, &mut size,
            );
        }
        if size == 0 {
            return Err(anyhow!(
                "InitializeProcThreadAttributeList sizing returned 0"
            ));
        }
        let mut storage = vec![0u8; size];
        unsafe {
            InitializeProcThreadAttributeList(
                Some(LPPROC_THREAD_ATTRIBUTE_LIST(
                    storage.as_mut_ptr() as *mut c_void,
                )),
                count,
                None,
                &mut size,
            )
            .context("InitializeProcThreadAttributeList")?;
        }
        Ok(Self { storage })
    }

    fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.storage.as_mut_ptr() as *mut c_void)
    }

    fn set_mitigation_policy(&mut self, policy: &u64) -> Result<()> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list(),
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                Some(policy as *const u64 as *const c_void),
                size_of::<u64>(),
                None,
                None,
            )
            .context("UpdateProcThreadAttribute(MITIGATION_POLICY)")
        }
    }

    /// `UpdateProcThreadAttribute(HANDLE_LIST)` requires at least
    /// one entry — Windows rejects an empty list with
    /// `ERROR_BAD_LENGTH`. The caller is expected to have filtered
    /// already.
    fn set_handle_list(&mut self, handles: &mut [HANDLE]) -> Result<()> {
        debug_assert!(!handles.is_empty());
        unsafe {
            UpdateProcThreadAttribute(
                self.list(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr() as *const c_void),
                std::mem::size_of_val(handles),
                None,
                None,
            )
            .context("UpdateProcThreadAttribute(HANDLE_LIST)")
        }
    }
}

impl Drop for ProcThreadAttrs {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list());
        }
    }
}

/// Mark this process's std handles inheritable and return the ones
/// that succeeded. We need at least one entry to satisfy the
/// kernel's `HANDLE_LIST` length check; the std handles are the
/// natural minimal set since the child attaches to the same
/// console anyway.
fn collect_inheritable_std_handles() -> Vec<HANDLE> {
    let mut out = Vec::with_capacity(3);
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let h = match unsafe { GetStdHandle(which) } {
            Ok(h) => h,
            Err(_) => continue,
        };
        if h.0.is_null() || (h.0 as isize) == -1 {
            continue;
        }
        // Best-effort: a detached broker may have non-inheritable
        // (or pseudo) handles here; skip rather than fail.
        let r = unsafe {
            SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
        };
        if r.is_ok() {
            out.push(h);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_arg_simple() {
        assert_eq!(quote_arg("foo"), "foo");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
    }

    #[test]
    fn quote_arg_backslash_quote() {
        // a\"b → "a\\\"b"
        assert_eq!(quote_arg(r#"a\"b"#), r#""a\\\"b""#);
        // trailing backslashes double before closing quote
        assert_eq!(quote_arg(r"a\"), r#""a\\""#);
        assert_eq!(quote_arg(r"a\\"), r#""a\\\\""#);
    }

    #[test]
    fn build_cmdline_cmd_passthrough() {
        let exe = Path::new(r"C:\Windows\System32\cmd.exe");
        // post-/c content is wrapped once in "…" for /s to strip;
        // inner quotes and metachars are NOT touched.
        let line = build_cmdline(
            exe,
            &["/d".into(), "/s".into(), "/c".into(),
              r#"echo "x & y""#.into()],
        );
        assert_eq!(
            line,
            r#""C:\Windows\System32\cmd.exe" /d /s /c "echo "x & y"""#
        );
        // Multiple post-/c argv elements are joined with a space.
        let line2 = build_cmdline(
            exe,
            &["/c".into(), "echo".into(), "a".into(), "&".into(),
              "echo".into(), "b".into()],
        );
        assert_eq!(
            line2,
            r#""C:\Windows\System32\cmd.exe" /c "echo a & echo b""#
        );
    }

    #[test]
    fn build_cmdline_cmd_no_split_when_no_c_flag() {
        // cmd.exe without /c|/k|/r → MSVCRT quoting throughout.
        let exe = Path::new("cmd.exe");
        let line = build_cmdline(exe, &["/?".into()]);
        assert_eq!(line, r#"cmd.exe /?"#);
    }

    #[test]
    fn build_cmdline_non_cmd_uses_msvcrt_quoting() {
        let exe = Path::new(r"C:\foo\bar.exe");
        let args = vec![r#"a "b"#.into()];
        let line = build_cmdline(exe, &args);
        assert!(line.ends_with(r#""a \"b""#), "got: {line}");
    }

    #[test]
    fn proxy_case_twins_suffix_rule_covers_any_proxy_var() {
        let mut entries = vec![
            // Any *_PROXY name is twinned, not just the standard trio.
            (
                "GRPC_PROXY".to_string(),
                "socks5h://localhost:60081".to_string(),
            ),
            // Mixed-case input → BOTH canonical forms appended.
            ("Http_Proxy".to_string(), "http://localhost:60080".to_string()),
            // Names that merely contain or extend the suffix are not.
            ("FOO_PROXYX".to_string(), "x".to_string()),
            ("PATH".to_string(), r"C:\Windows".to_string()),
        ];
        add_proxy_case_twins(&mut entries);
        let matching = |name: &str| {
            entries
                .iter()
                .filter(|(k, _)| k == name)
                .collect::<Vec<_>>()
        };
        assert_eq!(matching("grpc_proxy").len(), 1);
        assert_eq!(matching("grpc_proxy")[0].1, "socks5h://localhost:60081");
        assert_eq!(matching("GRPC_PROXY").len(), 1);
        // Mixed-case original is preserved AND both canonical forms added.
        assert_eq!(matching("Http_Proxy").len(), 1);
        assert_eq!(matching("HTTP_PROXY").len(), 1);
        assert_eq!(matching("http_proxy").len(), 1);
        assert_eq!(matching("http_proxy")[0].1, "http://localhost:60080");
        // Non-matching names untouched, nothing appended for them.
        assert_eq!(matching("FOO_PROXYX").len(), 1);
        assert!(matching("foo_proxyx").is_empty());
        assert_eq!(matching("PATH").len(), 1);
        assert!(matching("path").is_empty());
    }
}
