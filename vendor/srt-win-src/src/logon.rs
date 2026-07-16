//! Broker-side `CreateProcessWithLogonW` wrapper for the
//! broker→runner two-hop launch.
//!
//! Spawns `srt-win.exe runner` under the `srt-sandbox` account
//! (via the Secondary Logon service — no
//! `SeAssignPrimaryTokenPrivilege` needed on the broker), wires
//! three anonymous pipes to its stdio, writes the
//! [`crate::runner::RunnerCmd`] over stdin, pumps stdout/stderr
//! back to the broker's own stdio, waits, and returns the runner's
//! exit code.
//!
//! `lpEnvironment = NULL` + `LOGON_WITH_PROFILE` means the runner
//! starts with the **sandbox user's** profile environment
//! (`USERPROFILE`/`TEMP`/`LOCALAPPDATA` isolated; `PATH` = machine
//! `PATH`). The broker's `PATH` and the proxy var set ride to the
//! child via the spec's `env_overlay` instead, applied by the
//! runner's `build_env_block` — so profile-scoped vars stay the
//! sandbox user's while tool-resolution `PATH` is the broker's.
//!
//! **Do not key any ACL/WFP on the logon SID:** seclogon stamps the
//! broker's interactive logon SID into the runner's token. Key on
//! the **user SID** only.

use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_LOGON_FAILURE, ERROR_NOT_SUPPORTED, HANDLE, HANDLE_FLAG_INHERIT,
    HANDLE_FLAGS, SetHandleInformation, WAIT_OBJECT_0,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW,
    GetExitCodeProcess, INFINITE, LOGON_WITH_PROFILE, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

use crate::job::Job;
use crate::launch::{SpawnedChild, quote_arg};
use crate::util::{OwnedHandle, scrub_wstr, wstr};
use crate::winsta::{IsolatedDesk, grant_sandbox_on_session_bno, grant_sandbox_on_winsta};

/// One anonymous pipe pair. The end the runner gets is created
/// inheritable; the broker's end is flipped non-inheritable so the
/// runner doesn't get a copy of it (which would keep the pipe open
/// past the runner's exit and hang the pump).
struct PipePair {
    broker: OwnedHandle,
    runner: OwnedHandle,
}

fn make_pipe(runner_writes: bool) -> Result<PipePair> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: true.into(),
        ..Default::default()
    };
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe {
        CreatePipe(&mut read, &mut write, Some(&sa), 0).context("CreatePipe")?;
    }
    // Wrap immediately so the `?` below can't leak either end.
    let (broker, runner) = if runner_writes {
        (OwnedHandle(read), OwnedHandle(write))
    } else {
        (OwnedHandle(write), OwnedHandle(read))
    };
    // Broker end must NOT be inherited by the runner.
    unsafe {
        SetHandleInformation(broker.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
            .context("SetHandleInformation(broker end)")?;
    }
    Ok(PipePair { broker, runner })
}

/// Pump `src` to `dst` until `src` reaches EOF (broken pipe). Runs
/// on a dedicated thread per stream so a slow consumer on one
/// doesn't block the other.
fn pump(src: HANDLE, dst: HANDLE) {
    let mut buf = [0u8; 8192];
    loop {
        let mut read = 0u32;
        let r = unsafe { ReadFile(src, Some(&mut buf), Some(&mut read), None) };
        if r.is_err() || read == 0 {
            break;
        }
        let mut off = 0u32;
        while off < read {
            let mut wrote = 0u32;
            let chunk = &buf[off as usize..read as usize];
            if unsafe { WriteFile(dst, Some(chunk), Some(&mut wrote), None) }.is_err() || wrote == 0
            {
                return;
            }
            off += wrote;
        }
    }
}

/// Spawn `srt-win runner` as `username`, send `cmd` over stdin, and
/// return its exit code. `cwd` is set as the runner's working
/// directory; `None` inherits the broker's. `sb_sid` is the
/// `srt-sandbox` user-SID string (for the desktop DACL and the
/// `WinSta0` station grant). `quiet` suppresses the informational
/// stderr lines (the seclogon-job note); `SANDBOX_RUNTIME_WIN_DEBUG`
/// checkpoints are gated separately on `dbg` and are unaffected.
pub fn spawn_runner(
    username: &str,
    password: &str,
    sb_sid: &str,
    cwd: Option<&str>,
    cmd: &crate::runner::RunnerCmd,
    quiet: bool,
) -> Result<u32> {
    let cmd_bytes = crate::runner::encode_cmd(cmd)?;
    let stdin = make_pipe(false)?;
    let stdout = make_pipe(true)?;
    let stderr = make_pipe(true)?;

    // Broker-side per-exec desktop on `WinSta0` with an explicit
    // `[broker, srt-sandbox, SY]:GA` DACL. The broker (interactive
    // user) has `WINSTA_CREATEDESKTOP` non-elevated; the runner does
    // not — so this MUST happen here, not inside the runner. Held
    // open until the runner exits so the kernel object survives the
    // whole two-hop chain. See `winsta.rs` module doc.
    let dbg = std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some();
    let mut desk = IsolatedDesk::new(sb_sid).context("broker IsolatedDesk")?;

    let exe = std::env::current_exe().context("current_exe")?;
    let exe_s = exe
        .to_str()
        .ok_or_else(|| anyhow!("current_exe is not UTF-8"))?;
    let exe_w = wstr(exe_s);
    // `lpCommandLine` is parsed via `CommandLineToArgvW`; quote
    // argv[0] so a path with spaces survives. The
    // `SRT_WIN_DISPATCH_ARG1` sentinel at argv[1] is what a
    // multicall embedder's dispatcher routes on (`argv[0]` cannot be
    // spoofed across CPWLW); `run_from_args` strips it before clap so
    // the standalone binary accepts it harmlessly. `runner` is the
    // only real argument.
    let mut cmdline_w = wstr(&format!(
        "{} {} runner",
        quote_arg(exe_s),
        crate::cli::SRT_WIN_DISPATCH_ARG1,
    ));
    let user_w = wstr(username);
    let domain_w = wstr(".");
    let mut pw_w = wstr(password);
    let cwd_w = cwd.map(wstr);

    // Broker→runner kill-on-close Job: broker dies → runner dies →
    // runner's Job → child dies. The assign succeeds on current
    // Windows (rc=0, live-probed 2026-07-16); if a future seclogon
    // job refused nesting (ERROR_NOT_SUPPORTED), the always-armed
    // `SpawnedChild` guard below is the fallback.
    // `breakaway_ok = true`: the runner's child must break away
    // past the inherited [seclogon, broker] job stack onto the
    // runner's own Job, which requires every containing job to
    // allow it.
    let job = Job::new(true).context("broker→runner job")?;

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin.runner.raw();
    si.hStdOutput = stdout.runner.raw();
    si.hStdError = stderr.runner.raw();
    // `lpDesktop = "WinSta0\srt-sb-…"`. The runner never touches
    // `Default`; `run_lockdown` fail-closes if it somehow lands there.
    si.lpDesktop = PWSTR(desk.desktop_name_ptr());
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    // `CreateProcessWithLogonW` has no `bInheritHandles` parameter:
    // seclogon duplicates the `STARTF_USESTDHANDLES` handles into
    // the new logon, and nothing else. So no
    // `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` is needed (or possible —
    // there's no `STARTUPINFOEX` overload).
    let r = unsafe {
        CreateProcessWithLogonW(
            PCWSTR(user_w.as_ptr()),
            PCWSTR(domain_w.as_ptr()),
            PCWSTR(pw_w.as_ptr()),
            LOGON_WITH_PROFILE,
            PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
            // `NULL` → seclogon builds the sandbox user's profile
            // env (with `LOGON_WITH_PROFILE`). The broker's PATH
            // and proxy vars travel via the spec's env_overlay.
            None,
            match &cwd_w {
                Some(w) => PCWSTR(w.as_ptr()),
                None => PCWSTR::null(),
            },
            &si,
            &mut pi,
        )
    };
    // Scrub the UTF-16 password buffer now that seclogon has it.
    // (The UTF-8 source is zeroed by `SandboxCred::Drop`; this is a
    // separate heap allocation.) Before any `?` so the scrub runs
    // regardless of `r`. Volatile so DSE can't remove it in release.
    scrub_wstr(&mut pw_w);
    if let Err(e) = r {
        if e.code() == ERROR_LOGON_FAILURE.to_hresult() {
            return Err(anyhow!(
                "CreateProcessWithLogonW({username}): logon failure \
                 — the sandbox user's password is wrong or the \
                 account is disabled. Re-run `srt-win install` (one \
                 UAC prompt) to rotate the credential."
            ));
        }
        return Err(anyhow!(
            "CreateProcessWithLogonW({username}): {e} — ensure the \
             Secondary Logon service (seclogon) is running."
        ));
    }
    if dbg {
        eprintln!(
            "srt-win: spawn_runner: CPWLW ok pid={} (suspended)",
            pi.dwProcessId
        );
    }
    // Runner exists, suspended. The guard is never defused: its
    // `Drop` `TerminateProcess`es the runner on every in-process
    // exit — `?`/panic reap directly; on normal return the runner
    // has already exited and the terminate is a no-op on the held
    // handle. It cannot cover an external kill of the broker —
    // that is the Job's role; if a build ever regresses the assign
    // above, elevated `taskkill /F /FI "USERNAME eq srt-sandbox"`
    // is the operator fallback (admins hold SeDebugPrivilege and
    // BA is in every sandbox process's DACL — the by-user-filter
    // denial is non-elevated-only). Declared after `job` so it
    // drops first: terminate before job-close.
    let child = SpawnedChild::new(pi);

    // Grant `srt-sandbox` on the broker's `WinSta0` (with a non-NULL
    // `lpDesktop`, seclogon skips its station auto-grant for the new
    // logon, so the runner can't attach without this) and on the
    // session `BaseNamedObjects` directory (so the lockdown child —
    // whose logon SIDs are deny-only — can still create the
    // named-object subdirectory msys2/cygwin needs). Both persist for
    // the broker's logon session: revoking on drop would race against
    // a concurrent `srt-win exec`. See `winsta.rs`.
    grant_sandbox_on_winsta(sb_sid)?;
    grant_sandbox_on_session_bno(sb_sid)?;
    if dbg {
        eprintln!("srt-win: spawn_runner: WinSta0 + BNO grants applied");
    }

    // Assign before resuming so there is no window where broker
    // death orphans it. ERROR_NOT_SUPPORTED (seclogon's job won't
    // nest) → log + continue; any OTHER error → propagate (the guard
    // terminates the suspended runner).
    if let Err(e) = job.assign(child.process()) {
        if e.root_cause()
            .downcast_ref::<windows::core::Error>()
            .map(|we| we.code() == ERROR_NOT_SUPPORTED.to_hresult())
            .unwrap_or(false)
        {
            if !quiet {
                eprintln!(
                    "srt-win: broker→runner Job assign not supported \
                     (seclogon job); relying on runner→child Job for \
                     kill-chain"
                );
            }
        } else {
            return Err(e.context("assign runner to job"));
        }
    }
    if unsafe { ResumeThread(child.thread()) } == u32::MAX {
        return Err(anyhow!(
            "ResumeThread(runner): {}",
            std::io::Error::last_os_error()
        ));
    }
    if dbg {
        eprintln!("srt-win: spawn_runner: runner resumed; writing spec");
    }
    // No `child.defuse()` — the guard stays armed (see its decl).

    // Close the runner-side pipe ends in the broker so the pumps
    // see EOF when the runner exits.
    drop(stdin.runner);
    drop(stdout.runner);
    drop(stderr.runner);

    // Write the spec, then close stdin so the runner's
    // `read_exact` doesn't block waiting for more.
    {
        let mut wrote = 0u32;
        unsafe {
            WriteFile(stdin.broker.raw(), Some(&cmd_bytes), Some(&mut wrote), None)
                .context("write RunnerCmd to runner stdin")?;
        }
        if wrote as usize != cmd_bytes.len() {
            return Err(anyhow!(
                "short write of RunnerCmd ({}/{} bytes)",
                wrote,
                cmd_bytes.len()
            ));
        }
    }
    drop(stdin.broker);

    // Pump stdout/stderr on dedicated threads. `HANDLE` wraps a
    // `*mut c_void` which is `!Send`; the value is just an opaque
    // index into the process's handle table, so cast to `isize` for
    // the move and reconstruct inside the thread. Broker stdio
    // handles are not OwnedHandle — they're owned by the process,
    // not us.
    let bout = std::io::stdout().as_raw().0 as isize;
    let berr = std::io::stderr().as_raw().0 as isize;
    let so = stdout.broker.into_raw().0 as isize;
    let se = stderr.broker.into_raw().0 as isize;
    let h = |v: isize| HANDLE(v as *mut c_void);
    let t_out = std::thread::spawn(move || {
        pump(h(so), h(bout));
        unsafe {
            let _ = CloseHandle(h(so));
        }
    });
    let t_err = std::thread::spawn(move || {
        pump(h(se), h(berr));
        unsafe {
            let _ = CloseHandle(h(se));
        }
    });

    let rc = unsafe { WaitForSingleObject(child.process(), INFINITE) };
    if rc != WAIT_OBJECT_0 {
        eprintln!("srt-win: WaitForSingleObject(runner) returned 0x{:x}", rc.0);
    }
    let _ = t_out.join();
    let _ = t_err.join();
    let mut code: u32 = 1;
    unsafe {
        GetExitCodeProcess(child.process(), &mut code).context("GetExitCodeProcess(runner)")?;
    }
    // Implicit drop order: `child` (armed, no-op on the exited
    // runner) then `job`. An explicit `drop(job)` here would close
    // the Job before the fallback terminate.
    Ok(code)
}

/// `std::io::Stdout`/`Stderr` → raw `HANDLE` for [`pump`].
trait AsRawHandle {
    fn as_raw(&self) -> HANDLE;
}
impl AsRawHandle for std::io::Stdout {
    fn as_raw(&self) -> HANDLE {
        HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(self))
    }
}
impl AsRawHandle for std::io::Stderr {
    fn as_raw(&self) -> HANDLE {
        HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(self))
    }
}
