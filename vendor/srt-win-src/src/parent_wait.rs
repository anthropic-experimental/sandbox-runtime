//! Dedicated ACL-holder process support.
//!
//! `acl hold --parent-pid` opens the original parent process object
//! for SYNCHRONIZE and waits on that handle. The handle identifies the
//! process object itself, so PID reuse cannot keep the holder alive.

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use crate::util::OwnedHandle;

pub const ACL_HOLDER_READY_PROTOCOL: &str = "srt-win-acl-holder-ready-v2";

fn open_parent_process(parent_pid: u32) -> Result<OwnedHandle> {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, parent_pid) }
        .with_context(|| format!("OpenProcess({parent_pid}) for ACL holder"))?;
    if handle.is_invalid() {
        bail!("OpenProcess({parent_pid}) returned an invalid ACL-holder handle");
    }
    Ok(OwnedHandle(handle))
}

fn wait_for_opened_process(handle: &OwnedHandle) -> Result<()> {
    let wait = unsafe { WaitForSingleObject(handle.raw(), INFINITE) };
    if wait == WAIT_OBJECT_0 {
        return Ok(());
    }
    if wait == WAIT_FAILED {
        return Err(std::io::Error::last_os_error())
            .context("WaitForSingleObject(ACL holder parent)");
    }
    bail!("WaitForSingleObject(ACL holder parent) returned {wait:?}")
}

/// Wait until the process object currently identified by `parent_pid`
/// exits. Opening the process fails closed if the parent is already
/// gone or cannot be synchronized.
pub fn wait_for_parent_exit_after_ready<F>(parent_pid: u32, ready: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let handle = open_parent_process(parent_pid)?;
    ready()?;
    wait_for_opened_process(&handle)
}

pub fn wait_for_parent_exit(parent_pid: u32) -> Result<()> {
    wait_for_parent_exit_after_ready(parent_pid, || Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use windows::Win32::Foundation::WAIT_TIMEOUT;

    #[test]
    fn waits_for_the_opened_parent_process_object() {
        let mut parent = Command::new("cmd.exe")
            .args(["/d", "/q", "/c", "pause"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn test parent");
        let parent_handle = open_parent_process(parent.id()).expect("open test parent");
        assert_eq!(
            unsafe { WaitForSingleObject(parent_handle.raw(), 0) },
            WAIT_TIMEOUT,
            "parent should still be running"
        );

        parent.kill().expect("terminate test parent");
        parent.wait().expect("reap test parent");
        wait_for_opened_process(&parent_handle).expect("holder wait succeeded");
    }

    #[test]
    fn readiness_failure_stops_before_waiting() {
        let mut parent = Command::new("cmd.exe")
            .args(["/d", "/q", "/c", "pause"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn test parent");
        let error =
            wait_for_parent_exit_after_ready(parent.id(), || anyhow::bail!("ready pipe closed"))
                .expect_err("readiness failure must fail closed");
        assert!(format!("{error:#}").contains("ready pipe closed"));
        parent.kill().expect("terminate test parent");
        parent.wait().expect("reap test parent");
    }

    #[test]
    fn missing_parent_fails_closed() {
        let error = wait_for_parent_exit(u32::MAX).expect_err("missing PID must fail");
        assert!(format!("{error:#}").contains("OpenProcess"));
    }
}
