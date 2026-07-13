//! Job-object wrapper for the sandbox child.
//!
//! Two roles:
//!  1. `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` containment — the sandboxed
//!     process tree dies with the broker.
//!  2. `JOBOBJECT_BASIC_UI_RESTRICTIONS` — block clipboard, global
//!     atoms, system-parameter writes, display-settings changes,
//!     desktop switching, ExitWindows, and cross-job USER/GDI handle
//!     access. The bits are listed individually rather than relying
//!     on a hypothetical `_ALL` so the enforced surface is auditable
//!     from this call site.
//!
//! Both must be set BEFORE `AssignProcessToJobObject` so they're in
//! effect from the moment the suspended child is assigned (the caller
//! resumes the thread only after `assign`).

use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
};

/// RAII job object. `Drop` closes the handle; with
/// `KILL_ON_JOB_CLOSE` set, that terminates every process still in
/// the job.
pub struct Job(HANDLE);

impl Job {
    /// Create an unnamed job with kill-on-close + full UI lockdown.
    /// `breakaway_ok` sets `JOB_OBJECT_LIMIT_BREAKAWAY_OK` — `true`
    /// only on the broker→runner Job (so the runner's child can
    /// `CREATE_BREAKAWAY_FROM_JOB` past it onto the runner's own
    /// load-bearing Job); **`false` on the runner→child Job** (a
    /// child must NOT be able to break away from its containment).
    pub fn new(breakaway_ok: bool) -> Result<Self> {
        // Wrap the raw handle in `Self` immediately so a `?` from
        // either `SetInformationJobObject` below still closes it.
        let job = unsafe { Self(CreateJobObjectW(None, None).context("CreateJobObjectW")?) };
        unsafe {
            let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if breakaway_ok {
                ext.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
            }
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                &ext as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .context("SetInformationJobObject(KILL_ON_JOB_CLOSE)")?;

            //   READCLIPBOARD     — block OpenClipboard for read
            //   WRITECLIPBOARD    — block SetClipboardData
            //   HANDLES           — block USER/GDI handles from outside the job
            //   GLOBALATOMS       — block GlobalAddAtom (atom-table IPC)
            //   SYSTEMPARAMETERS  — block SystemParametersInfoW(SPI_SET*)
            //   DISPLAYSETTINGS   — block ChangeDisplaySettings
            //   DESKTOP           — block SwitchDesktop / SetThreadDesktop
            //   EXITWINDOWS       — block sandbox-initiated logoff/shutdown
            let ui_bits = JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_EXITWINDOWS;
            let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass: ui_bits,
            };
            SetInformationJobObject(
                job.0,
                JobObjectBasicUIRestrictions,
                &ui as *const _ as *const c_void,
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
            .context("SetInformationJobObject(BasicUIRestrictions)")?;
        }
        Ok(job)
    }

    /// Raw job handle (for `IsProcessInJob` diagnostics).
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// Assign a (suspended) process to the job.
    pub fn assign(&self, proc: HANDLE) -> Result<()> {
        unsafe { AssignProcessToJobObject(self.0, proc).context("AssignProcessToJobObject") }
    }
}

/// `IsProcessInJob(proc, job)` — `job = None` means "any job".
///
/// On API failure returns **`true`** (conservative): the only
/// non-diagnostic caller gates `CREATE_BREAKAWAY_FROM_JOB` on it, and
/// breakaway is harmless when the caller is NOT in a job (the kernel
/// just ignores the flag) but failing to set it when the caller IS in
/// one breaks the runner→child Job assign.
pub fn is_process_in_job(proc: HANDLE, job: Option<HANDLE>) -> bool {
    let mut r = windows::core::BOOL(0);
    match unsafe { IsProcessInJob(proc, job, &mut r) } {
        Ok(()) => r.as_bool(),
        Err(_) => true,
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
