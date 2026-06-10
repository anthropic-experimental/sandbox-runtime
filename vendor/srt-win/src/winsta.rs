//! Non-interactive window station + desktop for the sandbox child.
//!
//! Creates a per-broker anonymous window station with a single
//! desktop attached, and exposes the `<wsname>\desk` path that
//! `STARTUPINFOW.lpDesktop` consumes. The sandbox child spawns onto
//! this WS+desktop and so cannot enumerate or message top-level
//! windows on the user's interactive `WinSta0`.
//!
//! The kernel reference-counts a window station by attached
//! processes. The broker keeps both handles open from creation
//! until after the child exits — dropping `WinStaDesk` then
//! releases the kernel objects.
//!
//! We do NOT permanently re-home the broker via
//! `SetProcessWindowStation`; we briefly attach to the new WS to
//! create the desktop on it, then restore.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
    GetProcessWindowStation, GetUserObjectInformationW,
    SetProcessWindowStation, DESKTOP_CONTROL_FLAGS, HDESK, HWINSTA, UOI_NAME,
};

use crate::util::wstr;

// winuser.h: WINSTA_ALL_ACCESS = 0x37F; DESKTOP_ALL_ACCESS = 0x1FF.
// OR with STANDARD_RIGHTS_REQUIRED so the broker holds full control
// on the objects it just created.
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
const WS_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0x0000_037F;
const DESK_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | 0x0000_01FF;

/// RAII holder for the sandbox window station + its desktop, plus
/// the wide `<wsname>\desk` buffer that backs
/// `STARTUPINFOW.lpDesktop`.
pub struct WinStaDesk {
    winsta: HWINSTA,
    desktop: HDESK,
    /// `STARTUPINFOW.lpDesktop` is `PWSTR` (mutable wide pointer per
    /// the API contract), so we keep the buffer here and hand out a
    /// raw pointer via [`desktop_name_ptr`]. Null-terminated.
    desk_path: Vec<u16>,
}

impl WinStaDesk {
    /// Create an anonymous WS with a single `desk` desktop.
    ///
    /// A NULL name lets the kernel mint a unique anonymous name —
    /// passing an explicit name into the WS namespace
    /// (`\Sessions\<n>\Windows\WindowStations`) requires admin on
    /// Vista+, which a non-elevated broker doesn't have. The
    /// kernel-generated name is recovered via
    /// `GetUserObjectInformationW(UOI_NAME)`.
    pub fn new() -> Result<Self> {
        // 1) Anonymous WS, default DACL.
        let winsta = unsafe {
            CreateWindowStationW(PCWSTR::null(), 0, WS_ALL_ACCESS, None)
                .context("CreateWindowStationW(NULL)")?
        };
        let ws_name = match object_name(HANDLE(winsta.0)) {
            Ok(n) => n,
            Err(e) => {
                unsafe {
                    let _ = CloseWindowStation(winsta);
                }
                return Err(e.context("UOI_NAME on new window station"));
            }
        };

        // 2) Attach to it just long enough to create the desktop.
        //    `CreateDesktopW` targets the *calling process's* current
        //    WS; we must point at the new one, create, then restore
        //    — even on the error path so the broker isn't left
        //    re-homed.
        let prev = match unsafe { GetProcessWindowStation() } {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    let _ = CloseWindowStation(winsta);
                }
                return Err(anyhow!(
                    "GetProcessWindowStation (snapshot): {e}"
                ));
            }
        };
        if let Err(e) = unsafe { SetProcessWindowStation(winsta) } {
            unsafe {
                let _ = CloseWindowStation(winsta);
            }
            return Err(anyhow!(
                "SetProcessWindowStation({ws_name}): {e}"
            ));
        }

        let desk_name_w = wstr("desk");
        let desktop_result = unsafe {
            CreateDesktopW(
                PCWSTR(desk_name_w.as_ptr()),
                PCWSTR::null(),
                None,
                DESKTOP_CONTROL_FLAGS(0),
                DESK_ALL_ACCESS,
                None,
            )
        };

        // Always restore the broker's WS — a broker stuck on the
        // sandbox WS is a fatal state. If both CreateDesktopW and
        // restore failed, report both.
        let restore = unsafe { SetProcessWindowStation(prev) };

        let desktop = match (desktop_result, &restore) {
            (Ok(d), Ok(())) => d,
            (Ok(d), Err(re)) => {
                // Desktop created but we can't restore the broker.
                // Close what we made; the restore failure is the
                // error that matters.
                unsafe {
                    let _ = CloseDesktop(d);
                    let _ = CloseWindowStation(winsta);
                }
                return Err(anyhow!(
                    "SetProcessWindowStation(restore previous): {re} \
                     (after successful CreateDesktopW on {ws_name})"
                ));
            }
            (Err(de), restore_r) => {
                unsafe {
                    let _ = CloseWindowStation(winsta);
                }
                return Err(match restore_r {
                    Ok(()) => anyhow!(
                        "CreateDesktopW(desk) on {ws_name}: {de}"
                    ),
                    Err(re) => anyhow!(
                        "CreateDesktopW(desk) on {ws_name}: {de}; AND \
                         SetProcessWindowStation(restore) also \
                         failed: {re}"
                    ),
                });
            }
        };

        // `<wsname>\desk` — backslash separator.
        let desk_path = wstr(&format!("{ws_name}\\desk"));

        Ok(Self { winsta, desktop, desk_path })
    }

    /// Pointer to the wide name buffer for `STARTUPINFOW.lpDesktop`.
    /// Caller must keep `self` alive until after
    /// `CreateProcessAsUserW` returns.
    pub fn desktop_name_ptr(&mut self) -> *mut u16 {
        self.desk_path.as_mut_ptr()
    }
}

impl Drop for WinStaDesk {
    fn drop(&mut self) {
        unsafe {
            // Desktop first (it references the WS), then WS.
            let _ = CloseDesktop(self.desktop);
            let _ = CloseWindowStation(self.winsta);
        }
    }
}

/// Read a user-object's `UOI_NAME` (returned as a wide
/// NUL-terminated string).
fn object_name(h: HANDLE) -> Result<String> {
    let mut needed = 0u32;
    // Sizing call — expected to fail with ERROR_INSUFFICIENT_BUFFER
    // and write the required byte count.
    unsafe {
        let _ = GetUserObjectInformationW(
            h, UOI_NAME, None, 0, Some(&mut needed),
        );
    }
    if needed == 0 {
        return Err(anyhow!(
            "GetUserObjectInformationW sizing returned 0"
        ));
    }
    let mut buf = vec![0u8; needed as usize];
    unsafe {
        GetUserObjectInformationW(
            h,
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            Some(&mut needed),
        )
        .context("GetUserObjectInformationW(UOI_NAME)")?;
    }
    // SAFETY: `buf` is `needed` bytes, even-length (UTF-16);
    // reinterpret as u16.
    let wide = unsafe {
        std::slice::from_raw_parts(
            buf.as_ptr() as *const u16,
            (needed as usize) / 2,
        )
    };
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    Ok(String::from_utf16_lossy(&wide[..end]))
}
