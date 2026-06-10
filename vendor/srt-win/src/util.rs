//! Small Win32 string helpers shared by `sid.rs` and `wfp.rs`.

use std::ffi::c_void;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};

/// UTF-8 → NUL-terminated UTF-16 buffer. Keep the returned `Vec`
/// alive for as long as the resulting `PCWSTR` / `PWSTR` is in use.
pub fn wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Borrow a `Vec<u16>` from `wstr` as a `PCWSTR`.
pub fn pcwstr(buf: &[u16]) -> PCWSTR {
    PCWSTR(buf.as_ptr())
}

/// Read a NUL-terminated `PWSTR` (typically returned by a Win32 API
/// that allocates) into an owned `String`. Caller still owns the
/// underlying allocation.
pub fn from_pwstr(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.0.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(p.0, len) };
    String::from_utf16_lossy(slice)
}

/// `LocalFree` a pointer returned by a Win32 API documented to require
/// it (e.g. `ConvertSidToStringSidW`,
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`).
pub fn local_free(p: *mut c_void) {
    unsafe {
        let _ = LocalFree(Some(HLOCAL(p)));
    }
}
