//! Proof that the WFP block-user filter's security descriptor
//! matches only the intended principal — the sandbox user — the
//! way `wfp::install_filters` relies on.
//!
//! WFP's `ALE_USER_ID` `FWP_MATCH_EQUAL` condition runs `AccessCheck`
//! on the connecting token against the filter's SD; the filter
//! matches iff the check grants. This test calls `AccessCheck`
//! directly — no live WFP engine — so it pins the SD semantics
//! independent of the network stack.
//!
//! Expected:
//!   - SD = `O:LSG:LSD:(A;;CC;;;<sb-SID>)`
//!   - token whose user IS `<sb-SID>` → GRANT (filter matches →
//!     BLOCK fires)
//!   - any other token (broker, services, SYSTEM) → DENY (no
//!     ALLOW ACE matches → falls through to default-permit)
//!
//! The "is the sandbox user" row can't be exercised without
//! provisioning a real account, so we use the CALLING user's SID
//! as `<sb-SID>` and assert GRANT against our own token; then key
//! the SD on a SID we definitely DON'T carry and assert DENY.

#![cfg(windows)]

use std::mem::size_of;
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    AccessCheck, DuplicateTokenEx, GENERIC_MAPPING, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    SecurityImpersonation, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY, TokenImpersonation,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::BOOL;

use srt_win::util::wstr;
use srt_win::wfp::sddl_sandbox_user;

/// `CC` in SDDL is `ADS_RIGHT_DS_CREATE_CHILD` = bit 0. The filters
/// only need a single bit; `AccessCheck` is asked for that bit.
const DESIRED_ACCESS: u32 = 1;

/// Open an impersonation-level duplicate of the current process
/// token — `AccessCheck` requires an impersonation token.
fn own_impersonation_token() -> HANDLE {
    unsafe {
        let mut primary = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut primary,
        )
        .expect("OpenProcessToken");
        let mut imp = HANDLE::default();
        DuplicateTokenEx(
            primary,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut imp,
        )
        .expect("DuplicateTokenEx");
        let _ = CloseHandle(primary);
        imp
    }
}

/// Run `AccessCheck(token, SD-from-sddl, DESIRED_ACCESS)` and return
/// whether it granted.
fn check(token: HANDLE, sddl: &str) -> bool {
    let w = wstr(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            windows::core::PCWSTR(w.as_ptr()),
            1, // SDDL_REVISION_1
            &mut psd,
            None,
        )
        .expect("ConvertStringSecurityDescriptorToSecurityDescriptorW");
    }
    // GENERIC_MAPPING is required by the API but irrelevant here:
    // DESIRED_ACCESS has no generic bits set, so MapGenericMask
    // never consults this table.
    let mapping = GENERIC_MAPPING {
        GenericRead: GENERIC_READ.0,
        GenericWrite: GENERIC_WRITE.0,
        GenericExecute: GENERIC_EXECUTE.0,
        GenericAll: GENERIC_ALL.0,
    };
    let mut priv_set = PRIVILEGE_SET::default();
    let mut priv_set_len = size_of::<PRIVILEGE_SET>() as u32;
    let mut granted: u32 = 0;
    let mut status = BOOL(0);
    let r = unsafe {
        AccessCheck(
            psd,
            token,
            DESIRED_ACCESS,
            &mapping,
            Some(&mut priv_set),
            &mut priv_set_len,
            &mut granted,
            &mut status,
        )
    };
    unsafe {
        let _ =
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(psd.0)));
    }
    r.expect("AccessCheck");
    status.as_bool()
}

#[test]
fn sd_access_check_matrix() {
    let tok = own_impersonation_token();
    let me = srt_win::sid::current_user_sid().unwrap();

    // SD keyed on THIS token's user SID → GRANT (i.e. block-user
    // would fire — the sandbox user is fenced).
    assert!(
        check(tok, &sddl_sandbox_user(&me)),
        "block-user SD keyed on own user SID must match own token"
    );

    // SD keyed on a SID this token does NOT carry → DENY (i.e.
    // block-user does NOT match the broker / services / any other
    // user → falls through to default-permit). Well-formed RID
    // under `BUILTIN` that maps to nothing.
    assert!(
        !check(tok, &sddl_sandbox_user("S-1-5-32-9999")),
        "block-user SD keyed on a foreign SID must NOT match own token"
    );

    unsafe {
        let _ = CloseHandle(tok);
    }
}
