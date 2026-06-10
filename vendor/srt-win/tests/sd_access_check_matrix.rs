//! Proof that the WFP filter security descriptors discriminate the
//! three token states (group **enabled** / **deny-only** /
//! **absent**) the way `wfp::install_filters` relies on.
//!
//! WFP's `ALE_USER_ID` `FWP_MATCH_EQUAL` condition runs `AccessCheck`
//! on the connecting token against the filter's SD; the filter
//! matches iff the check grants. This test calls `AccessCheck`
//! directly — no live WFP engine — so it pins the SD semantics
//! independent of the network stack.
//!
//! Expected 3×3 matrix (`true` = AccessCheck grants → filter would
//! match):
//!
//!                | filter-0 SD          | filter-1 SD     | filter-3 SD
//!                | (D;;;G)(A;;;WD)      | (A;;;G)         | (A;;;WD)
//!   -------------+----------------------+-----------------+------------
//!   G enabled    | DENY (deny ACE hits) | GRANT           | GRANT
//!   G deny-only  | DENY (deny ACE hits  | DENY (deny-only | GRANT
//!                |  — deny-only SIDs    |  SIDs ignored   |
//!                |  match DENY ACEs)    |  by ALLOW ACEs) |
//!   G absent     | GRANT (allow WD)     | DENY (no grant) | GRANT
//!
//! The "G enabled" and "G deny-only" rows use `BUILTIN\Administrators`
//! (`S-1-5-32-544`) as the test group, since the CI runner's token
//! reliably carries it enabled; deny-only is produced via
//! `CreateRestrictedToken(SidsToDisable=[Admins])`. The "G absent"
//! row uses an unmapped well-known-shape SID (`S-1-5-32-9999`) so
//! the same process token is genuinely a non-member.

#![cfg(windows)]

use std::mem::size_of;
use windows::core::BOOL;
use windows::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    HANDLE,
};
use windows::Win32::Security::{
    AccessCheck, CreateRestrictedToken, DuplicateTokenEx, SecurityImpersonation,
    TokenImpersonation, GENERIC_MAPPING, PRIVILEGE_SET, PSECURITY_DESCRIPTOR,
    SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use srt_win::sid::LocalPsid;
use srt_win::util::wstr;
use srt_win::wfp::{sddl_group, sddl_nonmember, SDDL_EVERYONE};

/// `BUILTIN\Administrators`. Reliably present-and-enabled on the
/// GitHub-hosted Windows runner's token. If this test runs on a
/// non-admin host the "enabled" row's filter-1 assertion will fail —
/// in that case the test bails with a skip message rather than a
/// false negative.
const ADMINS_SID: &str = "S-1-5-32-544";

/// Well-formed RID under `BUILTIN` that maps to nothing. Stands in
/// for "a group this token has never heard of".
const ABSENT_GROUP_SID: &str = "S-1-5-32-9999";

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

/// Build an impersonation token in which `group_sid` is flipped to
/// `SE_GROUP_USE_FOR_DENY_ONLY` via `CreateRestrictedToken`.
fn deny_only_token(group_sid: &str) -> HANDLE {
    let psid = LocalPsid::from_string(group_sid).expect("group sid");
    unsafe {
        let mut primary = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ALL_ACCESS,
            &mut primary,
        )
        .expect("OpenProcessToken");
        let disable = [SID_AND_ATTRIBUTES {
            Sid: psid.as_psid(),
            Attributes: 0,
        }];
        let mut restricted = HANDLE::default();
        CreateRestrictedToken(
            primary,
            windows::Win32::Security::CREATE_RESTRICTED_TOKEN_FLAGS(0),
            Some(&disable),
            None,
            None,
            &mut restricted,
        )
        .expect("CreateRestrictedToken");
        let _ = CloseHandle(primary);
        // AccessCheck needs impersonation level.
        let mut imp = HANDLE::default();
        DuplicateTokenEx(
            restricted,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut imp,
        )
        .expect("DuplicateTokenEx(restricted)");
        let _ = CloseHandle(restricted);
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
        let _ = windows::Win32::Foundation::LocalFree(Some(
            windows::Win32::Foundation::HLOCAL(psd.0),
        ));
    }
    r.expect("AccessCheck");
    status.as_bool()
}

#[test]
fn sd_access_check_matrix() {
    // Bail (don't fail) if Admins isn't enabled on this token — the
    // "enabled" row can't be exercised on a non-admin host.
    match srt_win::sid::group_state_for_self(ADMINS_SID).unwrap() {
        srt_win::sid::GroupState::Enabled => {}
        other => {
            eprintln!(
                "skipping sd_access_check_matrix: Admins is {other:?}, \
                 need Enabled (run elevated)"
            );
            return;
        }
    }

    // SDs keyed on Admins (for enabled / deny-only rows).
    let sd0_admins = sddl_nonmember(ADMINS_SID);
    let sd1_admins = sddl_group(ADMINS_SID);
    // SDs keyed on a group this token does not carry (for absent row).
    let sd0_absent = sddl_nonmember(ABSENT_GROUP_SID);
    let sd1_absent = sddl_group(ABSENT_GROUP_SID);
    // Filter-3 SD is group-independent.
    let sd3 = SDDL_EVERYONE;

    let tok_enabled = own_impersonation_token();
    let tok_denyonly = deny_only_token(ADMINS_SID);

    // ── enabled row ──────────────────────────────────────────────
    // Filter 0: DENY-Admins hits → denied.
    assert!(
        !check(tok_enabled, &sd0_admins),
        "enabled vs filter-0: DENY ACE on the group should hit"
    );
    // Filter 1: ALLOW-Admins grants.
    assert!(
        check(tok_enabled, &sd1_admins),
        "enabled vs filter-1: ALLOW ACE on enabled group should grant"
    );
    // Filter 3: ALLOW-Everyone grants.
    assert!(check(tok_enabled, sd3), "enabled vs filter-3");

    // ── deny-only row ────────────────────────────────────────────
    // Filter 0: deny-only SIDs DO match DENY ACEs → denied. This is
    // the load-bearing semantic that lets filter 0 distinguish
    // "non-member" from "sandboxed member".
    assert!(
        !check(tok_denyonly, &sd0_admins),
        "deny-only vs filter-0: deny-only group must still match the DENY ACE"
    );
    // Filter 1: deny-only SIDs are ignored by ALLOW ACEs → no grant.
    assert!(
        !check(tok_denyonly, &sd1_admins),
        "deny-only vs filter-1: deny-only group must NOT satisfy the ALLOW ACE"
    );
    // Filter 3: ALLOW-Everyone still grants (Everyone is enabled).
    assert!(check(tok_denyonly, sd3), "deny-only vs filter-3");

    // ── absent row ───────────────────────────────────────────────
    // Filter 0: DENY misses (group not in token) → ALLOW-Everyone
    // grants. This is what lets services / SYSTEM / non-member
    // users through filter 0 untouched.
    assert!(
        check(tok_enabled, &sd0_absent),
        "absent vs filter-0: non-member token should fall through to ALLOW WD"
    );
    // Filter 1: ALLOW-<absent-group> can't grant.
    assert!(
        !check(tok_enabled, &sd1_absent),
        "absent vs filter-1: no grant when group not in token"
    );
    // Filter 3: ALLOW-Everyone grants.
    assert!(check(tok_enabled, sd3), "absent vs filter-3");

    unsafe {
        let _ = CloseHandle(tok_enabled);
        let _ = CloseHandle(tok_denyonly);
    }
}
