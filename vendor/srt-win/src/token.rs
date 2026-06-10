//! Restricted-token construction for the deny-only-group sandbox.
//!
//! Token shape:
//!   - `SidsToDisable = [<group_sid>, BUILTIN\Administrators]` — flips
//!     them to `SE_GROUP_USE_FOR_DENY_ONLY` without touching the
//!     restricting list.
//!   - `LUA_TOKEN` flag — token reads as a normal limited-user token
//!     to NT components.
//!   - All privileges deleted except `SeChangeNotifyPrivilege`.
//!   - Integrity Level = Medium (same as a normal user process).
//!   - No `RestrictingSids` array — that breaks Schannel/LSA RPC.
//!
//! WFP's `ALE_USER_ID` AccessCheck honours
//! `SE_GROUP_USE_FOR_DENY_ONLY`, so an SDDL ACE
//! `(A;;CC;;;<group_sid>)` matches only when the group is *enabled*
//! — i.e. on the broker, never on the sandbox child.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{
    AddAccessAllowedAce, AllocateAndInitializeSid, CreateRestrictedToken,
    DuplicateTokenEx, FreeSid, GetLengthSid, GetTokenInformation,
    InitializeAcl, LookupPrivilegeValueW, SecurityImpersonation,
    SetTokenInformation, TokenDefaultDacl, TokenGroups, TokenIntegrityLevel,
    TokenPrimary, TokenPrivileges, ACL, ACL_REVISION, LUA_TOKEN,
    LUID_AND_ATTRIBUTES, PSID, SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY,
    TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
};
use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken,
};

use crate::sid::LocalPsid;
use crate::util::{pcwstr, wstr};

/// Medium IL (`SECURITY_MANDATORY_MEDIUM_RID`). The sandbox child
/// runs at Medium — same as normal user processes — so Schannel /
/// LSA / registry edge cases that fire at Low IL don't apply.
pub const IL_MEDIUM: u32 = 0x2000;

/// `BUILTIN\Administrators`. Always added to `SidsToDisable` so an
/// elevated broker still produces a non-admin child.
const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";

/// `SE_GROUP_INTEGRITY` attribute (winnt.h). Required on the
/// `TOKEN_MANDATORY_LABEL.Label.Attributes` field.
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// Open this process's primary token with full access.
pub fn open_self_token() -> Result<HANDLE> {
    unsafe {
        let mut h = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h)
            .context("OpenProcessToken")?;
        Ok(h)
    }
}

/// Build the deny-only-group restricted token from `base` (the
/// broker's own token). `group_sid` is the discriminator group that
/// gets flipped deny-only. Returns a non-primary token; the caller
/// duplicates to primary via [`to_primary`].
pub fn make_sandbox_token(base: HANDLE, group_sid: &str) -> Result<HANDLE> {
    // SIDs to disable. `LocalPsid` is RAII over
    // `ConvertStringSidToSidW` and frees with `LocalFree` on drop —
    // the donor used raw `PSID` + `FreeSid` here, which is the wrong
    // free fn for that allocator.
    //
    // CI uses `group_sid == BUILTIN\Administrators` (the only SID
    // that's both on the runner's token without a logout AND
    // discriminator-shaped). Dedup so `CreateRestrictedToken`
    // doesn't see the same SID twice in `SidsToDisable`.
    let group = LocalPsid::from_string(group_sid)
        .with_context(|| format!("parse group SID '{group_sid}'"))?;
    let admins;
    let mut psids: Vec<PSID> = vec![group.as_psid()];
    if !group_sid.eq_ignore_ascii_case(SID_BUILTIN_ADMINS) {
        admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
        psids.push(admins.as_psid());
    }
    let disable: Vec<SID_AND_ATTRIBUTES> = psids
        .into_iter()
        .map(|s| SID_AND_ATTRIBUTES { Sid: s, Attributes: 0 })
        .collect();

    // Privileges to delete: everything in `base` except
    // SeChangeNotifyPrivilege.
    let to_delete = privileges_except(base, &["SeChangeNotifyPrivilege"])?;

    let mut out = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            base,
            LUA_TOKEN,
            Some(&disable),
            if to_delete.is_empty() { None } else { Some(&to_delete) },
            None, // RestrictingSids — intentionally empty
            &mut out,
        )
        .with_context(|| {
            format!("CreateRestrictedToken(disable=[Admins,{group_sid}])")
        })?;
    }
    // `admins` / `group` LocalPsid drop here → LocalFree.

    // RAII-own `out` so a `?` from set_il/set_default_dacl below
    // closes it. Local — token.rs is the only module that holds
    // raw HANDLEs across fallible calls outside launch.rs.
    struct Guard(HANDLE);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
    let guard = Guard(out);
    set_il(guard.0, IL_MEDIUM)?;
    set_default_dacl(guard.0, base)?;
    // Disarm and return the raw handle to the caller.
    let h = guard.0;
    std::mem::forget(guard);
    Ok(h)
}

/// Duplicate to a primary token (`CreateProcessAsUserW` requires a
/// primary).
pub fn to_primary(token: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut out = HANDLE::default();
        DuplicateTokenEx(
            token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut out,
        )
        .context("DuplicateTokenEx(primary)")?;
        Ok(out)
    }
}

/// Set the token's integrity level via a mandatory-label SID built
/// with `AllocateAndInitializeSid` (so [`FreeSid`] is the correct
/// release fn — the one place in this crate where it is).
fn set_il(tok: HANDLE, rid: u32) -> Result<()> {
    unsafe {
        let ml_auth = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 16],
        };
        let mut sid = PSID::default();
        AllocateAndInitializeSid(
            &ml_auth, 1, rid, 0, 0, 0, 0, 0, 0, 0, &mut sid,
        )
        .context("AllocateAndInitializeSid(mandatory label)")?;
        let tml = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        let r = SetTokenInformation(
            tok,
            TokenIntegrityLevel,
            &tml as *const _ as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
        );
        // Free regardless of outcome.
        FreeSid(sid);
        r.context("SetTokenInformation(IntegrityLevel)")?;
        Ok(())
    }
}

/// Rewrite the token's default DACL so objects the child *creates*
/// (process, thread, mutex, …) are accessible to SYSTEM and to the
/// logon session. The donor leaked the SYSTEM SID here; this version
/// uses [`LocalPsid`] so it's freed on return.
///
/// We deliberately keep the **logon SID** grant rather than switching
/// it to the discriminator group — switching would prevent siblings
/// inside the sandbox (e.g. a parallel build's worker processes) from
/// opening each other's pipes/mutexes, since they all hold the group
/// deny-only.
fn set_default_dacl(tok: HANDLE, base: HANDLE) -> Result<()> {
    let system = LocalPsid::from_string("S-1-5-18")?;

    // Find the logon-session SID in the base token's groups.
    let groups_buf = get_token_info(base, TokenGroups)?;
    let logon = unsafe {
        let tg = &*(groups_buf.as_ptr() as *const TOKEN_GROUPS);
        let arr = std::slice::from_raw_parts(
            tg.Groups.as_ptr(),
            tg.GroupCount as usize,
        );
        arr.iter()
            .find(|g| g.Attributes & (SE_GROUP_LOGON_ID as u32) != 0)
            .map(|g| g.Sid)
    };

    let sids: Vec<PSID> = match logon {
        Some(l) => vec![system.as_psid(), l],
        None => vec![system.as_psid()],
    };

    // Sized ACL: header + per-ACE (8-byte fixed prefix + SID body).
    const ACE_FIXED: usize = 8;
    let mut total = size_of::<ACL>();
    for s in &sids {
        total += ACE_FIXED + unsafe { GetLengthSid(*s) } as usize;
    }
    total = (total + 3) & !3;
    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe {
        InitializeAcl(acl, total as u32, ACL_REVISION)
            .context("InitializeAcl(default DACL)")?;
        // GENERIC_ALL.
        const GENERIC_ALL: u32 = 0x1000_0000;
        for s in &sids {
            AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, *s)
                .context("AddAccessAllowedAce(default DACL)")?;
        }
        let tdd = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
        SetTokenInformation(
            tok,
            TokenDefaultDacl,
            &tdd as *const _ as *const c_void,
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
        .context("SetTokenInformation(DefaultDacl)")?;
    }
    // `groups_buf` (which backs `logon`) and `system` both drop here.
    Ok(())
}

fn get_token_info(tok: HANDLE, cls: TOKEN_INFORMATION_CLASS) -> Result<Vec<u8>> {
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(tok, cls, None, 0, &mut len);
        if len == 0 {
            return Err(anyhow!(
                "GetTokenInformation({cls:?}) sizing returned 0"
            ));
        }
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(
            tok,
            cls,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .with_context(|| format!("GetTokenInformation({cls:?})"))?;
        Ok(buf)
    }
}

/// Every privilege LUID in `base` except those named in `keep`.
fn privileges_except(
    base: HANDLE,
    keep: &[&str],
) -> Result<Vec<LUID_AND_ATTRIBUTES>> {
    let keep_luids: Vec<LUID> = keep
        .iter()
        .filter_map(|n| {
            let mut l = LUID::default();
            let w = wstr(n);
            unsafe { LookupPrivilegeValueW(None, pcwstr(&w), &mut l).ok()? };
            Some(l)
        })
        .collect();
    let buf = get_token_info(base, TokenPrivileges)?;
    unsafe {
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let arr = std::slice::from_raw_parts(
            tp.Privileges.as_ptr(),
            tp.PrivilegeCount as usize,
        );
        Ok(arr
            .iter()
            .filter(|p| {
                !keep_luids.iter().any(|k| {
                    k.LowPart == p.Luid.LowPart && k.HighPart == p.Luid.HighPart
                })
            })
            .map(|p| LUID_AND_ATTRIBUTES {
                Luid: p.Luid,
                Attributes: Default::default(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::CloseHandle;

    #[test]
    fn restricted_token_builds() {
        // Group SID is BUILTIN\Users — always present, so the test
        // doesn't depend on the discriminator group being installed.
        let base = open_self_token().expect("open_self_token");
        let r = make_sandbox_token(base, "S-1-5-32-545");
        unsafe {
            let _ = CloseHandle(base);
        }
        let tok = r.expect("make_sandbox_token");
        let prim = to_primary(tok).expect("to_primary");
        unsafe {
            let _ = CloseHandle(tok);
            let _ = CloseHandle(prim);
        }
    }

    #[test]
    fn privileges_except_keeps_change_notify() {
        let base = open_self_token().expect("open_self_token");
        let to_delete =
            privileges_except(base, &["SeChangeNotifyPrivilege"]).unwrap();
        // Resolve SeChangeNotifyPrivilege's LUID and assert it's NOT
        // in the deletion set.
        let mut keep = LUID::default();
        let w = wstr("SeChangeNotifyPrivilege");
        unsafe {
            LookupPrivilegeValueW(None, pcwstr(&w), &mut keep).unwrap();
            let _ = CloseHandle(base);
        }
        assert!(
            !to_delete.iter().any(|p| p.Luid.LowPart == keep.LowPart
                && p.Luid.HighPart == keep.HighPart),
            "SeChangeNotifyPrivilege must not be in the deletion set"
        );
    }
}
