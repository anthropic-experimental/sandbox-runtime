//! Local SAM (Security Accounts Manager) helpers — `NetLocalGroup*`
//! / `NetUser*` wrappers shared by [`crate::user`] and [`crate::wfp`].
//!
//! All membership operations key on **PSID** (level 0). Level 3
//! (`DOMAIN\name`) wants the literal `<ComputerName>\<name>` form
//! and rejects `.\name` with `ERROR_NO_SUCH_MEMBER`, so it's
//! avoided entirely.

use anyhow::{Result, anyhow};
use std::ffi::c_void;
use windows::Win32::Foundation::ERROR_MEMBER_IN_ALIAS;
use windows::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_0, NERR_GroupExists, NERR_GroupNotFound,
    NetApiBufferFree, NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel,
    NetLocalGroupGetMembers,
};
use windows::core::{PCWSTR, PWSTR};

use crate::sid::{self, LocalPsid};
use crate::util::{pcwstr, wstr};

// Benign idempotency outcomes alongside the NERR_* constants.
const ERROR_ALIAS_EXISTS: u32 = 1379;
const ERROR_NO_SUCH_ALIAS: u32 = 1376;

/// `NetLocalGroupAdd(level=1)`. Idempotent on `ALIAS_EXISTS` /
/// `NERR_GroupExists`.
pub fn ensure_local_group(name: &str, comment: &str) -> Result<()> {
    let mut name_w = wstr(name);
    let mut comment_w = wstr(comment);
    let info = LOCALGROUP_INFO_1 {
        lgrpi1_name: PWSTR(name_w.as_mut_ptr()),
        lgrpi1_comment: PWSTR(comment_w.as_mut_ptr()),
    };
    let rc = unsafe { NetLocalGroupAdd(PCWSTR::null(), 1, &info as *const _ as *const u8, None) };
    if rc != 0 && rc != NERR_GroupExists && rc != ERROR_ALIAS_EXISTS {
        return Err(anyhow!("NetLocalGroupAdd({name}): {rc}"));
    }
    Ok(())
}

/// `NetLocalGroupDel`. Idempotent on `NERR_GroupNotFound` /
/// `ERROR_NO_SUCH_ALIAS`.
pub fn delete_local_group(name: &str) -> Result<()> {
    let name_w = wstr(name);
    let rc = unsafe { NetLocalGroupDel(PCWSTR::null(), pcwstr(&name_w)) };
    if rc != 0 && rc != NERR_GroupNotFound && rc != ERROR_NO_SUCH_ALIAS {
        return Err(anyhow!("NetLocalGroupDel({name}): {rc}"));
    }
    Ok(())
}

/// `NetLocalGroupAddMembers(level=0)` — adds by PSID. Only
/// `ERROR_MEMBER_IN_ALIAS` is benign; every other code (including
/// `ERROR_NO_SUCH_MEMBER`) is a real failure that must surface.
pub fn add_member(group_name: &str, member: &LocalPsid) -> Result<()> {
    let group_w = wstr(group_name);
    let info = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: member.as_psid(),
    };
    let rc = unsafe {
        NetLocalGroupAddMembers(
            PCWSTR::null(),
            pcwstr(&group_w),
            0,
            &info as *const _ as *const u8,
            1,
        )
    };
    if rc != 0 && rc != ERROR_MEMBER_IN_ALIAS.0 {
        return Err(anyhow!("NetLocalGroupAddMembers({group_name}, sid): {rc}"));
    }
    Ok(())
}

/// Is `member_sid` a **direct** member of the local group whose SID
/// is `group_sid`? Walks `NetLocalGroupGetMembers(level=0)` and
/// compares string SIDs. Returns `false` (not an error) when the
/// group doesn't exist.
pub fn is_member_of(group_sid: &str, member_sid: &str) -> Result<bool> {
    let group_name = match sid::lookup_account_name(group_sid) {
        Ok(n) => n,
        // Group SID doesn't map → not a member.
        Err(_) => return Ok(false),
    };
    let group_w = wstr(&group_name);
    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut read: u32 = 0;
    let mut total: u32 = 0;
    let rc = unsafe {
        NetLocalGroupGetMembers(
            PCWSTR::null(),
            pcwstr(&group_w),
            0,
            &mut buf,
            // MAX_PREFERRED_LENGTH — let the API allocate one buffer.
            u32::MAX,
            &mut read,
            &mut total,
            None,
        )
    };
    if rc == NERR_GroupNotFound || rc == ERROR_NO_SUCH_ALIAS {
        return Ok(false);
    }
    if rc != 0 {
        return Err(anyhow!("NetLocalGroupGetMembers({group_name}): {rc}"));
    }
    let mut found = false;
    if !buf.is_null() && read > 0 {
        let entries = unsafe {
            std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_0, read as usize)
        };
        for e in entries {
            if let Ok(s) = sid::psid_to_string(e.lgrmi0_sid)
                && s.eq_ignore_ascii_case(member_sid)
            {
                found = true;
                break;
            }
        }
    }
    if !buf.is_null() {
        unsafe {
            let _ = NetApiBufferFree(Some(buf as *const c_void));
        }
    }
    Ok(found)
}
