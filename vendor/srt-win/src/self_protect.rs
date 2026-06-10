//! Broker self-protection: rewrite the broker process's own DACL
//! so the sandbox child cannot `OpenProcess(broker_pid,
//! PROCESS_VM_*|CREATE_THREAD)`.
//!
//! The DACL is replaced with an explicit ALLOW list scoped to SIDs
//! the sandbox child does NOT have enabled in its token:
//!
//!   - `<group_sid>` — child has it deny-only
//!   - SYSTEM (S-1-5-18) — child doesn't carry it
//!   - BUILTIN\Admins — child has it deny-only
//!   - OWNER RIGHTS = 0 — suppresses the owner's implicit
//!     `READ_CONTROL|WRITE_DAC`, which would otherwise let the
//!     child (same user = owner) `WRITE_DAC` the broker
//!
//! `PROTECTED_DACL_SECURITY_INFORMATION` is required: without it
//! the inherited "user has full access to their own process" ACE
//! survives and the rewrite is a no-op for same-user children.
//!
//! Documented residual: another non-sandbox process belonging to
//! the same user (e.g. Explorer) still has the group enabled and
//! can therefore open the broker. That's intentional — the threat
//! model is the sandbox child, not the rest of the user's session.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use windows::core::PWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
    SetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    AddAccessAllowedAce, GetLengthSid, InitializeAcl, ACL, ACL_REVISION,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_ALL_ACCESS};

use crate::sid::LocalPsid;

/// Owner-Rights well-known SID (`S-1-3-4`). An ALLOW ACE with mask 0
/// on this SID overrides the implicit `READ_CONTROL|WRITE_DAC` that
/// the object's owner otherwise gets.
const SID_OWNER_RIGHTS: &str = "S-1-3-4";
const SID_SYSTEM: &str = "S-1-5-18";
const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";

/// Rewrite the current process's DACL to the broker-only pattern.
/// Idempotent — safe to call once per `srt-win exec` invocation.
pub fn install_broker_dacl(group_sid: &str) -> Result<()> {
    // RAII over `ConvertStringSidToSidW` → freed via `LocalFree` on
    // drop.
    let group = LocalPsid::from_string(group_sid)
        .with_context(|| format!("parse group SID '{group_sid}'"))?;
    let system = LocalPsid::from_string(SID_SYSTEM)?;
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let owner_rights = LocalPsid::from_string(SID_OWNER_RIGHTS)?;

    // (sid, mask) — first three get full access; OWNER_RIGHTS gets
    // nothing. CI passes `group_sid == BUILTIN\Administrators`;
    // dedup so we don't write a redundant ACE.
    let mut aces: Vec<(windows::Win32::Security::PSID, u32)> = vec![
        (group.as_psid(), PROCESS_ALL_ACCESS.0),
        (system.as_psid(), PROCESS_ALL_ACCESS.0),
    ];
    if !group_sid.eq_ignore_ascii_case(SID_BUILTIN_ADMINS) {
        aces.push((admins.as_psid(), PROCESS_ALL_ACCESS.0));
    }
    aces.push((owner_rights.as_psid(), 0u32));

    // ACL size = header + Σ(ACE fixed prefix + SID body). The fixed
    // prefix of an ACCESS_ALLOWED_ACE is 8 bytes (Header 4 + Mask 4);
    // `SidStart` is the first DWORD of the SID, so total per-ACE =
    // 8 + GetLengthSid.
    const ACE_FIXED: usize = 8;
    let mut total = size_of::<ACL>();
    for (s, _) in &aces {
        let len = unsafe { GetLengthSid(*s) } as usize;
        if len == 0 {
            return Err(anyhow!("GetLengthSid returned 0"));
        }
        total += ACE_FIXED + len;
    }
    total = (total + 3) & !3; // DWORD-align

    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe {
        InitializeAcl(acl, total as u32, ACL_REVISION)
            .context("InitializeAcl")?;
        for (s, mask) in &aces {
            AddAccessAllowedAce(acl, ACL_REVISION, *mask, *s)
                .context("AddAccessAllowedAce")?;
        }
        // PROTECTED strips inherited ACEs — without it the user
        // SID's default "full access to own process" inherited
        // grant fires and the rewrite is a no-op.
        let r = SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        );
        if r.is_err() {
            return Err(anyhow!(
                "SetSecurityInfo(broker process DACL): {r:?}"
            ));
        }
    }
    // `buf` can drop here — `SetSecurityInfo` copies the ACL into
    // the kernel object's SECURITY_DESCRIPTOR.

    // Diagnostic: read back and dump the DACL as SDDL so CI can
    // confirm exactly what's on the broker process. Gated on
    // SANDBOX_RUNTIME_WIN_DEBUG — production callers (batch 03:
    // one exec per user command) don't want a stderr line per
    // command. CI sets the env var so E6 still records the SDDL.
    if std::env::var_os("SANDBOX_RUNTIME_WIN_DEBUG").is_some() {
        match read_self_dacl_sddl() {
            Some(sddl) => eprintln!(
                "srt-win: self-protect applied (DACL: {sddl})"
            ),
            None => eprintln!("srt-win: self-protect applied"),
        }
    }
    Ok(())
}

/// Best-effort read of the current process's DACL as an SDDL
/// string. Returns `None` on any failure rather than erroring —
/// this is diagnostic only.
fn read_self_dacl_sddl() -> Option<String> {
    use crate::util::{from_pwstr, local_free};
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let r = GetSecurityInfo(
            HANDLE(GetCurrentProcess().0),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut psd),
        );
        if r.is_err() || psd.0.is_null() {
            return None;
        }
        let mut s = PWSTR::null();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut s,
            None,
        );
        local_free(psd.0);
        if ok.is_err() {
            return None;
        }
        let out = from_pwstr(s);
        local_free(s.0 as *mut c_void);
        Some(out)
    }
}
