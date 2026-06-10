//! Windows Filtering Platform (WFP) filter management and local-group
//! provisioning for the sandbox-runtime Windows network fence.
//!
//! ## Design
//!
//! At install time we create a local group (default
//! `sandbox-runtime-net`), add target users, and persist **one
//! machine-wide** filter set — four filters at each of
//! `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `_V6` (8 total), all under one
//! persistent sublayer. None of the filters reference a user SID, so
//! enterprises install once per machine; adding a user to the group
//! is the only per-user step.
//!
//! WFP's `ALE_USER_ID` condition with `FWP_MATCH_EQUAL` evaluates the
//! supplied security descriptor via `AccessCheck` against the
//! connecting token: the filter *matches* iff the check grants
//! access. We use that to discriminate three token states with
//! respect to `<group_sid>` — **enabled**, **deny-only**, **absent**:
//!
//!   0. **PERMIT non-member** (weight 0xF) — SD
//!      `O:LSG:LSD:(D;;CC;;;<group_sid>)(A;;CC;;;WD)`. The DENY ACE on the
//!      group hits any token where the group is present (enabled
//!      *or* deny-only — `SE_GROUP_USE_FOR_DENY_ONLY` SIDs match DENY
//!      ACEs); only tokens with the group *absent* fall through to
//!      ALLOW-Everyone and match. Lets services, SYSTEM, and users
//!      who haven't been added to the group through untouched.
//!
//!   1. **PERMIT group-enabled** (weight 0xE) — SD
//!      `O:LSG:LSD:(A;;CC;;;<group_sid>)`. Matches tokens with the group
//!      *enabled* (broker, ordinary processes of a member user).
//!      Tokens with the group deny-only do **not** match: deny-only
//!      SIDs are ignored by ALLOW ACEs.
//!
//!   2. **PERMIT loopback** (weight 0xD) — `IP_REMOTE_ADDRESS` is
//!      `127.0.0.0/8` (v4) / `::1` (v6) **and** `IP_REMOTE_PORT` is
//!      in `[low, high]` (default 60080–60089). No user condition.
//!      The sandboxed child reaches the host proxies — which on
//!      Windows bind inside this range — but not arbitrary
//!      loopback listeners. (Linux/macOS restrict the child to
//!      exactly the two proxy ports; this range is the closest
//!      Windows analogue without per-`initialize()` admin.)
//!
//!   3. **BLOCK** (weight 0x1) — SD `O:LSG:LSD:(A;;CC;;;WD)`
//!      (ALLOW-Everyone). Matches every token; catches the sandboxed
//!      child for everything off-loopback. The Everyone ACE is
//!      belt-and-braces — a no-condition BLOCK would behave the same
//!      — but keeping an `ALE_USER_ID` condition on every filter
//!      makes enumeration uniform.
//!
//! Filters carry a small JSON tag in `providerData` (`{tool, kind,
//! port_range?}`) so install/uninstall/status can locate them by
//! enumeration. There
//! is no marker file: `wfp status` enumerates the live engine; `group
//! status` queries SAM and the current token directly.

// The WFP structs are large and partially-initialised; the
// `..Default::default()` struct-update form clippy suggests is
// significantly less readable here than field-by-field assignment.
#![allow(clippy::field_reassign_with_default)]

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    LocalFree, ERROR_MEMBER_IN_ALIAS, HANDLE, HLOCAL,
};
use windows::Win32::NetworkManagement::NetManagement::{
    NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel,
    NERR_GroupExists, NERR_GroupNotFound, LOCALGROUP_INFO_1,
    LOCALGROUP_MEMBERS_INFO_0,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
    FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_ACTION0_0, FWPM_CONDITION_ALE_USER_ID,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_ARRAY16,
    FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_FILTER_ENUM_OVERLAPPING, FWP_MATCH_EQUAL,
    FWP_MATCH_RANGE, FWP_RANGE0, FWP_RANGE_TYPE,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT64,
    FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR,
};

use crate::sid;
use crate::util::{pcwstr, wstr};

const GROUP_COMMENT: &str = "sandbox-runtime network sandbox membership";

/// Default sublayer GUID. Stable so uninstall can find filters from a
/// previous install. Overridable via `--sublayer-guid` so an
/// enterprise that provisions WFP via its own tooling can point us at
/// theirs. {2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21}
pub const DEFAULT_SUBLAYER_GUID: GUID =
    GUID::from_u128(0x2c5d0ad6_5f3b_4d4e_9b8f_1a3e7c9d0b21);

/// Default loopback port range for filter 2. The JS http/socks
/// proxies bind inside this range on Windows so the sandboxed child
/// can reach them. Ten ports leaves headroom for http + socks +
/// future listeners and for `EADDRINUSE` retries. Overridable via
/// `--proxy-port-range`.
pub const DEFAULT_PROXY_PORT_RANGE: (u16, u16) = (60080, 60089);

/// Sanity cap on `--proxy-port-range` width (`high - low`). The
/// range exists to *narrow* loopback exposure relative to the
/// previous all-of-127/8 design; an unbounded range would defeat
/// that.
pub const MAX_PROXY_PORT_RANGE_WIDTH: u16 = 64;

// WFP error codes we treat as benign idempotency outcomes.
const FWP_E_ALREADY_EXISTS: u32 = 0x80320009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320003;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x80320007;
const FWP_E_IN_USE: u32 = 0x8032000A;

const SDDL_REVISION_1: u32 = 1;

// ────────────────────── small RAII helpers ──────────────────────

/// Heap SD owned by us; freed via `LocalFree`.
struct OwnedSd {
    ptr: PSECURITY_DESCRIPTOR,
    len: u32,
}

impl OwnedSd {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let w = wstr(sddl);
        let mut psd = PSECURITY_DESCRIPTOR::default();
        let mut sz: u32 = 0;
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                pcwstr(&w),
                SDDL_REVISION_1,
                &mut psd,
                Some(&mut sz),
            )
            .map_err(|e| {
                anyhow!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW({sddl}): {e}"
                )
            })?;
            if sz == 0 {
                sz = GetSecurityDescriptorLength(psd);
            }
        }
        Ok(Self { ptr: psd, len: sz })
    }
    fn byte_blob(&self) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB {
            size: self.len,
            data: self.ptr.0 as *mut u8,
        }
    }
}

impl Drop for OwnedSd {
    fn drop(&mut self) {
        if !self.ptr.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.ptr.0)));
            }
        }
    }
}

/// WFP engine handle; closed on drop.
struct EngineHandle(HANDLE);

impl EngineHandle {
    fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        // RPC_C_AUTHN_DEFAULT
        let rc = unsafe {
            FwpmEngineOpen0(PCWSTR::null(), 0xFFFF_FFFF, None, None, &mut h)
        };
        if rc != 0 {
            return Err(anyhow!("FwpmEngineOpen0 failed: 0x{rc:08x}"));
        }
        Ok(Self(h))
    }
    fn h(&self) -> HANDLE {
        self.0
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.0);
            }
        }
    }
}

// ────────────────────── condition builders ──────────────────────

fn fwp_uint64(slot: &mut u64) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT64,
        Anonymous: FWP_VALUE0_0 {
            uint64: slot as *mut u64,
        },
    }
}

fn cond_sd(field_key: GUID, blob: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                sd: blob as *mut _,
            },
        },
    }
}

fn cond_v4_subnet(
    field_key: GUID,
    am: &mut FWP_V4_ADDR_AND_MASK,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: am as *mut _,
            },
        },
    }
}

fn cond_v6_addr(
    field_key: GUID,
    addr: &mut FWP_BYTE_ARRAY16,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_ARRAY16_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteArray16: addr as *mut _,
            },
        },
    }
}

fn fwp_uint16(v: u16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_VALUE0_0 { uint16: v },
    }
}

fn cond_port_range(
    field_key: GUID,
    range: &mut FWP_RANGE0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field_key,
        matchType: FWP_MATCH_RANGE,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_RANGE_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                rangeValue: range as *mut _,
            },
        },
    }
}

// ────────────────────── filter tagging ──────────────────────

/// JSON payload stored in each filter's `providerData` so we can
/// identify our own filters during enumerate/uninstall without fixed
/// filter GUIDs. The optional `port_range` mirrors the
/// `IP_REMOTE_PORT` range condition on `permit-loopback` filters so
/// `wfp status` can report it without unsafe condition-walking.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct FilterTag {
    /// Discriminator: `"srt-win"`. Anything else means the filter
    /// belongs to some other tool that happens to share our sublayer.
    pub tool: String,
    /// One of `permit-nonmember`, `permit-group`, `permit-loopback`,
    /// `block`.
    pub kind: String,
    /// `[low, high]` for `permit-loopback`; `None` otherwise (and on
    /// pre-port-range installs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<[u16; 2]>,
}

impl FilterTag {
    fn new(kind: &str) -> Self {
        Self {
            tool: "srt-win".into(),
            kind: kind.into(),
            port_range: None,
        }
    }
    fn loopback(range: (u16, u16)) -> Self {
        Self {
            tool: "srt-win".into(),
            kind: "permit-loopback".into(),
            port_range: Some([range.0, range.1]),
        }
    }
    fn to_blob_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("FilterTag is always serialisable")
    }
}

// ────────────────────── local group management ──────────────────────

/// Create the local group if it doesn't exist and add `user_sid` to
/// it. Idempotent.
pub fn ensure_group(name: &str, user_sid: &str) -> Result<()> {
    unsafe {
        let mut name_w = wstr(name);
        let mut comment_w = wstr(GROUP_COMMENT);
        let info = LOCALGROUP_INFO_1 {
            lgrpi1_name: PWSTR(name_w.as_mut_ptr()),
            lgrpi1_comment: PWSTR(comment_w.as_mut_ptr()),
        };
        let rc = NetLocalGroupAdd(
            PCWSTR::null(),
            1,
            &info as *const _ as *const u8,
            None,
        );
        // SAM returns ERROR_ALIAS_EXISTS (1379) for an existing local
        // group; some paths return NERR_GroupExists (2223). Either is
        // fine for idempotency.
        const ERROR_ALIAS_EXISTS: u32 = 1379;
        if rc != 0 && rc != NERR_GroupExists && rc != ERROR_ALIAS_EXISTS {
            return Err(anyhow!("NetLocalGroupAdd({name}): {rc}"));
        }
    }
    let psid = sid::LocalPsid::from_string(user_sid)?;
    unsafe {
        let name_w = wstr(name);
        let info = LOCALGROUP_MEMBERS_INFO_0 {
            lgrmi0_sid: psid.as_psid(),
        };
        let rc = NetLocalGroupAddMembers(
            PCWSTR::null(),
            pcwstr(&name_w),
            0,
            &info as *const _ as *const u8,
            1,
        );
        if rc != 0 && rc != ERROR_MEMBER_IN_ALIAS.0 {
            return Err(anyhow!(
                "NetLocalGroupAddMembers({name}, {user_sid}): {rc}"
            ));
        }
    }
    Ok(())
}

/// Delete the local group. Idempotent on `NERR_GroupNotFound`.
pub fn delete_group(name: &str) -> Result<()> {
    unsafe {
        let name_w = wstr(name);
        let rc = NetLocalGroupDel(PCWSTR::null(), pcwstr(&name_w));
        // 2220 (NERR_GroupNotFound) and 1376 (ERROR_NO_SUCH_ALIAS) both
        // mean "already gone" depending on Windows version.
        const ERROR_NO_SUCH_ALIAS: u32 = 1376;
        if rc != 0 && rc != NERR_GroupNotFound && rc != ERROR_NO_SUCH_ALIAS {
            return Err(anyhow!("NetLocalGroupDel({name}): {rc}"));
        }
    }
    Ok(())
}

// ────────────────────── filter enumeration ──────────────────────

const ALE_LAYERS: [(GUID, &str); 2] = [
    (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "ale_auth_connect_v4"),
    (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "ale_auth_connect_v6"),
];

/// Walk every filter at the two ALE connect layers under
/// `sublayer` that carries a parseable `srt-win` providerData tag,
/// invoking `f(layer_name, filterKey, &tag)` for each. Owns the
/// enum-handle and per-batch `FwpmFreeMemory0` lifecycle so callers
/// don't duplicate the unsafe FFI walk.
///
/// Errors are propagated (with the enum handle destroyed first) —
/// don't swallow them: inside `install_filters`' txn, a missed enum
/// error would skip stale-filter cleanup and the fresh set would be
/// added on top, growing the filter count every install.
fn for_each_tagged_filter(
    engine: &EngineHandle,
    sublayer: &GUID,
    mut f: impl FnMut(&'static str, GUID, &FilterTag),
) -> Result<()> {
    for (layer, layer_name) in ALE_LAYERS {
        let mut tmpl = FWPM_FILTER_ENUM_TEMPLATE0::default();
        tmpl.layerKey = layer;
        tmpl.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        tmpl.actionMask = 0xFFFF_FFFF;
        let mut h = HANDLE::default();
        let rc = unsafe {
            FwpmFilterCreateEnumHandle0(engine.h(), Some(&tmpl), &mut h)
        };
        if rc != 0 {
            return Err(anyhow!(
                "FwpmFilterCreateEnumHandle0({layer_name}): 0x{rc:08x}"
            ));
        }
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut n: u32 = 0;
            let rc = unsafe {
                FwpmFilterEnum0(engine.h(), h, 256, &mut entries, &mut n)
            };
            if rc != 0 {
                unsafe {
                    let _ = FwpmFilterDestroyEnumHandle0(engine.h(), h);
                }
                return Err(anyhow!(
                    "FwpmFilterEnum0({layer_name}): 0x{rc:08x}"
                ));
            }
            if n == 0 {
                if !entries.is_null() {
                    unsafe {
                        FwpmFreeMemory0(&mut (entries as *mut c_void));
                    }
                }
                break;
            }
            let slice =
                unsafe { std::slice::from_raw_parts(entries, n as usize) };
            for &fp in slice {
                if fp.is_null() {
                    continue;
                }
                let flt = unsafe { &*fp };
                if &flt.subLayerKey != sublayer {
                    continue;
                }
                if flt.providerData.size == 0
                    || flt.providerData.data.is_null()
                {
                    continue;
                }
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        flt.providerData.data,
                        flt.providerData.size as usize,
                    )
                };
                if let Ok(tag) = serde_json::from_slice::<FilterTag>(bytes)
                    && tag.tool == "srt-win"
                {
                    // `tag` is owned (parsed from bytes); the
                    // `flt`/`bytes` borrows are released before
                    // FwpmFreeMemory0 below, so no FFI lifetime
                    // hazard for the closure.
                    f(layer_name, flt.filterKey, &tag);
                }
            }
            unsafe {
                FwpmFreeMemory0(&mut (entries as *mut c_void));
            }
            if (n as usize) < 256 {
                break;
            }
        }
        unsafe {
            let _ = FwpmFilterDestroyEnumHandle0(engine.h(), h);
        }
    }
    Ok(())
}

/// Delete every srt-win-tagged filter under `sublayer`. Returns the
/// number deleted. Does not delete the sublayer itself.
fn delete_tagged_filters(
    engine: &EngineHandle,
    sublayer: &GUID,
) -> Result<usize> {
    // Collect across both layers, then delete. Deletion is by global
    // filterKey GUID inside one txn, so per-layer ordering is not
    // load-bearing.
    let mut to_delete: Vec<GUID> = Vec::new();
    for_each_tagged_filter(engine, sublayer, |_, key, _| {
        to_delete.push(key);
    })?;
    let mut deleted = 0usize;
    for key in to_delete {
        let rc = unsafe { FwpmFilterDeleteByKey0(engine.h(), &key) };
        if rc == 0 {
            deleted += 1;
        } else if rc != FWP_E_FILTER_NOT_FOUND {
            return Err(anyhow!(
                "FwpmFilterDeleteByKey0({key:?}): 0x{rc:08x}"
            ));
        }
    }
    Ok(deleted)
}

// ────────────────────── install / uninstall ──────────────────────

#[allow(clippy::too_many_arguments)]
fn add_filter(
    engine: HANDLE,
    sublayer: &GUID,
    layer: GUID,
    name: &str,
    weight: u64,
    action: FWP_ACTION_TYPE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
    tag_bytes: &mut [u8],
) -> Result<()> {
    let mut name_w = wstr(name);
    let mut desc_w = wstr("sandbox-runtime WFP filter");
    let mut weight_slot = weight;
    let mut filter = FWPM_FILTER0::default();
    // filterKey left zeroed → WFP assigns a fresh GUID. We identify
    // our filters via providerData, not by fixed key.
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_w.as_mut_ptr()),
        description: PWSTR(desc_w.as_mut_ptr()),
    };
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = layer;
    filter.subLayerKey = *sublayer;
    filter.weight = fwp_uint64(&mut weight_slot);
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = if conditions.is_empty() {
        std::ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    filter.action = FWPM_ACTION0 {
        r#type: action,
        Anonymous: FWPM_ACTION0_0 {
            filterType: GUID::zeroed(),
        },
    };
    filter.providerData = FWP_BYTE_BLOB {
        size: tag_bytes.len() as u32,
        data: tag_bytes.as_mut_ptr(),
    };
    let rc = unsafe { FwpmFilterAdd0(engine, &filter, None, None) };
    if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
        return Err(anyhow!("FwpmFilterAdd0({name}): 0x{rc:08x}"));
    }
    Ok(())
}

// SDDL builders for the three ALE_USER_ID security descriptors.
//
// All carry `O:LS G:LS` (owner + primary group = LocalService).
// WFP's kernel-side ALE_USER_ID match doesn't require the primary
// group to be set, but user-mode `AccessCheck` — which
// `tests/sd_access_check_matrix.rs` uses to prove these SDs do
// what we claim — returns ERROR_INVALID_SECURITY_DESCR for an SD
// with no `G:`. The group's value is irrelevant to DACL
// evaluation; LS is just a stable, always-present principal.

/// SDDL for filter 0 — DENY `<group_sid>` then ALLOW Everyone.
/// `AccessCheck` against this SD grants iff the token does **not**
/// carry the group at all (deny-only counts as carrying it). DENY
/// before ALLOW is the canonical ACE order.
pub fn sddl_nonmember(group_sid: &str) -> String {
    format!("O:LSG:LSD:(D;;CC;;;{group_sid})(A;;CC;;;WD)")
}

/// SDDL for filter 1 — ALLOW `<group_sid>`. Grants iff the group is
/// **enabled** in the token; deny-only SIDs are ignored by ALLOW
/// ACEs.
pub fn sddl_group(group_sid: &str) -> String {
    format!("O:LSG:LSD:(A;;CC;;;{group_sid})")
}

/// SDDL for filter 3 — ALLOW Everyone. Grants for every token.
pub const SDDL_EVERYONE: &str = "O:LSG:LSD:(A;;CC;;;WD)";

/// Install (or refresh) the eight machine-wide filters under
/// `sublayer`, keyed only on `group_sid`. Filter 2's loopback
/// permit is restricted to `port_range` (inclusive). Idempotent:
/// any existing srt-win-tagged filters are deleted first, then a
/// fresh set is added, all inside one WFP transaction.
pub fn install_filters(
    sublayer: &GUID,
    group_sid: &str,
    port_range: (u16, u16),
) -> Result<()> {
    debug_assert!(port_range.0 <= port_range.1);
    let sd_nonmember = OwnedSd::from_sddl(&sddl_nonmember(group_sid))
        .context("build non-member SD")?;
    let sd_group = OwnedSd::from_sddl(&sddl_group(group_sid))
        .context("build group SD")?;
    let sd_everyone =
        OwnedSd::from_sddl(SDDL_EVERYONE).context("build Everyone SD")?;

    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.h(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0: 0x{rc:08x}"));
    }

    let result: Result<()> = (|| {
        // Sublayer (idempotent). Display name identifies the owning
        // tool, not the group.
        let mut sl_name = wstr("srt-win");
        let mut sl_desc =
            wstr("sandbox-runtime WFP sublayer (deny-only-group fence)");
        let sl = FWPM_SUBLAYER0 {
            subLayerKey: *sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(sl_name.as_mut_ptr()),
                description: PWSTR(sl_desc.as_mut_ptr()),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: std::ptr::null_mut(),
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight: 0x8000,
        };
        let rc = unsafe { FwpmSubLayerAdd0(engine.h(), &sl, None) };
        if rc != 0 && rc != FWP_E_ALREADY_EXISTS {
            return Err(anyhow!("FwpmSubLayerAdd0: 0x{rc:08x}"));
        }

        // Idempotency: drop any stale filter set before re-adding.
        // (Inside the transaction so a crash leaves the previous
        // state intact.)
        let _ = delete_tagged_filters(&engine, sublayer)?;

        // Weights — kept below 2^60 so we stay in WFP's "manual
        // weight" class (top 4 bits are auto-classifier).
        const W_NONMEMBER: u64 = 0x0F00_0000_0000_0000;
        const W_GROUP: u64 = 0x0E00_0000_0000_0000;
        const W_LOOPBACK: u64 = 0x0D00_0000_0000_0000;
        const W_BLOCK: u64 = 0x0100_0000_0000_0000;

        let mut sd_nonmember_blob = sd_nonmember.byte_blob();
        let mut sd_group_blob = sd_group.byte_blob();
        let mut sd_everyone_blob = sd_everyone.byte_blob();

        // 127.0.0.0/8
        let mut v4_loop = FWP_V4_ADDR_AND_MASK {
            addr: 0x7F00_0000,
            mask: 0xFF00_0000,
        };
        // ::1
        let mut v6_loop = FWP_BYTE_ARRAY16 {
            byteArray16: [0; 16],
        };
        v6_loop.byteArray16[15] = 1;
        // remote port ∈ [low, high]
        let mut port_range_slot = FWP_RANGE0 {
            valueLow: fwp_uint16(port_range.0),
            valueHigh: fwp_uint16(port_range.1),
        };

        let mut tag_nm = FilterTag::new("permit-nonmember").to_blob_bytes();
        let mut tag_gp = FilterTag::new("permit-group").to_blob_bytes();
        let mut tag_lb = FilterTag::loopback(port_range).to_blob_bytes();
        let mut tag_bk = FilterTag::new("block").to_blob_bytes();

        for (layer, label) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "v4"),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "v6"),
        ] {
            // 0 — PERMIT non-member.
            let mut c0 = [cond_sd(
                FWPM_CONDITION_ALE_USER_ID,
                &mut sd_nonmember_blob,
            )];
            add_filter(
                engine.h(),
                sublayer,
                layer,
                &format!("srt-win-{label}-permit-nonmember"),
                W_NONMEMBER,
                FWP_ACTION_PERMIT,
                &mut c0,
                &mut tag_nm,
            )?;

            // 1 — PERMIT group-enabled.
            let mut c1 =
                [cond_sd(FWPM_CONDITION_ALE_USER_ID, &mut sd_group_blob)];
            add_filter(
                engine.h(),
                sublayer,
                layer,
                &format!("srt-win-{label}-permit-group"),
                W_GROUP,
                FWP_ACTION_PERMIT,
                &mut c1,
                &mut tag_gp,
            )?;

            // 2 — PERMIT loopback ∩ port-range (no user condition).
            // Two conditions on different fieldKeys → ANDed by WFP.
            let addr_cond = if label == "v4" {
                cond_v4_subnet(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    &mut v4_loop,
                )
            } else {
                cond_v6_addr(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut v6_loop)
            };
            let mut c2 = [
                addr_cond,
                cond_port_range(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    &mut port_range_slot,
                ),
            ];
            add_filter(
                engine.h(),
                sublayer,
                layer,
                &format!("srt-win-{label}-permit-loopback"),
                W_LOOPBACK,
                FWP_ACTION_PERMIT,
                &mut c2,
                &mut tag_lb,
            )?;

            // 3 — BLOCK Everyone.
            let mut c3 = [cond_sd(
                FWPM_CONDITION_ALE_USER_ID,
                &mut sd_everyone_blob,
            )];
            add_filter(
                engine.h(),
                sublayer,
                layer,
                &format!("srt-win-{label}-block"),
                W_BLOCK,
                FWP_ACTION_BLOCK,
                &mut c3,
                &mut tag_bk,
            )?;
        }

        Ok(())
    })();

    if let Err(e) = result {
        unsafe {
            let _ = FwpmTransactionAbort0(engine.h());
        }
        return Err(e);
    }
    let rc = unsafe { FwpmTransactionCommit0(engine.h()) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionCommit0: 0x{rc:08x}"));
    }
    Ok(())
}

/// Remove every srt-win-tagged filter under `sublayer`, then attempt
/// to delete the sublayer itself (best-effort; `FWP_E_IN_USE` means
/// foreign filters are still under it).
pub fn uninstall_filters(sublayer: &GUID) -> Result<usize> {
    let engine = EngineHandle::open()?;
    let rc = unsafe { FwpmTransactionBegin0(engine.h(), 0) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionBegin0: 0x{rc:08x}"));
    }
    let n = match delete_tagged_filters(&engine, sublayer) {
        Ok(n) => n,
        Err(e) => {
            unsafe {
                let _ = FwpmTransactionAbort0(engine.h());
            }
            return Err(e);
        }
    };
    let rc = unsafe { FwpmSubLayerDeleteByKey0(engine.h(), sublayer) };
    if rc != 0
        && rc != FWP_E_SUBLAYER_NOT_FOUND
        && rc != FWP_E_FILTER_NOT_FOUND
        && rc != FWP_E_IN_USE
    {
        unsafe {
            let _ = FwpmTransactionAbort0(engine.h());
        }
        return Err(anyhow!("FwpmSubLayerDeleteByKey0: 0x{rc:08x}"));
    }
    let rc = unsafe { FwpmTransactionCommit0(engine.h()) };
    if rc != 0 {
        return Err(anyhow!("FwpmTransactionCommit0: 0x{rc:08x}"));
    }
    Ok(n)
}

/// Status of the WFP fence under `sublayer`. `installed` iff at
/// least one `permit-group` and one `block` srt-win filter exist.
/// (We don't insist on the exact count so enterprise tooling that
/// adds extras under the same sublayer doesn't break detection.)
/// `port_range` is read from the first `permit-loopback` tag;
/// `None` when no loopback filter is present or it predates the
/// port-range design.
#[derive(Debug, Serialize)]
pub struct WfpStatus {
    pub state: &'static str,
    pub filters: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_range: Option<[u16; 2]>,
}

pub fn filter_status(sublayer: &GUID) -> Result<WfpStatus> {
    let engine = EngineHandle::open()?;
    let mut filters = 0usize;
    let mut have_permit_group = false;
    let mut have_block = false;
    let mut port_range: Option<[u16; 2]> = None;
    for_each_tagged_filter(&engine, sublayer, |_, _, tag| {
        filters += 1;
        match tag.kind.as_str() {
            "permit-group" => have_permit_group = true,
            "block" => have_block = true,
            "permit-loopback" if port_range.is_none() => {
                port_range = tag.port_range;
            }
            _ => {}
        }
    })?;
    let state = if have_permit_group && have_block {
        "installed"
    } else {
        "absent"
    };
    Ok(WfpStatus { state, filters, port_range })
}

/// Parse a `--proxy-port-range LOW-HIGH` argument. Both ends are
/// inclusive. Validates `low <= high` and width `<=
/// MAX_PROXY_PORT_RANGE_WIDTH`.
pub fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    let (lo_s, hi_s) = s
        .split_once('-')
        .ok_or_else(|| anyhow!("expected LOW-HIGH (e.g. 60080-60089)"))?;
    let lo: u16 = lo_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid low port '{lo_s}'"))?;
    let hi: u16 = hi_s
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid high port '{hi_s}'"))?;
    if lo == 0 {
        // Port 0 is "any" at bind time and never appears as a
        // remote port, so it's a dead slot in the range.
        return Err(anyhow!("low port must be >= 1"));
    }
    if lo > hi {
        return Err(anyhow!("low ({lo}) > high ({hi})"));
    }
    if hi - lo > MAX_PROXY_PORT_RANGE_WIDTH {
        return Err(anyhow!(
            "range too wide ({} ports); max width {}",
            hi - lo + 1,
            MAX_PROXY_PORT_RANGE_WIDTH + 1
        ));
    }
    Ok((lo, hi))
}

/// Parse a `--sublayer-guid` argument. Accepts braced or unbraced
/// canonical form. `GUID::try_from` only takes the unbraced form and
/// returns an unhelpful error on failure, so strip braces and
/// pre-validate the shape for a friendlier message.
pub fn parse_guid(s: &str) -> Result<GUID> {
    let t = s.trim().trim_start_matches('{').trim_end_matches('}');
    // 8-4-4-4-12 hex with hyphens, exactly 36 chars.
    let ok = t.len() == 36
        && t.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if !ok {
        return Err(anyhow!(
            "invalid GUID '{s}': expected xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        ));
    }
    GUID::try_from(t).map_err(|e| anyhow!("invalid GUID '{s}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three SDDL templates used by `install_filters` must
    /// parse for a representative SID. Catches template typos
    /// without needing a live WFP engine.
    #[test]
    fn sddl_templates_parse() {
        let g = "S-1-5-32-545";
        for sddl in [sddl_nonmember(g), sddl_group(g), SDDL_EVERYONE.into()] {
            let sd = OwnedSd::from_sddl(&sddl).expect("sddl");
            assert!(!sd.ptr.0.is_null());
            assert!(sd.len > 0);
        }
    }

    #[test]
    fn sddl_rejects_garbage() {
        assert!(OwnedSd::from_sddl("O:LSG:LSD:(A;;CC;;;NOT-A-SID)").is_err());
    }

    #[test]
    fn filter_tag_round_trip() {
        let t = FilterTag::new("block");
        let bytes = t.to_blob_bytes();
        let back: FilterTag = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(t, back);
        // port_range omitted from JSON when None (back-compat with
        // pre-range tags).
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("port_range"));

        let lb = FilterTag::loopback((60080, 60089));
        let lb_bytes = lb.to_blob_bytes();
        let lb_back: FilterTag = serde_json::from_slice(&lb_bytes).unwrap();
        assert_eq!(lb, lb_back);
        assert_eq!(lb_back.port_range, Some([60080, 60089]));
    }

    #[test]
    fn filter_tag_parses_legacy() {
        // A pre-port-range tag (no port_range key) must still parse.
        let legacy = br#"{"tool":"srt-win","kind":"permit-loopback"}"#;
        let t: FilterTag = serde_json::from_slice(legacy).unwrap();
        assert_eq!(t.kind, "permit-loopback");
        assert_eq!(t.port_range, None);
    }

    #[test]
    fn parse_port_range_ok() {
        assert_eq!(parse_port_range("60080-60089").unwrap(), (60080, 60089));
        assert_eq!(parse_port_range(" 1 - 1 ").unwrap(), (1, 1));
        assert_eq!(
            parse_port_range("1-65").unwrap(),
            (1, 1 + MAX_PROXY_PORT_RANGE_WIDTH)
        );
    }

    #[test]
    fn parse_port_range_rejects() {
        assert!(parse_port_range("60089-60080").is_err()); // low>high
        assert!(parse_port_range("1-1000").is_err()); // too wide
        assert!(parse_port_range("60080").is_err()); // no dash
        assert!(parse_port_range("a-b").is_err()); // not u16
        assert!(parse_port_range("0-65536").is_err()); // overflow
        assert!(parse_port_range("0-9").is_err()); // port 0
    }

    #[test]
    fn parse_guid_accepts_both_forms() {
        let g1 =
            parse_guid("2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21").unwrap();
        let g2 =
            parse_guid("{2c5d0ad6-5f3b-4d4e-9b8f-1a3e7c9d0b21}").unwrap();
        assert_eq!(g1, g2);
        assert_eq!(g1, DEFAULT_SUBLAYER_GUID);
    }

    #[test]
    fn parse_guid_rejects_garbage() {
        assert!(parse_guid("not-a-guid").is_err());
    }
}
