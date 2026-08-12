//! Install-time state: the sandbox-user **credential** (DPAPI
//! ciphertext), the **setup marker**, and the optional **MITM CA**
//! (DER), in the store `state_db::state_dir()` resolves.
//!
//! Written by the elevated `srt-win install` step (after
//! [`crate::user::provision`]) and read by the non-elevated broker
//! at `srt-win exec` / `srt-win user status` time.
//!
//! The store is the machine-wide `%ProgramData%\sandbox-runtime`
//! (provisioned by [`provision_machine_store`]). The credential
//! lives in its own [`CRED_FILE`] whose PROTECTED DACL (Users
//! read-only, Administrators write, sandbox DENY) is stricter than
//! the Users-writable store around it; marker + CA rows stay in
//! `state.db`. The DPAPI blob is stored raw — no base64 layer.

use anyhow::{Context, Result, anyhow};

use crate::state_db::{self, SetupInfo};
use crate::{dpapi, logon, runner, user};

/// Bumped on schema-incompatible changes to the `sandbox_user`
/// row, or when `install` gains a step existing installs must pick
/// up (v2: ambient write-deny stamps — `ambient.rs`). The broker
/// compares this to the on-disk marker and refuses with a "re-run
/// `srt-win install`" message on mismatch; `install` treats a stale
/// marker as a partial install and completes the missing steps.
pub const SETUP_VERSION: u32 = 2;

/// The DPAPI credential blob's filename inside the MACHINE store.
/// A standalone file (not a `sandbox_user` column) because its DACL
/// is stricter than the store's: the DB must stay writable by every
/// real user's broker (ACE bookkeeping), while the credential is
/// written only by the elevated install.
pub const CRED_FILE: &str = "cred.dat";

/// Create (or repair) the machine-wide state store
/// `%ProgramData%\sandbox-runtime` — elevated install only.
///
/// `%ProgramData%`'s default DACL lets standard users pre-create
/// directories, so a squatter could plant this path with a DACL of
/// their choosing before the first install. Creation is therefore
/// never trusted: every elevated install (re)takes ownership to
/// Administrators and rewrites the PROTECTED inheritable DACL,
/// healing any pre-existing ACLs. The DACL is deliberately
/// multi-user:
/// - SYSTEM / Administrators: full control (install, rotation)
/// - BUILTIN\Users: modify — every real user's broker reads AND
///   writes `state.db` (holder refcounts, ACE bookkeeping) and the
///   `ca\` subdir (unelevated generate-if-absent self-heal)
/// - sandbox group: explicit DENY — the credential is machine-scope
///   DPAPI (readable ⇒ decryptable) and the CA key must not be
///   readable from inside the sandbox
///
/// Accepted trade-off (decided): any REAL local user can read the
/// credential or replace the CA. The sandbox account is
/// network-confined by SID-keyed WFP filters regardless of who
/// spawns it and has no inherent rights on other users' files, and
/// concurrently-interactive multi-user machines are rare.
pub fn provision_machine_store(sandbox_group_sid: &str) -> Result<std::path::PathBuf> {
    let dir = state_db::state_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create machine state dir {}", dir.display()))?;
    let dir_str = dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("machine state dir is not UTF-8"))?;
    // Ownership first: a squatter's creator-owner keeps WRITE_DAC
    // through ownership no matter what DACL we write.
    if !crate::util::enable_privilege("SeTakeOwnershipPrivilege")? {
        anyhow::bail!("SeTakeOwnershipPrivilege not held — machine store requires elevation");
    }
    crate::util::enable_privilege("SeRestorePrivilege")?;
    // No-follow, by-handle: a squatter can also plant the path as a
    // junction targeting a victim tree, turning a by-name take-own +
    // re-ACL into an elevated arbitrary-directory primitive. A
    // planted reparse point is removed (the junction itself, never
    // its target) and the directory recreated; the handle the
    // security writes use is the validated object itself.
    let h = match crate::acl::open_for_security_no_follow(dir_str) {
        Ok(h) => h,
        Err(e) if format!("{e:#}").contains("reparse point") => {
            std::fs::remove_dir(&dir)
                .with_context(|| format!("remove planted reparse point {}", dir.display()))?;
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("recreate machine state dir {}", dir.display()))?;
            crate::acl::open_for_security_no_follow(dir_str)?
        }
        Err(e) => return Err(e),
    };
    crate::acl::set_handle_owner_admins(&h, "machine state dir")
        .context("take ownership of machine state dir")?;
    // 0x1301bf = FILE_GENERIC_READ|WRITE|EXECUTE + DELETE ("modify"
    // minus FILE_DELETE_CHILD): brokers create/replace state.db-wal
    // and ca\ files but cannot delete other users' files via
    // parent-FDC.
    let sddl = format!(
        "D:P(D;OICI;FA;;;{sandbox_group_sid})\
         (A;OICI;FA;;;SY)\
         (A;OICI;FA;;;BA)\
         (A;OICI;0x1301bf;;;BU)"
    );
    crate::acl::set_handle_dacl_from_sddl(&h, &sddl, "machine state dir")?;
    drop(h);
    // A pre-existing state.db keeps its CREATOR OWNER's implicit
    // WRITE_DAC no matter what DACL the directory propagates — a
    // squatter who created it first (any unelevated srt-win command,
    // or a direct create) could later re-ACL it to let the sandbox
    // child tamper with the refcount. Heal ownership on every
    // elevated install; the inherited DACL then governs.
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let p = dir.join(f);
        if !p.exists() {
            continue;
        }
        if let Some(ps) = p.to_str()
            && let Ok(fh) = crate::acl::open_for_security_no_follow(ps)
            && let Err(e) = crate::acl::set_handle_owner_admins(&fh, f)
        {
            eprintln!("srt-win: warning: heal ownership of {f}: {e:#}");
        }
    }
    Ok(dir)
}

/// DPAPI-encrypt `u.password` into [`CRED_FILE`] — with its own
/// stricter PROTECTED DACL (Users read-only, Administrators write,
/// sandbox DENY): the file DACL is the only gate on the credential,
/// since machine-scope DPAPI lets any local account decrypt a
/// readable blob — and record the setup marker in `state.db`.
pub fn write_setup(u: &user::ProvisionedUser) -> Result<()> {
    let dir = state_db::state_dir()?;
    let blob = dpapi::protect_machine(u.password.as_bytes())?;
    let cred_path = dir.join(CRED_FILE);
    // The parent grants Users create, so a squatter may have
    // pre-created this path — and a file's CREATOR OWNER keeps
    // WRITE_DAC through ownership no matter what DACL we write.
    // Delete-and-recreate (best-effort), then take ownership
    // explicitly (the install enabled SeTakeOwnership/SeRestore in
    // provision_machine_store) so the protective DACL below is
    // actually final.
    let _ = std::fs::remove_file(&cred_path);
    std::fs::write(&cred_path, &blob).with_context(|| format!("write {}", cred_path.display()))?;
    let cred_str = cred_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("cred path is not UTF-8"))?;
    let ch = crate::acl::open_for_security_no_follow(cred_str)?;
    crate::acl::set_handle_owner_admins(&ch, "machine cred file")
        .context("take ownership of credential file")?;
    let sddl = format!(
        "D:P(D;;FA;;;{})\
         (A;;FA;;;SY)\
         (A;;FA;;;BA)\
         (A;;FR;;;BU)",
        u.group_sid
    );
    crate::acl::set_handle_dacl_from_sddl(&ch, &sddl, "machine cred file")?;
    let conn = state_db::open_db().context("open state DB for setup write")?;
    state_db::write_setup_info(
        &conn,
        &SetupInfo {
            marker_version: SETUP_VERSION,
            sandbox_user: u.username.clone(),
            sandbox_user_sid: u.sid.clone(),
            sandbox_group_sid: u.group_sid.clone(),
            created_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        },
    )
}

/// Whether the install-time ambient write-deny step is complete on
/// this machine: every CURRENT target
/// ([`crate::ambient::ambient_deny_targets`]) is both recorded in
/// the state DB and carrying its on-disk deny ACE
/// ([`crate::acl::sandbox_deny_present`]). Both halves matter: an
/// install that died mid-list falls through the install early-out
/// and finishes the remainder (missing rows), and "re-run `srt-win
/// install`" really is the repair for drift (an admin `icacls
/// /reset`, or a stamp that failed best-effort). Targets that no
/// longer canonicalize (dir vanished since the target list filtered
/// on existence) are ignored; any error reads as incomplete, which
/// at the call site just means the (idempotent) install steps run.
pub fn ambient_complete(
    conn: &rusqlite::Connection,
    sandbox_sid: &str,
    raw_targets: &[String],
) -> bool {
    raw_targets.iter().all(|raw| {
        let Ok((canon, _)) = crate::path_id::canonicalize_path(raw) else {
            return true;
        };
        state_db::ambient_deny_recorded(conn, &canon).unwrap_or(false)
            && crate::acl::sandbox_deny_present(&canon, sandbox_sid).unwrap_or(false)
    })
}

/// Read the install-time setup record (if any) without taking the
/// init mutex. `Ok(None)` when no install has run (state DB
/// absent or no marker row).
pub fn read_setup() -> Result<Option<SetupInfo>> {
    let info = match state_db::open_db_ro()? {
        Some(c) => state_db::read_setup_info(&c)?,
        None => None,
    };
    // The row lives in the Users-writable shared DB — its identity
    // fields are UNTRUSTED input to everything downstream (the
    // broker passes the SID to `acl grant`; elevated flows act on
    // it). Cross-validate against SAM, which only admins can edit:
    // the recorded name must resolve to the recorded SID, and the
    // recorded group must be the real sandbox group. A row that
    // fails reads as "not provisioned" (with a loud warning), so a
    // tampered row can misdirect nothing — the repair is re-running
    // the elevated install, which rewrites the row.
    let Some(info) = info else { return Ok(None) };
    match crate::sid::lookup_account_sid(&info.sandbox_user) {
        Ok(sid) if sid == info.sandbox_user_sid => {}
        Ok(sid) => {
            eprintln!(
                "srt-win: WARNING: state-DB identity row is stale or \
                 tampered: '{}' resolves to {sid}, row records {} — \
                 treating as not provisioned; re-run `srt-win install`",
                info.sandbox_user, info.sandbox_user_sid,
            );
            return Ok(None);
        }
        Err(e) => {
            eprintln!(
                "srt-win: WARNING: cannot resolve recorded sandbox \
                 user '{}' ({e:#}) — treating as not provisioned",
                info.sandbox_user,
            );
            return Ok(None);
        }
    }
    match crate::sid::lookup_account_sid(user::SANDBOX_GROUP) {
        Ok(gsid) if gsid == info.sandbox_group_sid => {}
        Ok(gsid) => {
            eprintln!(
                "srt-win: WARNING: state-DB group row is stale or \
                 tampered: '{}' resolves to {gsid}, row records {} — \
                 treating as not provisioned; re-run `srt-win install`",
                user::SANDBOX_GROUP,
                info.sandbox_group_sid,
            );
            return Ok(None);
        }
        Err(e) => {
            eprintln!(
                "srt-win: WARNING: cannot resolve '{}' ({e:#}) — \
                 treating as not provisioned",
                user::SANDBOX_GROUP,
            );
            return Ok(None);
        }
    }
    // The load-bearing check: name↔SID consistency alone would pass
    // for ANY existing account (an attacker's own row about
    // themselves is self-consistent). Sandbox-group MEMBERSHIP is
    // what only the elevated install grants — an account outside it
    // is not the sandbox user, whatever the row says.
    match crate::sam::is_member_of(&info.sandbox_group_sid, &info.sandbox_user_sid) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "srt-win: WARNING: state-DB row names account '{}' \
                 which is NOT a member of {} — treating as not \
                 provisioned; re-run `srt-win install`",
                info.sandbox_user,
                user::SANDBOX_GROUP,
            );
            return Ok(None);
        }
        Err(e) => {
            eprintln!(
                "srt-win: WARNING: sandbox-group membership check \
                 failed ({e:#}) — treating as not provisioned",
            );
            return Ok(None);
        }
    }
    Ok(Some(info))
}

/// Read the recorded MITM CA (DER), if `srt-win user trust-ca`
/// ever ran. `Ok(None)` when no install has run or no CA
/// is recorded.
pub fn read_ca_cert() -> Result<Option<crate::cert_store::CertDer>> {
    match state_db::open_db_ro()? {
        Some(c) => state_db::read_ca_cert(&c),
        None => Ok(None),
    }
}

/// Decrypted sandbox-user credential, as the broker needs it for
/// the two-hop launch. Zeroed on drop so the cleartext doesn't
/// linger past the `CreateProcessWithLogonW` call.
pub struct SandboxCred {
    pub user: String,
    pub pw: String,
}

impl Drop for SandboxCred {
    fn drop(&mut self) {
        // SAFETY: writing zeros into the String's bytes keeps it
        // valid UTF-8.
        for b in unsafe { self.pw.as_mut_vec() } {
            *b = 0;
        }
    }
}

/// Decrypt and return the sandbox user's credential. Fails if the
/// caller cannot read [`CRED_FILE`] — by design, the sandbox user
/// is DENY'd on it (and on the store directory) and so cannot call
/// this to learn its own password.
pub fn read_cred() -> Result<SandboxCred> {
    let info = read_setup()?.ok_or_else(|| {
        anyhow!(
            "no sandbox-user setup record in the state store — run \
             `srt-win install`"
        )
    })?;
    if info.marker_version != SETUP_VERSION {
        return Err(anyhow!(
            "setup marker version mismatch (have {}, expected {}); \
             re-run `srt-win install`",
            info.marker_version,
            SETUP_VERSION,
        ));
    }
    let blob = read_cred_blob()?;
    let pw = String::from_utf8(dpapi::unprotect(&blob)?).context("password is not UTF-8")?;
    Ok(SandboxCred {
        user: info.sandbox_user,
        pw,
    })
}

/// The DPAPI blob — only [`CRED_FILE`], never a DB column: the
/// Users-writable `state.db` must not be able to smuggle a
/// substitute credential past the install-ACL'd file. A
/// missing/unreadable file means the install is incomplete (or was
/// tampered with) and the repair is the same re-run either way.
pub(crate) fn read_cred_blob() -> Result<Vec<u8>> {
    let p = state_db::state_dir()?.join(CRED_FILE);
    std::fs::read(&p).with_context(|| {
        format!(
            "read credential file {} — run `srt-win install` \
             (elevated) to (re)provision it",
            p.display()
        )
    })
}

/// Whether [`CRED_FILE`] exists AND decrypts — the `cred_present`
/// half of `srt-win user status`, and the credential term of the
/// install early-out. The DPAPI round-trip matters for the latter:
/// the store directory lets any user create files, so a planted
/// junk `cred.dat` must read as ABSENT — making plain re-install
/// fall through and rewrite it — rather than blocking the repair
/// behind `--force`. Readable by every real user, which is the
/// point of the shared store: a SYSTEM/fleet install must read as
/// present from an ordinary user's session.
pub fn cred_present() -> bool {
    read_cred_blob()
        .and_then(|b| dpapi::unprotect(&b))
        .map(|pw| !pw.is_empty())
        .unwrap_or(false)
}

/// Write `der` into the **sandbox user's** `CurrentUser\Root` via a
/// one-shot `CreateProcessWithLogonW(srt-sandbox, "srt-win runner")`
/// carrying [`runner::RunnerCmd::InstallCa`], and — only on success
/// — record it in the `sandbox_user.ca_cert` column. The state-DB
/// record is what the host's `tlsTerminate` gate keys on, so it must
/// only exist when the registry write actually landed. Called only
/// from `srt-win user trust-ca` (with [`read_cred`]); `srt-win
/// install` never touches the CA. Persistent until `srt-win
/// uninstall` deletes the profile.
pub fn trust_ca(der: &crate::cert_store::CertDer, cred: &SandboxCred, sb_sid: &str) -> Result<()> {
    let code = logon::spawn_runner(
        &cred.user,
        &cred.pw,
        sb_sid,
        None,
        &runner::RunnerCmd::InstallCa { der: der.clone() },
        false,
    )
    .context("spawn runner for CA install")?;
    if code != 0 {
        return Err(anyhow!(
            "CA install runner exited {code} — the registry write \
             into the sandbox user's hive failed; CA NOT recorded"
        ));
    }
    let conn = state_db::open_db().context("open state DB for CA write")?;
    state_db::set_ca_cert(&conn, der)
}

/// Clear the credential and marker rows. Idempotent — no-op when
/// `state.db` is absent (no install ever ran). Unlike
/// [`write_setup`] this doesn't re-stamp the directory: uninstall
/// deletes rows, it doesn't need to assert the DACL.
pub fn clear_setup() -> Result<()> {
    let dir = state_db::state_dir()?;
    // The credential file goes with the setup rows: uninstall
    // deletes the account, so a surviving blob would be a
    // credential for a nonexistent user at best and a stale one
    // for a recreated user at worst.
    let cred = dir.join(CRED_FILE);
    if let Err(e) = std::fs::remove_file(&cred)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("srt-win: warning: could not remove {}: {e}", cred.display());
    }
    let path = dir.join("state.db");
    if !path.try_exists().unwrap_or(true) {
        return Ok(());
    }
    // Route through `open_db()` so a v5-schema DB is renamed away
    // (the rename-on-mismatch chokepoint) rather than written to
    // by `open_db_at`'s schema-less write path.
    let conn = state_db::open_db().context("open state DB for setup clear")?;
    state_db::clear_setup_info(&conn)
}
