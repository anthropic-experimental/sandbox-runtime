//! Install-time state in the `sandbox_user` table of
//! `%LOCALAPPDATA%\sandbox-runtime\state.db`: the sandbox-user
//! **credential** (DPAPI ciphertext), the **setup marker**, and the
//! optional **MITM CA** (DER).
//!
//! Written by the elevated `srt-win install` step (after
//! [`crate::user::provision`]) and read by the non-elevated broker
//! at `srt-win exec` / `srt-win user status` time.
//!
//! No separate JSON files: [`state_db::open_db`] already creates
//! and DACL-stamps the directory (broker-only `PROTECTED` allow set
//! plus the explicit [`user::SANDBOX_GROUP`] DENY), so `state.db`
//! inherits the same gate the credential needs. The DPAPI blob is
//! stored directly in a BLOB column — no base64 layer.

use anyhow::{Context, Result, anyhow};

use crate::state_db::{self, SetupInfo};
use crate::{dpapi, logon, runner, user};

/// Bumped on schema-incompatible changes to the `sandbox_user`
/// row. The broker compares this to the on-disk marker and
/// refuses with a "re-run `srt-win install`" message on mismatch.
pub const SETUP_VERSION: u32 = 1;

/// DPAPI-encrypt `u.password` and write the credential + setup
/// marker to the `sandbox_user` table. [`state_db::open_db`]
/// creates and stamps the directory (real-user `PROTECTED` allow
/// set plus the explicit [`user::SANDBOX_GROUP`] DENY) — the file
/// DACL is the **only** gate on the credential, since machine-scope
/// DPAPI lets any local account decrypt a readable blob.
pub fn write_setup(u: &user::ProvisionedUser) -> Result<()> {
    let conn = state_db::open_db().context("open state DB for setup write")?;
    state_db::write_setup_info(
        &conn,
        &SetupInfo {
            cred: dpapi::protect_machine(u.password.as_bytes())?,
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

/// Read the install-time setup record (if any) without taking the
/// init mutex. `Ok(None)` when no install has run (state DB
/// absent or no marker row).
pub fn read_setup() -> Result<Option<SetupInfo>> {
    match state_db::open_db_ro()? {
        Some(c) => state_db::read_setup_info(&c),
        None => Ok(None),
    }
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
/// caller cannot read `state.db` — by design, the sandbox user is
/// DENY'd on the directory and so cannot call this to learn its own
/// password.
pub fn read_cred() -> Result<SandboxCred> {
    let info = read_setup()?.ok_or_else(|| {
        anyhow!(
            "no sandbox-user credential in state DB — run \
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
    let pw = String::from_utf8(dpapi::unprotect(&info.cred)?).context("password is not UTF-8")?;
    Ok(SandboxCred {
        user: info.sandbox_user,
        pw,
    })
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
    let path = state_db::state_dir()?.join("state.db");
    if !path.try_exists().unwrap_or(true) {
        return Ok(());
    }
    // Route through `open_db()` so a v5-schema DB is renamed away
    // (the rename-on-mismatch chokepoint) rather than written to
    // by `open_db_at`'s schema-less write path.
    let conn = state_db::open_db().context("open state DB for setup clear")?;
    state_db::clear_setup_info(&conn)
}
