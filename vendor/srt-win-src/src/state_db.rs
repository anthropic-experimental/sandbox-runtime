//! Cross-broker state DB for `srt-win acl` — refcount additive
//! sandbox-user ACEs (grant ALLOW / stamp DENY) so the LAST broker
//! to release a path can drop the ACE.
//!
//! Lives at `%LOCALAPPDATA%\sandbox-runtime\state.db` (rusqlite,
//! WAL). The directory is ACL-stamped real-user-only `(OI)(CI)` on
//! every open so the sandbox child cannot tamper with the refcount.
//!
//! ## Disk-is-truth invariant
//!
//! A row is a refcount edge + `file_id` identity check. It NEVER
//! asserts on-disk state. Every add/drop/crash-recover routes
//! through [`recompose_at`], which reads the live `working_aces`
//! rows for the path and converges the on-disk ACEs for the
//! sandbox SID to exactly that set (walk-and-filter, no PROTECTED
//! rewrite, no SD snapshot). A poisoned row therefore degrades to
//! "sandbox user has an extra ACE the user can manually remove",
//! never to attacker-chosen permissions on the user's own files.
//!
//! ## Locking and crash safety
//!
//! Every `acl stamp|grant|restore|revoke|recover` runs under a
//! single named mutex `Local\sandbox-runtime-acl-init`
//! (real-user-only DACL). The mutex — NOT a DB transaction —
//! serializes whole operations across brokers; `WAIT_ABANDONED`
//! tells us the previous holder died mid-op (crash-recovery
//! already runs unconditionally).
//!
//! There is deliberately NO transaction spanning a caller's whole
//! apply batch. GRANT removal is record-first so a failed filesystem
//! convergence cannot leave an untracked ALLOW. DENY removal first
//! commits the holder transition, then converges the filesystem; a
//! crash therefore leaves the stronger DENY in place, and recovery
//! derives the desired state from the remaining holder edges. Crash
//! recovery uses per-broker and per-path retry units so one poisoned
//! path cannot block unrelated cleanup or the current operation.

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows::Win32::System::Threading::{
    CreateMutexExW, GetCurrentProcess, GetProcessTimes, INFINITE, MUTEX_ALL_ACCESS, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, ReleaseMutex, WaitForSingleObject,
};

use crate::acl::{self, SbAce};
use crate::path_id::{self, FileId};
use crate::util::{pcwstr, wstr};

/// Holder PID — the LONG-LIVED process that owns a set of stamps
/// (the Node host in production), NOT the ephemeral `srt-win acl`
/// CLI process. Newtype to avoid confusing it with arbitrary PIDs
/// at call sites; the SQLite `brokers.pid` column stores the bare
/// `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HolderPid(pub u32);

impl std::str::FromStr for HolderPid {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(HolderPid)
    }
}

/// PID plus the process object's immutable creation FILETIME. The
/// pair binds a caller-observed holder to the same process object at
/// registration/release time and closes the PID-reuse window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HolderIdentity {
    pub pid: HolderPid,
    pub process_create_time: i64,
}

impl HolderIdentity {
    /// Capture the current process identity. Used by the dedicated
    /// `acl hold` process before it emits readiness.
    pub fn current() -> Result<Self> {
        Ok(Self {
            pid: HolderPid(std::process::id()),
            process_create_time: process_create_time(unsafe { GetCurrentProcess() })?,
        })
    }

    /// Observe a live process and bind its PID to its creation time.
    pub fn observe(pid: HolderPid) -> Result<Self> {
        if pid.0 == std::process::id() {
            return Self::current();
        }
        let h = open_live_process(pid.0)?;
        Ok(Self {
            pid,
            process_create_time: process_create_time(h.raw())?,
        })
    }
}

/// `Local\` = per–Terminal-Services-session namespace. Brokers for
/// the SAME user in DIFFERENT TS sessions share the state DB
/// (`%LOCALAPPDATA%`) but NOT this mutex — they would not exclude
/// each other. `Global\` would, but creating it requires
/// `SeCreateGlobalPrivilege`, which an unelevated broker may lack.
/// The cross-session same-user case is rare enough that we accept
/// the limitation for v1; revisit if a real use case appears.
const MUTEX_NAME: &str = r"Local\sandbox-runtime-acl-init";
const SCHEMA_VERSION: i64 = 6;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS brokers (
  pid                 INTEGER PRIMARY KEY,
  process_create_time INTEGER NOT NULL,
  started_at          INTEGER NOT NULL
);
-- Additive explicit ACEs for the sandbox user. kind ∈
-- {'grant','deny','deny_fdc'}: `acl grant` writes ALLOW rows,
-- `acl stamp` writes DENY rows on the target plus a `deny_fdc`
-- row on the parent. Stores no original_sd — restore is a
-- walk-and-filter that drops the SID's ACEs, not a full-SD
-- restore. One row per (path, kind); a path may carry one grant
-- AND one deny (the recompose chokepoint applies both).
-- Refcounted via ace_holders.
CREATE TABLE IF NOT EXISTS working_aces (
  canonical_path TEXT NOT NULL,
  kind           TEXT NOT NULL,
  file_id        BLOB NOT NULL,
  -- The effective mask currently on disk: the MAX across live
  -- holders' want_mask (recomputed on every holder add/drop).
  mask           TEXT NOT NULL,
  PRIMARY KEY (canonical_path, kind)
);
CREATE TABLE IF NOT EXISTS ace_holders (
  canonical_path TEXT    NOT NULL,
  kind           TEXT    NOT NULL,
  pid            INTEGER NOT NULL REFERENCES brokers(pid) ON DELETE CASCADE,
  -- THIS holder's requested mask. The on-disk ACE is the MAX
  -- across live holders; release recomputes it so a holder that
  -- escalated the mask doesn't leave it escalated past its exit.
  want_mask      TEXT    NOT NULL,
  PRIMARY KEY (canonical_path, kind, pid)
);
CREATE INDEX IF NOT EXISTS ace_holders_by_pid ON ace_holders (pid);
-- Install-time setup record: the sandbox user's DPAPI-encrypted
-- credential plus the setup marker. One row per provisioned
-- sandbox user (currently exactly one). Additive table — no
-- schema-version bump.
CREATE TABLE IF NOT EXISTS sandbox_user (
  username        TEXT    PRIMARY KEY,
  user_sid        TEXT    NOT NULL,
  group_sid       TEXT    NOT NULL,
  cred            BLOB    NOT NULL,
  marker_version  INTEGER NOT NULL,
  created_at_unix INTEGER NOT NULL,
  -- DER-encoded MITM CA certificate (`srt-win user trust-ca`).
  -- NULL when no CA was installed. Persisted so `user status` can
  -- surface the thumbprint + PEM to the host's tlsTerminate setup
  -- without it having to re-read the original file.
  ca_cert         BLOB
);
"#;

/// Outcome of a crash-recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub dead_brokers: u32,
    /// `working_aces` rows whose on-disk state was reconciled.
    pub aces_revoked: u32,
    /// Per-broker or per-path cleanup attempts retained for retry.
    pub cleanup_failures: u32,
}

/// Begin a write transaction before reading derived holder state.
/// This closes cross-Terminal-Services-session stale-snapshot races
/// that the session-local named mutex cannot serialize.
fn immediate_transaction<'conn>(
    conn: &'conn Connection,
    operation: &str,
) -> Result<Transaction<'conn>> {
    Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .with_context(|| format!("begin {operation} IMMEDIATE tx"))
}

/// RAII guard for the init mutex. Releases on drop. The mutex
/// HANDLE itself is closed too — `CreateMutexExW` returns a fresh
/// handle every call (with `ERROR_ALREADY_EXISTS` set if the kernel
/// object already existed), so each `acquire` owns its own handle.
struct InitMutex {
    h: HANDLE,
}
impl Drop for InitMutex {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.h);
            let _ = CloseHandle(self.h);
        }
    }
}

impl InitMutex {
    /// Create-or-open and acquire the init mutex. The mutex carries
    /// a real-user-only DACL so a sandbox child cannot open it (and
    /// therefore cannot stall stamps by sitting on the lock).
    fn acquire() -> Result<Self> {
        let sa = acl::build_init_mutex_sa().context("build init-mutex SECURITY_ATTRIBUTES")?;
        let name = wstr(MUTEX_NAME);
        // Don't request CREATE_MUTEX_INITIAL_OWNER — if another
        // broker already created the mutex this call opens it,
        // and INITIAL_OWNER would silently NOT acquire in that
        // case. A separate Wait gives a uniform code path and
        // surfaces WAIT_ABANDONED.
        let h = unsafe {
            CreateMutexExW(
                Some(sa.as_ptr()),
                pcwstr(&name),
                0, // dwFlags — no CREATE_MUTEX_INITIAL_OWNER
                MUTEX_ALL_ACCESS.0,
            )
        }
        .with_context(|| format!("CreateMutexExW({MUTEX_NAME})"))?;
        // `sa` can drop now — the kernel object owns its SD.

        let r = unsafe { WaitForSingleObject(h, INFINITE) };
        match r {
            WAIT_OBJECT_0 => {}
            WAIT_ABANDONED => {
                // Previous holder died while owning the mutex. We
                // now own it. Crash-recovery (which the caller will
                // run next) handles the cleanup; nothing extra here.
                eprintln!(
                    "srt-win: init-mutex WAIT_ABANDONED — previous \
                     `srt-win acl` died mid-operation; running recovery"
                );
            }
            other => {
                let err = std::io::Error::last_os_error();
                unsafe {
                    let _ = CloseHandle(h);
                }
                bail!(
                    "WaitForSingleObject({MUTEX_NAME}): unexpected {other:?} \
                     ({err})"
                );
            }
        }
        Ok(Self { h })
    }
}

/// Open (creating if needed) the state DB at the default location.
/// Stamps the parent directory real-user-only on EVERY open.
pub fn open_db() -> Result<Connection> {
    let dir = state_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create_dir_all {}", dir.display()))?;
    // Stamp the directory `(OI)(CI)` real-user-only so the sandbox
    // child cannot tamper with state.db / -wal / -shm. Done on
    // EVERY open, not just first creation: defense-in-depth — the
    // child runs as a different user, but a working-tree grant
    // could otherwise expose this directory if it lives under a
    // granted root. `SetNamedSecurityInfoW` is
    // idempotent, so re-stamping an already-correct dir is a no-op.
    // Best-effort: if it fails we proceed (the `%LOCALAPPDATA%`
    // default DACL already excludes the separate `srt-sandbox`
    // user; the explicit stamp + sandbox-users DENY below is
    // belt-and-braces against a working-tree ALLOW grant covering
    // this directory) and warn so the test harness can assert. We
    // own this directory, so a user-applied custom DACL on it is
    // NOT preserved — it is rewritten on every open by design.
    let dir_str = dir.to_str().ok_or_else(|| {
        anyhow!(
            "state-DB directory path '{}' is not representable as \
             UTF-8 (contains unpaired surrogates); not supported",
            dir.display()
        )
    })?;
    // Include the sandbox-users DENY when the install has
    // provisioned that group. The credential file in this
    // directory is machine-scope DPAPI — readable-by-sandbox =
    // decryptable-by-sandbox — so the DENY is load-bearing once
    // the separate-user runner exists. The lookup distinguishes
    // "group genuinely absent" (install never run / older install
    // → DENY skipped, broker-only allow set still excludes the
    // sandbox user) from a transient SAM/LSA failure — the latter
    // is surfaced rather than silently dropping a security ACE.
    let deny_sid = match crate::sid::lookup_account_sid(crate::user::SANDBOX_GROUP) {
        Ok(s) => Some(s),
        Err(e) => {
            match crate::sid::sid_account_exists("S-1-5-32-545") {
                // BUILTIN\Users always maps; if it does, SAM is up
                // and the sandbox group is genuinely absent.
                Ok(crate::sid::SidExistence::Mapped) => None,
                _ => {
                    eprintln!(
                        "srt-win: WARNING: cannot resolve \
                         '{}' to add the state-dir DENY ACE \
                         ({e:#}); the broker-only allow set \
                         still excludes the sandbox user, but \
                         the explicit DENY is omitted for this \
                         stamp",
                        crate::user::SANDBOX_GROUP,
                    );
                    None
                }
            }
        }
    };
    if let Err(e) = acl::stamp_dir_inheriting(dir_str, deny_sid.as_deref()) {
        eprintln!(
            "srt-win: WARNING: failed to stamp state-DB dir {} \
             broker-only: {e:#}",
            dir.display()
        );
    }
    open_db_at(&dir.join("state.db"))
}

/// Filter on `release_aces` for the deny-ACE lifecycle.
pub const KIND_DENY: &[&str] = &["deny", "deny_fdc"];
/// Filter on `release_aces` for the grant lifecycle.
pub const KIND_GRANT: &[&str] = &["grant"];

/// `prepare → query_map → collect` with one error context. Shared
/// by every "list of T from one query" site so error plumbing is
/// edited once.
fn query_vec<T, P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    p: P,
    row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut s = conn
        .prepare(sql)
        .with_context(|| format!("prepare: {sql}"))?;
    let it = s
        .query_map(p, row)
        .with_context(|| format!("query: {sql}"))?;
    let mut v = Vec::new();
    for r in it {
        v.push(r.with_context(|| format!("row: {sql}"))?);
    }
    Ok(v)
}

/// Read-only open of the state DB at the default location. Returns
/// `None` if `state.db` doesn't exist yet. No mutex, no
/// `create_dir_all`, no dir-stamp, no schema apply — for the
/// per-Bash-call hot path (`install::read_setup` / `read_ca_cert`).
pub fn open_db_ro() -> Result<Option<Connection>> {
    let path = state_dir()?.join("state.db");
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Ok(true) => {}
        Err(e) => bail!(
            "cannot determine state-DB presence at {}: {e}",
            path.display()
        ),
    }
    let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("sqlite open RO {}", path.display()))?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // Schema-mismatch chokepoint: a v≠SCHEMA_VERSION DB is from an
    // older install whose `sandbox_user` row is stranded. Reading
    // it would surface a stale credential. Return None so
    // `srt-win user status` reports `provisioned=false` and the TS
    // dependency-check tells the user to re-run `srt-win install`
    // (which routes through `open_db_at()` → renames the stale DB
    // to `.bak` and creates fresh) at the start of the session,
    // not mid-exec. Also covers a DB
    // with no schema at all (`open_db_at` crashed between
    // `Connection::open` and `execute_batch(SCHEMA_SQL)`): ver==0
    // and there's no `sandbox_user` row, so "not provisioned yet"
    // is the right answer.
    let ver: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .context("read user_version (RO)")?;
    if ver != SCHEMA_VERSION {
        if ver != 0 {
            eprintln!(
                "srt-win: state DB at {} is at schema v{ver} \
                 (expected v{SCHEMA_VERSION}); treating as not \
                 provisioned. Re-run `srt-win install` to migrate.",
                path.display(),
            );
        }
        return Ok(None);
    }
    Ok(Some(conn))
}

/// Count exact-path ACL state rows for diagnostics and CI residue
/// assertions. Missing or uninitialized DBs report zeroes.
pub fn path_state_counts(canonical_path: &str) -> Result<(u32, u32)> {
    let Some(conn) = open_db_ro()? else {
        return Ok((0, 0));
    };
    conn.query_row(
        "SELECT
            (SELECT COUNT(*) FROM working_aces WHERE canonical_path = ?1),
            (SELECT COUNT(*) FROM ace_holders WHERE canonical_path = ?1)",
        [canonical_path],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .context("count ACL state for path")
}

/// Open at an arbitrary path. Tests use `:memory:` via
/// `open_db_at(Path::new(":memory:"))`.
pub(crate) fn open_db_at(path: &std::path::Path) -> Result<Connection> {
    // Schema mismatch → rename + recreate. No ALTER/DROP migration:
    // the old DB is preserved (debugging/recovery) at
    // state.db.v<old>.<ts>.bak alongside `path`, and a fresh DB is
    // created at the expected schema. The backup is the only durable
    // map of paths owned by the old schema; the targeted recovery
    // command deliberately does not sweep untracked trustee ACEs.
    // The `sandbox_user`
    // row (cred + ca_cert) is in the renamed-away DB → the hint
    // says re-run install + trust-ca. The .bak inherits the
    // PROTECTED broker-only DACL from the state dir (stamped by
    // [`open_db`]); no per-file stamp needed. Chokepoint here so
    // direct callers (`clear_setup`, `trust_ca`) don't silently
    // bump `user_version` on a stale DB.
    if path.exists() {
        let probe = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY);
        if let Ok(c) = probe {
            let ver: i64 = c
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap_or(0);
            drop(c);
            if ver != 0 && ver != SCHEMA_VERSION {
                let dir = path
                    .parent()
                    .ok_or_else(|| anyhow!("state DB path '{}' has no parent", path.display()))?;
                let stem = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("state.db");
                let ts = unix_now();
                let bak = dir.join(format!("{stem}.v{ver}.{ts}.bak"));
                std::fs::rename(path, &bak).map_err(|e| {
                    // SQLite's win32 VFS opens with no
                    // FILE_SHARE_DELETE; another live broker holds
                    // the file → rename fails 32 here where DROP
                    // TABLE under WAL would have succeeded.
                    if e.raw_os_error() == Some(32) {
                        anyhow!(
                            "rename incompatible state DB {} → {}: {e} \
                             — the DB is open in another process \
                             (likely a running srt-win/broker); close \
                             it and retry",
                            path.display(),
                            bak.display()
                        )
                    } else {
                        anyhow::Error::new(e).context(format!(
                            "rename incompatible state DB {} → {}",
                            path.display(),
                            bak.display()
                        ))
                    }
                })?;
                // WAL sidecars too (best-effort — they hold no cred,
                // only journal pages of it).
                for ext in ["-wal", "-shm"] {
                    let p = dir.join(format!("{stem}{ext}"));
                    let to = dir.join(format!("{stem}.v{ver}.{ts}.bak{ext}"));
                    let _ = std::fs::rename(&p, &to);
                }
                eprintln!(
                    "srt-win: state DB at schema v{ver} found, expected \
                     v{SCHEMA_VERSION}; renamed to {} and created fresh. \
                     Re-run `srt-win install` (and `srt-win user \
                     trust-ca <pem>` if you use TLS termination) to \
                     re-provision. Review the backup before manually \
                     removing sandbox-user ACEs from its tracked paths; \
                     `srt-win acl recover` only reconciles paths in the \
                     current DB. PROTECTED-stamp DACLs from the removed \
                     same-user mode require manual `icacls <path> /reset`.",
                    bak.display(),
                );
            }
        }
    }
    let conn = Connection::open(path).with_context(|| format!("sqlite open {}", path.display()))?;
    // WAL = concurrent readers + single writer + crash safety.
    // `synchronous=NORMAL` is the recommended companion for WAL and
    // is durable across power loss. busy_timeout is belt-and-braces
    // — the named mutex already serializes whole operations across
    // brokers, but a brief contention inside one process (tests)
    // shouldn't error.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(SCHEMA_SQL).context("apply schema")?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(conn)
}

/// One row of the `sandbox_user` table — the install-time setup
/// record: the sandbox user's DPAPI-encrypted credential plus the
/// setup marker. Written by `srt-win install`, read by the
/// non-elevated broker. The `ca_cert` column is read/written
/// separately ([`read_ca_cert`] / [`set_ca_cert`]) so this struct
/// carries exactly what [`write_setup_info`] owns.
#[derive(Debug, Clone)]
pub struct SetupInfo {
    pub sandbox_user: String,
    pub sandbox_user_sid: String,
    pub sandbox_group_sid: String,
    /// DPAPI ciphertext of the sandbox user's password.
    pub cred: Vec<u8>,
    pub marker_version: u32,
    pub created_at_unix: u64,
}

/// Write the setup record. `ON CONFLICT … DO UPDATE` (NOT
/// `INSERT OR REPLACE`) so a re-install preserves any column this
/// function doesn't own — currently `ca_cert`, whose only writer
/// is [`set_ca_cert`]. Install is sequential under self-elevation,
/// so the caller doesn't need [`with_init_lock`].
pub fn write_setup_info(conn: &Connection, info: &SetupInfo) -> Result<()> {
    // Single-row invariant: [`read_setup_info`] does `LIMIT 1`, so a
    // `--force` re-install under a different `--sandbox-user` name
    // must not leave the old row behind (the ON CONFLICT keys on
    // username and would insert a second row). This DOES drop the
    // old row's `ca_cert` — intentionally: the CA was written into
    // the OLD user's `CurrentUser\Root` hive, so preserving the
    // record for the NEW user would lie about a Root install that
    // hasn't happened. Same-name re-install skips this DELETE and
    // the ON CONFLICT below preserves `ca_cert`.
    conn.execute(
        "DELETE FROM sandbox_user WHERE username != ?1",
        params![info.sandbox_user],
    )
    .context("DELETE stale sandbox_user row")?;
    conn.execute(
        "INSERT INTO sandbox_user \
           (username, user_sid, group_sid, cred, marker_version, \
            created_at_unix) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(username) DO UPDATE SET \
           user_sid        = excluded.user_sid, \
           group_sid       = excluded.group_sid, \
           cred            = excluded.cred, \
           marker_version  = excluded.marker_version, \
           created_at_unix = excluded.created_at_unix",
        params![
            info.sandbox_user,
            info.sandbox_user_sid,
            info.sandbox_group_sid,
            info.cred,
            info.marker_version,
            info.created_at_unix as i64,
        ],
    )
    .context("UPSERT sandbox_user")?;
    Ok(())
}

/// Hydrate the setup record. `Ok(None)` when no install has run
/// (no row, or the `sandbox_user` table itself absent —
/// [`open_db_ro`] doesn't apply schema). Currently exactly one
/// sandbox user is provisioned, so this reads the single row.
pub fn read_setup_info(conn: &Connection) -> Result<Option<SetupInfo>> {
    match conn
        .query_row(
            "SELECT username, user_sid, group_sid, cred, \
                    marker_version, created_at_unix \
             FROM sandbox_user LIMIT 1",
            [],
            |r| {
                Ok(SetupInfo {
                    sandbox_user: r.get(0)?,
                    sandbox_user_sid: r.get(1)?,
                    sandbox_group_sid: r.get(2)?,
                    cred: r.get(3)?,
                    marker_version: r.get(4)?,
                    created_at_unix: r.get::<_, i64>(5)? as u64,
                })
            },
        )
        .optional()
    {
        Ok(v) => Ok(v),
        Err(e) if missing_sandbox_user_table(&e) => Ok(None),
        Err(e) => Err(anyhow!("SELECT sandbox_user: {e}")),
    }
}

/// Read just the `ca_cert` column from the (single) row. `Ok(None)`
/// when no install has run, no CA was recorded, or the table/column
/// is absent.
pub fn read_ca_cert(conn: &Connection) -> Result<Option<crate::cert_store::CertDer>> {
    match conn
        .query_row("SELECT ca_cert FROM sandbox_user LIMIT 1", [], |r| r.get(0))
        .optional()
    {
        Ok(v) => Ok(v.flatten()),
        Err(e) if missing_sandbox_user_table(&e) => Ok(None),
        Err(e) => Err(anyhow!("SELECT sandbox_user.ca_cert: {e}")),
    }
}

/// Overwrite just the `ca_cert` column on the (single) existing
/// row. `srt-win user trust-ca` uses this to record a CA without
/// re-provisioning. Fails when no install has run yet.
pub fn set_ca_cert(conn: &Connection, der: &crate::cert_store::CertDer) -> Result<()> {
    let n = conn
        .execute("UPDATE sandbox_user SET ca_cert = ?1", params![der])
        .context("UPDATE sandbox_user.ca_cert")?;
    if n == 0 {
        bail!("no sandbox-user row to attach CA to — run `srt-win install`");
    }
    Ok(())
}

/// `DELETE FROM sandbox_user` — uninstall clears the credential
/// and marker in one go.
pub fn clear_setup_info(conn: &Connection) -> Result<()> {
    match conn.execute("DELETE FROM sandbox_user", []) {
        Ok(_) => Ok(()),
        Err(e) if missing_sandbox_user_table(&e) => Ok(()),
        Err(e) => Err(anyhow!("clear_setup_info: {e}")),
    }
}

fn missing_sandbox_user_table(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(_, Some(m))
            if m.contains("no such table") && m.contains("sandbox_user")
    )
}

/// `%LOCALAPPDATA%\sandbox-runtime`. Errors if `LOCALAPPDATA` is
/// unset, empty, or yields a non-absolute path — a relative state
/// dir would put the broker-only-stamped DB in the CWD and break
/// cross-broker refcounting/recovery.
pub fn state_dir() -> Result<PathBuf> {
    state_dir_from(std::env::var_os("LOCALAPPDATA"))
}

fn state_dir_from(local_app_data: Option<std::ffi::OsString>) -> Result<PathBuf> {
    let base = local_app_data
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("LOCALAPPDATA not set or empty"))?;
    let dir = base.join("sandbox-runtime");
    if !dir.is_absolute() {
        bail!(
            "state-DB directory '{}' is not absolute \
             (LOCALAPPDATA='{}'); refusing relative state path",
            dir.display(),
            base.display()
        );
    }
    Ok(dir)
}

/// Run `f` under the init mutex with the DB open. Crash recovery is
/// run first. `f` receives a `Locked` view whose mutating methods
/// each autocommit (single-statement) or use their own short
/// transaction — there is NO single enclosing transaction.
///
/// See module doc for the no-enclosing-tx and ordering rationale.
pub fn with_init_lock<R>(
    holder_pid: HolderPid,
    force_recover: bool,
    f: impl FnOnce(&mut Locked) -> Result<R>,
) -> Result<(R, RecoveryReport)> {
    with_init_lock_inner(holder_pid, None, force_recover, f)
}

/// [`with_init_lock`] with an immutable holder process identity. New
/// protocols that can observe creation time should use this form;
/// PID-only callers remain supported for compatibility.
pub fn with_init_lock_bound<R>(
    holder: HolderIdentity,
    force_recover: bool,
    f: impl FnOnce(&mut Locked) -> Result<R>,
) -> Result<(R, RecoveryReport)> {
    with_init_lock_inner(
        holder.pid,
        Some(holder.process_create_time),
        force_recover,
        f,
    )
}

fn with_init_lock_inner<R>(
    holder_pid: HolderPid,
    expected_create_time: Option<i64>,
    force_recover: bool,
    f: impl FnOnce(&mut Locked) -> Result<R>,
) -> Result<(R, RecoveryReport)> {
    let _mutex = InitMutex::acquire()?;
    let conn = open_db()?;
    let report = crash_recovery(&conn, force_recover)?;
    let mut locked = Locked {
        conn,
        holder_pid,
        expected_create_time,
    };
    let out = f(&mut locked)?;
    Ok((out, report))
}

/// View inside `with_init_lock`. Owns the `Connection`; each method
/// commits independently (rusqlite autocommits a lone `execute`).
///
/// `holder_pid` is the LONG-LIVED owner of the stamps — typically
/// the Node host (sandbox-runtime) process, NOT this ephemeral
/// `srt-win acl` process. The CLI exits immediately; keying holders
/// on its PID would let the next acl op's crash-recovery reap it and
/// tear the stamp down. Keying on the caller-supplied holder PID
/// means a stamp persists until that process exits (or explicitly
/// restores), and refcount / crash-recovery track the real session.
pub struct Locked {
    conn: Connection,
    holder_pid: HolderPid,
    expected_create_time: Option<i64>,
}

impl Locked {
    /// Record `self.holder_pid` in `brokers`. The row's
    /// `process_create_time` is the HOLDER's, so crash-recovery
    /// checks whether the holder — not this short-lived CLI — is
    /// still alive.
    ///
    /// UPSERT, not `INSERT OR REPLACE`: with `foreign_keys=ON` and
    /// `ace_holders.pid REFERENCES brokers ON DELETE CASCADE`,
    /// REPLACE is a DELETE (cascading away every `ace_holders` row
    /// for this pid) plus a fresh INSERT — so a holder's *second*
    /// `acl stamp`/`grant` would silently drop its first batch's
    /// holds, and the next crash-recovery would strip those ACEs
    /// while the holder's child is still running. `ON CONFLICT DO
    /// UPDATE` updates in place and leaves child rows intact.
    pub fn register_broker(&self) -> Result<()> {
        let observed = HolderIdentity::observe(self.holder_pid)
            .with_context(|| format!("observe holder pid {}", self.holder_pid.0))?;
        if let Some(expected) = self.expected_create_time
            && observed.process_create_time != expected
        {
            bail!(
                "holder pid {} creation-time mismatch: expected {}, observed {}",
                self.holder_pid.0,
                expected,
                observed.process_create_time
            );
        }
        let ct = observed.process_create_time;
        let registered: Option<i64> = self
            .conn
            .query_row(
                "SELECT process_create_time FROM brokers WHERE pid = ?1",
                params![self.holder_pid.0 as i64],
                |row| row.get(0),
            )
            .optional()
            .context("SELECT existing broker identity")?;
        if let Some(registered) = registered
            && registered != ct
        {
            bail!(
                "holder pid {} collides with stale broker identity: observed {}, registered {}",
                self.holder_pid.0,
                ct,
                registered
            );
        }
        let now = unix_now();
        self.conn
            .execute(
                "INSERT INTO brokers (pid, process_create_time, started_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(pid) DO UPDATE SET \
                   process_create_time = excluded.process_create_time, \
                   started_at          = excluded.started_at",
                params![self.holder_pid.0 as i64, ct, now],
            )
            .context("INSERT brokers")?;
        Ok(())
    }

    /// Remove the holder's `brokers` row. CASCADE drops its
    /// `holders` rows.
    pub fn unregister_broker(&self) -> Result<()> {
        match self.expected_create_time {
            Some(ct) => self
                .conn
                .execute(
                    "DELETE FROM brokers WHERE pid = ?1 AND process_create_time = ?2",
                    params![self.holder_pid.0 as i64, ct],
                )
                .context("DELETE bound broker")?,
            None => self
                .conn
                .execute(
                    "DELETE FROM brokers WHERE pid = ?1",
                    params![self.holder_pid.0 as i64],
                )
                .context("DELETE brokers")?,
        };
        Ok(())
    }

    fn validate_bound_broker(&self) -> Result<()> {
        let Some(expected) = self.expected_create_time else {
            return Ok(());
        };
        let stored: Option<i64> = self
            .conn
            .query_row(
                "SELECT process_create_time FROM brokers WHERE pid = ?1",
                params![self.holder_pid.0 as i64],
                |row| row.get(0),
            )
            .optional()
            .context("SELECT bound broker identity")?;
        if let Some(stored) = stored
            && stored != expected
        {
            bail!(
                "holder pid {} no longer identifies the registered process: expected {}, stored {}",
                self.holder_pid.0,
                expected,
                stored
            );
        }
        Ok(())
    }

    /// ACL tracking is not SID-keyed, so accepting a caller-supplied
    /// SID different from the installed sandbox identity could remove
    /// tracking while filtering a different principal on disk.
    fn validate_sandbox_sid(&self, supplied: &str) -> Result<()> {
        let installed = read_setup_info(&self.conn)?
            .ok_or_else(|| anyhow!("sandbox setup missing; refusing ACL mutation"))?
            .sandbox_user_sid;
        if !installed.eq_ignore_ascii_case(supplied) {
            bail!("sandbox user SID mismatch: supplied {supplied}, installed {installed}");
        }
        Ok(())
    }

    /// Register the holder, run `f`, and on per-path failure roll
    /// back any ACEs `f` freshly added (then drop the broker row if
    /// it now holds nothing). All-or-nothing for `apply_aces`.
    fn with_broker_registration(
        &self,
        sandbox_sid: &str,
        f: impl FnOnce(&Self) -> Result<(Vec<AceWitness>, usize)>,
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.validate_sandbox_sid(sandbox_sid)?;
        self.register_broker()?;
        let (witnesses, failed) = f(self)?;
        if failed > 0 {
            for w in witnesses.iter().filter(|w| w.holder_added) {
                if let Err(e) = self.release_one_ace(&w.canon, w.ace.kind(), sandbox_sid) {
                    eprintln!(
                        "srt-win: WARNING: rollback {} '{}': {e:#}; \
                         ACE left in place",
                        w.ace.kind(),
                        w.canon
                    );
                }
            }
            if self
                .my_ace_holds(None)
                .map(|h| h.is_empty())
                .unwrap_or(false)
            {
                let _ = self.unregister_broker();
            }
        }
        Ok((witnesses, failed))
    }

    /// Apply additive sandbox-user ACEs on each `(canon, ace)` and
    /// record `self.holder_pid` as a holder. Refcounted: a path
    /// already held by another holder gets its on-disk ACE
    /// re-converged (idempotent) and a holder row added; release
    /// recomputes the effective mask from the remaining holders.
    ///
    /// `Deny` targets implicitly add a `(parent, DenyFdc)` entry so
    /// the sandbox user cannot `del`/`ren` the file via parent-FDC
    /// even when the parent carries an inherited
    /// `BUILTIN\Users:(F)`. Multiple denied siblings under one
    /// parent share the parent's `deny_fdc` row (PK
    /// `(path, kind, pid)` dedupes within one holder; refcount
    /// handles cross-holder).
    ///
    /// All-or-nothing per batch (via [`Self::with_broker_registration`]).
    pub fn apply_aces(
        &self,
        sandbox_sid: &str,
        targets: &[(String, SbAce)],
    ) -> Result<(Vec<AceWitness>, usize)> {
        self.with_broker_registration(sandbox_sid, |db| {
            let mut witnesses = Vec::with_capacity(targets.len());
            let mut failed = 0usize;
            let mut one = |canon: &str, ace: SbAce| -> bool {
                match db.ensure_ace(canon, ace, sandbox_sid) {
                    Ok(w) => {
                        witnesses.push(w);
                        true
                    }
                    Err(e) => {
                        eprintln!("srt-win: {} '{canon}': {e:#}", ace.kind());
                        failed += 1;
                        false
                    }
                }
            };
            for (canon, ace) in targets {
                // Skip the parent-FDC ACE when the file's own
                // Deny failed (e.g. hardlink refuse) — the batch
                // is going to roll back anyway (`failed > 0`),
                // and stamping the parent first just to release
                // it in the same pass wastes a SetSecurityInfo
                // round-trip and clutters the failure output.
                if one(canon, *ace)
                    && matches!(ace, SbAce::Deny(_))
                    && let Some(p) = path_id::canonical_parent_of(canon)
                {
                    one(&p, SbAce::DenyFdc);
                }
            }
            Ok((witnesses, failed))
        })
    }

    /// Converge one ACE with kind-specific crash ordering. GRANT
    /// commits tracking before adding access; DENY applies the
    /// restriction while its IMMEDIATE transaction is open, then
    /// commits tracking. Either crash direction is fail-closed.
    fn ensure_ace(&self, canon: &str, want: SbAce, sandbox_sid: &str) -> Result<AceWitness> {
        let (cur_id, links, is_dir) = path_id::capture_id_and_links(canon)
            .with_context(|| format!("capture file_id+links '{canon}'"))?;
        // Hardlink guard: NTFS hardlinks share one SD across
        // distinct canonical paths, but `ace_holders` is
        // PATH-keyed. A Deny on one alias is invisible to a holder
        // of another — `release_one_ace` on the alias sees
        // remaining=0 and recomposes the SHARED DACL without the
        // deny while the other holder's child is still running.
        // Refuse Deny on multi-link files; Grant is fail-open so
        // an early release is safe, and `DenyFdc` only targets
        // directories.
        if matches!(want, SbAce::Deny(_)) && !is_dir && links > 1 {
            bail!(
                "deny refused: '{canon}' has {links} hardlink(s); \
                 ace_holders rows are path-keyed, so releasing an \
                 alias would prematurely strip the shared deny ACE"
            );
        }
        // Serialize holder/effective-row derivation across TS sessions.
        // The tracking transaction commits before filesystem mutation,
        // so a GRANT can never exist without a durable working row.
        let tx = immediate_transaction(&self.conn, "ensure ACE tracking")?;
        let prior: Option<Vec<u8>> = tx
            .prepare_cached(
                "SELECT file_id FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, want.kind()], |r| r.get(0))
            .optional()
            .context("SELECT working_aces")?;
        if let Some(fid) = &prior
            && FileId::from_bytes(fid)? != cur_id
        {
            bail!(
                "'{canon}': file_id changed since prior {} — path \
                 was substituted (refusing)",
                want.kind()
            );
        }
        // Holder row first (`want_mask` is THIS holder's request,
        // independent of what other holders want — `effective_ace_at`
        // computes the MAX). Probe first because SQLite UPSERT reports
        // one changed row for both insert and update.
        let already_held: bool = tx
            .prepare_cached(
                "SELECT 1 FROM ace_holders WHERE \
                 canonical_path = ?1 AND kind = ?2 AND pid = ?3 \
                 LIMIT 1",
            )?
            .exists(params![canon, want.kind(), self.holder_pid.0 as i64])
            .context("SELECT ace_holders (held?)")?;
        tx.prepare_cached(
            "INSERT INTO ace_holders \
             (canonical_path, kind, pid, want_mask) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(canonical_path, kind, pid) \
             DO UPDATE SET want_mask = excluded.want_mask",
        )?
        .execute(params![
            canon,
            want.kind(),
            self.holder_pid.0 as i64,
            want.as_str()
        ])
        .context("UPSERT ace_holders")?;
        let holder_added = !already_held;
        let eff = effective_ace_at(&tx, canon, want.kind())?.unwrap_or(want);
        tx.prepare_cached(
            "INSERT INTO working_aces \
             (canonical_path, kind, file_id, mask) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(canonical_path, kind) DO UPDATE SET \
               file_id = excluded.file_id, \
               mask    = excluded.mask",
        )?
        .execute(params![
            canon,
            want.kind(),
            cur_id.as_bytes().as_slice(),
            eff.as_str()
        ])
        .context("UPSERT working_aces")?;
        match want {
            SbAce::Grant(_) => {
                tx.commit().context("commit ensure GRANT tracking")?;
                // Access may only be added after tracking is durable.
                // Re-acquire an IMMEDIATE writer lock so a concurrent
                // grant cannot widen the DB state and then have this
                // caller overwrite disk with a stale narrower mask.
                let tx = immediate_transaction(&self.conn, "ensure GRANT filesystem")?;
                recompose_at(&tx, canon, sandbox_sid)?;
                tx.commit().context("commit ensure GRANT filesystem")?;
            }
            SbAce::Deny(_) | SbAce::DenyFdc => {
                // Keep the write lock through the filesystem DENY. A
                // crash or commit failure can leave an extra DENY, but
                // can never leave a committed holder without its deny.
                recompose_object_at(&tx, canon, canon, sandbox_sid)?;
                tx.commit().context("commit ensure DENY tracking")?;
            }
        }
        Ok(AceWitness {
            canon: canon.to_string(),
            ace: eff,
            already: prior.is_some(),
            holder_added,
            _sealed: (),
        })
    }

    /// Release one `(canon, kind)` hold; recompute the effective ACE
    /// from the remaining holders (downgrade if this holder was the
    /// one that escalated it; revoke when zero remain).
    ///
    /// GRANT and DENY have opposite crash-safety ordering:
    ///
    /// - GRANT changes tracking and disk in one transaction so a
    ///   failure cannot leave an untracked ALLOW.
    /// - DENY first commits the holder removal while the stronger
    ///   on-disk DENY remains, then converges disk in a second
    ///   retryable phase. A crash before convergence is fail-closed.
    fn release_one_ace(&self, canon: &str, kind: &str, sandbox_sid: &str) -> Result<AceRelease> {
        self.release_one_ace_with(
            canon,
            kind,
            sandbox_sid,
            identity_gate,
            path_id::locate_by_file_id,
            recompose_object_at,
        )
    }

    fn release_one_ace_with<I, L, R>(
        &self,
        canon: &str,
        kind: &str,
        sandbox_sid: &str,
        identity: I,
        locate: L,
        recompose: R,
    ) -> Result<AceRelease>
    where
        I: Fn(&str, FileId) -> IdGate,
        L: Fn(&FileId) -> Result<Option<String>>,
        R: Fn(&Connection, &str, &str, &str) -> Result<()>,
    {
        match kind {
            "grant" => self.release_one_grant_with(canon, sandbox_sid, identity, locate, recompose),
            "deny" | "deny_fdc" => self.release_one_deny_with(
                canon,
                kind,
                sandbox_sid,
                identity,
                recompose,
                || Ok(()),
                |_| Ok(()),
                || Ok(()),
            ),
            _ => bail!("unknown ACE kind {kind:?}"),
        }
    }

    /// Remove a GRANT edge record-first. The transaction remains open
    /// through filesystem convergence, so rollback always retains a
    /// tracking row for any ALLOW that might still exist.
    fn release_one_grant_with<I, L, R>(
        &self,
        canon: &str,
        sandbox_sid: &str,
        identity: I,
        locate: L,
        recompose: R,
    ) -> Result<AceRelease>
    where
        I: Fn(&str, FileId) -> IdGate,
        L: Fn(&FileId) -> Result<Option<String>>,
        R: Fn(&Connection, &str, &str, &str) -> Result<()>,
    {
        let kind = "grant";
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin release grant tx")?;
        tx.prepare_cached(
            "DELETE FROM ace_holders WHERE canonical_path = ?1 AND kind = ?2 AND pid = ?3",
        )?
        .execute(params![canon, kind, self.holder_pid.0 as i64])
        .context("DELETE ace_holders (self)")?;
        let row: Option<(Vec<u8>, String)> = tx
            .prepare_cached(
                "SELECT file_id, mask FROM working_aces WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, kind], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((fid, stored)) = row else {
            tx.commit()
                .context("commit release grant with no working row")?;
            return Ok(AceRelease::NoRow);
        };
        let new_eff = effective_ace_at(&tx, canon, kind)?;
        update_working_ace(&tx, canon, kind, new_eff)?;
        let want_id = FileId::from_bytes(&fid)?;
        let outcome = match identity(canon, want_id) {
            IdGate::Match => {
                recompose(&tx, canon, canon, sandbox_sid)?;
                match new_eff {
                    Some(e) if e.as_str() == stored => AceRelease::StillHeld,
                    Some(_) => AceRelease::Downgraded,
                    None => AceRelease::Revoked,
                }
            }
            IdGate::Mismatch => {
                // The ALLOW travels with the inode. A confirmed delete
                // needs no cleanup; every lookup/recompose failure is
                // propagated so the original rows remain retryable.
                match locate(&want_id)? {
                    Some(at) => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id moved to '{at}'; revoking there"
                        );
                        recompose(&tx, canon, &at, sandbox_sid)?;
                        AceRelease::Relocated { moved_to: at }
                    }
                    None => {
                        eprintln!(
                            "srt-win: grant '{canon}': file_id no longer exists on its mounted volume; dropping row"
                        );
                        AceRelease::Missing
                    }
                }
            }
            IdGate::Unreadable => {
                bail!(
                    "grant '{canon}': file identity is unreadable; retaining holder and working rows for retry"
                )
            }
        };
        tx.commit().context("commit release grant tx")?;
        Ok(outcome)
    }

    /// Remove a DENY edge in two durable phases. Phase 1 commits only
    /// the holder transition while the existing (same-or-stronger)
    /// DENY remains on disk. Phase 2 derives the narrower desired state
    /// from the remaining holders and converges disk before committing
    /// the updated `working_aces`. Failed phase-2 commits leave the stale
    /// stronger row as a recovery marker.
    #[allow(clippy::too_many_arguments)]
    fn release_one_deny_with<I, R, B, C, A>(
        &self,
        canon: &str,
        kind: &str,
        sandbox_sid: &str,
        identity: I,
        recompose: R,
        before_holder_commit: B,
        between_phases: C,
        before_state_commit: A,
    ) -> Result<AceRelease>
    where
        I: Fn(&str, FileId) -> IdGate,
        R: Fn(&Connection, &str, &str, &str) -> Result<()>,
        B: FnOnce() -> Result<()>,
        C: FnOnce(&Connection) -> Result<()>,
        A: FnOnce() -> Result<()>,
    {
        let tx = immediate_transaction(&self.conn, "release DENY holder")?;
        tx.prepare_cached(
            "DELETE FROM ace_holders WHERE canonical_path = ?1 AND kind = ?2 AND pid = ?3",
        )?
        .execute(params![canon, kind, self.holder_pid.0 as i64])
        .context("DELETE deny ace_holders (self)")?;

        // This is the security boundary: no filesystem DENY is
        // weakened until the holder transition is durable.
        before_holder_commit().context("before commit deny holder transition")?;
        tx.commit().context("commit release deny holder tx")?;
        between_phases(&self.conn).context("between deny release phases")?;

        // Acquire the cross-session write lock before deriving the
        // remaining effective mask. Never carry a phase-1 snapshot
        // across the durable boundary.
        let tx = immediate_transaction(&self.conn, "release DENY state")?;
        let row: Option<(Vec<u8>, String)> = tx
            .prepare_cached(
                "SELECT file_id, mask FROM working_aces WHERE canonical_path = ?1 AND kind = ?2",
            )?
            .query_row(params![canon, kind], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let new_eff = effective_ace_at(&tx, canon, kind)?;
        let Some((fid, stored)) = row else {
            if new_eff.is_some() {
                bail!(
                    "{kind} '{canon}': holder remains but working row is missing; holder transition committed, recovery required"
                );
            }
            return Ok(AceRelease::NoRow);
        };

        update_working_ace(&tx, canon, kind, new_eff)?;
        let want_id = FileId::from_bytes(&fid)?;
        let outcome = match identity(canon, want_id) {
            IdGate::Match => {
                recompose(&tx, canon, canon, sandbox_sid)?;
                match new_eff {
                    Some(e) if e.as_str() == stored => AceRelease::StillHeld,
                    Some(_) => AceRelease::Downgraded,
                    None => AceRelease::Revoked,
                }
            }
            IdGate::Mismatch => {
                eprintln!(
                    "srt-win: {kind} '{canon}': file_id mismatch — path substituted; not touching DENY on the foreign object (fail-closed)"
                );
                AceRelease::Mismatch
            }
            IdGate::Unreadable => {
                bail!(
                    "{kind} '{canon}': file identity is unreadable; holder transition committed, stronger DENY and working row retained for retry"
                )
            }
        };
        before_state_commit().context("before commit deny state convergence")?;
        tx.commit().context("commit release deny state tx")?;
        Ok(outcome)
    }
    /// `(canon, kind)` rows held by this holder, optionally filtered
    /// to one set of kinds.
    fn my_ace_holds(&self, kinds: Option<&[&str]>) -> Result<Vec<(String, String)>> {
        let all: Vec<(String, String)> = query_vec(
            &self.conn,
            "SELECT canonical_path, kind FROM ace_holders \
             WHERE pid = ?1",
            params![self.holder_pid.0 as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(all
            .into_iter()
            .filter(|(_, k)| kinds.is_none_or(|ks| ks.contains(&k.as_str())))
            .collect())
    }

    /// Release every ACE hold of `self.holder_pid` for the given
    /// `kinds` (`["grant"]` for `acl revoke`;
    /// `["deny","deny_fdc"]` for `acl restore --sandbox-user-sid`)
    /// and unregister if no holds of any kind remain. Per-path
    /// catch-and-continue.
    pub fn release_aces(
        &self,
        sandbox_sid: &str,
        kinds: &[&str],
    ) -> Result<(Vec<(String, AceRelease)>, usize)> {
        self.validate_bound_broker()?;
        self.validate_sandbox_sid(sandbox_sid)?;
        let holds = self.my_ace_holds(Some(kinds))?;
        let mut out = Vec::with_capacity(holds.len());
        let mut failed = 0usize;
        for (canon, kind) in &holds {
            match self.release_one_ace(canon, kind, sandbox_sid) {
                Ok(r) => out.push((canon.clone(), r)),
                Err(e) => {
                    eprintln!(
                        "srt-win: WARNING: release {kind} '{canon}': \
                         {e:#}; ACE left in place"
                    );
                    failed += 1;
                }
            }
        }
        if self
            .my_ace_holds(None)
            .map(|h| h.is_empty())
            .unwrap_or(false)
        {
            self.unregister_broker()?;
        }
        Ok((out, failed))
    }
}

/// `MAX(want_mask)` across holder edges for one path/kind.
fn effective_ace_at(conn: &Connection, canon: &str, kind: &str) -> Result<Option<SbAce>> {
    let masks: Vec<String> = query_vec(
        conn,
        "SELECT want_mask FROM ace_holders WHERE canonical_path = ?1 AND kind = ?2",
        params![canon, kind],
        |r| r.get(0),
    )?;
    masks
        .iter()
        .map(|m| SbAce::parse(kind, m))
        .reduce(|a, b| Ok(a?.max(b?)))
        .transpose()
}

/// Update the tracked effective mask, or remove the row when no
/// holders remain. Callers own the surrounding crash-safety order.
fn update_working_ace(
    conn: &Connection,
    canon: &str,
    kind: &str,
    effective: Option<SbAce>,
) -> Result<()> {
    match effective {
        Some(ace) => conn
            .execute(
                "UPDATE working_aces SET mask = ?3 WHERE canonical_path = ?1 AND kind = ?2",
                params![canon, kind, ace.as_str()],
            )
            .context("UPDATE working_aces (effective mask)")?,
        None => conn
            .execute(
                "DELETE FROM working_aces WHERE canonical_path = ?1 AND kind = ?2",
                params![canon, kind],
            )
            .context("DELETE working_aces")?,
    };
    Ok(())
}

/// Read all `working_aces` rows for `canon` and converge the on-disk
/// ACEs for `sandbox_sid` to exactly that set. The single chokepoint
/// for sandbox-user ACE state — every add/drop/crash-recover routes
/// here so a path with both a grant AND a deny (or a parent that is
/// both granted and `deny_fdc`'d) is handled consistently.
fn recompose_at(conn: &Connection, canon: &str, sandbox_sid: &str) -> Result<()> {
    recompose_object_at(conn, canon, canon, sandbox_sid)
}

/// Converge the object currently at `target` from tracking attached
/// both to its original canonical path and to the current path. The
/// union preserves DENY/DENY_FDC when a relocated GRANT is removed.
fn recompose_object_at(
    conn: &Connection,
    source_canon: &str,
    target: &str,
    sandbox_sid: &str,
) -> Result<()> {
    let set = sandbox_ace_set_for_object(conn, source_canon, target)?;
    acl::apply_sandbox_aces(target, sandbox_sid, set)
        .with_context(|| format!("recompose '{target}' from '{source_canon}' ({set:?})"))
}

fn sandbox_ace_set_for_object(
    conn: &Connection,
    source_canon: &str,
    target: &str,
) -> Result<acl::SbAceSet> {
    let rows: Vec<(String, String)> = query_vec(
        conn,
        "SELECT kind, mask FROM working_aces WHERE canonical_path = ?1 OR canonical_path = ?2",
        params![source_canon, target],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let mut grant: Option<SbAce> = None;
    let mut deny: Option<SbAce> = None;
    let mut deny_fdc = false;
    for (kind, mask) in &rows {
        let ace = SbAce::parse(kind, mask)?;
        match ace {
            SbAce::Grant(_) => grant = Some(grant.map_or(ace, |current| current.max(ace))),
            SbAce::Deny(_) => deny = Some(deny.map_or(ace, |current| current.max(ace))),
            SbAce::DenyFdc => deny_fdc = true,
        }
    }
    let mut set = acl::SbAceSet {
        deny_fdc,
        ..Default::default()
    };
    if let Some(SbAce::Grant(mask)) = grant {
        set.grant = Some(mask);
    }
    if let Some(SbAce::Deny(mask)) = deny {
        set.deny = Some(mask);
    }
    Ok(set)
}
/// Sealed proof that [`Locked::apply_aces`] converged `canon` to
/// carry `ace` for the sandbox user.
#[must_use]
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug)]
pub struct AceWitness {
    pub canon: String,
    pub ace: SbAce,
    /// A row already existed (another holder, or a re-apply).
    pub already: bool,
    pub holder_added: bool,
    _sealed: (),
}

/// Per-path outcome of [`Locked::release_aces`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AceRelease {
    /// ACE removed (last holder); row deleted.
    Revoked,
    /// Other holders remain at the SAME effective mask; ACE
    /// untouched.
    StillHeld,
    /// Other holders remain at a NARROWER mask; ACE re-applied at
    /// the new MAX(want_mask).
    Downgraded,
    /// `file_id` mismatch; for `grant` the ACE was revoked at the
    /// relocated path. Row deleted.
    Relocated { moved_to: String },
    /// `file_id` mismatch — row deleted, ACE on the foreign object
    /// not touched.
    Mismatch,
    /// Path no longer opens — row deleted.
    Missing,
    /// Holder row removed but no `working_aces` row found.
    NoRow,
}

impl AceRelease {
    pub fn as_str(&self) -> &'static str {
        match self {
            AceRelease::Revoked => "revoked",
            AceRelease::StillHeld => "stillHeld",
            AceRelease::Downgraded => "downgraded",
            AceRelease::Relocated { .. } => "relocated",
            AceRelease::Mismatch => "mismatch",
            AceRelease::Missing => "missing",
            AceRelease::NoRow => "noRow",
        }
    }
}

/// Prune dead brokers and reconcile sandbox-user ACE tracking.
///
/// Broker deletion and each path convergence use independent retry
/// units. A poisoned row remains tracked and is reported, but cannot
/// block unrelated recovery or the operation that acquired the init
/// lock. `force` revalidates and recomposes every tracked row; it
/// never bypasses file-identity checks or deletes unreadable state.
fn crash_recovery(conn: &Connection, force: bool) -> Result<RecoveryReport> {
    crash_recovery_with(
        conn,
        force,
        is_process_alive,
        path_id::capture_file_id,
        identity_gate,
        path_id::locate_by_file_id,
        recompose_object_at,
    )
}

fn recovery_key_cmp(left: &(String, String), right: &(String, String)) -> std::cmp::Ordering {
    let left_fdc_rank = u8::from(left.1 != "deny_fdc");
    let right_fdc_rank = u8::from(right.1 != "deny_fdc");
    left_fdc_rank
        .cmp(&right_fdc_rank)
        .then_with(|| {
            std::path::Path::new(&left.0)
                .components()
                .count()
                .cmp(&std::path::Path::new(&right.0).components().count())
        })
        .then_with(|| left.0.cmp(&right.0))
        .then_with(|| left.1.cmp(&right.1))
}

fn crash_recovery_with<A, C, I, L, R>(
    conn: &Connection,
    force: bool,
    alive: A,
    capture: C,
    identity: I,
    locate: L,
    recompose: R,
) -> Result<RecoveryReport>
where
    A: Fn(u32, i64) -> bool,
    C: Fn(&str) -> Result<FileId>,
    I: Fn(&str, FileId) -> IdGate,
    L: Fn(&FileId) -> Result<Option<String>>,
    R: Fn(&Connection, &str, &str, &str) -> Result<()>,
{
    let mut report = RecoveryReport::default();
    let sandbox_sid = read_setup_info(conn)?.map(|setup| setup.sandbox_user_sid);

    // Older builds could commit a holder without its working row.
    // Rebuild only restrictive holder-only state before dead-broker
    // pruning; a GRANT has no durable file identity and must never
    // TOFU the object currently occupying the path.
    if let Some(sandbox_sid) = sandbox_sid.as_deref() {
        let holder_only_denies: Vec<(String, String)> = query_vec(
            conn,
            concat!(
                "SELECT DISTINCT h.canonical_path, h.kind ",
                "FROM ace_holders h ",
                "LEFT JOIN working_aces w ",
                "ON w.canonical_path = h.canonical_path AND w.kind = h.kind ",
                "WHERE w.canonical_path IS NULL ",
                "AND h.kind IN ('deny', 'deny_fdc')"
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        for (canon, kind) in holder_only_denies {
            match reconcile_working_ace_with(
                conn,
                &canon,
                &kind,
                false,
                sandbox_sid,
                &capture,
                &identity,
                &locate,
                &recompose,
            ) {
                Ok(ReconcileOutcome::Reconciled) => {
                    report.aces_revoked = report.aces_revoked.saturating_add(1);
                }
                Ok(ReconcileOutcome::Skipped) => {}
                Err(error) => {
                    report.cleanup_failures = report.cleanup_failures.saturating_add(1);
                    eprintln!(
                        "srt-win: WARNING: recovery could not rebuild holder-only {kind} '{canon}': {error:#}; tracking retained for retry"
                    );
                }
            }
        }
    }

    let brokers: Vec<(i64, i64)> = query_vec(
        conn,
        "SELECT pid, process_create_time FROM brokers",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    for (pid, create_time) in brokers {
        if alive(pid as u32, create_time) {
            continue;
        }
        let prune: Result<bool> = (|| {
            let tx = immediate_transaction(conn, "dead-broker prune")?;
            let holder_only: bool = tx
                .prepare_cached(concat!(
                    "SELECT 1 ",
                    "FROM ace_holders h ",
                    "LEFT JOIN working_aces w ",
                    "ON w.canonical_path = h.canonical_path AND w.kind = h.kind ",
                    "WHERE h.pid = ?1 AND w.canonical_path IS NULL ",
                    "LIMIT 1"
                ))?
                .exists(params![pid])
                .context("SELECT dead broker holder-only ACE")?;
            if holder_only {
                bail!("dead broker {pid} owns holder-only ACE state without file identity");
            }
            // Compare-and-delete the identity observed above. Another
            // recovery may have removed the stale row and allowed a
            // PID-reused live broker to register in the meantime.
            let deleted = tx
                .execute(
                    concat!(
                        "DELETE FROM brokers ",
                        "WHERE pid = ?1 AND process_create_time = ?2"
                    ),
                    params![pid, create_time],
                )
                .with_context(|| format!("DELETE dead broker {pid}"))?;
            tx.commit()
                .with_context(|| format!("commit dead-broker prune {pid}"))?;
            Ok(deleted > 0)
        })();
        match prune {
            Ok(true) => {
                report.dead_brokers = report.dead_brokers.saturating_add(1);
            }
            Ok(false) => {}
            Err(error) => {
                report.cleanup_failures = report.cleanup_failures.saturating_add(1);
                eprintln!(
                    "srt-win: WARNING: recovery could not prune dead broker {pid}: {error:#}; broker row retained for retry"
                );
            }
        }
    }

    let Some(sandbox_sid) = sandbox_sid else {
        return Ok(report);
    };
    let mut keys: Vec<(String, String)> = query_vec(
        conn,
        concat!(
            "SELECT canonical_path, kind FROM working_aces ",
            "UNION ",
            "SELECT canonical_path, kind FROM ace_holders"
        ),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    // Force recovery is the explicit migration path for legacy
    // inheritable parent-FDC ACEs. Recompose tracked parent rows
    // shallowest-first, then targets, and retain identity failures
    // per path instead of broad trustee sweeping.
    keys.sort_by(recovery_key_cmp);
    if force && keys.iter().any(|(_, kind)| kind == "deny_fdc") {
        eprintln!(concat!(
            "srt-win: WARNING: force recovery is migrating tracked parent-FDC ACEs; ",
            "stop older srt-win binaries first. Protected descendants and ",
            "out-of-band orphan ACEs require explicit targeted recovery"
        ));
    }
    for (canon, kind) in keys {
        match reconcile_working_ace_with(
            conn,
            &canon,
            &kind,
            force,
            &sandbox_sid,
            &capture,
            &identity,
            &locate,
            &recompose,
        ) {
            Ok(ReconcileOutcome::Reconciled) => {
                report.aces_revoked = report.aces_revoked.saturating_add(1);
            }
            Ok(ReconcileOutcome::Skipped) => {}
            Err(error) => {
                report.cleanup_failures = report.cleanup_failures.saturating_add(1);
                eprintln!(
                    "srt-win: WARNING: recovery could not reconcile {kind} '{canon}': {error:#}; tracking retained for retry"
                );
            }
        }
    }
    Ok(report)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileOutcome {
    Skipped,
    Reconciled,
}

/// Reconcile one tracking key while holding an IMMEDIATE writer
/// transaction. The desired mask is derived only after the lock is
/// acquired, so another TS session cannot widen a DENY between the
/// holder read and filesystem convergence.
#[allow(clippy::too_many_arguments)]
fn reconcile_working_ace_with<C, I, L, R>(
    conn: &Connection,
    canon: &str,
    kind: &str,
    force: bool,
    sandbox_sid: &str,
    capture: &C,
    identity: &I,
    locate: &L,
    recompose: &R,
) -> Result<ReconcileOutcome>
where
    C: Fn(&str) -> Result<FileId>,
    I: Fn(&str, FileId) -> IdGate,
    L: Fn(&FileId) -> Result<Option<String>>,
    R: Fn(&Connection, &str, &str, &str) -> Result<()>,
{
    let tx = immediate_transaction(conn, "working-ACE reconcile")?;
    let row: Option<(Vec<u8>, String)> = tx
        .prepare_cached(concat!(
            "SELECT file_id, mask FROM working_aces ",
            "WHERE canonical_path = ?1 AND kind = ?2"
        ))?
        .query_row(params![canon, kind], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()
        .context("SELECT working ACE for reconciliation")?;
    let desired = effective_ace_at(&tx, canon, kind)?;

    let Some((file_id, stored)) = row else {
        return match desired {
            None => {
                tx.commit().context("commit empty ACE reconciliation")?;
                Ok(ReconcileOutcome::Skipped)
            }
            Some(SbAce::Grant(_)) => {
                bail!(
                    "holder-only grant '{canon}' lacks original file identity; refusing current-path TOFU"
                )
            }
            Some(ace @ (SbAce::Deny(_) | SbAce::DenyFdc)) => {
                let file_id = capture(canon).with_context(|| {
                    format!("capture holder-only {kind} file identity '{canon}'")
                })?;
                tx.execute(
                    concat!(
                        "INSERT INTO working_aces ",
                        "(canonical_path, kind, file_id, mask) ",
                        "VALUES (?1, ?2, ?3, ?4)"
                    ),
                    params![canon, kind, file_id.as_bytes().as_slice(), ace.as_str()],
                )
                .context("INSERT holder-only working ACE")?;
                recompose(&tx, canon, canon, sandbox_sid)
                    .with_context(|| format!("rebuild holder-only {kind} '{canon}'"))?;
                tx.commit()
                    .with_context(|| format!("commit holder-only {kind} rebuild for '{canon}'"))?;
                Ok(ReconcileOutcome::Reconciled)
            }
        };
    };

    let desired_mask = desired.map(SbAce::as_str);
    let needs_transition = desired_mask != Some(stored.as_str());
    if !force && !needs_transition {
        tx.commit().context("commit skipped ACE reconciliation")?;
        return Ok(ReconcileOutcome::Skipped);
    }

    update_working_ace(&tx, canon, kind, desired)?;
    let want = FileId::from_bytes(&file_id)?;
    match identity(canon, want) {
        IdGate::Match => recompose(&tx, canon, canon, sandbox_sid)
            .with_context(|| format!("reconcile {kind} '{canon}'"))?,
        IdGate::Mismatch if !needs_transition => {
            bail!("force recompose {kind} '{canon}': file identity mismatch")
        }
        IdGate::Mismatch if kind == "grant" => {
            if let Some(at) = locate(&want)? {
                recompose(&tx, canon, &at, sandbox_sid)
                    .with_context(|| format!("reconcile relocated grant '{canon}' at '{at}'"))?;
            }
        }
        IdGate::Mismatch => {
            // Never weaken a substituted path. An ACE that travelled
            // with the original inode may remain, which is fail-closed.
        }
        IdGate::Unreadable => {
            bail!("reconcile {kind} '{canon}': file identity unreadable")
        }
    }
    tx.commit()
        .with_context(|| format!("commit {kind} reconciliation for '{canon}'"))?;
    Ok(ReconcileOutcome::Reconciled)
}

enum IdGate {
    Match,
    Mismatch,
    Unreadable,
}

/// `(path, file_id)` identity check. `path` gone
/// (ERROR_FILE/PATH_NOT_FOUND) or different inode → `Mismatch`;
/// any other open error → `Unreadable` (retryable, not a
/// mismatch).
fn identity_gate(path: &str, expect: FileId) -> IdGate {
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    match path_id::capture_file_id(path) {
        Ok(cur) if cur == expect => IdGate::Match,
        Ok(_) => IdGate::Mismatch,
        Err(e) => {
            let code = e.downcast_ref::<windows::core::Error>().map(|we| we.code());
            let gone = matches!(
                code,
                Some(c) if c == ERROR_FILE_NOT_FOUND.into()
                        || c == ERROR_PATH_NOT_FOUND.into()
            );
            if gone {
                IdGate::Mismatch
            } else {
                eprintln!(
                    "srt-win: '{path}': cannot read file_id ({e:#}); \
                     leaving row; fix access and retry `acl recover`"
                );
                IdGate::Unreadable
            }
        }
    }
}

/// True if `pid` refers to a live process whose CreationTime
/// matches `expected_create_filetime`. PID-recycle guard.
fn is_process_alive(pid: u32, expected_create_filetime: i64) -> bool {
    if pid == std::process::id() {
        return process_create_time(unsafe { GetCurrentProcess() })
            .map(|ct| ct == expected_create_filetime)
            .unwrap_or(true);
    }
    // SYNCHRONIZE so the WaitForSingleObject(0) signaled-check works.
    let h = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    } {
        Ok(h) if !h.is_invalid() => h,
        // A spurious `Ok` with an invalid handle is "uncertain" —
        // treat as ALIVE, matching the conservative stance below
        // (better to leave a stale row than reap a live broker and
        // restore a file it still holds).
        Ok(_) => return true,
        // Treat as DEAD only on ERROR_INVALID_PARAMETER (87) — the
        // "no such PID" signal. Every other error (ACCESS_DENIED,
        // transient low-memory, etc.) is uncertain → ALIVE, so we
        // never reap (and restore a file still used by) a holder
        // that's actually running.
        Err(e) => {
            return (e.code().0 as u32 & 0xFFFF) != 87;
        }
    };
    let h = crate::util::OwnedHandle(h);
    match process_create_time(h.raw()) {
        Ok(ct) => {
            ct == expected_create_filetime
                // An exited process whose handle is still held
                // elsewhere remains openable with the same
                // CreationTime — without this check it reads as
                // alive forever and is never reaped. Only
                // WAIT_OBJECT_0 (= signaled = exited) is "dead";
                // WAIT_TIMEOUT and WAIT_FAILED are both "alive"
                // (uncertain → ALIVE, matching the conservative
                // stance everywhere else in this function).
                && unsafe { WaitForSingleObject(h.raw(), 0) }
                    != WAIT_OBJECT_0
        }
        // Transient GetProcessTimes failure → uncertain → ALIVE,
        // matching the conservative stance everywhere else (better
        // a stale row than a live holder reaped and its files
        // restored under it).
        Err(_) => true,
    }
}

/// Open a process object that is still running. The SYNCHRONIZE
/// handle is checked before returning so registration cannot bind an
/// already-exited holder.
fn open_live_process(pid: u32) -> Result<crate::util::OwnedHandle> {
    let h = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .with_context(|| format!("OpenProcess({pid}) for holder identity"))?;
    if h.is_invalid() {
        bail!("OpenProcess({pid}) returned invalid holder handle");
    }
    let h = crate::util::OwnedHandle(h);
    match unsafe { WaitForSingleObject(h.raw(), 0) } {
        WAIT_OBJECT_0 => bail!("holder pid {pid} has already exited"),
        WAIT_FAILED => {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("WaitForSingleObject(holder pid {pid})"));
        }
        _ => {}
    }
    Ok(h)
}
/// FILETIME (100-ns since 1601-01-01) → i64 for storage.
fn process_create_time(h: HANDLE) -> Result<i64> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user)
            .context("GetProcessTimes")?;
    }
    Ok(((create.dwHighDateTime as i64) << 32) | (create.dwLowDateTime as i64))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_rejects_empty_or_relative() {
        use std::ffi::OsString;
        // Unset or empty → error (var_os returns Some("") for a
        // present-but-empty var, which the old code accepted).
        assert!(state_dir_from(None).is_err());
        assert!(state_dir_from(Some(OsString::from(""))).is_err());
        // Relative → error (would put the broker-only-stamped DB
        // in CWD).
        assert!(state_dir_from(Some(OsString::from("rel"))).is_err());
        // Absolute → ok.
        let ok = state_dir_from(Some(OsString::from(r"C:\Users\u\AppData\Local")));
        assert_eq!(
            ok.unwrap(),
            PathBuf::from(r"C:\Users\u\AppData\Local\sandbox-runtime")
        );
    }

    /// Open an in-memory DB and run `f` against a `Locked` view
    /// (autocommit, like production). Skips the named mutex + dir
    /// stamp (those are integration-tested via the G-rows in
    /// smoke-exec.ps1).
    fn with_mem_db<R>(f: impl FnOnce(&mut Locked) -> R) -> R {
        let conn = open_db_at(std::path::Path::new(":memory:")).unwrap();
        let mut db = Locked {
            conn,
            holder_pid: HolderPid(std::process::id()),
            expected_create_time: None,
        };
        f(&mut db)
    }

    /// Regression: `register_broker` uses ON CONFLICT DO UPDATE,
    /// not INSERT OR REPLACE — the latter would CASCADE-delete
    /// this holder's existing `ace_holders` rows on a second
    /// stamp/grant.
    #[test]
    fn register_broker_refuses_stale_pid_identity() {
        with_mem_db(|db| {
            let actual = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            db.conn
                .execute(
                    "INSERT INTO brokers (pid, process_create_time, started_at) VALUES (?1, ?2, 0)",
                    params![db.holder_pid.0 as i64, actual + 1],
                )
                .unwrap();
            let error = db
                .register_broker()
                .expect_err("stale PID row must fail closed");
            assert!(format!("{error:#}").contains("collides with stale broker identity"));
            let stored: i64 = db
                .conn
                .query_row(
                    "SELECT process_create_time FROM brokers WHERE pid = ?1",
                    params![db.holder_pid.0 as i64],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(stored, actual + 1, "stale row must not be adopted");
        });
    }
    #[test]
    fn second_register_broker_keeps_existing_holds() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            // Two holds via direct INSERT (ensure_ace needs a real
            // file; the CASCADE behavior under test is pure SQL).
            for p in [r"\\?\C:\a", r"\\?\C:\b"] {
                db.conn
                    .execute(
                        "INSERT INTO ace_holders \
                         (canonical_path, kind, pid, want_mask) \
                         VALUES (?1, 'deny', ?2, 'denyRead')",
                        params![p, db.holder_pid.0 as i64],
                    )
                    .unwrap();
            }
            assert_eq!(db.my_ace_holds(None).unwrap().len(), 2);
            // Second batch by the same holder.
            db.register_broker().unwrap();
            // Holds intact (would be 0 with INSERT OR REPLACE).
            assert_eq!(db.my_ace_holds(None).unwrap().len(), 2);
        });
    }

    #[test]
    fn schema_applies_in_memory() {
        with_mem_db(|db| {
            let n: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' \
                     AND name IN ('brokers','working_aces','ace_holders', \
                                  'sandbox_user')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 4);
        });
    }

    fn seed_setup_info(conn: &Connection, sandbox_sid: &str) {
        conn.execute(
            "INSERT INTO sandbox_user \
             (username, user_sid, group_sid, cred, marker_version, created_at_unix) \
             VALUES ('sandbox', ?1, 'S-1-test-group', X'01', 1, 0)",
            params![sandbox_sid],
        )
        .unwrap();
    }

    fn seed_ace(
        conn: &Connection,
        holder_pid: u32,
        holder_create_time: i64,
        path: &str,
        kind: &str,
        mask: &str,
    ) -> FileId {
        let mut id128 = [9; 16];
        id128[..4].copy_from_slice(&holder_pid.to_le_bytes());
        let file_id = FileId {
            volume_serial: 7,
            id128,
        };
        conn.execute(
            "INSERT INTO brokers (pid, process_create_time, started_at) VALUES (?1, ?2, 0)",
            params![holder_pid as i64, holder_create_time],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO working_aces (canonical_path, kind, file_id, mask) VALUES (?1, ?2, ?3, ?4)",
            params![path, kind, file_id.as_bytes().as_slice(), mask],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ace_holders (canonical_path, kind, pid, want_mask) VALUES (?1, ?2, ?3, ?4)",
            params![path, kind, holder_pid as i64, mask],
        )
        .unwrap();
        file_id
    }

    fn seed_grant(
        conn: &Connection,
        holder_pid: u32,
        holder_create_time: i64,
        path: &str,
    ) -> FileId {
        seed_ace(conn, holder_pid, holder_create_time, path, "grant", "read")
    }

    fn assert_ace_row_counts(conn: &Connection, path: &str, kind: &str, expected: (i64, i64)) {
        let working: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM working_aces WHERE canonical_path = ?1 AND kind = ?2",
                params![path, kind],
                |row| row.get(0),
            )
            .unwrap();
        let holders: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ace_holders WHERE canonical_path = ?1 AND kind = ?2",
                params![path, kind],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((working, holders), expected);
    }
    fn assert_grant_rows_remain(conn: &Connection, path: &str) {
        let working: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM working_aces \
                 WHERE canonical_path = ?1 AND kind = 'grant'",
                params![path],
                |row| row.get(0),
            )
            .unwrap();
        let holders: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ace_holders \
                 WHERE canonical_path = ?1 AND kind = 'grant'",
                params![path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((working, holders), (1, 1));
    }

    #[test]
    fn release_recompose_failure_rolls_back_tracking_rows() {
        with_mem_db(|db| {
            let path = r"\\?\C:\retry-release.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_grant(&db.conn, db.holder_pid.0, ct, path);

            let error = db
                .release_one_ace_with(
                    path,
                    "grant",
                    "S-1-test",
                    |_, _| IdGate::Match,
                    |_| Ok(None),
                    |_, _, _, _| Err(anyhow::anyhow!("injected recompose failure")),
                )
                .expect_err("release must propagate recompose failure");
            assert!(format!("{error:#}").contains("injected recompose failure"));
            assert_grant_rows_remain(&db.conn, path);
        });
    }

    #[test]
    fn moved_grant_lookup_failure_rolls_back_tracking_rows() {
        with_mem_db(|db| {
            let path = r"\\?\C:\retry-moved.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_grant(&db.conn, db.holder_pid.0, ct, path);

            let error = db
                .release_one_ace_with(
                    path,
                    "grant",
                    "S-1-test",
                    |_, _| IdGate::Mismatch,
                    |_| Err(anyhow::anyhow!("injected relocation lookup failure")),
                    |_, _, _, _| Ok(()),
                )
                .expect_err("release must propagate relocation lookup failure");
            assert!(format!("{error:#}").contains("injected relocation lookup failure"));
            assert_grant_rows_remain(&db.conn, path);
        });
    }

    #[test]
    fn moved_grant_recompose_failure_rolls_back_tracking_rows() {
        with_mem_db(|db| {
            let path = r"\\?\C:\retry-moved-recompose.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_grant(&db.conn, db.holder_pid.0, ct, path);
            let error = db
                .release_one_ace_with(
                    path,
                    "grant",
                    "S-1-test",
                    |_, _| IdGate::Mismatch,
                    |_| Ok(Some(r"\\?\C:\moved.exe".to_string())),
                    |_, _, _, _| Err(anyhow::anyhow!("injected moved recompose failure")),
                )
                .expect_err("moved cleanup failure must propagate");
            assert!(format!("{error:#}").contains("injected moved recompose failure"));
            assert_grant_rows_remain(&db.conn, path);
        });
    }
    #[test]
    fn deny_holder_commit_failure_does_not_weaken_acl() {
        with_mem_db(|db| {
            let path = r"\\?\C:\deny-holder-commit.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_ace(&db.conn, db.holder_pid.0, ct, path, "deny", "denyRead");
            let recomposed = std::cell::Cell::new(false);

            let error = db
                .release_one_deny_with(
                    path,
                    "deny",
                    "S-1-test",
                    |_, _| IdGate::Match,
                    |_, _, _, _| {
                        recomposed.set(true);
                        Ok(())
                    },
                    || Err(anyhow::anyhow!("injected holder commit failure")),
                    |_| Ok(()),
                    || Ok(()),
                )
                .expect_err("holder transition failure must abort before ACL change");

            assert!(format!("{error:#}").contains("injected holder commit failure"));
            assert!(!recomposed.get(), "ACL convergence must not run");
            assert_ace_row_counts(&db.conn, path, "deny", (1, 1));
        });
    }

    #[test]
    fn deny_post_recompose_commit_failure_is_retryable() {
        with_mem_db(|db| {
            let path = r"\\?\C:\deny-state-commit.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_setup_info(&db.conn, "S-1-test");
            seed_ace(&db.conn, db.holder_pid.0, ct, path, "deny", "denyRead");
            let recompose_calls = std::cell::Cell::new(0u32);

            let error = db
                .release_one_deny_with(
                    path,
                    "deny",
                    "S-1-test",
                    |_, _| IdGate::Match,
                    |_, _, _, _| {
                        recompose_calls.set(recompose_calls.get() + 1);
                        Ok(())
                    },
                    || Ok(()),
                    |_| Ok(()),
                    || Err(anyhow::anyhow!("injected state commit failure")),
                )
                .expect_err("post-recompose commit failure must be surfaced");

            assert!(format!("{error:#}").contains("injected state commit failure"));
            assert_eq!(recompose_calls.get(), 1);
            assert_ace_row_counts(&db.conn, path, "deny", (1, 0));

            let report = crash_recovery_with(
                &db.conn,
                false,
                |_, _| true,
                |_| panic!("capture must not run"),
                |_, _| IdGate::Match,
                |_| Ok(None),
                |_, _, _, _| {
                    recompose_calls.set(recompose_calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(report.dead_brokers, 0);
            assert_eq!(report.aces_revoked, 1);
            assert_eq!(report.cleanup_failures, 0);
            assert_eq!(recompose_calls.get(), 2);
            assert_ace_row_counts(&db.conn, path, "deny", (0, 0));
        });
    }

    #[test]
    fn crash_recovery_isolates_poisoned_path_and_continues() {
        with_mem_db(|db| {
            let poison = r"\\?\C:\poison-recovery.exe";
            let good = r"\\?\C:\good-recovery.exe";
            let dead_poison_pid = 4_000_000_000u32;
            let dead_good_pid = 3_999_999_999u32;
            seed_setup_info(&db.conn, "S-1-test");
            seed_grant(&db.conn, dead_poison_pid, 1, poison);
            seed_grant(&db.conn, dead_good_pid, 2, good);

            let report = crash_recovery_with(
                &db.conn,
                false,
                |_, _| false,
                |_| panic!("capture must not run"),
                |_, _| IdGate::Match,
                |_| Ok(None),
                |_, _, path, _| {
                    if path == poison {
                        Err(anyhow::anyhow!("injected poison path"))
                    } else {
                        Ok(())
                    }
                },
            )
            .expect("a poisoned path must not abort recovery");

            assert_eq!(report.dead_brokers, 2);
            assert_eq!(report.aces_revoked, 1);
            assert_eq!(report.cleanup_failures, 1);
            assert_ace_row_counts(&db.conn, poison, "grant", (1, 0));
            assert_ace_row_counts(&db.conn, good, "grant", (0, 0));
            let brokers: i64 = db
                .conn
                .query_row("SELECT COUNT(*) FROM brokers", [], |row| row.get(0))
                .unwrap();
            assert_eq!(brokers, 0);

            db.register_broker()
                .expect("current operation must proceed after isolated failure");
        });
    }

    #[test]
    fn force_recomposes_even_when_tracking_matches_holders() {
        with_mem_db(|db| {
            let path = r"\\?\C:\force-recompose.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_setup_info(&db.conn, "S-1-test");
            seed_grant(&db.conn, db.holder_pid.0, ct, path);
            let calls = std::cell::Cell::new(0u32);

            let normal = crash_recovery_with(
                &db.conn,
                false,
                |_, _| true,
                |_| panic!("capture must not run"),
                |_, _| IdGate::Match,
                |_| Ok(None),
                |_, _, _, _| {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(normal.aces_revoked, 0);
            assert_eq!(calls.get(), 0);

            let forced = crash_recovery_with(
                &db.conn,
                true,
                |_, _| true,
                |_| panic!("capture must not run"),
                |_, _| IdGate::Match,
                |_| Ok(None),
                |_, _, _, _| {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(forced.aces_revoked, 1);
            assert_eq!(forced.cleanup_failures, 0);
            assert_eq!(calls.get(), 1);
            assert_ace_row_counts(&db.conn, path, "grant", (1, 1));
        });
    }
    #[test]
    fn recovery_orders_parent_fdc_shallowest_first() {
        let mut keys = [
            (r"\\?\C:\root\child".to_string(), "deny_fdc".to_string()),
            (r"\\?\C:\root".to_string(), "deny".to_string()),
            (r"\\?\C:\root".to_string(), "deny_fdc".to_string()),
        ];
        keys.sort_by(recovery_key_cmp);
        assert_eq!(
            keys[0],
            (r"\\?\C:\root".to_string(), "deny_fdc".to_string())
        );
        assert_eq!(
            keys[1],
            (r"\\?\C:\root\child".to_string(), "deny_fdc".to_string())
        );
        assert_eq!(keys[2], (r"\\?\C:\root".to_string(), "deny".to_string()));
    }

    #[test]
    fn same_parent_fdc_stays_until_last_holder_releases() {
        with_mem_db(|db| {
            let parent = r"\\?\C:\shared-parent";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_ace(&db.conn, db.holder_pid.0, ct, parent, "deny_fdc", "fdc");
            let other_pid = 3_999_999_996u32;
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO brokers ",
                        "(pid, process_create_time, started_at) ",
                        "VALUES (?1, 1, 0)"
                    ),
                    params![other_pid as i64],
                )
                .unwrap();
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO ace_holders ",
                        "(canonical_path, kind, pid, want_mask) ",
                        "VALUES (?1, 'deny_fdc', ?2, 'fdc')"
                    ),
                    params![parent, other_pid as i64],
                )
                .unwrap();

            let first = db
                .release_one_deny_with(
                    parent,
                    "deny_fdc",
                    "S-1-test",
                    |_, _| IdGate::Match,
                    |conn, source, target, _| {
                        let set = sandbox_ace_set_for_object(conn, source, target)?;
                        assert!(set.deny_fdc);
                        Ok(())
                    },
                    || Ok(()),
                    |_| Ok(()),
                    || Ok(()),
                )
                .unwrap();
            assert_eq!(first, AceRelease::StillHeld);
            assert_ace_row_counts(&db.conn, parent, "deny_fdc", (1, 1));

            db.holder_pid = HolderPid(other_pid);
            let last = db
                .release_one_deny_with(
                    parent,
                    "deny_fdc",
                    "S-1-test",
                    |_, _| IdGate::Match,
                    |conn, source, target, _| {
                        let set = sandbox_ace_set_for_object(conn, source, target)?;
                        assert!(!set.deny_fdc);
                        Ok(())
                    },
                    || Ok(()),
                    |_| Ok(()),
                    || Ok(()),
                )
                .unwrap();
            assert_eq!(last, AceRelease::Revoked);
            assert_ace_row_counts(&db.conn, parent, "deny_fdc", (0, 0));
        });
    }

    #[test]
    fn moved_grant_cleanup_preserves_original_deny() {
        with_mem_db(|db| {
            let source = r"\\?\C:\moved-grant-source.exe";
            let target = r"\\?\C:\moved-grant-target.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            let file_id = seed_grant(&db.conn, db.holder_pid.0, ct, source);
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO working_aces ",
                        "(canonical_path, kind, file_id, mask) ",
                        "VALUES (?1, 'deny', ?2, 'denyRead')"
                    ),
                    params![source, file_id.as_bytes().as_slice()],
                )
                .unwrap();
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO ace_holders ",
                        "(canonical_path, kind, pid, want_mask) ",
                        "VALUES (?1, 'deny', ?2, 'denyRead')"
                    ),
                    params![source, db.holder_pid.0 as i64],
                )
                .unwrap();

            let outcome = db
                .release_one_ace_with(
                    source,
                    "grant",
                    "S-1-test",
                    |_, _| IdGate::Mismatch,
                    |_| Ok(Some(target.to_string())),
                    |conn, original, current, _| {
                        assert_eq!(original, source);
                        assert_eq!(current, target);
                        let set = sandbox_ace_set_for_object(conn, original, current)?;
                        assert_eq!(set.grant, None);
                        assert_eq!(set.deny, Some(crate::acl::DenyMask::ReadDeny));
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(
                outcome,
                AceRelease::Relocated {
                    moved_to: target.to_string()
                }
            );
            assert_ace_row_counts(&db.conn, source, "grant", (0, 0));
            assert_ace_row_counts(&db.conn, source, "deny", (1, 1));
        });
    }

    #[test]
    fn deny_phase_two_reloads_holder_added_between_phases() {
        with_mem_db(|db| {
            let path = r"\\?\C:\deny-cross-session.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_ace(&db.conn, db.holder_pid.0, ct, path, "deny", "denyRead");
            let other_pid = 3_999_999_998u32;

            let outcome = db
                .release_one_deny_with(
                    path,
                    "deny",
                    "S-1-test",
                    |_, _| IdGate::Match,
                    |conn, source, target, _| {
                        let set = sandbox_ace_set_for_object(conn, source, target)?;
                        assert_eq!(set.deny, Some(crate::acl::DenyMask::ReadDeny));
                        Ok(())
                    },
                    || Ok(()),
                    |conn| {
                        conn.execute(
                            concat!(
                                "INSERT INTO brokers ",
                                "(pid, process_create_time, started_at) ",
                                "VALUES (?1, 1, 0)"
                            ),
                            params![other_pid as i64],
                        )?;
                        conn.execute(
                            concat!(
                                "INSERT INTO ace_holders ",
                                "(canonical_path, kind, pid, want_mask) ",
                                "VALUES (?1, 'deny', ?2, 'denyRead')"
                            ),
                            params![path, other_pid as i64],
                        )?;
                        Ok(())
                    },
                    || Ok(()),
                )
                .unwrap();

            assert_eq!(outcome, AceRelease::StillHeld);
            assert_ace_row_counts(&db.conn, path, "deny", (1, 1));
        });
    }

    #[test]
    fn recovery_reloads_desired_inside_immediate_transaction() {
        with_mem_db(|db| {
            let path = r"\\?\C:\recovery-current-holder.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_setup_info(&db.conn, "S-1-test");
            seed_ace(&db.conn, db.holder_pid.0, ct, path, "deny", "denyWrite");
            let other_pid = 3_999_999_997u32;
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO brokers ",
                        "(pid, process_create_time, started_at) ",
                        "VALUES (?1, 1, 0)"
                    ),
                    params![other_pid as i64],
                )
                .unwrap();
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO ace_holders ",
                        "(canonical_path, kind, pid, want_mask) ",
                        "VALUES (?1, 'deny', ?2, 'denyRead')"
                    ),
                    params![path, other_pid as i64],
                )
                .unwrap();

            let outcome = reconcile_working_ace_with(
                &db.conn,
                path,
                "deny",
                false,
                "S-1-test",
                &|_| panic!("capture must not run"),
                &|_, _| IdGate::Match,
                &|_| Ok(None),
                &|conn, source, target, _| {
                    let set = sandbox_ace_set_for_object(conn, source, target)?;
                    assert_eq!(set.deny, Some(crate::acl::DenyMask::ReadDeny));
                    Ok(())
                },
            )
            .unwrap();

            assert_eq!(outcome, ReconcileOutcome::Reconciled);
            let stored: String = db
                .conn
                .query_row(
                    concat!(
                        "SELECT mask FROM working_aces ",
                        "WHERE canonical_path = ?1 AND kind = 'deny'"
                    ),
                    params![path],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(stored, "denyRead");
        });
    }

    #[test]
    fn holder_only_grant_is_retained_without_current_path_tofu() {
        with_mem_db(|db| {
            let path = r"\\?\C:\holder-only-grant.exe";
            seed_setup_info(&db.conn, "S-1-test");
            db.register_broker().unwrap();
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO ace_holders ",
                        "(canonical_path, kind, pid, want_mask) ",
                        "VALUES (?1, 'grant', ?2, 'read')"
                    ),
                    params![path, db.holder_pid.0 as i64],
                )
                .unwrap();

            let report = crash_recovery_with(
                &db.conn,
                false,
                |_, _| true,
                |_| panic!("holder-only grant must not capture current file identity"),
                |_, _| IdGate::Match,
                |_| Ok(None),
                |_, _, _, _| panic!("holder-only grant must not touch the filesystem"),
            )
            .unwrap();

            assert_eq!(report.aces_revoked, 0);
            assert_eq!(report.cleanup_failures, 1);
            assert_ace_row_counts(&db.conn, path, "grant", (0, 1));
        });
    }

    #[test]
    fn holder_only_deny_is_rebuilt_conservatively() {
        with_mem_db(|db| {
            let path = r"\\?\C:\holder-only-deny.exe";
            seed_setup_info(&db.conn, "S-1-test");
            db.register_broker().unwrap();
            db.conn
                .execute(
                    concat!(
                        "INSERT INTO ace_holders ",
                        "(canonical_path, kind, pid, want_mask) ",
                        "VALUES (?1, 'deny', ?2, 'denyRead')"
                    ),
                    params![path, db.holder_pid.0 as i64],
                )
                .unwrap();
            let file_id = FileId {
                volume_serial: 7,
                id128: [42; 16],
            };

            let report = crash_recovery_with(
                &db.conn,
                false,
                |_, _| true,
                |_| Ok(file_id),
                |_, _| IdGate::Match,
                |_| Ok(None),
                |conn, source, target, _| {
                    let set = sandbox_ace_set_for_object(conn, source, target)?;
                    assert_eq!(set.deny, Some(crate::acl::DenyMask::ReadDeny));
                    Ok(())
                },
            )
            .unwrap();

            assert_eq!(report.aces_revoked, 1);
            assert_eq!(report.cleanup_failures, 0);
            assert_ace_row_counts(&db.conn, path, "deny", (1, 1));
        });
    }

    #[test]
    fn release_rejects_wrong_sandbox_sid_without_mutation() {
        with_mem_db(|db| {
            let path = r"\\?\C:\wrong-sid-release.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_setup_info(&db.conn, "S-1-installed");
            seed_grant(&db.conn, db.holder_pid.0, ct, path);

            let error = db
                .release_aces("S-1-other", KIND_GRANT)
                .expect_err("wrong sandbox SID must fail closed");
            assert!(format!("{error:#}").contains("sandbox user SID mismatch"));
            assert_grant_rows_remain(&db.conn, path);
        });
    }

    #[test]
    fn force_recovery_never_bypasses_file_identity() {
        with_mem_db(|db| {
            let path = r"\\?\C:\force-identity-mismatch.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_setup_info(&db.conn, "S-1-test");
            seed_grant(&db.conn, db.holder_pid.0, ct, path);

            let report = crash_recovery_with(
                &db.conn,
                true,
                |_, _| true,
                |_| panic!("capture must not run"),
                |_, _| IdGate::Mismatch,
                |_| panic!("force mismatch without transition must not relocate"),
                |_, _, _, _| panic!("force mismatch must not recompose"),
            )
            .unwrap();

            assert_eq!(report.aces_revoked, 0);
            assert_eq!(report.cleanup_failures, 1);
            assert_grant_rows_remain(&db.conn, path);
        });
    }

    #[test]
    fn bound_identity_rejects_creation_time_mismatch_without_mutation() {
        with_mem_db(|db| {
            let path = r"\\?\C:\bound-holder.exe";
            let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
            seed_grant(&db.conn, db.holder_pid.0, ct, path);
            db.expected_create_time = Some(ct + 1);

            let error = db
                .release_aces("S-1-test", KIND_GRANT)
                .expect_err("mismatched holder identity must fail closed");
            assert!(format!("{error:#}").contains("no longer identifies"));
            assert_grant_rows_remain(&db.conn, path);
        });
    }
    #[test]
    fn aliveness_self_is_alive() {
        let ct = process_create_time(unsafe { GetCurrentProcess() }).unwrap();
        assert!(is_process_alive(std::process::id(), ct));
        // The same PID with a different creation time is a recycled
        // process identity and must be treated as dead.
        assert!(!is_process_alive(std::process::id(), ct + 1));
    }

    #[test]
    fn aliveness_bogus_pid_is_dead() {
        // PID 0x7FFF_FFFE is well above any plausible live PID.
        assert!(!is_process_alive(0x7FFF_FFFE, 0));
    }
}
