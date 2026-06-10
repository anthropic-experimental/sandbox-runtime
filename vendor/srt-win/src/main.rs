//! `srt-win` — CLI for the sandbox-runtime Windows network fence.
//!
//! Subcommands:
//!   install | uninstall                — convenience: group + WFP in one
//!                                         elevated call (one UAC prompt)
//!   group  create | status | delete    — manage the discriminator local group
//!   wfp    install | status | uninstall — manage the persistent WFP filters
//!   exec   -- <target> [args...]       — spawn under the deny-only-group
//!                                         token + job + hardening stack
//!
//! `status` subcommands write one line of JSON to stdout and exit 0.
//! Mutating subcommands require elevation and write human-readable
//! progress to stderr. `exec` propagates the child's exit code.

use clap::{Args, Parser, Subcommand};

/// Default group name. Lives here (not in the `#[cfg(windows)]`
/// library crate) so the clap-derive CLI structs compile on
/// non-Windows hosts where the library is empty.
const DEFAULT_GROUP_NAME: &str = "sandbox-runtime-net";

#[derive(Parser)]
#[command(name = "srt-win", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Group create + WFP install in one elevated step.
    ///
    /// Self-elevates via UAC if not already running as admin
    /// (one prompt; the elevated child does the work and the
    /// parent relays its exit code). With the machine-wide
    /// filter design, a token where the group is **absent**
    /// (i.e. this session, before logout) matches filter-0
    /// (PERMIT non-members) — so installing the WFP filters
    /// here does NOT break the user's network. Logout is still
    /// required before `srt-win exec` works (the broker
    /// pre-flight needs the group **enabled** to build a
    /// deny-only child token), but the install itself is one
    /// safe step → one UAC prompt.
    ///
    /// Equivalent to `group create --name <N> --user-sid <U>`
    /// followed by `wfp install --name <N> …`. With `--group-sid`,
    /// the group is assumed to already exist (e.g. provisioned by
    /// domain GPO) and only the filters are installed.
    ///
    /// Exit codes:
    ///   0  — installed (or already installed with the same
    ///        port-range; no changes)
    ///   10 — UAC prompt cancelled by the user
    ///   11 — group create / lookup failed
    ///   12 — WFP filter install failed
    ///   13 — already installed under this sublayer with a
    ///        DIFFERENT port-range; pass `--force` to replace
    ///   1  — other error (parse, elevation check, etc.)
    Install {
        #[command(flatten)]
        group: GroupRef,
        /// User SID to add to the group (default: current user).
        /// Ignored with `--group-sid`.
        #[arg(long)]
        user_sid: Option<String>,
        /// Sublayer GUID (default: compile-time constant).
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range (`LOW-HIGH`, default 60080-60089).
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
        /// Replace an existing install whose port-range differs
        /// (otherwise exits 13).
        #[arg(long)]
        force: bool,
    },
    /// Remove the srt-win WFP filters under the sublayer.
    ///
    /// Self-elevates via UAC if not already admin. Does NOT
    /// delete the discriminator group — use `srt-win group
    /// delete --name <N>` for that explicitly.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Manage the local discriminator group.
    Group {
        #[command(subcommand)]
        sub: GroupCmd,
    },
    /// Manage the persistent WFP filters.
    Wfp {
        #[command(subcommand)]
        sub: WfpCmd,
    },
    /// Spawn a process under the deny-only-group sandbox.
    ///
    /// Builds a restricted token (group + Admins flipped deny-only,
    /// LUA, Medium IL, all privs stripped except SeChangeNotify),
    /// self-protects the broker, assigns the child to a
    /// kill-on-close job with full UI lockdown, places it on a
    /// non-interactive desktop, applies process-mitigation
    /// policies + an explicit handle whitelist, and waits for it
    /// to exit. Propagates the child's exit code.
    ///
    /// The child inherits this process's environment verbatim — proxy
    /// configuration is single-sourced by the caller, which sets the
    /// proxy vars (TS `generateProxyEnvVars`) in the environment it
    /// spawns `srt-win exec` with. There are intentionally no
    /// `--http-proxy` / `--socks-proxy` flags and no proxy fallback.
    Exec {
        #[command(flatten)]
        group: GroupRef,
        /// Skip the "is the group enabled in the broker's token"
        /// pre-flight. **Fail-open** — the WFP fence depends on
        /// that membership; with this set the child may run with
        /// weaker isolation if the install was incomplete.
        /// Surfaced as a flag (not an env var) so the bypass is
        /// intentional and not accidentally inherited. Use ONLY
        /// in ephemeral CI runners that create the group in-job
        /// and cannot logout/login mid-run.
        #[arg(long)]
        skip_group_check: bool,
        /// Target executable followed by its arguments. Use `--`
        /// to terminate srt-win's own option parsing.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            num_args = 1..,
        )]
        target: Vec<String>,
    },
}

/// Group resolution: either by name (looked up via
/// `LookupAccountNameW`) or directly by SID. If both are given the
/// SID wins; `group create`/`delete` always need a name.
#[derive(Args, Clone)]
struct GroupRef {
    /// Group name (local or `DOMAIN\name`). Default
    /// `sandbox-runtime-net`.
    #[arg(long, default_value = DEFAULT_GROUP_NAME)]
    name: String,
    /// Group SID (`S-1-…`). Overrides `--name` for SID resolution.
    /// Use when the group is provisioned by external tooling and name
    /// lookup may be unreliable.
    #[arg(long)]
    group_sid: Option<String>,
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create the local group and add the current (or `--user-sid`)
    /// user to it. Idempotent. Self-elevates via UAC if not already
    /// admin.
    Create {
        #[command(flatten)]
        group: GroupRef,
        /// User SID to add (default: current user).
        #[arg(long)]
        user_sid: Option<String>,
    },
    /// Print group state as JSON: `{state, sid?, warning?}`.
    Status {
        #[command(flatten)]
        group: GroupRef,
    },
    /// Delete the local group. Idempotent. Self-elevates via UAC if
    /// not already admin.
    Delete {
        #[command(flatten)]
        group: GroupRef,
    },
}

#[derive(Subcommand)]
enum WfpCmd {
    /// Install (or refresh) the machine-wide persistent WFP filters
    /// keyed on the group SID. Idempotent. Self-elevates via UAC if
    /// not already admin.
    Install {
        #[command(flatten)]
        group: GroupRef,
        /// Sublayer GUID. Default is the compile-time constant; pass
        /// when integrating with externally-managed WFP state.
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range the sandboxed child may reach
        /// (`LOW-HIGH`, inclusive; default 60080-60089). The host
        /// http/socks proxies bind inside this range on Windows.
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
    },
    /// Print WFP fence state as JSON: `{state, filters,
    /// port_range?}`. Filters are identified by their
    /// `providerData` tag, so only `--sublayer-guid` is relevant.
    Status {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Remove every srt-win-tagged WFP filter under the sublayer.
    /// Self-elevates via UAC if not already admin.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
}

#[cfg(windows)]
fn main() {
    if let Err(e) = run() {
        eprintln!("srt-win: error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use serde_json::json;
    use srt_win::{sid, wfp};

    let cli = Cli::parse();

    // Validate a caller-supplied SID string up front so a typo
    // surfaces as "invalid --<flag>" rather than an SDDL parse
    // error three calls deep. Returns the CANONICAL `S-1-…` form
    // (round-tripped through ConvertSidToStringSidW) so SDDL
    // shorthands like `BA` or lower-case `s-1-…` collapse to a
    // single comparable representation; downstream
    // `eq_ignore_ascii_case("S-1-5-32-544")` dedup checks rely on
    // that.
    let canonicalize_sid =
        |flag: &str, s: &str| -> anyhow::Result<String> {
            let p = sid::LocalPsid::from_string(s)
                .with_context(|| format!("invalid --{flag} '{s}'"))?;
            sid::psid_to_string(p.as_psid())
                .with_context(|| format!("canonicalize --{flag} '{s}'"))
        };
    let resolve_group_sid = |g: &GroupRef| -> anyhow::Result<String> {
        if let Some(s) = &g.group_sid {
            return canonicalize_sid("group-sid", s);
        }
        sid::lookup_account_sid(&g.name)
            .with_context(|| format!("resolve group '{}'", g.name))
    };
    let resolve_sublayer = |s: &Option<String>| -> anyhow::Result<windows::core::GUID> {
        match s {
            Some(g) => wfp::parse_guid(g),
            None => Ok(wfp::DEFAULT_SUBLAYER_GUID),
        }
    };

    match cli.cmd {
        // ─── install / uninstall (convenience) ─────────────────────
        Cmd::Install {
            group,
            user_sid,
            sublayer_guid,
            proxy_port_range,
            force,
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            // Idempotency / conflict pre-check. If filters are
            // already installed under this sublayer with the SAME
            // port-range, this is a no-op (exit 0). With a
            // DIFFERENT range and no --force, refuse (exit 13) so
            // an unintended config drift surfaces instead of
            // silently overwriting. A pre-existing install whose
            // tags lack a port_range (legacy) is treated as
            // "different" and requires --force.
            if !force
                && let Ok(st) = wfp::filter_status(&sl)
                && st.state == "installed"
            {
                let want = [range.0, range.1];
                if st.port_range == Some(want) {
                    eprintln!(
                        "srt-win: already installed (sublayer={sl:?}, \
                         port_range={}-{}, filters={}); no changes",
                        range.0, range.1, st.filters,
                    );
                    return Ok(());
                }
                let have = st
                    .port_range
                    .map(|[l, h]| format!("{l}-{h}"))
                    .unwrap_or_else(|| "<unknown>".into());
                eprintln!(
                    "srt-win: error: already installed under sublayer \
                     {sl:?} with port_range={have}; pass --force to \
                     replace, or run `srt-win uninstall` first."
                );
                std::process::exit(13);
            }
            // With --group-sid the group is externally managed;
            // just canonicalize. With --name (or the default),
            // create the local group, add the user, then resolve
            // the SID. Failures here exit 11.
            let group_step = || -> anyhow::Result<(String, String)> {
                if let Some(s) = &group.group_sid {
                    let g = canonicalize_sid("group-sid", s)?;
                    Ok((g.clone(), g))
                } else {
                    let user = match &user_sid {
                        Some(s) => canonicalize_sid("user-sid", s)?,
                        None => sid::current_user_sid()
                            .context("resolve current user")?,
                    };
                    wfp::ensure_group(&group.name, &user)?;
                    let g = sid::lookup_account_sid(&group.name)?;
                    Ok((group.name.clone(), g))
                }
            };
            let (label, gsid) = match group_step() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("srt-win: error: group step: {e:#}");
                    std::process::exit(11);
                }
            };
            if let Err(e) = wfp::install_filters(&sl, &gsid, range) {
                eprintln!("srt-win: error: WFP install: {e:#}");
                std::process::exit(12);
            }
            eprintln!(
                "srt-win: installed (group={label} sid={gsid}, sublayer={sl:?}, \
                 proxy_port_range={}-{}, filters=8)",
                range.0, range.1,
            );
            eprintln!(
                "srt-win: NOTE — log out and back in before running \
                 `srt-win exec` (the group SID enters TokenGroups at \
                 logon; your network is unaffected meanwhile)."
            );
        }
        Cmd::Uninstall { sublayer_guid } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            eprintln!(
                "srt-win: uninstalled ({n} filter(s) removed). \
                 Group is left intact — run `srt-win group delete` \
                 to remove it."
            );
        }

        // ─── group ─────────────────────────────────────────────────
        Cmd::Group { sub: GroupCmd::Create { group, user_sid } } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            if group.group_sid.is_some() {
                return Err(anyhow!(
                    "`group create` needs --name; --group-sid is for \
                     referencing an existing group"
                ));
            }
            let user = match &user_sid {
                Some(s) => canonicalize_sid("user-sid", s)?,
                None => sid::current_user_sid()
                    .context("resolve current user")?,
            };
            wfp::ensure_group(&group.name, &user)?;
            let gsid = sid::lookup_account_sid(&group.name)?;
            eprintln!(
                "srt-win: group '{}' present (sid={gsid}); user {user} added",
                group.name
            );
            eprintln!(
                "srt-win: NOTE — the group SID enters TokenGroups at logon. \
                 Log out and back in before running `srt-win exec`."
            );
        }
        Cmd::Group { sub: GroupCmd::Status { group } } => {
            // Resolve SID first; if that fails the group is absent.
            let gsid = match &group.group_sid {
                Some(s) => {
                    // --group-sid bypasses the name lookup, so do a
                    // reverse lookup to distinguish "exists but not on
                    // this token yet" from "no such account at all".
                    // Tolerate transient lookup failure (domain
                    // unreachable) by falling through to the token
                    // check.
                    match sid::sid_account_exists(s) {
                        Ok(sid::SidExistence::Unmapped) => {
                            println!("{}", json!({"state": "absent"}));
                            return Ok(());
                        }
                        Ok(_) => {}
                        Err(e) => {
                            // Malformed SID string.
                            println!(
                                "{}",
                                json!({"state": "absent", "error": e.to_string()})
                            );
                            return Ok(());
                        }
                    }
                    s.clone()
                }
                None => match sid::lookup_account_sid(&group.name) {
                    Ok(s) => s,
                    Err(_) => {
                        println!("{}", json!({"state": "absent"}));
                        return Ok(());
                    }
                },
            };
            let out = match sid::group_state_for_self(&gsid)? {
                sid::GroupState::Enabled => {
                    json!({"state": "ready", "sid": gsid})
                }
                sid::GroupState::Absent => {
                    json!({"state": "created-not-on-token", "sid": gsid})
                }
                sid::GroupState::DenyOnly => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group is deny-only in this token — running \
                                inside a sandbox child?"
                }),
                sid::GroupState::Present => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group present but neither enabled nor \
                                deny-only (unexpected)"
                }),
            };
            println!("{out}");
        }
        Cmd::Group { sub: GroupCmd::Delete { group } } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            if group.group_sid.is_some() {
                return Err(anyhow!(
                    "`group delete` needs --name; cannot delete by SID"
                ));
            }
            wfp::delete_group(&group.name)?;
            eprintln!("srt-win: group '{}' deleted (if it existed)", group.name);
        }

        // ─── wfp ───────────────────────────────────────────────────
        Cmd::Wfp {
            sub:
                WfpCmd::Install {
                    group,
                    sublayer_guid,
                    proxy_port_range,
                },
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let gsid = resolve_group_sid(&group)?;
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            wfp::install_filters(&sl, &gsid, range)?;
            eprintln!(
                "srt-win: WFP filters installed (group_sid={gsid}, \
                 sublayer={sl:?}, proxy_port_range={}-{})",
                range.0, range.1,
            );
        }
        Cmd::Wfp { sub: WfpCmd::Status { sublayer_guid } } => {
            let sl = resolve_sublayer(&sublayer_guid)?;
            let st = wfp::filter_status(&sl)?;
            println!("{}", serde_json::to_string(&st)?);
        }
        Cmd::Wfp { sub: WfpCmd::Uninstall { sublayer_guid } } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            eprintln!("srt-win: removed {n} WFP filter(s)");
        }

        // ─── exec ──────────────────────────────────────────────────
        Cmd::Exec {
            group,
            skip_group_check,
            target,
        } => {
            use srt_win::launch;
            let gsid = resolve_group_sid(&group)?;
            // `target` is `required, num_args=1..` so non-empty.
            let exe = std::path::PathBuf::from(&target[0]);
            let args = &target[1..];
            let spec = launch::ExecSpec {
                group_sid: &gsid,
                skip_group_check,
                target_exe: &exe,
                target_args: args,
            };
            let code = launch::run(&spec)?;
            // Propagate the child's exit code verbatim.
            std::process::exit(code as i32);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_elevated() -> anyhow::Result<bool> {
    use anyhow::Context;
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken,
    };
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
            .context("OpenProcessToken")?;
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let r = GetTokenInformation(
            tok,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenElevation)")?;
        Ok(elev.TokenIsElevated != 0)
    }
}

/// Hard elevation gate: returns an error (no UAC relaunch) when not
/// admin. The granular admin mutators now self-elevate via
/// [`maybe_self_elevate`], so this currently has no caller — it's
/// retained as the non-interactive counterpart for `acl recover`
/// (a later batch), hence `allow(dead_code)`.
#[cfg(windows)]
#[allow(dead_code)]
fn require_elevated() -> anyhow::Result<()> {
    if is_elevated()? {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "this command requires elevation — run from an \
             administrator prompt"
        ))
    }
}

/// If not already elevated, re-launch ourselves with the same
/// argv via `ShellExecuteExW(verb="runas")` — one UAC prompt —
/// wait for the elevated child, and return its exit code. If
/// already elevated, returns `Ok(None)` and the caller proceeds
/// in-process. If the user cancels the UAC dialog
/// (`ERROR_CANCELLED`), exits with code **10** so the caller's
/// exit-code contract holds without the caller needing a
/// separate match.
///
/// The elevated child runs in its own (hidden) console, so its
/// stdout/stderr are NOT relayed to the parent. For
/// `install`/`uninstall` that's acceptable: the exit code is the
/// contract; the convenience commands' stderr is informational
/// only. The granular `group create|delete` and `wfp
/// install|uninstall` admin mutators call this too; their stderr is
/// likewise informational. Read-only subcommands (`group status`,
/// `wfp status`, `exec`) run as the broker and never self-elevate.
#[cfg(windows)]
fn maybe_self_elevate() -> anyhow::Result<Option<i32>> {
    use anyhow::Context;
    use srt_win::launch::quote_arg;
    use srt_win::util::wstr;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, GetLastError,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SEE_MASK_NO_CONSOLE,
        SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    if is_elevated()? {
        return Ok(None);
    }

    let exe = std::env::current_exe().context("current_exe")?;
    let exe_w = wstr(&exe.to_string_lossy());
    // Rebuild the original argv (minus argv[0]) using
    // CommandLineToArgvW-compatible quoting so the elevated
    // child parses identically.
    let params: String = std::env::args()
        .skip(1)
        .map(|a| quote_arg(&a))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w = wstr(&params);
    let verb_w = wstr("runas");

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: sei is fully initialized; the wide-string buffers
    // outlive the call.
    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok.is_err() {
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            eprintln!("srt-win: UAC prompt cancelled by user");
            std::process::exit(10);
        }
        return Err(anyhow::anyhow!(
            "ShellExecuteExW(runas): {} ({}",
            std::io::Error::from_raw_os_error(err.0 as i32),
            err.0,
        ));
    }
    let h = sei.hProcess;
    if h.is_invalid() {
        return Err(anyhow::anyhow!(
            "ShellExecuteExW returned no process handle"
        ));
    }
    unsafe { WaitForSingleObject(h, INFINITE) };
    let mut code: u32 = 1;
    unsafe {
        GetExitCodeProcess(h, &mut code)
            .context("GetExitCodeProcess(elevated child)")?;
        let _ = CloseHandle(h);
    }
    Ok(Some(code as i32))
}

#[cfg(not(windows))]
fn main() {
    // The clap-derived structs above keep `clap` referenced; just
    // print the platform error.
    let _ = <Cli as clap::CommandFactory>::command();
    eprintln!("srt-win: Windows only");
    std::process::exit(2);
}
