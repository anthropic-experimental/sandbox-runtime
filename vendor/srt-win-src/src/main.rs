//! `srt-win` standalone binary — a thin shim over the library's
//! [`srt_win::run_from_args`] CLI entry point. The dispatch lives in
//! `cli.rs` so an embedding multicall binary can link the crate and
//! route to it when `argv[1] == srt_win::SRT_WIN_DISPATCH_ARG1`
//! without shipping a separate executable. See `cli.rs` for why
//! dispatch keys on `argv[1]`, not `argv[0]`, on Windows.

#[cfg(windows)]
fn main() {
    std::process::exit(srt_win::run_from_args(std::env::args_os()));
}

#[cfg(not(windows))]
fn main() {
    eprintln!("srt-win: Windows only");
    std::process::exit(2);
}
