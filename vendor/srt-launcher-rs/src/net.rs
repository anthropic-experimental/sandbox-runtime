//! Networking helpers: the in-sandbox TCP↔Unix relay, the host-side relay
//! subcommand, the HTTP CONNECT helper, the splice pump, and lo-up.
//!
//! None of this is on a security boundary in the sense that mount.rs is — a
//! relay bug is a connectivity bug, not a sandbox escape. The seccomp'd worker
//! cannot ptrace the relay (PR_SET_DUMPABLE=0, set in run.rs before forking).

use crate::{die, die_errno, errno};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::zeroed;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;

// ---------------------------------------------------------------------------
// Bidirectional byte pump
// ---------------------------------------------------------------------------

/// Pump bytes in both directions between two fd pairs until both directions
/// hit EOF or either hits an error. `splice(2)` would avoid the userspace
/// copy, but it only works between a pipe and another fd; for socket↔socket
/// it's `EINVAL`. socat uses read/write too. 64 KiB matches Linux's default
/// pipe buffer, so a future splice swap is a drop-in.
///
/// On EOF in one direction, half-close the corresponding output with
/// `shutdown(SHUT_WR)` so the peer sees EOF, but keep pumping the other
/// direction. Non-socket fds (`connect`'s stdin/stdout) can't `shutdown`, so
/// we close them outright.
fn splice_loop(a_in: RawFd, a_out: RawFd, b_in: RawFd, b_out: RawFd) {
    let mut buf = [0u8; 64 * 1024];
    let mut fds = [
        libc::pollfd { fd: a_in, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: b_in, events: libc::POLLIN, revents: 0 },
    ];
    let dirs = [(a_in, a_out), (b_in, b_out)];
    let mut open = 2;

    while open > 0 {
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return;
        }
        for i in 0..2 {
            if fds[i].fd < 0 || fds[i].revents == 0 {
                continue;
            }
            let (rfd, wfd) = dirs[i];
            let n = loop {
                let r = unsafe { libc::read(rfd, buf.as_mut_ptr().cast(), buf.len()) };
                if r < 0 && errno() == libc::EINTR {
                    continue;
                }
                break r;
            };
            if n <= 0 {
                // EOF or error: half-close this direction.
                unsafe {
                    if libc::shutdown(wfd, libc::SHUT_WR) < 0 {
                        libc::close(wfd);
                    }
                }
                fds[i].fd = -1;
                open -= 1;
                continue;
            }
            let mut off = 0isize;
            while off < n {
                let w = unsafe {
                    libc::write(wfd, buf.as_ptr().add(off as usize).cast(), (n - off) as usize)
                };
                if w < 0 {
                    if errno() == libc::EINTR {
                        continue;
                    }
                    return;
                }
                off += w;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// lo up — bring loopback online inside a fresh netns
// ---------------------------------------------------------------------------

/// `--unshare-net` gives a netns with `lo` present but DOWN. The relay binds
/// 127.0.0.1, which fails on a downed lo. We only need IFF_UP via
/// SIOCSIFFLAGS — the kernel auto-assigns 127.0.0.1/8 and ::1/128 when lo
/// comes up. (bwrap uses netlink RTM_NEWLINK; this is the simpler ioctl path
/// to the same effect.)
pub fn loopback_up() {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            die_errno!("loopback: socket");
        }
        let mut ifr: libc::ifreq = zeroed();
        ifr.ifr_name[..3].copy_from_slice(&[b'l' as _, b'o' as _, 0]);
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        // musl's ioctl request is c_int; glibc's is c_ulong. The constant is
        // declared u64 in the libc crate either way, so cast.
        if libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            die_errno!("loopback: SIOCSIFFLAGS");
        }
        libc::close(s);
    }
}

// ---------------------------------------------------------------------------
// In-sandbox relay: TCP-LISTEN:port -> UNIX-CONNECT:path
//
// Forked from the *stub* in {host pidns, host mountns, sandbox netns}, with
// DUMPABLE=0 inherited. The workload has no PID for it, and it resolves
// `unix_path` in the host's mount view. Replaces `socat TCP-LISTEN:PORT,fork
// UNIX-CONNECT:PATH`.
// ---------------------------------------------------------------------------

pub struct RelaySpec {
    pub port: u16,
    pub unix_path: String,
}

pub fn relay_fork(spec: &RelaySpec) -> libc::pid_t {
    // Bind and pin the bridge inode in the *stub* before forking, so a missing
    // socket or busy port aborts the launcher rather than leaving the workload
    // running with a dead proxy. The fds are inherited by the child.
    let listener = match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, spec.port)) {
        Ok(l) => l,
        Err(e) => die!("relay: bind 127.0.0.1:{}: {e}", spec.port),
    };
    // Pin the bridge socket *inode* now, before the workload exists. The
    // workload may have rw access to the socket's directory via a bind mount
    // (writes to a bound path land on the same host filesystem); without this
    // it could swap `unix_path` to a symlink at, say, /var/run/docker.sock and
    // the relay — which has AF_UNIX capability the workload lacks — would
    // connect there on its behalf. /proc/self/fd/N resolves directly to the
    // inode this fd refers to, regardless of what the path now points at.
    let sock_path_c = std::ffi::CString::new(spec.unix_path.as_str())
        .unwrap_or_else(|_| die!("relay: unix path contains NUL"));
    let sock_fd = unsafe { libc::open(sock_path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if sock_fd < 0 {
        die_errno!("relay: open(O_PATH) {}", spec.unix_path);
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        die_errno!("fork relay");
    }
    if pid == 0 {
        unsafe {
            // Own process group so the stub's kill(-pid, SIGKILL) reaches our
            // per-connection children too.
            if libc::setpgid(0, 0) < 0 {
                die_errno!("relay: setpgid");
            }
            // We're outside the sandbox pidns, so pidns-teardown doesn't reach
            // us. Die with the stub instead.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                die_errno!("relay: prctl(PR_SET_PDEATHSIG)");
            }
            // The stub couldn't set DUMPABLE=0 before forking us (it needs to
            // write /proc/self/{uid,gid}_map after). Set it ourselves.
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) < 0 {
                die_errno!("relay: prctl(PR_SET_DUMPABLE)");
            }
        }
        // The relay never needs caps; drop them before doing anything else.
        crate::run::drop_all_caps();
        relay_serve_tcp_to_unix(listener, sock_fd);
    }
    // Stub: close inherited copies so PID 1 / worker don't see them.
    drop(listener);
    unsafe { libc::close(sock_fd) };
    pid
}

fn relay_serve_tcp_to_unix(listener: TcpListener, sock_fd: RawFd) -> ! {
    let pinned_path = format!("/proc/self/fd/{sock_fd}");

    install_nocldwait_sigpipe_ign();

    for conn in listener.incoming() {
        let client = match conn {
            Ok(c) => c,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR | libc::ECONNABORTED)) => continue,
            Err(e) => die!("relay: accept: {e}"),
        };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            continue;
        }
        if pid == 0 {
            // PDEATHSIG was cleared by fork; re-set so a stuck connection
            // child doesn't outlive the listener.
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            drop(listener);
            let _ = client.set_nodelay(true);
            if let Ok(upstream) = UnixStream::connect(&pinned_path) {
                let cfd = client.as_raw_fd();
                let ufd = upstream.as_raw_fd();
                splice_loop(cfd, ufd, ufd, cfd);
            }
            unsafe { libc::_exit(0) };
        }
        // Parent: SA_NOCLDWAIT reaps the child; just drop our copy of the fd.
    }
    unreachable!()
}

fn install_nocldwait_sigpipe_ign() {
    // Relay-connection children are fire-and-forget; SA_NOCLDWAIT stops them
    // becoming zombies the relay loop would otherwise have to reap.
    unsafe {
        let mut sa: libc::sigaction = zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        sa.sa_flags = libc::SA_NOCLDWAIT | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

// ---------------------------------------------------------------------------
// `srt-launcher relay` — host-side Unix-LISTEN -> TCP-CONNECT
//
// Only used when network.{http,socks}ProxyPort is configured (external proxy).
// The internal proxy listens on the unix socket directly, so the host bridge
// only exists where the upstream listening port isn't ours to control.
// ---------------------------------------------------------------------------

pub fn relay_main(args: Vec<String>) -> ExitCode {
    let mut ready_fd: Option<RawFd> = None;
    let mut unix_path: Option<String> = None;
    let mut tcp_target: Option<(Ipv4Addr, u16)> = None;

    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ready-fd" => {
                let v = it.next().unwrap_or_else(|| die!("relay: --ready-fd needs a value"));
                ready_fd = Some(v.parse().unwrap_or_else(|_| die!("relay: bad --ready-fd")));
            }
            _ if unix_path.is_none() => unix_path = Some(a),
            _ if tcp_target.is_none() => {
                tcp_target = Some(parse_tcp_target(&a));
            }
            _ => die!("relay: unexpected argument {a}"),
        }
    }
    let unix_path = unix_path.unwrap_or_else(|| die!("relay: missing UNIX_SOCKET"));
    let (host, port) = tcp_target.unwrap_or_else(|| die!("relay: missing TCP_HOST:PORT"));

    // Lifecycle contract with the spawner: PR_SET_PDEATHSIG means we die when
    // the host process dies — no orphan handling, no exit-event monitoring,
    // no SIGTERM→SIGKILL escalation on its side. The spawner can SIGKILL us
    // on reset() and unref() the handle.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
            die_errno!("relay: prctl(PR_SET_PDEATHSIG)");
        }
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }

    let listener = match UnixListener::bind(&unix_path) {
        Ok(l) => l,
        Err(e) => die!("relay: bind {unix_path}: {e}"),
    };

    // "Listening" handshake: one byte to ready_fd, then close it. Replaces the
    // "spawn socat, then poll fs.existsSync(socketPath) with backoff" loop.
    if let Some(fd) = ready_fd {
        // Ownership of the fd was passed in by the spawner via --ready-fd; we
        // close it here (File's drop). The unsafe is the ownership assertion.
        let _ = unsafe { File::from_raw_fd(fd) }.write_all(&[0u8]);
    }

    install_nocldwait_sigpipe_ign();

    for conn in listener.incoming() {
        let client = match conn {
            Ok(c) => c,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR | libc::ECONNABORTED)) => continue,
            Err(e) => die!("relay: accept: {e}"),
        };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            continue;
        }
        if pid == 0 {
            // PDEATHSIG was cleared by fork; re-set so a stuck connection
            // child doesn't outlive the listener.
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            drop(listener);
            if let Ok(upstream) = TcpStream::connect(SocketAddrV4::new(host, port)) {
                let _ = upstream.set_nodelay(true);
                set_tcp_keepalive(upstream.as_raw_fd());
                let cfd = client.as_raw_fd();
                let tfd = upstream.as_raw_fd();
                splice_loop(cfd, tfd, tfd, cfd);
            }
            unsafe { libc::_exit(0) };
        }
    }
    unreachable!("UnixListener::incoming() is infinite")
}

/// SO_KEEPALIVE + TCP_KEEPIDLE/KEEPINTVL/KEEPCNT on a TCP fd. Detects a hung
/// upstream within ~25s so the per-connection child exits instead of leaking.
fn set_tcp_keepalive(fd: RawFd) {
    let one = 1i32;
    let len = std::mem::size_of::<i32>() as u32;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, (&one as *const i32).cast(), len);
        for (opt, val) in [(libc::TCP_KEEPIDLE, 10), (libc::TCP_KEEPINTVL, 5), (libc::TCP_KEEPCNT, 3)] {
            libc::setsockopt(fd, libc::IPPROTO_TCP, opt, (&val as *const i32).cast(), len);
        }
    }
}

/// Parse `HOST:PORT` where HOST is a literal IPv4 address. No DNS — the
/// external proxy is configured by port and runs on the same host; resolving
/// here would be an extra moving part on the host data path.
fn parse_tcp_target(spec: &str) -> (Ipv4Addr, u16) {
    let (h, p) = spec
        .rsplit_once(':')
        .unwrap_or_else(|| die!("bad TCP target {spec}"));
    let host: Ipv4Addr = h
        .parse()
        .unwrap_or_else(|_| die!("TCP host must be a literal IPv4 address: {h}"));
    let port: u16 = p.parse().unwrap_or_else(|_| die!("bad TCP port {p}"));
    (host, port)
}

// ---------------------------------------------------------------------------
// `srt-launcher connect HOST PORT --proxy ADDR`
//
// HTTP CONNECT helper for ssh ProxyCommand inside the sandbox. Replaces
// `socat - PROXY:localhost:%h:%p,proxyport=...`.
// ---------------------------------------------------------------------------

pub fn connect_main(args: Vec<String>) -> ExitCode {
    let mut target_host: Option<String> = None;
    let mut target_port: Option<u16> = None;
    let mut proxy: Option<SocketAddrV4> = None;

    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--proxy" => {
                let v = it.next().unwrap_or_else(|| die!("connect: --proxy needs a value"));
                let (h, p) = parse_tcp_target(&v);
                proxy = Some(SocketAddrV4::new(h, p));
            }
            _ if target_host.is_none() => target_host = Some(a),
            _ if target_port.is_none() => {
                target_port = Some(
                    a.parse()
                        .ok()
                        .filter(|p| *p >= 1)
                        .unwrap_or_else(|| die!("connect: PORT must be 1-65535")),
                );
            }
            _ => die!("connect: unexpected argument {a}"),
        }
    }
    let host = target_host.unwrap_or_else(|| die!("connect: missing HOST"));
    let port = target_port.unwrap_or_else(|| die!("connect: missing PORT"));
    let proxy = proxy.unwrap_or_else(|| die!("connect: missing --proxy ADDR"));

    // HOST and PORT come from ssh's %h/%p, which derive from the git remote
    // URL — repository-controlled input. We're about to splice them into an
    // HTTP request line that lands on our own proxy, where the allow/deny
    // filter runs against the parsed host. Reject anything that could break
    // out of the request-line token (CRLF injection, request smuggling) or
    // confuse host parsing rather than rely on ssh/git/llhttp upstream
    // validation.
    if host.is_empty()
        || host.len() > 255
        || !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_:[]".contains(&c))
    {
        die!("connect: invalid HOST");
    }

    let mut sock = match TcpStream::connect(proxy) {
        Ok(s) => s,
        Err(e) => die!("connect: connect {proxy}: {e}"),
    };
    let _ = sock.set_nodelay(true);

    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    if sock.write_all(req.as_bytes()).is_err() {
        die_errno!("connect: write");
    }

    // Read the status line + headers up to the blank line, byte at a time so
    // we don't swallow tunnel payload.
    let mut hdr = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match sock.read(&mut byte) {
            Ok(0) => die!("connect: proxy closed during handshake"),
            Ok(_) => {
                hdr.push(byte[0]);
                if hdr.len() > 8192 {
                    die!("connect: proxy header too long");
                }
                if hdr.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => die!("connect: read response: {e}"),
        }
    }
    // Expect "HTTP/1.x 2xx ...".
    let line = hdr.split(|b| *b == b'\r').next().unwrap_or(&[]);
    let ok = line
        .splitn(3, |b| *b == b' ')
        .nth(1)
        .map(|code| code.len() == 3 && code[0] == b'2')
        .unwrap_or(false);
    if !ok {
        die!("connect: proxy refused: {}", String::from_utf8_lossy(line));
    }

    let sfd = sock.as_raw_fd();
    splice_loop(libc::STDIN_FILENO, sfd, sfd, libc::STDOUT_FILENO);
    ExitCode::SUCCESS
}

