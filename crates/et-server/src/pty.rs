//! PTY plumbing: `openpty` + shell spawn. Upstream uses `forkpty` in
//! `PseudoUserTerminal.hpp`; `fork` in a multithreaded (tokio) process only
//! permits async-signal-safe work between fork and exec, so this port uses
//! `openpty` + `Command::pre_exec` (setsid, `TIOCSCTTY`, stdio dup2 via
//! `Stdio::from`) — the same end state: session leader, controlling tty,
//! stdio on the slave.

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use crate::ServerError;

/// A spawned shell on a fresh pseudo-terminal.
pub struct Pty {
    pub master: OwnedFd,
    pub child: tokio::process::Child,
}

/// Spawns `shell -l` with stdio on a new pty slave, cwd = home, env
/// overlaid with `TERM`, `ET_VERSION`, and the session environment from
/// `TermInit`. Mirrors upstream `PseudoUserTerminal::runTerminal`.
pub fn spawn_shell(
    shell: &str,
    term: &str,
    session_env: &BTreeMap<String, String>,
    home_override: Option<&std::path::Path>,
) -> Result<Pty, ServerError> {
    // 24x80 until the first TERMINAL_INFO resize arrives (upstream starts
    // with the kernel default and relies on the client resizing).
    let winsize = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = nix::pty::openpty(Some(&winsize), None)?;

    let home = home_override
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_default();

    // The pre_exec closure below captures the *raw fd number* of this
    // clone; it must stay open until after spawn() or the number can be
    // reused by an unrelated file and the child's TIOCSCTTY would hit the
    // wrong descriptor.
    let slave_alive_during_spawn = pty.slave.try_clone()?;
    let slave_fd = slave_alive_during_spawn.as_raw_fd();

    let mut command = tokio::process::Command::new(shell);
    command
        .arg("-l")
        .env("TERM", term)
        .env("ET_VERSION", format!("rust-{}", env!("CARGO_PKG_VERSION")))
        .env("HOME", &home)
        .envs(session_env)
        .current_dir(std::path::Path::new(if home.is_empty() { "/" } else { &home }))
        .stdin(std::process::Stdio::from(pty.slave.try_clone()?))
        .stdout(std::process::Stdio::from(pty.slave.try_clone()?))
        .stderr(std::process::Stdio::from(pty.slave.try_clone()?));

    unsafe {
        command.pre_exec(move || {
            use std::io;
            nix::unistd::setsid().map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            // Session leader adopts the slave as its controlling terminal,
            // so job control (Ctrl+C) works inside the shell.
            if libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    // The shell (and every descendant) must NOT inherit the master: with
    // it open, closing our master cannot hang the tty up and any process
    // in the session could read or inject terminal traffic.
    set_cloexec(pty.master.as_raw_fd());
    set_cloexec(slave_alive_during_spawn.as_raw_fd());

    let child = command.spawn()?;

    // Parent's slave copies must close so the child sees EOF on hangup.
    drop(slave_alive_during_spawn);
    drop(pty.slave);

    // Non-blocking master for the tokio readiness loop.
    nix::fcntl::fcntl(&pty.master, nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))?;

    Ok(Pty { master: pty.master, child })
}

fn set_cloexec(fd: RawFd) {
    // BorrowedFd::borrow_raw keeps this a raw-fd helper (the fd is owned
    // elsewhere); fcntl on macOS 0.31's nix wants AsFd, not RawFd.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let flags = nix::fcntl::fcntl(borrowed, nix::fcntl::FcntlArg::F_GETFD).unwrap_or_default();
    let _ = nix::fcntl::fcntl(
        borrowed,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::from_bits_truncate(flags)
            | nix::fcntl::FdFlag::FD_CLOEXEC),
    );
}

/// `TIOCSWINSZ` (upstream `PseudoUserTerminal::setInfo`). The kernel
/// delivers SIGWINCH to the shell's foreground group on change.
pub fn set_window_size(master: RawFd, row: i32, column: i32, width: i32, height: i32) {
    let ws = libc::winsize {
        ws_row: row as libc::c_ushort,
        ws_col: column as libc::c_ushort,
        ws_xpixel: width as libc::c_ushort,
        ws_ypixel: height as libc::c_ushort,
    };
    unsafe {
        libc::ioctl(master, libc::TIOCSWINSZ, &ws);
    }
}
