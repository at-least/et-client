//! `etterminal`: reads the id/passkey handshake from stdin, registers with
//! `etserver` over the unix socket, prints the `IDPASSKEY:` line, waits for
//! `TERMINAL_INIT`, then runs the PTY loop. Port of upstream
//! `TerminalMain` + `UserTerminalHandler`.
//!
//! The run loop mirrors `UserTerminalHandler::runUserTerminal`:
//! - pty output → **raw bytes** on the unix socket (no framing, no crypto —
//!   local leg);
//! - unix socket → `[type: u8][i64-LE framed proto]` frames:
//!   `TERMINAL_BUFFER` appends to pending input, `TERMINAL_INFO` resizes;
//! - pending input drains to the pty non-blocking, with backpressure
//!   (input frames stop being read while the buffer is full, reaching the
//!   client instead of growing without bound).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use std::os::fd::{AsRawFd, RawFd};

use et_proto::framing::{read_packet_frame, read_proto_frame, write_packet_frame};
use et_proto::{TerminalBuffer, TerminalInfo, TerminalUserInfo};
use buffa::Message as _;
use et_proto::client::EtClient;
use et_proto::framing::try_parse_packet_frame_from_buffer;
use et_proto::{Packet, DEFAULT_MAX_PROTO_LENGTH, terminal_packet_type};
use tokio::io::{AsyncReadExt, unix::AsyncFd};
use tokio::net::UnixStream;

use crate::client_event_shim::Event;
use crate::ServerError;

pub const IDPASSKEY_MARKER: &str = "IDPASSKEY:";
const PTY_CHUNK: usize = 16 * 1024;
/// Upstream `maxPendingInput`.
const MAX_PENDING_INPUT: usize = 256 * 1024;

/// etterminal configuration. `idpasskey: None` reads the standard
/// `'<id>/<passkey>_<TERM>'` line from stdin (the normal path over ssh).
#[derive(Debug, Clone, Default)]
pub struct TerminalOptions {
    pub idpasskey: Option<(String, String)>,
    pub term: Option<String>,
    /// `--serverfifo` override.
    pub socket_path: Option<std::path::PathBuf>,
    /// Shell override (defaults to `$SHELL`, then `/bin/sh`); test hook.
    pub shell: Option<String>,
    /// HOME override for the spawned shell (also its cwd); test hook —
    /// points the shell at an empty home so no profile noise pollutes the
    /// stream.
    pub home: Option<std::path::PathBuf>,
    /// Jumphost mode (upstream `--jump`): after `JUMPHOST_INIT`, relay
    /// packets to `dsthost:dstport` (the destination etserver) instead of
    /// hosting a PTY.
    pub jump: bool,
    pub dsthost: String,
    pub dstport: u16,
}

/// Runs the etterminal role to completion. The caller exits afterwards (the
/// ssh command finishes, printing nothing more).
pub async fn run(opts: TerminalOptions) -> Result<(), ServerError> {
    let (id, passkey, term) = resolve_idpasskey(opts.idpasskey, opts.term).map_err(|e| {
        eprintln!("etterminal: {e}");
        e
    })?;
    let mut stream = crate::fifo::detect_and_connect(opts.socket_path.as_deref()).await.map_err(|e| {
        eprintln!("etterminal: connect to etserver failed: {e}");
        e
    })?;

    // Register (unencrypted — the local leg; this is how etserver learns
    // the session key).
    let tui = TerminalUserInfo {
        id: Some(id.clone()),
        passkey: Some(passkey.clone()),
        uid: Some(nix::unistd::Uid::effective().as_raw() as i64),
        gid: Some(nix::unistd::Gid::effective().as_raw() as i64),
        fd: None,
        ..Default::default()
    };
    write_packet_frame(
        &mut stream,
        &Packet::new(terminal_packet_type::TERMINAL_USER_INFO, tui.encode_to_vec()),
    )
    .await?;

    // The client scrapes this from the ssh stdout (16 + 1 + 32 chars after
    // the marker; nothing else may follow on this line).
    println!("{IDPASSKEY_MARKER}{id}/{passkey}");
    std::io::stdout().flush().ok();

    if opts.jump {
        if opts.dsthost.is_empty() || opts.dstport == 0 {
            return Err(ServerError::Other(
                "jump mode requires --dsthost and --dstport".into(),
            ));
        }
        return run_jump(id, passkey, opts.dsthost.clone(), opts.dstport, stream).await;
    }

    // Wait for TERMINAL_INIT carrying the session environment.
    let init_packet =
        read_expected_packet(&mut stream, terminal_packet_type::TERMINAL_INIT)
            .await
            .map_err(|e| {
                eprintln!("etterminal: waiting for TERMINAL_INIT failed: {e}");
                e
            })?;
    let term_init = et_proto::TermInit::decode_from_slice(&init_packet[..])
        .map_err(|e| ServerError::Other(format!("bad TermInit: {e}")))?;
    let mut session_env = BTreeMap::new();
    for (name, value) in term_init.environmentnames.iter().zip(&term_init.environmentvalues) {
        session_env.insert(name.clone(), value.clone());
    }
    let term = session_env.remove("TERM").unwrap_or(term);

    let shell = opts
        .shell
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());
    let pty = crate::pty::spawn_shell(&shell, &term, &session_env, opts.home.as_deref()).map_err(|e| {
        eprintln!("etterminal: spawn shell failed: {e}");
        e
    })?;
    let master_raw: RawFd = pty.master.as_raw_fd();
    let master = AsyncFd::new(pty.master)?;
    let mut child = pty.child;

    let (mut unix_read, mut unix_write) = stream.split();
    let mut pending_input: Vec<u8> = Vec::new();
    let mut shell_exited = false;

    loop {
        tokio::select! {
            // Shell output → raw bytes to the router.
            readable = master.readable() => {
                let mut guard = readable?;
                let mut buf = [0u8; PTY_CHUNK];
                loop {
                    match guard.try_io(|fd| raw_read(fd.get_ref().as_raw_fd(), &mut buf)) {
                        Ok(Ok(0)) => { shell_exited = true; break; }
                        Ok(Ok(n)) => {
                            unix_write.write_all(&buf[..n]).await?;
                            continue;
                        }
                        Ok(Err(_)) => { shell_exited = true; break; }
                        Err(_would_block) => break,
                    }
                }
                if shell_exited { break; }
            }
            // Router frames → input / resize.
            frame = read_typed_frame(&mut unix_read) => {
                match frame? {
                    TypedFrame::TerminalBuffer(data) => {
                        if pending_input.len() < MAX_PENDING_INPUT {
                            pending_input.extend_from_slice(&data);
                        }
                    }
                    TypedFrame::TerminalInfo(info) => {
                        crate::pty::set_window_size(
                            master_raw,
                            info.row.unwrap_or(0),
                            info.column.unwrap_or(0),
                            info.width.unwrap_or(0),
                            info.height.unwrap_or(0),
                        );
                    }
                    TypedFrame::Ignored => {}
                    TypedFrame::Eof => break,
                }
            }
            // Drain pending input to the pty without blocking (a short
            // write leaves the rest pending, so output keeps flowing).
            writable = master.writable(), if !pending_input.is_empty() => {
                let mut guard = writable?;
                loop {
                    match guard.try_io(|fd| raw_write(fd.get_ref().as_raw_fd(), &pending_input)) {
                        Ok(Ok(n)) => {
                            pending_input.drain(..n);
                            if pending_input.is_empty() { break; }
                            continue;
                        }
                        Ok(Err(_)) => { shell_exited = true; break; }
                        Err(_would_block) => break,
                    }
                }
                if shell_exited { break; }
            }
        }
    }

    match shell_exited {
        // Reap the shell so it is not left as a zombie.
        true => {
            let _ = child.wait().await;
        }
        // Router gone: close the master (shell gets SIGHUP) and kill the
        // child as a fallback.
        false => {
            drop(master);
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
    Ok(())
}

enum TypedFrame {
    TerminalBuffer(Vec<u8>),
    TerminalInfo(TerminalInfo),
    /// A type the run loop does not act on (upstream's switch simply falls
    /// through: a second TERMINAL_INIT after a server-side session reset,
    /// JUMPHOST_INIT, …). The body is consumed and skipped.
    Ignored,
    Eof,
}

/// Reads one `[type: u8][i64-framed proto]` routing frame.
async fn read_typed_frame(stream: &mut tokio::net::unix::ReadHalf<'_>) -> Result<TypedFrame, ServerError> {
    use tokio::io::AsyncReadExt;
    let mut packet_type = [0u8; 1];
    match stream.read_exact(&mut packet_type).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(TypedFrame::Eof),
        Err(e) => return Err(ServerError::Io(e)),
    }
    let proto = read_proto_frame(stream, DEFAULT_MAX_PROTO_LENGTH).await?;
    match packet_type[0] {
        terminal_packet_type::TERMINAL_BUFFER => {
            let tb = TerminalBuffer::decode_from_slice(&proto)
                .map_err(|e| ServerError::Other(format!("bad TerminalBuffer: {e}")))?;
            Ok(TypedFrame::TerminalBuffer(tb.buffer.unwrap_or_default()))
        }
        terminal_packet_type::TERMINAL_INFO => {
            let ti = TerminalInfo::decode_from_slice(&proto)
                .map_err(|e| ServerError::Other(format!("bad TerminalInfo: {e}")))?;
            Ok(TypedFrame::TerminalInfo(ti))
        }
        // KEEP_ALIVE is answered by etserver, never routed here; anything
        // else is consumed and skipped, matching upstream's default case.
        _ => Ok(TypedFrame::Ignored),
    }
}

async fn read_expected_packet(
    stream: &mut UnixStream,
    expected: u8,
) -> Result<Vec<u8>, ServerError> {
    let packet = read_packet_frame(stream, DEFAULT_MAX_PROTO_LENGTH).await?;
    if packet.header() != expected {
        return Err(ServerError::Other(format!(
            "expected packet header {expected}, got {}",
            packet.header()
        )));
    }
    Ok(packet.into_payload())
}

/// `TerminalMain` stdin handshake: `<id>/<passkey>_<TERM>`; ids starting
/// with `XXX` are regenerated here (that is the "new client" signal).
fn resolve_idpasskey(
    explicit: Option<(String, String)>,
    term_override: Option<String>,
) -> Result<(String, String, String), ServerError> {
    let term_default = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let term_default = term_override.unwrap_or(term_default);
    if let Some((id, passkey)) = explicit {
        let (id, passkey) = et_proto::ids::regen_if_client_chosen(&id).unwrap_or((id, passkey));
        return Ok((id, passkey, term_default));
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(ServerError::Io)?;
    let line = line.trim_end_matches(['\r', '\n']);
    let Some((idpasskey, term)) = line.split_once('_') else {
        return Err(ServerError::Other(
            "invalid stdin handshake: expected '<id>/<passkey>_<TERM>'".into(),
        ));
    };
    let Some((id, passkey)) = idpasskey.split_once('/') else {
        return Err(ServerError::Other("invalid stdin handshake: missing '/'".into()));
    };
    let (id, passkey) =
        et_proto::ids::regen_if_client_chosen(id).unwrap_or((id.to_string(), passkey.to_string()));
    Ok((id, passkey, term.to_string()))
}

// Raw non-blocking fd I/O for the pty master, used through
// `AsyncFdReadyGuard::try_io` (WouldBlock errors are converted into the
// would-block signal by tokio).

fn raw_read(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(n as usize);
    }
}

fn raw_write(fd: RawFd, buf: &[u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(n as usize);
    }
}

/// Jumphost relay (upstream `UserJumphostHandler::run`): wait for
/// `JUMPHOST_INIT` carrying the client's `InitialPayload`, clear the
/// jumphost flag, open a resilient client connection to the destination
/// etserver, send the payload there, then relay packets verbatim between
/// the local unix leg and the destination TCP leg. The same id/passkey is
/// used on both legs, so every hop decrypts and re-encrypts in step.
async fn run_jump(
    id: String,
    passkey: String,
    dsthost: String,
    dstport: u16,
    mut stream: UnixStream,
) -> Result<(), ServerError> {
    let init_packet = read_expected_packet(&mut stream, et_proto::terminal_packet_type::JUMPHOST_INIT)
        .await
        .map_err(|e| {
            eprintln!("etterminal: waiting for JUMPHOST_INIT failed: {e}");
            e
        })?;
    let mut payload = et_proto::InitialPayload::decode_from_slice(&init_packet)
        .map_err(|e| ServerError::Other(format!("bad InitialPayload: {e}")))?;
    if payload.jumphost != Some(true) {
        return Err(ServerError::Other("jumphost init without jumphost flag".into()));
    }
    payload.jumphost = Some(false);

    let mut jump = EtClient::connect_with(
        format!("{dsthost}:{dstport}"),
        id.clone(),
        &passkey,
        None, // idle handling belongs to the relay, not keepalive probes
    )
    .await
    .map_err(|e| ServerError::Other(format!("connect to destination etserver: {e}")))?;
    use buffa::Message as _;
    use et_proto::et_packet_type;
    jump.write(et_packet_type::INITIAL_PAYLOAD, payload.encode_to_vec())
        .await
        .map_err(|_| ServerError::Other("destination leg closed".into()))?;
    // Wait for a successful INITIAL_RESPONSE from the destination.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(ServerError::Other(
                "timeout waiting for destination INITIAL_RESPONSE".into(),
            ));
        }
        match tokio::time::timeout(Duration::from_secs(2), jump.next_event()).await {
            Ok(Some(et_proto::client::Event::Packet(p))) => {
                if p.header() == et_packet_type::INITIAL_RESPONSE {
                    let response = et_proto::InitialResponse::decode_from_slice(p.payload())
                        .map_err(|e| ServerError::Other(format!("bad InitialResponse: {e}")))?;
                    if let Some(error) = response.error {
                        return Err(ServerError::Other(format!(
                            "destination refused session: {error}"
                        )));
                    }
                    break;
                }
            }
            Ok(Some(et_proto::client::Event::Dead(_))) | Ok(None) => {
                return Err(ServerError::Other("destination leg died during init".into()));
            }
            Err(_) => {}
        }
    }
    eprintln!("etterminal: jump relay to {dsthost}:{dstport} established");

    // Relay: unix leg (i64-framed packets, both directions) ↔ destination
    // client connection (decrypted packets). Every packet terminates at
    // this hop; each leg has its own nonce stream over the shared key.
    let (mut unix_read, mut unix_write) = stream.split();
    let mut inbuf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        tokio::select! {
            // destination → local etserver
            event = jump.next_event() => match event {
                Some(Event::Packet(packet)) => {
                    if write_packet_frame(&mut unix_write, &packet).await.is_err() {
                        break;
                    }
                }
                Some(Event::Dead(_)) | None => break,
            },
            // local etserver → destination
            read = unix_read.read(&mut chunk) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    inbuf.extend_from_slice(&chunk[..n]);
                    loop {
                        match try_parse_packet_frame_from_buffer(&mut inbuf) {
                            Some(Ok(packet)) => {
                                let header = packet.header();
                                let payload = packet.into_payload();
                                if jump.write(header, payload).await.is_err() {
                                    return Err(ServerError::Other(
                                        "destination leg closed".into(),
                                    ));
                                }
                            }
                            Some(Err(e)) => {
                                return Err(ServerError::Io(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    e.to_string(),
                                )));
                            }
                            None => break,
                        }
                    }
                }
            },
        }
    }
    jump.shutdown().await;
    Ok(())
}
