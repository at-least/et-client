//! `et` — the EternalTerminal client CLI (Rust port, wire-compatible with
//! upstream C++ `et` at protocol version 6).
//!
//! ```text
//! et [user@]host[:port] [-c CMD] [--keepalive N] [-v LEVEL]
//!    [--serverfifo PATH] [--etterminal-path PATH] [--kill] [-o SSH_OPT]...
//! ```
//!
//! The SSH handshake runs the system `ssh` binary (interactive prompts
//! pass through); everything after that is pure Rust. Port forwarding
//! (`-t`/`-r`) and `--jumphost` are not implemented in this port — see the
//! README.

use std::io::Write as _;
use std::time::Duration;

use et_client::session::{SessionEvent, TerminalSession, DEFAULT_KEEPALIVE};
use et_client::ssh::{self, SshDestination, TerminalCommandOptions};
use et_proto::InitialPayload;

struct Cli {
    destination: SshDestination,
    et_port: u16,
    command: Option<String>,
    no_exit: bool,
    keepalive: Duration,
    term_opts: TerminalCommandOptions,
    server_fifo: Option<String>,
    forward_sources: Vec<et_proto::PortForwardSourceRequest>,
    reverse_sources: Vec<et_proto::PortForwardSourceRequest>,
    /// `[user@]host[:etport]` of the jumphost etserver (upstream
    /// `--jumphost`).
    jumphost: Option<String>,
}

fn usage() -> &'static str {
    "et [user@]host[:port] [-c CMD] [--keepalive N] [--no-exit] \
     [--serverfifo PATH] [--etterminal-path PATH] [--kill] [-o SSH_OPT]... [-v LEVEL]"
}

fn parse_args() -> Result<Cli, String> {
    let mut destination = SshDestination::default();
    let mut et_port = 2022u16;
    let mut command = None;
    let mut no_exit = false;
    let mut keepalive = DEFAULT_KEEPALIVE;
    let mut term_opts = TerminalCommandOptions::default();
    let mut server_fifo = None;
    let mut positional: Option<String> = None;
    let mut forward_sources: Vec<et_proto::PortForwardSourceRequest> = Vec::new();
    let mut reverse_sources: Vec<et_proto::PortForwardSourceRequest> = Vec::new();
    let mut jumphost: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--command" => command = Some(args.next().ok_or("-c needs a value")?),
            "--no-exit" => no_exit = true,
            "-k" | "--keepalive" => {
                let secs: u64 = args
                    .next()
                    .ok_or("--keepalive needs seconds")?
                    .parse()
                    .map_err(|_| "--keepalive needs a number")?;
                keepalive = Duration::from_secs(secs);
            }
            "-t" | "--tunnel" => {
                let spec = args.next().ok_or("-t needs a value")?;
                let parsed = et_proto::forward::parse_ranges(&spec)
                    .map_err(|e| format!("-t {spec}: {e}"))?;
                forward_sources.extend(parsed);
            }
            "-r" | "--reversetunnel" => {
                let spec = args.next().ok_or("-r needs a value")?;
                let parsed = et_proto::forward::parse_ranges(&spec)
                    .map_err(|e| format!("-r {spec}: {e}"))?;
                reverse_sources.extend(parsed);
            }
            "--jumphost" => {
                jumphost = Some(args.next().ok_or("--jumphost needs [user@]host[:port]")?);
            }
            "--serverfifo" => server_fifo = Some(args.next().ok_or("--serverfifo needs a value")?),
            "--etterminal-path" => {
                term_opts.etterminal_path = args.next().ok_or("--etterminal-path needs a value")?
            }
            "--kill" => term_opts.kill_existing = true,
            "-u" | "--user" => term_opts.user = args.next().ok_or("--user needs a value")?,
            "-o" | "--ssh-option" => {
                destination
                    .ssh_options
                    .push(args.next().ok_or("-o needs a value")?);
            }
            "-p" | "--port" => {
                et_port = args
                    .next()
                    .ok_or("--port needs a value")?
                    .parse()
                    .map_err(|_| "--port needs a number")?;
            }
            "-v" | "--verbose" => {
                term_opts.verbose = args
                    .next()
                    .ok_or("--verbose needs a level")?
                    .parse()
                    .map_err(|_| "--verbose needs a number")?;
            }
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unrecognized argument {other:?}"));
            }
            other => {
                if positional.is_some() {
                    return Err(format!("unexpected extra argument {other:?}"));
                }
                positional = Some(other.to_string());
            }
        }
    }

    let target = positional.ok_or_else(|| format!("missing destination\nusage: {}", usage()))?;
    // [user@]host[:etport]
    let (user, hostport) = match target.split_once('@') {
        Some((u, rest)) => (u.to_string(), rest.to_string()),
        None => (std::env::var("USER").unwrap_or_default(), target),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| format!("bad port in {hostport:?}"))?,
        ),
        _ => (hostport, 2022),
    };
    let port = if port != 2022 { port } else { et_port };
    destination.user = user;
    destination.host = host;

    Ok(Cli {
        destination,
        et_port: port,
        command,
        no_exit,
        keepalive,
        term_opts,
        server_fifo,
        forward_sources,
        reverse_sources,
        jumphost,
    })
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = match parse_args() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("et: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // 1. SSH handshake: register (id, passkey) with a fresh etterminal.
    let fresh = ssh::generate_id_passkey();
    let mut term_opts = cli.term_opts.clone();
    term_opts.server_fifo = cli.server_fifo.clone();

    let idpasskey = if let Some(jump) = &cli.jumphost {
        // Jumphost mode (upstream SshSetupHandler): the destination
        // etterminal is launched first, through the jump host (`ssh -J`),
        // yielding the credentials both legs share; then the jump etterminal
        // is launched on the jumphost with `--jump --dsthost --dstport`.
        let mut via_jump = cli.destination.clone();
        via_jump.jumphost = Some(jump.clone());
        let dest_command = ssh::etterminal_command(
            &fresh.id,
            &fresh.passkey,
            &ssh::default_client_term(),
            &term_opts,
        );
        eprintln!("et: launching etterminal on {} via jumphost…", cli.destination.host);
        let idpasskey = match ssh::run_ssh_handshake(&via_jump, &dest_command).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("et: ssh handshake to destination failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let idpasskey = if idpasskey.id.is_empty() { fresh } else { idpasskey };

        let mut jump_dest = SshDestination::default();
        let (jump_user, jumphost_addr) = match jump.split_once('@') {
            Some((u, h)) => (u.to_string(), h.to_string()),
            None => (String::new(), jump.clone()),
        };
        jump_dest.user = jump_user;
        let (jump_host, jump_ssh_port) = match jumphost_addr.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => (h.to_string(), Some(p.to_string())),
            _ => (jumphost_addr, None),
        };
        jump_dest.host = jump_host;
        if let Some(p) = jump_ssh_port {
            match p.parse::<u16>() {
                Ok(port) => jump_dest.port = Some(port),
                Err(_) => return std::process::ExitCode::FAILURE,
            }
        }

        let mut jump_opts = term_opts.clone();
        jump_opts.kill_existing = false;
        let mut jump_command = ssh::etterminal_command(
            &idpasskey.id,
            &idpasskey.passkey,
            &ssh::default_client_term(),
            &jump_opts,
        );
        jump_command.push_str(&format!(
            " --jump --dsthost={} --dstport={}",
            cli.destination.host, cli.et_port
        ));
        eprintln!("et: launching etterminal --jump on jumphost…");
        let jump_idpasskey = match ssh::run_ssh_handshake(&jump_dest, &jump_command).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("et: ssh handshake to jumphost failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        if jump_idpasskey.id != idpasskey.id {
            eprintln!(
                "et: jumphost credentials diverged ({} != {})",
                jump_idpasskey.id, idpasskey.id
            );
            return std::process::ExitCode::FAILURE;
        }
        idpasskey
    } else {
        let command = ssh::etterminal_command(
            &fresh.id,
            &fresh.passkey,
            &ssh::default_client_term(),
            &term_opts,
        );
        eprintln!("et: launching etterminal over ssh to {}…", cli.destination.host);
        match ssh::run_ssh_handshake(&cli.destination, &command).await {
            Ok(x) => {
                if x.id.is_empty() {
                    fresh
                } else {
                    x
                }
            }
            Err(e) => {
                eprintln!("et: ssh handshake failed: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    };

    // 2. Connect and run the terminal session. Reverse tunnels ride the
    // INITIAL_PAYLOAD (the server binds its listeners before answering).
    // In jumphost mode the client TCP-connects to the JUMPHOST etserver
    // with jumphost=true; the destination etserver sees the jump relay
    // instead of this client.
    let connect_endpoint = match &cli.jumphost {
        Some(jump) => {
            let (jump_host, jump_et_port) = match jump.rsplit_once(':') {
                Some((h, p)) if !h.is_empty() => {
                    (h.to_string(), p.parse::<u16>().ok())
                }
                _ => (jump.clone(), None),
            };
            format!(
                "{}:{}",
                jump_host,
                jump_et_port.unwrap_or(2022)
            )
        }
        None => format!("{}:{}", cli.destination.host, cli.et_port),
    };
    let payload = InitialPayload {
        reversetunnels: cli.reverse_sources.clone(),
        jumphost: Some(cli.jumphost.is_some()),
        environmentvariables: [(
            "ET_VERSION".to_string(),
            format!("rust-{}", env!("CARGO_PKG_VERSION")),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let mut session = match TerminalSession::start(
        connect_endpoint,
        idpasskey.id.clone(),
        &idpasskey.passkey,
        &payload,
        cli.keepalive,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("et: connect failed: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    eprintln!("et: connected (session survives drops; feel free to background…)");

    // Initial window size; resizes follow via events.
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        let _ = session.send_terminal_info(rows as i32, cols as i32, 0, 0).await;
    }

    // Forward tunnels: local listeners; failures warn and continue, like
    // upstream's "Failed to establish port forward".
    if !cli.forward_sources.is_empty() {
        if let Err(errors) = session.start_port_forwarding(cli.forward_sources.clone()).await {
            eprintln!("et: port forward warning: {errors}");
        }
    }

    // Optional remote command (upstream appends "; exit" unless --no-exit).
    if let Some(cmd) = &cli.command {
        let line = if cli.no_exit { format!("{cmd}\n") } else { format!("{cmd}; exit\n") };
        let _ = session.send_input(line.as_bytes()).await;
    }

    let exit_code = run_loop(&mut session).await;
    session.shutdown().await;
    exit_code
}

/// Raw-mode terminal loop: stdin ↔ TERMINAL_BUFFER, stdout ↔ output,
/// crossterm resize events ↔ TERMINAL_INFO.
async fn run_loop(session: &mut TerminalSession) -> std::process::ExitCode {
    let interactive = crossterm::tty::IsTty::is_tty(&std::io::stdin());
    if interactive && crossterm::terminal::enable_raw_mode().is_err() {
        return std::process::ExitCode::FAILURE;
    }
    // Terminal events (keys + resize) come from a blocking thread; the
    // crossterm queue must have exactly one reader.
    let (term_tx, term_rx) = tokio::sync::mpsc::unbounded_channel();
    let event_thread = interactive.then(|| {
        std::thread::spawn(move || {
            loop {
                match crossterm::event::read() {
                    Ok(event) => {
                        if term_tx.send(event).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        })
    });

    let outcome = drive(session, interactive, term_rx).await;

    if interactive {
        // The reader thread stays blocked in crossterm::event::read until
        // process exit; detach it and restore the terminal.
        let _ = crossterm::terminal::disable_raw_mode();
        std::mem::forget(event_thread);
    }
    outcome
}

async fn drive(
    session: &mut TerminalSession,
    interactive: bool,
    mut term_rx: tokio::sync::mpsc::UnboundedReceiver<crossterm::event::Event>,
) -> std::process::ExitCode {
    let mut stdout = std::io::stdout();
    let mut stdin_async = if interactive {
        None
    } else {
        // Piped input: forward raw bytes (automation, tests).
        Some(tokio::io::BufReader::new(tokio::io::stdin()))
    };
    let mut input_buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            event = session.next_event() => match event {
                Some(SessionEvent::TerminalBuffer(bytes)) => {
                    if stdout.write_all(&bytes).and_then(|_| stdout.flush()).is_err() {
                        return std::process::ExitCode::FAILURE;
                    }
                }
                Some(SessionEvent::KeepAlive) | Some(SessionEvent::Other(_)) => {}
                Some(SessionEvent::Dead(reason)) => {
                    eprintln!("et: session ended ({reason:?})");
                    break;
                }
                None => break,
            },
            ev = async {
                if interactive {
                    term_rx.recv().await
                } else {
                    std::future::pending().await
                }
            } => match ev {
                Some(crossterm::event::Event::Resize(cols, rows)) => {
                    let _ = session.send_terminal_info(rows as i32, cols as i32, 0, 0).await;
                }
                Some(crossterm::event::Event::Key(key)) => {
                    if let Some(bytes) = key_to_bytes(key) {
                        if session.send_input(&bytes).await.is_err() {
                            return std::process::ExitCode::FAILURE;
                        }
                    }
                }
                Some(_) => {}
                None => {}
            },
            read = async {
                match stdin_async.as_mut() {
                    Some(reader) => tokio::io::AsyncReadExt::read(reader, &mut input_buf).await,
                    None => std::future::pending().await,
                }
            } => match read {
                Ok(0) | Err(_) => { /* input gone; keep draining output */ }
                Ok(n) => {
                    if session.send_input(&input_buf[..n]).await.is_err() {
                        return std::process::ExitCode::FAILURE;
                    }
                }
            },
        }
    }
    std::process::ExitCode::SUCCESS
}

/// Maps crossterm key events to the byte sequences a terminal in raw mode
/// would have sent. Covers the keys upstream's Console forwards; exotic
/// combinations degrade to their base key.
fn key_to_bytes(key: crossterm::event::KeyEvent) -> Option<Vec<u8>> {
    use crossterm::event::{KeyCode, KeyModifiers};
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let mut out = Vec::new();
    if alt {
        out.push(0x1b);
    }
    match key.code {
        KeyCode::Char(c) => {
            if ctrl {
                let lower = c.to_ascii_uppercase();
                if lower.is_ascii_uppercase() || lower == ' ' {
                    out.push((lower as u8) & 0x1f);
                } else if c == '?' {
                    out.push(0x1f);
                } else {
                    out.push(c as u8);
                }
            } else {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
        KeyCode::Enter => out.push(b'\r'),
        KeyCode::Backspace => out.push(0x7f),
        KeyCode::Tab => out.push(b'\t'),
        KeyCode::BackTab => out.extend_from_slice(b"\x1b[Z"),
        KeyCode::Esc => out.push(0x1b),
        KeyCode::Left => out.extend_from_slice(b"\x1b[D"),
        KeyCode::Right => out.extend_from_slice(b"\x1b[C"),
        KeyCode::Up => out.extend_from_slice(b"\x1b[A"),
        KeyCode::Down => out.extend_from_slice(b"\x1b[B"),
        KeyCode::Home => out.extend_from_slice(b"\x1b[H"),
        KeyCode::End => out.extend_from_slice(b"\x1b[F"),
        KeyCode::PageUp => out.extend_from_slice(b"\x1b[5~"),
        KeyCode::PageDown => out.extend_from_slice(b"\x1b[6~"),
        KeyCode::Delete => out.extend_from_slice(b"\x1b[3~"),
        KeyCode::Insert => out.extend_from_slice(b"\x1b[2~"),
        KeyCode::F(n) => {
            let seq: &[&str] = match n {
                1..=4 => &["\x1bOP", "\x1bOQ", "\x1bOR", "\x1bOS"],
                5 => &["\x1b[15~"],
                6 => &["\x1b[17~"],
                7 => &["\x1b[18~"],
                8 => &["\x1b[19~"],
                9 => &["\x1b[20~"],
                10 => &["\x1b[21~"],
                11 => &["\x1b[23~"],
                12 => &["\x1b[24~"],
                _ => &[],
            };
            let idx = match n {
                1..=4 => (n as usize) - 1,
                5..=12 => (n as usize) - 5 + 4,
                _ => 0,
            };
            if let Some(s) = seq.get(idx) {
                out.extend_from_slice(s.as_bytes());
            }
        }
        _ => return if out.is_empty() { None } else { Some(out) },
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}
