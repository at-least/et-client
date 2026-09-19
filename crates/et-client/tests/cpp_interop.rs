//! Interop test against the **upstream C++ binaries** (brew `et`):
//! Rust `TerminalSession` ↔ C++ `etserver` ↔ C++ `etterminal`.
//!
//! This is the wire-compatibility gate — and, since the Rust server was
//! removed, also the only behavioural net for the client (reconnect,
//! catch-up, keepalive, tunnels, jumphost). The nonce streams, packet
//! framing, protobuf bytes, the INITIAL exchange, and the recover exchange
//! must all agree with the C++ implementation byte-for-byte.
//!
//! Gated behind `#[ignore]`: plain `cargo test` never runs them. Running
//! them with `--ignored` requires the C++ binaries (brew `et`; set
//! `ET_CPP_PREFIX` to the install prefix, default /opt/homebrew) and they
//! panic loudly when the binaries are missing.

use std::process::Stdio;
use std::time::Duration;

use et_client::session::{SessionEvent, TerminalSession, DEFAULT_KEEPALIVE};
use et_proto::InitialPayload;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;

fn cpp_bin(name: &str) -> Option<std::path::PathBuf> {
    let prefix = std::env::var("ET_CPP_PREFIX").unwrap_or_else(|_| "/opt/homebrew".into());
    let path = std::path::Path::new(&prefix).join("bin").join(name);
    path.exists().then_some(path)
}

/// Unique temp dir per call: the process id alone would collide across
/// rapid sequential calls within one test binary, so a counter is mixed in.
fn unique_dir(_tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    // Short by construction: macOS caps sockaddr_un::sun_path at 104
    // bytes and $TMPDIR is already ~40 of them.
    let dir = std::env::temp_dir().join(format!("etX{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Serializes the interop tests: each spawns a C++ etserver on a port
/// reserved with a bind-then-close probe, which races under parallel
/// execution (two daemons, one port → the loser dies, the client resets).
static INTEROP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct CppStack {
    port: u16,
    id: String,
    passkey: String,
    server: Child,
    terminal: Child,
    dir: std::path::PathBuf,
}

impl Drop for CppStack {
    fn drop(&mut self) {
        let _ = self.server.start_kill();
        let _ = self.terminal.start_kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Starts the C++ etserver + C++ etterminal pair exactly the way the real
/// deployment does, and returns the (possibly server-regenerated) credentials.
async fn start_cpp_stack() -> CppStack {
    let etserver = cpp_bin("etserver").expect("C++ et binaries required");
    let etterminal = cpp_bin("etterminal").expect("C++ et binaries required");
    let dir = unique_dir("cpp-interop");
    let socket_path = dir.join("etserver.sock");
    let port = free_port();

    let server = tokio::process::Command::new(&etserver)
        .arg("--port")
        .arg(port.to_string())
        .arg("--serverfifo")
        .arg(&socket_path)
        .env("HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn C++ etserver");

    // Wait for the TCP listener.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "C++ etserver never listened");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Launch C++ etterminal the way the ssh command would: id/passkey on
    // stdin; the XXX prefix makes the C++ side regenerate both values and
    // print them on stdout as `IDPASSKEY:<16>/<32>`. An empty HOME keeps
    // the login shell free of profile output.
    let mut terminal = tokio::process::Command::new(&etterminal)
        .arg("--serverfifo")
        .arg(&socket_path)
        .env("HOME", &dir)
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn C++ etterminal");
    terminal
        .stdin
        .take()
        .unwrap()
        .write_all(b"XXX0123456789abc/pkaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_xterm-256color\n")
        .await
        .unwrap();

    let mut stdout = terminal.stdout.take().unwrap();
    let (id, passkey) = scrape_idpasskey(&mut stdout).await;

    CppStack { port, id, passkey, server, terminal, dir }
}

/// Reads the `IDPASSKEY:<16>/<32>` line from an etterminal stdout,
/// tolerating partial reads. The C++ side prints it only after the
/// etserver confirms the registration, so a successful scrape also
/// proves the registration round-trip completed.
async fn scrape_idpasskey(stdout: &mut tokio::process::ChildStdout) -> (String, String) {
    let mut output = String::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no IDPASSKEY from C++ etterminal");
        let n = match tokio::time::timeout(Duration::from_millis(500), stdout.read(&mut buf)).await
        {
            Ok(read) => read.expect("read etterminal stdout"),
            Err(_) => continue, // poll window elapsed; keep waiting until the deadline
        };
        if n == 0 {
            panic!("C++ etterminal exited before IDPASSKEY");
        }
        output.push_str(&String::from_utf8_lossy(&buf[..n]));
        if let Some(pos) = output.find("IDPASSKEY:") {
            let rest = &output[pos + "IDPASSKEY:".len()..];
            if rest.len() >= 16 + 1 + 32 {
                let (id, passkey) = rest[..16 + 1 + 32].split_once('/').unwrap();
                return (id.to_string(), passkey.to_string());
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires the C++ binaries (brew install et); run with --ignored"]
async fn rust_client_talks_to_cpp_server() {
    let _guard = INTEROP.lock().await;
    let stack = start_cpp_stack().await;
    let payload = InitialPayload::default();
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{}", stack.port),
        stack.id.clone(),
        &stack.passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .expect("Rust client ↔ C++ etserver handshake");
    session.send_terminal_info(24, 80, 0, 0).await.unwrap();

    // Echo through the C++ server and C++ shell.
    session.send_input(b"echo RS_CPP_$((6*7))\n").await.unwrap();
    let mut out: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !String::from_utf8_lossy(&out).contains("RS_CPP_42") {
        assert!(tokio::time::Instant::now() < deadline, "no RS_CPP_42; got {out:?}");
        match tokio::time::timeout(Duration::from_millis(300), session.next_event()).await {
            Ok(Some(SessionEvent::TerminalBuffer(bytes))) => out.extend_from_slice(&bytes),
            Ok(Some(_)) => {}
            Ok(None) => panic!("session died before echo"),
            Err(_) => {}
        }
    }

    // Kill the TCP socket mid-stream and verify the C++ server's catch-up
    // delivers every line — this exercises the Rust↔C++ recover exchange,
    // nonce continuity across sockets, and the CatchupBuffer framing.
    session.send_input(b"seq 1 5000\n").await.unwrap();
    session.kill_socket().await;
    session.send_input(b"echo AFTER_CPP_$((40+2))\n").await.unwrap();

    use std::collections::BTreeSet;
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut marker = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline && (seen.len() < 5000 || !marker) {
        match tokio::time::timeout(Duration::from_millis(500), session.next_event()).await {
            Ok(Some(SessionEvent::TerminalBuffer(bytes))) => {
                out.extend_from_slice(&bytes);
                for line in String::from_utf8_lossy(&out).lines() {
                    if let Ok(n) = line.trim().parse::<u32>() {
                        if (1..=5000).contains(&n) {
                            seen.insert(n);
                        }
                    }
                    if line.contains("AFTER_CPP_42") {
                        marker = true;
                    }
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("session died during catch-up ({} lines so far)", seen.len()),
            Err(_) => {}
        }
    }
    assert!(marker, "post-disconnect input lost; {} lines recovered", seen.len());
    if seen.len() != 5000 {
        let missing: Vec<u32> = (1..=5000).filter(|n| !seen.contains(n)).collect();
        panic!(
            "catch-up from C++ server lost {} lines: {:?}",
            5000 - seen.len(),
            &missing[..missing.len().min(20)]
        );
    }

    // Clean end: exit the shell; the C++ server drops the session; our
    // reconnect learns INVALID_KEY.
    session.send_input(b"exit\n").await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "session never ended");
        match tokio::time::timeout(Duration::from_secs(2), session.next_event()).await {
            Ok(Some(SessionEvent::Dead(_))) => break,
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {}
        }
    }
    session.shutdown().await;
}

/// ECHO server on an ephemeral port; returns the port.
async fn spawn_echo_listener() -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tunnel_request(source_port: u16, destination_port: u16) -> et_proto::PortForwardSourceRequest {
    et_proto::PortForwardSourceRequest {
        source: et_proto::SocketEndpoint {
            name: Some("127.0.0.1".into()),
            port: Some(source_port as i32),
            ..Default::default()
        }
        .into(),
        destination: et_proto::SocketEndpoint {
            name: None,
            port: Some(destination_port as i32),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
}

/// Forward tunnel through the **C++ etserver**: our Rust client listens,
/// the C++ server opens the loopback destination (`createDestination`).
#[tokio::test]
#[ignore = "requires the C++ binaries (brew install et); run with --ignored"]
async fn forward_tunnel_through_cpp_server() {
    let _guard = INTEROP.lock().await;
    let stack = start_cpp_stack().await;
    let echo_port = spawn_echo_listener().await;
    let client_port = free_tcp_port();

    let payload = InitialPayload::default();
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{}", stack.port),
        stack.id.clone(),
        &stack.passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .expect("handshake");
    session.send_terminal_info(24, 80, 0, 0).await.unwrap();
    session
        .start_port_forwarding(vec![tunnel_request(client_port, echo_port)])
        .await
        .expect("start forward tunnel");

    let pump = tokio::spawn(async move {
        loop {
            if session.next_event().await.is_none() {
                return;
            }
        }
    });

    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", client_port))
        .await
        .expect("connect to forwarded port");
    conn.write_all(b"CPP_PF_9").await.unwrap();
    let mut buf = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(15), conn.read_exact(&mut buf))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(&buf, b"CPP_PF_9");
    pump.abort();
}

/// Reverse tunnel through the **C++ etserver**: the C++ server listens
/// (`createSource`) and sends DESTINATION_REQUESTs; our Rust client opens
/// the loopback destination and must answer with RESPONSE/DATA.
#[tokio::test]
#[ignore = "requires the C++ binaries (brew install et); run with --ignored"]
async fn reverse_tunnel_through_cpp_server() {
    let _guard = INTEROP.lock().await;
    let stack = start_cpp_stack().await;
    let client_echo_port = spawn_echo_listener().await;
    let server_listen_port = free_tcp_port();

    let payload = InitialPayload {
        reversetunnels: vec![tunnel_request(server_listen_port, client_echo_port)],
        ..Default::default()
    };
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{}", stack.port),
        stack.id.clone(),
        &stack.passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .expect("handshake with reverse tunnel");
    session.send_terminal_info(24, 80, 0, 0).await.unwrap();

    let pump = tokio::spawn(async move {
        loop {
            if session.next_event().await.is_none() {
                return;
            }
        }
    });

    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", server_listen_port))
        .await
        .expect("connect to C++ reverse-tunnel listener");
    conn.write_all(b"CPP_REV_4").await.unwrap();
    let mut buf = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(15), conn.read_exact(&mut buf))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(&buf, b"CPP_REV_4");
    pump.abort();
}

/// The full upstream jump topology, all-C++ on the server side:
/// Rust client → **C++ etserver (jump)** → **C++ etterminal --jump** →
/// **C++ etserver (destination)** → **C++ etterminal** (PTY). The
/// destination etterminal registers first; its (server-regenerated)
/// credentials are then fed to the jump etterminal — exactly what
/// upstream's two-ssh handshake produces. Validates JUMPHOST_INIT
/// handling, the jump relay, and the client leg against C++ `runJumpHost`.
#[tokio::test]
#[ignore = "requires the C++ binaries (brew install et); run with --ignored"]
async fn jumphost_chain_through_cpp_servers() {
    let _guard = INTEROP.lock().await;
    let dir = unique_dir("cpp-jump");

    // Destination: C++ etserver + C++ etterminal (regenerates credentials).
    let dest = start_cpp_stack().await;

    // Jump: C++ etserver (its own fifo/port).
    let jump_fifo = dir.join("jump.sock");
    let jump_port = free_port();
    let etserver = cpp_bin("etserver").unwrap();
    let mut jump_server = tokio::process::Command::new(&etserver)
        .arg("--port")
        .arg(jump_port.to_string())
        .arg("--serverfifo")
        .arg(&jump_fifo)
        .env("HOME", &dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", jump_port)).await.is_ok() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "C++ jump etserver never listened");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // C++ etterminal --jump on the jumphost, registered with the
    // DESTINATION credentials (non-XXX input keeps them; the IDPASSKEY
    // line it prints proves the registration round-trip completed).
    let etterminal = cpp_bin("etterminal").unwrap();
    let mut jump_terminal = tokio::process::Command::new(&etterminal)
        .arg("--serverfifo")
        .arg(&jump_fifo)
        .arg("--jump")
        .arg("--dsthost")
        .arg("127.0.0.1")
        .arg("--dstport")
        .arg(dest.port.to_string())
        .env("HOME", &dir)
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let registration = format!("{}/{}_xterm-256color\n", dest.id, dest.passkey);
    jump_terminal
        .stdin
        .take()
        .unwrap()
        .write_all(registration.as_bytes())
        .await
        .unwrap();
    let mut jump_stdout = jump_terminal.stdout.take().unwrap();
    let (jump_id, jump_passkey) = scrape_idpasskey(&mut jump_stdout).await;
    assert_eq!(
        (jump_id.as_str(), jump_passkey.as_str()),
        (dest.id.as_str(), dest.passkey.as_str()),
        "jump registration diverged from the destination credentials"
    );

    let payload = InitialPayload { jumphost: Some(true), ..Default::default() };
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{jump_port}"),
        dest.id.clone(),
        &dest.passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .expect("jump chain handshake (Rust client → C++ jump etserver)");
    session.send_terminal_info(24, 80, 0, 0).await.unwrap();

    session.send_input(b"echo JCPP_$((4*8))\n").await.unwrap();
    let mut out: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !String::from_utf8_lossy(&out).contains("JCPP_32") {
        assert!(tokio::time::Instant::now() < deadline, "no JCPP_32; got {out:?}");
        match tokio::time::timeout(Duration::from_millis(300), session.next_event()).await {
            Ok(Some(SessionEvent::TerminalBuffer(bytes))) => out.extend_from_slice(&bytes),
            Ok(Some(_)) => {}
            Ok(None) => panic!("jump chain died before echo"),
            Err(_) => {}
        }
    }
    session.send_input(b"exit\n").await.unwrap();
    session.shutdown().await;
    let _ = jump_terminal.start_kill();
    let _ = jump_server.start_kill();
    drop(dest); // tears the destination stack down
    let _ = std::fs::remove_dir_all(&dir);
}
