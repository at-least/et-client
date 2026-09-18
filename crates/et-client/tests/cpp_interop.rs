//! Interop test against the **upstream C++ binaries** (brew `et`):
//! Rust `TerminalSession` ↔ C++ `etserver` ↔ C++ `etterminal`.
//!
//! This is the wire-compatibility gate for conch: the nonce streams,
//! packet framing, protobuf bytes, the INITIAL exchange, and the reconnect
//! catch-up must all agree with the C++ implementation byte-for-byte.
//!
//! Skips when the C++ binaries are absent (set `ET_CPP_PREFIX` to the
//! install prefix; defaults to /opt/homebrew). The reverse leg (C++ `et`
//! client ↔ Rust server) needs a local sshd to launch the remote command
//! and is exercised manually; the launch command it runs is byte-compatible
//! with `et_client::ssh::etterminal_command`.

use std::process::Stdio;
use std::time::Duration;

use et_client::session::{SessionEvent, TerminalSession, DEFAULT_KEEPALIVE};
use et_proto::messages::InitialPayload;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;

/// Fixed non-`XXX` credentials so the Rust etterminal does not regenerate
/// (its IDPASSKEY line goes to the process stdout, not to the test).
const FIXED_ID: &str = "tst0123456789abc"; // exactly 16 chars
const FIXED_PASSKEY: &str = "pkaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn cpp_bin(name: &str) -> Option<std::path::PathBuf> {
    let prefix = std::env::var("ET_CPP_PREFIX").unwrap_or_else(|_| "/opt/homebrew".into());
    let path = std::path::Path::new(&prefix).join("bin").join(name);
    path.exists().then_some(path)
}

/// Unique temp dir per call (see fullstack.rs for why pid+nanos collides).
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
    let mut output = String::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    use tokio::io::AsyncReadExt;
    let (id, passkey) = loop {
        assert!(tokio::time::Instant::now() < deadline, "no IDPASSKEY from C++ etterminal");
        let n = tokio::time::timeout(Duration::from_millis(500), stdout.read(&mut buf))
            .await
            .unwrap()
            .expect("read etterminal stdout");
        if n == 0 {
            panic!("C++ etterminal exited before IDPASSKEY");
        }
        output.push_str(&String::from_utf8_lossy(&buf[..n]));
        if let Some(pos) = output.find("IDPASSKEY:") {
            let rest = &output[pos + "IDPASSKEY:".len()..];
            if rest.len() >= 16 + 1 + 32 {
                let (id, passkey) = rest[..16 + 1 + 32].split_once('/').unwrap();
                break (id.to_string(), passkey.to_string());
            }
        }
    };

    CppStack { port, id, passkey, server, terminal, dir }
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

/// C++ `etterminal` registering with the **Rust** etserver over the unix
/// leg: the TERMINAL_USER_INFO packet and the server→terminal typed frames
/// must agree with the C++ client of that socket.
#[tokio::test]
#[ignore = "requires the C++ binaries (brew install et); run with --ignored"]
async fn cpp_etterminal_registers_with_rust_server() {
    let _guard = INTEROP.lock().await;
    let dir = unique_dir("cpp-reg");
    let socket_path = dir.join("etserver.sock");

    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let bound = et_server::server::bind(et_server::server::ServerOptions {
        port: 0,
        socket_path: Some(socket_path.clone()),
    })
    .await
    .unwrap();
    let port = bound.tcp.local_addr().unwrap().port();
    tokio::spawn(et_server::server::serve(bound, shutdown_rx));

    // C++ etterminal registers against the Rust server.
    let mut terminal = tokio::process::Command::new(cpp_bin("etterminal").unwrap())
        .arg("--serverfifo")
        .arg(&socket_path)
        .env("HOME", &dir)
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    terminal
        .stdin
        .take()
        .unwrap()
        .write_all(b"XXX0123456789abc/pkaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_xterm-256color\n")
        .await
        .unwrap();

    // The C++ side regenerates and prints; scrape it.
    let mut stdout = terminal.stdout.take().unwrap();
    let mut output = String::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    use tokio::io::AsyncReadExt;
    let (id, passkey) = loop {
        assert!(tokio::time::Instant::now() < deadline, "no IDPASSKEY from C++ etterminal");
        let n = tokio::time::timeout(Duration::from_millis(500), stdout.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            panic!("C++ etterminal exited before IDPASSKEY");
        }
        output.push_str(&String::from_utf8_lossy(&buf[..n]));
        if let Some(pos) = output.find("IDPASSKEY:") {
            let rest = &output[pos + "IDPASSKEY:".len()..];
            if rest.len() >= 16 + 1 + 32 {
                let (id, passkey) = rest[..16 + 1 + 32].split_once('/').unwrap();
                break (id.to_string(), passkey.to_string());
            }
        }
    };

    let payload = InitialPayload::default();
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{port}"),
        id,
        &passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .expect("Rust client ↔ Rust server with C++ etterminal attached");
    session.send_terminal_info(24, 80, 0, 0).await.unwrap();
    session.send_input(b"echo MIX_RS_$((3*14))\n").await.unwrap();
    let mut out: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !String::from_utf8_lossy(&out).contains("MIX_RS_42") {
        assert!(tokio::time::Instant::now() < deadline, "no MIX_RS_42; got {out:?}");
        match tokio::time::timeout(Duration::from_millis(300), session.next_event()).await {
            Ok(Some(SessionEvent::TerminalBuffer(bytes))) => out.extend_from_slice(&bytes),
            Ok(Some(_)) => {}
            Ok(None) => panic!("session died before echo"),
            Err(_) => {}
        }
    }
    session.send_input(b"exit\n").await.unwrap();
    let _ = shutdown.send(true);
    session.shutdown().await;
    let _ = terminal.start_kill();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The **Rust** etterminal registering with the C++ etserver: its
/// TERMINAL_USER_INFO packet and raw output stream must match what the C++
/// server expects from its own etterminal.
#[tokio::test]
#[ignore = "requires the C++ binaries (brew install et); run with --ignored"]
async fn rust_etterminal_registers_with_cpp_server() {
    let _guard = INTEROP.lock().await;
    let dir = unique_dir("rust-reg");
    let socket_path = dir.join("etserver.sock");
    let port = free_port();

    let server_log = dir.join("etserver.log");
    let mut server = tokio::process::Command::new(cpp_bin("etserver").unwrap())
        .arg("--port")
        .arg(port.to_string())
        .arg("--serverfifo")
        .arg(&socket_path)
        .env("HOME", &dir)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&server_log).unwrap())
        .stderr(std::fs::File::create(dir.join("etserver.err")).unwrap())
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "C++ etserver never listened");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Rust etterminal with fixed (non-XXX) credentials. Unlike the ssh
    // path, there is no built-in delay between registration and the
    // client's ConnectRequest, so give the daemon a beat to process the
    // TERMINAL_USER_INFO packet.
    tokio::spawn(et_server::terminal::run(et_server::terminal::TerminalOptions {
        idpasskey: Some((FIXED_ID.to_string(), FIXED_PASSKEY.to_string())),
        term: Some("xterm-256color".into()),
        socket_path: Some(socket_path.clone()),
        shell: Some("/bin/sh".into()),
        home: Some(dir.clone()),
    }));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let payload = InitialPayload::default();
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{port}"),
        FIXED_ID.to_string(),
        FIXED_PASSKEY,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .unwrap_or_else(|e| {
        let log = std::fs::read_to_string(dir.join("etserver.err")).unwrap_or_default();
        panic!("Rust client ↔ C++ etserver with Rust etterminal attached: {e}\netserver log: {log}");
    });
    session.send_terminal_info(24, 80, 0, 0).await.unwrap();
    session.send_input(b"echo MIX2_RS_$((2*21))\n").await.unwrap();
    let mut out: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !String::from_utf8_lossy(&out).contains("MIX2_RS_42") {
        assert!(tokio::time::Instant::now() < deadline, "no MIX2_RS_42; got {out:?}");
        match tokio::time::timeout(Duration::from_millis(300), session.next_event()).await {
            Ok(Some(SessionEvent::TerminalBuffer(bytes))) => out.extend_from_slice(&bytes),
            Ok(Some(_)) => {}
            Ok(None) => panic!("session died before echo"),
            Err(_) => {}
        }
    }
    session.send_input(b"exit\n").await.unwrap();
    session.shutdown().await;
    let _ = server.start_kill();
    let _ = std::fs::remove_dir_all(&dir);
}
