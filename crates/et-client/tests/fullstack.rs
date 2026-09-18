//! Full-stack integration tests: Rust client ↔ Rust etserver ↔ Rust
//! etterminal, all in-process, over real TCP + unix sockets with a real
//! shell on a real PTY. These encode the observable behavior that matters
//! for conch: echo round-trips, session survival across a forced
//! disconnect (catch-up), keepalive echoes, and the handshake failure
//! paths a UI must surface.

use std::collections::BTreeSet;
use std::time::Duration;

use et_client::session::{SessionEvent, TerminalSession, DEFAULT_KEEPALIVE};
use buffa::Message as _;
use et_proto::{ConnectRequest, InitialPayload};
use et_proto::PROTOCOL_VERSION;

/// A non-`XXX` id (so etterminal does not regenerate) with a 32-char
/// alphanumeric passkey (constructed, not hand-counted).
fn test_id_passkey() -> (String, String) {
    ("tst0123456789abcd".to_string(), format!("pk{}", "a".repeat(30)))
}

/// Unique temp dir per call. `pid + nanos` alone collides: the macOS clock
/// has ~microsecond resolution and parallel tests in one process start
/// within the same tick.
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

struct Stack {
    port: u16,
    socket_path: std::path::PathBuf,
    shutdown: tokio::sync::watch::Sender<bool>,
}

/// Binds etserver on an ephemeral port with a temp unix socket and spawns
/// an etterminal registering `id`/`passkey` (using /bin/sh, no login files).
async fn start_stack(id: &str, passkey: &str) -> Stack {
    let dir = unique_dir("test");
    let socket_path = dir.join("etserver.sock");

    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let bound = et_server::server::bind(et_server::server::ServerOptions {
        port: 0,
        socket_path: Some(socket_path.clone()),
    })
    .await
    .unwrap_or_else(|e| panic!("bind failed: {e}"));
    let port = bound.tcp.local_addr().unwrap().port();
    tokio::spawn(et_server::server::serve(bound, shutdown_rx));

    tokio::spawn(et_server::terminal::run(et_server::terminal::TerminalOptions {
        idpasskey: Some((id.to_string(), passkey.to_string())),
        term: Some("xterm-256color".into()),
        socket_path: Some(socket_path.clone()),
        shell: Some("/bin/sh".into()),
        home: Some(dir.clone()),
    }));

    // Let the terminal register before the client knocks.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Stack { port, socket_path, shutdown }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        let _ = std::fs::remove_dir_all(
            self.socket_path.parent().expect("socket inside temp dir"),
        );
    }
}

async fn connect(stack: &Stack, id: &str, passkey: &str) -> TerminalSession {
    let payload = InitialPayload::default();
    TerminalSession::start(
        format!("127.0.0.1:{}", stack.port),
        id.to_string(),
        passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .unwrap()
}

/// Collects TerminalBuffer bytes until `predicate` holds or `budget`
/// elapses; returns the accumulated output.
async fn collect_until(
    session: &mut TerminalSession,
    budget: Duration,
    mut predicate: impl FnMut(&str) -> bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if predicate(&String::from_utf8_lossy(&out)) {
            return out;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return out;
        }
        match tokio::time::timeout(remaining.min(Duration::from_millis(200)), session.next_event())
            .await
        {
            Ok(Some(SessionEvent::TerminalBuffer(bytes))) => out.extend_from_slice(&bytes),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {}
        }
    }
}

#[tokio::test]
async fn echo_round_trip_and_clean_session_end() {
    let (id, passkey) = test_id_passkey();
    let stack = start_stack(&id, &passkey).await;
    let mut session = connect(&stack, &id, &passkey).await;

    session.send_terminal_info(24, 80, 0, 0).await.unwrap();
    // Computed marker so the pty echo of the command line cannot satisfy
    // the predicate.
    session.send_input(b"echo RS_$((6*7))\n").await.unwrap();
    let out = collect_until(&mut session, Duration::from_secs(10), |s| s.contains("RS_42"))
        .await;
    assert!(
        String::from_utf8_lossy(&out).contains("RS_42"),
        "expected echo marker in {:?}",
        String::from_utf8_lossy(&out)
    );

    // Exit the shell: etterminal ends → etserver removes the client → the
    // reconnect attempt gets INVALID_KEY → the session dies.
    session.send_input(b"exit\n").await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let dead = loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "session never ended after shell exit");
        match tokio::time::timeout(remaining, session.next_event()).await {
            Ok(Some(SessionEvent::Dead(_))) => break true,
            Ok(Some(_)) => {}
            Ok(None) => break false,
            Err(_) => panic!("timeout waiting for session end"),
        }
    };
    assert!(dead);
}

#[tokio::test]
async fn reconnect_catchup_delivers_everything() {
    let (id, passkey) = test_id_passkey();
    let stack = start_stack(&id, &passkey).await;
    let mut session = connect(&stack, &id, &passkey).await;

    session.send_terminal_info(24, 80, 0, 0).await.unwrap();
    session.send_input(b"seq 1 20000\n").await.unwrap();
    // Kill the TCP socket while the server is streaming; the write issued
    // while disconnected must be buffered and delivered after recovery.
    session.kill_socket().await;
    session.send_input(b"echo AFTER_RS_$((40+2))\n").await.unwrap();

    // The predicate must not use substrings: the pty echoes the command
    // line itself ("seq 1 20000"), which contains "20000" verbatim. Count
    // distinct numeric lines instead.
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut marker_seen = false;
    let mut out: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while tokio::time::Instant::now() < deadline && (seen.len() < 20000 || !marker_seen) {
        match tokio::time::timeout(Duration::from_millis(500), session.next_event()).await {
            Ok(Some(SessionEvent::TerminalBuffer(bytes))) => {
                out.extend_from_slice(&bytes);
                let text = String::from_utf8_lossy(&out).to_string();
                for line in text.lines() {
                    if let Ok(n) = line.trim().parse::<u32>() {
                        if (1..=20000).contains(&n) {
                            seen.insert(n);
                        }
                    }
                    if line.contains("AFTER_RS_42") {
                        marker_seen = true;
                    }
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {}
        }
    }
    let text = String::from_utf8_lossy(&out);
    assert!(marker_seen, "buffered post-disconnect input lost");
    if seen.len() != 20000 {
        let missing: Vec<u32> = (1..=20000).filter(|n| !seen.contains(n)).collect();
        let head: String = text.chars().take(160).collect();
        panic!(
            "catch-up lost {} lines: {:?}\noutput head: {head:?}\n'1' anywhere: {}",
            20000 - seen.len(),
            &missing[..missing.len().min(20)],
            text.lines().any(|l| l.trim() == "1")
        );
    }
}

#[tokio::test]
async fn keepalive_is_echoed_while_idle() {
    let (id, passkey) = test_id_passkey();
    let stack = start_stack(&id, &passkey).await;
    // Short keepalive so the test stays fast.
    let payload = InitialPayload::default();
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{}", stack.port),
        id,
        &passkey,
        &payload,
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut got_keepalive = false;
    let mut dead_reason = String::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(3), session.next_event()).await {
            Ok(Some(SessionEvent::KeepAlive)) => {
                got_keepalive = true;
                break;
            }
            Ok(Some(SessionEvent::Dead(reason))) => {
                dead_reason = format!("{reason:?}");
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                dead_reason = "events channel closed".into();
                break;
            }
            Err(_) => {}
        }
    }
    assert!(got_keepalive, "no keepalive echo while idle; dead={dead_reason}");
    session.shutdown().await;
}

#[tokio::test]
async fn fresh_client_cannot_resume_a_live_session() {
    // Session A is live. A second client presenting the SAME id gets
    // RETURNING_CLIENT on its initial connect — it must fail fast with a
    // clear error (a fresh client's nonce phase cannot resume the stream),
    // and session A must keep working afterwards.
    let (id, passkey) = test_id_passkey();
    let stack = start_stack(&id, &passkey).await;
    let mut session = connect(&stack, &id, &passkey).await;
    session.send_input(b"echo FIRST_$((1+1))\n").await.unwrap();

    let payload = InitialPayload::default();
    let Err(err) = TerminalSession::start(
        format!("127.0.0.1:{}", stack.port),
        id.clone(),
        &passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    else {
        panic!("second client with a live id must be rejected");
    };
    let et_client::session::StartError::Connect(
        et_client::ConnectFailure::Protocol(message),
    ) = err
    else {
        panic!("second client with a live id was not rejected with a connect error");
    };
    assert!(message.contains("live session"), "unexpected error: {message}");

    // Session A survived the attempt (server-side recover rolled back).
    let out = collect_until(&mut session, Duration::from_secs(10), |s| s.contains("FIRST_2"))
        .await;
    assert!(
        String::from_utf8_lossy(&out).contains("FIRST_2"),
        "original session broken by second connect: {:?}",
        String::from_utf8_lossy(&out)
    );
    session.shutdown().await;
}

#[tokio::test]
async fn initial_connect_retries_until_terminal_registers() {
    // No sleep between server start and client connect: the etterminal is
    // spawned late, so the first ConnectRequest legitimately hits
    // INVALID_KEY and the start() retry window must absorb it.
    let (id, passkey) = test_id_passkey();
    let dir = std::env::temp_dir().join(format!(
        "et-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
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

    // The etterminal shows up a second in — while start() is already
    // retrying. This mirrors conch's shape: connect immediately after the
    // ssh command returns, registration still in flight.
    let term_socket = socket_path.clone();
    let term_home = dir.clone();
    let term_id = id.clone();
    let term_passkey = passkey.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let _ = et_server::terminal::run(et_server::terminal::TerminalOptions {
            idpasskey: Some((term_id, term_passkey)),
            term: Some("xterm-256color".into()),
            socket_path: Some(term_socket),
            shell: Some("/bin/sh".into()),
            home: Some(term_home),
        })
        .await;
    });

    let payload = InitialPayload::default();
    let mut session = TerminalSession::start(
        format!("127.0.0.1:{port}"),
        id.clone(),
        &passkey,
        &payload,
        DEFAULT_KEEPALIVE,
    )
    .await
    .unwrap_or_else(|e| panic!("start should retry through the registration race: {e}"));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "session never became usable");
        match tokio::time::timeout(Duration::from_millis(500), session.next_event()).await {
            Ok(Some(SessionEvent::Dead(reason))) => {
                panic!("session died while waiting for registration: {reason:?}")
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("session ended before registration"),
            Err(_) => {}
        }
        // Once the terminal registers and a reconnect lands, input works.
        if session.send_input(b"echo LATE_$((21*2))\n").await.is_ok() {
            let mut out: Vec<u8> = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                if String::from_utf8_lossy(&out).contains("LATE_42") {
                    session.shutdown().await;
                    let _ = shutdown.send(true);
                    let _ = std::fs::remove_dir_all(&dir);
                    return;
                }
                assert!(tokio::time::Instant::now() < deadline, "no LATE_42; got {out:?}");
                match tokio::time::timeout(Duration::from_millis(300), session.next_event()).await
                {
                    Ok(Some(SessionEvent::TerminalBuffer(bytes))) => out.extend_from_slice(&bytes),
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("session died waiting for echo"),
                    Err(_) => {}
                }
            }
        }
    }
}

#[tokio::test]
async fn mismatched_protocol_is_rejected() {
    let (id, _passkey) = test_id_passkey();
    let stack = start_stack(&id, "x").await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", stack.port))
        .await
        .unwrap();
    let request = ConnectRequest {
        clientId: Some(id),
        version: Some(PROTOCOL_VERSION - 1),
        ..Default::default()
    };
    et_proto::write_proto_frame(&mut stream, &request.encode_to_vec())
        .await
        .unwrap();
    let bytes = et_proto::read_proto_frame(&mut stream, et_proto::MAX_HANDSHAKE_PROTO_LENGTH)
        .await
        .unwrap();
    let response = et_proto::ConnectResponse::decode_from_slice(&bytes).unwrap();
    assert_eq!(response.status, Some(et_proto::ConnectStatus::MismatchedProtocol));
    assert!(response.error.unwrap().contains("Mismatched protocol versions"));
}

#[tokio::test]
async fn unknown_id_is_invalid_key() {
    let (id, _passkey) = test_id_passkey();
    let stack = start_stack(&id, "x").await;

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", stack.port))
        .await
        .unwrap();
    let request = ConnectRequest {
        clientId: Some("ZZZno-such-client00".into()),
        version: Some(PROTOCOL_VERSION),
        ..Default::default()
    };
    et_proto::write_proto_frame(&mut stream, &request.encode_to_vec())
        .await
        .unwrap();
    let bytes = et_proto::read_proto_frame(&mut stream, et_proto::MAX_HANDSHAKE_PROTO_LENGTH)
        .await
        .unwrap();
    let response = et_proto::ConnectResponse::decode_from_slice(&bytes).unwrap();
    assert_eq!(response.status, Some(et_proto::ConnectStatus::InvalidKey));
    assert_eq!(response.error.as_deref(), Some("Client is not registered"));
}
