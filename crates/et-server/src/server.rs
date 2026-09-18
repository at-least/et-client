//! `etserver`: the TCP-facing daemon. Port of `TerminalServerMain` +
//! `TerminalServer` + `ServerConnection` + `UserTerminalRouter`.
//!
//! Per TCP connection the flow mirrors upstream `ServerConnection::clientHandler`:
//! read `ConnectRequest`, answer `ConnectResponse`
//! (`NEW_CLIENT`/`RETURNING_CLIENT`/`INVALID_KEY`/`MISMATCHED_PROTOCOL`),
//! then either spawn a backed connection and the relay session, or hand the
//! socket to the existing connection's recover exchange.

use std::time::Duration;

use et_proto::backed::{BackedConfig, BackedEvent, BackedHandle};
use et_proto::framing::{read_packet_frame, read_proto_frame, write_packet_frame, write_proto_frame, write_typed_proto};
use et_proto::{ConnectRequest, ConnectResponse, InitialPayload, TerminalBuffer};
use buffa::Message as _;
use et_proto::{
    ConnectStatus, Packet, CLIENT_SERVER_NONCE_MSB, DEFAULT_MAX_PROTO_LENGTH,
    MAX_HANDSHAKE_PROTO_LENGTH, PROTOCOL_VERSION, SERVER_CLIENT_NONCE_MSB, et_packet_type,
    terminal_packet_type,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::time::timeout;

use crate::router::Router;
use crate::ServerError;

/// Upstream default listen port.
pub const DEFAULT_PORT: u16 = 2022;
/// Upstream `INITIAL_PAYLOAD_TIMEOUT_DURATION`: how long a client connection
/// may sit without speaking after `NEW_CLIENT`.
const INITIAL_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// Ceiling for any single handshake frame on the unix leg.
const UNIX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// Terminal→server chunks (`BUF_SIZE` upstream).
const TERMINAL_CHUNK: usize = 16 * 1024;

/// etserver configuration.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub port: u16,
    /// `--serverfifo` override; `None` uses the standard path rules.
    pub socket_path: Option<std::path::PathBuf>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self { port: DEFAULT_PORT, socket_path: None }
    }
}

/// A bound but not yet serving server; exposes the chosen port/socket so
/// tests and embedding callers can point clients at it.
pub struct BoundServer {
    pub tcp: TcpListener,
    pub unix: UnixListener,
    pub socket_path: std::path::PathBuf,
    pub router: Router,
}

/// Binds the TCP and unix listeners (stale socket files removed, directory
/// rules applied). `port: 0` lets the OS pick, `local_addr()` reveals it.
pub async fn bind(opts: ServerOptions) -> Result<BoundServer, ServerError> {
    crate::fifo::create_directories_if_required(opts.socket_path.as_deref())?;
    let socket_path = crate::fifo::path_for_creation(opts.socket_path.as_deref())?;
    // A stale socket file from a crashed daemon would fail bind().
    let _ = std::fs::remove_file(&socket_path);
    let unix = UnixListener::bind(&socket_path)?;
    {
        // Upstream chmods the socket world-accessible (0777); a system
        // daemon restricts the parent directory instead.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o777));
    }
    let tcp = TcpListener::bind(("0.0.0.0", opts.port)).await?;
    Ok(BoundServer { tcp, unix, socket_path, router: Router::default() })
}

/// Accept loop until `shutdown` fires. Removes the unix socket on exit.
pub async fn serve(
    bound: BoundServer,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), ServerError> {
    eprintln!(
        "etserver: listening on {}, socket {:?}",
        bound.tcp.local_addr()?,
        bound.socket_path
    );
    let router = bound.router.clone();
    let result = loop {
        tokio::select! {
            accepted = bound.tcp.accept() => {
                let (stream, _peer) = match accepted {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let router = router.clone();
                tokio::spawn(handle_tcp(router, stream));
            }
            accepted = bound.unix.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let router = router.clone();
                tokio::spawn(register_terminal(router, stream));
            }
            _ = shutdown.changed() => break Ok(()),
        }
    };
    let _ = std::fs::remove_file(&bound.socket_path);
    result
}

/// Bind + serve; the binary's entry point.
pub async fn run(
    opts: ServerOptions,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), ServerError> {
    serve(bind(opts).await?, shutdown).await
}

/// `UserTerminalRouter::acceptNewConnection`: the first packet on the unix
/// socket registers (id, passkey, uid, gid). Unencrypted by design — it is
/// a local socket, and this is how etserver learns the per-session key.
async fn register_terminal(router: Router, stream: UnixStream) {
    let mut stream = stream;
    let packet = match timeout(
        UNIX_HANDSHAKE_TIMEOUT,
        read_packet_frame(&mut stream, DEFAULT_MAX_PROTO_LENGTH),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => return,
    };
    if packet.header() != terminal_packet_type::TERMINAL_USER_INFO {
        return;
    }
    let Ok(tui) = crate::decode_payload::<et_proto::TerminalUserInfo>(&packet) else {
        return;
    };
    let (Some(id), Some(passkey)) = (tui.id.clone(), tui.passkey.clone()) else {
        return;
    };
    let uid = tui.uid.unwrap_or(-1).max(0) as u32;
    let gid = tui.gid.unwrap_or(-1).max(0) as u32;
    if !router.register_terminal(&id, &passkey, uid, gid, stream) {
        eprintln!("etserver: rejecting duplicate terminal registration for {id}");
    }
}

/// `ServerConnection::clientHandler`.
async fn handle_tcp(router: Router, mut stream: TcpStream) {
    stream.set_nodelay(true).ok();
    let request = match read_proto_frame(&mut stream, MAX_HANDSHAKE_PROTO_LENGTH).await {
        Ok(bytes) => ConnectRequest::decode_from_slice(&bytes),
        Err(_) => return,
    };
    let Ok(request) = request else { return };

    if request.version != Some(PROTOCOL_VERSION) {
        let response = ConnectResponse {
            status: Some(ConnectStatus::MismatchedProtocol),
            error: Some(format!(
                "Mismatched protocol versions. Your client & server must be on the same version of ET. Client: {} != Server: {PROTOCOL_VERSION}",
                request.version.unwrap_or(0)
            )),
            ..Default::default()
        };
        let _ = write_proto_frame(&mut stream, &response.encode_to_vec()).await;
        return;
    }
    let Some(id) = request.clientId else { return };

    if let Some(entry) = router.get_client(&id) {
        // `RETURNING_CLIENT`: hand the fresh socket to the live connection
        // for the SequenceHeader/CatchupBuffer exchange.
        let response = ConnectResponse {
            status: Some(ConnectStatus::ReturningClient),
            ..Default::default()
        };
        if write_proto_frame(&mut stream, &response.encode_to_vec()).await.is_err() {
            return;
        }
        let _ = entry.conn.recover(stream).await;
        return;
    }

    if let Some(key) = router.get_key(&id) {
        let response = ConnectResponse {
            status: Some(ConnectStatus::NewClient),
            ..Default::default()
        };
        if write_proto_frame(&mut stream, &response.encode_to_vec()).await.is_err() {
            return;
        }

        let (conn, events) = BackedHandle::spawn(
            stream,
            BackedConfig {
                key: key_bytes(&key),
                // Server directions: reads use the client's writer MSB.
                reader_msb: CLIENT_SERVER_NONCE_MSB,
                writer_msb: SERVER_CLIENT_NONCE_MSB,
                keepalive: None,
            },
        )
        .await;
        router.add_client(&id, &key, conn.clone());
        tokio::spawn(run_session(router, id, key, conn, events));
    } else {
        let response = ConnectResponse {
            status: Some(ConnectStatus::InvalidKey),
            error: Some("Client is not registered".into()),
            ..Default::default()
        };
        let _ = write_proto_frame(&mut stream, &response.encode_to_vec()).await;
    }
}

/// `TerminalServer::handleConnection` + `runTerminal`: the relay between
/// one client connection and its terminal.
async fn run_session(
    router: Router,
    id: String,
    key: String,
    conn: BackedHandle,
    mut events: tokio::sync::mpsc::Receiver<BackedEvent>,
) {
    let cleanup = |router: &Router, id: &str, conn: &BackedHandle| {
        router.remove_client(id);
        let conn = conn.clone();
        tokio::spawn(async move { conn.shutdown().await });
    };

    // Wait for INITIAL_PAYLOAD (600 s deadline, like upstream).
    let packet = match timeout(INITIAL_PAYLOAD_TIMEOUT, wait_packet(&mut events)).await {
        Ok(Some(p)) if p.header() == et_packet_type::INITIAL_PAYLOAD => p,
        _ => {
            eprintln!("etserver: client {id} sent no INITIAL_PAYLOAD; dropping");
            cleanup(&router, &id, &conn);
            return;
        }
    };
    let payload = match crate::decode_payload::<InitialPayload>(&packet) {
        Ok(p) => p,
        Err(_) => {
            cleanup(&router, &id, &conn);
            return;
        }
    };
    if payload.jumphost == Some(true) {
        // Jump mode is not implemented in this port.
        let response = et_proto::InitialResponse {
            error: Some("jumphost mode is not supported by this etserver build".into()),
            ..Default::default()
        };
        let _ = conn
            .write(et_packet_type::INITIAL_RESPONSE, response.encode_to_vec())
            .await;
        eprintln!("etserver: client {id} requested jumphost mode; refusing");
        cleanup(&router, &id, &conn);
        return;
    }

    // The terminal may still be registering; poll until it shows up.
    let deadline = tokio::time::Instant::now() + INITIAL_PAYLOAD_TIMEOUT;
    let (terminal_info, mut unix) = loop {
        if let Some(slot) = router.take_terminal(&id) {
            break slot;
        }
        if tokio::time::Instant::now() >= deadline {
            eprintln!("etserver: no terminal registered for {id}; dropping");
            cleanup(&router, &id, &conn);
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Port forwarding. Upstream etserver always runs the handler here (the
    // terminal never sees PF frames): reverse tunnels (upstream `-r`) bind
    // server-side listeners before INITIAL_RESPONSE, and any bind failure
    // rejects the session with the INITIAL_RESPONSE error string, exactly
    // like upstream runTerminal. Forward tunnels need a live handler even
    // with no reversetunnels configured.
    let (pf_inbound, pf_outbound, bind_errors) =
        et_proto::forward::EngineHandle::spawn(payload.reversetunnels.clone(), true).await;
    let mut pf_outbound = Some(pf_outbound);
    if !payload.reversetunnels.is_empty() && !bind_errors.is_empty() {
        let response = et_proto::InitialResponse {
            error: Some(format!(
                "could not establish reverse tunnels: {}",
                bind_errors.join("; ")
            )),
            ..Default::default()
        };
        let _ = conn
            .write(et_packet_type::INITIAL_RESPONSE, response.encode_to_vec())
            .await;
        cleanup(&router, &id, &conn);
        return;
    }

    // Upstream `ServerClientConnection::verifyPasskey`.
    if !crate::router::verify_passkey(&key, &terminal_info.passkey) {
        eprintln!("etserver: passkey mismatch for {id}");
        cleanup(&router, &id, &conn);
        return;
    }

    // Success: empty INITIAL_RESPONSE (reverse tunnels would go here; not
    // implemented in this port).
    let response = et_proto::InitialResponse { error: None, ..Default::default() };
    if conn
        .write(et_packet_type::INITIAL_RESPONSE, response.encode_to_vec())
        .await
        .is_err()
    {
        cleanup(&router, &id, &conn);
        return;
    }

    // `TERMINAL_INIT` to the terminal with the requested environment. This
    // packet is unencrypted (local unix leg).
    let mut names = Vec::new();
    let mut values = Vec::new();
    for (k, v) in &payload.environmentvariables {
        names.push(k.clone());
        values.push(v.clone());
    }
    let term_init = et_proto::TermInit {
        environmentnames: names,
        environmentvalues: values,
        ..Default::default()
    };
    if write_packet_frame(&mut unix, &Packet::new(terminal_packet_type::TERMINAL_INIT, term_init.encode_to_vec()))
        .await
        .is_err()
    {
        cleanup(&router, &id, &conn);
        return;
    }

    // Relay loop.
    let (mut unix_read, mut unix_write) = unix.split();
    let mut chunk = [0u8; TERMINAL_CHUNK];
    loop {
        tokio::select! {
            pf_frame = async {
                match &mut pf_outbound {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => match pf_frame {
                Some(packet) => {
                    let header = packet.header();
                    let payload = packet.into_payload();
                    if conn.write(header, payload).await.is_err() {
                        break;
                    }
                }
                None => pf_outbound = None,
            },
            event = events.recv() => match event {
                Some(BackedEvent::Packet(packet)) => {
                    match packet.header() {
                        terminal_packet_type::TERMINAL_BUFFER
                        | terminal_packet_type::TERMINAL_INFO => {
                            if write_typed_proto(&mut unix_write, packet.header(), packet.payload())
                                .await
                                .is_err()
                            {
                                // Terminal died: session over.
                                break;
                            }
                        }
                        terminal_packet_type::KEEP_ALIVE => {
                            // Echo (upstream TerminalServer answers here, the
                            // terminal never sees it).
                            let _ = conn.write(terminal_packet_type::KEEP_ALIVE, Vec::new()).await;
                        }
                        terminal_packet_type::PORT_FORWARD_DATA
                        | terminal_packet_type::PORT_FORWARD_DESTINATION_REQUEST
                        | terminal_packet_type::PORT_FORWARD_DESTINATION_RESPONSE => {
                            // Forward-tunnel traffic: the engine opens the
                            // destinations (upstream runs the same handler
                            // inside etserver, never etterminal).
                            pf_inbound.send(packet);
                        }
                        _ => {}
                    }
                }
                Some(BackedEvent::SocketDown) => {
                    // Client offline: keep the session (writes buffer up to
                    // 64 MiB) and wait for the reconnect.
                }
                Some(BackedEvent::Dead(_)) | None => break,
            },
            read = unix_read.read(&mut chunk) => match read {
                Ok(0) | Err(_) => break, // terminal session ended
                Ok(n) => {
                    let tb = TerminalBuffer {
                        buffer: Some(chunk[..n].to_vec()),
                        ..Default::default()
                    };
                    if conn
                        .write(terminal_packet_type::TERMINAL_BUFFER, tb.encode_to_vec())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            },
        }
    }
    eprintln!("etserver: session {id} ended");
    cleanup(&router, &id, &conn);
}

async fn wait_packet(events: &mut tokio::sync::mpsc::Receiver<BackedEvent>) -> Option<Packet> {
    loop {
        match events.recv().await {
            Some(BackedEvent::Packet(p)) => return Some(p),
            Some(BackedEvent::SocketDown) => continue,
            _ => return None,
        }
    }
}

/// The passkey string is the 32-byte key (upstream asserts the length).
fn key_bytes(passkey: &str) -> [u8; 32] {
    debug_assert_eq!(passkey.len(), 32);
    let mut key = [0u8; 32];
    let bytes = passkey.as_bytes();
    key[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    key
}
