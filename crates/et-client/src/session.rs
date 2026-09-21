//! Terminal session layer: `TerminalClient` minus the console. Owns the
//! `INITIAL_PAYLOAD`/`INITIAL_RESPONSE` exchange and gives typed access to
//! the terminal packet stream, so conch can plug its own terminal emulator
//! and input pipeline in.

use std::time::Duration;

use buffa::Message as _;
use et_proto::forward::{
    EngineHandle, DESTINATION_REQUEST_HEADER, DESTINATION_RESPONSE_HEADER, PORT_FORWARD_HEADER,
};
use et_proto::{et_packet_type, terminal_packet_type, Packet};
use et_proto::{
    InitialPayload, InitialResponse, PortForwardSourceRequest, TerminalBuffer, TerminalInfo,
};
use tokio::sync::mpsc;

use crate::connection::ClientDeadReason;
use crate::connection::{EtClient, Event};
use crate::error::ConnectFailure;
use et_proto::backed::WriteError;
use et_proto::ConnectStatus;

/// Upstream `MAX_CLIENT_KEEP_ALIVE_DURATION`.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(5);
/// Ceiling for the `INITIAL_RESPONSE` wait. Upstream retries for a few
/// seconds and gives up ("Connect Timeout"); one generous window matches the
/// effect without the retry bookkeeping.
const INITIAL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the initial connect may keep retrying `INVALID_KEY` while the
/// freshly-launched etterminal is still registering with etserver.
const INITIAL_INVALID_KEY_RETRY: Duration = Duration::from_secs(3);

/// Failure of [`TerminalSession::start`].
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Connect(#[from] ConnectFailure),
    #[error("write failed: {0}")]
    Write(#[from] WriteError),
    #[error("timed out waiting for INITIAL_RESPONSE")]
    Timeout,
    #[error("expected INITIAL_RESPONSE, got a different packet")]
    UnexpectedPacket,
    #[error("server refused the session: {0}")]
    Server(String),
}

/// Session-level events after the `INITIAL_RESPONSE` gate.
#[derive(Debug)]
pub enum SessionEvent {
    /// Shell output.
    TerminalBuffer(Vec<u8>),
    /// Server's echo of our keepalive (the connection layer enforces
    /// keepalive deadlines itself; this is surfaced for latency probes).
    KeepAlive,
    /// The session ended. One final event, then `next_event` returns `None`.
    Dead(ClientDeadReason),
    /// Anything else (port-forward frames etc.) — passed through so a future
    /// port-forward handler can layer on without changing this API.
    Other(Packet),
}

impl SessionEvent {
    fn from_packet(packet: Packet) -> Self {
        match packet.header() {
            terminal_packet_type::TERMINAL_BUFFER => {
                match TerminalBuffer::decode_from_slice(packet.payload()) {
                    Ok(tb) => SessionEvent::TerminalBuffer(tb.buffer.unwrap_or_default()),
                    // A payload that does not decode is surfaced rather
                    // than silently rendered as empty output.
                    Err(_) => SessionEvent::Other(packet),
                }
            }
            terminal_packet_type::KEEP_ALIVE => SessionEvent::KeepAlive,
            _ => SessionEvent::Other(packet),
        }
    }
}

/// A resilient encrypted terminal session with an `etserver`.
pub struct TerminalSession {
    client: EtClient,
    /// Port-forward engine once [`TerminalSession::start_port_forwarding`]
    /// ran: peer PF frames route in, engine frames write out.
    pf_inbound: Option<EngineHandle>,
    pf_outbound: Option<mpsc::Receiver<Packet>>,
}

impl TerminalSession {
    /// Connect, register with `INITIAL_PAYLOAD`, and wait for a successful
    /// `INITIAL_RESPONSE` (upstream `TerminalClient::run`'s gate before the
    /// terminal loop starts).
    pub async fn start(
        endpoint: String,
        id: String,
        passkey: &str,
        initial_payload: &InitialPayload,
        keepalive: Duration,
    ) -> Result<Self, StartError> {
        // A reconnecting client gets INVALID_KEY when the server has torn
        // the session down — terminal. On the *initial* connect, though,
        // INVALID_KEY can also mean the etterminal has not finished
        // registering yet: upstream hides this behind the ssh round-trip
        // latency, a russh-driven handshake has none. Retry briefly before
        // giving up (deliberate divergence from upstream, which exits).
        let deadline = std::time::Instant::now() + INITIAL_INVALID_KEY_RETRY;
        let mut client = loop {
            match EtClient::connect(endpoint.clone(), id.clone(), passkey, keepalive).await {
                Ok(client) => break client,
                Err(ConnectFailure::Rejected {
                    status: ConnectStatus::InvalidKey,
                    ..
                }) if std::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => return Err(e.into()),
            }
        };
        client
            .write(
                et_packet_type::INITIAL_PAYLOAD,
                initial_payload.encode_to_vec(),
            )
            .await?;

        let wait = async {
            while let Some(event) = client.next_event().await {
                match event {
                    Event::Packet(packet) => {
                        if packet.header() != et_packet_type::INITIAL_RESPONSE {
                            continue;
                        }
                        let response = InitialResponse::decode_from_slice(packet.payload())
                            .map_err(|_| StartError::UnexpectedPacket)?;
                        if let Some(error) = response.error {
                            return Err(StartError::Server(error));
                        }
                        return Ok(());
                    }
                    Event::Dead(reason) => {
                        return Err(StartError::Server(format!("session died: {reason:?}")));
                    }
                }
            }
            Err(StartError::UnexpectedPacket)
        };
        match tokio::time::timeout(INITIAL_RESPONSE_TIMEOUT, wait).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(StartError::Timeout),
        }
        // Upstream clients always run a port-forward handler; when this
        // session declared reverse tunnels, the peer WILL send
        // DESTINATION_REQUESTs — start the engine (destinations only, no
        // local listeners) so they are answered instead of surfacing as
        // unknown packets.
        let (mut pf_inbound, mut pf_outbound) = (None, None);
        if !initial_payload.reversetunnels.is_empty() {
            let (handle, outbound_rx, _) = EngineHandle::spawn(Vec::new(), true).await;
            pf_inbound = Some(handle);
            pf_outbound = Some(outbound_rx);
        }
        Ok(Self {
            client,
            pf_inbound,
            pf_outbound,
        })
    }

    /// Starts port forwarding. `sources` listen **locally** (forward
    /// tunnels, upstream `-t`); every `DESTINATION_REQUEST` the peer sends
    /// opens a loopback connection (reverse tunnels, upstream `-r` client
    /// side). Peer PF frames stop surfacing in
    /// [`TerminalSession::next_event`] and are pumped internally; bind
    /// failures are returned like upstream's
    /// `PortForwardSourceResponse.error` (the session stays usable). When
    /// the session pre-spawned a destinations-only engine for reverse
    /// tunnels, the sources are bound into that running engine — forward
    /// and reverse tunnels combine, like upstream.
    pub async fn start_port_forwarding(
        &mut self,
        sources: Vec<PortForwardSourceRequest>,
    ) -> Result<(), String> {
        let bind_errors = match &self.pf_inbound {
            Some(engine) => engine.add_sources(sources).await,
            None => {
                let (inbound, outbound_rx, bind_errors) = EngineHandle::spawn(sources, true).await;
                self.pf_outbound = Some(outbound_rx);
                self.pf_inbound = Some(inbound);
                bind_errors
            }
        };
        if bind_errors.is_empty() {
            Ok(())
        } else {
            Err(bind_errors.join("; "))
        }
    }

    /// Send raw input to the shell (`TERMINAL_BUFFER`).
    pub async fn send_input(&self, data: &[u8]) -> Result<(), WriteError> {
        let tb = TerminalBuffer {
            buffer: Some(data.to_vec()),
            ..Default::default()
        };
        self.client
            .write(terminal_packet_type::TERMINAL_BUFFER, tb.encode_to_vec())
            .await
    }

    /// Resize the remote terminal (`TERMINAL_INFO`).
    pub async fn send_terminal_info(
        &self,
        row: i32,
        column: i32,
        width: i32,
        height: i32,
    ) -> Result<(), WriteError> {
        let ti = TerminalInfo {
            id: Some(String::new()),
            row: Some(row),
            column: Some(column),
            width: Some(width),
            height: Some(height),
            ..Default::default()
        };
        self.client
            .write(terminal_packet_type::TERMINAL_INFO, ti.encode_to_vec())
            .await
    }

    /// Send an arbitrary packet (library-level escape hatch).
    pub async fn send_packet(&self, header: u8, payload: Vec<u8>) -> Result<(), WriteError> {
        self.client.write(header, payload).await
    }

    /// Force the current socket closed (tests, "network changed" buttons in
    /// a UI). Reconnect happens automatically.
    pub async fn kill_socket(&self) {
        self.client.kill_socket().await;
    }

    /// End the session. Also stops the port-forward engine, releasing its
    /// source listeners and tearing down tunneled connections.
    pub async fn shutdown(&self) {
        if let Some(engine) = &self.pf_inbound {
            engine.shutdown().await;
        }
        self.client.shutdown().await;
    }

    fn is_port_forward_header(header: u8) -> bool {
        header == PORT_FORWARD_HEADER
            || header == DESTINATION_REQUEST_HEADER
            || header == DESTINATION_RESPONSE_HEADER
    }

    /// Hand one peer port-forward packet to the engine. Awaiting the
    /// bounded queue is the backpressure path: while the engine is
    /// saturated (a stalled local tunneled connection holds it in the
    /// data path) the pump parks here, which backs up the supervisor, the
    /// backed layer, and finally the ET socket itself. While parked, the
    /// pump keeps draining the engine's *outbound* side — `reserve` (not
    /// `send`) so the packet is never moved into a future the select
    /// might drop — because only this pump drains outbound and only the
    /// engine drains inbound; parking without draining would deadlock the
    /// two queues against each other. A short tick aborts the park when
    /// the session has died underneath it, so `next_event` cannot hang
    /// behind a queue that will never drain; the parked packet is dropped
    /// (the session is over either way).
    async fn deliver_to_engine(&mut self, packet: Packet) {
        let engine = match self.pf_inbound.as_ref() {
            Some(handle) => handle,
            None => return,
        };
        loop {
            tokio::select! {
                permit = engine.reserve() => match permit {
                    Ok(permit) => {
                        permit.send(packet);
                        return;
                    }
                    Err(_) => return, // engine stopped: nothing to feed
                },
                frame = async {
                    match self.pf_outbound.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => match frame {
                    Some(p) => {
                        let _ = self.client.write(p.header(), p.into_payload()).await;
                    }
                    None => self.pf_outbound = None,
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if self.client.session_ended() {
                        return;
                    }
                }
            }
        }
    }

    /// Next session event; `None` after the session ended. Port-forward
    /// frames (once [`TerminalSession::start_port_forwarding`] ran) are
    /// pumped to the engine and never surface here.
    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        loop {
            tokio::select! {
                frame = async {
                    match &mut self.pf_outbound {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match frame {
                        Some(packet) => {
                            // Best-effort, like upstream writePacket: the
                            // backed writer buffers while disconnected.
                            let header = packet.header();
                            let payload = packet.into_payload();
                            let _ = self.client.write(header, payload).await;
                        }
                        None => self.pf_outbound = None,
                    }
                }
                event = self.client.next_event() => match event? {
                    Event::Packet(packet) => {
                        if Self::is_port_forward_header(packet.header())
                            && self.pf_inbound.is_some()
                        {
                            if self.client.session_ended() {
                                // The session is over; port-forward packets
                                // queued behind the terminal event are dead
                                // weight — drop them instead of parking on
                                // a saturated engine for each.
                                continue;
                            }
                            self.deliver_to_engine(packet).await;
                            continue;
                        }
                        return Some(SessionEvent::from_packet(packet));
                    }
                    Event::Dead(reason) => return Some(SessionEvent::Dead(reason)),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use et_proto::crypto::CryptoHandler;
    use et_proto::framing::{
        read_framed_packet, read_proto_frame, write_framed_packet, write_proto_frame,
    };
    use et_proto::{
        ConnectRequest, ConnectResponse, ConnectStatus, PortForwardData,
        PortForwardDestinationRequest, PortForwardDestinationResponse, SocketEndpoint,
        CLIENT_SERVER_NONCE_MSB, MAX_HANDSHAKE_PROTO_LENGTH, MAX_PACKET_LENGTH, PROTOCOL_VERSION,
        SERVER_CLIENT_NONCE_MSB,
    };
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, timeout_at};

    const ID: &str = "XXXabcdefghijklmnop";
    const PASSKEY: &str = "0123456789abcdef0123456789abcdef";
    const LONG: Duration = Duration::from_secs(5);

    /// A malformed TERMINAL_BUFFER payload must surface as `Other` instead
    /// of being silently rendered as empty output.
    #[test]
    fn undecodable_terminal_buffer_surfaces_as_other() {
        // Truncated varint: not a decodable TerminalBuffer.
        let packet = Packet::new(terminal_packet_type::TERMINAL_BUFFER, vec![0xff, 0xff]);
        assert!(TerminalBuffer::decode_from_slice(packet.payload()).is_err());
        match SessionEvent::from_packet(packet) {
            SessionEvent::Other(_) => {}
            other => panic!("a malformed TERMINAL_BUFFER must surface as Other, got {other:?}"),
        }
    }

    struct Rig {
        peer: tokio::net::TcpStream,
        from_client: CryptoHandler,
        to_client: CryptoHandler,
        /// Still-bound handshake listener: a test can answer the
        /// supervisor's reconnect attempts after dropping `peer`.
        listener: Arc<TcpListener>,
    }

    impl Rig {
        /// Reads one encrypted packet from the client.
        async fn read_client_packet(&mut self) -> Packet {
            let mut packet = read_framed_packet(&mut self.peer, MAX_PACKET_LENGTH)
                .await
                .unwrap();
            assert!(packet.is_encrypted());
            packet.decrypt(&mut self.from_client).unwrap();
            packet
        }
    }

    /// Starts a session against an in-process mock server: handshake
    /// (`NEW_CLIENT`), then the INITIAL_PAYLOAD/INITIAL_RESPONSE exchange.
    async fn start_session(initial_payload: &InitialPayload) -> (TerminalSession, Rig) {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();
        let (session_tx, session_rx) = tokio::sync::oneshot::channel();
        let payload = initial_payload.clone();
        let addr_string = addr.to_string();
        tokio::spawn(async move {
            let session = TerminalSession::start(
                addr_string,
                ID.into(),
                PASSKEY,
                &payload,
                DEFAULT_KEEPALIVE,
            )
            .await;
            let _ = session_tx.send(session);
        });

        let (mut peer, _) = listener.accept().await.unwrap();
        peer.set_nodelay(true).ok();
        let bytes = read_proto_frame(&mut peer, MAX_HANDSHAKE_PROTO_LENGTH)
            .await
            .unwrap();
        let request = ConnectRequest::decode_from_slice(&bytes).unwrap();
        assert_eq!(request.clientId.as_deref(), Some(ID));
        assert_eq!(request.version, Some(PROTOCOL_VERSION));
        let response = ConnectResponse {
            status: Some(ConnectStatus::NewClient),
            ..Default::default()
        };
        write_proto_frame(&mut peer, &response.encode_to_vec())
            .await
            .unwrap();

        let mut key = [0u8; 32];
        key.copy_from_slice(PASSKEY.as_bytes());
        let mut to_client = CryptoHandler::new(&key, SERVER_CLIENT_NONCE_MSB);
        let mut from_client = CryptoHandler::new(&key, CLIENT_SERVER_NONCE_MSB);

        timeout(LONG, async {
            let mut packet = read_framed_packet(&mut peer, MAX_PACKET_LENGTH)
                .await
                .unwrap();
            assert!(packet.is_encrypted());
            packet.decrypt(&mut from_client).unwrap();
            assert_eq!(packet.header(), et_packet_type::INITIAL_PAYLOAD);
            let resp = InitialResponse {
                error: None,
                ..Default::default()
            };
            let mut p = Packet::new(et_packet_type::INITIAL_RESPONSE, resp.encode_to_vec());
            p.encrypt(&mut to_client);
            write_framed_packet(&mut peer, &p).await.unwrap();
        })
        .await
        .expect("the INITIAL exchange must complete");

        let session = timeout(LONG, session_rx).await.unwrap().unwrap().unwrap();
        (session, Rig {
            peer,
            from_client,
            to_client,
            listener,
        })
    }

    /// Answers one supervisor reconnect handshake with `status`.
    async fn answer_reconnect(listener: &TcpListener, status: ConnectStatus) {
        let (mut peer, _) = timeout(LONG, listener.accept())
            .await
            .expect("the supervisor must reconnect")
            .unwrap();
        let bytes = timeout(
            LONG,
            read_proto_frame(&mut peer, MAX_HANDSHAKE_PROTO_LENGTH),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(ConnectRequest::decode_from_slice(&bytes).is_ok());
        let response = ConnectResponse {
            status: Some(status),
            ..Default::default()
        };
        write_proto_frame(&mut peer, &response.encode_to_vec())
            .await
            .unwrap();
    }

    fn source_request(port: u16) -> PortForwardSourceRequest {
        PortForwardSourceRequest {
            source: SocketEndpoint {
                name: Some("127.0.0.1".into()),
                port: Some(port as i32),
                ..Default::default()
            }
            .into(),
            destination: SocketEndpoint {
                name: Some("127.0.0.1".into()),
                port: Some(1),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }
    }

    async fn free_port() -> u16 {
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        probe.local_addr().unwrap().port()
    }

    /// A session whose INITIAL_PAYLOAD declared reverse tunnels auto-spawns
    /// a destinations-only engine; `start_port_forwarding` must add local
    /// sources into the running engine instead of failing with "already
    /// started" (upstream supports `-t` and `-r` together).
    #[tokio::test]
    async fn forward_sources_can_be_added_to_a_reverse_tunnel_session() {
        let payload = InitialPayload {
            reversetunnels: vec![PortForwardSourceRequest::default()],
            ..Default::default()
        };
        let (mut session, mut rig) = start_session(&payload).await;
        let port = free_port().await;

        session
            .start_port_forwarding(vec![source_request(port)])
            .await
            .expect("adding forward sources to a reverse-tunnel session must work");

        // The source is really bound: a local connection reaches the peer
        // as a DESTINATION_REQUEST once the session pump runs.
        let _conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let driver = tokio::spawn(async move { while session.next_event().await.is_some() {} });
        let request = timeout(LONG, async {
            loop {
                let packet = rig.read_client_packet().await;
                if packet.header() == DESTINATION_REQUEST_HEADER {
                    break packet;
                }
            }
        })
        .await
        .expect("the accepted connection must produce a DESTINATION_REQUEST");
        let pf = PortForwardDestinationRequest::decode_from_slice(request.payload()).unwrap();
        assert!(pf.fd.is_some(), "{pf:?}");
        driver.abort();
    }

    /// `shutdown()` ends the session *and* stops the port-forward engine:
    /// the source listener is released.
    #[tokio::test]
    async fn shutdown_releases_the_port_forward_listener() {
        let (mut session, _rig) = start_session(&InitialPayload::default()).await;
        let port = free_port().await;
        session
            .start_port_forwarding(vec![source_request(port)])
            .await
            .unwrap();

        session.shutdown().await;

        // The listener must stop accepting (macOS SO_REUSEADDR allows
        // re-binding a live port, so acceptance is the observable).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match timeout_at(
                deadline,
                tokio::net::TcpStream::connect(("127.0.0.1", port)),
            )
            .await
            {
                Err(_) => panic!("the PF listener must stop accepting after shutdown()"),
                Ok(Ok(_conn)) => continue, // still up; recheck until the deadline
                Ok(Err(_)) => break,       // refused: listener released
            }
        }
    }

    /// A peer flooding port-forward data at a stalled local reverse-tunnel
    /// destination must hit TCP backpressure: the engine wedges in the
    /// data path, the bounded inbound queue fills, the session pump stops
    /// reading — and the peer's own writes then stop completing instead of
    /// being absorbed into client memory without bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pf_flood_backpressures_the_peer_socket() {
        // The reverse-tunnel destination: accepts but never reads.
        let service = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = service.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let destination = SocketEndpoint {
            name: Some("127.0.0.1".into()),
            port: Some(service_port as i32),
            ..Default::default()
        };
        let payload = InitialPayload {
            reversetunnels: vec![PortForwardSourceRequest {
                destination: destination.clone().into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (mut session, mut rig) = start_session(&payload).await;
        let driver = tokio::spawn(async move { while session.next_event().await.is_some() {} });

        // The peer opens the destination; the engine answers with a socket.
        let request = PortForwardDestinationRequest {
            destination: destination.into(),
            fd: Some(1),
            ..Default::default()
        };
        let mut p = Packet::new(DESTINATION_REQUEST_HEADER, request.encode_to_vec());
        p.encrypt(&mut rig.to_client);
        write_framed_packet(&mut rig.peer, &p).await.unwrap();
        let response = timeout(LONG, rig.read_client_packet()).await.unwrap();
        assert_eq!(response.header(), DESTINATION_RESPONSE_HEADER);
        let pf = PortForwardDestinationResponse::decode_from_slice(response.payload()).unwrap();
        let socket_id = pf.socketid.expect("the destination opened");

        // Flood 16 KiB data frames from the peer, counting delivered
        // writes, until the socket closes.
        let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let flood = {
            let mut peer = rig.peer;
            let mut to_client = rig.to_client;
            let sent = sent.clone();
            tokio::spawn(async move {
                loop {
                    let data = PortForwardData {
                        sourcetodestination: Some(true),
                        socketid: Some(socket_id),
                        buffer: Some(vec![0u8; 4 * 1024]),
                        ..Default::default()
                    };
                    let mut frame = Packet::new(PORT_FORWARD_HEADER, data.encode_to_vec());
                    frame.encrypt(&mut to_client);
                    if write_framed_packet(&mut peer, &frame).await.is_err() {
                        break;
                    }
                    sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };

        // The flood must stabilize at the bounded queues (several thousand
        // frames of capacity fill first): sample until three consecutive
        // reads are flat. An unbounded path keeps draining the socket at
        // line rate and the count never stabilizes.
        let mut prev = 0usize;
        let mut flat_streak = 0;
        let froze_at = 'stable: {
            for _ in 0..160 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let now = sent.load(std::sync::atomic::Ordering::Relaxed);
                if now <= prev + 2 {
                    flat_streak += 1;
                    if flat_streak == 3 {
                        break 'stable Some(now);
                    }
                } else {
                    flat_streak = 0;
                }
                prev = now;
            }
            None
        };
        froze_at.expect("the peer must hit TCP backpressure once the queues fill");

        driver.abort();
        flood.abort();
    }

    /// A session pump under sustained inbound port-forward load must keep
    /// draining the engine's *outbound* side: only the pump drains
    /// outbound and only the engine drains inbound, so a pump that parks
    /// on a full inbound queue without draining can wedge the pair (the
    /// engine parks on a full outbound queue in the same window). The
    /// mutual park is race-dependent, so this test pins the observable
    /// contract — reverse-tunnel data keeps flowing under sustained
    /// inbound congestion — rather than one interleaving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_pump_drains_outbound_while_parked_on_a_full_inbound() {
        // A ticker destination: pushes bytes to the engine's local side
        // unsolicited, so its traffic rides the engine→peer outbound path.
        let ticker = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let ticker_port = ticker.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            let (mut stream, _) = ticker.accept().await.unwrap();
            let mut i = 0u64;
            loop {
                if stream
                    .write_all(format!("tick{i};").as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                i += 1;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });

        let payload = InitialPayload {
            reversetunnels: vec![PortForwardSourceRequest::default()],
            ..Default::default()
        };
        let (mut session, mut rig) = start_session(&payload).await;
        // The embedder does NOT poll yet — the pump is not running.

        let request = PortForwardDestinationRequest {
            destination: SocketEndpoint {
                name: Some("127.0.0.1".into()),
                port: Some(ticker_port as i32),
                ..Default::default()
            }
            .into(),
            fd: Some(1),
            ..Default::default()
        };
        let mut p = Packet::new(DESTINATION_REQUEST_HEADER, request.encode_to_vec());
        p.encrypt(&mut rig.to_client);
        write_framed_packet(&mut rig.peer, &p).await.unwrap();
        // Drive the pump only long enough for the open round trip, then
        // stop polling (the response returns to the peer over the wire).
        let response = timeout(LONG, async {
            loop {
                tokio::select! {
                    event = session.next_event() => {
                        assert!(event.is_some(), "the session must stay alive");
                    }
                    response = rig.read_client_packet() => break response,
                }
            }
        })
        .await
        .expect("the destination must open");
        let pf = PortForwardDestinationResponse::decode_from_slice(response.payload()).unwrap();
        let ticker_id = pf.socketid.expect("the ticker destination opened");

        // Split the peer socket: the flood task writes; a reader task
        // counts ticker bytes coming back from the client.
        let (mut read_half, write_half) = rig.peer.into_split();
        let ticker_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader = {
            let ticker_bytes = ticker_bytes.clone();
            tokio::spawn(async move {
                let mut from_client = rig.from_client;
                loop {
                    match read_framed_packet(&mut read_half, MAX_PACKET_LENGTH).await {
                        Ok(mut packet) => {
                            if packet.is_encrypted() && packet.decrypt(&mut from_client).is_ok() {
                                if let Ok(data) =
                                    PortForwardData::decode_from_slice(packet.payload())
                                {
                                    if data.socketid == Some(ticker_id) {
                                        ticker_bytes.fetch_add(
                                            data.buffer.map(|b| b.len()).unwrap_or(0),
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                    }
                                }
                            }
                        }
                        Err(_) => return,
                    }
                }
            })
        };

        // Phase 1 — the ticker fills the engine's outbound queue; with no
        // pump running, the engine parks on its outbound send.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Phase 2 — a sustained inbound flood of frames for an unknown
        // socket id (the engine drops them silently once it consumes
        // them, so the flood pressures the queues without wedging any
        // local connection). The flood holds the peer's write half for
        // its whole life: dropping it would EOF the client's read side
        // and kill the ET socket.
        let flood = {
            let mut to_client = rig.to_client;
            tokio::spawn(async move {
                let mut peer = write_half;
                loop {
                    let data = PortForwardData {
                        sourcetodestination: Some(true),
                        socketid: Some(9999),
                        buffer: Some(vec![0u8; 8]),
                        ..Default::default()
                    };
                    let mut frame = Packet::new(PORT_FORWARD_HEADER, data.encode_to_vec());
                    frame.encrypt(&mut to_client);
                    if write_framed_packet(&mut peer, &frame).await.is_err() {
                        break;
                    }
                }
            })
        };

        // Phase 3 — the embedder resumes polling under sustained inbound
        // congestion; the ticker's reverse data must keep flowing for as
        // long as the session lives (sampled late, past any startup
        // burst, and again after a further window).
        let driver = tokio::spawn(async move { while session.next_event().await.is_some() {} });
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let first = ticker_bytes.load(std::sync::atomic::Ordering::Relaxed);
        assert!(first > 100, "reverse data must flow under congestion: {first}");
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let second = ticker_bytes.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            second > first + 100,
            "reverse data must keep flowing under sustained congestion \
             (ticker bytes {first} → {second})"
        );

        driver.abort();
        flood.abort();
        reader.abort();
    }

    /// A pump parked on a saturated engine (a stalled local tunneled
    /// connection) must not swallow the session's death: when the session
    /// ends underneath the park, `next_event` must surface the terminal
    /// event instead of hanging behind an inbound queue that will never
    /// drain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_parked_pump_surfaces_the_sessions_death() {
        // The stalled destination: accepts but never reads.
        let stalled = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let stalled_port = stalled.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = stalled.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let payload = InitialPayload {
            reversetunnels: vec![PortForwardSourceRequest::default()],
            ..Default::default()
        };
        let (mut session, mut rig) = start_session(&payload).await;

        let request = PortForwardDestinationRequest {
            destination: SocketEndpoint {
                name: Some("127.0.0.1".into()),
                port: Some(stalled_port as i32),
                ..Default::default()
            }
            .into(),
            fd: Some(1),
            ..Default::default()
        };
        let mut p = Packet::new(DESTINATION_REQUEST_HEADER, request.encode_to_vec());
        p.encrypt(&mut rig.to_client);
        write_framed_packet(&mut rig.peer, &p).await.unwrap();
        // Drive the pump only long enough for the open round trip.
        let response = timeout(LONG, async {
            loop {
                tokio::select! {
                    event = session.next_event() => {
                        assert!(event.is_some(), "the session must stay alive");
                    }
                    response = rig.read_client_packet() => break response,
                }
            }
        })
        .await
        .expect("the destination must open");
        let pf = PortForwardDestinationResponse::decode_from_slice(response.payload()).unwrap();
        let stalled_id = pf.socketid.expect("the stalled destination opened");

        // Flood the stalled destination with 4 KiB frames until the
        // engine wedges in the data path and the pump parks on the full
        // inbound queue (the queues are frame-counted, so the wedge point
        // is stable; the session's own event chain stays well below its
        // capacity — the death must stay routable through it). The pump
        // runs alongside; when the flood
        // task finishes, dropping the peer's write half kills the ET
        // socket (the supervisor reconnects; the mock answers NEW_CLIENT —
        // the terminal ServerStateLost path).
        let (_read_half, write_half) = rig.peer.into_split();
        let mut to_client = rig.to_client;
        let flood = tokio::spawn(async move {
            let mut peer = write_half;
            for _ in 0..1200 {
                let data = PortForwardData {
                    sourcetodestination: Some(true),
                    socketid: Some(stalled_id),
                    buffer: Some(vec![0u8; 4 * 1024]),
                    ..Default::default()
                };
                let mut frame = Packet::new(PORT_FORWARD_HEADER, data.encode_to_vec());
                frame.encrypt(&mut to_client);
                if write_framed_packet(&mut peer, &frame).await.is_err() {
                    break;
                }
            }
        });
        let mut flood = flood;
        timeout(LONG * 8, async {
            loop {
                tokio::select! {
                    event = session.next_event() => {
                        assert!(event.is_some(), "the session must stay alive");
                    }
                    done = &mut flood => {
                        let _ = done;
                        break;
                    }
                }
            }
        })
        .await
        .expect("the flood must complete");

        answer_reconnect(&rig.listener, ConnectStatus::NewClient).await;

        match timeout(Duration::from_secs(8), session.next_event()).await {
            Ok(Some(SessionEvent::Dead(ClientDeadReason::ServerStateLost))) => {}
            other => panic!("the parked pump must surface the death, got {other:?}"),
        }
    }
}
