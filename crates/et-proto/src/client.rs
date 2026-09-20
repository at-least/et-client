//! Client-side connection wrapper: the plaintext `ConnectRequest`/
//! `ConnectResponse` handshake plus the reconnect supervisor
//! (`ClientConnection::pollReconnect`), on top of the shared backed
//! connection state machine in [`crate::backed`].

use std::time::Duration;

use crate::backed::{BackedConfig, BackedEvent, BackedHandle, WriteError};
use crate::{ConnectRequest, ConnectResponse};
use crate::{
    ConnectStatus, DeadReason, Packet, CLIENT_SERVER_NONCE_MSB, MAX_HANDSHAKE_PROTO_LENGTH,
    PROTOCOL_VERSION, SERVER_CLIENT_NONCE_MSB,
};
use buffa::Message as _;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Keepalive: `None` disables client-side enforcement (the jump relay).
pub type Keepalive = std::option::Option<Duration>;

/// Failure of the *initial* TCP handshake (`ConnectRequest` →
/// `ConnectResponse`). The reconnect loop never surfaces these: it retries
/// forever (mirroring upstream), except `InvalidKey`, which ends the session.
#[derive(Debug, thiserror::Error)]
pub enum ConnectFailure {
    #[error("tcp connect failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake timed out")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("server rejected the session: {status:?}: {error}")]
    Rejected {
        status: ConnectStatus,
        error: String,
    },
}

/// Upstream reconnect cadence (`pollReconnect`): 1 s between attempts.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// Ceiling for the handshake exchange (upstream bounds each handshake read
/// at 30 s idle / 60 s absolute).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a session ended. `InvalidKey` is what the client sees after the
/// server tears the session down (shell exited, `etterminal` died, server
/// restarted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeadReason {
    InvalidKey,
    /// A reconnect answered `NEW_CLIENT`: the server lost this session's
    /// connection state (partial-connection cleanup, daemon restart) while
    /// the key survived. The server's fresh crypto phase cannot
    /// resynchronize with our mid-stream handlers, so the session ends;
    /// upstream instead retries in a silent loop forever.
    ServerStateLost,
    Other(DeadReason),
}

/// What the client connection sends its owner.
#[derive(Debug)]
pub enum Event {
    /// A decrypted packet, in wire order; catch-up entries arrive first.
    Packet(Packet),
    /// The session is over; one final event, then the channel closes.
    Dead(ClientDeadReason),
}

fn frame_error_to_connect_failure(e: crate::FrameError) -> ConnectFailure {
    match e {
        crate::FrameError::Io(io) => ConnectFailure::Io(io),
        other => ConnectFailure::Protocol(other.to_string()),
    }
}

/// Outcome of the plaintext handshake on a fresh socket.
enum Handshake {
    NewClient(TcpStream),
    Returning(TcpStream),
}

/// `ConnectRequest` → `ConnectResponse` (i64-LE framed protos, both
/// plaintext — the id must be readable before the per-client key is known,
/// exactly like upstream).
async fn handshake_request(endpoint: &str, id: &str) -> Result<Handshake, ConnectFailure> {
    let attempt = async {
        let mut stream = TcpStream::connect(endpoint.to_string()).await?;
        let request = ConnectRequest {
            clientId: Some(id.to_string()),
            version: Some(PROTOCOL_VERSION),
            ..Default::default()
        };
        crate::write_proto_frame(&mut stream, &request.encode_to_vec())
            .await
            .map_err(frame_error_to_connect_failure)?;
        let bytes = timeout(
            HANDSHAKE_TIMEOUT,
            crate::read_proto_frame(&mut stream, MAX_HANDSHAKE_PROTO_LENGTH),
        )
        .await
        .map_err(|_| ConnectFailure::Timeout)?
        .map_err(frame_error_to_connect_failure)?;
        let response = ConnectResponse::decode_from_slice(&bytes)
            .map_err(|e| ConnectFailure::Protocol(format!("bad ConnectResponse: {e}")))?;
        match response.status {
            Some(ConnectStatus::NewClient) => Ok(Handshake::NewClient(stream)),
            Some(ConnectStatus::ReturningClient) => Ok(Handshake::Returning(stream)),
            Some(status) => Err(ConnectFailure::Rejected {
                status,
                error: response.error.unwrap_or_default(),
            }),
            None => Err(ConnectFailure::Protocol(format!(
                "ConnectResponse without status: {response:?}"
            ))),
        }
    };
    match timeout(HANDSHAKE_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => Err(ConnectFailure::Timeout),
    }
}

/// Handle to a resilient client connection: initial handshake done, writes
/// buffer while offline, reconnection is automatic.
pub struct EtClient {
    backed: BackedHandle,
    events_rx: mpsc::Receiver<Event>,
}

impl EtClient {
    /// `ClientConnection::connect`: TCP connect + `ConnectRequest`/
    /// `ConnectResponse`. Accepts `NEW_CLIENT` (fresh session) and
    /// `RETURNING_CLIENT` (a previous incarnation of this id still exists
    /// server-side and recovery already ran), like upstream.
    pub async fn connect(
        endpoint: String,
        id: String,
        passkey: &str,
        keepalive: Duration,
    ) -> Result<Self, ConnectFailure> {
        Self::connect_with(endpoint, id, passkey, Some(keepalive)).await
    }

    /// Like [`EtClient::connect`] with optional keepalive enforcement (the
    /// jump relay manages its own idle handling).
    pub async fn connect_with(
        endpoint: String,
        id: String,
        passkey: &str,
        keepalive: Keepalive,
    ) -> Result<Self, ConnectFailure> {
        let key = key_bytes(passkey)
            .ok_or_else(|| ConnectFailure::Protocol("passkey must be 32 bytes".into()))?;
        let stream = match handshake_request(&endpoint, &id).await {
            Ok(Handshake::NewClient(stream)) => stream,
            Ok(Handshake::Returning(stream)) => {
                // `RETURNING_CLIENT` on an initial connect means a live
                // session with its own nonce/sequence phase still exists
                // under this id. A fresh client's handlers restart at nonce
                // 1 while the server continues mid-stream, so resumption is
                // impossible by construction; upstream wedges ~60 s here
                // (its recover exchange reads our packet-framed socket as
                // i64-framed protos) and then times out. Fail fast and
                // leave the live session untouched — the server's failed
                // recover rolls back to the old socket.
                drop(stream);
                return Err(ConnectFailure::Protocol(
                    "this id already has a live session on the server and a fresh client cannot \
                     resume it; rerun the ssh handshake to get a new id"
                        .to_string(),
                ));
            }
            Err(e) => return Err(e),
        };

        let (backed, mut backed_events) = BackedHandle::spawn(
            stream,
            BackedConfig {
                key,
                reader_msb: SERVER_CLIENT_NONCE_MSB,
                writer_msb: CLIENT_SERVER_NONCE_MSB,
                keepalive,
            },
        )
        .await;
        let (events_tx, events_rx) = mpsc::channel(1024);

        // The supervisor task *is* `pollReconnect`: on `SocketDown`, retry
        // the handshake every second forever until `RETURNING_CLIENT`
        // (recover through the handle) or `INVALID_KEY` (session dead).
        let sup_endpoint = endpoint.clone();
        let sup_id = id.clone();
        let sup_backed = backed.clone();
        tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    event = backed_events.recv() => event,
                    // The owner dropped the client: return so the last
                    // handle clone drops and the backed actor's command
                    // channel closes — without keepalive traffic or a
                    // tick, nothing else would carry the notice.
                    _ = events_tx.closed() => return,
                };
                match event {
                    Some(BackedEvent::Packet(packet)) => {
                        if events_tx.send(Event::Packet(packet)).await.is_err() {
                            return;
                        }
                    }
                    Some(BackedEvent::SocketDown) => loop {
                        match handshake_request(&sup_endpoint, &sup_id).await {
                            Ok(Handshake::Returning(stream)) => {
                                if sup_backed.recover(stream).await {
                                    break;
                                }
                            }
                            // NEW_CLIENT on reconnect: the server kept the
                            // key but lost the connection entry.
                            Ok(Handshake::NewClient(stream)) => {
                                drop(stream);
                                let _ = events_tx
                                    .send(Event::Dead(ClientDeadReason::ServerStateLost))
                                    .await;
                                return;
                            }
                            Err(ConnectFailure::Rejected {
                                status: ConnectStatus::InvalidKey,
                                ..
                            }) => {
                                let _ = events_tx
                                    .send(Event::Dead(ClientDeadReason::InvalidKey))
                                    .await;
                                let _ = sup_backed.shutdown().await;
                                return;
                            }
                            // MISMATCHED_PROTOCOL and every other failure:
                            // logged upstream, retried here.
                            Err(_) => {}
                        }
                        tokio::time::sleep(RECONNECT_DELAY).await;
                    },
                    Some(BackedEvent::Dead(reason)) => {
                        let _ = events_tx
                            .send(Event::Dead(ClientDeadReason::Other(reason)))
                            .await;
                        return;
                    }
                    None => return,
                }
            }
        });

        Ok(Self { backed, events_rx })
    }

    /// `Connection::writePacket`: encrypts, backs up, flushes. While
    /// disconnected this only buffers and still returns `Ok(())`
    /// (`BUFFERED_ONLY`), like upstream.
    pub async fn write(&self, header: u8, payload: Vec<u8>) -> Result<(), WriteError> {
        self.backed.write(header, payload).await
    }

    /// `closeSocketAndMaybeReconnect` without the "maybe".
    pub async fn kill_socket(&self) {
        self.backed.kill_socket().await;
    }

    /// `Connection::shutdown`.
    pub async fn shutdown(&self) {
        self.backed.shutdown().await;
    }

    /// Next event; `None` after the session ended.
    pub async fn next_event(&mut self) -> Option<Event> {
        self.events_rx.recv().await
    }
}

/// Upstream asserts `key.length() == crypto_secretbox_KEYBYTES`: the
/// passkey string *is* the 32-byte key.
fn key_bytes(passkey: &str) -> Option<[u8; 32]> {
    let bytes = passkey.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{
        read_framed_packet, read_proto_frame, write_framed_packet, write_proto_frame,
    };
    use crate::gen::et::{CatchupBuffer, SequenceHeader};
    use crate::{DEFAULT_MAX_PROTO_LENGTH, MAX_PACKET_LENGTH};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    const ID: &str = "XXXabcdefghijklmnop";
    const PASSKEY: &str = "0123456789abcdef0123456789abcdef";
    const KEEPALIVE: Keepalive = Some(Duration::from_secs(5));
    const LONG: Duration = Duration::from_secs(5);

    struct ServerRig {
        listener: Arc<TcpListener>,
        addr: SocketAddr,
    }

    async fn server_rig() -> ServerRig {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        ServerRig {
            listener: Arc::new(listener),
            addr,
        }
    }

    async fn connect(rig: &ServerRig) -> Result<EtClient, ConnectFailure> {
        EtClient::connect_with(rig.addr.to_string(), ID.to_string(), PASSKEY, KEEPALIVE).await
    }

    /// Accepts one connection, consumes the ConnectRequest, answers
    /// `status`, and returns the peer end for data-plane interaction.
    async fn accept_handshake(listener: &TcpListener, status: ConnectStatus) -> TcpStream {
        let (mut peer, _) = listener.accept().await.unwrap();
        peer.set_nodelay(true).ok();
        let bytes = read_proto_frame(&mut peer, MAX_HANDSHAKE_PROTO_LENGTH)
            .await
            .unwrap();
        let request = ConnectRequest::decode_from_slice(&bytes).unwrap();
        assert_eq!(request.clientId.as_deref(), Some(ID));
        assert_eq!(request.version, Some(PROTOCOL_VERSION));
        let response = ConnectResponse {
            status: Some(status),
            error: None,
            ..Default::default()
        };
        write_proto_frame(&mut peer, &response.encode_to_vec())
            .await
            .unwrap();
        peer
    }

    /// One scripted handshake as its own task; the receiver resolves once
    /// the reply is on the wire. Only safe when no other task accepts from
    /// the same listener concurrently — otherwise accepts race. For ordered
    /// multi-connection scripts, call [`accept_handshake`] sequentially
    /// inside one task instead.
    fn spawn_handshake(rig: &ServerRig, status: ConnectStatus) -> oneshot::Receiver<TcpStream> {
        let listener = rig.listener.clone();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = tx.send(accept_handshake(&listener, status).await);
        });
        rx
    }

    struct PeerCrypto {
        writer: crate::crypto::CryptoHandler,
        reader: crate::crypto::CryptoHandler,
    }

    fn peer_crypto() -> PeerCrypto {
        let key = key_bytes(PASSKEY).unwrap();
        PeerCrypto {
            writer: crate::crypto::CryptoHandler::new(&key, SERVER_CLIENT_NONCE_MSB),
            reader: crate::crypto::CryptoHandler::new(&key, CLIENT_SERVER_NONCE_MSB),
        }
    }

    async fn read_client_packet(
        peer: &mut TcpStream,
        reader: &mut crate::crypto::CryptoHandler,
    ) -> Packet {
        let mut packet = read_framed_packet(peer, MAX_PACKET_LENGTH).await.unwrap();
        assert!(packet.is_encrypted());
        packet.decrypt(reader).unwrap();
        packet
    }

    async fn send_peer_packet(
        peer: &mut TcpStream,
        writer: &mut crate::crypto::CryptoHandler,
        header: u8,
        payload: &[u8],
    ) {
        let mut packet = Packet::new(header, payload.to_vec());
        packet.encrypt(writer);
        write_framed_packet(peer, &packet).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_passkeys_that_are_not_32_bytes() {
        let rig = server_rig().await;
        let err = match EtClient::connect_with(rig.addr.to_string(), ID.into(), "short", KEEPALIVE)
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("a short passkey must be rejected"),
        };
        assert!(
            matches!(err, ConnectFailure::Protocol(ref m) if m.contains("32 bytes")),
            "{err}"
        );
    }

    /// `RETURNING_CLIENT` on an *initial* connect means a live session
    /// already owns this id: fail fast instead of wedging like upstream.
    #[tokio::test]
    async fn returning_client_on_initial_connect_fails_fast() {
        let rig = server_rig().await;
        let rx = spawn_handshake(&rig, ConnectStatus::ReturningClient);
        let err = match connect(&rig).await {
            Err(e) => e,
            Ok(_) => panic!("an id with a live session must be rejected"),
        };
        let _ = rx.await;
        assert!(
            matches!(err, ConnectFailure::Protocol(ref m) if m.contains("already has a live session")),
            "{err}"
        );
    }

    /// Dropping the client ends the whole stack promptly — even with
    /// keepalive disabled (the jump-relay configuration), where no
    /// keepalive tick or traffic would otherwise carry the notice to the
    /// actor; the mock peer sees the socket close.
    #[tokio::test]
    async fn dropping_the_client_closes_the_socket_promptly_without_keepalive() {
        let rig = server_rig().await;
        let rx = spawn_handshake(&rig, ConnectStatus::NewClient);
        let client = EtClient::connect_with(rig.addr.to_string(), ID.into(), PASSKEY, None)
            .await
            .unwrap();
        let mut peer = rx.await.unwrap();
        drop(client);

        let mut eof = vec![0u8; 4];
        let read = timeout(Duration::from_secs(2), peer.read_exact(&mut eof)).await;
        let read = read.expect("the socket must close within 2s of dropping the client");
        assert!(read.is_err(), "expected EOF after the drop, got {read:?}");
    }

    /// Reconnect answered `NEW_CLIENT`: the server kept the key but lost
    /// the connection state, the streams can never resynchronize, and the
    /// session ends with `ServerStateLost`.
    #[tokio::test]
    async fn reconnect_answered_new_client_ends_the_session() {
        let rig = server_rig().await;
        let rx1 = spawn_handshake(&rig, ConnectStatus::NewClient);
        let mut client = connect(&rig).await.unwrap();
        let mut peer1 = rx1.await.unwrap();
        let mut pc = peer_crypto();

        client.write(1, b"hi".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer1, &mut pc.reader).await;
        assert_eq!(packet.payload(), b"hi");

        drop(peer1);
        let rx2 = spawn_handshake(&rig, ConnectStatus::NewClient);
        let _peer2 = rx2.await.unwrap();
        match timeout(LONG, client.next_event()).await.unwrap() {
            Some(Event::Dead(ClientDeadReason::ServerStateLost)) => {}
            other => panic!("expected Dead(ServerStateLost), got {other:?}"),
        }
        assert!(
            client.next_event().await.is_none(),
            "the channel closes afterwards"
        );
    }

    /// Reconnect answered `INVALID_KEY`: the server tore the session down;
    /// the supervisor reports the death and shuts the backed layer down.
    #[tokio::test]
    async fn reconnect_answered_invalid_key_ends_the_session() {
        let rig = server_rig().await;
        let rx1 = spawn_handshake(&rig, ConnectStatus::NewClient);
        let mut client = connect(&rig).await.unwrap();
        let mut peer1 = rx1.await.unwrap();
        let mut pc = peer_crypto();

        client.write(1, b"hi".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer1, &mut pc.reader).await;
        assert_eq!(packet.payload(), b"hi");

        drop(peer1);
        let rx2 = spawn_handshake(&rig, ConnectStatus::InvalidKey);
        let _ = rx2.await.unwrap();
        match timeout(LONG, client.next_event()).await.unwrap() {
            Some(Event::Dead(ClientDeadReason::InvalidKey)) => {}
            other => panic!("expected Dead(InvalidKey), got {other:?}"),
        }
        assert_eq!(
            client.write(1, b"x".to_vec()).await,
            Err(WriteError::Shutdown),
            "the supervisor shut the backed layer down"
        );
        assert!(client.next_event().await.is_none());
    }

    /// A dropped socket, one retryable handshake failure
    /// (`MISMATCHED_PROTOCOL`), then `RETURNING_CLIENT` with the recover
    /// exchange: the session comes back on the new socket with the undelivered
    /// packet resent as identical ciphertext, both nonce streams unbroken.
    #[tokio::test]
    async fn reconnect_retries_then_recovers_on_returning_client() {
        let rig = server_rig().await;
        let rx1 = spawn_handshake(&rig, ConnectStatus::NewClient);
        let mut client = connect(&rig).await.unwrap();
        let mut peer1 = rx1.await.unwrap();
        let mut pc = peer_crypto();

        client.write(1, b"pre".to_vec()).await.unwrap();
        let pre = {
            // Serialize before decrypting: the backup stores ciphertext.
            let wire = read_framed_packet(&mut peer1, MAX_PACKET_LENGTH)
                .await
                .unwrap();
            let bytes = wire.serialize();
            let mut packet = wire;
            packet.decrypt(&mut pc.reader).unwrap();
            assert_eq!(packet.payload(), b"pre");
            bytes
        };

        drop(peer1);
        // One task owns every later accept in arrival order (concurrent
        // acceptors would race): attempt #2 gets a retryable
        // MISMATCHED_PROTOCOL; attempt #3, after the supervisor's 1 s
        // backoff, returns the session via the recover exchange.
        let listener = rig.listener.clone();
        let exchange = tokio::spawn(async move {
            accept_handshake(&listener, ConnectStatus::MismatchedProtocol).await;
            let mut peer3 = accept_handshake(&listener, ConnectStatus::ReturningClient).await;
            let bytes = read_proto_frame(&mut peer3, MAX_HANDSHAKE_PROTO_LENGTH)
                .await
                .unwrap();
            let sh = SequenceHeader::decode_from_slice(&bytes).unwrap();
            assert_eq!(sh.sequenceNumber, Some(0), "the peer delivered nothing");
            write_proto_frame(
                &mut peer3,
                &SequenceHeader {
                    sequenceNumber: Some(0),
                    ..Default::default()
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
            let bytes = read_proto_frame(&mut peer3, DEFAULT_MAX_PROTO_LENGTH)
                .await
                .unwrap();
            let catchup = CatchupBuffer::decode_from_slice(&bytes).unwrap();
            write_proto_frame(&mut peer3, &CatchupBuffer::default().encode_to_vec())
                .await
                .unwrap();
            (peer3, catchup.buffer)
        });

        let (mut peer3, entries) = exchange.await.unwrap();
        assert_eq!(
            entries.len(),
            1,
            "the packet from the dead socket is resent"
        );
        assert_eq!(entries[0], pre, "catch-up resends identical ciphertext");

        client.write(2, b"post".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer3, &mut pc.reader).await;
        assert_eq!(packet.header(), 2);
        assert_eq!(packet.payload(), b"post");

        send_peer_packet(&mut peer3, &mut pc.writer, 3, b"down").await;
        match timeout(LONG, client.next_event()).await.unwrap() {
            Some(Event::Packet(packet)) => {
                assert_eq!(packet.header(), 3);
                assert_eq!(packet.payload(), b"down");
            }
            other => panic!("expected a packet on the recovered session, got {other:?}"),
        }
    }
}
