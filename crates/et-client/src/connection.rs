//! Client-side connection wrapper: the plaintext `ConnectRequest`/
//! `ConnectResponse` handshake plus the reconnect supervisor
//! (`ClientConnection::pollReconnect`), on top of the shared backed
//! connection state machine in [`et_proto::backed`].

use std::time::Duration;

use et_proto::backed::{BackedConfig, BackedEvent, BackedHandle, WriteError};
use et_proto::messages::{ConnectRequest, ConnectResponse};
use prost::Message as _;
use et_proto::{
    ConnectStatus, DeadReason, Packet, CLIENT_SERVER_NONCE_MSB, MAX_HANDSHAKE_PROTO_LENGTH,
    PROTOCOL_VERSION, SERVER_CLIENT_NONCE_MSB,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::error::ConnectFailure;

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

fn frame_error_to_connect_failure(e: et_proto::FrameError) -> ConnectFailure {
    match e {
        et_proto::FrameError::Io(io) => ConnectFailure::Io(io),
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
            client_id: Some(id.to_string()),
            version: Some(PROTOCOL_VERSION),
        };
        et_proto::write_proto_frame(&mut stream, &request.encode_to_vec())
            .await
            .map_err(frame_error_to_connect_failure)?;
        let bytes = timeout(
            HANDSHAKE_TIMEOUT,
            et_proto::read_proto_frame(&mut stream, MAX_HANDSHAKE_PROTO_LENGTH),
        )
        .await
        .map_err(|_| ConnectFailure::Timeout)?
        .map_err(frame_error_to_connect_failure)?;
        let response = ConnectResponse::decode(&bytes[..])
            .map_err(|e| ConnectFailure::Protocol(format!("bad ConnectResponse: {e}")))?;
        match ConnectStatus::from_i32(response.status()) {
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
                    "this id already has a live session on the server and a fresh client                      cannot resume it; rerun the ssh handshake to get a new id"
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
                keepalive: Some(keepalive),
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
                match backed_events.recv().await {
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
                        let _ = events_tx.send(Event::Dead(ClientDeadReason::Other(reason))).await;
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
