//! Terminal session layer: `TerminalClient` minus the console. Owns the
//! `INITIAL_PAYLOAD`/`INITIAL_RESPONSE` exchange and gives typed access to
//! the terminal packet stream, so conch can plug its own terminal emulator
//! and input pipeline in.

use std::time::Duration;

use et_proto::messages::{InitialPayload, InitialResponse, TerminalBuffer, TerminalInfo};
use et_proto::{et_packet_type, terminal_packet_type, Packet};
use prost::Message;

use crate::connection::{EtClient, Event};
use crate::error::ConnectFailure;
use crate::connection::ClientDeadReason;
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
            terminal_packet_type::TERMINAL_BUFFER => SessionEvent::TerminalBuffer(
                TerminalBuffer::decode(packet.payload())
                    .ok()
                    .and_then(|tb| tb.buffer)
                    .unwrap_or_default(),
            ),
            terminal_packet_type::KEEP_ALIVE => SessionEvent::KeepAlive,
            _ => SessionEvent::Other(packet),
        }
    }
}

/// A resilient encrypted terminal session with an `etserver`.
pub struct TerminalSession {
    client: EtClient,
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
                Err(ConnectFailure::Rejected { status: ConnectStatus::InvalidKey, .. })
                    if std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => return Err(e.into()),
            }
        };
        client
            .write(et_packet_type::INITIAL_PAYLOAD, initial_payload.encode_to_vec())
            .await?;

        let wait = async {
            while let Some(event) = client.next_event().await {
                match event {
                    Event::Packet(packet) => {
                        if packet.header() != et_packet_type::INITIAL_RESPONSE {
                            continue;
                        }
                        let response = InitialResponse::decode(packet.payload())
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
        Ok(Self { client })
    }

    /// Send raw input to the shell (`TERMINAL_BUFFER`).
    pub async fn send_input(&self, data: &[u8]) -> Result<(), WriteError> {
        let tb = TerminalBuffer { buffer: Some(data.to_vec()) };
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

    /// End the session.
    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }

    /// Next session event; `None` after the session ended.
    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        match self.client.next_event().await? {
            Event::Packet(packet) => Some(SessionEvent::from_packet(packet)),
            Event::Dead(reason) => Some(SessionEvent::Dead(reason)),
        }
    }
}
