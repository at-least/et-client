//! The backed, resumable packet connection shared by both peers — the port
//! of upstream `BackedReader`/`BackedWriter`/`Connection`.
//!
//! Upstream runs the same classes on both sides (`ClientConnection` and
//! `ServerClientConnection` both embed them); only the nonce directions and
//! who initiates reconnection differ. This module therefore implements the
//! state machine once:
//!
//! - `writer_msb`/`reader_msb` select the nonce directions (client: write 0
//!   / read 1; server: the reverse);
//! - the owner drives reconnection: a fresh `RETURNING_CLIENT` socket is
//!   handed over with [`BackedHandle::recover`], which performs the
//!   symmetric SequenceHeader/CatchupBuffer exchange;
//! - keepalive enforcement (send KEEP_ALIVE after N idle, kill the socket
//!   after the next N) is the client's job upstream, so it is behind
//!   `keepalive: Option<Duration>`.
//!
//! Invariants fixed by upstream, in one place:
//! - nonce handlers live as long as the *session*, never the socket;
//! - the backup buffer stores serialized **ciphertext**; catch-up resends
//!   identical bytes and never re-encrypts;
//! - the recover exchange order is identical on both peers (both write
//!   their reader sequence first, so nobody deadlocks);
//! - writes while disconnected buffer up to `DISCONNECT_BUFFER_BYTES` and
//!   still succeed (`BUFFERED_ONLY`); past that they are `SKIPPED`;
//! - the backup is trimmed only while connected — disconnected data must
//!   survive for catch-up.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::crypto::CryptoHandler;
use crate::framing::{read_proto_frame, write_proto_frame};
use crate::messages::{CatchupBuffer, SequenceHeader};
use crate::packet::Packet;
use crate::{
    DEFAULT_MAX_PROTO_LENGTH, MAX_HANDSHAKE_PROTO_LENGTH, MAX_PACKET_LENGTH,
    terminal_packet_type,
};
use prost::Message as _;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

/// Upstream `BackedWriter::MAX_BACKUP_BYTES`.
pub const MAX_BACKUP_BYTES: i64 = 64 * 1024 * 1024;
/// Upstream `BackedWriter::DISCONNECT_BUFFER_BYTES`.
pub const DISCONNECT_BUFFER_BYTES: i64 = 64 * 1024 * 1024;
/// Ceiling for every recover exchange (upstream: 30 s idle / 60 s absolute
/// per handshake read).
pub const RECOVER_TIMEOUT: Duration = Duration::from_secs(60);
const WRITE_QUEUE_DEPTH: usize = 1024;
const EVENT_QUEUE_DEPTH: usize = 1024;

/// Outcome of a write. [`WriteError::Skipped`] is upstream
/// `BackedWriterWriteState::SKIPPED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    #[error("disconnect buffer full, packet skipped")]
    Skipped,
    #[error("session is shutting down")]
    Shutdown,
}

/// Terminal event of a backed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadReason {
    /// `shutdown()` was called.
    Shutdown,
    /// Decryption failed — the stream is unrecoverable (upstream STFATALs).
    CryptoMismatch,
}

#[derive(Debug)]
pub enum BackedEvent {
    /// A decrypted packet, in order (catch-up first).
    Packet(Packet),
    /// The live socket was lost (`closeSocket`). Writes keep buffering; the
    /// owner decides when/whether to reconnect (client: supervisor loop;
    /// server: wait for the peer).
    SocketDown,
    /// Terminal event; the channel closes afterwards.
    Dead(DeadReason),
}

enum Cmd {
    Write { header: u8, payload: Vec<u8>, reply: oneshot::Sender<Result<(), WriteError>> },
    KillSocket,
    Recover { stream: TcpStream, reply: oneshot::Sender<bool> },
    Shutdown,
}

/// Configuration: key and nonce directions (upstream constructs the reader
/// and writer `CryptoHandler`s with swapped MSBs per side).
#[derive(Clone)]
pub struct BackedConfig {
    pub key: [u8; 32],
    pub reader_msb: u8,
    pub writer_msb: u8,
    /// Client-side keepalive enforcement; `None` on the server.
    pub keepalive: Option<Duration>,
}

/// Handle to a running backed connection. Clonable; the actor stops when
/// every clone is dropped (the command channel closing is a shutdown).
#[derive(Clone)]
pub struct BackedHandle {
    cmd_tx: mpsc::Sender<Cmd>,
}

impl BackedHandle {
    /// Takes over an already-handshaked socket (`NEW_CLIENT` path). Returns
    /// the handle and the event stream.
    pub async fn spawn(stream: TcpStream, cfg: BackedConfig) -> (Self, mpsc::Receiver<BackedEvent>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE_DEPTH);
        let actor = BackedActor::new(cfg, events_tx);
        let live = actor.spawn_socket_tasks(stream);
        tokio::spawn(actor.run(cmd_rx, live));
        (Self { cmd_tx }, events_rx)
    }

    pub async fn write(&self, header: u8, payload: Vec<u8>) -> Result<(), WriteError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Cmd::Write { header, payload, reply: reply_tx })
            .await
            .is_err()
        {
            return Err(WriteError::Shutdown);
        }
        reply_rx.await.map_err(|_| WriteError::Shutdown)?
    }

    /// `closeSocketAndMaybeReconnect` without the "maybe": drop the current
    /// socket. The owner decides what to do next (client: reconnect loop;
    /// server: wait for the client to come back).
    pub async fn kill_socket(&self) {
        let _ = self.cmd_tx.send(Cmd::KillSocket).await;
    }

    /// `Connection::recover` over a socket whose handshake answered
    /// `RETURNING_CLIENT`. Returns `true` when the socket went live.
    pub async fn recover(&self, stream: TcpStream) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Cmd::Recover { stream, reply: reply_tx })
            .await
            .is_err()
        {
            return false;
        }
        reply_rx.await.unwrap_or(false)
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown).await;
    }

    /// True while the connection has a live socket. Diagnostic only —
    /// writes are valid either way (they buffer).
    pub fn is_connected(&self) -> bool {
        !self.cmd_tx.is_closed()
    }
}

/// Writer-task side: owns the write half, drains framed packets.
async fn writer_task(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    use tokio::io::AsyncWriteExt;
    while let Some(frame) = rx.recv().await {
        if write_half.write_all(&frame).await.is_err() {
            return;
        }
    }
}

/// Reader-task side: raw `u32`-BE framed packet pump (`BackedReader` up to
/// but not including decryption — the nonce state must stay in the actor).
async fn reader_task(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    tx: mpsc::Sender<Result<Vec<u8>, ()>>,
) {
    use tokio::io::AsyncReadExt;
    loop {
        let result = async {
            let mut len_buf = [0u8; 4];
            read_half.read_exact(&mut len_buf).await.map_err(|_| ())?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > MAX_PACKET_LENGTH {
                return Err(());
            }
            let mut buf = vec![0u8; len];
            read_half.read_exact(&mut buf).await.map_err(|_| ())?;
            Ok(buf)
        }
        .await;
        let is_err = result.is_err();
        if tx.send(result).await.is_err() || is_err {
            return;
        }
    }
}

struct LiveSocket {
    write_tx: mpsc::Sender<Vec<u8>>,
    io_rx: mpsc::Receiver<Result<Vec<u8>, ()>>,
}

struct BackedActor {
    cfg: BackedConfig,
    writer_crypto: CryptoHandler,
    reader_crypto: CryptoHandler,
    backup: VecDeque<Vec<u8>>,
    backup_size: i64,
    writer_seq: i64,
    reader_seq: i64,
    /// Serialized (still-encrypted) packets awaiting delivery.
    inbox: VecDeque<Vec<u8>>,
    live: Option<LiveSocket>,
    disconnected_bytes: Option<i64>,
    /// Set by `close_current_socket` when a live socket went down; the run
    /// loop turns it into a `SocketDown` event.
    socket_down_pending: bool,
    waiting_on_keepalive: bool,
    last_activity: Instant,
    shutting_down: bool,
    events_tx: mpsc::Sender<BackedEvent>,
}

impl BackedActor {
    fn new(cfg: BackedConfig, events_tx: mpsc::Sender<BackedEvent>) -> Self {
        let writer_crypto = CryptoHandler::new(&cfg.key, cfg.writer_msb);
        let reader_crypto = CryptoHandler::new(&cfg.key, cfg.reader_msb);
        Self {
            cfg,
            writer_crypto,
            reader_crypto,
            backup: VecDeque::new(),
            backup_size: 0,
            writer_seq: 0,
            reader_seq: 0,
            inbox: VecDeque::new(),
            live: None,
            disconnected_bytes: None,
            socket_down_pending: false,
            waiting_on_keepalive: false,
            last_activity: Instant::now(),
            shutting_down: false,
            events_tx,
        }
    }

    fn spawn_socket_tasks(&self, stream: TcpStream) -> LiveSocket {
        stream.set_nodelay(true).ok();
        let (read_half, write_half) = stream.into_split();
        let (write_tx, write_rx) = mpsc::channel(WRITE_QUEUE_DEPTH);
        let (io_tx, io_rx) = mpsc::channel(WRITE_QUEUE_DEPTH);
        tokio::spawn(reader_task(read_half, io_tx));
        tokio::spawn(writer_task(write_half, write_rx));
        LiveSocket { write_tx, io_rx }
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<Cmd>, live: LiveSocket) {
        self.live = Some(live);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => match cmd {
                    Some(Cmd::Write { header, payload, reply }) => {
                        let result = self.write(header, payload).await;
                        let _ = reply.send(result);
                    }
                    Some(Cmd::KillSocket) => self.close_current_socket(),
                    Some(Cmd::Recover { stream, reply }) => {
                        let ok = self.recover(stream).await;
                        let _ = reply.send(ok);
                    }
                    // Channel closed: every handle was dropped.
                    Some(Cmd::Shutdown) | None => {
                        self.shutting_down = true;
                        break;
                    }
                },
                frame = async {
                    match self.live.as_mut() {
                        Some(live) => live.io_rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => match frame {
                    Some(Ok(bytes)) => self.inbox.push_back(bytes),
                    Some(Err(_)) | None => self.close_current_socket(),
                },
                _ = tick.tick() => self.keepalive_tick().await,
            }

            if self.shutting_down {
                break;
            }
            if self.socket_down_pending {
                self.socket_down_pending = false;
                if self.events_tx.send(BackedEvent::SocketDown).await.is_err() {
                    break;
                }
            }
            self.deliver_inbox().await;
            if self.shutting_down {
                break;
            }
        }

        if let Some(mut live) = self.live.take() {
            live.io_rx.close();
        }
        let _ = self.events_tx.send(BackedEvent::Dead(DeadReason::Shutdown)).await;
    }

    async fn deliver_inbox(&mut self) {
        while let Some(bytes) = self.inbox.pop_front() {
            let Some(mut packet) = Packet::parse(&bytes) else {
                continue;
            };
            if packet.is_encrypted()
                && packet.decrypt(&mut self.reader_crypto).is_err()
            {
                self.shutting_down = true;
                let _ = self
                    .events_tx
                    .send(BackedEvent::Dead(DeadReason::CryptoMismatch))
                    .await;
                return;
            }
            // Inbound traffic resets the keepalive deadline; a KEEP_ALIVE
            // echo clears the outstanding-ping flag (upstream
            // TerminalClient: `keepaliveTime = ...` on reads, and
            // `waitingOnKeepalive = false` on the echo).
            self.last_activity = Instant::now();
            if packet.header() == terminal_packet_type::KEEP_ALIVE {
                self.waiting_on_keepalive = false;
            }
            self.reader_seq += 1;
            if self.events_tx.send(BackedEvent::Packet(packet)).await.is_err() {
                return;
            }
        }
    }

    /// `BackedWriter::write`.
    async fn write(&mut self, header: u8, payload: Vec<u8>) -> Result<(), WriteError> {
        if self.shutting_down {
            return Err(WriteError::Shutdown);
        }
        if let Some(buffered) = self.disconnected_bytes {
            if buffered + payload.len() as i64 > DISCONNECT_BUFFER_BYTES {
                return Err(WriteError::Skipped);
            }
        }

        let mut packet = Packet::new(header, payload);
        packet.encrypt(&mut self.writer_crypto);
        let serialized = packet.serialize();

        self.backup.push_front(serialized.clone());
        self.backup_size += serialized.len() as i64;
        self.writer_seq += 1;

        if self.live.is_some() {
            while self.backup_size > MAX_BACKUP_BYTES {
                match self.backup.pop_back() {
                    Some(old) => self.backup_size -= old.len() as i64,
                    None => break,
                }
            }
        }

        match &mut self.live {
            None => {
                *self.disconnected_bytes.get_or_insert(0) += serialized.len() as i64;
                Ok(()) // BUFFERED_ONLY
            }
            Some(live) => {
                let mut frame = (serialized.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(&serialized);
                if live.write_tx.send(frame).await.is_err() {
                    // WROTE_WITH_FAILURE: the bytes are backed up either way.
                    self.close_current_socket();
                }
                self.last_activity = Instant::now();
                Ok(())
            }
        }
    }

    fn close_current_socket(&mut self) {
        if let Some(mut live) = self.live.take() {
            live.io_rx.close();
            self.socket_down_pending = true;
        }
        self.waiting_on_keepalive = false;
        self.disconnected_bytes.get_or_insert(0);
    }

    /// Client-side keepalive enforcement (`TerminalClient::run`). The
    /// server passes `keepalive = None` and never calls this.
    async fn keepalive_tick(&mut self) {
        let Some(period) = self.cfg.keepalive else {
            return;
        };
        if self.live.is_none() || self.shutting_down {
            return;
        }
        if self.last_activity.elapsed() >= period {
            if self.waiting_on_keepalive {
                self.close_current_socket();
            } else {
                self.waiting_on_keepalive = true;
                self.last_activity = Instant::now();
                let _ = self.write(terminal_packet_type::KEEP_ALIVE, Vec::new()).await;
            }
        }
    }

    /// `Connection::recover`, the identical exchange both peers run:
    /// write my reader seq → read their reader seq → write my catch-up →
    /// read their catch-up. On failure the old socket (if any) is restored
    /// untouched, so a bogus reconnect cannot force-disconnect a live
    /// session (upstream `recoverClient` guarantee).
    async fn recover(&mut self, stream: TcpStream) -> bool {
        let exchange = async {
            let mut stream = stream;
            let sh = SequenceHeader { sequence_number: Some(self.reader_seq as i32) };
            write_proto_frame(&mut stream, &sh.encode_to_vec())
                .await
                .map_err(|e| e.to_string())?;

            let bytes = read_proto_frame(&mut stream, MAX_HANDSHAKE_PROTO_LENGTH)
                .await
                .map_err(|e| e.to_string())?;
            let remote = SequenceHeader::decode(&bytes[..])
                .map_err(|e| format!("bad SequenceHeader: {e}"))?;
            let remote_seq = remote.sequence_number.unwrap_or(0);

            // `BackedWriter::recover`: newest `writer_seq - remote_seq`
            // backed-up packets, chronological. Pre-encrypted bytes only.
            let to_recover = self.writer_seq - remote_seq as i64;
            if to_recover < 0 {
                return Err("peer claims more of our packets than we ever sent".to_string());
            }
            let mut catchup = CatchupBuffer { buffer: Vec::new() };
            if to_recover > 0 {
                if self.backup.len() < to_recover as usize {
                    return Err(format!(
                        "peer is too far behind: needs {to_recover}, {} backed up",
                        self.backup.len()
                    ));
                }
                catchup.buffer = self.backup.iter().take(to_recover as usize).cloned().collect();
                catchup.buffer.reverse();
            }
            write_proto_frame(&mut stream, &catchup.encode_to_vec())
                .await
                .map_err(|e| e.to_string())?;

            let bytes = read_proto_frame(&mut stream, DEFAULT_MAX_PROTO_LENGTH)
                .await
                .map_err(|e| e.to_string())?;
            let their_catchup =
                CatchupBuffer::decode(&bytes[..]).map_err(|e| format!("bad CatchupBuffer: {e}"))?;
            Ok((stream, their_catchup.buffer))
        };

        let old = self.live.take();
        match timeout(RECOVER_TIMEOUT, exchange).await {
            Ok(Ok((stream, entries))) => {
                drop(old); // close the superseded socket
                // `BackedReader::revive` + `BackedWriter::revive`.
                self.inbox.extend(entries);
                self.disconnected_bytes = None;
                self.last_activity = Instant::now();
                self.live = Some(self.spawn_socket_tasks(stream));
                true
            }
            Ok(Err(_)) | Err(_) => {
                // Restore the previous socket untouched (`recoverClient`'s
                // victim protection).
                self.live = old;
                false
            }
        }
    }
}
