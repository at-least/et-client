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
use crate::gen::et::{CatchupBuffer, SequenceHeader};
use crate::packet::Packet;
use crate::{
    terminal_packet_type, DEFAULT_MAX_PROTO_LENGTH, MAX_HANDSHAKE_PROTO_LENGTH, MAX_PACKET_LENGTH,
};
use buffa::Message as _;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

/// Upstream `BackedWriter::MAX_BACKUP_BYTES`.
pub const MAX_BACKUP_BYTES: i64 = 64 * 1024 * 1024;
/// Upstream `BackedWriter::DISCONNECT_BUFFER_BYTES`.
pub const DISCONNECT_BUFFER_BYTES: i64 = 64 * 1024 * 1024;
/// Per-IO-step idle bound during the recover exchange: every 64 KiB
/// chunk of the catch-up must complete within this window. Upstream
/// bounds each handshake read at 30 s idle; 10 s keeps the short ceiling
/// on how long a bogus reconnect (anyone who knows the id can start the
/// plaintext exchange) can stall the victim, while a slow link that
/// keeps making progress still recovers instead of livelocking on
/// retries.
pub const RECOVER_STEP_IDLE: Duration = Duration::from_secs(10);
/// Absolute ceiling for the whole recover exchange — upstream's own bound
/// (the C++ peer abandons the exchange at 60 s absolute, so waiting
/// longer can never succeed). It also bounds how long a trickling peer
/// can hold the exchange open reading out backed-up ciphertext.
pub const RECOVER_ABSOLUTE: Duration = Duration::from_secs(60);
/// Recover-exchange IO chunk: each chunk must complete within one
/// [`RECOVER_STEP_IDLE`] window (~6.5 KiB/s minimum sustainable rate).
const RECOVER_IO_CHUNK: usize = 64 * 1024;
/// Bound on delivering a terminal `Dead` event: a stalled consumer (a
/// normal state once port-forward backpressure engages) must not keep a
/// dying actor alive. If the bound hits, the *reason* is lost — the
/// channel close right after still ends the session (the owner sees
/// `next_event() == None` rather than `Dead(reason)`) — but the actor is
/// never held hostage by consumer progress.
const DEAD_SEND_BOUND: Duration = Duration::from_secs(1);
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

#[derive(Debug, Clone)]
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
    Write {
        header: u8,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), WriteError>>,
    },
    KillSocket,
    Recover {
        stream: TcpStream,
        reply: oneshot::Sender<bool>,
        idle: Duration,
        absolute: Duration,
    },
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

impl Drop for BackedConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Defense-in-depth beyond upstream: the key copy this struct owns
        // does not outlive the session on the heap. (The cipher's internal
        // copy is unreachable from here.)
        self.key.zeroize();
    }
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
    pub async fn spawn(
        stream: TcpStream,
        cfg: BackedConfig,
    ) -> (Self, mpsc::Receiver<BackedEvent>) {
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
            .send(Cmd::Write {
                header,
                payload,
                reply: reply_tx,
            })
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
        self.recover_timed(stream, RECOVER_STEP_IDLE, RECOVER_ABSOLUTE)
            .await
    }

    /// Timing-injectable [`BackedHandle::recover`] (tests drive small
    /// windows); production callers take the documented constants.
    pub(crate) async fn recover_timed(
        &self,
        stream: TcpStream,
        idle: Duration,
        absolute: Duration,
    ) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(Cmd::Recover {
                stream,
                reply: reply_tx,
                idle,
                absolute,
            })
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
    /// Set once a terminal `Dead` event went out, so the run loop's final
    /// send does not append a second, reason-less one.
    dead_sent: bool,
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
            dead_sent: false,
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
                cmd = cmd_rx.recv() => {
                    self.handle_cmd(cmd).await;
                }
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
                if !self.send_event(BackedEvent::SocketDown, &mut cmd_rx).await {
                    break;
                }
            }
            self.deliver_inbox(&mut cmd_rx).await;
            if self.shutting_down {
                break;
            }
        }

        if let Some(mut live) = self.live.take() {
            live.io_rx.close();
        }
        if !self.dead_sent {
            // Bounded (see DEAD_SEND_BOUND): a stalled consumer must not
            // keep the dying actor alive.
            let _ = tokio::time::timeout(
                DEAD_SEND_BOUND,
                self.events_tx.send(BackedEvent::Dead(DeadReason::Shutdown)),
            )
            .await;
        }
    }

    /// One command off the queue (`None` = every handle dropped, a
    /// shutdown). Sets `shutting_down` on the terminal commands.
    async fn handle_cmd(&mut self, cmd: Option<Cmd>) {
        match cmd {
            Some(Cmd::Write { header, payload, reply }) => {
                let result = self.write(header, payload).await;
                let _ = reply.send(result);
            }
            Some(Cmd::KillSocket) => self.close_current_socket(),
            Some(Cmd::Recover { stream, reply, idle, absolute }) => {
                let ok = self.recover_timed_actor(stream, idle, absolute).await;
                let _ = reply.send(ok);
            }
            Some(Cmd::Shutdown) | None => {
                self.shutting_down = true;
            }
        }
    }

    /// Delivers `event` to the consumer without ever freezing command
    /// processing on consumer progress: once port-forward backpressure can
    /// stall the session pump, a full event queue is a normal operating
    /// state, and the actor must keep serving writes and recovery through
    /// it (the write path already never blocks on socket progress;
    /// consumer progress gets the same guarantee). Timer-driven keepalive
    /// is deliberately suspended while parked here — congestion means the
    /// peer is demonstrably still sending; a link that dies *during* a
    /// stall is detected when the stall clears or the write path kills a
    /// full socket. Returns false when the consumer is gone or a drained
    /// command ended the session.
    async fn send_event(&mut self, event: BackedEvent, cmd_rx: &mut mpsc::Receiver<Cmd>) -> bool {
        loop {
            // Unbiased, like the engine's data-path select: commands get
            // served during a stall, but a steady stream of them must not
            // starve event delivery entirely.
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    self.handle_cmd(cmd).await;
                    if self.shutting_down {
                        return false;
                    }
                }
                sent = self.events_tx.send(event.clone()) => {
                    return sent.is_ok();
                }
            }
        }
    }

    /// Fail closed on unparseable, unauthenticated, or undecryptable input:
    /// the session dies once with `CryptoMismatch` (upstream STFATALs) and
    /// the run loop's final send must not append a second Dead.
    async fn die_crypto_mismatch(&mut self) {
        self.shutting_down = true;
        self.dead_sent = true;
        let _ = tokio::time::timeout(
            DEAD_SEND_BOUND,
            self.events_tx.send(BackedEvent::Dead(DeadReason::CryptoMismatch)),
        )
        .await;
    }

    async fn deliver_inbox(&mut self, cmd_rx: &mut mpsc::Receiver<Cmd>) {
        while let Some(bytes) = self.inbox.pop_front() {
            // A frame that fails to parse is protocol corruption: skipping
            // it without advancing the reader sequence would desynchronize
            // every later recover (the peer would resend the wrong span).
            let Some(mut packet) = Packet::parse(&bytes) else {
                self.die_crypto_mismatch().await;
                return;
            };
            // The flag byte is attacker-writable, so a packet that claims
            // to be plaintext was never MAC-verified by anyone — and the
            // secretbox stream is the only authenticity guarantee on this
            // leg. Upstream's reader decrypts unconditionally and STFATALs
            // on exactly this case; fail closed the same way instead of
            // delivering unauthenticated bytes.
            if !packet.is_encrypted() {
                self.die_crypto_mismatch().await;
                return;
            }
            if packet.decrypt(&mut self.reader_crypto).is_err() {
                self.die_crypto_mismatch().await;
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
            if !self.send_event(BackedEvent::Packet(packet), cmd_rx).await {
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
                if live.write_tx.try_send(frame).is_err() {
                    // WROTE_WITH_FAILURE: the bytes are backed up either
                    // way, and catch-up resends anything the queue never
                    // took. A full queue means the writer task is wedged
                    // in `write_all` on a socket that stopped draining:
                    // kill it instead of blocking the actor here, which
                    // would freeze keepalive enforcement and the recover
                    // exchange (upstream's reader thread would keep
                    // running; this actor must not depend on socket
                    // progress to stay alive). The failed packet stays in
                    // the backup undelivered, so it opens the disconnect
                    // ledger — otherwise the budget could overshoot by it.
                    *self.disconnected_bytes.get_or_insert(0) += serialized.len() as i64;
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
                let _ = self
                    .write(terminal_packet_type::KEEP_ALIVE, Vec::new())
                    .await;
            }
        }
    }

    /// `Connection::recover`, the identical exchange both peers run:
    /// write my reader seq → read their reader seq → write my catch-up →
    /// read their catch-up. Every IO step is bounded by `idle`, the whole
    /// exchange by `absolute`: a slow-but-progressing peer recovers, a
    /// stalled or trickling one is abandoned. On failure the old socket
    /// (if any) is restored untouched, so a bogus reconnect cannot
    /// force-disconnect a live session (upstream `recoverClient`
    /// guarantee).
    async fn recover_timed_actor(
        &mut self,
        stream: TcpStream,
        idle: Duration,
        absolute: Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + absolute;
        let exchange = async {
            let mut stream = stream;
            let sh = SequenceHeader {
                sequenceNumber: Some(self.reader_seq as i32),
                ..Default::default()
            };
            write_frame_idle(&mut stream, &sh.encode_to_vec(), idle, deadline).await?;

            let remote = SequenceHeader::decode_from_slice(
                &read_frame_idle(&mut stream, MAX_HANDSHAKE_PROTO_LENGTH, idle, deadline).await?,
            )
            .map_err(|e| format!("bad SequenceHeader: {e}"))?;
            let remote_seq = remote.sequenceNumber.unwrap_or(0);

            // `BackedWriter::recover`: newest `writer_seq - remote_seq`
            // backed-up packets, chronological. Pre-encrypted bytes only.
            let to_recover = self.writer_seq - remote_seq as i64;
            if to_recover < 0 {
                return Err("peer claims more of our packets than we ever sent".to_string());
            }
            let mut catchup = CatchupBuffer {
                buffer: Vec::new(),
                ..Default::default()
            };
            if to_recover > 0 {
                if self.backup.len() < to_recover as usize {
                    return Err(format!(
                        "peer is too far behind: needs {to_recover}, {} backed up",
                        self.backup.len()
                    ));
                }
                catchup.buffer = self
                    .backup
                    .iter()
                    .take(to_recover as usize)
                    .cloned()
                    .collect();
                catchup.buffer.reverse();
            }
            write_frame_idle(&mut stream, &catchup.encode_to_vec(), idle, deadline).await?;

            let their_bytes =
                read_frame_idle(&mut stream, DEFAULT_MAX_PROTO_LENGTH, idle, deadline).await?;
            let their_catchup = CatchupBuffer::decode_from_slice(&their_bytes)
                .map_err(|e| format!("bad CatchupBuffer: {e}"))?;
            Ok((stream, their_catchup.buffer))
        };

        let old = self.live.take();
        match exchange.await {
            Ok((stream, entries)) => {
                drop(old); // close the superseded socket
                           // `BackedReader::revive` + `BackedWriter::revive`.
                self.inbox.extend(entries);
                self.disconnected_bytes = None;
                self.last_activity = Instant::now();
                self.live = Some(self.spawn_socket_tasks(stream));
                true
            }
            Err(_) => {
                // Restore the previous socket untouched (`recoverClient`'s
                // victim protection).
                self.live = old;
                false
            }
        }
    }
}

/// One `i64`-LE framed write with progress-bounded IO: each
/// [`RECOVER_IO_CHUNK`] slice must complete within `idle`, everything
/// within `deadline`.
///
/// Cancel-unsafety is fine here by construction: a timeout abandons the
/// whole exchange and the stream is dropped, so the unknown number of
/// bytes a dropped `write_all` already pushed is never resumed.
async fn write_frame_idle<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    body: &[u8],
    idle: Duration,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    let header = (body.len() as i64).to_le_bytes();
    write_all_idle(w, &header, idle, deadline).await?;
    write_all_idle(w, body, idle, deadline).await
}

async fn write_all_idle<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    buf: &[u8],
    idle: Duration,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt as _;
    let mut off = 0;
    while off < buf.len() {
        let end = (off + RECOVER_IO_CHUNK).min(buf.len());
        let step_bound = (tokio::time::Instant::now() + idle).min(deadline);
        match tokio::time::timeout_at(step_bound, w.write_all(&buf[off..end])).await {
            Ok(Ok(())) => off = end,
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("recover exchange stalled (idle window exceeded)".into()),
        }
    }
    Ok(())
}

/// One `i64`-LE framed read with progress-bounded IO (see
/// [`write_frame_idle`]); `max_len` mirrors `read_proto_frame`'s bound.
async fn read_frame_idle<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    max_len: i64,
    idle: Duration,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 8];
    read_exact_idle(r, &mut len_buf, idle, deadline).await?;
    let len = i64::from_le_bytes(len_buf);
    if !(0..=max_len).contains(&len) {
        return Err(format!(
            "recover exchange frame of {len} bytes exceeds the maximum"
        ));
    }
    let mut body = vec![0u8; len as usize];
    read_exact_idle(r, &mut body, idle, deadline).await?;
    Ok(body)
}

async fn read_exact_idle<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
    idle: Duration,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    use tokio::io::AsyncReadExt as _;
    let mut off = 0;
    while off < buf.len() {
        let end = (off + RECOVER_IO_CHUNK).min(buf.len());
        let step_bound = (tokio::time::Instant::now() + idle).min(deadline);
        match tokio::time::timeout_at(step_bound, r.read_exact(&mut buf[off..end])).await {
            Ok(Ok(_)) => off = end,
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("recover exchange stalled (idle window exceeded)".into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{
        read_framed_packet, read_proto_frame, write_framed_packet, write_proto_frame,
    };
    use crate::{
        CLIENT_SERVER_NONCE_MSB, DEFAULT_MAX_PROTO_LENGTH, MAX_PACKET_LENGTH,
        SERVER_CLIENT_NONCE_MSB,
    };
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    const TEST_KEY: [u8; 32] = [0x5a; 32];
    const LONG: Duration = Duration::from_secs(5);

    /// The mock peer's crypto: its writer feeds the client's reader stream
    /// (MSB 1), its reader consumes the client's writer stream (MSB 0) —
    /// the mirror of the `BackedConfig` the rig hands the client side.
    struct PeerCrypto {
        writer: CryptoHandler,
        reader: CryptoHandler,
    }

    fn peer_crypto() -> PeerCrypto {
        PeerCrypto {
            writer: CryptoHandler::new(&TEST_KEY, SERVER_CLIENT_NONCE_MSB),
            reader: CryptoHandler::new(&TEST_KEY, CLIENT_SERVER_NONCE_MSB),
        }
    }

    struct Rig {
        listener: TcpListener,
        addr: SocketAddr,
        backed: BackedHandle,
        events: mpsc::Receiver<BackedEvent>,
    }

    async fn rig(keepalive: Option<Duration>) -> Rig {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (backed, events) = BackedHandle::spawn(
            stream,
            BackedConfig {
                key: TEST_KEY,
                reader_msb: SERVER_CLIENT_NONCE_MSB,
                writer_msb: CLIENT_SERVER_NONCE_MSB,
                keepalive,
            },
        )
        .await;
        Rig {
            listener,
            addr,
            backed,
            events,
        }
    }

    impl Rig {
        /// The peer end of the live connection.
        async fn accept(&self) -> tokio::net::TcpStream {
            let (peer, _) = self.listener.accept().await.unwrap();
            peer
        }

        /// A second loopback connection for recover attempts.
        async fn connect_extra(&self) -> tokio::net::TcpStream {
            tokio::net::TcpStream::connect(self.addr).await.unwrap()
        }
    }

    /// What the mock peer reads off the wire from the client: one framed
    /// packet, decrypted on the peer's reader stream.
    async fn read_client_packet(
        peer: &mut tokio::net::TcpStream,
        reader: &mut CryptoHandler,
    ) -> Packet {
        let mut packet = read_framed_packet(peer, MAX_PACKET_LENGTH).await.unwrap();
        assert!(packet.is_encrypted(), "client packets are always encrypted");
        packet.decrypt(reader).unwrap();
        packet
    }

    /// Mock peer → client: one framed, encrypted packet.
    async fn send_peer_packet(
        peer: &mut tokio::net::TcpStream,
        writer: &mut CryptoHandler,
        header: u8,
        payload: &[u8],
    ) {
        let mut packet = Packet::new(header, payload.to_vec());
        packet.encrypt(writer);
        write_framed_packet(peer, &packet).await.unwrap();
    }

    /// Recover-exchange peer side: read the client's SequenceHeader, reply
    /// with `remote_seq`, collect the client's CatchupBuffer, answer with
    /// `reply_entries`. Returns (client-reported reader seq, catch-up).
    async fn run_recover_peer(
        peer: &mut tokio::net::TcpStream,
        remote_seq: i32,
        reply_entries: Vec<Vec<u8>>,
    ) -> (i32, Vec<Vec<u8>>) {
        let client_seq = read_reply_sequence_header(peer, remote_seq).await;
        let bytes = read_proto_frame(peer, DEFAULT_MAX_PROTO_LENGTH)
            .await
            .unwrap();
        let catchup = CatchupBuffer::decode_from_slice(&bytes).unwrap();
        write_proto_frame(
            peer,
            &CatchupBuffer {
                buffer: reply_entries,
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
        (client_seq, catchup.buffer)
    }

    /// The exchange's first leg only, for peers whose `remote_seq` makes the
    /// client abort *before* sending its CatchupBuffer — reading further
    /// here would deadlock against a client that never writes again.
    async fn read_reply_sequence_header(peer: &mut tokio::net::TcpStream, remote_seq: i32) -> i32 {
        let bytes = read_proto_frame(peer, MAX_HANDSHAKE_PROTO_LENGTH)
            .await
            .unwrap();
        let sh = SequenceHeader::decode_from_slice(&bytes).unwrap();
        write_proto_frame(
            peer,
            &SequenceHeader {
                sequenceNumber: Some(remote_seq),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
        sh.sequenceNumber.unwrap()
    }

    #[tokio::test]
    async fn write_delivers_encrypted_and_reads_decrypt() {
        let mut rig = rig(None).await;
        let mut peer = rig.accept().await;
        let mut pc = peer_crypto();

        rig.backed.write(7, b"ping".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer, &mut pc.reader).await;
        assert_eq!(packet.header(), 7);
        assert_eq!(packet.payload(), b"ping");

        send_peer_packet(&mut peer, &mut pc.writer, 8, b"pong").await;
        match rig.events.recv().await {
            Some(BackedEvent::Packet(packet)) => {
                assert_eq!(packet.header(), 8);
                assert_eq!(packet.payload(), b"pong");
            }
            other => panic!("expected a packet event, got {other:?}"),
        }
    }

    /// The core reconnect invariant: everything written before and *during*
    /// the outage reaches the peer on recovery as the identical pre-encrypted
    /// bytes, in order, with the nonce stream continuing across sockets.
    #[tokio::test]
    async fn recover_resends_identical_ciphertext_after_disconnect() {
        let mut rig = rig(None).await;
        let mut peer = rig.accept().await;
        let mut pc = peer_crypto();

        rig.backed.write(1, b"alpha".to_vec()).await.unwrap();
        let first_bytes = {
            // Serialize before decrypting: the backup stores ciphertext.
            let wire = read_framed_packet(&mut peer, MAX_PACKET_LENGTH)
                .await
                .unwrap();
            let bytes = wire.serialize();
            let mut packet = wire;
            packet.decrypt(&mut pc.reader).unwrap();
            assert_eq!(packet.payload(), b"alpha");
            bytes
        };
        rig.backed.write(2, b"beta".to_vec()).await.unwrap();
        let second_bytes = {
            let wire = read_framed_packet(&mut peer, MAX_PACKET_LENGTH)
                .await
                .unwrap();
            let bytes = wire.serialize();
            let mut packet = wire;
            packet.decrypt(&mut pc.reader).unwrap();
            assert_eq!(packet.payload(), b"beta");
            bytes
        };

        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));
        // Writes while disconnected: buffered, still Ok (BUFFERED_ONLY).
        rig.backed.write(3, b"gamma".to_vec()).await.unwrap();
        rig.backed.write(4, b"delta".to_vec()).await.unwrap();

        // The client hands `recover` the client end; the mock drives the
        // accepted (peer) end of the *same* connection.
        let recover_stream = rig.connect_extra().await;
        let mut peer2 = rig.accept().await;
        let exchange = tokio::spawn(async move {
            let (client_seq, entries) = run_recover_peer(&mut peer2, 0, Vec::new()).await;
            (peer2, client_seq, entries)
        });
        assert!(rig.backed.recover(recover_stream).await);

        let (mut peer2, client_seq, entries) = exchange.await.unwrap();
        assert_eq!(
            client_seq, 0,
            "the peer sent nothing, so the client read 0 packets"
        );
        assert_eq!(
            entries.len(),
            4,
            "everything ever written, connected or not"
        );
        assert_eq!(entries[0], first_bytes, "catch-up resends identical bytes");
        assert_eq!(entries[1], second_bytes);
        for (entry, (header, payload)) in entries[2..]
            .iter()
            .zip([(3, &b"gamma"[..]), (4, &b"delta"[..])])
        {
            let mut packet = Packet::parse(entry).unwrap();
            packet.decrypt(&mut pc.reader).unwrap();
            assert_eq!(packet.header(), header);
            assert_eq!(packet.payload(), payload);
        }

        // Both directions live on the new socket, nonce streams unbroken.
        send_peer_packet(&mut peer2, &mut pc.writer, 5, b"echo").await;
        match rig.events.recv().await {
            Some(BackedEvent::Packet(packet)) => {
                assert_eq!(packet.header(), 5);
                assert_eq!(packet.payload(), b"echo");
            }
            other => panic!("expected a packet event after recover, got {other:?}"),
        }
        rig.backed.write(6, b"post".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer2, &mut pc.reader).await;
        assert_eq!(packet.header(), 6);
        assert_eq!(packet.payload(), b"post");
    }

    /// `recoverClient`'s victim protection: a recover exchange that fails
    /// mid-way must leave the live socket untouched and working.
    #[tokio::test]
    async fn failed_recover_leaves_live_socket_untouched() {
        let mut rig = rig(None).await;
        let mut peer = rig.accept().await;
        let mut pc = peer_crypto();

        rig.backed.write(1, b"before".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer, &mut pc.reader).await;
        assert_eq!(packet.payload(), b"before");

        // A bogus stream: connected, then dropped mid-exchange.
        let bogus = rig.connect_extra().await;
        let dead_peer = rig.accept().await;
        drop(dead_peer);
        assert!(!rig.backed.recover(bogus).await, "the exchange must fail");

        // The original socket still carries traffic both ways, and no
        // SocketDown was invented for it.
        rig.backed.write(2, b"after".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer, &mut pc.reader).await;
        assert_eq!(packet.header(), 2);
        assert_eq!(packet.payload(), b"after");
        assert!(
            timeout(Duration::from_millis(150), rig.events.recv())
                .await
                .is_err(),
            "a failed recover must not emit SocketDown for the live socket"
        );
    }

    /// A peer that claims to have received more of our packets than we ever
    /// sent (`writer_seq - remote_seq < 0`) fails the exchange instead of
    /// underflowing, and the session stays disconnected-but-alive.
    #[tokio::test]
    async fn recover_rejects_peer_claiming_unsent_packets() {
        let mut rig = rig(None).await;
        let mut peer = rig.accept().await;
        let mut pc = peer_crypto();

        rig.backed.write(1, b"one".to_vec()).await.unwrap();
        read_client_packet(&mut peer, &mut pc.reader).await;
        rig.backed.write(2, b"two".to_vec()).await.unwrap();
        read_client_packet(&mut peer, &mut pc.reader).await;

        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));

        let recover_stream = rig.connect_extra().await;
        let mut peer2 = rig.accept().await;
        let exchange = tokio::spawn(async move {
            let client_seq = read_reply_sequence_header(&mut peer2, 5).await;
            (peer2, client_seq)
        });
        assert!(!rig.backed.recover(recover_stream).await);
        let (_, client_seq) = exchange.await.unwrap();
        assert_eq!(client_seq, 0);

        // Still disconnected: writes buffer instead of erroring.
        assert_eq!(rig.backed.write(3, b"three".to_vec()).await, Ok(()));
    }

    /// While connected the backup is trimmed to `MAX_BACKUP_BYTES`, so a
    /// peer that fell further behind than the trim window cannot be
    /// revived — and the failure must not wedge the session.
    #[tokio::test]
    async fn backup_trimmed_while_connected_rejects_far_behind_peer() {
        let mut rig = rig(None).await;
        let _peer = rig.accept().await;
        const MIB: usize = 1024 * 1024;
        for i in 0..70usize {
            rig.backed.write(1, vec![i as u8; MIB]).await.unwrap();
        }
        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));

        let recover_stream = rig.connect_extra().await;
        let mut peer2 = rig.accept().await;
        let exchange = tokio::spawn(async move {
            let client_seq = read_reply_sequence_header(&mut peer2, 0).await;
            (peer2, client_seq)
        });
        assert!(
            !rig.backed.recover(recover_stream).await,
            "70 MiB written but only ~64 MiB kept: the peer is too far behind"
        );
        let (_, client_seq) = exchange.await.unwrap();
        assert_eq!(client_seq, 0);

        // Disconnected-but-alive: the failed recover changed nothing.
        assert_eq!(rig.backed.write(2, b"still here".to_vec()).await, Ok(()));
    }

    /// While disconnected nothing is trimmed: every buffered write (up to
    /// the disconnect buffer's own cap) reaches the peer on recovery, in
    /// order, as the identical pre-encrypted bytes.
    #[tokio::test]
    async fn offline_writes_beyond_backup_limit_survive_until_recover() {
        let mut rig = rig(None).await;
        let _peer = rig.accept().await;
        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));

        const MIB: usize = 1024 * 1024;
        for i in 0..60usize {
            rig.backed.write(1, vec![i as u8; MIB]).await.unwrap();
        }

        let recover_stream = rig.connect_extra().await;
        let mut peer2 = rig.accept().await;
        let exchange = tokio::spawn(async move {
            let (client_seq, entries) = run_recover_peer(&mut peer2, 0, Vec::new()).await;
            (peer2, client_seq, entries)
        });
        assert!(rig.backed.recover(recover_stream).await);
        let (mut peer2, client_seq, entries) = exchange.await.unwrap();
        assert_eq!(client_seq, 0);
        assert_eq!(entries.len(), 60, "no trimming while disconnected");

        let mut reader = peer_crypto().reader;
        for (i, entry) in entries.iter().enumerate() {
            let mut packet = Packet::parse(entry).unwrap();
            packet.decrypt(&mut reader).unwrap();
            assert_eq!(packet.header(), 1);
            assert_eq!(packet.payload().len(), MIB);
            assert_eq!(
                packet.payload()[0],
                i as u8,
                "delivery order must be chronological"
            );
        }

        // Back to live: traffic flows on the new socket.
        rig.backed.write(2, b"live".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer2, &mut reader).await;
        assert_eq!(packet.payload(), b"live");
    }

    /// `BackedWriter::write` on a full disconnect buffer: the write that
    /// exactly reaches the limit is buffered (BUFFERED_ONLY), the next is
    /// SKIPPED, and the skipped write leaves backup/sequence consistent.
    #[tokio::test]
    async fn disconnect_buffer_overflow_skips_writes_without_corrupting_state() {
        let mut rig = rig(None).await;
        let _peer = rig.accept().await;
        let mut pc = peer_crypto();
        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));

        let big = vec![0u8; DISCONNECT_BUFFER_BYTES as usize];
        assert_eq!(
            rig.backed.write(1, big).await,
            Ok(()),
            "exactly at the limit still buffers"
        );
        assert_eq!(
            rig.backed.write(2, b"x".to_vec()).await,
            Err(WriteError::Skipped),
            "one byte past the limit is skipped"
        );

        // The skipped write must not have advanced anything: recovery
        // resends exactly the one real packet, and post-recover traffic
        // continues the nonce stream without a gap.
        let recover_stream = rig.connect_extra().await;
        let mut peer2 = rig.accept().await;
        let exchange = tokio::spawn(async move {
            let (client_seq, entries) = run_recover_peer(&mut peer2, 0, Vec::new()).await;
            (peer2, client_seq, entries)
        });
        assert!(rig.backed.recover(recover_stream).await);
        let (mut peer2, client_seq, entries) = exchange.await.unwrap();
        assert_eq!(client_seq, 0, "the client read nothing from the peer");
        assert_eq!(entries.len(), 1, "only the real packet is in the backup");
        let mut big_packet = Packet::parse(&entries[0]).unwrap();
        big_packet.decrypt(&mut pc.reader).unwrap();
        assert_eq!(big_packet.payload().len(), DISCONNECT_BUFFER_BYTES as usize);

        rig.backed.write(3, b"live".to_vec()).await.unwrap();
        let packet = read_client_packet(&mut peer2, &mut pc.reader).await;
        assert_eq!(packet.header(), 3);
        assert_eq!(packet.payload(), b"live");
    }

    /// A frame the parser or the MAC rejects is protocol corruption: the
    /// session dies with `CryptoMismatch` (rather than skipping a frame and
    /// desynchronizing every later recover), then writes report shutdown.
    #[tokio::test]
    async fn corrupt_frame_kills_session_with_crypto_mismatch() {
        // [encrypted=1, header] + 16 junk bytes: parses, fails the MAC.
        let bad_mac = vec![
            1u8, 7, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42,
        ];
        // A single byte cannot even parse as a packet.
        let unparseable = vec![0xABu8];
        for frame in [bad_mac, unparseable] {
            let mut rig = rig(None).await;
            let mut peer = rig.accept().await;
            let len = frame.len() as u32;
            peer.write_all(&len.to_be_bytes()).await.unwrap();
            peer.write_all(&frame).await.unwrap();

            match rig.events.recv().await {
                Some(BackedEvent::Dead(DeadReason::CryptoMismatch)) => {}
                other => panic!("expected Dead(CryptoMismatch), got {other:?}"),
            }
            assert_eq!(
                rig.backed.write(1, b"x".to_vec()).await,
                Err(WriteError::Shutdown)
            );
            // The Dead event is the *only* terminal event: the channel then
            // closes without a second, reason-less Dead.
            assert!(rig.events.recv().await.is_none());
        }
    }

    /// A packet whose own wire flag says "not encrypted" was never
    /// MAC-verified by anyone, and the flag byte is attacker-writable: the
    /// secretbox stream is the only authenticity guarantee on this leg
    /// (etserver relays ciphertext), so delivering it would let anyone
    /// inject unauthenticated terminal output or port-forward steering.
    /// Upstream's reader decrypts unconditionally and STFATALs on exactly
    /// this case — the session dies with `CryptoMismatch` here too.
    #[tokio::test]
    async fn plaintext_flagged_packet_kills_session_with_crypto_mismatch() {
        let mut rig = rig(None).await;
        let mut peer = rig.accept().await;
        // [encrypted=0][TERMINAL_BUFFER] + payload: no MAC, no key needed.
        let frame = [
            0u8,
            terminal_packet_type::TERMINAL_BUFFER,
            b'p',
            b'w',
            b'n',
        ];
        let len = frame.len() as u32;
        peer.write_all(&len.to_be_bytes()).await.unwrap();
        peer.write_all(&frame).await.unwrap();

        match timeout(LONG, rig.events.recv()).await {
            Ok(Some(BackedEvent::Dead(DeadReason::CryptoMismatch))) => {}
            other => panic!("expected Dead(CryptoMismatch), got {other:?}"),
        }
        assert_eq!(
            rig.backed.write(1, b"x".to_vec()).await,
            Err(WriteError::Shutdown)
        );
        assert!(rig.events.recv().await.is_none());
    }

    /// The actor must keep serving commands while its event consumer
    /// stalls: with port-forward backpressure in the session layer, a full
    /// event queue is a *normal* operating state, and freezing command
    /// processing inside delivery would deadlock the session pump's own
    /// writes and keepalive enforcement along with it.
    #[tokio::test]
    async fn commands_are_served_while_the_event_consumer_stalls() {
        let rig = rig(None).await;
        let mut peer = rig.accept().await;
        let mut pc = peer_crypto();

        // Overfill the 1024-deep event queue: packets the test never
        // receives, so the actor runs out of delivery capacity.
        for i in 0..1100u16 {
            send_peer_packet(&mut peer, &mut pc.writer, 1, &[i as u8; 64]).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The socket is alive: a write command must still be served —
        // its reply comes from the actor, which must not be wedged inside
        // event delivery.
        match timeout(LONG, rig.backed.write(7, b"cmd".to_vec())).await {
            Ok(Ok(())) => {}
            other => panic!("write must be served while events back up, got {other:?}"),
        }
    }

    /// The write that kills a full socket stays in the backup and must
    /// count toward the disconnect budget: otherwise the first write
    /// after the kill is admitted against a ledger that forgot it and the
    /// buffer overshoots `DISCONNECT_BUFFER_BYTES` by one packet.
    #[tokio::test]
    async fn the_packet_that_kills_a_full_socket_counts_toward_the_budget() {
        let mut rig = rig(None).await;
        // The peer accepts but never reads: the writer task stalls in
        // write_all, the 1024-frame write queue fills, and the next write
        // kills the socket — that packet stays in the backup undelivered.
        // Stop at the kill so nothing else enters the disconnect ledger.
        let peer = rig.accept().await;
        loop {
            rig.backed.write(1, vec![0u8; 16 * 1024]).await.unwrap();
            if matches!(
                timeout(Duration::from_millis(1), rig.events.recv()).await,
                Ok(Some(BackedEvent::SocketDown))
            ) {
                break;
            }
        }

        // A full-budget write must not be admitted on top of the killing
        // packet still sitting in the backup.
        assert_eq!(
            rig.backed
                .write(1, vec![0u8; DISCONNECT_BUFFER_BYTES as usize])
                .await,
            Err(WriteError::Skipped),
            "the killing packet must already count against the budget"
        );
        drop(peer);
    }

    /// Dropping every handle is a shutdown: the actor drains, reports
    /// `Dead(Shutdown)` once, and closes the event channel.
    #[tokio::test]
    async fn dropping_all_handles_ends_the_actor() {
        let mut rig = rig(None).await;
        let _peer = rig.accept().await;
        drop(rig.backed);
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::Dead(DeadReason::Shutdown))
        ));
        assert!(rig.events.recv().await.is_none());
    }

    /// Idle past the keepalive period makes the client send an encrypted
    /// KEEP_ALIVE; the peer's echo clears the outstanding flag, so the next
    /// tick pings again instead of killing the socket.
    #[tokio::test]
    async fn keepalive_pings_when_idle_and_echo_keeps_the_socket_alive() {
        let rig = rig(Some(Duration::from_millis(100))).await;
        let mut peer = rig.accept().await;
        let mut pc = peer_crypto();

        // The actor ticks once a second; the first idle tick (~1s) pings.
        let ping = timeout(LONG, read_client_packet(&mut peer, &mut pc.reader))
            .await
            .unwrap();
        assert_eq!(ping.header(), terminal_packet_type::KEEP_ALIVE);
        assert!(ping.payload().is_empty());

        send_peer_packet(
            &mut peer,
            &mut pc.writer,
            terminal_packet_type::KEEP_ALIVE,
            &[],
        )
        .await;

        let ping = timeout(LONG, read_client_packet(&mut peer, &mut pc.reader))
            .await
            .unwrap();
        assert_eq!(
            ping.header(),
            terminal_packet_type::KEEP_ALIVE,
            "the echo reset the flag"
        );

        // A second full cycle: the reset persists, the socket stays up.
        send_peer_packet(
            &mut peer,
            &mut pc.writer,
            terminal_packet_type::KEEP_ALIVE,
            &[],
        )
        .await;
        let ping = timeout(LONG, read_client_packet(&mut peer, &mut pc.reader))
            .await
            .unwrap();
        assert_eq!(ping.header(), terminal_packet_type::KEEP_ALIVE);
    }

    /// A missing KEEP_ALIVE echo kills the socket: SocketDown surfaces,
    /// writes keep buffering (Ok), and the session is not Dead.
    #[tokio::test]
    async fn keepalive_without_echo_kills_the_socket() {
        let mut rig = rig(Some(Duration::from_millis(100))).await;
        let mut peer = rig.accept().await;
        let mut pc = peer_crypto();

        let ping = timeout(LONG, read_client_packet(&mut peer, &mut pc.reader))
            .await
            .unwrap();
        assert_eq!(ping.header(), terminal_packet_type::KEEP_ALIVE);
        // Deliberately no echo.

        match timeout(LONG, rig.events.recv()).await {
            Ok(Some(BackedEvent::SocketDown)) => {}
            other => panic!("expected SocketDown after the unanswered ping, got {other:?}"),
        }
        assert_eq!(rig.backed.write(1, b"buffered".to_vec()).await, Ok(()));
        assert!(
            timeout(Duration::from_millis(300), rig.events.recv())
                .await
                .is_err(),
            "keepalive loss disconnects but does not kill the session"
        );
    }

    /// A peer that stops reading wedges the writer task in `write_all`;
    /// once the socket's write queue fills, a write must kill the socket
    /// instead of blocking the actor — SocketDown surfaces (the supervisor
    /// can reconnect), writes keep succeeding (buffered), and the unsent
    /// frame stays in the backup for catch-up.
    #[tokio::test]
    async fn a_full_socket_write_queue_kills_the_socket_instead_of_blocking_the_actor() {
        let mut rig = rig(None).await;
        // The peer accepts but never reads: kernel buffers fill, the
        // writer task stalls, the queue fills.
        let peer = rig.accept().await;

        // 32 MiB: past the kernel buffers and the 1024-frame queue.
        for _ in 0..2048 {
            rig.backed.write(1, vec![0u8; 16 * 1024]).await.unwrap();
        }

        match timeout(LONG, rig.events.recv()).await {
            Ok(Some(BackedEvent::SocketDown)) => {}
            other => panic!("expected SocketDown once the write queue filled, got {other:?}"),
        }
        assert_eq!(
            rig.backed.write(2, b"still buffered".to_vec()).await,
            Ok(()),
            "writes buffer while disconnected"
        );
        drop(peer);
    }

    // ---- recover exchange timing ----

    /// Reads one i64-LE framed body in `chunk`-byte slices, delaying
    /// between slices: a peer that keeps making progress, but slowly.
    async fn read_frame_slowly<R: tokio::io::AsyncRead + Unpin>(
        peer: &mut R,
        chunk: usize,
        delay: Duration,
    ) -> Vec<u8> {
        use tokio::io::AsyncReadExt as _;
        let mut len_buf = [0u8; 8];
        peer.read_exact(&mut len_buf).await.unwrap();
        let len = i64::from_le_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        let mut off = 0;
        while off < len {
            let end = (off + chunk).min(len);
            peer.read_exact(&mut body[off..end]).await.unwrap();
            off = end;
            tokio::time::sleep(delay).await;
        }
        body
    }

    /// Mirror of [`read_frame_slowly`] for the peer's writes.
    async fn write_frame_slowly<W: tokio::io::AsyncWrite + Unpin>(
        peer: &mut W,
        bytes: &[u8],
        chunk: usize,
        delay: Duration,
    ) {
        use tokio::io::AsyncWriteExt as _;
        peer.write_all(&(bytes.len() as i64).to_le_bytes())
            .await
            .unwrap();
        let mut off = 0;
        while off < bytes.len() {
            let end = (off + chunk).min(bytes.len());
            peer.write_all(&bytes[off..end]).await.unwrap();
            off = end;
            tokio::time::sleep(delay).await;
        }
    }

    /// A catch-up entry the client can actually decrypt: real ciphertext
    /// from a fresh peer writer (the client's reader stream is fresh too —
    /// the peer delivered nothing before the outage).
    fn encrypted_entry(writer: &mut CryptoHandler, payload: &[u8]) -> Vec<u8> {
        let mut packet = Packet::new(1, payload.to_vec());
        packet.encrypt(writer);
        packet.serialize()
    }

    /// A slow-but-progressing peer recovers: every 64 KiB chunk of the
    /// catch-up lands inside the idle window even though the whole
    /// transfer outlasts it — a single total timeout would livelock this
    /// session on retry forever.
    #[tokio::test]
    async fn recover_tolerates_a_slow_but_progressing_peer() {
        let mut rig = rig(None).await;
        let _peer = rig.accept().await;
        // ~512 KiB of backlog: 9+ chunks at 64 KiB.
        for i in 0..8u8 {
            rig.backed.write(1, vec![i; 64 * 1024]).await.unwrap();
        }
        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));

        let recover_stream = rig.connect_extra().await;
        let peer2 = rig.accept().await;
        let exchange = tokio::spawn(async move {
            // Header phase at full speed.
            let mut peer2 = peer2;
            let bytes = read_proto_frame(&mut peer2, MAX_HANDSHAKE_PROTO_LENGTH)
                .await
                .unwrap();
            let sh = SequenceHeader::decode_from_slice(&bytes).unwrap();
            write_proto_frame(
                &mut peer2,
                &SequenceHeader {
                    sequenceNumber: Some(0),
                    ..Default::default()
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();

            // Full-duplex slow peer: their catch-up streams back on the
            // write half WHILE our catch-up is still being trickled off
            // the read half — both directions progress past the idle
            // window chunk by chunk, without a pipeline bubble between
            // the phases (a sequential peer's reply-start delay would
            // itself exceed any idle window shorter than the transfer).
            let mut entry_writer = peer_crypto().writer;
            let entries: Vec<Vec<u8>> = (0..4)
                .map(|i| encrypted_entry(&mut entry_writer, &[i; 64 * 1024]))
                .collect();
            let reply = CatchupBuffer {
                buffer: entries,
                ..Default::default()
            }
            .encode_to_vec();
            let (mut read_half, mut write_half) = peer2.into_split();
            let reply_task = tokio::spawn(async move {
                write_frame_slowly(
                    &mut write_half,
                    &reply,
                    crate::backed::RECOVER_IO_CHUNK,
                    Duration::from_millis(400),
                )
                .await;
                write_half // moved back out when the task finishes
            });
            // Our catch-up read slowly: 64 KiB chunks, 400 ms apart —
            // 8 chunks ≈ 3.2 s total. Keep the bytes: the test replays
            // them below to align its mock reader's nonce phase.
            let slow = read_frame_slowly(
                &mut read_half,
                crate::backed::RECOVER_IO_CHUNK,
                Duration::from_millis(400),
            )
            .await;
            let write_half = reply_task.await.unwrap();
            (sh.sequenceNumber.unwrap(), read_half, write_half, slow)
        });

        // idle 2 s < total ≈ 5 s, per-chunk ≈ 400 ms: only progress-based
        // bounds can carry this exchange — a single 2 s total timeout
        // would abort it.
        let ok = rig
            .backed
            .recover_timed(
                recover_stream,
                Duration::from_secs(2),
                Duration::from_secs(30),
            )
            .await;
        let (client_seq, mut read_half, write_half, slow) = exchange.await.unwrap();
        assert_eq!(client_seq, 0);
        assert!(ok, "a progressing peer must recover despite a slow link");

        // The slowly-arrived catch-up is delivered, decrypted, in order.
        let writer = peer_crypto().writer;
        for i in 0..4u8 {
            match timeout(LONG, rig.events.recv()).await.unwrap() {
                Some(BackedEvent::Packet(packet)) => {
                    assert_eq!(packet.header(), 1);
                    assert_eq!(packet.payload(), &vec![i; 64 * 1024][..]);
                }
                other => panic!("expected catch-up packet {i}, got {other:?}"),
            }
        }
        // And the recovered socket is live both ways. The mock reader
        // must first replay the 8 re-sent catch-up entries (nonce 1-8)
        // so it expects the "live" packet at the right nonce (9).
        let mut reader = peer_crypto().reader;
        let resent = CatchupBuffer::decode_from_slice(&slow).unwrap();
        assert_eq!(resent.buffer.len(), 8);
        for entry in &resent.buffer {
            Packet::parse(entry).unwrap().decrypt(&mut reader).unwrap();
        }
        rig.backed.write(2, b"live".to_vec()).await.unwrap();
        let mut wire = read_framed_packet(&mut read_half, MAX_PACKET_LENGTH)
            .await
            .unwrap();
        assert!(wire.is_encrypted());
        wire.decrypt(&mut reader).unwrap();
        assert_eq!(wire.payload(), b"live");
        let _ = (write_half, writer); // entries were pre-encrypted above
    }

    /// A peer that stalls mid-exchange is abandoned at the idle window —
    /// the bogus-reconnect bound must survive the new timing scheme.
    #[tokio::test]
    async fn recover_abandons_a_stalled_exchange_at_the_idle_window() {
        let mut rig = rig(None).await;
        let _peer = rig.accept().await;
        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));

        let recover_stream = rig.connect_extra().await;
        let peer2 = rig.accept().await;
        // Reads our SequenceHeader, then stalls forever before replying —
        // in its own task: the client only writes the header once
        // `recover_timed` below starts, so an inline read would deadlock
        // the test against itself.
        let stalled = tokio::spawn(async move {
            let mut peer2 = peer2;
            let _ = read_proto_frame(&mut peer2, MAX_HANDSHAKE_PROTO_LENGTH).await;
            // Hold the socket open, never reply.
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let started = std::time::Instant::now();
        let ok = rig
            .backed
            .recover_timed(
                recover_stream,
                Duration::from_millis(200),
                Duration::from_secs(30),
            )
            .await;
        assert!(!ok, "a stalled peer must not recover");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the idle window must bound the stall, took {:?}",
            started.elapsed()
        );
        stalled.abort();
    }

    /// Even a progressing peer is bounded by the absolute ceiling: the
    /// exchange cannot run past it, matching the C++ peer's own 60 s
    /// abandonment (and bounding ciphertext exfiltration by a trickling
    /// peer).
    #[tokio::test]
    async fn recover_absolute_cap_binds_even_a_progressing_peer() {
        let mut rig = rig(None).await;
        let _peer = rig.accept().await;
        for i in 0..8u8 {
            rig.backed.write(1, vec![i; 64 * 1024]).await.unwrap();
        }
        rig.backed.kill_socket().await;
        assert!(matches!(
            rig.events.recv().await,
            Some(BackedEvent::SocketDown)
        ));

        let recover_stream = rig.connect_extra().await;
        let mut peer2 = rig.accept().await;
        let exchange = tokio::spawn(async move {
            let bytes = read_proto_frame(&mut peer2, MAX_HANDSHAKE_PROTO_LENGTH)
                .await
                .unwrap();
            let _ = SequenceHeader::decode_from_slice(&bytes).unwrap();
            write_proto_frame(
                &mut peer2,
                &SequenceHeader {
                    sequenceNumber: Some(0),
                    ..Default::default()
                }
                .encode_to_vec(),
            )
            .await
            .unwrap();
            // Trickle-reads our ~512 KiB catch-up: every chunk well inside
            // the idle window, but the total outlasts the absolute cap.
            let _slow = read_frame_slowly(
                &mut peer2,
                crate::backed::RECOVER_IO_CHUNK,
                Duration::from_millis(150),
            )
            .await;
        });

        let started = std::time::Instant::now();
        let ok = rig
            .backed
            .recover_timed(
                recover_stream,
                Duration::from_secs(10),
                Duration::from_millis(600),
            )
            .await;
        assert!(
            !ok,
            "the absolute ceiling must bind even a progressing peer"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the exchange must end near the ceiling, took {:?}",
            started.elapsed()
        );
        let _ = exchange.await;
    }
}
