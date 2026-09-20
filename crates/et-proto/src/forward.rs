//! Port-forwarding engine — port of upstream `PortForwardHandler` +
//! `ForwardSourceHandler`/`ForwardDestinationHandler` (TCP ports only;
//! unix-socket pipes and env-var forwarding are not supported).
//!
//! Roles are symmetric: each side of a session runs one engine owning
//! - **sources**: local listeners (client `-t`, server `-r`). An accepted
//!   connection produces a `DESTINATION_REQUEST`; the peer's `RESPONSE`
//!   assigns a socket id; local reads become `DATA{sourcetodestination=true}`;
//!   `DATA{std=false}` from the peer is written into the local connection.
//! - **destinations**: connections opened on `DESTINATION_REQUEST`
//!   (server for `-t`, client for `-r`). Mirrored direction flags.
//!
//! Upstream details kept: destinations connect to `::1` then `127.0.0.1`
//! (the destination *name* is ignored for TCP), socket ids are random u32s,
//! EOF becomes a `closed` DATA frame and tears the tunnel down. Divergences:
//! reads are 16 KiB (not 1 KiB), and a session that never opted into local
//! destinations answers requests with an error instead of opening loopback
//! ports (upstream clients would).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use buffa::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};

use crate::{
    Packet, PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse,
    PortForwardSourceRequest,
};

pub use crate::terminal_packet_type::{
    PORT_FORWARD_DATA as PORT_FORWARD_HEADER,
    PORT_FORWARD_DESTINATION_REQUEST as DESTINATION_REQUEST_HEADER,
    PORT_FORWARD_DESTINATION_RESPONSE as DESTINATION_RESPONSE_HEADER,
};

#[derive(Debug, thiserror::Error)]
pub enum TunnelParseError {
    #[error("tunnel argument must have source and destination between a ':'")]
    MissingDestination,
    #[error("source/destination port range must have same length")]
    RangeLengthMismatch,
    #[error("invalid port range syntax: if source is a range, destination must be a range (and vice versa)")]
    HalfRange,
    #[error("invalid tunnel argument '{0}': {1}")]
    Invalid(String, String),
    #[error("port {0} is out of range (must be 0-65535)")]
    PortOutOfRange(i64),
    #[error("unix-socket forwarding ('{0}') is not supported in this build")]
    UnsupportedSocket(String),
}

fn is_socket_path(s: &str) -> bool {
    s.starts_with('/')
}

fn numeric_or_range(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// Port of upstream `parseRangesToRequests` (`TunnelUtils.cpp`): et-style
/// `src:dst` entries (ports, ranges `a-b:c-d`), ssh-style
/// `bind:port:host:hostport`, and env-var pipe specs, comma separated.
/// Unix-socket forms parse like upstream but return
/// [`TunnelParseError::UnsupportedSocket`] — this build forwards TCP only.
pub fn parse_ranges(input: &str) -> Result<Vec<PortForwardSourceRequest>, TunnelParseError> {
    let mut out = Vec::new();
    for element in input.split(',') {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }
        let parts: Vec<&str> = element.split(':').collect();
        if parts.len() <= 2 {
            process_et_style(&mut out, &parts, input)?;
        } else {
            let ssh = parse_ssh_tunnel_arg(element)?;
            let port = |v: &String| parse_port(v, input);
            out.push(PortForwardSourceRequest {
                source: crate::SocketEndpoint {
                    name: Some(ssh[0].clone()),
                    port: Some(port(&ssh[1])?),
                    ..Default::default()
                }
                .into(),
                destination: crate::SocketEndpoint {
                    name: Some(ssh[2].clone()),
                    port: Some(port(&ssh[3])?),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            });
        }
    }
    Ok(out)
}

fn endpoint(name: Option<&str>, port: Option<i32>) -> crate::SocketEndpoint {
    crate::SocketEndpoint {
        name: name.map(str::to_string),
        port,
        ..Default::default()
    }
}

fn process_et_style(
    out: &mut Vec<PortForwardSourceRequest>,
    parts: &[&str],
    input: &str,
) -> Result<(), TunnelParseError> {
    if parts.len() < 2 {
        return Err(TunnelParseError::MissingDestination);
    }
    let (src, dst) = (parts[0], parts[1]);
    let src_is_socket = is_socket_path(src);
    let src_is_numeric = numeric_or_range(src);
    let dst_is_numeric = numeric_or_range(dst);
    let dst_is_socket = is_socket_path(dst);

    if src_is_socket || (dst_is_socket && src_is_numeric) {
        return Err(TunnelParseError::UnsupportedSocket(
            if src_is_socket { src } else { dst }.to_string(),
        ));
    }
    if !src_is_numeric && !dst_is_numeric && !src.is_empty() {
        // env-var pipe forwarding (`ENV:/path`)
        return Err(TunnelParseError::UnsupportedSocket(format!("{src}:{dst}")));
    }
    if src.contains('-') && dst.contains('-') {
        let src_range: Vec<&str> = src.split('-').collect();
        let dst_range: Vec<&str> = dst.split('-').collect();
        if src_range.len() != 2 || dst_range.len() != 2 {
            return Err(TunnelParseError::Invalid(input.into(), "bad range".into()));
        }
        let (src_start, src_end) = (
            parse_port(src_range[0], input)?,
            parse_port(src_range[1], input)?,
        );
        let (dst_start, dst_end) = (
            parse_port(dst_range[0], input)?,
            parse_port(dst_range[1], input)?,
        );
        if src_end - src_start != dst_end - dst_start {
            return Err(TunnelParseError::RangeLengthMismatch);
        }
        for i in 0..=(src_end - src_start) {
            out.push(PortForwardSourceRequest {
                source: endpoint(Some("localhost"), Some(src_start + i)).into(),
                destination: endpoint(None, Some(dst_start + i)).into(),
                ..Default::default()
            });
        }
        return Ok(());
    }
    if src.contains('-') || dst.contains('-') {
        return Err(TunnelParseError::HalfRange);
    }
    out.push(PortForwardSourceRequest {
        source: endpoint(Some("localhost"), Some(parse_port(src, input)?)).into(),
        destination: endpoint(None, Some(parse_port(dst, input)?)).into(),
        ..Default::default()
    });
    Ok(())
}

fn parse_port(v: &str, input: &str) -> Result<i32, TunnelParseError> {
    let port: i64 = v
        .parse()
        .map_err(|_| TunnelParseError::Invalid(input.into(), "bad port".into()))?;
    if !(0..=65535).contains(&port) {
        return Err(TunnelParseError::PortOutOfRange(port));
    }
    Ok(port as i32)
}

fn parse_ssh_tunnel_arg(input: &str) -> Result<Vec<String>, TunnelParseError> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_brackets = false;
    for c in input.chars() {
        match c {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            ':' if !in_brackets => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    if parts.len() < 4 {
        return Err(TunnelParseError::Invalid(
            input.into(),
            "the 4 part ssh-style tunneling arg (bind_address:port:host:hostport) must be supplied"
                .into(),
        ));
    }
    if parts.len() > 4 {
        return Err(TunnelParseError::Invalid(
            input.into(),
            "ipv6 addresses must be inside of square brackets, ie [::1]:8080:[::]:9090".into(),
        ));
    }
    Ok(parts)
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// How long [`EngineHandle::add_sources`] may wait for the engine to get
/// to the command: the engine processes it between data-path work, and a
/// congested tunnel can hold it. Bounded so an embedder's
/// `start_port_forwarding` cannot hang forever; shutdown ends the wait
/// immediately.
const ADD_SOURCES_BOUND: Duration = Duration::from_secs(30);

/// Per-connection local write queue depth. Bounded so a stalled local
/// reader applies backpressure through the engine instead of growing
/// memory without limit; a send failure means the writer task is gone
/// (connection dead) and the tunnel is torn down.
const CONN_WRITE_QUEUE_DEPTH: usize = 256;
/// Local I/O event queue depth: read tasks block here when the engine is
/// saturated, which backs up the local TCP connections.
const EVENT_QUEUE_DEPTH: usize = 1024;
/// Outbound (engine → session) queue depth: the engine blocks here when
/// the session pump is not draining, the last backpressure stage before
/// the backed layer's own 64 MiB caps.
const OUTBOUND_QUEUE_DEPTH: usize = 256;

/// A running engine. Feed it the peer's port-forward packets; it emits the
/// frames to write back to the session. The engine stops — listeners
/// released, connections torn down, outbound closed — on [`shutdown`]
/// (EngineHandle::shutdown) or when every handle clone is dropped.
pub struct EngineHandle {
    inbound: mpsc::UnboundedSender<Packet>,
    cmd_tx: mpsc::Sender<Cmd>,
    shutdown_tx: watch::Sender<bool>,
    /// Live handle-clone count; the Drop impl raises the shutdown watch on
    /// the transition to zero. An explicit atomic, not `Arc::strong_count`:
    /// concurrent drops can each observe the pre-decrement strong count, so
    /// neither would fire and a congested engine (whose only data-path
    /// preempt is the watch) would run forever.
    handle_count: Arc<AtomicUsize>,
}

/// Commands into the engine task.
enum Cmd {
    /// Bind more sources into the running engine; reply carries the bind
    /// errors (one per failed bind, like [`EngineHandle::spawn`]).
    AddSources {
        sources: Vec<PortForwardSourceRequest>,
        reply: oneshot::Sender<Vec<String>>,
    },
    /// Stop the engine.
    Shutdown,
}

impl EngineHandle {
    /// Spawns the engine task. `sources` are bound locally (forward tunnels
    /// on the client, reverse tunnels on the server); bind failures are
    /// returned so the caller can reject the session like upstream's
    /// `PortForwardSourceResponse.error`. When `answer_destinations` is
    /// set, `DESTINATION_REQUEST`s open loopback connections (upstream
    /// always does; this build makes it opt-in). Returns the handle to feed
    /// peer port-forward packets into.
    pub async fn spawn(
        sources: Vec<PortForwardSourceRequest>,
        answer_destinations: bool,
    ) -> (EngineHandle, mpsc::Receiver<Packet>, Vec<String>) {
        let (inbound, inbound_rx) = mpsc::unbounded_channel();
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (events_tx, events) = mpsc::channel(EVENT_QUEUE_DEPTH);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (listeners, bind_errors) = bind_source_listeners(&sources, 0).await;
        for (source_idx, listener) in listeners {
            spawn_accept_task(listener, source_idx, events_tx.clone(), shutdown_rx.clone());
        }
        let state = EngineState::new(sources, events_tx.clone());
        tokio::spawn(run(
            state,
            answer_destinations,
            EngineChannels {
                inbound: inbound_rx,
                cmd_rx,
                outbound,
                events,
                shutdown_tx: shutdown_tx.clone(),
                shutdown_rx,
            },
        ));
        (
            EngineHandle {
                inbound,
                cmd_tx,
                shutdown_tx,
                handle_count: Arc::new(AtomicUsize::new(1)),
            },
            outbound_rx,
            bind_errors,
        )
    }

    pub fn send(&self, packet: Packet) {
        let _ = self.inbound.send(packet);
    }

    /// Stops the engine: source listeners are released, every tunneled
    /// connection is torn down, and the outbound channel closes. Idempotent;
    /// also happens implicitly when every handle clone is dropped. The
    /// watch is raised here directly (not only via the command queue) so a
    /// run loop blocked behind a congested tunnel still stops promptly.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.cmd_tx.send(Cmd::Shutdown).await;
    }

    /// Binds additional sources into the already-running engine (the
    /// session layer uses this to add local forward sources to a session
    /// that pre-spawned a destinations-only engine for reverse tunnels).
    /// Returns one message per failed bind, like [`EngineHandle::spawn`].
    /// The whole call is bounded: the engine may be busy draining a
    /// congested tunnel, so the wait races [`shutdown`]
    /// (EngineHandle::shutdown) and the [`ADD_SOURCES_BOUND`] ceiling —
    /// either surfaces as an error entry instead of hanging the caller.
    pub async fn add_sources(&self, sources: Vec<PortForwardSourceRequest>) -> Vec<String> {
        self.add_sources_timed(sources, ADD_SOURCES_BOUND).await
    }

    /// Timing-injectable [`EngineHandle::add_sources`] (tests drive small
    /// bounds).
    pub(crate) async fn add_sources_timed(
        &self,
        sources: Vec<PortForwardSourceRequest>,
        bound: Duration,
    ) -> Vec<String> {
        let (reply, reply_rx) = oneshot::channel();
        // try_send: a blocked engine can leave the 16-deep command queue
        // full, and an unbounded send would defeat the bound entirely.
        if let Err(mpsc::error::TrySendError::Full(_)) =
            self.cmd_tx.try_send(Cmd::AddSources { sources, reply })
        {
            return vec![
                "port-forward engine command queue is full (congested); retry after shutdown or once the tunnel drains"
                    .into(),
            ];
        }
        if self.cmd_tx.is_closed() {
            return vec!["port-forward engine is not running".into()];
        }
        let mut shutdown = self.shutdown_tx.subscribe();
        tokio::select! {
            replied = reply_rx => replied.unwrap_or_else(|_| {
                vec!["port-forward engine stopped before binding the new sources".into()]
            }),
            res = shutdown.wait_for(|v| *v) => {
                let _ = res;
                vec!["port-forward engine is shutting down".into()]
            }
            _ = tokio::time::sleep(bound) => {
                vec![format!(
                    "port-forward engine did not bind the new sources within {bound:?} (a congested tunnel is blocking it)"
                )]
            }
        }
    }
}

impl Clone for EngineHandle {
    fn clone(&self) -> Self {
        // Relaxed: the count guards only the drop transition to zero, and
        // the decrement side orders that decision.
        self.handle_count.fetch_add(1, Ordering::Relaxed);
        Self {
            inbound: self.inbound.clone(),
            cmd_tx: self.cmd_tx.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            handle_count: self.handle_count.clone(),
        }
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        // Last handle gone: raise the watch so the run loop's blocked
        // sends abandon even before the command channel's close is seen.
        if self.handle_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _ = self.shutdown_tx.send(true);
        }
    }
}

/// Binds `sources` (whose indices start at `base_idx` in the engine's
/// source table) and returns the live listeners plus one error message
/// per failed bind.
async fn bind_source_listeners(
    sources: &[PortForwardSourceRequest],
    base_idx: usize,
) -> (Vec<(usize, TcpListener)>, Vec<String>) {
    let mut bound = Vec::new();
    let mut bind_errors = Vec::new();
    for (i, pfsr) in sources.iter().enumerate() {
        let source = &pfsr.source;
        if !source.is_set() {
            continue;
        }
        let Some(port) = source.port else { continue };
        let host = source.name.clone().unwrap_or_else(|| "localhost".into());
        match TcpListener::bind((host.as_str(), port as u16)).await {
            Ok(listener) => bound.push((base_idx + i, listener)),
            Err(e) => bind_errors.push(format!("{host}:{port}: {e}")),
        }
    }
    (bound, bind_errors)
}

/// One source listener: accepts until the engine shuts down or the event
/// channel dies. Blocking on a full event channel is the backpressure
/// path (the accept backlog absorbs the excess).
fn spawn_accept_task(
    listener: TcpListener,
    source_idx: usize,
    events: mpsc::Sender<Event>,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            if events
                                .send(Event::Accepted { source_idx, stream })
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    });
}

#[derive(Debug)]
enum Event {
    /// A connection accepted by one of our source listeners.
    Accepted {
        source_idx: usize,
        stream: TcpStream,
    },
    /// Bytes (or EOF/error) read from a local connection. Destination-role
    /// connections use their random socket id as `conn_id`.
    Read {
        conn_id: u32,
        result: std::io::Result<Vec<u8>>,
    },
}

/// A local TCP connection: one task writing peer data, one reading.
struct Conn {
    write_tx: mpsc::Sender<Vec<u8>>,
    read_abort: tokio::task::AbortHandle,
}

fn spawn_conn(conn_id: u32, stream: TcpStream, events: mpsc::Sender<Event>) -> Conn {
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(CONN_WRITE_QUEUE_DEPTH);
    // tokio TcpStream is not clonable: round-trip through std to duplicate,
    // then re-wrap (both halves stay in the non-blocking mode tokio set).
    let dup = || -> std::io::Result<(TcpStream, TcpStream)> {
        let std_stream = stream.into_std()?;
        let clone = std_stream.try_clone()?;
        Ok((
            TcpStream::from_std(std_stream)?,
            TcpStream::from_std(clone)?,
        ))
    };
    let (mut read_stream, mut write_stream) = match dup() {
        Ok(pair) => pair,
        Err(_) => {
            return Conn {
                write_tx,
                read_abort: dead_abort(),
            }
        }
    };
    let read_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match read_stream.read(&mut buf).await {
                Ok(0) => {
                    let _ = events
                        .send(Event::Read {
                            conn_id,
                            result: Ok(Vec::new()),
                        })
                        .await;
                    return;
                }
                Ok(n) => {
                    if events
                        .send(Event::Read {
                            conn_id,
                            result: Ok(buf[..n].to_vec()),
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) => {
                    let _ = events
                        .send(Event::Read {
                            conn_id,
                            result: Err(e),
                        })
                        .await;
                    return;
                }
            }
        }
    });
    let read_abort = read_handle.abort_handle();
    tokio::spawn(async move {
        while let Some(bytes) = write_rx.recv().await {
            if bytes.is_empty() {
                return;
            }
            if write_stream.write_all(&bytes).await.is_err() {
                return;
            }
        }
    });
    Conn {
        write_tx,
        read_abort,
    }
}

fn dead_abort() -> tokio::task::AbortHandle {
    tokio::spawn(async {}).abort_handle()
}

impl Conn {
    fn teardown(self) {
        self.read_abort.abort();
        // Dropping write_tx ends the writer task and the stream (FIN).
    }
}

/// The engine's mutable state, shared by the select arms of [`run`].
struct EngineState {
    sources: Vec<PortForwardSourceRequest>,
    events_tx: mpsc::Sender<Event>,
    next_conn_id: u32,
    /// Accepted, REQUEST sent, awaiting RESPONSE (source role).
    pending: HashMap<u32, TcpStream>,
    /// socketid → connection, source role (mapped on RESPONSE).
    source_sockets: HashMap<u32, Conn>,
    /// conn_id → socketid, source role.
    source_conn_ids: HashMap<u32, u32>,
    /// socketid → connection, destination role (conn_id == socketid).
    destinations: HashMap<u32, Conn>,
}

impl EngineState {
    fn new(sources: Vec<PortForwardSourceRequest>, events_tx: mpsc::Sender<Event>) -> Self {
        Self {
            sources,
            events_tx,
            next_conn_id: 1,
            pending: HashMap::new(),
            source_sockets: HashMap::new(),
            source_conn_ids: HashMap::new(),
            destinations: HashMap::new(),
        }
    }

    /// Terminate every tracked connection; called when the engine stops.
    fn teardown_all(self) {
        for (_, conn) in self.source_sockets {
            conn.teardown();
        }
        for (_, conn) in self.destinations {
            conn.teardown();
        }
        // `pending` holds bare streams: dropping closes them.
    }

    async fn handle_accepted(
        &mut self,
        source_idx: usize,
        stream: TcpStream,
        outbound: &mpsc::Sender<Packet>,
        shutdown: &mut watch::Receiver<bool>,
    ) {
        let Some(destination) = self
            .sources
            .get(source_idx)
            .and_then(|pfsr| pfsr.destination.as_option().cloned())
        else {
            return;
        };
        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;
        self.pending.insert(conn_id, stream);
        let request = PortForwardDestinationRequest {
            destination: destination.into(),
            fd: Some(conn_id as i32),
            ..Default::default()
        };
        let _ = send_or_shutdown(
            outbound,
            Packet::new(DESTINATION_REQUEST_HEADER, request.encode_to_vec()),
            shutdown,
        )
        .await;
    }

    async fn handle_read(
        &mut self,
        conn_id: u32,
        result: std::io::Result<Vec<u8>>,
        outbound: &mpsc::Sender<Packet>,
        shutdown: &mut watch::Receiver<bool>,
    ) {
        if let Some(&socket_id) = self.source_conn_ids.get(&conn_id) {
            // Source role: local reads → peer destination.
            match result {
                Ok(bytes) if !bytes.is_empty() => {
                    let _ =
                        send_or_shutdown(outbound, data_packet(socket_id, true, bytes), shutdown)
                            .await;
                }
                Ok(_) => {
                    let _ =
                        send_or_shutdown(outbound, closed_packet(socket_id, true), shutdown).await;
                    if let Some(conn) = self.source_sockets.remove(&socket_id) {
                        conn.teardown();
                    }
                    self.source_conn_ids.remove(&conn_id);
                }
                Err(e) => {
                    let _ = send_or_shutdown(outbound, error_packet(socket_id, true, &e), shutdown)
                        .await;
                    let _ =
                        send_or_shutdown(outbound, closed_packet(socket_id, true), shutdown).await;
                    if let Some(conn) = self.source_sockets.remove(&socket_id) {
                        conn.teardown();
                    }
                    self.source_conn_ids.remove(&conn_id);
                }
            }
        } else if self.destinations.contains_key(&conn_id) {
            // Destination role: local reads → peer source.
            let socket_id = conn_id;
            match result {
                Ok(bytes) if !bytes.is_empty() => {
                    let _ =
                        send_or_shutdown(outbound, data_packet(socket_id, false, bytes), shutdown)
                            .await;
                }
                Ok(_) => {
                    let _ =
                        send_or_shutdown(outbound, closed_packet(socket_id, false), shutdown).await;
                    if let Some(conn) = self.destinations.remove(&socket_id) {
                        conn.teardown();
                    }
                }
                Err(e) => {
                    let _ =
                        send_or_shutdown(outbound, error_packet(socket_id, false, &e), shutdown)
                            .await;
                    let _ =
                        send_or_shutdown(outbound, closed_packet(socket_id, false), shutdown).await;
                    if let Some(conn) = self.destinations.remove(&socket_id) {
                        conn.teardown();
                    }
                }
            }
        }
        // else: connection already torn down; trailing read events.
    }

    async fn handle_peer_packet(
        &mut self,
        packet: Packet,
        answer_destinations: bool,
        outbound: &mpsc::Sender<Packet>,
        shutdown: &mut watch::Receiver<bool>,
    ) {
        match packet.header() {
            DESTINATION_REQUEST_HEADER => {
                let Ok(request) =
                    PortForwardDestinationRequest::decode_from_slice(packet.payload())
                else {
                    return;
                };
                let response = if !answer_destinations {
                    PortForwardDestinationResponse {
                        clientfd: request.fd,
                        error: Some(
                            "port forwarding destinations are not enabled on this session".into(),
                        ),
                        ..Default::default()
                    }
                } else {
                    create_destination(&request, &mut self.destinations, &self.events_tx).await
                };
                let _ = send_or_shutdown(
                    outbound,
                    Packet::new(DESTINATION_RESPONSE_HEADER, response.encode_to_vec()),
                    shutdown,
                )
                .await;
            }
            DESTINATION_RESPONSE_HEADER => {
                let Ok(response) =
                    PortForwardDestinationResponse::decode_from_slice(packet.payload())
                else {
                    return;
                };
                let Some(conn_id) = response.clientfd.map(|v| v as u32) else {
                    return;
                };
                let Some(stream) = self.pending.remove(&conn_id) else {
                    return;
                };
                match response.socketid {
                    Some(socketid) => {
                        let socket_id = socketid as u32;
                        let conn = spawn_conn(conn_id, stream, self.events_tx.clone());
                        if let Some(old) = self.source_sockets.insert(socket_id, conn) {
                            // A peer that reuses a socket id must not leak
                            // the old connection's read task and fd.
                            old.teardown();
                        }
                        self.source_conn_ids.insert(conn_id, socket_id);
                    }
                    None => {
                        // Peer refused (or its destination failed): the
                        // local stream drops, resetting the acceptor.
                        drop(stream);
                    }
                }
            }
            PORT_FORWARD_HEADER => {
                let Ok(pwd) = PortForwardData::decode_from_slice(packet.payload()) else {
                    return;
                };
                let Some(socket_id) = pwd.socketid.map(|v| v as u32) else {
                    return;
                };
                let closed = pwd.closed.unwrap_or(false) || pwd.error.is_some();
                let sourcetodestination = pwd.sourcetodestination.unwrap_or(false);
                let table = if sourcetodestination {
                    // Peer's source data → our destination connection.
                    &mut self.destinations
                } else {
                    // Peer's destination data → our source connection.
                    &mut self.source_sockets
                };
                // Unknown sockets were already filtered out: `remove`
                // returning None means the frame is dropped without a
                // reply, like upstream — a mirrored close could ping-pong
                // between two engines that both lost the socket.
                if let Some(conn) = table.remove(&socket_id) {
                    if closed {
                        conn.teardown();
                    } else if let Some(bytes) = pwd.buffer {
                        // `wait_for` (not `changed()`): the preempt must
                        // be idempotent — a second blocked send after the
                        // first one was abandoned must still see the
                        // already-raised shutdown.
                        let sent = tokio::select! {
                            r = conn.write_tx.send(bytes) => r.is_ok(),
                            res = shutdown.wait_for(|v| *v) => {
                                let _ = res;
                                false
                            }
                        };
                        if sent {
                            // keep the connection registered
                            table.insert(socket_id, conn);
                        } else {
                            // The local write half is gone (the writer
                            // task died on a failed write), or the
                            // engine is shutting down: tear the tunnel
                            // down. The peer learns of the death the
                            // usual way — frames for this socket are
                            // now dropped as unknown, like upstream's
                            // "socket id that has already closed" path.
                            conn.teardown();
                        }
                    } else {
                        table.insert(socket_id, conn);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Sends `packet` toward the session, abandoned early if the engine shuts
/// down: a stalled session pump must not delay shutdown. Returns false
/// when the frame was dropped.
async fn send_or_shutdown(
    outbound: &mpsc::Sender<Packet>,
    packet: Packet,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        r = outbound.send(packet) => r.is_ok(),
        res = shutdown.wait_for(|v| *v) => {
            let _ = res;
            false
        }
    }
}

/// The engine task's channel endpoints.
struct EngineChannels {
    inbound: mpsc::UnboundedReceiver<Packet>,
    cmd_rx: mpsc::Receiver<Cmd>,
    outbound: mpsc::Sender<Packet>,
    events: mpsc::Receiver<Event>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Which data-path channel produced the next item for the engine loop.
enum PeerOrLocal {
    Peer(Option<Packet>),
    Local(Option<Event>),
}

async fn run(mut state: EngineState, answer_destinations: bool, chans: EngineChannels) {
    let EngineChannels {
        mut inbound,
        mut cmd_rx,
        outbound,
        mut events,
        shutdown_tx,
        mut shutdown_rx,
    } = chans;

    loop {
        tokio::select! {
            // Commands first: add_sources and shutdown stay prompt while
            // the loop is merely busy (a blocked data-path send is handled
            // by the shutdown preemption inside the handlers). Only this
            // arm is biased — inbound and events stay randomly fair below,
            // so a saturating peer stream cannot starve local accepts.
            biased;
            cmd = cmd_rx.recv() => match cmd {
                Some(Cmd::AddSources { sources: new_sources, reply }) => {
                    let base = state.sources.len();
                    let (listeners, bind_errors) =
                        bind_source_listeners(&new_sources, base).await;
                    state.sources.extend(new_sources);
                    for (source_idx, listener) in listeners {
                        spawn_accept_task(
                            listener,
                            source_idx,
                            state.events_tx.clone(),
                            shutdown_rx.clone(),
                        );
                    }
                    let _ = reply.send(bind_errors);
                }
                // Explicit shutdown, or every handle dropped.
                Some(Cmd::Shutdown) | None => break,
            },
            // The data-path arms sit in their own *unbiased* select, so a
            // saturating peer stream cannot starve local accepts/reads.
            work = async {
                tokio::select! {
                    packet = inbound.recv() => PeerOrLocal::Peer(packet),
                    event = events.recv() => PeerOrLocal::Local(event),
                }
            } => match work {
                PeerOrLocal::Peer(Some(packet)) => {
                    state
                        .handle_peer_packet(
                            packet,
                            answer_destinations,
                            &outbound,
                            &mut shutdown_rx,
                        )
                        .await
                }
                PeerOrLocal::Peer(None) => break,
                PeerOrLocal::Local(Some(Event::Accepted { source_idx, stream })) => {
                    state
                        .handle_accepted(source_idx, stream, &outbound, &mut shutdown_rx)
                        .await
                }
                PeerOrLocal::Local(Some(Event::Read { conn_id, result })) => {
                    state
                        .handle_read(conn_id, result, &outbound, &mut shutdown_rx)
                        .await
                }
                PeerOrLocal::Local(None) => break,
            },
        }
    }

    // Shutdown cascade: signal the accept tasks, then tear everything down.
    let _ = shutdown_tx.send(true);
    state.teardown_all();
}

/// Upstream `createDestination`: connect `::1:port` then `127.0.0.1:port`
/// (the destination name is ignored for TCP), random unique socket id.
async fn create_destination(
    request: &PortForwardDestinationRequest,
    destinations: &mut HashMap<u32, Conn>,
    events: &mpsc::Sender<Event>,
) -> PortForwardDestinationResponse {
    let Some(port) = request.destination.as_option().and_then(|d| d.port) else {
        return PortForwardDestinationResponse {
            clientfd: request.fd,
            error: Some("destination has no port".into()),
            ..Default::default()
        };
    };
    let Ok(port) = u16::try_from(port) else {
        return PortForwardDestinationResponse {
            clientfd: request.fd,
            error: Some(format!(
                "destination port {port} is out of range (must be 0-65535)"
            )),
            ..Default::default()
        };
    };
    let stream = match TcpStream::connect(("::1", port)).await {
        Ok(s) => Some(s),
        Err(_) => TcpStream::connect(("127.0.0.1", port)).await.ok(),
    };
    let Some(stream) = stream else {
        return PortForwardDestinationResponse {
            clientfd: request.fd,
            error: Some("could not connect to destination".into()),
            ..Default::default()
        };
    };
    let mut socket_id = random_u32();
    while destinations.contains_key(&socket_id) {
        socket_id = random_u32();
    }
    let conn = spawn_conn(socket_id, stream, events.clone());
    destinations.insert(socket_id, conn);
    PortForwardDestinationResponse {
        clientfd: request.fd,
        socketid: Some(socket_id as i32),
        ..Default::default()
    }
}

fn data_packet(socket_id: u32, sourcetodestination: bool, buffer: Vec<u8>) -> Packet {
    Packet::new(
        PORT_FORWARD_HEADER,
        PortForwardData {
            sourcetodestination: Some(sourcetodestination),
            socketid: Some(socket_id as i32),
            buffer: Some(buffer),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn closed_packet(socket_id: u32, sourcetodestination: bool) -> Packet {
    Packet::new(
        PORT_FORWARD_HEADER,
        PortForwardData {
            sourcetodestination: Some(sourcetodestination),
            socketid: Some(socket_id as i32),
            closed: Some(true),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn error_packet(socket_id: u32, sourcetodestination: bool, error: &std::io::Error) -> Packet {
    Packet::new(
        PORT_FORWARD_HEADER,
        PortForwardData {
            sourcetodestination: Some(sourcetodestination),
            socketid: Some(socket_id as i32),
            error: Some(error.to_string()),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    getrandom::fill(&mut buf).expect("system randomness unavailable");
    u32::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    fn src(req: &PortForwardSourceRequest) -> (Option<String>, Option<i32>) {
        let s = req.source.as_option().expect("source set");
        (s.name.clone(), s.port)
    }

    fn dst(req: &PortForwardSourceRequest) -> (Option<String>, Option<i32>) {
        let d = req.destination.as_option().expect("destination set");
        (d.name.clone(), d.port)
    }

    #[test]
    fn single_port_pair_matches_upstream() {
        // -t 18000:8000 → source name "localhost", destination name unset.
        let reqs = parse_ranges("18000:8000").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(src(&reqs[0]), (Some("localhost".into()), Some(18000)));
        assert_eq!(dst(&reqs[0]), (None, Some(8000)));
    }

    #[test]
    fn ranges_expand_pairwise() {
        let reqs = parse_ranges("18001-18003:8001-8003").unwrap();
        assert_eq!(reqs.len(), 3);
        for (i, req) in reqs.iter().enumerate() {
            assert_eq!(src(req), (Some("localhost".into()), Some(18001 + i as i32)));
            assert_eq!(dst(req), (None, Some(8001 + i as i32)));
        }
    }

    #[test]
    fn comma_separated_mix() {
        let reqs = parse_ranges("18000:8000, 2222:22").unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(src(&reqs[1]), (Some("localhost".into()), Some(2222)));
        assert_eq!(dst(&reqs[1]), (None, Some(22)));
    }

    #[test]
    fn ssh_style_four_parts() {
        let reqs = parse_ranges("127.0.0.1:18000:example.com:80").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(src(&reqs[0]), (Some("127.0.0.1".into()), Some(18000)));
        assert_eq!(dst(&reqs[0]), (Some("example.com".into()), Some(80)));
    }

    #[test]
    fn mismatched_range_lengths_rejected() {
        assert!(matches!(
            parse_ranges("18000-18002:8000-8001"),
            Err(TunnelParseError::RangeLengthMismatch)
        ));
        assert!(matches!(
            parse_ranges("18000-18002:8000"),
            Err(TunnelParseError::HalfRange)
        ));
        assert!(matches!(
            parse_ranges("18000"),
            Err(TunnelParseError::MissingDestination)
        ));
    }

    #[test]
    fn unix_socket_forms_parse_but_are_reported_unsupported() {
        // The parser accepts what upstream accepts; callers turn
        // UnsupportedSocket into a user-facing error.
        assert!(matches!(
            parse_ranges("/tmp/sock:8080"),
            Err(TunnelParseError::UnsupportedSocket(_))
        ));
        assert!(matches!(
            parse_ranges("ENV_VAR:/var/run/example.sock"),
            Err(TunnelParseError::UnsupportedSocket(_))
        ));
    }

    /// Ports outside 0-65535 must be rejected loudly: binding with a
    /// silently truncated `port as u16` would listen on a port nobody
    /// asked for (upstream's getaddrinfo fails loudly here).
    #[test]
    fn out_of_range_ports_are_rejected_not_truncated() {
        for input in ["70000:80", "80:70000", "65536:65536"] {
            assert!(
                matches!(
                    parse_ranges(input),
                    Err(TunnelParseError::PortOutOfRange(_))
                ),
                "{input} must be rejected as out of range"
            );
        }
        // ssh-style arg positions are validated too.
        assert!(matches!(
            parse_ranges("127.0.0.1:70000:example.com:80"),
            Err(TunnelParseError::PortOutOfRange(_))
        ));
        // Boundary values keep working.
        assert!(parse_ranges("65535:0").is_ok());
        assert!(parse_ranges("0:65535").is_ok());
    }

    // ---- engine ----

    fn endpoint(port: u16) -> crate::SocketEndpoint {
        crate::SocketEndpoint {
            name: Some("127.0.0.1".into()),
            port: Some(port as i32),
            ..Default::default()
        }
    }

    fn source_request(port: u16) -> PortForwardSourceRequest {
        PortForwardSourceRequest {
            source: endpoint(port).into(),
            destination: endpoint(1).into(),
            ..Default::default()
        }
    }

    fn destination_request(fd: i32, port: u16) -> Packet {
        destination_request_i32(fd, port as i32)
    }

    fn destination_request_i32(fd: i32, port: i32) -> Packet {
        Packet::new(
            DESTINATION_REQUEST_HEADER,
            PortForwardDestinationRequest {
                destination: crate::SocketEndpoint {
                    name: Some("127.0.0.1".into()),
                    port: Some(port),
                    ..Default::default()
                }
                .into(),
                fd: Some(fd),
                ..Default::default()
            }
            .encode_to_vec(),
        )
    }

    /// A peer-originated PORT_FORWARD frame, as the engine's owner would
    /// receive it from the wire and feed back through `EngineHandle::send`.
    fn pf_frame(socket_id: i32, sourcetodestination: bool, buffer: &[u8], closed: bool) -> Packet {
        Packet::new(
            PORT_FORWARD_HEADER,
            PortForwardData {
                sourcetodestination: Some(sourcetodestination),
                socketid: Some(socket_id),
                buffer: (!closed || !buffer.is_empty()).then(|| buffer.to_vec()),
                closed: Some(closed),
                ..Default::default()
            }
            .encode_to_vec(),
        )
    }

    async fn next_outbound(rx: &mut mpsc::Receiver<Packet>) -> Packet {
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for an engine frame")
            .expect("the engine task died")
    }

    /// Echo server on an ephemeral 127.0.0.1 port.
    async fn spawn_echo() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
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

    #[tokio::test]
    async fn spawn_reports_bind_failures() {
        let taken = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = taken.local_addr().unwrap().port();
        let (_, _, errors) = EngineHandle::spawn(vec![source_request(port)], false).await;
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].contains(&format!("127.0.0.1:{port}")),
            "{errors:?}"
        );
    }

    /// Dropping every handle is a shutdown: the engine task ends, the
    /// outbound channel closes, and source listeners are released.
    #[tokio::test]
    async fn dropping_every_handle_stops_the_engine_and_releases_listeners() {
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let (handle, mut outbound, errors) =
            EngineHandle::spawn(vec![source_request(port)], false).await;
        assert!(errors.is_empty(), "{errors:?}");
        let _conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        drop(handle);
        drop(_conn);

        let drained = timeout(Duration::from_secs(2), async {
            while outbound.recv().await.is_some() {}
        })
        .await;
        assert!(
            drained.is_ok(),
            "the outbound channel must close when the engine stops"
        );

        let rebound = timeout(
            Duration::from_secs(2),
            TcpListener::bind(("127.0.0.1", port)),
        )
        .await;
        assert!(
            rebound.is_ok(),
            "the listener must be released after the engine stops"
        );
    }

    /// Explicit `shutdown()` stops the engine even while a handle is held.
    #[tokio::test]
    async fn explicit_shutdown_stops_the_engine_and_releases_listeners() {
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let (handle, mut outbound, errors) =
            EngineHandle::spawn(vec![source_request(port)], false).await;
        assert!(errors.is_empty(), "{errors:?}");

        handle.shutdown().await;

        let drained = timeout(Duration::from_secs(2), async {
            while outbound.recv().await.is_some() {}
        })
        .await;
        assert!(
            drained.is_ok(),
            "the outbound channel must close after shutdown()"
        );

        let rebound = timeout(
            Duration::from_secs(2),
            TcpListener::bind(("127.0.0.1", port)),
        )
        .await;
        assert!(
            rebound.is_ok(),
            "the listener must be released after shutdown()"
        );
    }

    /// Sources can be bound into an already-running engine: the session
    /// layer uses this so a reverse-tunnel session (which auto-spawns a
    /// destinations-only engine) can still add local forward sources.
    #[tokio::test]
    async fn add_sources_binds_new_listeners_on_a_running_engine() {
        let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), false).await;

        let errors = handle.add_sources(vec![source_request(port)]).await;
        assert!(errors.is_empty(), "{errors:?}");

        // The new listener routes accepts into the engine.
        let _conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let packet = next_outbound(&mut outbound).await;
        assert_eq!(packet.header(), DESTINATION_REQUEST_HEADER);
        let request = PortForwardDestinationRequest::decode_from_slice(packet.payload()).unwrap();
        assert_eq!(
            request.fd,
            Some(1),
            "the first accepted conn gets conn id 1"
        );

        // Bind failures are reported like at spawn time.
        let taken = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let errors = handle.add_sources(vec![source_request(taken_port)]).await;
        assert_eq!(errors.len(), 1, "{errors:?}");
    }

    /// A never-reading destination wedges the engine in the data path;
    /// `add_sources` must still return — bounded — instead of hanging the
    /// caller (the embedder's `start_port_forwarding`) forever.
    #[tokio::test]
    async fn add_sources_is_bounded_while_the_engine_is_congested() {
        let service = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = service.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        handle.send(destination_request(1, service_port));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        let socket_id = response.socketid.expect("the destination opened");
        for _ in 0..1024 {
            handle.send(pf_frame(socket_id, true, &[0u8; 16 * 1024], false));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let port = {
            let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            probe.local_addr().unwrap().port()
        };
        let errors = timeout(
            Duration::from_secs(2),
            handle.add_sources_timed(vec![source_request(port)], Duration::from_millis(300)),
        )
        .await
        .expect("add_sources must return within its bound even while congested");
        assert!(
            errors.iter().any(|e| e.as_str().contains("did not bind")),
            "the bounded wait must report itself, got {errors:?}"
        );
    }

    /// The bound must cover the command-channel send too: with the engine
    /// blocked in the data path, the 16-deep command queue fills and a
    /// further `add_sources` must return an error entry instead of
    /// blocking on the send forever.
    #[tokio::test]
    async fn add_sources_is_bounded_even_when_the_command_queue_is_full() {
        let service = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = service.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        handle.send(destination_request(1, service_port));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        let socket_id = response.socketid.expect("the destination opened");
        for _ in 0..1024 {
            handle.send(pf_frame(socket_id, true, &[0u8; 16 * 1024], false));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Fill the 16-deep command queue and then some; every call must
        // return within the (small) bound.
        let mut calls = Vec::new();
        for _ in 0..20 {
            let handle = handle.clone();
            calls.push(tokio::spawn(async move {
                handle
                    .add_sources_timed(vec![], Duration::from_millis(300))
                    .await
            }));
        }
        for call in calls {
            let errors = timeout(Duration::from_secs(2), call)
                .await
                .expect("every add_sources call must return, even with a full queue")
                .expect("the add_sources task must not panic");
            assert!(
                errors.iter().any(|e| !e.is_empty()),
                "a full command queue must surface as an error entry"
            );
        }
    }

    /// `add_sources` racing shutdown returns promptly (well inside its
    /// bound) instead of hanging — whether the reply or the shutdown
    /// notice wins is scheduling, so both outcomes are accepted.
    #[tokio::test]
    async fn add_sources_waiting_in_congestion_reports_shutdown() {
        let service = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = service.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        handle.send(destination_request(1, service_port));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        let socket_id = response.socketid.expect("the destination opened");
        for _ in 0..1024 {
            handle.send(pf_frame(socket_id, true, &[0u8; 16 * 1024], false));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        let waiting = tokio::spawn({
            let handle = handle.clone();
            async move {
                handle
                    .add_sources_timed(vec![], Duration::from_secs(30))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.shutdown().await;

        let errors = timeout(Duration::from_secs(2), waiting)
            .await
            .expect("shutdown must end the add_sources wait promptly")
            .expect("the add_sources task must not panic");
        // Which arm wins (the reply if the engine got to the command
        // first, the shutdown notice if not) is scheduling — the contract
        // is that shutdown ends the wait far inside its 30 s bound.
        assert!(
            errors.is_empty() || errors.iter().any(|e| e.as_str().contains("shutting down")),
            "the wait must end via the reply or the shutdown notice, got {errors:?}"
        );
    }

    #[tokio::test]
    async fn destination_requests_are_refused_when_not_enabled() {
        let (handle, mut outbound, errors) = EngineHandle::spawn(Vec::new(), false).await;
        assert!(errors.is_empty());
        handle.send(destination_request(7, 1));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        assert_eq!(response.clientfd, Some(7));
        assert!(response.socketid.is_none(), "nothing was opened");
        let error = response.error.expect("a refusal reason");
        assert!(error.contains("not enabled"), "{error}");
    }

    #[tokio::test]
    async fn unreachable_destinations_answer_with_an_error() {
        // A port that listened and is now closed: connect refuses fast on
        // both ::1 and 127.0.0.1.
        let port = {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        handle.send(destination_request(3, port));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        assert_eq!(response.clientfd, Some(3));
        assert!(response.socketid.is_none(), "nothing was opened");
        let error = response.error.expect("a connect failure");
        assert!(error.contains("could not connect"), "{error}");
    }

    /// A peer-supplied destination port outside 0-65535 is refused without
    /// attempting a truncated `port as u16` loopback connection.
    #[tokio::test]
    async fn destination_requests_with_out_of_range_ports_are_refused() {
        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        handle.send(destination_request_i32(3, 70000));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        assert_eq!(response.clientfd, Some(3));
        assert!(response.socketid.is_none(), "nothing was opened");
        let error = response.error.expect("a refusal reason");
        assert!(error.contains("out of range"), "{error}");
    }

    /// The destination role end to end without a peer: DESTINATION_REQUEST
    /// opens a loopback connection, DATA{s2d=true} flows into it and comes
    /// back as DATA{s2d=false}, and a close tears the tunnel down.
    #[tokio::test]
    async fn destination_role_moves_data_and_closes() {
        let echo_port = spawn_echo().await;
        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;

        handle.send(destination_request(1, echo_port));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        assert_eq!(response.clientfd, Some(1));
        assert!(response.error.is_none());
        let socket_id = response.socketid.expect("the destination opened");

        handle.send(pf_frame(socket_id, true, b"ping", false));
        let back = PortForwardData::decode_from_slice(next_outbound(&mut outbound).await.payload())
            .unwrap();
        assert_eq!(back.socketid, Some(socket_id));
        assert_eq!(
            back.sourcetodestination,
            Some(false),
            "the echo flows destination→source"
        );
        assert_eq!(back.buffer.as_deref(), Some(&b"ping"[..]));

        // The peer's close tears the tunnel down locally — no close frame is
        // mirrored for a socket we still track (that mirror is only for
        // unknown sockets) — and data for the dead id is dropped silently.
        handle.send(pf_frame(socket_id, true, b"", true));
        handle.send(pf_frame(socket_id, true, b"late", false));
        assert!(
            timeout(Duration::from_millis(300), outbound.recv())
                .await
                .is_err(),
            "no frame may follow the tunnel teardown"
        );
    }

    /// Frames for a socket we do not track are dropped silently — the
    /// upstream `PortForwardHandler::handlePacket` logs "socket id that
    /// has already closed" and moves on. Nothing may be mirrored back:
    /// an echoed close can ping-pong between two engines that both lost
    /// the socket, and it never reaches whichever side still tracks it.
    #[tokio::test]
    async fn closes_for_unknown_sockets_are_dropped() {
        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        for flag in [true, false] {
            handle.send(pf_frame(999, flag, b"", true));
            handle.send(pf_frame(999, flag, b"data", false));
        }
        assert!(
            timeout(Duration::from_millis(300), outbound.recv())
                .await
                .is_err(),
            "frames for unknown sockets must not produce outbound frames"
        );
    }

    /// Shutdown stays responsive while the engine is blocked feeding a
    /// stalled local connection: the destinations never read, the write
    /// queues fill, and the engine sits in the data path — shutdown must
    /// still complete and close the outbound channel. TWO congested
    /// connections, because a shutdown preempt must not be one-shot: the
    /// first abandoned send must not leave later blocked sends unnoticed.
    #[tokio::test]
    async fn shutdown_works_while_connection_queues_are_congested() {
        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        let mut socket_ids = Vec::new();
        for i in 0..2 {
            let service = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let service_port = service.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (_sock, _) = service.accept().await.unwrap();
                // Hold the socket open without reading, forever.
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            });
            handle.send(destination_request(i + 1, service_port));
            let response = PortForwardDestinationResponse::decode_from_slice(
                next_outbound(&mut outbound).await.payload(),
            )
            .unwrap();
            socket_ids.push(response.socketid.expect("the destination opened"));
        }

        // 2048 × 16 KiB = 32 MiB interleaved: past kernel buffers and both
        // 256-frame queues, so the engine blocks in the data path twice.
        for _ in 0..1024 {
            for &socket_id in &socket_ids {
                handle.send(pf_frame(socket_id, true, &[0u8; 16 * 1024], false));
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        timeout(Duration::from_secs(2), handle.shutdown())
            .await
            .expect("shutdown must not hang while the engine is congested");
        let drained = timeout(Duration::from_secs(2), async {
            while outbound.recv().await.is_some() {}
        })
        .await;
        assert!(
            drained.is_ok(),
            "the outbound channel must close after shutdown during congestion"
        );
    }

    /// Dropping the last handle also stops a congested engine: the drop
    /// itself must raise the shutdown watch, or a blocked data-path send
    /// wedges the engine exactly as before shutdown preemption existed.
    #[tokio::test]
    async fn dropping_the_last_handle_stops_a_congested_engine() {
        let service = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = service.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        handle.send(destination_request(1, service_port));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        let socket_id = response.socketid.expect("the destination opened");

        for _ in 0..1024 {
            handle.send(pf_frame(socket_id, true, &[0u8; 16 * 1024], false));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        drop(handle);
        let drained = timeout(Duration::from_secs(2), async {
            while outbound.recv().await.is_some() {}
        })
        .await;
        assert!(
            drained.is_ok(),
            "the engine must stop on last-handle drop even while congested"
        );
    }

    /// Dropping the last handle clones *concurrently* must still stop the
    /// engine exactly once. An `Arc::strong_count == 1` check cannot make
    /// that call: two drops on different workers can each observe the
    /// pre-decrement count, neither raises the watch, and a congested
    /// engine (whose only data-path preempt is that watch) runs forever.
    /// The count is therefore an explicit atomic; this test pins that
    /// contract with a barrier-synchronized mass drop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_last_handle_drops_stop_a_congested_engine() {
        let service = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let service_port = service.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = service.accept().await.unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        handle.send(destination_request(1, service_port));
        let response = PortForwardDestinationResponse::decode_from_slice(
            next_outbound(&mut outbound).await.payload(),
        )
        .unwrap();
        let socket_id = response.socketid.expect("the destination opened");
        for _ in 0..1024 {
            handle.send(pf_frame(socket_id, true, &[0u8; 16 * 1024], false));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Eight clones, all released at one barrier and dropped at once;
        // the original handle is already gone, so these are the last ones.
        let clones: Vec<_> = (0..8).map(|_| handle.clone()).collect();
        drop(handle);
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let drops: Vec<_> = clones
            .into_iter()
            .map(|clone| {
                let barrier = barrier.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    drop(clone);
                })
            })
            .collect();
        for d in drops {
            d.await.unwrap();
        }

        let drained = timeout(Duration::from_secs(2), async {
            while outbound.recv().await.is_some() {}
        })
        .await;
        assert!(
            drained.is_ok(),
            "concurrent drops of the last clones must stop the engine"
        );
    }
}
