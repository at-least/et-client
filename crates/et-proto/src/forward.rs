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

use buffa::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::{
    Packet, PortForwardData, PortForwardDestinationRequest, PortForwardDestinationResponse,
    PortForwardSourceRequest,
};

pub use crate::terminal_packet_type::{
    PORT_FORWARD_DATA as PORT_FORWARD_HEADER, PORT_FORWARD_DESTINATION_REQUEST as DESTINATION_REQUEST_HEADER,
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
    crate::SocketEndpoint { name: name.map(str::to_string), port, ..Default::default() }
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
        let (src_start, src_end) = (parse_port(src_range[0], input)?, parse_port(src_range[1], input)?);
        let (dst_start, dst_end) = (parse_port(dst_range[0], input)?, parse_port(dst_range[1], input)?);
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
    let port: i64 =
        v.parse().map_err(|_| TunnelParseError::Invalid(input.into(), "bad port".into()))?;
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

/// A running engine. Feed it the peer's port-forward packets; it emits the
/// frames to write back to the session.
#[derive(Clone)]
pub struct EngineHandle {
    inbound: mpsc::UnboundedSender<Packet>,
}

impl EngineHandle {
    pub fn send(&self, packet: Packet) {
        let _ = self.inbound.send(packet);
    }
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
    ) -> (EngineHandle, mpsc::UnboundedReceiver<Packet>, Vec<String>) {
        let (inbound, inbound_rx) = mpsc::unbounded_channel();
        let (outbound, outbound_rx) = mpsc::unbounded_channel();
        let mut bind_errors = Vec::new();
        let mut bound: Vec<(usize, TcpListener)> = Vec::new();
        for (source_idx, pfsr) in sources.iter().enumerate() {
            let source = &pfsr.source;
            if !source.is_set() {
                continue;
            }
            let Some(port) = source.port else { continue };
            let host = source.name.clone().unwrap_or_else(|| "localhost".into());
            match TcpListener::bind((host.as_str(), port as u16)).await {
                Ok(listener) => bound.push((source_idx, listener)),
                Err(e) => bind_errors.push(format!("{host}:{port}: {e}")),
            }
        }
        tokio::spawn(run(sources, bound, answer_destinations, inbound_rx, outbound));
        (EngineHandle { inbound }, outbound_rx, bind_errors)
    }
}

#[derive(Debug)]
enum Event {
    /// A connection accepted by one of our source listeners.
    Accepted { source_idx: usize, stream: TcpStream },
    /// Bytes (or EOF/error) read from a local connection. Destination-role
    /// connections use their random socket id as `conn_id`.
    Read { conn_id: u32, result: std::io::Result<Vec<u8>> },
    Packet(Packet),
}

/// A local TCP connection: one task writing peer data, one reading.
struct Conn {
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_abort: tokio::task::AbortHandle,
}

fn spawn_conn(conn_id: u32, stream: TcpStream, events: mpsc::UnboundedSender<Event>) -> Conn {
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // tokio TcpStream is not clonable: round-trip through std to duplicate,
    // then re-wrap (both halves stay in the non-blocking mode tokio set).
    let dup = || -> std::io::Result<(TcpStream, TcpStream)> {
        let std_stream = stream.into_std()?;
        let clone = std_stream.try_clone()?;
        Ok((TcpStream::from_std(std_stream)?, TcpStream::from_std(clone)?))
    };
    let (mut read_stream, mut write_stream) = match dup() {
        Ok(pair) => pair,
        Err(_) => return Conn { write_tx, read_abort: dead_abort() },
    };
    let read_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match read_stream.read(&mut buf).await {
                Ok(0) => {
                    let _ = events.send(Event::Read { conn_id, result: Ok(Vec::new()) });
                    return;
                }
                Ok(n) => {
                    if events
                        .send(Event::Read { conn_id, result: Ok(buf[..n].to_vec()) })
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) => {
                    let _ = events.send(Event::Read { conn_id, result: Err(e) });
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
    Conn { write_tx, read_abort }
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

async fn run(
    sources: Vec<PortForwardSourceRequest>,
    bound: Vec<(usize, TcpListener)>,
    answer_destinations: bool,
    mut inbound: mpsc::UnboundedReceiver<Packet>,
    outbound: mpsc::UnboundedSender<Packet>,
) {
    let (events_tx, mut events) = mpsc::unbounded_channel::<Event>();
    // Peer packets merge into the same event stream as local I/O.
    {
        let events_tx = events_tx.clone();
        tokio::spawn(async move {
            while let Some(packet) = inbound.recv().await {
                if events_tx.send(Event::Packet(packet)).is_err() {
                    return;
                }
            }
        });
    }

    // Source listeners (forward role). Accept tasks attribute connections
    // with the listener's index into `sources`.
    for (source_idx, listener) in bound {
        let tx = events_tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        if tx.send(Event::Accepted { source_idx, stream }).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }

    let mut next_conn_id: u32 = 1;
    // Accepted, REQUEST sent, awaiting RESPONSE (source role).
    let mut pending: HashMap<u32, TcpStream> = HashMap::new();
    // socketid → connection, source role (mapped on RESPONSE).
    let mut source_sockets: HashMap<u32, Conn> = HashMap::new();
    // conn_id → socketid, source role.
    let mut source_conn_ids: HashMap<u32, u32> = HashMap::new();
    // socketid → connection, destination role (conn_id == socketid).
    let mut destinations: HashMap<u32, Conn> = HashMap::new();

    while let Some(event) = events.recv().await {
        match event {
            Event::Accepted { source_idx, stream } => {
                let Some(destination) =
                    sources.get(source_idx).and_then(|pfsr| pfsr.destination.as_option().cloned())
                else {
                    continue;
                };
                let conn_id = next_conn_id;
                next_conn_id += 1;
                pending.insert(conn_id, stream);
                let request = PortForwardDestinationRequest {
                    destination: destination.into(),
                    fd: Some(conn_id as i32),
                    ..Default::default()
                };
                let _ = outbound.send(Packet::new(
                    DESTINATION_REQUEST_HEADER,
                    request.encode_to_vec(),
                ));
            }
            Event::Read { conn_id, result } => {
                if let Some(&socket_id) = source_conn_ids.get(&conn_id) {
                    // Source role: local reads → peer destination.
                    match result {
                        Ok(bytes) if !bytes.is_empty() => {
                            let _ = outbound.send(data_packet(socket_id, true, bytes));
                        }
                        Ok(_) => {
                            let _ = outbound.send(closed_packet(socket_id, true));
                            if let Some(conn) = source_sockets.remove(&socket_id) {
                                conn.teardown();
                            }
                            source_conn_ids.remove(&conn_id);
                        }
                        Err(e) => {
                            let _ = outbound.send(error_packet(socket_id, true, &e));
                            let _ = outbound.send(closed_packet(socket_id, true));
                            if let Some(conn) = source_sockets.remove(&socket_id) {
                                conn.teardown();
                            }
                            source_conn_ids.remove(&conn_id);
                        }
                    }
                } else if destinations.contains_key(&conn_id) {
                    // Destination role: local reads → peer source.
                    let socket_id = conn_id;
                    match result {
                        Ok(bytes) if !bytes.is_empty() => {
                            let _ = outbound.send(data_packet(socket_id, false, bytes));
                        }
                        Ok(_) => {
                            let _ = outbound.send(closed_packet(socket_id, false));
                            if let Some(conn) = destinations.remove(&socket_id) {
                                conn.teardown();
                            }
                        }
                        Err(e) => {
                            let _ = outbound.send(error_packet(socket_id, false, &e));
                            let _ = outbound.send(closed_packet(socket_id, false));
                            if let Some(conn) = destinations.remove(&socket_id) {
                                conn.teardown();
                            }
                        }
                    }
                }
                // else: connection already torn down; trailing read events.
            }
            Event::Packet(packet) => match packet.header() {
                DESTINATION_REQUEST_HEADER => {
                    let Ok(request) =
                        PortForwardDestinationRequest::decode_from_slice(packet.payload())
                    else {
                        continue;
                    };
                    let response = if !answer_destinations {
                        PortForwardDestinationResponse {
                            clientfd: request.fd,
                            error: Some(
                                "port forwarding destinations are not enabled on this session"
                                    .into(),
                            ),
                            ..Default::default()
                        }
                    } else {
                        create_destination(&request, &mut destinations, &events_tx).await
                    };
                    let _ = outbound.send(Packet::new(
                        DESTINATION_RESPONSE_HEADER,
                        response.encode_to_vec(),
                    ));
                }
                DESTINATION_RESPONSE_HEADER => {
                    let Ok(response) =
                        PortForwardDestinationResponse::decode_from_slice(packet.payload())
                    else {
                        continue;
                    };
                    let Some(conn_id) = response.clientfd.map(|v| v as u32) else { continue };
                    let Some(stream) = pending.remove(&conn_id) else { continue };
                    match response.socketid {
                        Some(socketid) => {
                            let socket_id = socketid as u32;
                            let conn = spawn_conn(conn_id, stream, events_tx.clone());
                            source_sockets.insert(socket_id, conn);
                            source_conn_ids.insert(conn_id, socket_id);
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
                        continue;
                    };
                    let Some(socket_id) = pwd.socketid.map(|v| v as u32) else { continue };
                    let closed = pwd.closed.unwrap_or(false) || pwd.error.is_some();
                    let sourcetodestination = pwd.sourcetodestination.unwrap_or(false);
                    let (table, mirror_flag) = if sourcetodestination {
                        // Peer's source data → our destination connection.
                        (&mut destinations, true)
                    } else {
                        // Peer's destination data → our source connection.
                        (&mut source_sockets, false)
                    };
                    match table.remove(&socket_id) {
                        Some(conn) => {
                            if closed {
                                conn.teardown();
                            } else if let Some(bytes) = pwd.buffer {
                                let _ = conn.write_tx.send(bytes);
                                // keep the connection registered
                                table.insert(socket_id, conn);
                            } else {
                                table.insert(socket_id, conn);
                            }
                        }
                        None => {
                            if closed {
                                // Mirror the close back so the peer stops
                                // pumping even if our side already died.
                                let _ = outbound.send(closed_packet(socket_id, mirror_flag));
                            }
                        }
                    }
                }
                _ => {}
            },
        }
    }
}

/// Upstream `createDestination`: connect `::1:port` then `127.0.0.1:port`
/// (the destination name is ignored for TCP), random unique socket id.
async fn create_destination(
    request: &PortForwardDestinationRequest,
    destinations: &mut HashMap<u32, Conn>,
    events: &mpsc::UnboundedSender<Event>,
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
            error: Some(format!("destination port {port} is out of range (must be 0-65535)")),
            ..Default::default()
        };
    };
    let stream = match TcpStream::connect(("::1", port as u16)).await {
        Ok(s) => Some(s),
        Err(_) => TcpStream::connect(("127.0.0.1", port as u16)).await.ok(),
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
        assert!(matches!(parse_ranges("18000-18002:8000"), Err(TunnelParseError::HalfRange)));
        assert!(matches!(parse_ranges("18000"), Err(TunnelParseError::MissingDestination)));
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

    async fn next_outbound(rx: &mut mpsc::UnboundedReceiver<Packet>) -> Packet {
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
                let Ok((mut stream, _)) = listener.accept().await else { return };
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
        assert!(errors[0].contains(&format!("127.0.0.1:{port}")), "{errors:?}");
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
        let back =
            PortForwardData::decode_from_slice(next_outbound(&mut outbound).await.payload())
                .unwrap();
        assert_eq!(back.socketid, Some(socket_id));
        assert_eq!(back.sourcetodestination, Some(false), "the echo flows destination→source");
        assert_eq!(back.buffer.as_deref(), Some(&b"ping"[..]));

        // The peer's close tears the tunnel down locally — no close frame is
        // mirrored for a socket we still track (that mirror is only for
        // unknown sockets) — and data for the dead id is dropped silently.
        handle.send(pf_frame(socket_id, true, b"", true));
        handle.send(pf_frame(socket_id, true, b"late", false));
        assert!(
            timeout(Duration::from_millis(300), outbound.recv()).await.is_err(),
            "no frame may follow the tunnel teardown"
        );
    }

    /// A close for a socket we no longer track is mirrored back so the peer
    /// stops pumping, keeping the engine's direction flags.
    #[tokio::test]
    async fn closes_for_unknown_sockets_are_mirrored_back() {
        let (handle, mut outbound, _) = EngineHandle::spawn(Vec::new(), true).await;
        for (their_flag, ours) in [(true, true), (false, false)] {
            handle.send(pf_frame(999, their_flag, b"", true));
            let mirrored =
                PortForwardData::decode_from_slice(next_outbound(&mut outbound).await.payload())
                    .unwrap();
            assert_eq!(mirrored.socketid, Some(999));
            assert_eq!(mirrored.sourcetodestination, Some(ours));
            assert_eq!(mirrored.closed, Some(true));
        }
    }
}
