//! The protobuf message set, hand-transcribed from the upstream
//! `proto/ET.proto` and `proto/ETerminal.proto` (kept verbatim in `proto/`).
//!
//! Upstream builds with `protoc`; here the messages are `prost` derives with
//! the exact field numbers and proto2 `optional` presence, so no code
//! generator is a build dependency (conch's "generated output is committed,
//! generators are never a build dependency" rule). Wire compatibility is
//! guarded by golden-bytes tests (`tests/golden.rs`).
//!
//! proto2 `optional` maps to `Option<T>`: a field explicitly set to its
//! default value *is* serialized, exactly like C++ `set_x(default)`.
//! Map fields use `HashMap`: protobuf maps are unordered by spec (C++
//! merges entries in any arrival order), so iteration order never affects
//! interoperability.

use prost::Message;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// ET.proto
// ---------------------------------------------------------------------------

/// Upstream `et.ConnectRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ConnectRequest {
    #[prost(string, optional, tag = "1")]
    pub client_id: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub version: Option<i32>,
}

/// Upstream `et.ConnectResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ConnectResponse {
    #[prost(int32, optional, tag = "1")]
    pub status: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub error: Option<String>,
}

impl ConnectResponse {
    /// Typed view of the raw status code. (prost 0.14 generates its own
    /// raw `status()` getter, hence the different name.)
    pub fn connect_status(&self) -> Option<crate::ConnectStatus> {
        self.status.and_then(crate::ConnectStatus::from_i32)
    }
}

/// Upstream `et.SequenceHeader`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct SequenceHeader {
    #[prost(int32, optional, tag = "1")]
    pub sequence_number: Option<i32>,
}

/// Upstream `et.CatchupBuffer`: serialized (still-encrypted) packets the peer
/// has not yet received.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct CatchupBuffer {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub buffer: Vec<Vec<u8>>,
}

/// Upstream `et.SocketEndpoint`: a unix path (`name`) or TCP port (`port`).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct SocketEndpoint {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub port: Option<i32>,
}

// ---------------------------------------------------------------------------
// ETerminal.proto
// ---------------------------------------------------------------------------

/// Upstream `et.TerminalBuffer`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TerminalBuffer {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub buffer: Option<Vec<u8>>,
}

/// Upstream `et.TerminalInfo`. `row`/`column` are the window size in
/// characters, `width`/`height` in pixels.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TerminalInfo {
    #[prost(string, optional, tag = "1")]
    pub id: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub row: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    pub column: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    pub width: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    pub height: Option<i32>,
}

/// Upstream `et.PortForwardSourceRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PortForwardSourceRequest {
    #[prost(message, optional, tag = "1")]
    pub source: Option<SocketEndpoint>,
    #[prost(message, optional, tag = "2")]
    pub destination: Option<SocketEndpoint>,
    #[prost(string, optional, tag = "3")]
    pub environmentvariable: Option<String>,
}

/// Upstream `et.PortForwardSourceResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PortForwardSourceResponse {
    #[prost(string, optional, tag = "1")]
    pub error: Option<String>,
}

/// Upstream `et.PortForwardDestinationRequest`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PortForwardDestinationRequest {
    #[prost(message, optional, tag = "1")]
    pub destination: Option<SocketEndpoint>,
    #[prost(int32, optional, tag = "2")]
    pub fd: Option<i32>,
}

/// Upstream `et.PortForwardDestinationResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PortForwardDestinationResponse {
    #[prost(int32, optional, tag = "1")]
    pub clientfd: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub socketid: Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub error: Option<String>,
}

/// Upstream `et.PortForwardData`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct PortForwardData {
    #[prost(bool, optional, tag = "1")]
    pub sourcetodestination: Option<bool>,
    #[prost(int32, optional, tag = "2")]
    pub socketid: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub buffer: Option<Vec<u8>>,
    #[prost(string, optional, tag = "4")]
    pub error: Option<String>,
    #[prost(bool, optional, tag = "5")]
    pub closed: Option<bool>,
}

/// Upstream `et.InitialPayload` — the first encrypted packet the client sends
/// after `ConnectResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct InitialPayload {
    #[prost(bool, optional, tag = "1", default = "false")]
    pub jumphost: Option<bool>,
    #[prost(message, repeated, tag = "2")]
    pub reversetunnels: Vec<PortForwardSourceRequest>,
    #[prost(map = "string, string", tag = "3")]
    pub environmentvariables: HashMap<String, String>,
}

/// Upstream `et.InitialResponse`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct InitialResponse {
    #[prost(string, optional, tag = "1")]
    pub error: Option<String>,
}

/// Upstream `et.ConfigParams`.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct ConfigParams {
    #[prost(int32, optional, tag = "1")]
    pub vlevel: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub minloglevel: Option<i32>,
}

/// Upstream `et.TermInit` — sent by the server to the terminal after the
/// client's `InitialPayload` is accepted; carries the environment the shell
/// should be started with.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TermInit {
    #[prost(string, repeated, tag = "1")]
    pub environmentnames: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    pub environmentvalues: Vec<String>,
}

/// Upstream `et.TerminalUserInfo` — sent *unencrypted* by `etterminal` to
/// `etserver` over the unix leg to register (id, passkey).
#[derive(Clone, PartialEq, Eq, Message)]
pub struct TerminalUserInfo {
    #[prost(string, optional, tag = "1")]
    pub id: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub passkey: Option<String>,
    #[prost(int64, optional, tag = "3")]
    pub uid: Option<i64>,
    #[prost(int64, optional, tag = "4")]
    pub gid: Option<i64>,
    #[prost(int64, optional, tag = "5")]
    pub fd: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_status_round_trip() {
        for status in [
            crate::ConnectStatus::NewClient,
            crate::ConnectStatus::ReturningClient,
            crate::ConnectStatus::InvalidKey,
            crate::ConnectStatus::MismatchedProtocol,
        ] {
            let r = ConnectResponse { status: Some(status as i32), error: None };
            assert_eq!(r.connect_status(), Some(status));
        }
        assert_eq!(ConnectResponse::default().connect_status(), None);
        assert_eq!(
            ConnectResponse { status: Some(99), error: None }.connect_status(),
            None
        );
    }

    #[test]
    fn map_field_round_trips_regardless_of_order() {
        // Protobuf maps are unordered on the wire: insertion order must not
        // change what decodes back (byte equality is NOT asserted —
        // prost's HashMap iteration order is unspecified by design).
        let mut a = InitialPayload::default();
        a.environmentvariables.insert("ZZ".to_string(), "1".to_string());
        a.environmentvariables.insert("AA".to_string(), "2".to_string());
        let mut b = InitialPayload::default();
        b.environmentvariables.insert("AA".to_string(), "2".to_string());
        b.environmentvariables.insert("ZZ".to_string(), "1".to_string());
        let decoded_a = InitialPayload::decode(a.encode_to_vec().as_slice()).unwrap();
        let decoded_b = InitialPayload::decode(b.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded_a, decoded_b);
        assert_eq!(decoded_a.environmentvariables.len(), 2);
    }
}
