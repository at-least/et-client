//! Wire layer of the EternalTerminal protocol (upstream C++ `MisterTea/EternalTerminal`,
//! protocol version 6), reimplemented in Rust.
//!
//! Everything in this crate is byte-exact: the packet layout, the two frame
//! formats, the XSalsa20-Poly1305 crypto (libsodium `crypto_secretbox_easy`
//! semantics, including the little-endian nonce counter that is incremented
//! *before* each operation), and the protobuf message set are all fixed by
//! interoperability with the C++ `et`/`etserver`/`etterminal` binaries.
//! The upstream `.proto` files are kept verbatim in `proto/` as the reference.
//!
//! Two frame formats coexist (both inherited from upstream):
//! - **TCP legs** (`et`↔`etserver`): `[u32 BE length][packet]` where a packet
//!   is `[encrypted: u8][header: u8][payload]`.
//! - **Every handshake message**: `[i64 LE length][bytes]`, where the bytes
//!   are a serialized protobuf message.

pub mod backed;
pub mod client;
pub mod crypto;
pub mod forward;
pub mod framing;
pub mod gen;
pub mod ids;
pub mod packet;

pub use backed::{BackedConfig, BackedEvent, BackedHandle, DeadReason, WriteError};
pub use crypto::CryptoHandler;
pub use framing::{
    read_framed_packet, read_proto_frame, write_framed_packet, write_proto_frame, FrameError,
};
pub use gen::et::*;
pub use packet::Packet;

/// Upstream `Headers.hpp`: `static const int PROTOCOL_VERSION = 6`.
pub const PROTOCOL_VERSION: i32 = 6;

/// Client→server direction of the nonce stream (upstream
/// `CLIENT_SERVER_NONCE_MSB`).
pub const CLIENT_SERVER_NONCE_MSB: u8 = 0;
/// Server→client direction of the nonce stream (upstream
/// `SERVER_CLIENT_NONCE_MSB`).
pub const SERVER_CLIENT_NONCE_MSB: u8 = 1;

/// Upstream `SocketHandler::MAX_HANDSHAKE_PROTO_LENGTH` — cap for every
/// pre-crypto message (`ConnectRequest`, `ConnectResponse`, `SequenceHeader`,
/// `CatchupBuffer`).
pub const MAX_HANDSHAKE_PROTO_LENGTH: i64 = 4 * 1024;
/// Upstream `SocketHandler::DEFAULT_MAX_PROTO_LENGTH` — cap for large
/// protobuf frames (the recover exchange's `CatchupBuffer`).
pub const DEFAULT_MAX_PROTO_LENGTH: i64 = 128 * 1024 * 1024;
/// Sanity cap for the `u32`-framed packet length on TCP legs. Upstream does
/// not bound this before allocating; 128 MiB matches the upstream cap used
/// for the unix-leg packet frame.
pub const MAX_PACKET_LENGTH: usize = 128 * 1024 * 1024;

/// Upstream `EtPacketType` (`ET.proto`): connection-level packet headers.
pub mod et_packet_type {
    pub const INITIAL_RESPONSE: u8 = 252;
    pub const INITIAL_PAYLOAD: u8 = 253;
    pub const HEARTBEAT: u8 = 254;
}

/// Upstream `TerminalPacketType` (`ETerminal.proto`): terminal-level packet
/// headers. These are also the one-byte type prefixes the server writes to
/// the terminal unix stream.
pub mod terminal_packet_type {
    pub const KEEP_ALIVE: u8 = 0;
    pub const TERMINAL_BUFFER: u8 = 1;
    pub const TERMINAL_INFO: u8 = 2;
    pub const PORT_FORWARD_DESTINATION_REQUEST: u8 = 5;
    pub const PORT_FORWARD_DESTINATION_RESPONSE: u8 = 6;
    pub const PORT_FORWARD_DATA: u8 = 7;
    pub const TERMINAL_USER_INFO: u8 = 8;
    pub const TERMINAL_INIT: u8 = 9;
    pub const JUMPHOST_INIT: u8 = 10;
}

// `ConnectStatus` and every message type come from the generated module
// (`gen/et.rs`), re-exported above. Unknown enum values on the wire route
// to unknown fields (proto2 closed-enum semantics, like the C++ side).
