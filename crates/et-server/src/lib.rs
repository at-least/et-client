//! Rust implementation of the EternalTerminal **server side** — the
//! `etserver` daemon and the per-session `etterminal` PTY host —
//! wire-compatible with the upstream C++ binaries at protocol version 6.
//!
//! Architecture (see `docs/protocol.md` upstream and this repo's README):
//! - `etterminal` connects to `etserver` over a local **unix socket**
//!   (upstream calls it a "fifo"; it is `AF_UNIX` `SOCK_STREAM`) and
//!   registers `(id, passkey)` with a `TERMINAL_USER_INFO` packet;
//! - the client reaches `etserver` over TCP (default port 2022);
//! - `etserver` relays between the two legs. Terminal data is encrypted
//!   only on the TCP leg — the unix leg is a plain local stream;
//! - server→terminal frames are `[type: u8][i64-LE framed proto]`;
//!   terminal→server output is a raw byte stream.

/// Re-export of the shared client event type used by the jump relay.
pub mod client_event_shim {
    pub use et_proto::client::Event;
}

pub mod fifo;
pub mod pty;
pub mod router;
pub mod server;
pub mod terminal;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
    #[error("{0}")]
    Other(String),
}

impl From<et_proto::FrameError> for ServerError {
    fn from(e: et_proto::FrameError) -> Self {
        match e {
            et_proto::FrameError::Io(io) => ServerError::Io(io),
            other => ServerError::Other(other.to_string()),
        }
    }
}

/// Reads the payload of a packet as a protobuf message.
pub(crate) fn decode_payload<M: buffa::Message + Default>(
    packet: &et_proto::Packet,
) -> Result<M, String> {
    M::decode_from_slice(packet.payload())
        .map_err(|e| format!("bad {}: {e}", std::any::type_name::<M>()))
}
