//! Frame formats. Two coexist, both inherited from upstream:
//!
//! - **`i64` LE length prefix** (`SocketHandler::readProto`/`writeProto` and
//!   `SocketHandler::readPacket`/`writePacket`): used for every handshake
//!   message (`ConnectRequest`, `ConnectResponse`, `SequenceHeader`,
//!   `CatchupBuffer`), and on the unix leg (`etserver`↔`etterminal`) for
//!   registration/init packets and the typed routing frames. Upstream writes
//!   a native-endian `int64_t`; every platform ET supports is little-endian,
//!   so the wire order is little-endian.
//! - **`u32` BE length prefix** (`BackedReader`/`BackedWriter`): the
//!   encrypted packet stream on the TCP legs (`et`↔`etserver`).
//!
//! Toward the terminal the server prefixes a one-byte packet type before an
//! `i64`-framed protobuf ([`write_typed_proto`]); terminal output flows back
//! as a raw byte stream with no framing at all ([`write_unframed`]).

use crate::packet::Packet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// EOF at a frame boundary (or mid-frame — both mean the peer went away).
    #[error("connection closed")]
    Closed,
    #[error("frame of {0} bytes exceeds the allowed maximum")]
    InvalidLength(i64),
    #[error("truncated or malformed packet")]
    InvalidPacket,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl FrameError {
    fn map_io(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Closed
        } else {
            FrameError::Io(err)
        }
    }
}

/// `SocketHandler::readProto`: one `i64`-LE length + serialized protobuf.
/// An empty frame decodes to an empty buffer (upstream returns the default
/// message); upstream rejects `length < 0 || length > max` before reading.
pub async fn read_proto_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: i64,
) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 8];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) => return Err(FrameError::map_io(e)),
    }
    let len = i64::from_le_bytes(len_buf);
    if len < 0 || len > max_len {
        return Err(FrameError::InvalidLength(len));
    }
    let mut buf = vec![0u8; len as usize];
    match r.read_exact(&mut buf).await {
        Ok(_) => Ok(buf),
        Err(e) => Err(FrameError::map_io(e)),
    }
}

/// `SocketHandler::writeProto`: one `i64`-LE length + bytes.
pub async fn write_proto_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
) -> Result<(), FrameError> {
    w.write_all(&(bytes.len() as i64).to_le_bytes()).await?;
    w.write_all(bytes).await?;
    Ok(())
}

/// `SocketHandler::readPacket` (unix leg): `i64`-LE length + serialized
/// [`Packet`].
pub async fn read_packet_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: i64,
) -> Result<Packet, FrameError> {
    let bytes = read_proto_frame(r, max_len).await?;
    Packet::parse(&bytes).ok_or(FrameError::InvalidPacket)
}

/// `SocketHandler::writePacket` (unix leg).
pub async fn write_packet_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    packet: &Packet,
) -> Result<(), FrameError> {
    write_proto_frame(w, &packet.serialize()).await
}

/// `BackedReader` frame: `u32` BE length + serialized [`Packet`] (TCP legs).
pub async fn read_framed_packet<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: usize,
) -> Result<Packet, FrameError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) => return Err(FrameError::map_io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(FrameError::InvalidLength(len as i64));
    }
    let mut buf = vec![0u8; len];
    match r.read_exact(&mut buf).await {
        Ok(_) => Packet::parse(&buf).ok_or(FrameError::InvalidPacket),
        Err(e) => Err(FrameError::map_io(e)),
    }
}

/// `BackedWriter` frame: `u32` BE length + serialized [`Packet`] (TCP legs).
pub async fn write_framed_packet<W: AsyncWrite + Unpin>(
    w: &mut W,
    packet: &Packet,
) -> Result<(), FrameError> {
    let bytes = packet.serialize();
    w.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    Ok(())
}

/// Server→terminal routing frame: one type byte ([`crate::terminal_packet_type`])
/// followed by an `i64`-LE framed protobuf.
pub async fn write_typed_proto<W: AsyncWrite + Unpin>(
    w: &mut W,
    packet_type: u8,
    proto_bytes: &[u8],
) -> Result<(), FrameError> {
    w.write_all(&[packet_type]).await?;
    write_proto_frame(w, proto_bytes).await
}

/// Terminal→server direction: a raw byte stream with no framing
/// (`UserTerminalHandler::runUserTerminal` writes pty output raw; the server
/// `read()`s it raw).
pub async fn write_unframed<W: AsyncWrite + Unpin>(
    w: &mut W,
    bytes: &[u8],
) -> Result<(), FrameError> {
    w.write_all(bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::ConnectRequest;
    use prost::Message;

    #[tokio::test]
    async fn proto_frame_round_trip() {
        let mut buf = Vec::new();
        let req = ConnectRequest {
            client_id: Some("XXXabcdefghijklmnop".into()),
            version: Some(crate::PROTOCOL_VERSION),
        };
        write_proto_frame(&mut buf, &req.encode_to_vec()).await.unwrap();
        let decoded = read_proto_frame(&mut &buf[..], crate::MAX_HANDSHAKE_PROTO_LENGTH)
            .await
            .unwrap();
        assert_eq!(ConnectRequest::decode(&decoded[..]).unwrap(), req);
    }

    #[tokio::test]
    async fn proto_frame_rejects_negative_and_oversize() {
        let buf = (-1i64).to_le_bytes().to_vec();
        assert!(matches!(
            read_proto_frame(&mut &buf[..], 1024).await,
            Err(FrameError::InvalidLength(-1))
        ));
        let buf = (9999i64).to_le_bytes().to_vec();
        assert!(matches!(
            read_proto_frame(&mut &buf[..], 1024).await,
            Err(FrameError::InvalidLength(9999))
        ));
    }

    #[tokio::test]
    async fn empty_frame_is_empty_message() {
        let mut buf = Vec::new();
        write_proto_frame(&mut buf, &[]).await.unwrap();
        assert_eq!(buf.len(), 8);
        let decoded = read_proto_frame(&mut &buf[..], 1024).await.unwrap();
        assert!(decoded.is_empty());
    }

    #[tokio::test]
    async fn closed_at_boundary_and_mid_frame() {
        let mut empty: &[u8] = &[];
        assert!(matches!(
            read_proto_frame(&mut empty, 1024).await,
            Err(FrameError::Closed)
        ));
        let partial = [1u8, 2]; // 3 of 8 length bytes
        assert!(matches!(
            read_proto_frame(&mut &partial[..], 1024).await,
            Err(FrameError::Closed)
        ));
    }

    #[tokio::test]
    async fn tcp_packet_frame_round_trip() {
        let mut buf = Vec::new();
        let p = Packet::new(crate::terminal_packet_type::KEEP_ALIVE, Vec::new());
        write_framed_packet(&mut buf, &p).await.unwrap();
        // u32 BE length prefix, then [0, header].
        assert_eq!(&buf[..6], &[0, 0, 0, 2, 0, 0]);
        assert_eq!(read_framed_packet(&mut &buf[..], crate::MAX_PACKET_LENGTH).await.unwrap(), p);
    }

    #[tokio::test]
    async fn unix_packet_frame_and_typed_proto() {
        let mut buf = Vec::new();
        let p = Packet::new(crate::terminal_packet_type::TERMINAL_USER_INFO, b"x".to_vec());
        write_packet_frame(&mut buf, &p).await.unwrap();
        assert_eq!(read_packet_frame(&mut &buf[..], 1024).await.unwrap(), p);

        let mut buf = Vec::new();
        write_typed_proto(&mut buf, crate::terminal_packet_type::TERMINAL_BUFFER, b"hi")
            .await
            .unwrap();
        assert_eq!(buf[0], crate::terminal_packet_type::TERMINAL_BUFFER);
        let proto = read_proto_frame(&mut &buf[1..], 1024).await.unwrap();
        assert_eq!(proto, b"hi");
    }
}
