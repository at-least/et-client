//! Error types for the client-side protocol machinery. The write-path error
//! is shared with the server (it is the backed-connection state machine's).

pub use et_proto::backed::WriteError;

/// Failure of the *initial* TCP handshake (`ConnectRequest` →
/// `ConnectResponse`). The reconnect loop never surfaces these: it retries
/// forever (mirroring upstream), except `InvalidKey`, which ends the session.
#[derive(Debug, thiserror::Error)]
pub enum ConnectFailure {
    #[error("tcp connect failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake timed out")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("server rejected the session: {status:?}: {error}")]
    Rejected {
        status: et_proto::ConnectStatus,
        error: String,
    },
}
