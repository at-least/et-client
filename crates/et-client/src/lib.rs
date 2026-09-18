//! Rust implementation of the EternalTerminal **client** (upstream `et`),
//! wire-compatible with the C++ `etserver`/`etterminal` at protocol version
//! 6. Built for conch: the SSH handshake is exposed as pure functions
//! ([`ssh`]) so an embedding app can run it over its own SSH transport, and
//! the session ([`session::TerminalSession`]) is a plain async API over
//! plain data types.
//!
//! ```no_run
//! use et_client::session::TerminalSession;
//! use et_proto::InitialPayload;
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! // id/passkey come from the SSH handshake (see et_client::ssh).
//! let mut session = TerminalSession::start(
//!     "server.example.com:2022".into(),
//!     "XXX0123456789abcd".into(),
//!     "0123456789012345678901234567890123456789012345", // placeholder
//!     &InitialPayload::default(),
//!     et_client::session::DEFAULT_KEEPALIVE,
//! ).await?;
//! session.send_input(b"uname -a\n").await?;
//! while let Some(event) = session.next_event().await {
//!     match event {
//!         et_client::session::SessionEvent::TerminalBuffer(bytes) => { /* paint */ }
//!         et_client::session::SessionEvent::Dead(_) => break,
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod connection;
pub mod error;
pub mod protocol;
pub mod session;
pub mod ssh;

pub use connection::{EtClient, Event};
pub use error::ConnectFailure;
pub use et_proto::backed::WriteError;
pub use session::{SessionEvent, TerminalSession, DEFAULT_KEEPALIVE};
