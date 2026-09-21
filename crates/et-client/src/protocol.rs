//! Client-side protocol constants that live upstream in `Headers.hpp` /
//! `TerminalMain.cpp`. The wire-length constants (`ID_LEN`, `PASSKEY_LEN`)
//! live once in [`et_proto::ids`] — this module only adds client-side
//! defaults.

/// `$TERM` used when the environment does not provide one (upstream default
/// in `SshSetupHandler::SetupSsh`).
pub const DEFAULT_TERMINAL: &str = "xterm-256color";
