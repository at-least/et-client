//! Client-side protocol constants that live upstream in `Headers.hpp` /
//! `TerminalMain.cpp`.

/// Length of the client id (`genRandomAlphaNum(16)`).
pub const ID_LEN: usize = 16;
/// Length of the passkey (`genRandomAlphaNum(32)`).
pub const PASSKEY_LEN: usize = 32;
/// `$TERM` used when the environment does not provide one (upstream default
/// in `SshSetupHandler::SetupSsh`).
pub const DEFAULT_TERMINAL: &str = "xterm-256color";
