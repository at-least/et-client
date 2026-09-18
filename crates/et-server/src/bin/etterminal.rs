//! `etterminal` — hosts one PTY session and registers it with `etserver`
//! (Rust port, wire-compatible with upstream C++ etterminal at protocol
//! version 6).
//!
//! Normal invocation (what the `et` client runs over ssh):
//! ```text
//! echo '<id>/<passkey>_<TERM>' | etterminal --verbose=0
//! ```
//! Jumphost mode (`--jump`) is not implemented in this port.

use et_server::terminal::{self, TerminalOptions};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let mut opts = TerminalOptions::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--idpasskey" => {
                if let Some(value) = args.next() {
                    opts.idpasskey = parse_idpasskey(&value);
                }
            }
            "--idpasskeyfile" => {
                if let Some(path) = args.next() {
                    match std::fs::read_to_string(&path) {
                        Ok(content) => {
                            let trimmed = content.trim_end_matches(['\r', '\n']);
                            opts.idpasskey = parse_idpasskey(trimmed);
                        }
                        Err(e) => {
                            eprintln!("etterminal: cannot read {path}: {e}");
                            return std::process::ExitCode::FAILURE;
                        }
                    }
                }
            }
            "--serverfifo" => {
                if let Some(path) = args.next() {
                    opts.socket_path = Some(path.into());
                }
            }
            "--jump" => opts.jump = true,
            "--dsthost" => {
                if let Some(host) = args.next() {
                    opts.dsthost = host;
                }
            }
            "--dstport" => {
                if let Some(port) = args.next() {
                    opts.dstport = port.parse().unwrap_or(0);
                }
            }
            "-v" | "--verbose" | "--logdir" | "--logtostdout" => {
                let _ = args.next();
            }
            "-h" | "--help" => {
                println!(
                    "echo '<id>/<passkey>_<TERM>' | etterminal [--serverfifo PATH] \
                     [--idpasskey ID/PASSKEY] [--jump --dsthost H --dstport P] [-v LEVEL]"
                );
                return std::process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("etterminal: unrecognized argument {other:?}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    match terminal::run(opts).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("etterminal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Accepts `id/passkey` or the full stdin shape `id/passkey_TERM`.
fn parse_idpasskey(value: &str) -> Option<(String, String)> {
    let value = value.split('_').next().unwrap_or(value);
    let (id, passkey) = value.split_once('/')?;
    Some((id.to_string(), passkey.to_string()))
}
