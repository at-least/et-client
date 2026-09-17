//! `etserver` — the EternalTerminal server daemon (Rust port, wire-compatible
//! with upstream C++ etserver at protocol version 6).
//!
//! ```text
//! etserver [--port N] [--serverfifo PATH] [-v LEVEL]
//! ```
//! Run it as a system daemon via systemd/launchd as usual; this binary does
//! not daemonize itself.

use et_server::server::{self, ServerOptions};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let mut opts = ServerOptions::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                opts.port = args.next().and_then(|v| v.parse().ok()).unwrap_or(opts.port);
            }
            "--serverfifo" => {
                if let Some(path) = args.next() {
                    opts.socket_path = Some(path.into());
                }
            }
            "-v" | "--verbose" | "--logtostdout" | "--logdir" => {
                // Accepted for compatibility; logging level is not plumbed.
                let _ = args.next();
            }
            "-h" | "--help" => {
                println!("etserver [--port N] [--serverfifo PATH] [-v LEVEL]");
                return std::process::ExitCode::SUCCESS;
            }
            other => {
                eprintln!("etserver: unrecognized argument {other:?}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            tokio::select! {
                _ = ctrl_c => {}
                _ = async {
                    match sigterm.as_mut() {
                        Some(s) => s.recv().await,
                        None => std::future::pending().await,
                    }
                } => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        let _ = shutdown_tx.send(true);
    });

    match server::run(opts, shutdown_rx).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("etserver: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
