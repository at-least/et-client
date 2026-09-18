//! The `etserver`↔`etterminal` rendezvous path — port of upstream
//! `ServerFifoPath.cpp`. Despite the historical name ("fifo"), it is a
//! unix-domain `SOCK_STREAM` socket.
//!
//! Rules inherited from upstream:
//! - root uses `/var/run/etserver.idpasskey.fifo` and nothing else;
//! - non-root uses `$XDG_RUNTIME_DIR/etserver/etserver.idpasskey.fifo`,
//!   falling back to `$HOME/.local/share/etserver/...`, with the directory
//!   created (0700) if missing;
//! - `etterminal` probes root first, then the non-root path.

use std::path::PathBuf;

use tokio::net::UnixStream;

use crate::ServerError;

const ROUTER_FIFO_BASENAME: &str = "etserver.idpasskey.fifo";
const ROOT_ROUTER_FIFO_PATH: &str = "/var/run/etserver.idpasskey.fifo";

fn home() -> Result<PathBuf, ServerError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| ServerError::Other("$HOME is missing or relative".into()))
}

fn xdg_runtime_dir() -> Result<(PathBuf, bool), ServerError> {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if let Some(dir) = dir.to_str().map(PathBuf::from).filter(|p| p.is_absolute()) {
            return Ok((dir, false));
        }
    }
    Ok((home()?.join(".local/share"), true))
}

/// Path `etserver` listens on (port of `ServerFifoPath::getPathForCreation`).
pub fn path_for_creation(override_path: Option<&std::path::Path>) -> Result<PathBuf, ServerError> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    if nix::unistd::Uid::effective().is_root() {
        return Ok(PathBuf::from(ROOT_ROUTER_FIFO_PATH));
    }
    let (dir, _used_default) = xdg_runtime_dir()?;
    Ok(dir.join("etserver").join(ROUTER_FIFO_BASENAME))
}

/// Port of `ServerFifoPath::createDirectoriesIfRequired`: only the non-root
/// default path triggers directory creation, with the upstream permission
/// checks (0700 `etserver` dir owned by the current user).
pub fn create_directories_if_required(override_path: Option<&std::path::Path>) -> Result<(), ServerError> {
    if override_path.is_some() || nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let (dir, used_default) = xdg_runtime_dir()?;
    if used_default {
        let home = home()?;
        for sub in [".local", ".local/share"] {
            let _ = std::fs::create_dir(home.join(sub));
        }
    }
    let etserver_dir = dir.join("etserver");
    let _ = std::fs::create_dir(&etserver_dir);
    let meta = std::fs::metadata(&etserver_dir)
        .map_err(|e| ServerError::Other(format!("failed to stat {etserver_dir:?}: {e}")))?;
    let perms = std::os::unix::fs::PermissionsExt::from_mode(0o700);
    std::fs::set_permissions(&etserver_dir, perms)
        .map_err(|e| ServerError::Other(format!("failed to chmod {etserver_dir:?}: {e}")))?;
    if !meta.is_dir() {
        return Err(ServerError::Other(format!("{etserver_dir:?} is not a directory")));
    }
    Ok(())
}

/// Port of `ServerFifoPath::detectAndConnect`: explicit override, else root
/// path first, then the non-root default.
pub async fn detect_and_connect(
    override_path: Option<&std::path::Path>,
) -> Result<UnixStream, ServerError> {
    if let Some(p) = override_path {
        return tokio::net::UnixStream::connect(p).await.map_err(map_connect_error);
    }
    if let Ok(stream) = tokio::net::UnixStream::connect(ROOT_ROUTER_FIFO_PATH).await {
        return Ok(stream);
    }
    if !nix::unistd::Uid::effective().is_root() {
        let path = path_for_creation(None)?;
        if let Ok(stream) = tokio::net::UnixStream::connect(&path).await {
            return Ok(stream);
        }
    }
    Err(ServerError::Other(
        "The Eternal Terminal daemon is not running. Please (re)start the et daemon on the server."
            .into(),
    ))
}

fn map_connect_error(e: std::io::Error) -> ServerError {
    if e.kind() == std::io::ErrorKind::ConnectionRefused {
        ServerError::Other(
            "The Eternal Terminal daemon is not running. Please (re)start the et daemon on the server."
                .into(),
        )
    } else {
        ServerError::Io(e)
    }
}
