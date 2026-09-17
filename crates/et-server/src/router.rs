//! Shared registry on `etserver` — port of `UserTerminalRouter` +
//! `ServerConnection`'s `clientKeys`/`clientConnections` maps.
//!
//! Three id-keyed tables:
//! - `keys`: id → passkey, set when an `etterminal` registers; a client
//!   `ConnectRequest` with an id missing here gets `INVALID_KEY`;
//! - `terminals`: id → registration info + the unix socket until a session
//!   takes it over;
//! - `clients`: id → live backed connection (`clientConnections`), whose
//!   presence turns a reconnecting client's handshake into
//!   `RETURNING_CLIENT`.

use std::collections::HashMap;
use std::sync::Mutex;

use et_proto::BackedHandle;
use tokio::net::UnixStream;

#[derive(Debug, Clone)]
pub struct TerminalInfo {
    pub passkey: String,
    pub uid: u32,
    pub gid: u32,
}

pub struct TerminalSlot {
    pub info: TerminalInfo,
    /// Taken by the client session when it starts relaying.
    pub stream: Option<UnixStream>,
}

#[derive(Clone)]
pub struct ClientEntry {
    pub key: String,
    pub conn: BackedHandle,
}

#[derive(Default)]
struct Inner {
    keys: HashMap<String, String>,
    terminals: HashMap<String, TerminalSlot>,
    clients: HashMap<String, ClientEntry>,
}

#[derive(Default, Clone)]
pub struct Router {
    inner: std::sync::Arc<Mutex<Inner>>,
}

/// Passkey comparison without early-exit timing (upstream
/// `ServerClientConnection::verifyPasskey`).
pub fn verify_passkey(key: &str, target: &str) -> bool {
    let (a, b) = (key.as_bytes(), target.as_bytes());
    let len = a.len().min(b.len());
    let mut mismatch = a.len() != b.len();
    for i in 0..len {
        mismatch |= a[i] != b[i];
    }
    !mismatch
}

impl Router {
    /// `UserTerminalRouter::acceptNewConnection` registration step. Returns
    /// `false` on a duplicate id (upstream rejects the second terminal).
    pub fn register_terminal(
        &self,
        id: &str,
        passkey: &str,
        uid: u32,
        gid: u32,
        stream: UnixStream,
    ) -> bool {
        let mut inner = self.inner.lock().expect("router lock");
        if inner.terminals.contains_key(id) {
            return false;
        }
        inner.keys.insert(id.to_string(), passkey.to_string());
        inner.terminals.insert(
            id.to_string(),
            TerminalSlot {
                info: TerminalInfo { passkey: passkey.to_string(), uid, gid },
                stream: Some(stream),
            },
        );
        true
    }

    /// `tryGetInfoForConnection` + fd takeover. `None` while the terminal
    /// has not registered (yet).
    pub fn take_terminal(&self, id: &str) -> Option<(TerminalInfo, UnixStream)> {
        let mut inner = self.inner.lock().expect("router lock");
        let slot = inner.terminals.get_mut(id)?;
        let stream = slot.stream.take()?;
        Some((slot.info.clone(), stream))
    }

    pub fn drop_terminal(&self, id: &str) {
        let mut inner = self.inner.lock().expect("router lock");
        inner.terminals.remove(id);
    }

    pub fn client_exists(&self, id: &str) -> bool {
        self.inner.lock().expect("router lock").clients.contains_key(id)
    }

    pub fn get_client(&self, id: &str) -> Option<ClientEntry> {
        self.inner.lock().expect("router lock").clients.get(id).cloned()
    }

    pub fn key_exists(&self, id: &str) -> bool {
        self.inner.lock().expect("router lock").keys.contains_key(id)
    }

    pub fn get_key(&self, id: &str) -> Option<String> {
        self.inner.lock().expect("router lock").keys.get(id).cloned()
    }

    /// `ServerConnection::newClient` insert.
    pub fn add_client(&self, id: &str, key: &str, conn: BackedHandle) {
        let mut inner = self.inner.lock().expect("router lock");
        inner.clients.insert(id.to_string(), ClientEntry { key: key.to_string(), conn });
    }

    /// `ServerConnection::removeClient`: forget key + connection + terminal.
    pub fn remove_client(&self, id: &str) {
        let mut inner = self.inner.lock().expect("router lock");
        inner.keys.remove(id);
        inner.clients.remove(id);
        inner.terminals.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_compare_is_exact_and_length_sensitive() {
        assert!(verify_passkey("abcdefgh", "abcdefgh"));
        assert!(!verify_passkey("abcdefgh", "abcdefgZ"));
        assert!(!verify_passkey("abcdefgh", "abcdefg"));
        assert!(!verify_passkey("", "x"));
    }
}
