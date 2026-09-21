//! SSH handshake helpers, faithful to upstream `SshSetupHandler.cpp`.
//!
//! Everything here is **pure** — no process is spawned, no trait must be
//! implemented — so conch can drive the handshake over its own SSH
//! transport (russh): build the command string, run it remotely, feed the
//! collected output back into [`parse_idpasskey_output`]. [`run_ssh_handshake`]
//! is the reference transport using the system `ssh` binary.

use crate::protocol::DEFAULT_TERMINAL;
use et_proto::ids::{ID_LEN, PASSKEY_LEN};

#[derive(Clone, PartialEq, Eq)]
pub struct IdPasskey {
    pub id: String,
    pub passkey: String,
}

impl std::fmt::Debug for IdPasskey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The passkey is the session key; a derived Debug would print it
        // straight into any log line that includes an IdPasskey.
        f.debug_struct("IdPasskey")
            .field("id", &self.id)
            .field("passkey", &"[REDACTED]")
            .finish()
    }
}

impl Drop for IdPasskey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Defense-in-depth beyond upstream: scrub the strings on drop.
        self.id.zeroize();
        self.passkey.zeroize();
    }
}

/// Marker the server-side `etterminal` prints on stdout (upstream
/// `TerminalMain.cpp`: `CLOG(INFO, "stdout") << "IDPASSKEY:" << idpasskey`).
pub const IDPASSKEY_MARKER: &str = "IDPASSKEY:";

/// Options for the remote `etterminal` command line. Only fields the upstream
/// client actually varies for a plain terminal session.
#[derive(Debug, Clone, Default)]
pub struct TerminalCommandOptions {
    /// `--verbose=N` (upstream always passes it).
    pub verbose: i32,
    /// `--serverfifo=PATH` override, mirrors upstream `--serverfifo`.
    pub server_fifo: Option<String>,
    /// `cmd_prefix` upstream: full path to the etterminal binary (empty =
    /// `etterminal` on `$PATH`).
    pub etterminal_path: String,
    /// Upstream `--kill`: `pkill etterminal -u <user>; sleep 0.5;` prefix.
    pub kill_existing: bool,
    /// Remote user for the `pkill -u` part of `--kill`.
    pub user: String,
}

/// Builds `echo '<id>/<passkey>_<TERM>' | etterminal --verbose=N ...`,
/// byte-identical to upstream `genCommand` (quoting included — upstream does
/// not escape, and neither do we; the id/passkey alphabet is shell-safe).
pub fn etterminal_command(
    id: &str,
    passkey: &str,
    client_term: &str,
    opts: &TerminalCommandOptions,
) -> String {
    let bin = if opts.etterminal_path.is_empty() {
        "etterminal"
    } else {
        &opts.etterminal_path
    };
    let mut command = format!(
        "echo '{id}/{passkey}_{client_term}' | {bin} --verbose={}",
        opts.verbose
    );
    if let Some(fifo) = &opts.server_fifo {
        command.push_str(&format!(" --serverfifo={fifo}"));
    }
    if opts.kill_existing {
        let user = if opts.user.is_empty() {
            "$USER"
        } else {
            &opts.user
        };
        command = format!("pkill etterminal -u {user}; sleep 0.5; {command}");
    }
    command
}

/// Upstream `SshSetupHandler::SetupSsh`: new clients send an id starting
/// with `XXX` so a modern server regenerates both values.
pub fn generate_id_passkey() -> IdPasskey {
    let (id, passkey) = et_proto::ids::generate_id_passkey();
    IdPasskey { id, passkey }
}

/// `$TERM` default for the remote shell (upstream: `xterm-256color`).
pub fn default_client_term() -> String {
    std::env::var("TERM").unwrap_or_else(|_| DEFAULT_TERMINAL.to_string())
}

/// Destination for [`build_ssh_args`].
#[derive(Debug, Clone, Default)]
pub struct SshDestination {
    pub user: String,
    pub host: String,
    pub port: Option<u16>,
    /// `--jumphost` value upstream (`-J`); an `ssh -J` transport dials the
    /// destination through this jump host during the handshake.
    pub jumphost: Option<String>,
    /// Extra `-o` options (upstream `--ssh-option`).
    pub ssh_options: Vec<String>,
}

/// Builds the `ssh` argv (without the program name): `[-J jumphost]
/// [user@]host [-p port] [-o opt]... <command>`. Mirrors
/// `SshSetupHandler::SetupSsh` ordering.
pub fn build_ssh_args(dest: &SshDestination, command: &str) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(jump) = &dest.jumphost {
        args.push("-J".into());
        args.push(jump.clone());
    }
    let mut target = String::new();
    if !dest.user.is_empty() {
        target.push_str(&dest.user);
        target.push('@');
    }
    target.push_str(&dest.host);
    args.push(target);
    if let Some(port) = dest.port {
        args.push("-p".into());
        args.push(port.to_string());
    }
    for opt in &dest.ssh_options {
        args.push(format!("-o{opt}"));
    }
    args.push(command.to_string());
    args
}

/// Extracts the (possibly server-regenerated) id/passkey from the collected
/// ssh output. Upstream searches for `"IDPASSKEY:"` anywhere in the buffer
/// and takes exactly `16 + 1 + 32` characters after the marker — everything
/// before it may be noise from login scripts.
pub fn parse_idpasskey_output(output: &str) -> Option<IdPasskey> {
    parse_idpasskey_bytes(output.as_bytes())
}

/// Byte-level variant of [`parse_idpasskey_output`]: motd noise around the
/// marker is arbitrary bytes, so slicing the `&str` could panic on a char
/// boundary; the id/passkey payload itself must be the upstream
/// `genRandomAlphaNum` alphabet — which is what keeps
/// [`etterminal_command`]'s unescaped single-quoting shell-safe (a
/// compromised SSH-leg endpoint controls these bytes, a quote there would
/// break out of the quoting in any command built from them).
pub fn parse_idpasskey_bytes(output: &[u8]) -> Option<IdPasskey> {
    let marker = IDPASSKEY_MARKER.as_bytes();
    let mut start = None;
    for i in 0..output.len().saturating_sub(marker.len() - 1) {
        if &output[i..i + marker.len()] == marker {
            start = Some(i + marker.len());
            break;
        }
    }
    let start = start?;
    let end = start.checked_add(ID_LEN + 1 + PASSKEY_LEN)?;
    if output.len() < end {
        return None;
    }
    let idpasskey = std::str::from_utf8(&output[start..end]).ok()?;
    let (id, passkey) = idpasskey.split_once('/')?;
    if !id
        .bytes()
        .chain(passkey.bytes())
        .all(|b| b.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(IdPasskey {
        id: id.to_string(),
        passkey: passkey.to_string(),
    })
}

/// Error of [`run_ssh_handshake`].
#[derive(Debug, thiserror::Error)]
pub enum SshHandshakeError {
    #[error("ssh exited unsuccessfully")]
    SshFailed,
    #[error("no IDPASSKEY in server output (is anything printed in the server shell rc files?)")]
    MissingMarker,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Runs the handshake with the system `ssh`: stdout is piped (that is where
/// `IDPASSKEY:` arrives), stdin and stderr stay attached so interactive
/// host-key/password prompts keep working — the same split as upstream
/// `SubprocessToStringInteractive`.
pub async fn run_ssh_handshake(
    dest: &SshDestination,
    command: &str,
) -> Result<IdPasskey, SshHandshakeError> {
    let args = build_ssh_args(dest, command);
    let output = tokio::process::Command::new("ssh")
        .args(&args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .await?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(SshHandshakeError::SshFailed);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_idpasskey_output(&text).ok_or(SshHandshakeError::MissingMarker)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The passkey *is* the session key: a derived `Debug` would print it
    /// straight into any log line that includes an `IdPasskey`.
    #[test]
    fn idpasskey_debug_does_not_leak_the_passkey() {
        let ip = generate_id_passkey();
        let rendered = format!("{ip:?}");
        assert!(
            !rendered.contains(&ip.passkey),
            "Debug must redact the passkey, got: {rendered}"
        );
    }

    #[test]
    fn generated_ids_have_upstream_shape() {
        const ALPHANUM: &[u8; 62] =
            b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for _ in 0..32 {
            let ip = generate_id_passkey();
            assert_eq!(ip.id.len(), ID_LEN);
            assert_eq!(&ip.id[..3], "XXX");
            assert_eq!(ip.passkey.len(), PASSKEY_LEN);
            assert!(
                ip.id.bytes().all(|b| ALPHANUM.contains(&b))
                    && ip.passkey.bytes().all(|b| ALPHANUM.contains(&b))
            );
        }
    }

    #[test]
    fn command_matches_upstream_format() {
        let opts = TerminalCommandOptions::default();
        assert_eq!(
            etterminal_command("XXXabc", "key123", "xterm-256color", &opts),
            "echo 'XXXabc/key123_xterm-256color' | etterminal --verbose=0"
        );
        let opts = TerminalCommandOptions {
            verbose: 3,
            server_fifo: Some("/tmp/fifo".into()),
            ..Default::default()
        };
        assert_eq!(
            etterminal_command("i", "p", "t", &opts),
            "echo 'i/p_t' | etterminal --verbose=3 --serverfifo=/tmp/fifo"
        );
        let opts = TerminalCommandOptions {
            kill_existing: true,
            user: "joe".into(),
            ..Default::default()
        };
        assert_eq!(
            etterminal_command("i", "p", "t", &opts),
            "pkill etterminal -u joe; sleep 0.5; echo 'i/p_t' | etterminal --verbose=0"
        );
    }

    #[test]
    fn parse_idpasskey_survives_non_ascii_noise() {
        // Multibyte bytes directly around the marker must not panic (the
        // old &str slicing did) and must not swallow the payload.
        let ip = generate_id_passkey();
        let mut noisy = b"\xe5\xba\x8f\x1b[0m ".to_vec();
        noisy.extend_from_slice(format!("IDPASSKEY:{}/{}", ip.id, ip.passkey).as_bytes());
        noisy.extend_from_slice(b" trailing \xe5\xba\x8f");
        assert_eq!(parse_idpasskey_bytes(&noisy).unwrap(), ip);
        assert!(parse_idpasskey_bytes(b"IDPASSKEY:\xff\xfe/xxx").is_none());
    }

    /// The id/passkey alphabet is what makes `etterminal_command`'s
    /// unescaped single-quoting safe (upstream `genCommand` parity): the
    /// parser must enforce it, not assume it — a compromised SSH-leg
    /// endpoint controls these bytes, and a quote there would break out
    /// of the quoting in any later command built from them.
    #[test]
    fn parse_idpasskey_rejects_non_alphanumeric_payloads() {
        // Exactly 16 + '/' + 32 bytes after the marker, with a quote in
        // the passkey window: length-valid, charset-invalid.
        let shell_breakout = format!(
            "IDPASSKEY:XXXabcdefghijklmnop/{}'{}",
            "a".repeat(15),
            "b".repeat(16)
        );
        assert!(
            parse_idpasskey_output(&shell_breakout).is_none(),
            "a payload with shell metacharacters must be rejected"
        );
        // The shape is only checked past the marker: noise before it
        // stays arbitrary.
        let honest = format!("IDPASSKEY:XXXabcdefghijklmnop/{}", "k".repeat(32));
        assert!(parse_idpasskey_output(&honest).is_some());
    }

    #[test]
    fn parse_idpasskey_finds_marker_after_noise() {
        let ip = generate_id_passkey();
        let output = format!(
            "Last login: today\nsome motd\nIDPASSKEY:{}/{}",
            ip.id, ip.passkey
        );
        assert_eq!(parse_idpasskey_output(&output).unwrap(), ip);
        // Marker absent (login shell printed something else).
        assert!(parse_idpasskey_output("hello world").is_none());
        // Marker present but truncated.
        let truncated = format!("IDPASSKEY:{}/{}", ip.id, &ip.passkey[..10]);
        assert!(parse_idpasskey_output(&truncated).is_none());
    }

    #[test]
    fn ssh_args_match_upstream_order() {
        let dest = SshDestination {
            user: "me".into(),
            host: "example.com".into(),
            port: Some(2222),
            jumphost: Some("jump@bastion".into()),
            ssh_options: vec!["BatchMode=yes".into()],
        };
        assert_eq!(
            build_ssh_args(&dest, "echo hi"),
            vec![
                "-J",
                "jump@bastion",
                "me@example.com",
                "-p",
                "2222",
                "-oBatchMode=yes",
                "echo hi"
            ]
        );
    }
}
