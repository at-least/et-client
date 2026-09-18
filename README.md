# et (Rust) — EternalTerminal, wire-compatible

A Rust implementation of [EternalTerminal](https://github.com/MisterTea/EternalTerminal)
(protocol version **6**), built for [conch](../conch): a remote shell whose
session **survives disconnects and IP changes** without interrupting the
program running inside it. Wire-compatible with the upstream C++
`et` / `etserver` / `etterminal` binaries — verified by automated interop
tests against the real C++ binaries (see *Interop* below).

```
crates/
  et-proto    wire layer: packets, framing, XSalsa20-Poly1305 crypto,
              generated protobuf types, and the shared backed-connection
              state machine (backup buffer, sequence numbers, recover
              exchange)
  et-client   the client library (TerminalSession) + `et` CLI
  et-server   `etserver` daemon + `etterminal` (PTY host) library + CLIs
tools/
  et-proto-gen  regenerates the committed protobuf code from proto/
proto/        the upstream .proto files — the single source of truth
```

## The protocol in one page

Three roles (upstream `docs/protocol.md`):

```
et (client) ──TCP 2022── etserver ──unix socket── etterminal (PTY + shell)
```

1. **SSH handshake.** The client generates `id` (16 alphanumerics, first 3
   `XXX`) and `passkey` (32 alphanumerics), then has *any* SSH transport run
   `echo '<id>/<passkey>_<TERM>' | etterminal` on the server. etterminal
   registers `(id, passkey)` with etserver over a local unix socket and
   prints `IDPASSKEY:<id>/<passkey>` (the server may regenerate both). The
   passkey never travels over the ET connection itself.
2. **TCP session.** The client connects to port 2022 and exchanges
   `ConnectRequest`/`ConnectResponse` (`NEW_CLIENT`, `RETURNING_CLIENT`,
   `INVALID_KEY`, `MISMATCHED_PROTOCOL`; int64-LE-length-framed protobufs).
   Every packet after that is `[u32 BE length][encrypted:u8][header:u8][payload]`,
   with the payload encrypted using libsodium `crypto_secretbox_easy`
   semantics (XSalsa20-Poly1305): the 24-byte nonce starts all-zero except
   the direction MSB (client→server `0`, server→client `1`) and increments
   little-endian **before** every operation. The passkey string *is* the
   32-byte key, so etserver relays ciphertext without decrypting terminal
   data.

   Crypto provenance: the primitive is the RustCrypto
   [`crypto_secretbox`](https://crates.io/crates/crypto_secretbox) crate
   (exact-pinned) — nothing cryptographic is implemented by hand. The only
   hand-written crypto-adjacent code is `CryptoHandler`'s ~60 lines of nonce
   bookkeeping, which is ET **protocol logic** (the counter scheme above is
   fixed by the wire format and interop-tested against the C++ binaries); no
   crate provides it.
3. **Roaming/reconnect.** On any socket death the client retries every
   second. `RETURNING_CLIENT` triggers the recover exchange (both peers run
   the identical sequence, so nobody deadlocks): swap `SequenceHeader`
   (last received sequence), then `CatchupBuffer` — the backed-up
   **ciphertext** packets the peer missed, resent byte-identical, never
   re-encrypted. Writes made while offline buffer up to 64 MiB and flush
   after recovery. Keepalive: after 5 idle seconds the client pings; a
   missed echo kills the socket and reconnect takes over.

The unix leg (etserver↔etterminal, an `AF_UNIX` stream despite the
historical "fifo" name) is unencrypted and asymmetric: registration/init are
`[i64 LE length][packet]` frames; toward the terminal the server writes
`[type:u8][i64-framed proto]`; terminal output is a raw byte stream.

**Protobuf codegen.** The message types in `crates/et-proto/src/gen/` are
generated from `proto/*.proto` with [buffa](https://github.com/anthropics/buffa)
(pure Rust, conformance-tested, editions-first) and **committed**. When
upstream's protos change:

```sh
cargo run -p et-proto-gen   # needs protoc on PATH; regen is a manual act
```

The workspace builds without protoc or the generator. This kills the
hand-transcription drift risk: the `.proto` file is the schema, the generator
is the only transcription step, and the golden-bytes + C++ interop tests below
verify the result against upstream itself. Buffa also preserves unknown fields
through decode/re-encode, so a relayed packet from a newer peer keeps fields
this build does not know (upstream's protobuf-lite drops them).

## Usage

```sh
cargo build --release
# server side (systemd/launchd usually; no self-daemonizing)
target/release/etserver --port 2022
# client side
target/release/et user@host:2022            # SSH handshake via system ssh
target/release/et user@host -c "tail -f /var/log/syslog"
```

The `et` CLI shells out to the system `ssh` for the handshake only;
everything else is Rust.

## For conch

The client library is the embeddable surface (conch wraps it behind UniFFI):

- **No SSH dependency**: `et_client::ssh` exposes *pure functions* —
  [`generate_id_passkey`](crates/et-client/src/ssh.rs),
  [`etterminal_command`](crates/et-client/src/ssh.rs) (the remote command
  string), and [`parse_idpasskey_output`](crates/et-client/src/ssh.rs) — so
  conch drives the handshake over its own russh transport (exec + stdout
  scrape) and never touches a trait or a system binary.
- **Plain async API over plain data**: [`TerminalSession`](crates/et-client/src/session.rs)
  takes `(endpoint, id, passkey, InitialPayload, keepalive)` and yields
  `SessionEvent::TerminalBuffer / KeepAlive / Dead / Other`. No tokio types
  leak across the boundary; reconnect, catch-up, buffering, and keepalive
  enforcement are automatic inside the connection.
- Same dep hygiene as conch-core: wire-format deps pinned exact
  (`prost`, `crypto_secretbox`), committed `Cargo.lock`, `thiserror`.

```rust
let idpasskey = et_client::ssh::generate_id_passkey();
let command = et_client::ssh::etterminal_command(&idpasskey.id, &idpasskey.passkey,
                                                 "xterm-256color", &Default::default());
// run `command` over russh, scrape ssh::parse_idpasskey_output(&stdout)…
let mut session = TerminalSession::start("host:2022", idpasskey.id, &idpasskey.passkey,
                                         &InitialPayload::default(),
                                         et_client::DEFAULT_KEEPALIVE).await?;
session.send_terminal_info(24, 80, 0, 0).await?;
session.send_input(b"htop\n").await?;
```

## Tests

```sh
cargo test                       # unit + golden-wire + full-stack (Rust only)
cargo test --test cpp_interop -- --ignored   # against real C++ binaries
```

- **Golden wire tests** lock every message encoding and frame layout against
  hand-computed protobuf bytes (the upstream `.proto` files in `proto/` are
  the reference).
- **Full-stack tests** run client + etserver + etterminal in-process over
  real TCP/unix sockets with `/bin/sh` on a real PTY: echo round-trip,
  forced disconnect mid-`seq 1 20000` with **every line recovered via
  catch-up**, keepalive echo, `MISMATCHED_PROTOCOL`, `INVALID_KEY`.
- **Interop tests** (`--ignored`; auto-skip without the binaries, set
  `ET_CPP_PREFIX` to override `/opt/homebrew`) run against the actual C++
  binaries — verified against **brew et 7.0.0** (protocol version 6): Rust client ↔ C++ etserver + C++ etterminal (including kill /
  reconnect / catch-up), C++ etterminal registering with the Rust etserver,
  and the Rust etterminal registering with the C++ etserver. The fourth leg
  (C++ `et` client driving the Rust server) needs a local sshd and was
  verified manually; the command the C++ client runs over ssh is
  byte-identical to what `et_client::ssh::etterminal_command` produces.

## Not implemented (deliberately)

- **Port forwarding** (`-t`/`-r`): the packet types exist and etserver
  relays them as ciphertext (its job ends there), but the client-side and
  etterminal-side handlers are not written. The CLI rejects the flags
  loudly rather than half-working.
- **Jumphost** (`--jump` mode): refused by the CLI and etterminal. Upstream
  compatibility of the *terminal* path is unaffected.
- Windows. The unix leg and PTY layer are unix-only by design.
- Upstream's `et.cfg` INI file (flags cover `--port`/`--serverfifo`).
- Cosmetic divergences (documented in code): output rate limiting
  (1024 lines/s) and the Ctrl+C output-flush optimization are omitted; the
  PTY starts at 24x80 instead of 0x0 until the first resize arrives.
- **Deliberate hardening beyond upstream** (each with a code comment): a
  fresh client whose initial `ConnectRequest` answers `RETURNING_CLIENT`
  fails fast with a clear error instead of wedging ~60 s (a fresh client's
  nonce phase cannot resume a live stream); a reconnect answered
  `NEW_CLIENT` ends the session with `ServerStateLost` instead of upstream's
  silent infinite retry; the recover exchange is capped at 10 s (not 60) to
  bound how long a bogus reconnect stalls the victim's writes; the initial
  connect retries `INVALID_KEY` briefly while the freshly-launched
  etterminal is still registering (upstream hides the race behind ssh
  latency; a russh-driven handshake has none); the pty master is
  `FD_CLOEXEC` so session processes cannot touch terminal traffic.

Apache-2.0, matching upstream.
