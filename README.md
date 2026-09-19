# et — EternalTerminal client library (Rust, wire-compatible)

A Rust client library for [EternalTerminal](https://github.com/MisterTea/EternalTerminal)
(protocol version **6**), built for [conch](../conch): a remote shell whose
session **survives disconnects and IP changes** without interrupting the
program running inside it. Wire-compatible with the upstream C++
`etserver` / `etterminal` binaries — verified by automated interop tests
against the real C++ binaries (see *Tests* below).

```
crates/
  et-proto    wire layer: packets, framing, XSalsa20-Poly1305 crypto,
              generated protobuf types, and the shared backed-connection
              state machine (backup buffer, sequence numbers, recover
              exchange)
  et-client   the client library (TerminalSession)
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

Library-only — there is no shipped binary. Embedders call
[`TerminalSession::start`](crates/et-client/src/session.rs) directly (doc
example in [`crates/et-client/src/lib.rs`](crates/et-client/src/lib.rs),
embedder surface in *For conch* below). The interop tests are the reference
driver against real servers; deploy upstream C++ `etserver`/`etterminal`
(`brew install et`, distro packages) or any wire-compatible server.

## For conch

The client library is the embeddable surface: conch will embed it as a
sibling path dep (the `mosh` pattern) and expose it over UniFFI from
conch-core:

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
  (`buffa`, `crypto_secretbox`), committed `Cargo.lock`, `thiserror`.

```rust
let idpasskey = et_client::ssh::generate_id_passkey();
let command = et_client::ssh::etterminal_command(&idpasskey.id, &idpasskey.passkey,
                                                 "xterm-256color", &Default::default());
// run `command` over russh, scrape ssh::parse_idpasskey_output(&stdout)…
let mut session = TerminalSession::start("host:2022".into(), idpasskey.id, &idpasskey.passkey,
                                         &InitialPayload::default(),
                                         et_client::DEFAULT_KEEPALIVE).await?;
session.send_terminal_info(24, 80, 0, 0).await?;
session.send_input(b"htop\n").await?;
```

## Tests

```sh
cargo test                       # unit + golden-wire
cargo test --test cpp_interop -- --ignored   # against real C++ binaries
scripts/docker-test.sh           # the whole thing on Linux in a container
```

`scripts/docker-test.sh` builds an Ubuntu 22.04 image with the upstream C++
binaries (et 7.0.0 from the `jgmath2000/et` PPA — same protocol, same
version family as the macOS verification) and runs the full suite, the C++
interop tests, and clippy inside it, validating the Linux build.

- **Golden wire tests** lock every message encoding and frame layout against
  hand-computed protobuf bytes (the upstream `.proto` files in `proto/` are
  the reference).
- **Interop tests** (`--ignored`; they need the C++ binaries and panic
  loudly without them — set `ET_CPP_PREFIX` to the install prefix, default
  `/opt/homebrew`) run against the actual C++
  binaries — verified against **brew et 7.0.0** (protocol version 6):
  Rust client ↔ C++ etserver + C++ etterminal, including kill /
  reconnect / catch-up (every line of a mid-stream `seq 1 5000` recovered)
  and forward + reverse tunnels, plus the all-C++ jumphost chain
  (C++ etserver → C++ `etterminal --jump` → C++ etserver → C++ etterminal).
  With the Rust server removed, these are also the client's behavioural
  net; `cargo test` alone covers encodings (golden) and pure functions.

## Port forwarding

Forward and reverse TCP tunnels are implemented in the library:
[`parse_ranges`](crates/et-proto/src/forward.rs) accepts `18000:8000`,
range syntax `a-b:c-d`, comma lists, and ssh-style
`bind:port:host:hostport` (like upstream `TunnelUtils`); the client passes
sources to `TerminalSession::start_port_forwarding`, and reverse sources
ride the `INITIAL_PAYLOAD`. The engine lives in `et_proto::forward` and is
role-symmetric: sources bind locally and emit `DESTINATION_REQUEST`s;
destinations connect `::1` then `127.0.0.1` like upstream (the destination
*name* is ignored for TCP). Unix-socket forwarding (`ENV:/path`, SSH agent)
is not supported — the parser accepts those forms but rejects them with a
clear error. Interop tests cover both directions against the C++ etserver.

## Jumphost

The library implements the upstream jump topology:

```
client → jumphost etserver:2022 → etterminal --jump → destination etserver → etterminal(PTY)
```

The embedder launches the destination etterminal first (its handshake —
over `ssh -J jump`, conch's russh, anything — yields the credentials both
legs share), then the jump etterminal with `--jump --dsthost --dstport`;
the client then TCP-connects to the **jumphost** etserver with
`jumphost=true` in its `INITIAL_PAYLOAD`. The jumphost etserver hands the
payload to its jump etterminal as `JUMPHOST_INIT`, which opens a resilient
client connection to the destination etserver and relays packets hop by hop
(each leg decrypts and re-encrypts; the destination etserver owns the
terminal protocol and the keepalive echoes). Port forwarding works through
the chain — PF frames relay to the destination etserver, which owns them —
so tunnels combine with jumphost mode. The all-C++ interop test exercises
exactly this chain.

## Not implemented (deliberately)

- **Unix-socket forwarding** (`ENV:/path`, SSH agent): parsed like upstream,
  rejected with a clear error; TCP port forwarding is fully supported.
- **Client-side hardening beyond upstream** (each with a code comment): a
  fresh client whose initial `ConnectRequest` answers `RETURNING_CLIENT`
  fails fast with a clear error instead of wedging ~60 s (a fresh client's
  nonce phase cannot resume a live stream); a reconnect answered
  `NEW_CLIENT` ends the session with `ServerStateLost` instead of upstream's
  silent infinite retry; the recover exchange is capped at 10 s (not 60) to
  bound how long a bogus reconnect stalls the victim's writes; the initial
  connect retries `INVALID_KEY` briefly while the freshly-launched
  etterminal is still registering (upstream hides the race behind ssh
  latency; a russh-driven handshake has none).

Apache-2.0, matching upstream.
