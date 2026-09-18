//! Committed protobuf code, generated from the upstream `proto/` files by
//! [`et-proto-gen`](../../../tools/et-proto-gen) (protoc + buffa-build).
//! Regenerate with `cargo run -p et-proto-gen` when `proto/` changes; the
//! workspace builds without protoc or this tool.
//!
//! The upstream `.proto` files are the single source of truth for the wire
//! format — this directory must never be edited by hand.

// The generator emits hand-rolled `impl Default` for enums (first proto
// value); silence the lints against generated code here, never in et.rs.
#[allow(clippy::derivable_impls, clippy::all)]
pub mod et;
