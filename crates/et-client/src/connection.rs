//! Client connection — implemented in [`et_proto::client`] (shared with the
//! jump relay, which runs the same resilient client against the destination
//! etserver); re-exported here for the et-client API surface.

pub use et_proto::client::{ClientDeadReason, EtClient, Event};
