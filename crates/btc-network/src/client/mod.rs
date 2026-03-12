//! Application-facing client helpers built on top of the lower-level session layer.
//!
//! This module is the boundary for code that wants a simple "connect to a peer and do
//! a workflow" API without owning Bitcoin message sequencing directly. It is intended
//! for app entrypoints such as the CLI and desktop bridge.
//!
//! Responsibilities:
//! - Resolve peer addresses and open TCP connections
//! - Construct a [`crate::session::Session`] over an established stream
//! - Expose UI/CLI-friendly summaries for shared workflows
//!
//! Non-responsibilities:
//! - Framing or message decoding
//! - Stateful protocol rules such as handshake ordering or ping/pong handling
//! - Frontend- or CLI-specific presentation logic

pub mod peer;
