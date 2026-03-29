//! Bitcoin P2P wire protocol primitives.
//!
//! This module provides low-level utilities to read and decode
//! Bitcoin P2P messages directly from a TCP stream.
//!
//! It implements:
//! - Parsing of the 24-byte Bitcoin message header
//! - Extraction of command name and payload
//! - Raw message reading from `std::net::TcpStream`
//!
//! Higher-level message decoding is handled by [`Message`],
//! which converts raw payloads into strongly typed variants.
//!
//! Protocol reference:
//! https://developer.bitcoin.org/reference/p2p_networking.html
pub mod codec;

pub mod decode;
pub mod message;
pub mod payload;

pub mod constants;

pub use codec::{read_message, read_message_async, send_message, send_message_async};
pub use message::{Command, Message, RawMessage};
pub use payload::*;
