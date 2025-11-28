//! Transport layer for GhostQuery protocol.
//!
//! Handles DNS queries/responses and ICMP side-channel signaling.

pub mod dns;
pub mod icmp;

pub use dns::{DnsClient, DnsServer, DnsQuery, DnsResponse};
pub use icmp::{IcmpClient, IcmpServer};

