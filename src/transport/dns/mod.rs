//! DNS transport layer for data exfiltration.
//!
//! Implements the DNS hierarchy as a shared bus:
//! - Upstream: Data encoded in QNAME (subdomain)
//! - Downstream: Commands encoded in RDATA (A/AAAA/CNAME/MX/TXT)

pub mod client;
pub mod query;
pub mod response;
pub mod server;

pub use client::DnsClient;
pub use query::DnsQuery;
pub use response::DnsResponse;
pub use server::DnsServer;

