//! ICMP side-channel for signaling.
//!
//! Uses ICMP echo requests as "hardware interrupts" to:
//! - Open/close transmission windows
//! - Signal session start/end
//! - Coordinate timing

pub mod client;
pub mod server;

pub use client::IcmpClient;
pub use server::IcmpServer;

use crate::common::constants::ICMP_MAGIC;
use crate::common::types::IcmpSignal;

/// ICMP packet structure for signaling
#[derive(Debug, Clone)]
pub struct IcmpPacket {
    /// Signal type
    pub signal: IcmpSignal,
    /// Session ID (in payload)
    pub session_id: Option<[u8; 8]>,
    /// Additional data
    pub data: Vec<u8>,
}

impl IcmpPacket {
    /// Create a new ICMP packet
    pub fn new(signal: IcmpSignal) -> Self {
        Self {
            signal,
            session_id: None,
            data: Vec::new(),
        }
    }

    /// Set session ID
    pub fn with_session(mut self, session_id: [u8; 8]) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set additional data
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Encode to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Magic bytes for identification
        bytes.extend_from_slice(&ICMP_MAGIC);

        // Signal as 2-byte sequence
        let seq = self.signal.to_sequence();
        bytes.extend_from_slice(&seq.to_be_bytes());

        // Session ID if present
        if let Some(session_id) = &self.session_id {
            bytes.push(1); // Flag: has session
            bytes.extend_from_slice(session_id);
        } else {
            bytes.push(0); // Flag: no session
        }

        // Additional data
        bytes.extend_from_slice(&self.data);

        bytes
    }

    /// Decode from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 7 {
            return None;
        }

        // Check magic
        if bytes[0..4] != ICMP_MAGIC {
            return None;
        }

        // Parse sequence/signal
        let seq = u16::from_be_bytes([bytes[4], bytes[5]]);
        let signal = IcmpSignal::from_sequence(seq)?;

        // Check for session ID
        let has_session = bytes[6] == 1;
        let session_id = if has_session && bytes.len() >= 15 {
            let mut id = [0u8; 8];
            id.copy_from_slice(&bytes[7..15]);
            Some(id)
        } else {
            None
        };

        // Get additional data
        let data_start = if has_session { 15 } else { 7 };
        let data = if bytes.len() > data_start {
            bytes[data_start..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            signal,
            session_id,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encode_decode() {
        let session_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let packet = IcmpPacket::new(IcmpSignal::WindowOpen)
            .with_session(session_id)
            .with_data(vec![0xAB, 0xCD]);

        let bytes = packet.to_bytes();
        let decoded = IcmpPacket::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.signal, IcmpSignal::WindowOpen);
        assert_eq!(decoded.session_id, Some(session_id));
        assert_eq!(decoded.data, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_packet_without_session() {
        let packet = IcmpPacket::new(IcmpSignal::WindowClose);

        let bytes = packet.to_bytes();
        let decoded = IcmpPacket::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.signal, IcmpSignal::WindowClose);
        assert_eq!(decoded.session_id, None);
    }

    #[test]
    fn test_invalid_magic() {
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00];
        assert!(IcmpPacket::from_bytes(&bytes).is_none());
    }
}

