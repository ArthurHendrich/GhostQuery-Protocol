//! Base32 encoding for DNS-safe binary data representation.
//!
//! Uses RFC 4648 Base32 alphabet (A-Z, 2-7) which is case-insensitive
//! and DNS-safe (no special characters).

use crate::common::error::{GhostQueryError, Result};
use crate::encoding::Encoder;

/// Base32 encoder using RFC 4648 alphabet
#[derive(Debug, Clone)]
pub struct Base32Encoder {
    /// Whether to include padding
    padding: bool,
}

impl Base32Encoder {
    /// Create a new Base32 encoder (no padding by default for shorter labels)
    pub fn new() -> Self {
        Self { padding: false }
    }

    /// Create a new Base32 encoder with padding
    pub fn with_padding() -> Self {
        Self { padding: true }
    }
}

impl Default for Base32Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for Base32Encoder {
    fn encode(&self, data: &[u8]) -> Result<String> {
        let encoded = if self.padding {
            base32::encode(base32::Alphabet::RFC4648 { padding: true }, data)
        } else {
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, data)
        };

        // Convert to lowercase for DNS compatibility
        Ok(encoded.to_lowercase())
    }

    fn decode(&self, encoded: &str) -> Result<Vec<u8>> {
        // Base32 decode is case-insensitive
        let uppercase = encoded.to_uppercase();

        base32::decode(base32::Alphabet::RFC4648 { padding: self.padding }, &uppercase).ok_or_else(
            || {
                GhostQueryError::DecodingError(format!(
                    "Invalid base32 encoding: {}",
                    encoded
                ))
            },
        )
    }
}

/// Encode a session ID and sequence number into a subdomain
pub fn encode_address(session_id: &[u8; 8], sequence: u32) -> String {
    let encoder = Base32Encoder::new();

    let session_encoded = encoder.encode(session_id).unwrap_or_default();
    let seq_hex = format!("{:06x}", sequence);

    format!("{}.seq{}", session_encoded, seq_hex)
}

/// Decode a subdomain back to session ID and sequence number
pub fn decode_address(subdomain: &str) -> Result<([u8; 8], u32)> {
    let parts: Vec<&str> = subdomain.split('.').collect();

    if parts.len() < 2 {
        return Err(GhostQueryError::DecodingError(
            "Invalid subdomain format".to_string(),
        ));
    }

    let encoder = Base32Encoder::new();

    // Decode session ID
    let session_bytes = encoder.decode(parts[0])?;
    if session_bytes.len() != 8 {
        return Err(GhostQueryError::DecodingError(
            "Invalid session ID length".to_string(),
        ));
    }
    let mut session_id = [0u8; 8];
    session_id.copy_from_slice(&session_bytes);

    // Parse sequence number (expected format: "seqXXXXXX")
    let seq_part = parts[1];
    if !seq_part.starts_with("seq") {
        return Err(GhostQueryError::DecodingError(
            "Invalid sequence format".to_string(),
        ));
    }

    let seq_hex = &seq_part[3..];
    let sequence =
        u32::from_str_radix(seq_hex, 16).map_err(|e| GhostQueryError::DecodingError(e.to_string()))?;

    Ok((session_id, sequence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let encoder = Base32Encoder::new();
        let data = b"Hello, World!";

        let encoded = encoder.encode(data).unwrap();
        let decoded = encoder.decode(&encoded).unwrap();

        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_encode_produces_lowercase() {
        let encoder = Base32Encoder::new();
        let data = b"test";

        let encoded = encoder.encode(data).unwrap();
        assert_eq!(encoded, encoded.to_lowercase());
    }

    #[test]
    fn test_address_encoding() {
        let session_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let sequence = 100;

        let subdomain = encode_address(&session_id, sequence);
        let (decoded_session, decoded_seq) = decode_address(&subdomain).unwrap();

        assert_eq!(session_id, decoded_session);
        assert_eq!(sequence, decoded_seq);
    }

    #[test]
    fn test_dns_safe_output() {
        let encoder = Base32Encoder::new();

        // Test with various binary data
        for i in 0..=255u8 {
            let data = vec![i];
            let encoded = encoder.encode(&data).unwrap();

            // Verify all characters are DNS-safe (a-z, 2-7)
            for c in encoded.chars() {
                assert!(
                    c.is_ascii_lowercase() || ('2'..='7').contains(&c),
                    "Invalid character: {}",
                    c
                );
            }
        }
    }
}

