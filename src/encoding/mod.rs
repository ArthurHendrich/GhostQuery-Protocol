//! Encoding module for low-entropy DNS subdomain generation.
//!
//! This module implements dictionary-based encoding to reduce Shannon entropy
//! and make DNS queries resemble legitimate hostnames (e.g., cdn-img-02.example.com).

pub mod base32;
pub mod dictionary;
pub mod entropy;

pub use base32::Base32Encoder;
pub use dictionary::Dictionary;
pub use entropy::EntropyEncoder;

use crate::common::error::Result;

/// Trait for encoding binary data into DNS-safe strings
pub trait Encoder {
    /// Encode binary data into a DNS-safe string
    fn encode(&self, data: &[u8]) -> Result<String>;

    /// Decode a DNS-safe string back to binary data
    fn decode(&self, encoded: &str) -> Result<Vec<u8>>;
}

/// Combined encoder that uses dictionary + base32 for optimal stealth
pub struct GhostEncoder {
    dictionary: Dictionary,
    base32: Base32Encoder,
}

impl GhostEncoder {
    pub fn new() -> Self {
        Self {
            dictionary: Dictionary::default(),
            base32: Base32Encoder::new(),
        }
    }

    pub fn with_dictionary(dictionary: Dictionary) -> Self {
        Self {
            dictionary,
            base32: Base32Encoder::new(),
        }
    }

    /// Encode a chunk of data into a DNS subdomain label
    pub fn encode_chunk(&self, data: &[u8]) -> Result<String> {
        // First try dictionary-based encoding for common patterns
        if let Some(word) = self.dictionary.lookup_bytes(data) {
            return Ok(word);
        }

        // Fall back to base32 with dictionary wrapping
        let base32_encoded = self.base32.encode(data)?;

        // Wrap in realistic-looking prefix/suffix
        let wrapped = self.dictionary.wrap_encoded(&base32_encoded);

        Ok(wrapped)
    }

    /// Decode a DNS subdomain label back to binary data
    pub fn decode_chunk(&self, encoded: &str) -> Result<Vec<u8>> {
        // First check if it's a direct dictionary entry
        if let Some(bytes) = self.dictionary.reverse_lookup(encoded) {
            return Ok(bytes);
        }

        // Try to unwrap and decode base32
        let unwrapped = self.dictionary.unwrap_encoded(encoded)?;
        self.base32.decode(&unwrapped)
    }
}

impl Default for GhostEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let encoder = GhostEncoder::new();
        let data = b"Hello, World!";

        let encoded = encoder.encode_chunk(data).unwrap();
        let decoded = encoder.decode_chunk(&encoded).unwrap();

        assert_eq!(data.to_vec(), decoded);
    }
}

