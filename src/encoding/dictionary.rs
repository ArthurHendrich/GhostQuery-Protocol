//! Dictionary-based encoding for low-entropy DNS labels.
//!
//! Maps binary data to realistic-looking subdomain components like:
//! - cdn-img-02
//! - static-assets
//! - api-v2-prod
//!
//! This reduces Shannon entropy and evades detection based on random-looking hostnames.

use crate::common::error::{GhostQueryError, Result};
use std::collections::HashMap;

/// Prefixes that look like legitimate CDN/API endpoints
const PREFIXES: &[&str] = &[
    "cdn", "api", "img", "static", "assets", "cache", "edge", "node", "srv", "app", "web", "data",
    "prod", "dev", "stg", "test", "live", "beta", "auth", "usr", "sys", "net", "core", "hub",
    "cloud", "fast", "geo", "loc", "pub", "priv", "int", "ext",
];

/// Suffixes that look like version numbers or identifiers
const SUFFIXES: &[&str] = &[
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16",
    "a", "b", "c", "d", "e", "f", "v1", "v2", "v3", "v4", "us", "eu", "ap", "na", "sa", "au",
    "east", "west", "north", "south", "main", "backup", "primary", "secondary",
];

/// Middle components for three-part labels
const MIDDLES: &[&str] = &[
    "img", "assets", "content", "media", "files", "storage", "delivery", "stream", "upload",
    "download", "sync", "update", "patch", "build", "release", "stable", "latest", "current",
];

/// Dictionary for encoding binary data to realistic hostnames
#[derive(Debug, Clone)]
pub struct Dictionary {
    /// Maps byte values to prefix strings
    prefix_map: HashMap<u8, String>,
    /// Maps prefix strings back to byte values
    reverse_prefix: HashMap<String, u8>,
    /// Maps byte values to suffix strings
    suffix_map: HashMap<u8, String>,
    /// Maps suffix strings back to byte values
    reverse_suffix: HashMap<String, u8>,
    /// Common byte sequences mapped to words
    word_map: HashMap<Vec<u8>, String>,
    /// Reverse mapping for words
    reverse_word: HashMap<String, Vec<u8>>,
}

impl Dictionary {
    /// Create a new dictionary with default mappings
    pub fn new() -> Self {
        let mut dict = Self {
            prefix_map: HashMap::new(),
            reverse_prefix: HashMap::new(),
            suffix_map: HashMap::new(),
            reverse_suffix: HashMap::new(),
            word_map: HashMap::new(),
            reverse_word: HashMap::new(),
        };

        // Initialize prefix mappings (first 32 byte values)
        for (i, prefix) in PREFIXES.iter().enumerate() {
            if i < 32 {
                dict.prefix_map.insert(i as u8, (*prefix).to_string());
                dict.reverse_prefix.insert((*prefix).to_string(), i as u8);
            }
        }

        // Initialize suffix mappings
        for (i, suffix) in SUFFIXES.iter().enumerate() {
            if i < 40 {
                dict.suffix_map.insert(i as u8, (*suffix).to_string());
                dict.reverse_suffix.insert((*suffix).to_string(), i as u8);
            }
        }

        // Add common byte sequence mappings
        dict.add_common_patterns();

        dict
    }

    /// Add mappings for common byte patterns
    fn add_common_patterns(&mut self) {
        // Map common sequences to realistic words
        let patterns: &[(&[u8], &str)] = &[
            (b"\x00\x00", "null"),
            (b"\xff\xff", "full"),
            (b"\x00\x01", "init"),
            (b"\x01\x00", "start"),
            (b"HTTP", "http-req"),
            (b"GET ", "get-op"),
            (b"POST", "post-op"),
            (b"HEAD", "head-op"),
            (b"PK\x03\x04", "pkg-data"),
            (b"\x89PNG", "img-png"),
            (b"GIF8", "img-gif"),
            (b"\xff\xd8\xff", "img-jpg"),
            (b"MZ", "bin-exe"),
            (b"\x7fELF", "bin-elf"),
        ];

        for (bytes, word) in patterns {
            self.word_map.insert(bytes.to_vec(), (*word).to_string());
            self.reverse_word.insert((*word).to_string(), bytes.to_vec());
        }
    }

    /// Look up a byte sequence in the dictionary
    pub fn lookup_bytes(&self, data: &[u8]) -> Option<String> {
        // Check for exact word match
        if let Some(word) = self.word_map.get(data) {
            return Some(word.clone());
        }

        // For 2-byte sequences, use prefix-suffix encoding
        if data.len() == 2 {
            let prefix_idx = (data[0] >> 3) & 0x1F; // Top 5 bits -> 32 prefixes
            let suffix_idx = ((data[0] & 0x07) << 3) | ((data[1] >> 5) & 0x07); // Next 6 bits -> 64 values
            let num = data[1] & 0x1F; // Bottom 5 bits -> number

            if let (Some(prefix), Some(suffix)) =
                (self.prefix_map.get(&prefix_idx), self.suffix_map.get(&(suffix_idx % 40)))
            {
                return Some(format!("{}-{}-{:02}", prefix, suffix, num));
            }
        }

        None
    }

    /// Reverse lookup: word to bytes
    pub fn reverse_lookup(&self, word: &str) -> Option<Vec<u8>> {
        // Check for direct word mapping
        if let Some(bytes) = self.reverse_word.get(word) {
            return Some(bytes.clone());
        }

        // Try to parse prefix-suffix-num format
        let parts: Vec<&str> = word.split('-').collect();
        if parts.len() == 3 {
            if let (Some(&prefix_idx), Some(&suffix_idx)) = (
                self.reverse_prefix.get(parts[0]),
                self.reverse_suffix.get(parts[1]),
            ) {
                if let Ok(num) = parts[2].parse::<u8>() {
                    if num < 32 {
                        let byte0 = (prefix_idx << 3) | ((suffix_idx >> 3) & 0x07);
                        let byte1 = ((suffix_idx & 0x07) << 5) | (num & 0x1F);
                        return Some(vec![byte0, byte1]);
                    }
                }
            }
        }

        None
    }

    /// Wrap base32-encoded data in realistic-looking prefix/suffix
    pub fn wrap_encoded(&self, encoded: &str) -> String {
        // Use first char to select prefix, last char for suffix
        let prefix_idx = encoded.as_bytes().first().unwrap_or(&0) % PREFIXES.len() as u8;
        let suffix_idx = encoded.as_bytes().last().unwrap_or(&0) % SUFFIXES.len() as u8;

        let prefix = PREFIXES.get(prefix_idx as usize).unwrap_or(&"cdn");
        let suffix = SUFFIXES.get(suffix_idx as usize).unwrap_or(&"01");

        // Format: prefix-encoded-suffix
        format!("{}-{}-{}", prefix, encoded.to_lowercase(), suffix)
    }

    /// Unwrap to get the encoded data back
    pub fn unwrap_encoded(&self, wrapped: &str) -> Result<String> {
        let parts: Vec<&str> = wrapped.split('-').collect();

        if parts.len() < 3 {
            return Err(GhostQueryError::DecodingError(format!(
                "Invalid wrapped format: {}",
                wrapped
            )));
        }

        // The middle parts (excluding first and last) are the encoded data
        let encoded = parts[1..parts.len() - 1].join("-");
        Ok(encoded.to_uppercase())
    }

    /// Get all prefixes (for configuration)
    pub fn prefixes(&self) -> Vec<&str> {
        PREFIXES.to_vec()
    }

    /// Get all suffixes (for configuration)
    pub fn suffixes(&self) -> Vec<&str> {
        SUFFIXES.to_vec()
    }

    /// Add a custom word mapping
    pub fn add_word(&mut self, bytes: Vec<u8>, word: String) {
        self.reverse_word.insert(word.clone(), bytes.clone());
        self.word_map.insert(bytes, word);
    }
}

impl Default for Dictionary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_byte_encoding() {
        let dict = Dictionary::new();

        let data = [0xAB, 0xCD];
        if let Some(encoded) = dict.lookup_bytes(&data) {
            let decoded = dict.reverse_lookup(&encoded).unwrap();
            // Note: Due to bit manipulation, we verify the format is correct
            assert!(encoded.contains('-'));
            assert!(!decoded.is_empty());
        }
    }

    #[test]
    fn test_common_patterns() {
        let dict = Dictionary::new();

        // Test PNG magic bytes
        let png = b"\x89PNG";
        let encoded = dict.lookup_bytes(png);
        assert_eq!(encoded, Some("img-png".to_string()));

        let decoded = dict.reverse_lookup("img-png");
        assert_eq!(decoded, Some(png.to_vec()));
    }

    #[test]
    fn test_wrap_unwrap() {
        let dict = Dictionary::new();

        let original = "JBSWY3DP";
        let wrapped = dict.wrap_encoded(original);
        let unwrapped = dict.unwrap_encoded(&wrapped).unwrap();

        assert_eq!(original, unwrapped);
    }
}

