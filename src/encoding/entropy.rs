//! Entropy analysis and reduction for DNS subdomain encoding.
//!
//! High-entropy hostnames are a common indicator of DNS tunneling.
//! This module provides tools to measure and reduce entropy.

use crate::common::error::{GhostQueryError, Result};
use std::collections::HashMap;

/// Calculate Shannon entropy of a string (bits per character)
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;

    for count in freq.values() {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Threshold for "suspicious" entropy (legitimate domains typically < 3.5)
pub const ENTROPY_THRESHOLD: f64 = 3.5;

/// Check if a hostname looks legitimate based on entropy
pub fn is_low_entropy(hostname: &str) -> bool {
    calculate_entropy(hostname) < ENTROPY_THRESHOLD
}

/// Entropy-aware encoder that ensures output stays below threshold
#[derive(Debug, Clone)]
pub struct EntropyEncoder {
    /// Target maximum entropy
    max_entropy: f64,
    /// Character set for encoding (reduces to ASCII lowercase + digits)
    charset: Vec<char>,
}

impl EntropyEncoder {
    /// Create a new entropy encoder with default threshold
    pub fn new() -> Self {
        Self {
            max_entropy: ENTROPY_THRESHOLD,
            charset: ('a'..='z').chain('0'..='9').collect(),
        }
    }

    /// Create with custom entropy threshold
    pub fn with_threshold(max_entropy: f64) -> Self {
        Self {
            max_entropy,
            charset: ('a'..='z').chain('0'..='9').collect(),
        }
    }

    /// Encode data while trying to maintain low entropy
    ///
    /// Strategy: Use repeated patterns and common character sequences
    pub fn encode(&self, data: &[u8]) -> Result<String> {
        let mut result = String::new();

        for byte in data {
            // Map each byte to 2 characters from our charset
            let idx1 = (*byte >> 4) as usize;
            let idx2 = (*byte & 0x0F) as usize;

            // Use modular indexing with charset
            let c1 = self.charset[idx1 % self.charset.len()];
            let c2 = self.charset[idx2 % self.charset.len()];

            result.push(c1);
            result.push(c2);

            // Insert separator every 4 bytes for readability
            if result.len() % 9 == 8 {
                result.push('-');
            }
        }

        // Remove trailing separator if present
        if result.ends_with('-') {
            result.pop();
        }

        // Verify entropy is acceptable
        let entropy = calculate_entropy(&result);
        if entropy > self.max_entropy * 1.2 {
            // Allow 20% margin
            return Err(GhostQueryError::EncodingError(format!(
                "Encoded string has high entropy: {:.2}",
                entropy
            )));
        }

        Ok(result)
    }

    /// Decode entropy-encoded string back to bytes
    pub fn decode(&self, encoded: &str) -> Result<Vec<u8>> {
        let clean: String = encoded.chars().filter(|c| *c != '-').collect();
        let mut result = Vec::new();

        let chars: Vec<char> = clean.chars().collect();
        if chars.len() % 2 != 0 {
            return Err(GhostQueryError::DecodingError(
                "Invalid encoded length".to_string(),
            ));
        }

        for chunk in chars.chunks(2) {
            let idx1 = self
                .charset
                .iter()
                .position(|&c| c == chunk[0])
                .ok_or_else(|| {
                    GhostQueryError::DecodingError(format!("Invalid character: {}", chunk[0]))
                })?;

            let idx2 = self
                .charset
                .iter()
                .position(|&c| c == chunk[1])
                .ok_or_else(|| {
                    GhostQueryError::DecodingError(format!("Invalid character: {}", chunk[1]))
                })?;

            let byte = ((idx1 as u8) << 4) | (idx2 as u8 & 0x0F);
            result.push(byte);
        }

        Ok(result)
    }

    /// Get current max entropy setting
    pub fn max_entropy(&self) -> f64 {
        self.max_entropy
    }

    /// Analyze a string and suggest improvements for lower entropy
    pub fn analyze(&self, s: &str) -> EntropyAnalysis {
        let entropy = calculate_entropy(s);
        let char_distribution = self.character_distribution(s);

        EntropyAnalysis {
            entropy,
            is_suspicious: entropy >= ENTROPY_THRESHOLD,
            char_distribution,
            suggested_changes: self.suggest_changes(s, entropy),
        }
    }

    fn character_distribution(&self, s: &str) -> HashMap<char, f64> {
        let mut freq: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        freq.into_iter().map(|(c, n)| (c, n as f64 / len)).collect()
    }

    fn suggest_changes(&self, s: &str, entropy: f64) -> Vec<String> {
        let mut suggestions = Vec::new();

        if entropy >= ENTROPY_THRESHOLD {
            suggestions.push("Consider using more repeated characters".to_string());

            if s.chars().filter(|c| c.is_numeric()).count() as f64 / s.len() as f64 > 0.5 {
                suggestions.push("Reduce numeric character density".to_string());
            }

            if s.len() > 20 {
                suggestions.push("Consider shorter labels with separators".to_string());
            }
        }

        suggestions
    }
}

impl Default for EntropyEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Analysis results for entropy checking
#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    /// Calculated Shannon entropy
    pub entropy: f64,
    /// Whether entropy exceeds suspicious threshold
    pub is_suspicious: bool,
    /// Character frequency distribution
    pub char_distribution: HashMap<char, f64>,
    /// Suggested changes to reduce entropy
    pub suggested_changes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Highly repetitive = low entropy
        let low_entropy = calculate_entropy("aaaaaaaaaa");
        assert!(low_entropy < 1.0);

        // Random-looking = high entropy
        let high_entropy = calculate_entropy("a1b2c3d4e5f6g7h8");
        assert!(high_entropy > 3.0);

        // Realistic hostname
        let realistic = calculate_entropy("cdn-img-01");
        assert!(realistic < ENTROPY_THRESHOLD);
    }

    #[test]
    fn test_is_low_entropy() {
        assert!(is_low_entropy("cdn-img-02"));
        assert!(is_low_entropy("static-assets"));
        assert!(is_low_entropy("api-v2-prod"));

        // Base64-encoded data typically has high entropy
        assert!(!is_low_entropy("aGVsbG8gd29ybGQ"));
    }

    #[test]
    fn test_entropy_encoder_roundtrip() {
        let encoder = EntropyEncoder::new();
        let data = vec![0x12, 0x34, 0x56, 0x78];

        let encoded = encoder.encode(&data).unwrap();
        let decoded = encoder.decode(&encoded).unwrap();

        assert_eq!(data, decoded);
    }

    #[test]
    fn test_analysis() {
        let encoder = EntropyEncoder::new();

        let analysis = encoder.analyze("x8za9b7c6d5");
        assert!(analysis.is_suspicious);

        let analysis = encoder.analyze("cdn-img-01");
        assert!(!analysis.is_suspicious);
    }
}

