//! Hashing utilities for file integrity verification.

use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

use crate::common::constants::FILE_BUFFER_SIZE;
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::FileHash;

/// Hasher for computing file hashes (SHA-256)
#[derive(Debug, Clone, Default)]
pub struct Hasher {
    hasher: Sha256,
}

impl Hasher {
    /// Create a new hasher
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Update hasher with data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> FileHash {
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        FileHash::new(hash)
    }

    /// Hash data in one shot
    pub fn hash(data: &[u8]) -> FileHash {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash a file by path
    pub fn hash_file<R: Read>(reader: &mut R) -> Result<FileHash> {
        let mut hasher = Self::new();
        let mut buffer = [0u8; FILE_BUFFER_SIZE];

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize())
    }

    /// Hash a file and reset reader position
    pub fn hash_file_seekable<R: Read + Seek>(reader: &mut R) -> Result<FileHash> {
        let original_pos = reader
            .stream_position()
            .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

        let hash = Self::hash_file(reader)?;

        reader
            .seek(SeekFrom::Start(original_pos))
            .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

        Ok(hash)
    }
}

/// Verify that a reconstructed file matches the expected hash
pub fn verify_hash(data: &[u8], expected: &FileHash) -> bool {
    let actual = Hasher::hash(data);
    actual.as_bytes() == expected.as_bytes()
}

/// Incremental hash verifier for streaming verification
pub struct IncrementalVerifier {
    hasher: Hasher,
    expected: FileHash,
}

impl IncrementalVerifier {
    /// Create a new incremental verifier
    pub fn new(expected: FileHash) -> Self {
        Self {
            hasher: Hasher::new(),
            expected,
        }
    }

    /// Add data to the verification
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and verify
    pub fn verify(self) -> bool {
        let actual = self.hasher.finalize();
        actual.as_bytes() == self.expected.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_hash_data() {
        let data = b"Hello, World!";
        let hash = Hasher::hash(data);

        // SHA-256 of "Hello, World!" is known
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"Test data for hashing";

        let hash1 = Hasher::hash(data);
        let hash2 = Hasher::hash(data);

        assert_eq!(hash1.as_bytes(), hash2.as_bytes());
    }

    #[test]
    fn test_incremental_hash() {
        let data = b"Hello, World!";
        let expected = Hasher::hash(data);

        let mut hasher = Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let actual = hasher.finalize();

        assert_eq!(expected.as_bytes(), actual.as_bytes());
    }

    #[test]
    fn test_verify_hash() {
        let data = b"Test verification data";
        let hash = Hasher::hash(data);

        assert!(verify_hash(data, &hash));
        assert!(!verify_hash(b"Wrong data", &hash));
    }

    #[test]
    fn test_hash_file() {
        let data = b"File content for hashing";
        let mut cursor = Cursor::new(data);

        let file_hash = Hasher::hash_file(&mut cursor).unwrap();
        let direct_hash = Hasher::hash(data);

        assert_eq!(file_hash.as_bytes(), direct_hash.as_bytes());
    }

    #[test]
    fn test_incremental_verifier() {
        let data = b"Streaming verification test";
        let expected = Hasher::hash(data);

        let mut verifier = IncrementalVerifier::new(expected);
        verifier.update(b"Streaming ");
        verifier.update(b"verification ");
        verifier.update(b"test");

        assert!(verifier.verify());
    }
}

