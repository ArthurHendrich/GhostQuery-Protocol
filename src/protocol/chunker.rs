//! File chunking for DNS exfiltration.
//!
//! Splits files into fixed-size chunks suitable for encoding
//! into DNS subdomain labels.

use std::io::{Read, Seek, SeekFrom};

use crate::common::constants::{DEFAULT_CHUNK_SIZE, MAX_FILE_SIZE};
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{Chunk, ChunkId, FileHash};
use crate::crypto::cipher::AesGcmCipher;
use crate::crypto::hash::Hasher;

/// File chunker for splitting files into DNS-transmittable pieces
pub struct FileChunker {
    /// Chunk size in bytes
    chunk_size: usize,
    /// Optional cipher for encryption
    cipher: Option<AesGcmCipher>,
    /// Session ID for encryption context
    session_id: Option<[u8; 8]>,
}

impl FileChunker {
    /// Create a new chunker with default settings
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            cipher: None,
            session_id: None,
        }
    }

    /// Create with custom chunk size
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            cipher: None,
            session_id: None,
        }
    }

    /// Set encryption cipher and session ID
    pub fn with_encryption(mut self, cipher: AesGcmCipher, session_id: [u8; 8]) -> Self {
        self.cipher = Some(cipher);
        self.session_id = Some(session_id);
        self
    }

    /// Calculate number of chunks for a given file size
    pub fn calculate_chunks(&self, file_size: u64) -> u32 {
        ((file_size + self.chunk_size as u64 - 1) / self.chunk_size as u64) as u32
    }

    /// Chunk a file from a reader
    pub fn chunk_file<R: Read + Seek>(&self, reader: &mut R) -> Result<ChunkedFile> {
        // Get file size
        let file_size = reader
            .seek(SeekFrom::End(0))
            .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

        if file_size > MAX_FILE_SIZE {
            return Err(GhostQueryError::FileTooLarge {
                size: file_size,
                max: MAX_FILE_SIZE,
            });
        }

        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

        // Calculate file hash
        let file_hash = Hasher::hash_file_seekable(reader)?;

        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

        // Read and chunk the file
        let mut chunks = Vec::new();
        let mut buffer = vec![0u8; self.chunk_size];
        let mut chunk_id = 0u32;

        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?;

            if bytes_read == 0 {
                break;
            }

            let is_final = reader
                .seek(SeekFrom::Current(0))
                .map_err(|e| GhostQueryError::FileReadError(e.to_string()))?
                == file_size;

            let data = &buffer[..bytes_read];

            // Encrypt if cipher is set
            let chunk_data = if let (Some(cipher), Some(session_id)) = (&self.cipher, &self.session_id)
            {
                crate::crypto::cipher::encrypt_for_session(cipher, session_id, chunk_id, data)?
            } else {
                data.to_vec()
            };

            chunks.push(Chunk::new(ChunkId::new(chunk_id), chunk_data, is_final));
            chunk_id += 1;
        }

        // Mark last chunk as final if not empty
        if let Some(last) = chunks.last_mut() {
            last.is_final = true;
        }

        Ok(ChunkedFile {
            chunks,
            file_hash,
            file_size,
            chunk_size: self.chunk_size,
        })
    }

    /// Chunk data from a byte slice
    pub fn chunk_data(&self, data: &[u8]) -> Result<ChunkedFile> {
        let file_size = data.len() as u64;

        if file_size > MAX_FILE_SIZE {
            return Err(GhostQueryError::FileTooLarge {
                size: file_size,
                max: MAX_FILE_SIZE,
            });
        }

        let file_hash = Hasher::hash(data);

        let mut chunks = Vec::new();
        let total_chunks = self.calculate_chunks(file_size);

        for (i, chunk_data) in data.chunks(self.chunk_size).enumerate() {
            let is_final = i as u32 == total_chunks - 1;
            let chunk_id = i as u32;

            // Encrypt if cipher is set
            let encrypted_data =
                if let (Some(cipher), Some(session_id)) = (&self.cipher, &self.session_id) {
                    crate::crypto::cipher::encrypt_for_session(cipher, session_id, chunk_id, chunk_data)?
                } else {
                    chunk_data.to_vec()
                };

            chunks.push(Chunk::new(ChunkId::new(chunk_id), encrypted_data, is_final));
        }

        Ok(ChunkedFile {
            chunks,
            file_hash,
            file_size,
            chunk_size: self.chunk_size,
        })
    }

    /// Get the configured chunk size
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

impl Default for FileChunker {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of chunking a file
#[derive(Debug)]
pub struct ChunkedFile {
    /// All chunks
    pub chunks: Vec<Chunk>,
    /// File hash for verification
    pub file_hash: FileHash,
    /// Original file size
    pub file_size: u64,
    /// Chunk size used
    pub chunk_size: usize,
}

impl ChunkedFile {
    /// Get total number of chunks
    pub fn total_chunks(&self) -> u32 {
        self.chunks.len() as u32
    }

    /// Get a chunk by ID
    pub fn get_chunk(&self, id: ChunkId) -> Option<&Chunk> {
        self.chunks.get(id.as_u32() as usize)
    }

    /// Iterate over chunks
    pub fn iter(&self) -> impl Iterator<Item = &Chunk> {
        self.chunks.iter()
    }
}

/// Reassemble chunks back into original data
pub struct ChunkReassembler {
    /// Expected total chunks
    total_chunks: u32,
    /// Chunk size
    chunk_size: usize,
    /// Expected file hash
    expected_hash: FileHash,
    /// Received chunks (sparse array)
    chunks: Vec<Option<Vec<u8>>>,
    /// Cipher for decryption
    cipher: Option<AesGcmCipher>,
    /// Session ID for decryption
    session_id: Option<[u8; 8]>,
}

impl ChunkReassembler {
    /// Create a new reassembler
    pub fn new(total_chunks: u32, chunk_size: usize, expected_hash: FileHash) -> Self {
        Self {
            total_chunks,
            chunk_size,
            expected_hash,
            chunks: vec![None; total_chunks as usize],
            cipher: None,
            session_id: None,
        }
    }

    /// Set decryption cipher
    pub fn with_decryption(mut self, cipher: AesGcmCipher, session_id: [u8; 8]) -> Self {
        self.cipher = Some(cipher);
        self.session_id = Some(session_id);
        self
    }

    /// Add a chunk
    pub fn add_chunk(&mut self, chunk: &Chunk) -> Result<()> {
        let idx = chunk.id.as_u32() as usize;

        if idx >= self.total_chunks as usize {
            return Err(GhostQueryError::ChunkNotFound(chunk.id.as_u32()));
        }

        // Decrypt if cipher is set
        let data = if let (Some(cipher), Some(session_id)) = (&self.cipher, &self.session_id) {
            crate::crypto::cipher::decrypt_for_session(
                cipher,
                session_id,
                chunk.id.as_u32(),
                &chunk.data,
            )?
        } else {
            chunk.data.clone()
        };

        self.chunks[idx] = Some(data);
        Ok(())
    }

    /// Check if all chunks have been received
    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }

    /// Get missing chunk IDs
    pub fn missing_chunks(&self) -> Vec<ChunkId> {
        self.chunks
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                if c.is_none() {
                    Some(ChunkId::new(i as u32))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get number of received chunks
    pub fn received_count(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    /// Get completion percentage
    pub fn completion_pct(&self) -> f64 {
        (self.received_count() as f64 / self.total_chunks as f64) * 100.0
    }

    /// Reassemble the file
    pub fn reassemble(&self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            let missing = self.missing_chunks();
            return Err(GhostQueryError::ChunkNotFound(
                missing.first().map(|c| c.as_u32()).unwrap_or(0),
            ));
        }

        let mut data = Vec::new();
        for chunk in &self.chunks {
            if let Some(chunk_data) = chunk {
                data.extend_from_slice(chunk_data);
            }
        }

        // Verify hash
        let actual_hash = Hasher::hash(&data);
        if actual_hash.as_bytes() != self.expected_hash.as_bytes() {
            return Err(GhostQueryError::HashMismatch);
        }

        Ok(data)
    }

    /// Get received data without verification (for partial saves)
    pub fn get_received_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for chunk in &self.chunks {
            if let Some(chunk_data) = chunk {
                data.extend_from_slice(chunk_data);
            }
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_chunk_data() {
        let chunker = FileChunker::with_chunk_size(10);
        let data = b"Hello, World! This is a test of chunking.";

        let chunked = chunker.chunk_data(data).unwrap();

        assert_eq!(chunked.file_size, data.len() as u64);
        assert_eq!(chunked.total_chunks(), chunker.calculate_chunks(data.len() as u64));
        assert!(chunked.chunks.last().unwrap().is_final);
    }

    #[test]
    fn test_chunk_file() {
        let chunker = FileChunker::with_chunk_size(10);
        let data = b"Test file content for chunking";
        let mut cursor = Cursor::new(data);

        let chunked = chunker.chunk_file(&mut cursor).unwrap();

        assert_eq!(chunked.file_size, data.len() as u64);
    }

    #[test]
    fn test_reassemble() {
        let chunker = FileChunker::with_chunk_size(10);
        let original_data = b"Hello, World! This is test data for reassembly.";

        let chunked = chunker.chunk_data(original_data).unwrap();

        let mut reassembler =
            ChunkReassembler::new(chunked.total_chunks(), 10, chunked.file_hash.clone());

        for chunk in &chunked.chunks {
            reassembler.add_chunk(chunk).unwrap();
        }

        assert!(reassembler.is_complete());

        let reassembled = reassembler.reassemble().unwrap();
        assert_eq!(original_data.to_vec(), reassembled);
    }

    #[test]
    fn test_missing_chunks() {
        let chunker = FileChunker::with_chunk_size(10);
        let data = b"Test data for missing chunk detection";

        let chunked = chunker.chunk_data(data).unwrap();

        let mut reassembler =
            ChunkReassembler::new(chunked.total_chunks(), 10, chunked.file_hash.clone());

        // Add only even chunks
        for (i, chunk) in chunked.chunks.iter().enumerate() {
            if i % 2 == 0 {
                reassembler.add_chunk(chunk).unwrap();
            }
        }

        assert!(!reassembler.is_complete());

        let missing = reassembler.missing_chunks();
        assert!(!missing.is_empty());
        assert!(missing.iter().all(|c| c.as_u32() % 2 == 1));
    }

    #[test]
    fn test_encrypted_chunking() {
        let (cipher, key) = AesGcmCipher::generate();
        let session_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let chunker = FileChunker::with_chunk_size(16).with_encryption(cipher.clone(), session_id);

        let original_data = b"Secret data to encrypt and chunk";
        let chunked = chunker.chunk_data(original_data).unwrap();

        // Reassemble with decryption
        let cipher2 = AesGcmCipher::new(&key).unwrap();
        let mut reassembler = ChunkReassembler::new(
            chunked.total_chunks(),
            16,
            chunked.file_hash.clone(),
        )
        .with_decryption(cipher2, session_id);

        for chunk in &chunked.chunks {
            reassembler.add_chunk(chunk).unwrap();
        }

        let reassembled = reassembler.reassemble().unwrap();
        assert_eq!(original_data.to_vec(), reassembled);
    }
}

