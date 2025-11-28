//! Session state machine for tracking session lifecycle.
//!
//! States mirror the ADSM memory states:
//! - Invalid: Session not yet initialized
//! - Allocated: Session created, ready for transfer
//! - Active: Data transfer in progress
//! - Dirty: Has pending retransmissions
//! - Complete: All data transferred and verified
//! - Terminated: Session ended (success or error)

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{ChunkId, SessionId, SessionMetadata};

/// Session states (inspired by ADSM memory states)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session not initialized
    Invalid,
    /// Session allocated, ready for data transfer
    Allocated,
    /// Actively transferring data
    Active,
    /// Has dirty chunks requiring retransmission
    Dirty,
    /// Transfer complete, awaiting verification
    Verifying,
    /// All data transferred and verified
    Complete,
    /// Session terminated (success or failure)
    Terminated,
}

impl SessionState {
    /// Check if the session can accept new chunks
    pub fn can_send(&self) -> bool {
        matches!(self, SessionState::Active | SessionState::Dirty)
    }

    /// Check if the session is finished
    pub fn is_finished(&self) -> bool {
        matches!(self, SessionState::Complete | SessionState::Terminated)
    }

    /// Check if the session needs retransmission
    pub fn needs_retransmit(&self) -> bool {
        matches!(self, SessionState::Dirty)
    }

    /// Get human-readable state name
    pub fn name(&self) -> &'static str {
        match self {
            SessionState::Invalid => "Invalid",
            SessionState::Allocated => "Allocated",
            SessionState::Active => "Active",
            SessionState::Dirty => "Dirty",
            SessionState::Verifying => "Verifying",
            SessionState::Complete => "Complete",
            SessionState::Terminated => "Terminated",
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// State machine for managing session transitions
#[derive(Debug)]
pub struct SessionStateMachine {
    /// Current state
    state: SessionState,
    /// Session metadata
    metadata: Option<SessionMetadata>,
    /// Last chunk ID successfully sent
    last_sent: Option<ChunkId>,
    /// Last chunk ID acknowledged
    last_acked: Option<ChunkId>,
    /// Chunks pending retransmission
    dirty_chunks: Vec<ChunkId>,
    /// Time of last state change
    last_transition: Instant,
    /// Total state transitions
    transition_count: u32,
}

impl SessionStateMachine {
    /// Create a new state machine in Invalid state
    pub fn new() -> Self {
        Self {
            state: SessionState::Invalid,
            metadata: None,
            last_sent: None,
            last_acked: None,
            dirty_chunks: Vec::new(),
            last_transition: Instant::now(),
            transition_count: 0,
        }
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get session metadata if allocated
    pub fn metadata(&self) -> Option<&SessionMetadata> {
        self.metadata.as_ref()
    }

    /// Get session ID if allocated
    pub fn session_id(&self) -> Option<SessionId> {
        self.metadata.as_ref().map(|m| m.session_id)
    }

    /// Get last sent chunk ID
    pub fn last_sent(&self) -> Option<ChunkId> {
        self.last_sent
    }

    /// Get last acknowledged chunk ID
    pub fn last_acked(&self) -> Option<ChunkId> {
        self.last_acked
    }

    /// Get dirty chunks requiring retransmission
    pub fn dirty_chunks(&self) -> &[ChunkId] {
        &self.dirty_chunks
    }

    /// Get time since last state transition
    pub fn time_in_state(&self) -> Duration {
        self.last_transition.elapsed()
    }

    /// Allocate the session (Invalid -> Allocated)
    pub fn allocate(&mut self, metadata: SessionMetadata) -> Result<()> {
        self.validate_transition(SessionState::Allocated)?;

        self.metadata = Some(metadata);
        self.transition_to(SessionState::Allocated);
        Ok(())
    }

    /// Start data transfer (Allocated -> Active)
    pub fn start(&mut self) -> Result<()> {
        self.validate_transition(SessionState::Active)?;
        self.transition_to(SessionState::Active);
        Ok(())
    }

    /// Record a chunk being sent
    pub fn chunk_sent(&mut self, chunk_id: ChunkId) -> Result<()> {
        if !self.state.can_send() {
            return Err(GhostQueryError::InvalidSessionState {
                expected: "Active or Dirty".to_string(),
                actual: self.state.name().to_string(),
            });
        }

        self.last_sent = Some(chunk_id);

        // Remove from dirty list if present
        self.dirty_chunks.retain(|&id| id != chunk_id);

        // If no more dirty chunks and was Dirty, go back to Active
        if self.dirty_chunks.is_empty() && self.state == SessionState::Dirty {
            self.transition_to(SessionState::Active);
        }

        Ok(())
    }

    /// Record a chunk acknowledgment
    pub fn chunk_acked(&mut self, chunk_id: ChunkId) -> Result<()> {
        if !self.state.can_send() && self.state != SessionState::Verifying {
            return Err(GhostQueryError::InvalidSessionState {
                expected: "Active, Dirty, or Verifying".to_string(),
                actual: self.state.name().to_string(),
            });
        }

        self.last_acked = Some(chunk_id);
        self.dirty_chunks.retain(|&id| id != chunk_id);

        Ok(())
    }

    /// Mark a chunk as dirty (needs retransmission)
    pub fn mark_dirty(&mut self, chunk_id: ChunkId) -> Result<()> {
        if !self.state.can_send() {
            return Err(GhostQueryError::InvalidSessionState {
                expected: "Active or Dirty".to_string(),
                actual: self.state.name().to_string(),
            });
        }

        if !self.dirty_chunks.contains(&chunk_id) {
            self.dirty_chunks.push(chunk_id);
            self.dirty_chunks.sort();
        }

        if self.state != SessionState::Dirty {
            self.transition_to(SessionState::Dirty);
        }

        Ok(())
    }

    /// Start verification (Active -> Verifying)
    pub fn start_verification(&mut self) -> Result<()> {
        self.validate_transition(SessionState::Verifying)?;
        self.transition_to(SessionState::Verifying);
        Ok(())
    }

    /// Complete the session (Verifying -> Complete)
    pub fn complete(&mut self) -> Result<()> {
        self.validate_transition(SessionState::Complete)?;
        self.transition_to(SessionState::Complete);
        Ok(())
    }

    /// Terminate the session (any state -> Terminated)
    pub fn terminate(&mut self) -> Result<()> {
        self.transition_to(SessionState::Terminated);
        Ok(())
    }

    /// Check if a state transition is valid
    fn validate_transition(&self, target: SessionState) -> Result<()> {
        let valid = match (self.state, target) {
            (SessionState::Invalid, SessionState::Allocated) => true,
            (SessionState::Allocated, SessionState::Active) => true,
            (SessionState::Active, SessionState::Dirty) => true,
            (SessionState::Active, SessionState::Verifying) => true,
            (SessionState::Dirty, SessionState::Active) => true,
            (SessionState::Dirty, SessionState::Verifying) => true,
            (SessionState::Verifying, SessionState::Complete) => true,
            (_, SessionState::Terminated) => true, // Can always terminate
            _ => false,
        };

        if valid {
            Ok(())
        } else {
            Err(GhostQueryError::InvalidSessionState {
                expected: target.name().to_string(),
                actual: self.state.name().to_string(),
            })
        }
    }

    /// Perform a state transition
    fn transition_to(&mut self, new_state: SessionState) {
        self.state = new_state;
        self.last_transition = Instant::now();
        self.transition_count += 1;
    }

    /// Get progress as percentage
    pub fn progress(&self) -> f64 {
        match (&self.metadata, &self.last_acked) {
            (Some(meta), Some(acked)) => {
                let progress = (acked.as_u32() + 1) as f64 / meta.total_chunks as f64;
                progress.min(1.0) * 100.0
            }
            _ => 0.0,
        }
    }
}

impl Default for SessionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::FileHash;

    fn create_test_metadata() -> SessionMetadata {
        SessionMetadata::new(
            SessionId::new(),
            FileHash::new([0u8; 32]),
            100,
            32,
            3200,
        )
    }

    #[test]
    fn test_initial_state() {
        let sm = SessionStateMachine::new();
        assert_eq!(sm.state(), SessionState::Invalid);
    }

    #[test]
    fn test_allocation() {
        let mut sm = SessionStateMachine::new();
        let metadata = create_test_metadata();

        sm.allocate(metadata).unwrap();
        assert_eq!(sm.state(), SessionState::Allocated);
        assert!(sm.metadata().is_some());
    }

    #[test]
    fn test_full_lifecycle() {
        let mut sm = SessionStateMachine::new();
        let metadata = create_test_metadata();

        // Allocate
        sm.allocate(metadata).unwrap();
        assert_eq!(sm.state(), SessionState::Allocated);

        // Start
        sm.start().unwrap();
        assert_eq!(sm.state(), SessionState::Active);

        // Send and ack some chunks
        sm.chunk_sent(ChunkId::new(0)).unwrap();
        sm.chunk_acked(ChunkId::new(0)).unwrap();

        // Mark dirty
        sm.mark_dirty(ChunkId::new(1)).unwrap();
        assert_eq!(sm.state(), SessionState::Dirty);
        assert_eq!(sm.dirty_chunks().len(), 1);

        // Retransmit
        sm.chunk_sent(ChunkId::new(1)).unwrap();
        sm.chunk_acked(ChunkId::new(1)).unwrap();
        assert_eq!(sm.state(), SessionState::Active);

        // Verify and complete
        sm.start_verification().unwrap();
        assert_eq!(sm.state(), SessionState::Verifying);

        sm.complete().unwrap();
        assert_eq!(sm.state(), SessionState::Complete);
        assert!(sm.state().is_finished());
    }

    #[test]
    fn test_invalid_transition() {
        let mut sm = SessionStateMachine::new();

        // Cannot start without allocation
        let result = sm.start();
        assert!(result.is_err());
    }

    #[test]
    fn test_can_always_terminate() {
        let mut sm = SessionStateMachine::new();

        // Can terminate from any state
        sm.terminate().unwrap();
        assert_eq!(sm.state(), SessionState::Terminated);
    }

    #[test]
    fn test_progress_calculation() {
        let mut sm = SessionStateMachine::new();
        let metadata = create_test_metadata(); // 100 chunks

        sm.allocate(metadata).unwrap();
        sm.start().unwrap();

        sm.chunk_acked(ChunkId::new(49)).unwrap();
        let progress = sm.progress();
        assert!((progress - 50.0).abs() < 0.1);
    }
}

