//! Coherence protocols for error detection and recovery.
//!
//! Implements ADSM-inspired coherence:
//! - Gap detection: Identify missing chunks
//! - Dirty bit signaling: Request retransmission
//! - Rolling update: Limit outstanding dirty chunks

use std::collections::{BTreeMap, BTreeSet};

use crate::common::constants::MAX_RETRANSMIT_ATTEMPTS;
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::ChunkId;

/// Coherence state for a chunk
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkState {
    /// Chunk has not been received
    Invalid,
    /// Chunk is expected next
    Expected,
    /// Chunk has been received and is valid
    Valid,
    /// Chunk needs retransmission (dirty)
    Dirty,
}

/// Coherence protocol for tracking and recovering from errors
#[derive(Debug)]
pub struct CoherenceProtocol {
    /// Total expected chunks
    total_chunks: u32,
    /// Chunk states
    states: BTreeMap<ChunkId, ChunkState>,
    /// Retransmission attempts per chunk
    retries: BTreeMap<ChunkId, u32>,
    /// Currently expected sequence number
    expected_seq: ChunkId,
    /// Set of chunks marked dirty
    dirty_set: BTreeSet<ChunkId>,
    /// Maximum dirty chunks allowed (rolling limit)
    rolling_limit: usize,
}

impl CoherenceProtocol {
    /// Create a new coherence protocol handler
    pub fn new(total_chunks: u32) -> Self {
        let mut states = BTreeMap::new();
        // Initialize all chunks as invalid
        for i in 0..total_chunks {
            states.insert(ChunkId::new(i), ChunkState::Invalid);
        }
        // First chunk is expected
        if total_chunks > 0 {
            states.insert(ChunkId::new(0), ChunkState::Expected);
        }

        Self {
            total_chunks,
            states,
            retries: BTreeMap::new(),
            expected_seq: ChunkId::new(0),
            dirty_set: BTreeSet::new(),
            rolling_limit: 4,
        }
    }

    /// Set the rolling limit for dirty chunks
    pub fn with_rolling_limit(mut self, limit: usize) -> Self {
        self.rolling_limit = limit;
        self
    }

    /// Process a received chunk and return any action needed
    pub fn receive_chunk(&mut self, chunk_id: ChunkId) -> CoherenceAction {
        if chunk_id.as_u32() >= self.total_chunks {
            return CoherenceAction::Error(GhostQueryError::ChunkNotFound(chunk_id.as_u32()));
        }

        // Check for gap
        if chunk_id.as_u32() > self.expected_seq.as_u32() {
            // Gap detected - mark missing chunks as dirty
            let missing = self.detect_gap(chunk_id);
            if !missing.is_empty() {
                for &m in &missing {
                    self.mark_dirty(m);
                }
                return CoherenceAction::RequestRetransmit(missing);
            }
        }

        // Mark chunk as valid
        self.states.insert(chunk_id, ChunkState::Valid);
        self.dirty_set.remove(&chunk_id);

        // Advance expected sequence
        self.advance_expected();

        // Check if complete
        if self.is_complete() {
            CoherenceAction::Complete
        } else {
            CoherenceAction::Ack
        }
    }

    /// Detect missing chunks (gap) before the given chunk
    fn detect_gap(&self, received: ChunkId) -> Vec<ChunkId> {
        let mut missing = Vec::new();

        for i in self.expected_seq.as_u32()..received.as_u32() {
            let id = ChunkId::new(i);
            if let Some(&state) = self.states.get(&id) {
                if state != ChunkState::Valid {
                    missing.push(id);
                }
            }
        }

        missing
    }

    /// Mark a chunk as dirty (needs retransmission)
    pub fn mark_dirty(&mut self, chunk_id: ChunkId) {
        if chunk_id.as_u32() < self.total_chunks {
            self.states.insert(chunk_id, ChunkState::Dirty);
            self.dirty_set.insert(chunk_id);
        }
    }

    /// Advance the expected sequence number
    fn advance_expected(&mut self) {
        while let Some(&state) = self.states.get(&self.expected_seq) {
            if state == ChunkState::Valid {
                self.expected_seq = self.expected_seq.next();
            } else {
                break;
            }
        }

        // Mark next as expected if not already valid
        if self.expected_seq.as_u32() < self.total_chunks {
            if let Some(state) = self.states.get_mut(&self.expected_seq) {
                if *state == ChunkState::Invalid {
                    *state = ChunkState::Expected;
                }
            }
        }
    }

    /// Record a retransmission attempt
    pub fn record_retransmit(&mut self, chunk_id: ChunkId) -> Result<()> {
        let retries = self.retries.entry(chunk_id).or_insert(0);
        *retries += 1;

        if *retries > MAX_RETRANSMIT_ATTEMPTS {
            return Err(GhostQueryError::MaxRetransmitExceeded(chunk_id.as_u32()));
        }

        Ok(())
    }

    /// Get all dirty chunks
    pub fn get_dirty(&self) -> Vec<ChunkId> {
        self.dirty_set.iter().copied().collect()
    }

    /// Check if there are too many dirty chunks (rolling limit)
    pub fn is_rolling_limit_exceeded(&self) -> bool {
        self.dirty_set.len() > self.rolling_limit
    }

    /// Check if all chunks have been received
    pub fn is_complete(&self) -> bool {
        self.states.values().all(|&s| s == ChunkState::Valid)
    }

    /// Get completion percentage
    pub fn completion_pct(&self) -> f64 {
        let valid_count = self
            .states
            .values()
            .filter(|&&s| s == ChunkState::Valid)
            .count();

        (valid_count as f64 / self.total_chunks as f64) * 100.0
    }

    /// Get current expected sequence
    pub fn expected_seq(&self) -> ChunkId {
        self.expected_seq
    }

    /// Get chunk state
    pub fn chunk_state(&self, chunk_id: ChunkId) -> Option<ChunkState> {
        self.states.get(&chunk_id).copied()
    }

    /// Get statistics
    pub fn stats(&self) -> CoherenceStats {
        let mut invalid = 0;
        let mut expected = 0;
        let mut valid = 0;
        let mut dirty = 0;

        for &state in self.states.values() {
            match state {
                ChunkState::Invalid => invalid += 1,
                ChunkState::Expected => expected += 1,
                ChunkState::Valid => valid += 1,
                ChunkState::Dirty => dirty += 1,
            }
        }

        CoherenceStats {
            total: self.total_chunks,
            invalid,
            expected,
            valid,
            dirty,
            completion_pct: self.completion_pct(),
        }
    }
}

/// Action to take after processing a chunk
#[derive(Debug)]
pub enum CoherenceAction {
    /// Acknowledge the chunk (all good)
    Ack,
    /// Request retransmission of missing chunks
    RequestRetransmit(Vec<ChunkId>),
    /// All chunks received
    Complete,
    /// Error occurred
    Error(GhostQueryError),
}

/// Statistics about coherence state
#[derive(Debug, Clone)]
pub struct CoherenceStats {
    pub total: u32,
    pub invalid: u32,
    pub expected: u32,
    pub valid: u32,
    pub dirty: u32,
    pub completion_pct: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order_receive() {
        let mut protocol = CoherenceProtocol::new(5);

        for i in 0..5 {
            let action = protocol.receive_chunk(ChunkId::new(i));
            if i < 4 {
                assert!(matches!(action, CoherenceAction::Ack));
            } else {
                assert!(matches!(action, CoherenceAction::Complete));
            }
        }
    }

    #[test]
    fn test_gap_detection() {
        let mut protocol = CoherenceProtocol::new(5);

        // Receive chunk 0
        protocol.receive_chunk(ChunkId::new(0));

        // Skip chunk 1, receive chunk 2
        let action = protocol.receive_chunk(ChunkId::new(2));

        match action {
            CoherenceAction::RequestRetransmit(missing) => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], ChunkId::new(1));
            }
            _ => panic!("Expected retransmit request"),
        }
    }

    #[test]
    fn test_dirty_tracking() {
        let mut protocol = CoherenceProtocol::new(5);

        protocol.mark_dirty(ChunkId::new(1));
        protocol.mark_dirty(ChunkId::new(3));

        let dirty = protocol.get_dirty();
        assert_eq!(dirty.len(), 2);
        assert!(dirty.contains(&ChunkId::new(1)));
        assert!(dirty.contains(&ChunkId::new(3)));
    }

    #[test]
    fn test_rolling_limit() {
        let mut protocol = CoherenceProtocol::new(10).with_rolling_limit(2);

        protocol.mark_dirty(ChunkId::new(1));
        protocol.mark_dirty(ChunkId::new(2));

        assert!(!protocol.is_rolling_limit_exceeded());

        protocol.mark_dirty(ChunkId::new(3));

        assert!(protocol.is_rolling_limit_exceeded());
    }

    #[test]
    fn test_completion() {
        let mut protocol = CoherenceProtocol::new(3);

        assert!(!protocol.is_complete());
        assert_eq!(protocol.completion_pct(), 0.0);

        protocol.receive_chunk(ChunkId::new(0));
        assert!(!protocol.is_complete());

        protocol.receive_chunk(ChunkId::new(1));
        protocol.receive_chunk(ChunkId::new(2));

        assert!(protocol.is_complete());
        assert_eq!(protocol.completion_pct(), 100.0);
    }

    #[test]
    fn test_stats() {
        let mut protocol = CoherenceProtocol::new(5);

        protocol.receive_chunk(ChunkId::new(0));
        protocol.receive_chunk(ChunkId::new(1));
        protocol.mark_dirty(ChunkId::new(3));

        let stats = protocol.stats();
        assert_eq!(stats.total, 5);
        assert_eq!(stats.valid, 2);
        assert_eq!(stats.dirty, 1);
    }
}

