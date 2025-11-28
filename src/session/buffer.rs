//! Chunk buffer for managing data during exfiltration.
//!
//! Implements release consistency: chunks are buffered locally
//! and only released during authorized transmission windows.

use std::collections::{BTreeMap, VecDeque};

use crate::common::constants::{DEFAULT_ROLLING_SIZE, DEFAULT_WINDOW_SIZE, MAX_RETRANSMIT_ATTEMPTS};
use crate::common::error::{GhostQueryError, Result};
use crate::common::types::{Chunk, ChunkId};

/// Status of a buffered chunk
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkStatus {
    /// Chunk is pending transmission
    Pending,
    /// Chunk has been sent, awaiting acknowledgment
    InFlight,
    /// Chunk was acknowledged successfully
    Acknowledged,
    /// Chunk needs retransmission (dirty)
    Dirty,
}

/// Entry in the chunk buffer
#[derive(Debug, Clone)]
pub struct BufferEntry {
    /// The chunk data
    pub chunk: Chunk,
    /// Current status
    pub status: ChunkStatus,
    /// Number of transmission attempts
    pub attempts: u32,
    /// Timestamp of last send attempt (for timeout detection)
    pub last_sent: Option<std::time::Instant>,
}

impl BufferEntry {
    pub fn new(chunk: Chunk) -> Self {
        Self {
            chunk,
            status: ChunkStatus::Pending,
            attempts: 0,
            last_sent: None,
        }
    }
}

/// Chunk buffer with sliding/rolling window support
#[derive(Debug)]
pub struct ChunkBuffer {
    /// All chunks indexed by ID
    chunks: BTreeMap<ChunkId, BufferEntry>,
    /// Queue of chunks pending transmission
    pending_queue: VecDeque<ChunkId>,
    /// Chunks currently in flight
    in_flight: Vec<ChunkId>,
    /// Maximum window size (outstanding chunks)
    window_size: usize,
    /// Rolling size for coherence protocol
    rolling_size: usize,
    /// Next expected chunk ID for acknowledgment
    next_expected_ack: ChunkId,
    /// Whether the window is open for transmission
    window_open: bool,
}

impl ChunkBuffer {
    /// Create a new chunk buffer with default settings
    pub fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            pending_queue: VecDeque::new(),
            in_flight: Vec::new(),
            window_size: DEFAULT_WINDOW_SIZE,
            rolling_size: DEFAULT_ROLLING_SIZE,
            next_expected_ack: ChunkId::new(0),
            window_open: false,
        }
    }

    /// Create with custom window settings
    pub fn with_window(window_size: usize, rolling_size: usize) -> Self {
        Self {
            window_size,
            rolling_size,
            ..Self::new()
        }
    }

    /// Add a chunk to the buffer
    pub fn add_chunk(&mut self, chunk: Chunk) {
        let id = chunk.id;
        let entry = BufferEntry::new(chunk);
        self.pending_queue.push_back(id);
        self.chunks.insert(id, entry);
    }

    /// Open the transmission window
    pub fn open_window(&mut self) {
        self.window_open = true;
    }

    /// Close the transmission window
    pub fn close_window(&mut self) {
        self.window_open = false;
    }

    /// Check if window is open
    pub fn is_window_open(&self) -> bool {
        self.window_open
    }

    /// Get the next chunk to send (if window allows)
    pub fn next_to_send(&mut self) -> Result<Option<Chunk>> {
        if !self.window_open {
            return Err(GhostQueryError::WindowClosed);
        }

        if self.in_flight.len() >= self.window_size {
            return Err(GhostQueryError::WindowFull);
        }

        // First, check for dirty chunks that need retransmission
        let dirty_chunk = self.chunks.iter().find_map(|(id, entry)| {
            if entry.status == ChunkStatus::Dirty && entry.attempts < MAX_RETRANSMIT_ATTEMPTS {
                Some(*id)
            } else {
                None
            }
        });

        if let Some(id) = dirty_chunk {
            return self.mark_in_flight(id);
        }

        // Then, get from pending queue
        if let Some(id) = self.pending_queue.pop_front() {
            return self.mark_in_flight(id);
        }

        Ok(None)
    }

    /// Mark a chunk as in-flight
    fn mark_in_flight(&mut self, id: ChunkId) -> Result<Option<Chunk>> {
        if let Some(entry) = self.chunks.get_mut(&id) {
            if entry.attempts >= MAX_RETRANSMIT_ATTEMPTS {
                return Err(GhostQueryError::MaxRetransmitExceeded(id.as_u32()));
            }

            entry.status = ChunkStatus::InFlight;
            entry.attempts += 1;
            entry.last_sent = Some(std::time::Instant::now());
            self.in_flight.push(id);

            Ok(Some(entry.chunk.clone()))
        } else {
            Err(GhostQueryError::ChunkNotFound(id.as_u32()))
        }
    }

    /// Acknowledge a chunk
    pub fn acknowledge(&mut self, id: ChunkId) -> Result<()> {
        if let Some(entry) = self.chunks.get_mut(&id) {
            entry.status = ChunkStatus::Acknowledged;
            self.in_flight.retain(|&in_flight_id| in_flight_id != id);

            // Update next expected if this was the expected one
            if id == self.next_expected_ack {
                self.advance_expected_ack();
            }

            Ok(())
        } else {
            Err(GhostQueryError::ChunkNotFound(id.as_u32()))
        }
    }

    /// Mark a chunk as dirty (needs retransmission)
    pub fn mark_dirty(&mut self, id: ChunkId) -> Result<()> {
        if let Some(entry) = self.chunks.get_mut(&id) {
            entry.status = ChunkStatus::Dirty;
            self.in_flight.retain(|&in_flight_id| in_flight_id != id);
            Ok(())
        } else {
            Err(GhostQueryError::ChunkNotFound(id.as_u32()))
        }
    }

    /// Advance the expected acknowledgment counter
    fn advance_expected_ack(&mut self) {
        let mut next = self.next_expected_ack;
        while let Some(entry) = self.chunks.get(&next) {
            if entry.status == ChunkStatus::Acknowledged {
                next = next.next();
            } else {
                break;
            }
        }
        self.next_expected_ack = next;
    }

    /// Get chunks that have timed out
    pub fn get_timed_out(&self, timeout: std::time::Duration) -> Vec<ChunkId> {
        let now = std::time::Instant::now();
        self.chunks
            .iter()
            .filter_map(|(id, entry)| {
                if entry.status == ChunkStatus::InFlight {
                    if let Some(sent_time) = entry.last_sent {
                        if now.duration_since(sent_time) > timeout {
                            return Some(*id);
                        }
                    }
                }
                None
            })
            .collect()
    }

    /// Check if all chunks are acknowledged
    pub fn all_acknowledged(&self) -> bool {
        self.chunks
            .values()
            .all(|entry| entry.status == ChunkStatus::Acknowledged)
    }

    /// Get statistics about the buffer
    pub fn stats(&self) -> BufferStats {
        let mut pending = 0;
        let mut in_flight = 0;
        let mut acknowledged = 0;
        let mut dirty = 0;

        for entry in self.chunks.values() {
            match entry.status {
                ChunkStatus::Pending => pending += 1,
                ChunkStatus::InFlight => in_flight += 1,
                ChunkStatus::Acknowledged => acknowledged += 1,
                ChunkStatus::Dirty => dirty += 1,
            }
        }

        BufferStats {
            total: self.chunks.len(),
            pending,
            in_flight,
            acknowledged,
            dirty,
            window_open: self.window_open,
        }
    }

    /// Get a chunk by ID
    pub fn get_chunk(&self, id: ChunkId) -> Option<&Chunk> {
        self.chunks.get(&id).map(|e| &e.chunk)
    }

    /// Get total number of chunks
    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.pending_queue.clear();
        self.in_flight.clear();
        self.next_expected_ack = ChunkId::new(0);
    }
}

impl Default for ChunkBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the chunk buffer
#[derive(Debug, Clone)]
pub struct BufferStats {
    pub total: usize,
    pub pending: usize,
    pub in_flight: usize,
    pub acknowledged: usize,
    pub dirty: usize,
    pub window_open: bool,
}

impl BufferStats {
    /// Get completion percentage
    pub fn completion_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.acknowledged as f64 / self.total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_chunk(id: u32) -> Chunk {
        Chunk::new(ChunkId::new(id), vec![0u8; 32], false)
    }

    #[test]
    fn test_buffer_creation() {
        let buffer = ChunkBuffer::new();
        assert!(buffer.is_empty());
        assert!(!buffer.is_window_open());
    }

    #[test]
    fn test_add_chunks() {
        let mut buffer = ChunkBuffer::new();

        for i in 0..10 {
            buffer.add_chunk(create_test_chunk(i));
        }

        assert_eq!(buffer.total_chunks(), 10);
    }

    #[test]
    fn test_window_control() {
        let mut buffer = ChunkBuffer::new();
        buffer.add_chunk(create_test_chunk(0));

        // Window closed - should error
        let result = buffer.next_to_send();
        assert!(matches!(result, Err(GhostQueryError::WindowClosed)));

        // Open window
        buffer.open_window();
        let result = buffer.next_to_send();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_sliding_window() {
        let mut buffer = ChunkBuffer::with_window(2, 1);

        for i in 0..5 {
            buffer.add_chunk(create_test_chunk(i));
        }

        buffer.open_window();

        // Can send up to window size
        assert!(buffer.next_to_send().unwrap().is_some());
        assert!(buffer.next_to_send().unwrap().is_some());

        // Window full
        let result = buffer.next_to_send();
        assert!(matches!(result, Err(GhostQueryError::WindowFull)));

        // Acknowledge one
        buffer.acknowledge(ChunkId::new(0)).unwrap();

        // Can send again
        assert!(buffer.next_to_send().unwrap().is_some());
    }

    #[test]
    fn test_dirty_chunks() {
        let mut buffer = ChunkBuffer::new();
        buffer.add_chunk(create_test_chunk(0));
        buffer.add_chunk(create_test_chunk(1));
        buffer.open_window();

        // Send chunk 0
        buffer.next_to_send().unwrap();

        // Mark as dirty
        buffer.mark_dirty(ChunkId::new(0)).unwrap();

        // Next to send should be the dirty chunk
        let chunk = buffer.next_to_send().unwrap().unwrap();
        assert_eq!(chunk.id, ChunkId::new(0));
    }

    #[test]
    fn test_all_acknowledged() {
        let mut buffer = ChunkBuffer::new();
        buffer.add_chunk(create_test_chunk(0));
        buffer.add_chunk(create_test_chunk(1));
        buffer.open_window();

        buffer.next_to_send().unwrap();
        buffer.next_to_send().unwrap();

        assert!(!buffer.all_acknowledged());

        buffer.acknowledge(ChunkId::new(0)).unwrap();
        buffer.acknowledge(ChunkId::new(1)).unwrap();

        assert!(buffer.all_acknowledged());
    }

    #[test]
    fn test_stats() {
        let mut buffer = ChunkBuffer::new();

        for i in 0..5 {
            buffer.add_chunk(create_test_chunk(i));
        }

        buffer.open_window();
        buffer.next_to_send().unwrap();
        buffer.next_to_send().unwrap();
        buffer.acknowledge(ChunkId::new(0)).unwrap();

        let stats = buffer.stats();
        assert_eq!(stats.total, 5);
        assert_eq!(stats.pending, 3);
        assert_eq!(stats.in_flight, 1);
        assert_eq!(stats.acknowledged, 1);
    }
}

