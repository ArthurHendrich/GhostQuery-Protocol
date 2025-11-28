//! Sliding and rolling window algorithms for congestion control.
//!
//! Implements the ADSM-inspired windowing:
//! - Sliding window: Controls outstanding chunks
//! - Rolling window: Limits dirty chunks for coherence

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::common::constants::{DEFAULT_ROLLING_SIZE, DEFAULT_WINDOW_SIZE, DNS_QUERY_TIMEOUT_MS};
use crate::common::types::ChunkId;

/// Status of a window slot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotStatus {
    /// Slot is empty, can be used
    Empty,
    /// Slot contains an in-flight chunk
    InFlight,
    /// Slot contains an acknowledged chunk
    Acknowledged,
    /// Slot contains a dirty chunk (needs retransmit)
    Dirty,
}

/// A slot in the sliding window
#[derive(Debug, Clone)]
struct WindowSlot {
    chunk_id: ChunkId,
    status: SlotStatus,
    sent_at: Instant,
    retries: u32,
}

/// Sliding window controller for congestion control
#[derive(Debug)]
pub struct WindowController {
    /// Window size (max outstanding chunks)
    size: usize,
    /// Active slots
    slots: VecDeque<WindowSlot>,
    /// Base sequence number (first unacknowledged)
    base: ChunkId,
    /// Next sequence number to send
    next: ChunkId,
    /// Timeout for considering a chunk lost
    timeout: Duration,
    /// Whether the window is open
    is_open: bool,
    /// Rolling window limit (max dirty chunks)
    rolling_size: usize,
    /// Current dirty count
    dirty_count: usize,
}

impl WindowController {
    /// Create a new window controller
    pub fn new() -> Self {
        Self {
            size: DEFAULT_WINDOW_SIZE,
            slots: VecDeque::with_capacity(DEFAULT_WINDOW_SIZE),
            base: ChunkId::new(0),
            next: ChunkId::new(0),
            timeout: Duration::from_millis(DNS_QUERY_TIMEOUT_MS),
            is_open: false,
            rolling_size: DEFAULT_ROLLING_SIZE,
            dirty_count: 0,
        }
    }

    /// Create with custom settings
    pub fn with_settings(size: usize, rolling_size: usize, timeout: Duration) -> Self {
        Self {
            size,
            rolling_size,
            timeout,
            slots: VecDeque::with_capacity(size),
            ..Self::new()
        }
    }

    /// Open the window for transmission
    pub fn open(&mut self) {
        self.is_open = true;
    }

    /// Close the window
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Check if window is open
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Check if we can send more chunks
    pub fn can_send(&self) -> bool {
        self.is_open && self.slots.len() < self.size && self.dirty_count < self.rolling_size
    }

    /// Get the next chunk ID to send
    pub fn next_to_send(&self) -> Option<ChunkId> {
        if self.can_send() {
            Some(self.next)
        } else {
            None
        }
    }

    /// Record that a chunk was sent
    pub fn mark_sent(&mut self, chunk_id: ChunkId) {
        let slot = WindowSlot {
            chunk_id,
            status: SlotStatus::InFlight,
            sent_at: Instant::now(),
            retries: 0,
        };

        self.slots.push_back(slot);

        if chunk_id.as_u32() >= self.next.as_u32() {
            self.next = chunk_id.next();
        }
    }

    /// Record that a chunk was acknowledged
    pub fn mark_acked(&mut self, chunk_id: ChunkId) {
        for slot in &mut self.slots {
            if slot.chunk_id == chunk_id {
                if slot.status == SlotStatus::Dirty {
                    self.dirty_count = self.dirty_count.saturating_sub(1);
                }
                slot.status = SlotStatus::Acknowledged;
                break;
            }
        }

        // Slide window forward
        self.slide_window();
    }

    /// Mark a chunk as dirty (needs retransmit)
    pub fn mark_dirty(&mut self, chunk_id: ChunkId) {
        for slot in &mut self.slots {
            if slot.chunk_id == chunk_id && slot.status != SlotStatus::Dirty {
                slot.status = SlotStatus::Dirty;
                self.dirty_count += 1;
                break;
            }
        }
    }

    /// Slide the window forward (remove acknowledged chunks from front)
    fn slide_window(&mut self) {
        while let Some(front) = self.slots.front() {
            if front.status == SlotStatus::Acknowledged {
                self.base = front.chunk_id.next();
                self.slots.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get chunks that have timed out
    pub fn get_timed_out(&self) -> Vec<ChunkId> {
        let now = Instant::now();
        self.slots
            .iter()
            .filter(|slot| {
                slot.status == SlotStatus::InFlight && now.duration_since(slot.sent_at) > self.timeout
            })
            .map(|slot| slot.chunk_id)
            .collect()
    }

    /// Get dirty chunks that need retransmission
    pub fn get_dirty(&self) -> Vec<ChunkId> {
        self.slots
            .iter()
            .filter(|slot| slot.status == SlotStatus::Dirty)
            .map(|slot| slot.chunk_id)
            .collect()
    }

    /// Record a retry for a chunk
    pub fn record_retry(&mut self, chunk_id: ChunkId) {
        for slot in &mut self.slots {
            if slot.chunk_id == chunk_id {
                slot.retries += 1;
                slot.sent_at = Instant::now();
                if slot.status == SlotStatus::Dirty {
                    slot.status = SlotStatus::InFlight;
                    self.dirty_count = self.dirty_count.saturating_sub(1);
                }
                break;
            }
        }
    }

    /// Get retry count for a chunk
    pub fn retry_count(&self, chunk_id: ChunkId) -> Option<u32> {
        self.slots
            .iter()
            .find(|slot| slot.chunk_id == chunk_id)
            .map(|slot| slot.retries)
    }

    /// Get current window state
    pub fn stats(&self) -> WindowStats {
        let mut in_flight = 0;
        let mut acknowledged = 0;
        let mut dirty = 0;

        for slot in &self.slots {
            match slot.status {
                SlotStatus::InFlight => in_flight += 1,
                SlotStatus::Acknowledged => acknowledged += 1,
                SlotStatus::Dirty => dirty += 1,
                SlotStatus::Empty => {}
            }
        }

        WindowStats {
            size: self.size,
            used: self.slots.len(),
            in_flight,
            acknowledged,
            dirty,
            base: self.base,
            next: self.next,
            is_open: self.is_open,
        }
    }

    /// Get window size
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get number of slots in use
    pub fn used(&self) -> usize {
        self.slots.len()
    }

    /// Check if window is empty
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Reset the window
    pub fn reset(&mut self) {
        self.slots.clear();
        self.base = ChunkId::new(0);
        self.next = ChunkId::new(0);
        self.dirty_count = 0;
        self.is_open = false;
    }
}

impl Default for WindowController {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the window state
#[derive(Debug, Clone)]
pub struct WindowStats {
    pub size: usize,
    pub used: usize,
    pub in_flight: usize,
    pub acknowledged: usize,
    pub dirty: usize,
    pub base: ChunkId,
    pub next: ChunkId,
    pub is_open: bool,
}

impl WindowStats {
    /// Get utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.size == 0 {
            0.0
        } else {
            (self.used as f64 / self.size as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_creation() {
        let window = WindowController::new();
        assert!(!window.is_open());
        assert!(window.is_empty());
    }

    #[test]
    fn test_window_open_close() {
        let mut window = WindowController::new();

        window.open();
        assert!(window.is_open());
        assert!(window.can_send());

        window.close();
        assert!(!window.is_open());
        assert!(!window.can_send());
    }

    #[test]
    fn test_send_and_ack() {
        let mut window = WindowController::with_settings(4, 2, Duration::from_secs(5));
        window.open();

        // Send chunks
        for i in 0..3 {
            let id = ChunkId::new(i);
            window.mark_sent(id);
        }

        assert_eq!(window.used(), 3);
        assert!(window.can_send()); // Still have room

        // Ack first chunk
        window.mark_acked(ChunkId::new(0));

        // Window should slide
        let stats = window.stats();
        assert_eq!(stats.base, ChunkId::new(1));
    }

    #[test]
    fn test_window_full() {
        let mut window = WindowController::with_settings(2, 2, Duration::from_secs(5));
        window.open();

        window.mark_sent(ChunkId::new(0));
        window.mark_sent(ChunkId::new(1));

        assert!(!window.can_send()); // Window full
    }

    #[test]
    fn test_dirty_chunks() {
        let mut window = WindowController::with_settings(4, 2, Duration::from_secs(5));
        window.open();

        window.mark_sent(ChunkId::new(0));
        window.mark_sent(ChunkId::new(1));

        // Mark as dirty
        window.mark_dirty(ChunkId::new(0));

        let dirty = window.get_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0], ChunkId::new(0));

        // Dirty count should limit further sends
        window.mark_dirty(ChunkId::new(1));
        assert!(!window.can_send()); // Rolling limit reached
    }

    #[test]
    fn test_sliding_window() {
        let mut window = WindowController::with_settings(4, 4, Duration::from_secs(5));
        window.open();

        // Send 4 chunks
        for i in 0..4 {
            window.mark_sent(ChunkId::new(i));
        }

        assert!(!window.can_send());

        // Ack first two
        window.mark_acked(ChunkId::new(0));
        window.mark_acked(ChunkId::new(1));

        // Window should slide, can send more
        assert!(window.can_send());
        assert_eq!(window.stats().base, ChunkId::new(2));
    }

    #[test]
    fn test_stats() {
        let mut window = WindowController::with_settings(4, 4, Duration::from_secs(5));
        window.open();

        window.mark_sent(ChunkId::new(0));
        window.mark_sent(ChunkId::new(1));
        window.mark_acked(ChunkId::new(0));
        window.mark_dirty(ChunkId::new(1));

        let stats = window.stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.dirty, 1);
        assert!(stats.is_open);
    }
}

