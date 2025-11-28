//! Session management module for tracking exfiltration state.
//!
//! Implements the ADSM-inspired session lifecycle:
//! - Allocation (adsmAlloc): Session initialization
//! - Migration: Data transfer with coherence tracking
//! - De-allocation (adsmFree): Session completion

pub mod buffer;
pub mod manager;
pub mod state;

pub use buffer::ChunkBuffer;
pub use manager::SessionManager;
pub use state::{SessionState, SessionStateMachine};

