//! Protocol logic module for GhostQuery.
//!
//! Implements the core protocol mechanisms:
//! - Chunking: File splitting and encoding
//! - Windowing: Sliding/rolling window algorithms
//! - Coherence: Error detection and retransmission
//! - Commands: Control signaling

pub mod chunker;
pub mod coherence;
pub mod commands;
pub mod window;

pub use chunker::FileChunker;
pub use coherence::CoherenceProtocol;
pub use commands::CommandHandler;
pub use window::WindowController;

