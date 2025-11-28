//! Error types for the GhostQuery protocol.

use thiserror::Error;

/// Result type alias using GhostQueryError
pub type Result<T> = std::result::Result<T, GhostQueryError>;

/// Main error type for GhostQuery operations
#[derive(Error, Debug)]
pub enum GhostQueryError {
    // Session errors
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session already exists: {0}")]
    SessionExists(String),

    #[error("Session expired: {0}")]
    SessionExpired(String),

    #[error("Invalid session state: expected {expected}, got {actual}")]
    InvalidSessionState { expected: String, actual: String },

    // Chunk errors
    #[error("Chunk not found: {0}")]
    ChunkNotFound(u32),

    #[error("Chunk out of order: expected {expected}, got {actual}")]
    ChunkOutOfOrder { expected: u32, actual: u32 },

    #[error("Invalid chunk size: expected {expected}, got {actual}")]
    InvalidChunkSize { expected: usize, actual: usize },

    #[error("Maximum retransmission attempts exceeded for chunk {0}")]
    MaxRetransmitExceeded(u32),

    // Encoding errors
    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Dictionary entry not found: {0}")]
    DictionaryEntryNotFound(String),

    // Crypto errors
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Hash verification failed")]
    HashMismatch,

    // Transport errors
    #[error("DNS query failed: {0}")]
    DnsQueryError(String),

    #[error("DNS response parse error: {0}")]
    DnsParseError(String),

    #[error("ICMP error: {0}")]
    IcmpError(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Network unreachable")]
    NetworkUnreachable,

    // File errors
    #[error("File too large: {size} bytes (max: {max})")]
    FileTooLarge { size: u64, max: u64 },

    #[error("File read error: {0}")]
    FileReadError(String),

    #[error("File write error: {0}")]
    FileWriteError(String),

    // Protocol errors
    #[error("Invalid command: {0}")]
    InvalidCommand(u8),

    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },

    #[error("Invalid domain format: {0}")]
    InvalidDomainFormat(String),

    // Window errors
    #[error("Window full, cannot send more chunks")]
    WindowFull,

    #[error("Window closed, waiting for signal")]
    WindowClosed,

    // Generic errors
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl GhostQueryError {
    /// Check if this error is recoverable (retry might succeed)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            GhostQueryError::Timeout
                | GhostQueryError::WindowFull
                | GhostQueryError::WindowClosed
                | GhostQueryError::DnsQueryError(_)
        )
    }

    /// Check if this error is a fatal session error
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            GhostQueryError::HashMismatch
                | GhostQueryError::MaxRetransmitExceeded(_)
                | GhostQueryError::FileTooLarge { .. }
                | GhostQueryError::InvalidKeyLength { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_recoverable() {
        assert!(GhostQueryError::Timeout.is_recoverable());
        assert!(GhostQueryError::WindowFull.is_recoverable());
        assert!(!GhostQueryError::HashMismatch.is_recoverable());
    }

    #[test]
    fn test_error_fatal() {
        assert!(GhostQueryError::HashMismatch.is_fatal());
        assert!(GhostQueryError::MaxRetransmitExceeded(5).is_fatal());
        assert!(!GhostQueryError::Timeout.is_fatal());
    }
}

