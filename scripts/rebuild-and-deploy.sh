#!/bin/bash

# InfiniService Rebuild and Deploy Script
# This script rebuilds InfiniService with the latest changes and provides deployment instructions

set -e

echo "=== InfiniService Rebuild and Deploy Script ==="
echo "Building InfiniService with reduced logging..."

# Navigate to infiniservice directory
cd "$(dirname "$0")/.."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
cargo clean

# Build for Windows (cross-compilation)
echo "🔨 Building for Windows (x86_64-pc-windows-gnu)..."
if cargo build --release --target x86_64-pc-windows-gnu; then
    echo "✅ Windows build successful!"
    WINDOWS_BINARY="target/x86_64-pc-windows-gnu/release/infiniservice.exe"
    if [ -f "$WINDOWS_BINARY" ]; then
        echo "📦 Windows binary created: $WINDOWS_BINARY"
        echo "📏 Binary size: $(du -h "$WINDOWS_BINARY" | cut -f1)"
    fi
else
    echo "❌ Windows build failed!"
    exit 1
fi

# Build for Linux (native)
echo "🔨 Building for Linux (native)..."
if cargo build --release; then
    echo "✅ Linux build successful!"
    LINUX_BINARY="target/release/infiniservice"
    if [ -f "$LINUX_BINARY" ]; then
        echo "📦 Linux binary created: $LINUX_BINARY"
        echo "📏 Binary size: $(du -h "$LINUX_BINARY" | cut -f1)"
    fi
else
    echo "❌ Linux build failed!"
    exit 1
fi

echo ""
echo "=== DEPLOYMENT INSTRUCTIONS ==="
echo ""

echo "🪟 For Windows VMs:"
echo "1. Copy the Windows binary to your VM:"
echo "   scp $WINDOWS_BINARY user@vm-ip:C:/Program Files/InfiniService/"
echo ""
echo "2. Stop the current service (if running):"
echo "   sc stop InfiniService"
echo ""
echo "3. Replace the binary and restart:"
echo "   sc start InfiniService"
echo ""
echo "4. Check service status:"
echo "   sc query InfiniService"
echo ""

echo "🐧 For Linux VMs:"
echo "1. Copy the Linux binary to your VM:"
echo "   scp $LINUX_BINARY user@vm-ip:/usr/local/bin/"
echo ""
echo "2. Stop the current service (if running):"
echo "   sudo systemctl stop infiniservice"
echo ""
echo "3. Make executable and restart:"
echo "   sudo chmod +x /usr/local/bin/infiniservice"
echo "   sudo systemctl start infiniservice"
echo ""
echo "4. Check service status:"
echo "   sudo systemctl status infiniservice"
echo ""

echo "=== CHANGES IN THIS BUILD ==="
echo "✅ Reduced command checking frequency from 100ms to 500ms"
echo "✅ Added rate limiting for error logs (max once per 60 seconds)"
echo "✅ Improved error handling for expected conditions (EOF, timeout, etc.)"
echo "✅ Reduced debug logging spam for normal operations"
echo ""

echo "=== EXPECTED IMPROVEMENTS ==="
echo "📉 Significantly reduced log spam"
echo "⚡ Lower CPU usage due to less frequent command checking"
echo "🔇 Quieter operation while maintaining functionality"
echo "📊 Better error reporting with aggregated counts"
echo ""

echo "🎉 Build and deployment preparation complete!"
echo "The updated InfiniService should produce much cleaner logs."
