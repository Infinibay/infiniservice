#!/bin/bash

# Infiniservice Build and Installer Creation Script
# This script builds the infiniservice for multiple platforms and creates installation packages

set -e

# Parse command line arguments
DEPLOY_TO_BACKEND=false
HELP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --deploy|--deploy-to-backend)
            DEPLOY_TO_BACKEND=true
            shift
            ;;
        --help|-h)
            HELP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Show help if requested
if [ "$HELP" = true ]; then
    echo "Infiniservice Build and Installer Creation Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --deploy, --deploy-to-backend    Deploy built binaries to production directory (\$INFINIBAY_BASE_DIR/infiniservice)"
    echo "  --help, -h                       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              Build installer packages only"
    echo "  $0 --deploy                     Build and deploy to production for automatic VM integration"
    echo ""
    echo "Environment Variables:"
    echo "  INFINIBAY_BASE_DIR              Production base directory (default: /opt/infinibay)"
    echo ""
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
INSTALL_DIR="$SCRIPT_DIR/install"

echo "🏗️ Building Infiniservice installer packages..."
echo "📁 Script directory: $SCRIPT_DIR"
echo "📁 Build directory: $BUILD_DIR"
echo "📁 Install directory: $INSTALL_DIR"

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust/Cargo not found. Please install Rust first."
    exit 1
fi

# Check if cross compilation tools are available
if ! command -v cross &> /dev/null; then
    echo "📦 Installing cross for cross-compilation..."
    cargo install cross
fi

echo "🔨 Building for Linux x86_64..."
cargo build --release --target x86_64-unknown-linux-gnu
if [ $? -eq 0 ]; then
    echo "✅ Linux build completed"
else
    echo "❌ Linux build failed"
    exit 1
fi

echo "🔨 Building for Windows x86_64..."
if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "✅ MinGW-w64 found, attempting Windows build..."
    cargo build --release --target x86_64-pc-windows-gnu
    if [ $? -eq 0 ]; then
        echo "✅ Windows build completed"
        WINDOWS_BUILD_SUCCESS=true
    else
        echo "⚠️ Windows build failed with cargo, trying with cross..."
        if command -v cross &> /dev/null; then
            cross build --release --target x86_64-pc-windows-gnu
            if [ $? -eq 0 ]; then
                echo "✅ Windows build completed with cross"
                WINDOWS_BUILD_SUCCESS=true
            else
                echo "⚠️ Windows build failed with cross"
                WINDOWS_BUILD_SUCCESS=false
            fi
        else
            echo "⚠️ Cross not available, skipping Windows build"
            WINDOWS_BUILD_SUCCESS=false
        fi
    fi
else
    echo "⚠️ MinGW-w64 not found, skipping Windows build"
    echo "   To enable Windows builds, install: sudo apt install gcc-mingw-w64-x86-64"
    WINDOWS_BUILD_SUCCESS=false
fi

# Create Linux installer package
echo "📦 Creating Linux installer package..."
LINUX_PKG_DIR="$BUILD_DIR/infiniservice-linux"
mkdir -p "$LINUX_PKG_DIR"

# Copy Linux binary
cp "target/x86_64-unknown-linux-gnu/release/infiniservice" "$LINUX_PKG_DIR/"

# Copy installation script
cp "$INSTALL_DIR/install-linux.sh" "$LINUX_PKG_DIR/"
chmod +x "$LINUX_PKG_DIR/install-linux.sh"

# Create README for Linux
cat > "$LINUX_PKG_DIR/README.md" << 'EOF'
# Infiniservice Linux Installation

## Installation

Run the installation script as root:

```bash
sudo ./install-linux.sh [mode] [vm-id]
```

### Parameters:
- `mode`: "normal" (default) or "ping-pong" for testing
- `vm-id`: Optional VM ID (will be auto-detected if not provided)

### Examples:

```bash
# Normal installation
sudo ./install-linux.sh

# Ping-pong test mode
sudo ./install-linux.sh ping-pong

# Normal mode with specific VM ID
sudo ./install-linux.sh normal 12345678-1234-1234-1234-123456789abc
```

## Service Management

```bash
# Check status
sudo systemctl status infiniservice

# View logs
sudo journalctl -u infiniservice -f

# Restart service
sudo systemctl restart infiniservice

# Stop service
sudo systemctl stop infiniservice
```

## Uninstallation

```bash
sudo /opt/infiniservice/uninstall.sh
```
EOF

echo "✅ Linux package created: $LINUX_PKG_DIR"

# Create Windows installer package (if Windows build succeeded)
if [ "$WINDOWS_BUILD_SUCCESS" = true ]; then
    echo "📦 Creating Windows installer package..."
    WINDOWS_PKG_DIR="$BUILD_DIR/infiniservice-windows"
    mkdir -p "$WINDOWS_PKG_DIR"

    # Copy Windows binary
    cp "target/x86_64-pc-windows-gnu/release/infiniservice.exe" "$WINDOWS_PKG_DIR/"

    # Copy installation script
    cp "$INSTALL_DIR/install-windows.ps1" "$WINDOWS_PKG_DIR/"

    # Create README for Windows
    cat > "$WINDOWS_PKG_DIR/README.md" << 'EOF'
# Infiniservice Windows Installation

## Installation

Run PowerShell as Administrator and execute:

```powershell
.\install-windows.ps1 [-ServiceMode mode] [-VmId vm-id]
```

### Parameters:
- `ServiceMode`: "normal" (default) or "ping-pong" for testing
- `VmId`: Optional VM ID (will be auto-detected if not provided)

### Examples:

```powershell
# Normal installation
.\install-windows.ps1

# Ping-pong test mode
.\install-windows.ps1 -ServiceMode ping-pong

# Normal mode with specific VM ID
.\install-windows.ps1 -ServiceMode normal -VmId "12345678-1234-1234-1234-123456789abc"
```

## Service Management

```powershell
# Check status
Get-Service Infiniservice

# View logs (Event Viewer)
Get-EventLog -LogName Application -Source Infiniservice -Newest 10

# Restart service
Restart-Service Infiniservice

# Stop service
Stop-Service Infiniservice
```

## Uninstallation

```powershell
& "C:\Program Files\Infiniservice\uninstall.ps1"
```
EOF

    echo "✅ Windows package created: $WINDOWS_PKG_DIR"
else
    echo "⚠️ Skipping Windows installer package (Windows build failed)"
    WINDOWS_PKG_DIR=""
fi

# Create combined installer ISO structure
echo "💿 Creating combined installer structure..."
ISO_DIR="$BUILD_DIR/infiniservice-installer"
mkdir -p "$ISO_DIR"

# Copy Linux package (always available)
cp -r "$LINUX_PKG_DIR" "$ISO_DIR/"

# Copy Windows package (if available)
if [ "$WINDOWS_BUILD_SUCCESS" = true ] && [ -n "$WINDOWS_PKG_DIR" ]; then
    cp -r "$WINDOWS_PKG_DIR" "$ISO_DIR/"
    echo "✅ Added Windows package to installer"
else
    echo "⚠️ Windows package not available, creating Linux-only installer"
fi

# Create autorun script for Linux
cat > "$ISO_DIR/autorun-linux.sh" << 'EOF'
#!/bin/bash

# Auto-detection and installation script for Linux
echo "🐧 Infiniservice Linux Auto-Installer"

# Detect if we're in a VM
if [ -d "/dev/virtio-ports" ] || [ -e "/dev/vport0p1" ]; then
    echo "✅ Virtio-serial device detected"
else
    echo "⚠️ No virtio-serial device detected. Installation may not work properly."
fi

# Check for ping-pong mode
if [ "$1" = "ping-pong" ] || [ "$INFINISERVICE_MODE" = "ping-pong" ]; then
    echo "🏓 Installing in ping-pong test mode"
    cd infiniservice-linux && sudo ./install-linux.sh ping-pong
else
    echo "📊 Installing in normal mode"
    cd infiniservice-linux && sudo ./install-linux.sh
fi
EOF

chmod +x "$ISO_DIR/autorun-linux.sh"

# Create autorun script for Windows
cat > "$ISO_DIR/autorun-windows.ps1" << 'EOF'
# Auto-detection and installation script for Windows
Write-Host "🪟 Infiniservice Windows Auto-Installer" -ForegroundColor Green

# Check for ping-pong mode
$ServiceMode = if ($env:INFINISERVICE_MODE -eq "ping-pong" -or $args[0] -eq "ping-pong") { "ping-pong" } else { "normal" }

if ($ServiceMode -eq "ping-pong") {
    Write-Host "🏓 Installing in ping-pong test mode" -ForegroundColor Yellow
} else {
    Write-Host "📊 Installing in normal mode" -ForegroundColor Cyan
}

Set-Location "infiniservice-windows"
.\install-windows.ps1 -ServiceMode $ServiceMode
EOF

# Create main README
cat > "$ISO_DIR/README.md" << 'EOF'
# Infiniservice Installer

This installer contains Infiniservice packages for both Linux and Windows.

## Linux Installation

```bash
sudo ./autorun-linux.sh [ping-pong]
```

Or manually:
```bash
cd infiniservice-linux
sudo ./install-linux.sh [mode] [vm-id]
```

## Windows Installation

Run PowerShell as Administrator:
```powershell
.\autorun-windows.ps1 [ping-pong]
```

Or manually:
```powershell
cd infiniservice-windows
.\install-windows.ps1 [-ServiceMode mode] [-VmId vm-id]
```

## Testing

For ping-pong testing, use the "ping-pong" parameter to verify virtio-serial communication.

## Support

- Linux logs: `journalctl -u infiniservice -f`
- Windows logs: Event Viewer → Application logs
EOF

echo "✅ Combined installer created: $ISO_DIR"

# Create archive packages
echo "📦 Creating archive packages..."
cd "$BUILD_DIR"

tar -czf "infiniservice-linux.tar.gz" infiniservice-linux/
echo "✅ Created: infiniservice-linux.tar.gz"

if [ "$WINDOWS_BUILD_SUCCESS" = true ] && [ -d "infiniservice-windows" ]; then
    zip -r "infiniservice-windows.zip" infiniservice-windows/
    echo "✅ Created: infiniservice-windows.zip"
else
    echo "⚠️ Skipped: infiniservice-windows.zip (Windows build not available)"
fi

tar -czf "infiniservice-installer.tar.gz" infiniservice-installer/
echo "✅ Created: infiniservice-installer.tar.gz"

# Deploy to backend if requested
if [ "$DEPLOY_TO_BACKEND" = true ]; then
    echo ""
    echo "🚀 Deploying binaries to backend integration directory..."

    # Determine the target directory - should be inside INFINIBAY_BASE_DIR for production
    INFINIBAY_BASE_DIR="${INFINIBAY_BASE_DIR:-/opt/infinibay}"
    INFINISERVICE_TARGET_DIR="$INFINIBAY_BASE_DIR/infiniservice"

    echo "📁 Target directory: $INFINISERVICE_TARGET_DIR"

    # Check if we can write to the target directory
    if [ ! -d "$INFINIBAY_BASE_DIR" ]; then
        echo "⚠️ INFINIBAY_BASE_DIR ($INFINIBAY_BASE_DIR) does not exist"
        echo "   Creating directory (may require sudo)..."
        if ! mkdir -p "$INFINIBAY_BASE_DIR" 2>/dev/null; then
            echo "❌ Cannot create $INFINIBAY_BASE_DIR"
            echo "   Please run: sudo mkdir -p $INFINIBAY_BASE_DIR && sudo chown $USER:$USER $INFINIBAY_BASE_DIR"
            exit 1
        fi
    fi

    if [ ! -w "$INFINIBAY_BASE_DIR" ]; then
        echo "⚠️ No write permission to $INFINIBAY_BASE_DIR"
        echo "   Please run: sudo chown $USER:$USER $INFINIBAY_BASE_DIR"
        exit 1
    fi

    echo "📁 Target directory: $INFINISERVICE_TARGET_DIR"

    # Create target directories
    mkdir -p "$INFINISERVICE_TARGET_DIR/target/release"
    mkdir -p "$INFINISERVICE_TARGET_DIR/target/x86_64-pc-windows-gnu/release"
    mkdir -p "$INFINISERVICE_TARGET_DIR/install"

    # Copy Linux binary
    LINUX_BINARY_SOURCE="$SCRIPT_DIR/target/release/infiniservice"
    if [ -f "$LINUX_BINARY_SOURCE" ]; then
        cp "$LINUX_BINARY_SOURCE" "$INFINISERVICE_TARGET_DIR/target/release/"
        chmod +x "$INFINISERVICE_TARGET_DIR/target/release/infiniservice"
        echo "✅ Deployed Linux binary to: $INFINISERVICE_TARGET_DIR/target/release/infiniservice"
    else
        echo "⚠️ Linux binary not found at: $LINUX_BINARY_SOURCE"
    fi

    # Copy Windows binary (if available)
    WINDOWS_BINARY_SOURCE="$SCRIPT_DIR/target/x86_64-pc-windows-gnu/release/infiniservice.exe"
    if [ -f "$WINDOWS_BINARY_SOURCE" ]; then
        cp "$WINDOWS_BINARY_SOURCE" "$INFINISERVICE_TARGET_DIR/target/x86_64-pc-windows-gnu/release/"
        echo "✅ Deployed Windows binary to: $INFINISERVICE_TARGET_DIR/target/x86_64-pc-windows-gnu/release/infiniservice.exe"
    else
        echo "⚠️ Windows binary not found at: $WINDOWS_BINARY_SOURCE"
    fi

    # Copy installation scripts
    if [ -d "$INSTALL_DIR" ]; then
        cp -r "$INSTALL_DIR"/* "$INFINISERVICE_TARGET_DIR/install/"
        echo "✅ Deployed installation scripts to: $INFINISERVICE_TARGET_DIR/install/"
    else
        echo "⚠️ Installation scripts directory not found, skipping"
    fi

    echo ""
    echo "🎯 Deployment completed! Infiniservice is now installed in production location:"
    echo "   📁 Base directory: $INFINISERVICE_TARGET_DIR"
    echo "   🐧 Linux binary: $INFINISERVICE_TARGET_DIR/target/release/infiniservice"
    if [ -f "$SCRIPT_DIR/target/x86_64-pc-windows-gnu/release/infiniservice.exe" ]; then
        echo "   🪟 Windows binary: $INFINISERVICE_TARGET_DIR/target/x86_64-pc-windows-gnu/release/infiniservice.exe"
    fi
    echo "   📜 Installation scripts: $INFINISERVICE_TARGET_DIR/install/"
    echo ""
    echo "💡 The unattended managers will automatically find and use these binaries!"
    echo "🚀 You can now create VMs and infiniservice will be automatically installed!"
fi

echo ""
echo "🎉 Build completed successfully!"
echo "📁 Build artifacts in: $BUILD_DIR"
echo ""
echo "📦 Available packages:"
echo "   - infiniservice-linux.tar.gz (Linux only)"
if [ "$WINDOWS_BUILD_SUCCESS" = true ]; then
    echo "   - infiniservice-windows.zip (Windows only)"
    echo "   - infiniservice-installer.tar.gz (Combined Linux + Windows installer)"
else
    echo "   - infiniservice-installer.tar.gz (Linux-only installer)"
    echo ""
    echo "⚠️ Windows build was skipped due to missing dependencies"
    echo "   To enable Windows builds, install: sudo apt install gcc-mingw-w64-x86-64"
fi
echo ""
echo "💿 To create ISO (requires genisoimage):"
echo "   genisoimage -o infiniservice-installer.iso -R -J infiniservice-installer/"
echo ""
if [ "$DEPLOY_TO_BACKEND" = false ]; then
    echo "🚀 To deploy binaries for automatic VM integration:"
    echo "   $0 --deploy"
fi
