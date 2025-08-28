#!/bin/bash

# Deploy script for InfiniService
# Builds and deploys binaries to /opt/infinibay/infiniservice/binaries/

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_BASE="/opt/infinibay/infiniservice/binaries"
WINDOWS_DIR="${DEPLOY_BASE}/windows"
LINUX_DIR="${DEPLOY_BASE}/linux"
INSTALL_DIR="/opt/infinibay/infiniservice/install"

echo -e "${GREEN}InfiniService Deployment Script${NC}"
echo "================================"

# Check if running with proper permissions
if [ ! -w "/opt/infinibay" ] 2>/dev/null; then
    echo -e "${YELLOW}Warning: You may need sudo permissions to deploy to /opt/infinibay${NC}"
    echo "Trying with sudo..."
    exec sudo "$0" "$@"
fi

# Create deployment directories if they don't exist
echo -e "${GREEN}Creating deployment directories...${NC}"
mkdir -p "$WINDOWS_DIR"
mkdir -p "$LINUX_DIR"
mkdir -p "$INSTALL_DIR"

# Function to build for a specific target
build_target() {
    local target=$1
    local output_dir=$2
    local binary_name=$3
    
    echo -e "${GREEN}Building for ${target}...${NC}"
    
    if cargo build --release --target "$target"; then
        echo -e "${GREEN}✓ Build successful for ${target}${NC}"
        return 0
    else
        echo -e "${RED}✗ Build failed for ${target}${NC}"
        return 1
    fi
}

# Build for Linux (x86_64)
echo ""
echo -e "${GREEN}Building Linux binary...${NC}"
if build_target "x86_64-unknown-linux-gnu" "$LINUX_DIR" "infiniservice"; then
    cp "target/x86_64-unknown-linux-gnu/release/infiniservice" "$LINUX_DIR/"
    chmod +x "$LINUX_DIR/infiniservice"
    echo -e "${GREEN}✓ Linux binary deployed to ${LINUX_DIR}/infiniservice${NC}"
else
    echo -e "${YELLOW}⚠ Linux build skipped due to errors${NC}"
fi

# Build for Windows (x86_64)
echo ""
echo -e "${GREEN}Building Windows binary...${NC}"

# Check if Windows target is installed
if ! rustup target list --installed | grep -q "x86_64-pc-windows-gnu"; then
    echo -e "${YELLOW}Installing Windows cross-compilation target...${NC}"
    rustup target add x86_64-pc-windows-gnu
fi

# Check for mingw-w64 (required for Windows cross-compilation)
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo -e "${YELLOW}mingw-w64 not found. Installing...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y mingw-w64
    elif command -v yum &> /dev/null; then
        sudo yum install -y mingw64-gcc
    else
        echo -e "${RED}Please install mingw-w64 manually for Windows cross-compilation${NC}"
        echo -e "${YELLOW}⚠ Windows build skipped${NC}"
    fi
fi

if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    # Use additional flags to reduce false positives
    export RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-s"
    if build_target "x86_64-pc-windows-gnu" "$WINDOWS_DIR" "infiniservice.exe"; then
        cp "target/x86_64-pc-windows-gnu/release/infiniservice.exe" "$WINDOWS_DIR/"
        
        # Additional stripping to reduce false positives
        if command -v x86_64-w64-mingw32-strip &> /dev/null; then
            x86_64-w64-mingw32-strip "$WINDOWS_DIR/infiniservice.exe"
            echo -e "${GREEN}✓ Binary stripped to reduce AV false positives${NC}"
        fi
        echo -e "${GREEN}✓ Windows binary deployed to ${WINDOWS_DIR}/infiniservice.exe${NC}"
        
        # Offer to sign the executable
        if [ -f "./sign-windows.sh" ]; then
            echo ""
            read -p "¿Deseas firmar digitalmente el ejecutable de Windows? [y/N]: " sign_exe
            if [[ $sign_exe =~ ^[Yy]$ ]]; then
                ./sign-windows.sh
            fi
        fi
    else
        echo -e "${YELLOW}⚠ Windows build skipped due to errors${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Windows build skipped (mingw-w64 not available)${NC}"
fi

# Copy installation scripts
echo ""
echo -e "${GREEN}Copying installation scripts...${NC}"

# Copy Linux installation script
if [ -f "install/install-linux.sh" ]; then
    cp "install/install-linux.sh" "$LINUX_DIR/"
    chmod +x "$LINUX_DIR/install-linux.sh"
    # Also copy to main install directory
    cp "install/install-linux.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/install-linux.sh"
    echo -e "${GREEN}✓ Linux installation script copied to binaries and install directories${NC}"
fi

# Copy Windows installation script
if [ -f "install/install-windows.ps1" ]; then
    cp "install/install-windows.ps1" "$WINDOWS_DIR/"
    # Also copy to main install directory
    cp "install/install-windows.ps1" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Windows installation script copied to binaries and install directories${NC}"
fi

# Copy cloud-init template
if [ -f "install/cloud-init-ubuntu.yaml" ]; then
    cp "install/cloud-init-ubuntu.yaml" "$LINUX_DIR/"
    # Also copy to main install directory
    cp "install/cloud-init-ubuntu.yaml" "$INSTALL_DIR/"
    echo -e "${GREEN}✓ Cloud-init template copied to binaries and install directories${NC}"
fi

# Generate deployment summary
echo ""
echo -e "${GREEN}Deployment Summary${NC}"
echo "=================="
echo -e "Binary deployment: ${DEPLOY_BASE}"
echo -e "Install scripts:   ${INSTALL_DIR}"
echo ""

if [ -f "$LINUX_DIR/infiniservice" ]; then
    size=$(du -h "$LINUX_DIR/infiniservice" | cut -f1)
    echo -e "${GREEN}Linux binary:${NC}"
    echo "  Path: $LINUX_DIR/infiniservice"
    echo "  Size: $size"
    echo "  Hash: $(sha256sum "$LINUX_DIR/infiniservice" | cut -d' ' -f1 | head -c 16)..."
fi

if [ -f "$WINDOWS_DIR/infiniservice.exe" ]; then
    size=$(du -h "$WINDOWS_DIR/infiniservice.exe" | cut -f1)
    echo -e "${GREEN}Windows binary:${NC}"
    echo "  Path: $WINDOWS_DIR/infiniservice.exe"
    echo "  Size: $size"
    echo "  Hash: $(sha256sum "$WINDOWS_DIR/infiniservice.exe" | cut -d' ' -f1 | head -c 16)..."
fi

# Set proper permissions on deployment directories
chown -R $(logname 2>/dev/null || echo $SUDO_USER):$(logname 2>/dev/null || echo $SUDO_USER) "$DEPLOY_BASE" 2>/dev/null || true
chown -R $(logname 2>/dev/null || echo $SUDO_USER):$(logname 2>/dev/null || echo $SUDO_USER) "$INSTALL_DIR" 2>/dev/null || true

echo ""
echo -e "${GREEN}✓ Deployment complete!${NC}"
echo ""
echo "To install on target VMs:"
echo "  Linux:   scp $LINUX_DIR/infiniservice* <vm>:/tmp/ && ssh <vm> 'sudo /tmp/install-linux.sh'"
echo "  Windows: Copy $WINDOWS_DIR/infiniservice.exe and run install-windows.ps1 as Administrator"