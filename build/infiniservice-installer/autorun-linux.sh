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
