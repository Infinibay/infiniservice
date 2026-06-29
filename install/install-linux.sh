#!/bin/bash

# Infiniservice Linux Installation Script
# This script installs and configures the Infiniservice on Linux VMs

set -e

SERVICE_MODE="${1:-normal}"
VM_ID="${2:-}"
INSTALL_PATH="/opt/infiniservice"
SERVICE_NAME="infiniservice"
USER_NAME="infiniservice"

echo "🚀 Starting Infiniservice installation..."
echo "📁 Installation path: $INSTALL_PATH"
echo "🔧 Service mode: $SERVICE_MODE"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (use sudo)"
   exit 1
fi

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION=$VERSION_ID
else
    echo "❌ Cannot detect Linux distribution"
    exit 1
fi

echo "🐧 Detected distribution: $DISTRO $VERSION"

# Create installation directory
mkdir -p "$INSTALL_PATH"
echo "✅ Created installation directory: $INSTALL_PATH"

# Create service user
if ! id "$USER_NAME" &>/dev/null; then
    useradd --system --no-create-home --shell /bin/false "$USER_NAME"
    echo "✅ Created service user: $USER_NAME"
else
    echo "ℹ️ Service user already exists: $USER_NAME"
fi

# Copy executable
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_EXE="$SCRIPT_DIR/infiniservice"
DEST_EXE="$INSTALL_PATH/infiniservice"

if [ -f "$SOURCE_EXE" ]; then
    cp "$SOURCE_EXE" "$DEST_EXE"
    chmod +x "$DEST_EXE"
    chown root:root "$DEST_EXE"
    echo "✅ Copied infiniservice to $DEST_EXE"
else
    echo "❌ Source executable not found: $SOURCE_EXE"
    exit 1
fi

# Create configuration file
CONFIG_PATH="$INSTALL_PATH/config.toml"
cat > "$CONFIG_PATH" << EOF
collection_interval = 30
log_level = "info"
service_name = "infiniservice"

# Linux virtio-serial device path will be auto-detected
virtio_serial_path = ""
EOF

chown root:root "$CONFIG_PATH"
chmod 644 "$CONFIG_PATH"
echo "✅ Created configuration file: $CONFIG_PATH"

# Set environment variables
ENV_FILE="/etc/environment"

# Remove existing entries
sed -i '/INFINIBAY_VM_ID/d' "$ENV_FILE" 2>/dev/null || true
sed -i '/INFINISERVICE_MODE/d' "$ENV_FILE" 2>/dev/null || true

if [ -n "$VM_ID" ]; then
    echo "INFINIBAY_VM_ID=$VM_ID" >> "$ENV_FILE"
    echo "✅ Set VM ID environment variable: $VM_ID"
fi

if [ "$SERVICE_MODE" = "ping-pong" ]; then
    echo "INFINISERVICE_MODE=ping-pong" >> "$ENV_FILE"
    echo "✅ Set service mode to ping-pong"
fi

# SECURITY: the per-VM HMAC shared secret authenticates host→agent commands.
# It MUST stay readable only by root — the agent runs as root, but any other
# guest process that could read it could forge commands. So it is written to a
# 0600 root-only EnvironmentFile, NEVER to world-readable /etc/environment.
# The backend passes the derived secret in this installer's environment
# (INFINISERVICE_SHARED_SECRET), not on the command line, so it never appears
# in `ps`/argv. Without it, the agent runs locked (rejects all commands).
SECRET_DIR="/etc/infiniservice"
SECRET_FILE="$SECRET_DIR/agent.env"
mkdir -p "$SECRET_DIR"
chown root:root "$SECRET_DIR"
chmod 700 "$SECRET_DIR"
if [ -n "${INFINISERVICE_SHARED_SECRET:-}" ]; then
    umask 077
    printf 'INFINISERVICE_SHARED_SECRET=%s\n' "$INFINISERVICE_SHARED_SECRET" > "$SECRET_FILE"
    chown root:root "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
    echo "✅ Installed per-VM agent secret (root-only): $SECRET_FILE"
else
    # Do not leave a stale secret from a previous install in place.
    rm -f "$SECRET_FILE"
    echo "⚠️  INFINISERVICE_SHARED_SECRET not provided — agent will run LOCKED (commands rejected)."
fi

# Create systemd service file
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
SERVICE_ARGS=""
if [ "$SERVICE_MODE" = "ping-pong" ]; then
    SERVICE_ARGS="--ping-pong"
fi

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Infinibay Service
Documentation=https://github.com/infinibay/infiniservice
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_PATH
ExecStart=$DEST_EXE $SERVICE_ARGS
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Security settings
# Note: Relaxed security settings because infiniservice needs to execute
# arbitrary scripts that may write anywhere on the filesystem
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=false
ProtectHome=false

# Environment
Environment=RUST_LOG=info
EnvironmentFile=-/etc/environment
# Per-VM HMAC secret (root-only 0600 file). Optional (-) so the service still
# starts without it, in which case the agent runs locked and rejects commands.
EnvironmentFile=-/etc/infiniservice/agent.env

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Created systemd service file: $SERVICE_FILE"

# Set proper permissions
chown root:root "$INSTALL_PATH" -R
chmod 755 "$INSTALL_PATH"

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo "✅ Service enabled for auto-start"

# Start the service
echo "🚀 Starting Infiniservice..."
if systemctl start "$SERVICE_NAME"; then
    echo "✅ Infiniservice started successfully!"
else
    echo "⚠️ Service created but failed to start. Check logs with: journalctl -u $SERVICE_NAME"
fi

# Create uninstall script
UNINSTALL_SCRIPT="$INSTALL_PATH/uninstall.sh"
cat > "$UNINSTALL_SCRIPT" << 'EOF'
#!/bin/bash

# Infiniservice Uninstall Script
echo "🛑 Uninstalling Infiniservice..."

SERVICE_NAME="infiniservice"
INSTALL_PATH="/opt/infiniservice"
USER_NAME="infiniservice"

# Stop and disable service
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true

# Remove service file
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload

# Remove environment variables
sed -i '/INFINIBAY_VM_ID/d' /etc/environment 2>/dev/null || true
sed -i '/INFINISERVICE_MODE/d' /etc/environment 2>/dev/null || true

# Remove the per-VM secret
rm -rf /etc/infiniservice 2>/dev/null || true

# Remove user
userdel "$USER_NAME" 2>/dev/null || true

# Remove installation directory
rm -rf "$INSTALL_PATH"

echo "✅ Infiniservice uninstalled successfully!"
EOF

chmod +x "$UNINSTALL_SCRIPT"
echo "✅ Created uninstall script: $UNINSTALL_SCRIPT"

# Display service status
echo ""
echo "📊 Service Status:"
systemctl status "$SERVICE_NAME" --no-pager -l || true

echo ""
echo "🎉 Infiniservice installation completed successfully!"
echo "📝 Configuration file: $CONFIG_PATH"
echo "📋 Service logs: journalctl -u $SERVICE_NAME -f"
echo "🗑️ To uninstall, run: $UNINSTALL_SCRIPT"

if [ "$SERVICE_MODE" = "ping-pong" ]; then
    echo ""
    echo "🏓 Service is running in PING-PONG test mode"
    echo "   Check the backend logs to see ping-pong communication"
    echo "   Monitor logs with: journalctl -u $SERVICE_NAME -f"
fi
