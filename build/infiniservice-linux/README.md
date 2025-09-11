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
