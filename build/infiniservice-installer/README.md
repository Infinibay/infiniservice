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
