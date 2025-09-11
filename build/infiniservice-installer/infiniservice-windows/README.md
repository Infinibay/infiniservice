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
