# Infiniservice

A multiplatform background service written in Rust that runs on Windows and Linux VMs to collect system information and communicate with the host via virtio-serial.

## Overview

Infiniservice is designed to be installed on every VM in the Infinibay infrastructure. It operates as a lightweight background service that:

- Collects system metrics and information
- Communicates with the host system via virtio-serial
- Runs continuously with configurable collection intervals
- Supports both Windows and Linux platforms

## Architecture

The service is structured into several modules:

- **config**: Configuration management and loading
- **collector**: System information collection
- **communication**: Virtio-serial communication interface
- **service**: Main service orchestration and lifecycle management

## Building

```bash
# Build the project
cargo build

# Build for release
cargo build --release

# Run the service
cargo run
```

## Configuration

The service uses a default configuration that can be customized:

- **Collection Interval**: 30 seconds (configurable)
- **VirtIO Channel**:
  - Channel Name: `org.infinibay.agent`
  - Windows: Accessed via VirtIO Serial Port (COMx) provided by vioserial driver
  - Linux: `/dev/virtio-ports/org.infinibay.agent`
- **Log Level**: info

## VirtIO Configuration

InfiniService requires proper VirtIO serial device configuration to communicate with the host system. The service communicates through VirtIO channels that must be configured at the hypervisor level.

### Quick Setup

For detailed configuration examples and automation scripts, see:
- **Comprehensive Guide**: [docs/vm-configuration.md](../docs/vm-configuration.md)
- **Automation Script**: [scripts/configure-vm.sh](scripts/configure-vm.sh)
- **Windows Diagnostics**: [scripts/diagnose-virtio.ps1](scripts/diagnose-virtio.ps1)

### Hypervisor-Specific Requirements

**QEMU/KVM**: Requires VirtIO serial controller with `org.infinibay.agent` channel
```bash
# Quick configuration check
./scripts/configure-vm.sh detect
./scripts/configure-vm.sh configure --vm-name "your-vm-name"
```

**VMware**: Requires serial port configuration in .vmx file (provides standard serial ports, not VirtIO)
```ini
serial0.present = "TRUE"
serial0.fileType = "pipe"
serial0.fileName = "\\.\\pipe\\infinibay-agent"
```

**VirtualBox**: Requires serial port setup with host pipe communication (provides standard serial ports, not VirtIO)
```bash
VBoxManage modifyvm "VM-Name" --uart1 0x3F8 4
VBoxManage modifyvm "VM-Name" --uartmode1 server /tmp/infinibay-agent
```

**Note**: VMware and VirtualBox provide standard serial ports that appear as COM ports in the guest OS, while QEMU/KVM provides true VirtIO serial devices.

## Troubleshooting

### Common VirtIO Issues

#### DEV_1043 Device Detected but Not Accessible

**Symptoms**: Windows Device Manager shows VirtIO Serial Device (DEV_1043), but InfiniService reports "Access denied" or "Win32 error 5".

**Solutions**:
1. **Run as Administrator** (Most Common Fix):
   ```cmd
   # Always run InfiniService as Administrator
   runas /user:Administrator "C:\Program Files\InfiniService\infiniservice.exe"
   ```

2. **Check VirtIO Driver Installation**:
   ```powershell
   # Verify VirtIO devices
   Get-PnpDevice | Where-Object {$_.FriendlyName -like "*VirtIO*"}

   # Reinstall driver if needed
   pnputil /delete-driver vioserial.inf /uninstall /force
   pnputil /add-driver "C:\virtio\vioserial\w10\amd64\vioserial.inf" /install
   ```

3. **Run Diagnostics**:
   ```cmd
   # Use built-in diagnostic mode
   infiniservice.exe --diag

   # Or run comprehensive PowerShell diagnostics
   powershell -ExecutionPolicy Bypass -File scripts\diagnose-virtio.ps1
   ```

#### Access Denied Errors (Win32 Error 5)

**Cause**: Insufficient privileges or security restrictions

**Solutions**:
- Run InfiniService as Administrator
- Add Windows Defender exclusions for InfiniService
- Verify user account has "Log on as a service" right
- Temporarily disable UAC for testing

#### Missing COM Ports Despite Driver Installation

**Important**: VirtIO serial devices don't create traditional COM ports. InfiniService communicates directly with VirtIO devices through the Windows VirtIO API, not through COM ports.

**If you see this issue**:
- This is normal behavior for VirtIO serial devices
- Verify VirtIO drivers are installed correctly
- Check that the hypervisor has VirtIO serial channels configured
- Use diagnostic tools to verify device accessibility

### Platform-Specific Issues

#### Windows Issues

**Administrator Privilege Requirements**:
- InfiniService requires Administrator privileges to access VirtIO devices
- Install as Windows service with proper privileges
- Ensure service account has "Log on as a service" right

**Driver Installation Problems**:
```powershell
# Check driver status
Get-PnpDevice -FriendlyName "*VirtIO Serial*" | Format-List *

# Force driver update
Get-PnpDevice -FriendlyName "*VirtIO Serial*" | Update-PnpDevice

# Check for driver conflicts
Get-WmiObject Win32_SystemDriver | Where-Object {$_.Name -like "*virtio*"}
```

**Windows Defender and Security**:
- Add InfiniService executable to Windows Defender exclusions
- Check Windows Event Log for security-related blocks
- Verify no third-party antivirus is blocking VirtIO access

#### Linux Issues

**Device Permissions**:
```bash
# Check VirtIO devices
ls -la /dev/vport*

# Fix permissions
sudo chmod 666 /dev/vport*
sudo usermod -a -G dialout $USER

# Create udev rule for persistent permissions
echo 'KERNEL=="vport*", ATTR{name}=="org.infinibay.agent", MODE="0666", SYMLINK+="infinibay-agent"' | sudo tee /etc/udev/rules.d/99-infinibay.rules
sudo udevadm control --reload-rules
```

**VirtIO Module Loading**:
```bash
# Load VirtIO modules
sudo modprobe virtio_console
sudo modprobe virtio_serial

# Verify modules
lsmod | grep virtio

# Make persistent
echo "virtio_console" | sudo tee -a /etc/modules
echo "virtio_serial" | sudo tee -a /etc/modules
```

**SELinux/AppArmor Issues**:
```bash
# SELinux: Check for denials
sudo ausearch -m avc -ts recent | grep virtio

# SELinux: Allow VirtIO access
sudo setsebool -P virt_use_comm on

# AppArmor: Check logs
sudo dmesg | grep DENIED | grep virtio

# AppArmor: Set to complain mode temporarily
sudo aa-complain /usr/sbin/infiniservice
```

### Diagnostic Commands

#### Quick Diagnostics

**Windows**:
```cmd
# Run built-in diagnostics
infiniservice.exe --diag

# Check VirtIO devices
powershell "Get-PnpDevice | Where-Object {$_.InstanceId -like '*DEV_1043*'}"

# Check services
sc query infiniservice
```

**Linux**:
```bash
# Check VirtIO devices
ls -la /sys/class/virtio-ports/
cat /sys/class/virtio-ports/vport*/name

# Check service status
systemctl status infiniservice

# Test device access
echo "test" > /dev/vport0p1
```

#### Comprehensive Diagnostics

Use the provided diagnostic scripts for detailed analysis:

```bash
# Automated VM configuration check
./scripts/configure-vm.sh diagnose

# Windows-specific VirtIO diagnostics (run on Windows guest)
powershell -ExecutionPolicy Bypass -File scripts\diagnose-virtio.ps1

# Validate existing configuration
./scripts/configure-vm.sh validate --vm-name "your-vm-name"
```

### Installation Troubleshooting

#### Service Registration Failures

**Windows**:
```cmd
# Manual service installation
sc create infiniservice binPath="C:\Program Files\InfiniService\infiniservice.exe" start=auto
sc description infiniservice "InfiniBay VM Information Service"

# Check service status
sc query infiniservice

# Start service
sc start infiniservice
```

**Linux**:
```bash
# Manual systemd service installation
sudo cp infiniservice.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable infiniservice
sudo systemctl start infiniservice

# Check service status
sudo systemctl status infiniservice
```

#### Permission Denied During Installation

- Run installer as Administrator (Windows) or with sudo (Linux)
- Check that target directories are writable
- Verify no existing service is running
- Ensure antivirus is not blocking installation

#### VirtIO Device Not Found During Startup

1. **Verify Hypervisor Configuration**:
   - Check VM configuration includes VirtIO serial devices
   - Verify channel names match expected values
   - Ensure VM is using correct VirtIO drivers

2. **Check Device Availability**:
   ```bash
   # Linux
   ls -la /dev/vport* /sys/class/virtio-ports/

   # Windows
   powershell "Get-PnpDevice | Where-Object {$_.FriendlyName -like '*VirtIO*'}"
   ```

3. **Validate Configuration**:
   ```bash
   # Use automation script to validate
   ./scripts/configure-vm.sh validate --vm-name "your-vm-name"
   ```

### Quick Fixes Summary

1. **Windows Access Denied**: Run as Administrator
2. **Linux Permission Denied**: Add user to dialout group, fix device permissions
3. **Device Not Found**: Check hypervisor VirtIO configuration
4. **Driver Issues**: Reinstall VirtIO drivers
5. **Service Won't Start**: Check logs, verify configuration file
6. **Communication Fails**: Validate VirtIO channel configuration

### When to Contact Support

Contact support if you encounter:
- Persistent access denied errors after trying all solutions
- VirtIO devices not appearing despite correct hypervisor configuration
- Service crashes or unexpected behavior
- Performance issues or high resource usage

**Include in Support Requests**:
- Output from diagnostic commands (`--diag` flag)
- Hypervisor type and version
- Operating system version
- VirtIO driver version
- InfiniService logs and error messages

## Dependencies

The project uses only well-maintained Rust libraries:

- **tokio**: Async runtime
- **serde**: Serialization framework
- **log/env_logger**: Logging infrastructure
- **anyhow/thiserror**: Error handling
- **config**: Configuration management
- **dirs**: Cross-platform directory utilities

## FAQ

### Why does InfiniService need VirtIO?

VirtIO provides a standardized, high-performance communication channel between the guest VM and the host system. This allows InfiniService to efficiently transmit system information and receive commands without relying on network-based communication, which may not always be available or reliable.

### How do I verify VirtIO is working?

**Quick Check**:
```bash
# Run diagnostic mode
infiniservice.exe --diag  # Windows
./infiniservice --diag   # Linux

# Or use automation script
./scripts/configure-vm.sh test --vm-name "your-vm-name"
```

**Manual Verification**:
- Windows: Check Device Manager for VirtIO Serial devices
- Linux: Check for `/dev/vport*` devices and `/sys/class/virtio-ports/`

### What to do when access is denied?

1. **Windows**: Run as Administrator (most common solution)
2. **Linux**: Check device permissions and user groups
3. **Both**: Verify VirtIO drivers are properly installed
4. **Both**: Check hypervisor VirtIO configuration

### How to run diagnostics?

InfiniService includes built-in diagnostic capabilities:

```bash
# Built-in diagnostics
infiniservice --diag

# Comprehensive Windows diagnostics
powershell -ExecutionPolicy Bypass -File scripts\diagnose-virtio.ps1

# VM configuration diagnostics
./scripts/configure-vm.sh diagnose
```

### When to contact support?

Contact support when:
- Diagnostic tools show errors you can't resolve
- VirtIO devices are missing despite correct configuration
- Service fails to start after following troubleshooting steps
- Performance issues persist after optimization

Always include diagnostic output and system information in support requests.

## Links and References

### Documentation
- **[VM Configuration Guide](../docs/vm-configuration.md)**: Comprehensive hypervisor configuration examples
- **[Deployment Guide](doc/DEPLOYMENT.md)**: Detailed deployment procedures and VM setup
- **[Project README](../README.md)**: Main project documentation

### Scripts and Tools
- **[VM Configuration Script](scripts/configure-vm.sh)**: Automated VirtIO configuration for different hypervisors
- **[Windows VirtIO Diagnostics](scripts/diagnose-virtio.ps1)**: Comprehensive Windows VirtIO diagnostic tool
- **[Installation Scripts](scripts/)**: Platform-specific installation and setup scripts

### External Resources
- **[VirtIO Drivers](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/)**: Official VirtIO drivers for Windows
- **[QEMU Documentation](https://qemu.readthedocs.io/en/latest/system/devices/virtio-serial.html)**: VirtIO serial device documentation
- **[libvirt Documentation](https://libvirt.org/formatdomain.html#serial-port)**: Domain XML configuration reference

## Development Status

This is the initial project setup. The core functionality is currently implemented as placeholders and TODOs that will be developed based on specific requirements.

## Future Development

- Implement actual system metrics collection
- Add virtio-serial communication protocol
- Create platform-specific installers
- Add configuration file support
- Implement proper error handling and recovery
- Add comprehensive logging and monitoring
