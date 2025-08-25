# VirtIO Serial Communication

## Overview

VirtIO-serial is a paravirtualized character device that provides efficient communication channels between the guest VM and the host system. InfiniService uses VirtIO-serial as its primary communication mechanism for metrics reporting and command execution.

## Architecture

### VirtIO-Serial Device Stack

```
┌─────────────────────────────────────────┐
│           Host System (QEMU/KVM)         │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │     VirtIO-Serial Controller       │ │
│  │  ┌──────────┐    ┌──────────┐    │ │
│  │  │  Port 0  │    │  Port 1  │    │ │
│  │  └────┬─────┘    └────┬─────┘    │ │
│  └───────┼───────────────┼───────────┘ │
│          │               │              │
│    Unix Socket      Unix Socket         │
│  /tmp/vm-uuid.sock  (other ports)       │
└──────────┼──────────────────────────────┘
           │
    ══════════════════ (VirtIO Bus)
           │
┌──────────┼──────────────────────────────┐
│          │        Guest VM               │
│  ┌───────▼───────────────────────────┐ │
│  │     VirtIO-Serial Driver          │ │
│  │  ┌──────────┐    ┌──────────┐    │ │
│  │  │/dev/vport│    │/dev/vport│    │ │
│  │  │   0p1    │    │   1p1    │    │ │
│  │  └────┬─────┘    └──────────┘    │ │
│  └───────┼───────────────────────────┘ │
│          │                              │
│    InfiniService                        │
└─────────────────────────────────────────┘
```

## Device Configuration

### QEMU/Libvirt Configuration

XML configuration for libvirt:

```xml
<devices>
  <!-- VirtIO-Serial Controller -->
  <controller type='virtio-serial' index='0'>
    <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
  </controller>
  
  <!-- InfiniService Channel -->
  <channel type='unix'>
    <source mode='bind' path='/tmp/vm-550e8400.sock'/>
    <target type='virtio' name='org.infinibay.agent'/>
    <address type='virtio-serial' controller='0' bus='0' port='1'/>
  </channel>
</devices>
```

QEMU command line:

```bash
qemu-system-x86_64 \
  -device virtio-serial-pci,id=virtio-serial0,bus=pci.0 \
  -chardev socket,id=channel0,path=/tmp/vm-uuid.sock,server,nowait \
  -device virtserialport,bus=virtio-serial0.0,nr=1,chardev=channel0,\
          id=channel0,name=org.infinibay.agent
```

### Guest Device Detection

#### Linux

VirtIO-serial devices appear as character devices:

```bash
# Named ports (preferred)
/dev/virtio-ports/org.infinibay.agent

# Generic ports
/dev/vport0p1  # Controller 0, Port 1
/dev/vport1p1  # Controller 1, Port 1

# Check available devices
ls -la /dev/virtio-ports/
ls -la /dev/vport*
```

Device properties:
```bash
# Get device information
udevadm info /dev/vport0p1

# Check device major/minor numbers
stat /dev/vport0p1
```

#### Windows

VirtIO-serial devices appear as COM ports:

```powershell
# List COM ports
Get-WmiObject Win32_SerialPort | Select Name, DeviceID, Description

# Check for VirtIO devices
Get-WmiObject Win32_PnPEntity | Where {$_.Name -like "*VirtIO*"}

# Registry location
HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AF4&DEV_1003
```

## Device Detection Implementation

### Linux Detection Strategy

```rust
fn detect_linux_device(debug: bool) -> Result<PathBuf> {
    // Priority order for device detection
    let candidates = [
        // 1. Named port (most specific)
        "/dev/virtio-ports/org.infinibay.agent",
        
        // 2. Common guest agent ports
        "/dev/virtio-ports/org.qemu.guest_agent.0",
        
        // 3. Generic VirtIO ports
        "/dev/vport0p1",
        "/dev/vport1p1",
        
        // 4. Scan for any VirtIO port
        "/dev/vport*",
    ];
    
    for path in candidates {
        if Path::new(path).exists() {
            // Verify it's a character device
            let metadata = fs::metadata(path)?;
            if metadata.file_type().is_char_device() {
                return Ok(PathBuf::from(path));
            }
        }
    }
    
    // Fallback: scan /dev directory
    scan_dev_directory()
}
```

### Windows Detection Strategy

```rust
fn detect_windows_device(debug: bool) -> Result<PathBuf> {
    // Use Windows Setup API to enumerate devices
    let devices = enumerate_com_ports()?;
    
    for device in devices {
        // Check if it's a VirtIO device
        if is_virtio_device(&device) {
            // Test if we can open it
            if test_device_access(&device.path) {
                return Ok(device.path);
            }
        }
    }
    
    Err(anyhow!("No VirtIO device found"))
}

fn is_virtio_device(device: &ComPortInfo) -> bool {
    // Check hardware ID for VirtIO vendor
    device.hardware_id.contains("VEN_1AF4") &&
    (device.hardware_id.contains("DEV_1003") ||  // Legacy
     device.hardware_id.contains("DEV_1043") ||  // Modern
     device.hardware_id.contains("DEV_1044"))    // Console
}
```

## Communication Protocol

### Opening the Device

```rust
// Linux
let file = OpenOptions::new()
    .read(true)
    .write(true)
    .open("/dev/vport0p1")?;

// Windows
use serialport::SerialPort;
let port = serialport::new("\\\\.\\COM3", 115200)
    .timeout(Duration::from_millis(100))
    .open()?;
```

### Reading and Writing

```rust
pub async fn send_message<T: Serialize>(&mut self, msg: &T) -> Result<()> {
    let json = serde_json::to_string(msg)?;
    let data = format!("{}\n", json); // Newline delimiter
    
    self.device.write_all(data.as_bytes())?;
    self.device.flush()?;
    Ok(())
}

pub async fn receive_message(&mut self) -> Result<String> {
    let mut reader = BufReader::new(&mut self.device);
    let mut line = String::new();
    
    reader.read_line(&mut line)?;
    Ok(line.trim().to_string())
}
```

## Performance Characteristics

### Throughput

| Operation | Typical Performance |
|-----------|-------------------|
| Small message (<1KB) | <1ms latency |
| Large message (100KB) | 5-10ms |
| Sustained throughput | 100+ MB/s |
| IOPS | 10,000+ ops/sec |

### Buffer Management

```rust
const READ_BUFFER_SIZE: usize = 65536;   // 64KB
const WRITE_BUFFER_SIZE: usize = 65536;  // 64KB
const MAX_MESSAGE_SIZE: usize = 1048576; // 1MB

pub struct VirtioSerial {
    device: File,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
}
```

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Device not found | VirtIO driver not installed | Install VirtIO drivers |
| Permission denied | Insufficient privileges | Run as root/admin |
| Device busy | Already in use | Check for other processes |
| Broken pipe | Host disconnected | Reconnect |
| Buffer overflow | Message too large | Split message |

### Recovery Strategies

```rust
async fn connect_with_retry(&mut self) -> Result<()> {
    let mut delay = Duration::from_secs(1);
    let max_delay = Duration::from_secs(60);
    
    loop {
        match self.open_device() {
            Ok(_) => return Ok(()),
            Err(e) => {
                warn!("Connection failed: {}, retrying in {:?}", e, delay);
                sleep(delay).await;
                
                // Exponential backoff
                delay = (delay * 2).min(max_delay);
            }
        }
    }
}
```

## Security Considerations

### Device Permissions

Linux:
```bash
# Default permissions (root only)
crw------- 1 root root 248, 1 /dev/vport0p1

# Allow service user access
sudo chmod 666 /dev/vport0p1
# OR
sudo chown infiniservice:infiniservice /dev/vport0p1
```

Windows:
- Runs as LocalSystem or specific service account
- COM port access controlled by Windows security

### Channel Isolation

- VirtIO-serial provides isolated channels
- No network exposure
- Host-controlled access
- Per-VM socket isolation

## Troubleshooting

### Diagnostic Commands

Linux:
```bash
# Check if VirtIO modules are loaded
lsmod | grep virtio

# Check device nodes
ls -la /dev/vport* /dev/virtio-ports/

# Monitor device I/O
strace -e read,write -p $(pidof infiniservice)

# Check device major/minor
cat /proc/devices | grep virtio
```

Windows:
```powershell
# Check Device Manager
devmgmt.msc

# List VirtIO devices
Get-WmiObject Win32_PnPEntity | Where {$_.Name -like "*VirtIO*"}

# Check driver version
Get-WmiObject Win32_PnPSignedDriver | Where {$_.DeviceName -like "*VirtIO*"}
```

### Common Issues

#### Device Not Found

1. Check VirtIO drivers are installed:
   - Linux: `modprobe virtio_console`
   - Windows: Install from virtio-win ISO

2. Verify QEMU configuration includes channel

3. Check device permissions

#### Communication Failures

1. Verify host socket exists:
   ```bash
   ls -la /tmp/vm-*.sock
   ```

2. Check host service is listening:
   ```bash
   lsof /tmp/vm-uuid.sock
   ```

3. Test with manual connection:
   ```bash
   # Host side
   socat UNIX-LISTEN:/tmp/test.sock -
   
   # Guest side
   echo "test" > /dev/vport0p1
   ```

## Best Practices

1. **Always Check Device Availability**: Before opening
2. **Use Buffered I/O**: For efficiency
3. **Implement Reconnection Logic**: Handle disconnections
4. **Validate Message Size**: Prevent buffer overflows
5. **Log Device Operations**: For debugging
6. **Handle Partial Reads/Writes**: May occur under load
7. **Clean Shutdown**: Close device properly

## Platform-Specific Notes

### Linux

- Requires `CONFIG_VIRTIO_CONSOLE` kernel option
- udev rules can create persistent names
- SELinux may require context adjustments

### Windows

- Requires VirtIO-Win drivers
- May need to disable driver signature enforcement
- Windows Defender may flag as suspicious

## Future Enhancements

1. **Multiple Channels**: Support multiple communication channels
2. **Encryption**: Add TLS/encryption layer
3. **Compression**: Compress large messages
4. **Multiplexing**: Multiple logical channels over single device
5. **Flow Control**: Implement proper flow control
6. **Zero-Copy**: Optimize for zero-copy operations