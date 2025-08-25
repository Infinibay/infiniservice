# InfiniService Deployment Guide

## Overview

This guide covers the complete deployment process for InfiniService, from building the binaries to installing them on target VMs and integrating with the Infinibay infrastructure.

## Prerequisites

### Build Environment

- **Rust**: 1.70+ with cargo
- **Cross-compilation tools**:
  - Linux: gcc, make
  - Windows: mingw-w64 (for Linux→Windows builds)
- **Git**: For source code management

### Target Environment

- **Linux VMs**:
  - Systemd-based distributions (Ubuntu, Debian, RHEL, Fedora)
  - VirtIO drivers installed
  - Root or sudo access for installation

- **Windows VMs**:
  - Windows 10/11 or Server 2016+
  - VirtIO drivers installed
  - Administrator privileges for installation

## Building InfiniService

### Quick Build

Use the provided deployment script for automated building:

```bash
cd infiniservice
./deploy.sh
```

This script:
1. Builds Linux and Windows binaries
2. Copies binaries to `/opt/infinibay/infiniservice/binaries/`
3. Copies installation scripts
4. Sets proper permissions

### Manual Build

#### Linux Binary

```bash
# Native build (for current architecture)
cargo build --release

# Cross-compile for x86_64
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# Binary location: target/release/infiniservice
# or: target/x86_64-unknown-linux-gnu/release/infiniservice
```

#### Windows Binary

```bash
# Install Windows target
rustup target add x86_64-pc-windows-gnu

# Install mingw-w64 (Ubuntu/Debian)
sudo apt-get install mingw-w64

# Build Windows binary
cargo build --release --target x86_64-pc-windows-gnu

# Binary location: target/x86_64-pc-windows-gnu/release/infiniservice.exe
```

### Build Optimization

For production builds with size optimization:

```toml
# Cargo.toml
[profile.release]
opt-level = 'z'     # Optimize for size
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit
strip = true        # Strip symbols
```

## Deployment Structure

### Directory Layout

```
/opt/infinibay/infiniservice/
├── binaries/
│   ├── linux/
│   │   ├── infiniservice          # Linux binary
│   │   ├── install-linux.sh       # Installation script
│   │   └── cloud-init-ubuntu.yaml # Cloud-init template
│   └── windows/
│       ├── infiniservice.exe      # Windows binary
│       ├── install-windows.ps1    # Installation script
│       └── test_virtio.bat        # VirtIO test script
├── install/
│   ├── install-linux.sh
│   ├── install-windows.ps1
│   └── cloud-init-ubuntu.yaml
└── metadata.json                  # Version information
```

### Setting Up Deployment Directory

```bash
# Create directory structure
sudo mkdir -p /opt/infinibay/infiniservice/{binaries/{linux,windows},install}

# Copy binaries
sudo cp target/release/infiniservice /opt/infinibay/infiniservice/binaries/linux/
sudo cp target/x86_64-pc-windows-gnu/release/infiniservice.exe \
        /opt/infinibay/infiniservice/binaries/windows/

# Copy installation scripts
sudo cp install/*.sh /opt/infinibay/infiniservice/binaries/linux/
sudo cp install/*.ps1 /opt/infinibay/infiniservice/binaries/windows/
sudo cp install/* /opt/infinibay/infiniservice/install/

# Set permissions
sudo chmod +x /opt/infinibay/infiniservice/binaries/linux/*
sudo chown -R $USER:$USER /opt/infinibay/infiniservice/
```

## Installation Methods

### 1. Unattended Installation (Recommended)

InfiniService is automatically installed during VM provisioning:

#### Windows Unattended

Configured in `unattended.xml`:
```xml
<FirstLogonCommands>
  <SynchronousCommand>
    <Order>10</Order>
    <CommandLine>powershell.exe -ExecutionPolicy Bypass -Command "
      $dir = 'C:\Temp\InfiniService';
      New-Item -ItemType Directory -Force -Path $dir;
      Invoke-WebRequest -Uri 'http://backend:4000/infiniservice/windows/binary' 
                       -OutFile '$dir\infiniservice.exe';
      Invoke-WebRequest -Uri 'http://backend:4000/infiniservice/windows/script' 
                       -OutFile '$dir\install.ps1';
      & '$dir\install.ps1' -ServiceMode 'normal' -VmId 'VM_ID';
      Remove-Item -Path $dir -Recurse -Force
    "</CommandLine>
  </SynchronousCommand>
</FirstLogonCommands>
```

#### Ubuntu Cloud-Init

Configured in `user-data.yaml`:
```yaml
late-commands:
  - |
    cat > /target/var/lib/cloud/scripts/per-instance/install-infiniservice.sh << 'EOF'
    #!/bin/bash
    cd /tmp
    curl -O http://backend:4000/infiniservice/linux/binary
    curl -O http://backend:4000/infiniservice/linux/script
    chmod +x infiniservice install-linux.sh
    ./install-linux.sh normal "VM_ID"
    EOF
  - chmod +x /target/var/lib/cloud/scripts/per-instance/install-infiniservice.sh
```

#### RedHat/Fedora Kickstart

Configured in `kickstart.cfg`:
```bash
%post --log=/root/infiniservice-install.log
cd /tmp
curl -O http://backend:4000/infiniservice/linux/binary
curl -O http://backend:4000/infiniservice/linux/script
chmod +x infiniservice install-linux.sh
./install-linux.sh normal "VM_ID"
%end
```

### 2. Manual Installation

#### Linux Manual Installation

```bash
# Download files
cd /tmp
wget http://backend:4000/infiniservice/linux/binary -O infiniservice
wget http://backend:4000/infiniservice/linux/script -O install-linux.sh

# Make executable
chmod +x infiniservice install-linux.sh

# Install with VM ID
sudo ./install-linux.sh normal "your-vm-id-here"

# Verify installation
systemctl status infiniservice
```

#### Windows Manual Installation

```powershell
# Download files
$tempDir = "C:\Temp\InfiniService"
New-Item -ItemType Directory -Force -Path $tempDir
Set-Location $tempDir

Invoke-WebRequest -Uri "http://backend:4000/infiniservice/windows/binary" `
                  -OutFile "infiniservice.exe"
Invoke-WebRequest -Uri "http://backend:4000/infiniservice/windows/script" `
                  -OutFile "install-windows.ps1"

# Install as Administrator
.\install-windows.ps1 -ServiceMode "normal" -VmId "your-vm-id-here"

# Verify installation
Get-Service Infiniservice
```

### 3. Ansible Deployment

```yaml
---
- name: Deploy InfiniService
  hosts: vms
  become: yes
  vars:
    backend_host: "192.168.1.100"
    backend_port: "4000"
    
  tasks:
    - name: Create temp directory
      file:
        path: /tmp/infiniservice
        state: directory
        
    - name: Download InfiniService binary
      get_url:
        url: "http://{{ backend_host }}:{{ backend_port }}/infiniservice/linux/binary"
        dest: /tmp/infiniservice/infiniservice
        mode: '0755'
        
    - name: Download installation script
      get_url:
        url: "http://{{ backend_host }}:{{ backend_port }}/infiniservice/linux/script"
        dest: /tmp/infiniservice/install-linux.sh
        mode: '0755'
        
    - name: Install InfiniService
      command: ./install-linux.sh normal "{{ vm_id }}"
      args:
        chdir: /tmp/infiniservice
        
    - name: Ensure service is running
      systemd:
        name: infiniservice
        state: started
        enabled: yes
```

## Configuration

### Environment Variables

Set during installation:

```bash
# Linux (/etc/environment)
INFINIBAY_VM_ID=550e8400-e29b-41d4-a716-446655440000
INFINISERVICE_MODE=normal
RUST_LOG=info

# Windows (System Environment Variables)
INFINIBAY_VM_ID=550e8400-e29b-41d4-a716-446655440000
INFINISERVICE_MODE=normal
RUST_LOG=info
```

### Configuration File

Location: `/opt/infiniservice/config.toml` (Linux) or `C:\ProgramData\InfiniService\config.toml` (Windows)

```toml
# Collection interval in seconds
collection_interval = 30

# Logging level
log_level = "info"

# Service name
service_name = "infiniservice"

# VirtIO serial device path (auto-detected if empty)
virtio_serial_path = ""

# Enable debug mode
debug_mode = false

# Command execution timeout (seconds)
command_timeout = 30

# Maximum message size (bytes)
max_message_size = 1048576
```

### Service Configuration

#### Linux (systemd)

Location: `/etc/systemd/system/infiniservice.service`

```ini
[Unit]
Description=Infinibay Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/infiniservice/infiniservice
Restart=always
RestartSec=5
Environment=RUST_LOG=info
EnvironmentFile=-/etc/environment

[Install]
WantedBy=multi-user.target
```

#### Windows (Service)

Configured via PowerShell:
```powershell
New-Service -Name "Infiniservice" `
            -BinaryPathName "C:\Program Files\InfiniService\infiniservice.exe" `
            -DisplayName "Infinibay Service" `
            -StartupType Automatic `
            -Description "VM monitoring and management service"
```

## Backend Integration

### HTTP Endpoints

The backend must expose these endpoints:

```typescript
// Backend routes (Express.js example)
app.get('/infiniservice/:platform/binary', (req, res) => {
  const platform = req.params.platform; // 'linux' or 'windows'
  const binaryPath = path.join(INFINIBAY_BASE_DIR, 
    'infiniservice/binaries', platform,
    platform === 'windows' ? 'infiniservice.exe' : 'infiniservice');
  res.sendFile(binaryPath);
});

app.get('/infiniservice/:platform/script', (req, res) => {
  const platform = req.params.platform;
  const scriptPath = path.join(INFINIBAY_BASE_DIR,
    'infiniservice/binaries', platform,
    platform === 'windows' ? 'install-windows.ps1' : 'install-linux.sh');
  res.sendFile(scriptPath);
});

app.get('/infiniservice/metadata', (req, res) => {
  res.json({
    version: '0.1.0',
    platforms: ['linux', 'windows'],
    updated: new Date().toISOString()
  });
});
```

### VirtIO Configuration

QEMU VM configuration must include VirtIO-serial device:

```xml
<channel type='unix'>
  <source mode='bind' path='/tmp/vm-UUID.sock'/>
  <target type='virtio' name='org.infinibay.agent'/>
  <address type='virtio-serial' controller='0' bus='0' port='1'/>
</channel>
```

## Monitoring Deployment

### Health Checks

#### Linux Health Check

```bash
#!/bin/bash
# check-infiniservice.sh

# Check if service is running
if systemctl is-active --quiet infiniservice; then
    echo "✓ Service is running"
else
    echo "✗ Service is not running"
    exit 1
fi

# Check if VM ID is set
if [ -n "$INFINIBAY_VM_ID" ]; then
    echo "✓ VM ID is set: $INFINIBAY_VM_ID"
else
    echo "✗ VM ID is not set"
    exit 1
fi

# Check VirtIO device
if ls /dev/vport* 2>/dev/null || ls /dev/virtio-ports/* 2>/dev/null; then
    echo "✓ VirtIO device found"
else
    echo "✗ VirtIO device not found"
    exit 1
fi
```

#### Windows Health Check

```powershell
# Check-InfiniService.ps1

# Check service status
$service = Get-Service -Name "Infiniservice" -ErrorAction SilentlyContinue
if ($service.Status -eq "Running") {
    Write-Host "✓ Service is running"
} else {
    Write-Host "✗ Service is not running"
    exit 1
}

# Check VM ID
$vmId = [System.Environment]::GetEnvironmentVariable("INFINIBAY_VM_ID", "Machine")
if ($vmId) {
    Write-Host "✓ VM ID is set: $vmId"
} else {
    Write-Host "✗ VM ID is not set"
    exit 1
}

# Check COM ports
$comPorts = Get-WmiObject Win32_SerialPort | Where-Object {$_.Name -like "*VirtIO*"}
if ($comPorts) {
    Write-Host "✓ VirtIO device found"
} else {
    Write-Host "✗ VirtIO device not found"
    exit 1
}
```

### Deployment Verification

1. **Service Status**: Verify service is running
2. **Log Analysis**: Check for errors in logs
3. **Metrics Reception**: Confirm backend receives metrics
4. **Command Execution**: Test command functionality
5. **Resource Usage**: Monitor CPU/memory usage

## Troubleshooting

### Common Deployment Issues

#### Binary Not Found

**Problem**: Installation script can't find binary
**Solution**:
```bash
# Check backend endpoint
curl -I http://backend:4000/infiniservice/linux/binary

# Verify file exists
ls -la /opt/infinibay/infiniservice/binaries/linux/
```

#### Service Won't Start

**Problem**: Service fails to start after installation
**Solution**:
```bash
# Check logs
journalctl -u infiniservice -n 50

# Run manually for debugging
RUST_LOG=debug /opt/infiniservice/infiniservice --debug
```

#### VirtIO Device Not Available

**Problem**: InfiniService can't find VirtIO device
**Solution**:
```bash
# Linux: Check for device
ls -la /dev/vport* /dev/virtio-ports/

# Windows: Check Device Manager for VirtIO Serial Device

# Run diagnostics
infiniservice --diagnose
```

#### Permission Denied

**Problem**: Service lacks permissions
**Solution**:
```bash
# Linux: Run as root or adjust permissions
chmod 666 /dev/vport*

# Windows: Run as LocalSystem or Administrator
```

## Security Hardening

### Linux Security

```bash
# Create restricted user
useradd -r -s /bin/false infiniservice

# Set file permissions
chown root:root /opt/infiniservice/infiniservice
chmod 755 /opt/infiniservice/infiniservice

# SELinux context (if applicable)
semanage fcontext -a -t bin_t /opt/infiniservice/infiniservice
restorecon -v /opt/infiniservice/infiniservice

# AppArmor profile (if applicable)
aa-enforce /etc/apparmor.d/infiniservice
```

### Windows Security

```powershell
# Run as restricted service account
$account = "NT AUTHORITY\LocalService"
Set-Service -Name "Infiniservice" -StartupType Automatic `
            -Credential $account

# Set ACLs
$acl = Get-Acl "C:\Program Files\InfiniService"
$acl.SetAccessRuleProtection($true, $false)
Set-Acl "C:\Program Files\InfiniService" $acl
```

## Updating InfiniService

### Rolling Update Process

1. **Build New Version**
```bash
cargo build --release
./deploy.sh
```

2. **Update Backend Binaries**
```bash
sudo cp target/release/infiniservice \
        /opt/infinibay/infiniservice/binaries/linux/
```

3. **Update VMs** (one at a time)
```bash
# On each VM
systemctl stop infiniservice
wget http://backend:4000/infiniservice/linux/binary -O /opt/infiniservice/infiniservice
systemctl start infiniservice
```

### Automated Updates

Use configuration management tools:
- Ansible playbooks
- Puppet manifests
- Chef cookbooks
- Salt states

## Monitoring Metrics

### Prometheus Integration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'infiniservice'
    static_configs:
      - targets: ['backend:4000']
    metrics_path: '/metrics/vms'
```

### Grafana Dashboard

Import dashboard JSON for VM monitoring:
- CPU usage trends
- Memory utilization
- Disk I/O patterns
- Network traffic
- Service availability

## Best Practices

1. **Version Control**: Tag releases in Git
2. **Testing**: Test on non-production VMs first
3. **Rollback Plan**: Keep previous version available
4. **Monitoring**: Set up alerts for service failures
5. **Documentation**: Document deployment procedures
6. **Automation**: Use CI/CD for builds
7. **Security**: Regular security updates
8. **Logging**: Centralize logs for analysis