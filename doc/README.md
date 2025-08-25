# InfiniService Documentation

## Overview

InfiniService is a high-performance, cross-platform background service written in Rust that enables real-time monitoring, metrics collection, and remote management of virtual machines in the Infinibay infrastructure. It runs as a system service on both Windows and Linux VMs, communicating with the host system via VirtIO-serial channels.

## Purpose

InfiniService serves as the guest agent within virtual machines, providing:

- **Real-time Metrics Collection**: CPU, memory, disk, network, and process monitoring
- **Bidirectional Communication**: Command execution and response handling via VirtIO-serial
- **Cross-platform Support**: Native Windows service and Linux systemd integration
- **Secure Remote Management**: Safe and unsafe command execution frameworks
- **Application Monitoring**: Track installed applications and their usage patterns
- **Service Management**: Control and monitor system services
- **Package Management**: Install, remove, and update software packages

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Host System (Infinibay Backend)         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │   VirtioSocketWatcherService (Node.js/TypeScript)   │   │
│  └──────────────────┬──────────────────────────────────┘   │
│                     │                                        │
│              Socket Connection                               │
│           (/tmp/vm-{uuid}.sock)                             │
└─────────────────────┼────────────────────────────────────────┘
                      │
         ┌────────────▼────────────┐
         │   QEMU VirtIO-Serial    │
         │   Character Device      │
         └────────────┬────────────┘
                      │
┌─────────────────────┼────────────────────────────────────────┐
│                VM Guest                                       │
│         ┌───────────▼────────────┐                          │
│         │  VirtIO-Serial Device  │                          │
│         │  /dev/vport* (Linux)   │                          │
│         │  \\.\COM* (Windows)    │                          │
│         └───────────┬────────────┘                          │
│                     │                                        │
│  ┌──────────────────▼──────────────────────────────────┐   │
│  │              InfiniService (Rust)                    │   │
│  │                                                      │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐│   │
│  │  │ Collector   │  │Communication │  │  Commands  ││   │
│  │  │   Module    │  │   Module     │  │  Executor  ││   │
│  │  └─────────────┘  └──────────────┘  └────────────┘│   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. **Service Module** (`src/service.rs`)
- Main service orchestration and lifecycle management
- Coordinates metrics collection and command handling
- Manages the main event loop with configurable intervals

### 2. **Collector Module** (`src/collector.rs`)
- System information gathering using platform-specific APIs
- Metrics aggregation and formatting
- Performance-optimized data collection with caching

### 3. **Communication Module** (`src/communication.rs`)
- VirtIO-serial device detection and management
- Message serialization/deserialization
- Bidirectional command and response handling

### 4. **Command Framework** (`src/commands/`)
- Safe command execution with validation
- Unsafe command execution for administrative tasks
- Service control, package management, and process management

### 5. **Platform-Specific Implementations**
- **Windows** (`src/windows_com.rs`): COM port detection, Windows service integration
- **Linux**: Native VirtIO device handling, systemd integration

## Key Features

### Real-time Metrics Collection

InfiniService collects comprehensive system metrics every 30 seconds (configurable):

- **CPU Metrics**: Usage percentage, per-core usage, temperature
- **Memory Metrics**: Total, used, available memory, swap usage
- **Disk Metrics**: Usage statistics, I/O operations per second
- **Network Metrics**: Interface statistics, bytes/packets transferred
- **Process Information**: Running processes with CPU/memory usage
- **Application Tracking**: Installed applications and usage patterns
- **Port Monitoring**: Open ports and listening services
- **Windows Services**: Service status and configuration (Windows only)

### Command Execution Framework

InfiniService supports two types of command execution:

1. **Safe Commands**: Pre-validated operations with structured parameters
   - Service management (start, stop, restart, enable, disable)
   - Package management (install, remove, update, search)
   - Process control (list, kill, top)
   - System information queries

2. **Unsafe Commands**: Raw command execution for administrative tasks
   - Direct shell command execution
   - Custom environment variables
   - Working directory specification
   - Configurable timeout

### Cross-Platform Support

InfiniService is designed to run seamlessly on:

- **Windows**: Windows 10/11, Server 2016/2019/2022
  - Runs as Windows Service
  - PowerShell command execution
  - WMI integration for system metrics

- **Linux**: Ubuntu, Debian, RHEL, Fedora, CentOS
  - Systemd service integration
  - procfs/sysfs for metrics collection
  - Package manager detection (apt, yum, dnf)

## Documentation Structure

- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - Detailed system architecture and design decisions
- **[PROTOCOL.md](./PROTOCOL.md)** - Communication protocol specification
- **[DEPLOYMENT.md](./DEPLOYMENT.md)** - Deployment and installation guide
- **[API.md](./API.md)** - Complete API reference and message formats
- **[DEVELOPMENT.md](./DEVELOPMENT.md)** - Development guide and contribution guidelines

### Infrastructure Documentation
- **[infrastructure/virtio-serial.md](./infrastructure/virtio-serial.md)** - VirtIO serial device communication
- **[infrastructure/cross-platform.md](./infrastructure/cross-platform.md)** - Platform-specific implementations
- **[infrastructure/service-management.md](./infrastructure/service-management.md)** - Service lifecycle management
- **[infrastructure/networking.md](./infrastructure/networking.md)** - Network architecture

### Protocol Documentation
- **[protocol/message-formats.md](./protocol/message-formats.md)** - Message types and structures
- **[protocol/command-execution.md](./protocol/command-execution.md)** - Command framework
- **[protocol/metrics-collection.md](./protocol/metrics-collection.md)** - Data collection
- **[protocol/error-handling.md](./protocol/error-handling.md)** - Error codes and recovery

### Code Patterns Documentation
- **[patterns/async-patterns.md](./patterns/async-patterns.md)** - Async/await patterns
- **[patterns/error-management.md](./patterns/error-management.md)** - Error handling
- **[patterns/serialization.md](./patterns/serialization.md)** - Data serialization
- **[patterns/testing-strategies.md](./patterns/testing-strategies.md)** - Testing approaches

### Integration Documentation
- **[integration/backend-integration.md](./integration/backend-integration.md)** - Backend integration
- **[integration/vm-provisioning.md](./integration/vm-provisioning.md)** - VM provisioning
- **[integration/monitoring-pipeline.md](./integration/monitoring-pipeline.md)** - Monitoring pipeline
- **[integration/security-model.md](./integration/security-model.md)** - Security considerations

## Quick Start

### Building from Source

```bash
# Clone the repository
git clone https://github.com/infinibay/infinibay.git
cd infinibay/infiniservice

# Build for current platform
cargo build --release

# Run with debug output
RUST_LOG=debug cargo run -- --debug
```

### Installation

**Linux:**
```bash
sudo ./install-linux.sh normal <VM_ID>
```

**Windows (PowerShell as Administrator):**
```powershell
.\install-windows.ps1 -ServiceMode "normal" -VmId "<VM_ID>"
```

### Diagnostics

Run diagnostics to check VirtIO device availability:

```bash
# Linux/Windows
infiniservice --diagnose
```

## Configuration

InfiniService uses environment variables and configuration files:

### Environment Variables
- `INFINIBAY_VM_ID` - Unique VM identifier
- `INFINISERVICE_DEVICE` - Override VirtIO device path
- `RUST_LOG` - Logging level (error, warn, info, debug)

### Configuration File (`config.toml`)
```toml
collection_interval = 30
log_level = "info"
service_name = "infiniservice"
virtio_serial_path = ""  # Auto-detected if empty
```

## Monitoring and Logs

### Linux
```bash
# Service status
systemctl status infiniservice

# View logs
journalctl -u infiniservice -f

# Installation logs
cat /var/log/infiniservice_install.log
```

### Windows
```powershell
# Service status
Get-Service Infiniservice

# Event logs
Get-EventLog -LogName Application -Source Infiniservice

# Installation logs
Get-Content C:\Windows\Temp\infiniservice_install.log
```

## Security Considerations

1. **Service Privileges**: Runs with minimal required privileges
2. **Command Validation**: Safe commands are validated before execution
3. **Resource Limits**: Configurable timeouts and resource constraints
4. **Secure Communication**: VirtIO-serial provides isolated VM-to-host channel
5. **Audit Logging**: All commands and operations are logged

## Performance

InfiniService is optimized for minimal resource usage:

- **Memory**: ~20-30 MB resident memory
- **CPU**: <1% average CPU usage during idle
- **Disk I/O**: Minimal, only during metrics collection
- **Network**: No direct network access (communicates via VirtIO-serial)

## Troubleshooting

Common issues and solutions:

1. **VirtIO Device Not Found**
   - Ensure VirtIO drivers are installed (Windows)
   - Check device exists: `/dev/vport*` (Linux) or COM ports (Windows)
   - Run diagnostics: `infiniservice --diagnose`

2. **Service Won't Start**
   - Check logs for specific errors
   - Verify VM_ID is set correctly
   - Ensure proper permissions on device files

3. **No Metrics Received**
   - Verify backend connectivity
   - Check socket file exists: `/tmp/vm-{uuid}.sock`
   - Review backend VirtioSocketWatcherService logs

## Contributing

See [DEVELOPMENT.md](./DEVELOPMENT.md) for development setup and contribution guidelines.

## License

InfiniService is part of the Infinibay project and is licensed under the MIT License.

## Support

For issues, questions, or contributions:
- GitHub Issues: [infinibay/infinibay](https://github.com/infinibay/infinibay/issues)
- Documentation: This directory
- Backend Integration: See [integration/backend-integration.md](./integration/backend-integration.md)