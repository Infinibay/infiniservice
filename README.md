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
- **Virtio-serial Path**: 
  - Windows: `\\\\.\\pipe\\virtio-serial`
  - Linux: `/dev/virtio-ports/org.infinibay.0`
- **Log Level**: info

## Dependencies

The project uses only well-maintained Rust libraries:

- **tokio**: Async runtime
- **serde**: Serialization framework
- **log/env_logger**: Logging infrastructure
- **anyhow/thiserror**: Error handling
- **config**: Configuration management
- **dirs**: Cross-platform directory utilities

## Development Status

This is the initial project setup. The core functionality is currently implemented as placeholders and TODOs that will be developed based on specific requirements.

## Future Development

- Implement actual system metrics collection
- Add virtio-serial communication protocol
- Create platform-specific installers
- Add configuration file support
- Implement proper error handling and recovery
- Add comprehensive logging and monitoring
