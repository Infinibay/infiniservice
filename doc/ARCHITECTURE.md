# InfiniService Architecture

## System Design Philosophy

InfiniService follows several key architectural principles:

1. **Cross-Platform Compatibility**: Single codebase supporting Windows and Linux
2. **Async-First Design**: Leveraging Tokio for efficient concurrent operations
3. **Modular Architecture**: Clear separation of concerns with distinct modules
4. **Resilient Communication**: Automatic reconnection and error recovery
5. **Performance Optimization**: Minimal resource footprint with efficient data collection
6. **Security by Design**: Validated command execution and privilege separation

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    InfiniService                          │
│                                                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │                 Main Entry Point                 │    │
│  │                  (src/main.rs)                   │    │
│  │  • Command-line argument parsing                 │    │
│  │  • Service vs console mode detection             │    │
│  │  • Platform-specific service registration        │    │
│  └────────────────────┬────────────────────────────┘    │
│                       │                                   │
│  ┌────────────────────▼────────────────────────────┐    │
│  │              Service Orchestrator                │    │
│  │               (src/service.rs)                   │    │
│  │  • Main event loop coordination                  │    │
│  │  • Task scheduling and management                │    │
│  │  • Component initialization                      │    │
│  └──────┬──────────────┬──────────────┬───────────┘    │
│         │              │              │                  │
│    ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐           │
│    │Collector │  │  Comm.   │  │ Commands │           │
│    │ Module   │  │  Module  │  │ Executor │           │
│    └──────────┘  └──────────┘  └──────────┘           │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Main Entry Point (`src/main.rs`)

The entry point handles platform-specific initialization:

**Responsibilities:**
- Parse command-line arguments
- Detect execution mode (service vs console)
- Initialize logging system
- Handle Windows service registration
- Launch the main service runtime

**Key Features:**
- `--debug` flag for verbose logging
- `--diagnose` mode for VirtIO troubleshooting
- `--device` override for manual device specification
- Windows service integration via `windows-service` crate

**Platform-Specific Behavior:**
- **Windows**: Attempts to run as service first, falls back to console
- **Linux**: Runs as standard process (systemd manages service)

### 2. Service Orchestrator (`src/service.rs`)

The heart of InfiniService, coordinating all components:

**Components:**
```rust
pub struct InfiniService {
    config: Config,
    collector: DataCollector,
    communication: VirtioSerial,
    command_executor: CommandExecutor,
    debug_mode: bool,
}
```

**Main Loop Architecture:**
```rust
loop {
    select! {
        // Periodic metrics collection (30s default)
        _ = interval.tick() => {
            collect_and_send_metrics().await
        }
        
        // Command checking (100ms intervals)
        _ = command_check_interval.tick() => {
            process_incoming_commands().await
        }
    }
}
```

**Error Handling Strategy:**
- Non-blocking error recovery
- Automatic reconnection on communication failures
- Graceful degradation when components fail

### 3. Data Collector (`src/collector.rs`)

Efficient system metrics collection with platform abstractions:

**Architecture:**
```rust
pub struct DataCollector {
    system: System,  // sysinfo crate
    previous_disk_stats: Option<HashMap<String, DiskIoSnapshot>>,
    previous_network_stats: Option<HashMap<String, NetworkSnapshot>>,
    last_collection_time: Option<Instant>,
    #[cfg(target_os = "windows")]
    wmi_conn: Option<WMIConnection>,
}
```

**Collection Pipeline:**
1. **Initialize**: Cache system information
2. **Refresh**: Update dynamic metrics
3. **Calculate**: Compute rates and deltas
4. **Aggregate**: Combine into SystemMetrics
5. **Serialize**: Convert to JSON format

**Performance Optimizations:**
- Lazy initialization of expensive operations
- Caching of static information
- Delta calculations for I/O metrics
- Selective metric refresh based on changes

### 4. Communication Module (`src/communication.rs`)

Handles VirtIO-serial device communication:

**Key Components:**
```rust
pub struct VirtioSerial {
    device_path: PathBuf,
    vm_id: String,
}
```

**Device Detection Strategy:**

**Linux:**
```
1. Check /dev/virtio-ports/org.infinibay.agent
2. Check /dev/virtio-ports/org.qemu.guest_agent.*
3. Check /dev/vport*p1
4. Scan /dev for virtio devices
```

**Windows:**
```
1. Enumerate COM ports via SetupAPI
2. Filter by VirtIO vendor ID (VEN_1AF4)
3. Check device IDs (DEV_1003, DEV_1043, DEV_1044)
4. Test port accessibility
```

**Message Protocol:**
- Line-based JSON messages
- Newline-delimited for streaming
- Automatic reconnection on errors
- Buffered I/O for efficiency

### 5. Command Execution Framework (`src/commands/`)

Modular command execution system:

**Module Structure:**
```
commands/
├── mod.rs              # Type definitions and traits
├── executor.rs         # Main command dispatcher
├── safe_executor.rs    # Validated command execution
├── unsafe_executor.rs  # Raw command execution
├── service_control.rs  # Service management
├── package_management.rs # Package operations
└── process_control.rs  # Process management
```

**Command Flow:**
```
Incoming Message
    ↓
Command Parser
    ↓
Type Detection ──→ Safe Command ──→ Validation ──→ Safe Executor
    ↓                                                    ↓
Unsafe Command ──→ Permission Check ──→ Unsafe Executor
                                              ↓
                                        Command Response
```

**Security Model:**
- Safe commands: Pre-validated with structured parameters
- Unsafe commands: Require explicit permission, logged
- Timeout enforcement on all operations
- Resource limits to prevent abuse

## Data Flow Architecture

### Metrics Collection Flow

```
System APIs → DataCollector → SystemMetrics → JSON Serialization
                   ↓
            Rate Calculation
                   ↓
              Caching Layer
                   ↓
            VirtioSerial → Host System
```

### Command Execution Flow

```
Host System → VirtioSerial → Message Parser
                                  ↓
                          Command Dispatcher
                          ↙              ↘
                 Safe Executor      Unsafe Executor
                      ↓                    ↓
                System APIs          Shell Process
                      ↓                    ↓
                   Response            Response
                        ↘              ↙
                         JSON Response
                              ↓
                        VirtioSerial → Host
```

## Memory Management

InfiniService uses several strategies to minimize memory usage:

1. **Lazy Initialization**: Components initialized only when needed
2. **Resource Pooling**: Reuse of buffers and connections
3. **Selective Updates**: Only refresh changed metrics
4. **Bounded Buffers**: Limited size for command/response queues
5. **Drop Guards**: Automatic cleanup via RAII

## Concurrency Model

Built on Tokio's async runtime:

**Task Organization:**
```
Main Task (service.run())
    ├── Metrics Collection Task (30s interval)
    ├── Command Polling Task (100ms interval)
    └── Command Execution Tasks (spawned per command)
```

**Synchronization:**
- No shared mutable state between tasks
- Message passing for inter-task communication
- Timeout guards on all async operations

## Error Recovery

### Communication Failures

```rust
// Automatic reconnection with exponential backoff
loop {
    match connect().await {
        Ok(_) => break,
        Err(e) => {
            delay *= 2;
            sleep(delay).await;
        }
    }
}
```

### Collection Failures

- Individual metric failures don't stop collection
- Partial data sent when some metrics unavailable
- Error details included in response

### Command Failures

- Timeouts enforced on all operations
- Graceful termination of hung processes
- Error responses sent to host

## Platform Abstractions

### Cross-Platform Traits

```rust
trait SystemMetricsProvider {
    fn collect_cpu(&self) -> CpuMetrics;
    fn collect_memory(&self) -> MemoryMetrics;
    fn collect_disk(&self) -> DiskMetrics;
}

#[cfg(target_os = "windows")]
impl SystemMetricsProvider for WindowsCollector { ... }

#[cfg(target_os = "linux")]
impl SystemMetricsProvider for LinuxCollector { ... }
```

### Platform-Specific Features

**Windows:**
- WMI for detailed system information
- Windows Service API integration
- COM port enumeration
- PowerShell command execution

**Linux:**
- procfs/sysfs for system metrics
- systemd integration
- Native VirtIO device support
- Shell command execution

## Performance Characteristics

### Resource Usage

| Component | Memory | CPU | I/O |
|-----------|--------|-----|-----|
| Base Service | 15-20 MB | <0.5% | Minimal |
| Data Collection | +5-10 MB | 1-2% spike | Read-only |
| Command Execution | +Variable | Variable | Variable |
| Total Typical | 20-30 MB | <1% avg | Low |

### Optimization Techniques

1. **Zero-Copy Operations**: Where possible
2. **Buffered I/O**: Reduce system calls
3. **Batch Processing**: Group related operations
4. **Selective Refresh**: Update only changed data
5. **Async I/O**: Non-blocking operations

## Scalability Considerations

InfiniService is designed to scale:

- **Vertical**: Efficient resource usage on any VM size
- **Horizontal**: Thousands of instances manageable
- **Collection Interval**: Configurable based on needs
- **Metric Granularity**: Selective metric collection
- **Command Queuing**: Handle multiple commands

## Security Architecture

### Defense in Depth

1. **Process Isolation**: Runs as separate service
2. **Privilege Separation**: Minimal required permissions
3. **Input Validation**: All commands validated
4. **Resource Limits**: Timeouts and memory limits
5. **Audit Logging**: All operations logged

### Attack Surface Minimization

- No network listeners
- No file system access beyond metrics
- Validated command parameters
- Secure defaults

## Future Architecture Considerations

### Planned Enhancements

1. **Plugin System**: Extensible metric collectors
2. **Compression**: Reduce data transfer size
3. **Encryption**: End-to-end message encryption
4. **Multi-Channel**: Support multiple communication channels
5. **Hot Reload**: Configuration without restart

### Scalability Improvements

1. **Metric Streaming**: Real-time metric updates
2. **Command Pipelining**: Batch command execution
3. **Adaptive Collection**: Dynamic interval adjustment
4. **Resource Governance**: Better resource management
5. **Distributed Tracing**: Cross-VM operation tracking