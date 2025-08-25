# InfiniService Communication Protocol

## Overview

InfiniService uses a bidirectional, JSON-based protocol over VirtIO-serial channels for communication between the guest VM and the host system. The protocol is designed to be simple, efficient, and extensible.

## Transport Layer

### VirtIO-Serial Channel

The protocol operates over VirtIO-serial, a paravirtualized character device that provides:

- **Full-duplex communication**: Simultaneous send and receive
- **Reliable delivery**: No packet loss within the channel
- **Low latency**: Direct VM-to-host communication
- **Isolation**: Secure channel without network exposure

### Connection Establishment

```
VM Boot
    ↓
InfiniService Start
    ↓
Device Detection (/dev/vport* or COM*)
    ↓
Open Device (Read/Write)
    ↓
Send Initial Handshake
    ↓
Begin Message Loop
```

## Message Format

### Base Structure

All messages are JSON objects with newline delimiters:

```json
{
  "type": "message_type",
  "timestamp": "2024-01-15T10:30:00Z",
  ...additional fields...
}\n
```

### Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `metrics` | VM → Host | System metrics data |
| `handshake` | VM → Host | Initial connection establishment |
| `error` | VM → Host | Error reporting |
| `command` | Host → VM | Command request |
| `response` | VM → Host | Command response |

## Protocol Messages

### 1. Handshake Message

Sent immediately after connection establishment:

```json
{
  "type": "handshake",
  "timestamp": "2024-01-15T10:30:00Z",
  "vm_id": "550e8400-e29b-41d4-a716-446655440000",
  "version": "0.1.0",
  "platform": "linux",
  "capabilities": ["metrics", "safe_commands", "unsafe_commands"]
}
```

### 2. Metrics Message

Sent periodically (default 30s) with system metrics:

```json
{
  "type": "metrics",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "system": {
      "cpu": {
        "usage_percent": 45.2,
        "cores_usage": [40.1, 50.3, 42.0, 48.5],
        "temperature": 65.0
      },
      "memory": {
        "total_kb": 8388608,
        "used_kb": 4194304,
        "available_kb": 4194304,
        "swap_total_kb": 2097152,
        "swap_used_kb": 524288
      },
      "disk": {
        "usage_stats": [
          {
            "mount_point": "/",
            "total_gb": 100.0,
            "used_gb": 45.5,
            "available_gb": 54.5,
            "filesystem": "ext4"
          }
        ],
        "io_stats": {
          "read_bytes_per_sec": 1048576,
          "write_bytes_per_sec": 524288,
          "read_ops_per_sec": 100,
          "write_ops_per_sec": 50
        }
      },
      "network": {
        "interfaces": [
          {
            "name": "eth0",
            "bytes_received": 1073741824,
            "bytes_sent": 536870912,
            "packets_received": 1000000,
            "packets_sent": 500000,
            "errors_in": 0,
            "errors_out": 0
          }
        ]
      },
      "system": {
        "uptime_seconds": 86400,
        "name": "Linux",
        "os_version": "Ubuntu 22.04",
        "kernel_version": "5.15.0-58-generic",
        "hostname": "vm-web-01",
        "load_average": {
          "load_1min": 0.5,
          "load_5min": 0.7,
          "load_15min": 0.6
        }
      },
      "processes": [...],
      "ports": [...],
      "windows_services": [...]
    }
  }
}
```

### 3. Error Message

Sent when errors occur:

```json
{
  "type": "error",
  "timestamp": "2024-01-15T10:30:00Z",
  "error": "Failed to collect disk metrics",
  "details": {
    "component": "collector",
    "error_code": "DISK_ACCESS_DENIED",
    "message": "Permission denied accessing /dev/sda"
  }
}
```

### 4. Command Messages

**IMPORTANT**: All commands (both Safe and Unsafe) MUST include a unique `id` field for response correlation.

#### Safe Command Request (Host → VM)

```json
{
  "type": "SafeCommand",
  "id": "cmd-123e4567-e89b-12d3-a456-426614174000",  // REQUIRED: Unique ID
  "command_type": {
    "action": "ServiceControl",
    "service": "nginx",
    "operation": "restart"
  },
  "params": null,
  "timeout": 30
}
```

#### Unsafe Command Request (Host → VM)

```json
{
  "type": "UnsafeCommand",
  "id": "cmd-987f6543-a21b-34c5-d678-123456789abc",  // REQUIRED: Unique ID
  "raw_command": "apt-get update && apt-get upgrade -y",
  "shell": "bash",
  "timeout": 300,
  "working_dir": "/tmp",
  "env_vars": {
    "DEBIAN_FRONTEND": "noninteractive"
  }
}
```

### 5. Command Response (VM → Host)

```json
{
  "type": "response",
  "id": "cmd-123e4567-e89b-12d3-a456-426614174000",
  "success": true,
  "exit_code": 0,
  "stdout": "Service nginx restarted successfully",
  "stderr": "",
  "execution_time_ms": 1523,
  "command_type": "safe",
  "data": {
    "service_status": "active",
    "pid": 12345
  }
}
```

## Command Protocol

### Safe Commands

Safe commands are pre-validated operations with structured parameters:

#### Service Management

```json
{
  "action": "ServiceControl",
  "service": "service_name",
  "operation": "start|stop|restart|enable|disable|status"
}
```

```json
{
  "action": "ServiceList"
}
```

#### Package Management

```json
{
  "action": "PackageInstall",
  "package": "package_name"
}
```

```json
{
  "action": "PackageRemove",
  "package": "package_name"
}
```

```json
{
  "action": "PackageUpdate",
  "package": "package_name"
}
```

```json
{
  "action": "PackageSearch",
  "query": "search_term"
}
```

```json
{
  "action": "PackageList"
}
```

#### Process Management

```json
{
  "action": "ProcessList",
  "limit": 50
}
```

```json
{
  "action": "ProcessKill",
  "pid": 12345,
  "force": true
}
```

```json
{
  "action": "ProcessTop",
  "limit": 10,
  "sort_by": "cpu|memory"
}
```

#### System Information

```json
{
  "action": "SystemInfo"
}
```

```json
{
  "action": "OsInfo"
}
```

### Unsafe Commands

Unsafe commands allow raw command execution with full control:

```json
{
  "id": "unique-command-id",           // REQUIRED: For response correlation
  "raw_command": "command to execute", // REQUIRED: Command to execute
  "shell": "bash|sh|powershell|cmd",   // Optional: Shell to use
  "timeout": 60,                       // Optional: Timeout in seconds
  "working_dir": "/path/to/dir",       // Optional: Working directory
  "env_vars": {                        // Optional: Environment variables
    "KEY": "value"
  }
}
```

**Note**: The `id` field is mandatory for tracking command responses. Without it, the host cannot correlate responses with requests.

## Error Handling

### Error Codes

| Code | Description |
|------|-------------|
| `DEVICE_NOT_FOUND` | VirtIO device not available |
| `CONNECTION_FAILED` | Failed to establish connection |
| `INVALID_MESSAGE` | Malformed JSON message |
| `COMMAND_TIMEOUT` | Command execution timeout |
| `PERMISSION_DENIED` | Insufficient permissions |
| `COMMAND_FAILED` | Command execution failed |
| `UNKNOWN_COMMAND` | Unrecognized command type |
| `RESOURCE_LIMIT` | Resource limit exceeded |

### Error Response Format

```json
{
  "type": "response",
  "id": "command_id",
  "success": false,
  "exit_code": 1,
  "stdout": "",
  "stderr": "Error message",
  "execution_time_ms": 0,
  "command_type": "safe|unsafe",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {}
  }
}
```

## Flow Control

### Message Queuing

- Commands are processed sequentially
- Maximum queue size: 100 messages
- Overflow handling: Oldest messages dropped
- Priority: Commands > Metrics

### Rate Limiting

- Metrics: Configurable interval (default 30s)
- Commands: No artificial limit
- Responses: Immediate after execution

### Timeout Handling

Default timeouts:
- Connection establishment: 10 seconds
- Command execution: 30 seconds (configurable)
- Metrics collection: 5 seconds
- Message transmission: 5 seconds

## Protocol Extensions

### Capability Negotiation

During handshake, capabilities are announced:

```json
{
  "capabilities": [
    "metrics",           // Basic metrics collection
    "safe_commands",     // Safe command execution
    "unsafe_commands",   // Unsafe command execution
    "streaming",         // Real-time metric streaming
    "compression",       // Message compression
    "encryption"         // Message encryption
  ]
}
```

### Version Compatibility

- Protocol version in handshake
- Backward compatibility for minor versions
- Feature detection via capabilities
- Graceful degradation for missing features

## Security Considerations

### Message Validation

1. **JSON Schema Validation**: All messages validated against schema
2. **Size Limits**: Maximum message size 1MB
3. **Rate Limiting**: Prevent message flooding
4. **Input Sanitization**: Command parameters sanitized

### Command Security

1. **Safe Commands**: Pre-validated, limited scope
2. **Unsafe Commands**: Logged, audited, optional
3. **Timeout Enforcement**: Prevent resource exhaustion
4. **Permission Checks**: Verify execution permissions

### Channel Security

1. **Isolation**: VirtIO-serial isolated from network
2. **No External Access**: Host-only communication
3. **VM Identification**: UUID-based VM tracking
4. **Audit Logging**: All operations logged

## Performance Optimizations

### Message Batching

Multiple metrics can be batched:

```json
{
  "type": "metrics_batch",
  "messages": [
    {...metric1...},
    {...metric2...},
    {...metric3...}
  ]
}
```

### Compression (Future)

- Gzip compression for large messages
- Negotiated during handshake
- Transparent to application layer

### Streaming Mode (Future)

- Real-time metric updates
- Binary protocol for efficiency
- WebSocket-style framing

## Debugging

### Protocol Tracing

Enable with environment variable:
```bash
INFINISERVICE_TRACE=1
```

Output format:
```
[2024-01-15 10:30:00] TX: {"type":"metrics",...}
[2024-01-15 10:30:01] RX: {"type":"command",...}
[2024-01-15 10:30:02] TX: {"type":"response",...}
```

### Message Validation

Test message validity:
```bash
echo '{"type":"metrics",...}' | infiniservice --validate
```

### Protocol Testing

Mock host for testing:
```bash
infiniservice --mock-host --port /tmp/test.sock
```

## Implementation Notes

### Buffer Management

- Read buffer: 64KB
- Write buffer: 64KB
- Line delimiter: \n
- Maximum line length: 1MB

### Reconnection Strategy

```
Initial delay: 1 second
Maximum delay: 60 seconds
Backoff factor: 2
Jitter: ±10%
```

### State Management

```
States: Disconnected → Connecting → Connected → Active
Transitions: Automatic on events
Recovery: Automatic reconnection
```