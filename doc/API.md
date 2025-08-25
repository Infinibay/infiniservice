# InfiniService API Reference

## Overview

This document provides a complete reference for all API messages, commands, and data structures used by InfiniService.

## Message Types

### Base Message Structure

All messages inherit from this base structure:

```typescript
interface BaseMessage {
  type: 'metrics' | 'error' | 'handshake' | 'command' | 'response';
  timestamp: string; // ISO 8601 format
}
```

## Outgoing Messages (VM → Host)

### Handshake Message

Sent on connection establishment to identify the VM and capabilities.

```typescript
interface HandshakeMessage extends BaseMessage {
  type: 'handshake';
  vm_id: string;           // UUID of the VM
  version: string;          // InfiniService version
  platform: string;         // 'linux' | 'windows'
  capabilities: string[];   // Supported features
}
```

**Example:**
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

### Metrics Message

Periodic system metrics report.

```typescript
interface MetricsMessage extends BaseMessage {
  type: 'metrics';
  data: {
    system: SystemMetrics;
  };
}

interface SystemMetrics {
  cpu: CpuMetrics;
  memory: MemoryMetrics;
  disk: DiskMetrics;
  network: NetworkMetrics;
  system: SystemInfoMetrics;
  processes?: ProcessInfo[];
  ports?: PortInfo[];
  windows_services?: WindowsService[];
}
```

#### CPU Metrics

```typescript
interface CpuMetrics {
  usage_percent: number;      // Overall CPU usage (0-100)
  cores_usage: number[];      // Per-core usage percentages
  temperature?: number;       // CPU temperature in Celsius
}
```

#### Memory Metrics

```typescript
interface MemoryMetrics {
  total_kb: number;          // Total physical memory
  used_kb: number;           // Used physical memory
  available_kb: number;      // Available physical memory
  swap_total_kb?: number;    // Total swap space
  swap_used_kb?: number;     // Used swap space
}
```

#### Disk Metrics

```typescript
interface DiskMetrics {
  usage_stats: DiskUsage[];
  io_stats: DiskIO;
}

interface DiskUsage {
  mount_point: string;       // Mount point or drive letter
  total_gb: number;          // Total capacity
  used_gb: number;           // Used space
  available_gb: number;      // Available space
  filesystem: string;        // Filesystem type
}

interface DiskIO {
  read_bytes_per_sec: number;    // Read throughput
  write_bytes_per_sec: number;   // Write throughput
  read_ops_per_sec: number;      // Read IOPS
  write_ops_per_sec: number;     // Write IOPS
}
```

#### Network Metrics

```typescript
interface NetworkMetrics {
  interfaces: NetworkInterface[];
}

interface NetworkInterface {
  name: string;                // Interface name
  bytes_received: number;      // Total bytes received
  bytes_sent: number;          // Total bytes sent
  packets_received: number;    // Total packets received
  packets_sent: number;        // Total packets sent
  errors_in: number;           // Receive errors
  errors_out: number;          // Transmit errors
}
```

#### System Information

```typescript
interface SystemInfoMetrics {
  uptime_seconds: number;     // System uptime
  name: string;               // OS name
  os_version: string;         // OS version
  kernel_version: string;     // Kernel version
  hostname: string;           // System hostname
  load_average?: LoadAverage; // Unix load average
}

interface LoadAverage {
  load_1min: number;          // 1-minute average
  load_5min: number;          // 5-minute average
  load_15min: number;         // 15-minute average
}
```

#### Process Information

```typescript
interface ProcessInfo {
  id: number;                     // Process ID
  parent_id?: number;             // Parent process ID
  name: string;                   // Process name
  executable_path?: string;       // Full path to executable
  command_line?: string;          // Full command line
  cpu_usage_percent: number;      // CPU usage (0-100)
  memory_usage_kb: number;        // Memory usage in KB
  status: string;                 // Process status
  start_time?: number;            // Start timestamp
}
```

#### Port Information

```typescript
interface PortInfo {
  port: number;                   // Port number
  protocol: string;               // 'tcp' | 'udp'
  state: string;                  // Connection state
  process_id?: number;            // Owning process ID
  process_name?: string;          // Owning process name
  is_listening: boolean;          // Listening port flag
}
```

#### Windows Services

```typescript
interface WindowsService {
  name: string;                   // Service name
  display_name: string;           // Display name
  description?: string;           // Service description
  start_type: string;             // Startup type
  service_type: string;           // Service type
  exe_path?: string;              // Executable path
  dependencies?: string[];        // Service dependencies
  state: string;                  // Current state
  pid?: number;                   // Process ID if running
  is_default: boolean;            // Windows default service
}
```

### Error Message

Reports errors to the host.

```typescript
interface ErrorMessage extends BaseMessage {
  type: 'error';
  error: string;                  // Error summary
  details?: {
    component: string;            // Component that failed
    error_code: string;           // Error code
    message: string;              // Detailed message
    stack_trace?: string;         // Optional stack trace
  };
}
```

**Example:**
```json
{
  "type": "error",
  "timestamp": "2024-01-15T10:30:00Z",
  "error": "Failed to collect metrics",
  "details": {
    "component": "collector",
    "error_code": "PERMISSION_DENIED",
    "message": "Cannot access /proc/1/stat: Permission denied"
  }
}
```

### Command Response

Response to command execution requests.

```typescript
interface CommandResponse extends BaseMessage {
  type: 'response';
  id: string;                    // Command ID for correlation
  success: boolean;              // Execution success flag
  exit_code?: number;            // Process exit code
  stdout: string;                // Standard output
  stderr: string;                // Standard error
  execution_time_ms: number;     // Execution duration
  command_type: string;          // 'safe' | 'unsafe'
  data?: any;                    // Additional structured data
}
```

## Incoming Messages (Host → VM)

### Safe Command Request

Pre-validated commands with structured parameters.

```typescript
interface SafeCommandRequest {
  type: 'SafeCommand';
  id: string;                    // Unique command ID
  command_type: SafeCommandType; // Command specification
  params?: any;                  // Additional parameters
  timeout?: number;              // Timeout in seconds
}
```

#### Service Management Commands

```typescript
// List all services
{
  "type": "SafeCommand",
  "id": "cmd-123",
  "command_type": {
    "action": "ServiceList"
  }
}

// Control a service
{
  "type": "SafeCommand",
  "id": "cmd-124",
  "command_type": {
    "action": "ServiceControl",
    "service": "nginx",
    "operation": "restart"  // start|stop|restart|enable|disable|status
  }
}
```

**Response Data Structure:**
```typescript
interface ServiceInfo {
  name: string;
  display_name: string;
  state: string;        // running|stopped|disabled
  start_type: string;   // auto|manual|disabled
  pid?: number;
  description?: string;
}
```

#### Package Management Commands

```typescript
// List installed packages
{
  "type": "SafeCommand",
  "id": "cmd-125",
  "command_type": {
    "action": "PackageList"
  }
}

// Install a package
{
  "type": "SafeCommand",
  "id": "cmd-126",
  "command_type": {
    "action": "PackageInstall",
    "package": "nginx"
  }
}

// Remove a package
{
  "type": "SafeCommand",
  "id": "cmd-127",
  "command_type": {
    "action": "PackageRemove",
    "package": "apache2"
  }
}

// Update a package
{
  "type": "SafeCommand",
  "id": "cmd-128",
  "command_type": {
    "action": "PackageUpdate",
    "package": "nodejs"
  }
}

// Search for packages
{
  "type": "SafeCommand",
  "id": "cmd-129",
  "command_type": {
    "action": "PackageSearch",
    "query": "python"
  }
}
```

**Response Data Structure:**
```typescript
interface PackageInfo {
  name: string;
  version: string;
  description?: string;
  installed: boolean;
  size?: number;
  dependencies?: string[];
}
```

#### Process Management Commands

```typescript
// List processes
{
  "type": "SafeCommand",
  "id": "cmd-130",
  "command_type": {
    "action": "ProcessList",
    "limit": 50  // Optional limit
  }
}

// Kill a process
{
  "type": "SafeCommand",
  "id": "cmd-131",
  "command_type": {
    "action": "ProcessKill",
    "pid": 12345,
    "force": true  // Optional force flag
  }
}

// Get top processes
{
  "type": "SafeCommand",
  "id": "cmd-132",
  "command_type": {
    "action": "ProcessTop",
    "limit": 10,
    "sort_by": "cpu"  // cpu|memory
  }
}
```

#### System Information Commands

```typescript
// Get system information
{
  "type": "SafeCommand",
  "id": "cmd-133",
  "command_type": {
    "action": "SystemInfo"
  }
}

// Get OS information
{
  "type": "SafeCommand",
  "id": "cmd-134",
  "command_type": {
    "action": "OsInfo"
  }
}
```

### Unsafe Command Request

Raw command execution with full control.

```typescript
interface UnsafeCommandRequest {
  type: 'UnsafeCommand';
  id: string;                    // REQUIRED: Unique command ID for response correlation
  raw_command: string;           // REQUIRED: Command to execute
  shell?: string;                // Optional: Shell to use (bash|sh|powershell|cmd)
  timeout?: number;              // Optional: Timeout in seconds (default: 300)
  working_dir?: string;          // Optional: Working directory
  env_vars?: Record<string, string>; // Optional: Environment variables
}
```

**IMPORTANT**: The `id` field is mandatory. All commands must have a unique ID to correlate responses. Without this ID, the host cannot match responses to their corresponding requests.

**Example:**
```json
{
  "type": "UnsafeCommand",
  "id": "cmd-987f6543-a21b-34c5-d678-123456789abc",  // REQUIRED
  "raw_command": "apt-get update && apt-get upgrade -y",
  "shell": "bash",
  "timeout": 300,
  "working_dir": "/tmp",
  "env_vars": {
    "DEBIAN_FRONTEND": "noninteractive"
  }
}
```

**Shell Options:**
- Linux: `bash`, `sh`, `zsh`
- Windows: `powershell`, `cmd`

## Error Codes

| Code | Description | Recovery Action |
|------|-------------|-----------------|
| `DEVICE_NOT_FOUND` | VirtIO device not available | Check device drivers |
| `CONNECTION_FAILED` | Cannot connect to host | Check socket/device |
| `INVALID_MESSAGE` | Malformed JSON | Fix message format |
| `COMMAND_TIMEOUT` | Command exceeded timeout | Increase timeout |
| `PERMISSION_DENIED` | Insufficient permissions | Run as admin/root |
| `COMMAND_FAILED` | Command execution failed | Check command syntax |
| `UNKNOWN_COMMAND` | Command not recognized | Use valid command |
| `RESOURCE_LIMIT` | Resource limit exceeded | Reduce resource usage |
| `SERVICE_NOT_FOUND` | Service doesn't exist | Check service name |
| `PACKAGE_NOT_FOUND` | Package doesn't exist | Check package name |
| `PROCESS_NOT_FOUND` | Process doesn't exist | Verify process ID |
| `UNSUPPORTED_PLATFORM` | Platform not supported | Check compatibility |

## Response Formats

### Success Response

```json
{
  "type": "response",
  "id": "cmd-123",
  "timestamp": "2024-01-15T10:30:00Z",
  "success": true,
  "exit_code": 0,
  "stdout": "Command output here",
  "stderr": "",
  "execution_time_ms": 1523,
  "command_type": "safe",
  "data": {
    "additional": "structured data"
  }
}
```

### Error Response

```json
{
  "type": "response",
  "id": "cmd-123",
  "timestamp": "2024-01-15T10:30:00Z",
  "success": false,
  "exit_code": 1,
  "stdout": "",
  "stderr": "Error message",
  "execution_time_ms": 0,
  "command_type": "safe",
  "error": {
    "code": "COMMAND_FAILED",
    "message": "Failed to restart service",
    "details": {
      "service": "nginx",
      "reason": "Service not found"
    }
  }
}
```

## Rate Limits and Constraints

### Message Size Limits

| Message Type | Maximum Size |
|--------------|--------------|
| Metrics | 1 MB |
| Command Request | 64 KB |
| Command Response | 1 MB |
| Error Message | 64 KB |

### Timing Constraints

| Operation | Default Timeout |
|-----------|----------------|
| Connection establishment | 10 seconds |
| Metrics collection | 5 seconds |
| Safe command execution | 30 seconds |
| Unsafe command execution | 300 seconds |
| Message transmission | 5 seconds |

### Rate Limits

| Operation | Limit |
|-----------|-------|
| Metrics transmission | 1 per 30 seconds |
| Command execution | 10 concurrent |
| Error reports | 100 per minute |
| Message queue | 100 messages |

## Best Practices

### Command Design

1. **Use Safe Commands When Possible**: Prefer structured safe commands
2. **Set Appropriate Timeouts**: Adjust based on expected duration
3. **Handle Partial Failures**: Commands may partially succeed
4. **Log Command Execution**: Audit all command requests
5. **Validate Parameters**: Check inputs before sending

### Error Handling

1. **Graceful Degradation**: Continue operation on non-critical errors
2. **Retry Logic**: Implement exponential backoff
3. **Error Context**: Include relevant details in error messages
4. **Recovery Actions**: Define recovery procedures for each error
5. **Monitoring**: Alert on repeated errors

### Performance

1. **Batch Operations**: Group related commands
2. **Async Execution**: Use non-blocking operations
3. **Cache Results**: Cache expensive operations
4. **Minimize Payload**: Send only necessary data
5. **Compression**: Consider compression for large payloads

## Testing

### Mock Messages

Test InfiniService with mock messages:

```bash
# Send test command
echo '{"type":"SafeCommand","id":"test-1","command_type":{"action":"SystemInfo"}}' | \
  socat - UNIX-CONNECT:/tmp/vm-test.sock

# Receive response
socat UNIX-LISTEN:/tmp/vm-test.sock,fork EXEC:"cat"
```

### Validation

Validate message format:

```bash
# Validate JSON structure
echo '{"type":"metrics",...}' | jq .

# Test with InfiniService
infiniservice --validate < message.json
```

### Integration Testing

Test end-to-end flow:

```python
import json
import socket

# Connect to VirtIO socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('/tmp/vm-uuid.sock')

# Send command
command = {
    "type": "SafeCommand",
    "id": "test-123",
    "command_type": {"action": "SystemInfo"}
}
sock.send(json.dumps(command).encode() + b'\n')

# Receive response
response = sock.recv(4096)
print(json.loads(response))
```