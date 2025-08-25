# Backend Integration

## Overview

This document describes how InfiniService integrates with the Infinibay backend system, including the communication flow, data processing, and synchronization mechanisms.

## Integration Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    Infinibay Backend                        │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐ │
│  │            VirtioSocketWatcherService                 │ │
│  │                                                       │ │
│  │  • Socket monitoring (/tmp/vm-*.sock)                │ │
│  │  • Message parsing and validation                    │ │
│  │  • Command dispatching                               │ │
│  │  • Metrics storage                                   │ │
│  └────────────────┬─────────────────────────────────────┘ │
│                   │                                        │
│  ┌────────────────▼─────────────────────────────────────┐ │
│  │                  Event System                         │ │
│  │                                                       │ │
│  │  • VmEventManager                                    │ │
│  │  • WebSocket broadcasting                            │ │
│  │  • Real-time updates                                 │ │
│  └────────────────┬─────────────────────────────────────┘ │
│                   │                                        │
│  ┌────────────────▼─────────────────────────────────────┐ │
│  │               Database (PostgreSQL)                   │ │
│  │                                                       │ │
│  │  • VM metadata                                       │ │
│  │  • Historical metrics                                │ │
│  │  • Command logs                                      │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

## Backend Service Components

### VirtioSocketWatcherService

Location: `backend/app/services/VirtioSocketWatcherService.ts`

**Responsibilities:**
- Monitor Unix sockets for VM connections
- Parse and validate InfiniService messages
- Store metrics in database
- Execute commands on VMs
- Broadcast events via WebSocket

**Key Methods:**

```typescript
class VirtioSocketWatcherService {
  // Start monitoring for VM connections
  async startWatching(): Promise<void>
  
  // Handle new VM connection
  private handleConnection(vmId: string, socket: net.Socket): void
  
  // Process incoming message from InfiniService
  private async processMessage(vmId: string, message: string): Promise<void>
  
  // Send command to VM
  async sendCommand(vmId: string, command: CommandRequest): Promise<CommandResponse>
  
  // Store metrics in database
  private async storeMetrics(vmId: string, metrics: SystemMetrics): Promise<void>
}
```

### Socket Management

**Socket Path Convention:**
```
/tmp/vm-{uuid}.sock
```

**Socket Creation (QEMU/Libvirt):**
```xml
<channel type='unix'>
  <source mode='bind' path='/tmp/vm-550e8400-e29b-41d4-a716-446655440000.sock'/>
  <target type='virtio' name='org.infinibay.agent'/>
</channel>
```

**Socket Monitoring:**
```typescript
// Watch for new socket files
const watcher = chokidar.watch('/tmp/vm-*.sock', {
  persistent: true,
  ignoreInitial: false
});

watcher.on('add', (path) => {
  const vmId = extractVmId(path);
  this.connectToVm(vmId, path);
});
```

## Message Processing

### Incoming Message Flow

```typescript
// 1. Receive raw message from socket
socket.on('data', (data: Buffer) => {
  const messages = data.toString().split('\n');
  
  for (const message of messages) {
    if (message.trim()) {
      this.processMessage(vmId, message);
    }
  }
});

// 2. Parse and validate message
private async processMessage(vmId: string, rawMessage: string) {
  try {
    const message = JSON.parse(rawMessage);
    
    // Validate message structure
    if (!this.validateMessage(message)) {
      throw new Error('Invalid message format');
    }
    
    // Route based on message type
    switch (message.type) {
      case 'metrics':
        await this.handleMetrics(vmId, message);
        break;
      case 'response':
        await this.handleCommandResponse(vmId, message);
        break;
      case 'error':
        await this.handleError(vmId, message);
        break;
    }
  } catch (error) {
    this.logger.error(`Failed to process message: ${error}`);
  }
}
```

### Metrics Storage

```typescript
private async handleMetrics(vmId: string, message: MetricsMessage) {
  const metrics = message.data.system;
  
  // Store in database
  await this.prisma.vmMetrics.create({
    data: {
      vmId,
      timestamp: new Date(message.timestamp),
      cpuUsage: metrics.cpu.usage_percent,
      memoryUsed: metrics.memory.used_kb,
      memoryTotal: metrics.memory.total_kb,
      diskUsage: JSON.stringify(metrics.disk),
      networkStats: JSON.stringify(metrics.network),
      processes: JSON.stringify(metrics.processes),
      raw: JSON.stringify(metrics)
    }
  });
  
  // Broadcast to WebSocket clients
  this.eventManager.emitVmMetrics(vmId, metrics);
  
  // Update VM status
  await this.updateVmStatus(vmId, 'online');
}
```

## Command Execution

### Sending Commands to VMs

```typescript
async executeCommand(vmId: string, command: SafeCommandRequest): Promise<CommandResponse> {
  const connection = this.connections.get(vmId);
  
  if (!connection) {
    throw new Error(`VM ${vmId} is not connected`);
  }
  
  // Create command with unique ID
  const commandId = uuidv4();
  const commandMessage = {
    type: 'SafeCommand',
    id: commandId,
    ...command
  };
  
  // Send command
  connection.socket.write(JSON.stringify(commandMessage) + '\n');
  
  // Wait for response
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error('Command timeout'));
    }, command.timeout || 30000);
    
    this.pendingCommands.set(commandId, {
      resolve: (response) => {
        clearTimeout(timeout);
        resolve(response);
      },
      reject
    });
  });
}
```

### GraphQL Resolvers

```typescript
// backend/app/graphql/resolvers/VmResolver.ts
@Resolver()
export class VmResolver {
  @Mutation(() => CommandResponse)
  async executeVmCommand(
    @Arg('vmId') vmId: string,
    @Arg('command') command: CommandInput
  ): Promise<CommandResponse> {
    return this.socketWatcher.executeCommand(vmId, command);
  }
  
  @Query(() => [VmMetrics])
  async getVmMetrics(
    @Arg('vmId') vmId: string,
    @Arg('hours', { defaultValue: 24 }) hours: number
  ): Promise<VmMetrics[]> {
    const since = new Date();
    since.setHours(since.getHours() - hours);
    
    return this.prisma.vmMetrics.findMany({
      where: {
        vmId,
        timestamp: { gte: since }
      },
      orderBy: { timestamp: 'desc' }
    });
  }
}
```

## Event Broadcasting

### WebSocket Integration

```typescript
// Real-time metric updates
this.io.on('connection', (socket) => {
  socket.on('subscribe:vm', (vmId: string) => {
    socket.join(`vm:${vmId}`);
  });
});

// Broadcast metrics
private broadcastMetrics(vmId: string, metrics: SystemMetrics) {
  this.io.to(`vm:${vmId}`).emit('metrics', {
    vmId,
    timestamp: new Date(),
    data: metrics
  });
}
```

### Event Types

```typescript
enum VmEventType {
  VM_ONLINE = 'vm:online',
  VM_OFFLINE = 'vm:offline',
  VM_METRICS = 'vm:metrics',
  VM_COMMAND = 'vm:command',
  VM_ERROR = 'vm:error'
}
```

## Database Schema

### Metrics Storage

```prisma
model VmMetrics {
  id          String   @id @default(uuid())
  vmId        String
  timestamp   DateTime
  cpuUsage    Float
  memoryUsed  BigInt
  memoryTotal BigInt
  diskUsage   Json
  networkStats Json
  processes   Json?
  ports       Json?
  raw         Json
  createdAt   DateTime @default(now())
  
  vm          Vm       @relation(fields: [vmId], references: [id])
  
  @@index([vmId, timestamp])
}
```

### Command Logs

```prisma
model CommandLog {
  id          String   @id @default(uuid())
  vmId        String
  commandId   String
  type        String
  command     Json
  response    Json?
  success     Boolean
  executionMs Int
  createdAt   DateTime @default(now())
  
  vm          Vm       @relation(fields: [vmId], references: [id])
  
  @@index([vmId, createdAt])
}
```

## HTTP Endpoints

### Binary Distribution

```typescript
// backend/app/routes/infiniservice.ts
router.get('/infiniservice/:platform/binary', (req, res) => {
  const platform = req.params.platform;
  const binaryPath = path.join(
    process.env.INFINIBAY_BASE_DIR,
    'infiniservice/binaries',
    platform,
    platform === 'windows' ? 'infiniservice.exe' : 'infiniservice'
  );
  
  if (!fs.existsSync(binaryPath)) {
    return res.status(404).send('Binary not found');
  }
  
  res.sendFile(binaryPath);
});

router.get('/infiniservice/:platform/script', (req, res) => {
  const platform = req.params.platform;
  const scriptName = platform === 'windows' 
    ? 'install-windows.ps1' 
    : 'install-linux.sh';
  
  const scriptPath = path.join(
    process.env.INFINIBAY_BASE_DIR,
    'infiniservice/install',
    scriptName
  );
  
  res.sendFile(scriptPath);
});
```

## VM Lifecycle Integration

### VM Creation

```typescript
// During VM creation, prepare InfiniService installation
async createVm(config: VmConfig): Promise<Vm> {
  const vm = await this.libvirt.createVm(config);
  
  // Add VirtIO-serial channel
  await this.addVirtioChannel(vm.id);
  
  // Configure unattended installation with InfiniService
  if (config.unattended) {
    config.unattendedConfig.infiniserviceVmId = vm.id;
    config.unattendedConfig.infiniserviceUrl = 
      `http://${process.env.APP_HOST}:${process.env.PORT}/infiniservice`;
  }
  
  return vm;
}
```

### VM Deletion

```typescript
async deleteVm(vmId: string): Promise<void> {
  // Close InfiniService connection
  const connection = this.socketWatcher.connections.get(vmId);
  if (connection) {
    connection.socket.destroy();
    this.socketWatcher.connections.delete(vmId);
  }
  
  // Clean up socket file
  const socketPath = `/tmp/vm-${vmId}.sock`;
  if (fs.existsSync(socketPath)) {
    fs.unlinkSync(socketPath);
  }
  
  // Delete VM
  await this.libvirt.deleteVm(vmId);
}
```

## Monitoring and Health Checks

### Connection Health

```typescript
// Monitor connection health
setInterval(() => {
  for (const [vmId, connection] of this.connections) {
    const lastSeen = Date.now() - connection.lastMessageTime;
    
    if (lastSeen > 60000) { // 1 minute timeout
      this.logger.warn(`VM ${vmId} appears offline`);
      this.handleVmOffline(vmId);
    }
  }
}, 30000); // Check every 30 seconds
```

### Metrics Validation

```typescript
private validateMetrics(metrics: SystemMetrics): boolean {
  // Validate required fields
  if (!metrics.cpu || !metrics.memory) {
    return false;
  }
  
  // Validate ranges
  if (metrics.cpu.usage_percent < 0 || metrics.cpu.usage_percent > 100) {
    return false;
  }
  
  // Validate memory values
  if (metrics.memory.used_kb > metrics.memory.total_kb) {
    return false;
  }
  
  return true;
}
```

## Error Handling

### Connection Errors

```typescript
socket.on('error', (error) => {
  this.logger.error(`Socket error for VM ${vmId}: ${error}`);
  
  // Attempt reconnection
  setTimeout(() => {
    this.attemptReconnection(vmId);
  }, 5000);
});

socket.on('close', () => {
  this.logger.info(`Connection closed for VM ${vmId}`);
  this.connections.delete(vmId);
  this.eventManager.emitVmOffline(vmId);
});
```

### Message Errors

```typescript
private handleError(vmId: string, error: ErrorMessage) {
  this.logger.error(`VM ${vmId} error: ${error.error}`);
  
  // Store error in database
  this.prisma.vmError.create({
    data: {
      vmId,
      error: error.error,
      details: error.details,
      timestamp: new Date(error.timestamp)
    }
  });
  
  // Notify administrators
  this.notificationService.sendAlert({
    type: 'vm_error',
    vmId,
    message: error.error
  });
}
```

## Performance Optimization

### Connection Pooling

```typescript
class ConnectionPool {
  private maxConnections = 1000;
  private connections = new Map<string, VmConnection>();
  
  async acquire(vmId: string): Promise<VmConnection> {
    if (this.connections.size >= this.maxConnections) {
      // Remove least recently used
      const lru = this.findLeastRecentlyUsed();
      lru.socket.destroy();
      this.connections.delete(lru.vmId);
    }
    
    return this.createConnection(vmId);
  }
}
```

### Batch Processing

```typescript
// Batch metrics inserts
private metricsBuffer = new Map<string, SystemMetrics[]>();

private async flushMetrics() {
  const batch = [];
  
  for (const [vmId, metrics] of this.metricsBuffer) {
    batch.push(...metrics.map(m => ({
      vmId,
      timestamp: new Date(),
      data: m
    })));
  }
  
  if (batch.length > 0) {
    await this.prisma.vmMetrics.createMany({ data: batch });
    this.metricsBuffer.clear();
  }
}

// Flush every 10 seconds
setInterval(() => this.flushMetrics(), 10000);
```

## Security

### Message Validation

```typescript
private validateMessage(message: any): boolean {
  // Check message structure
  if (!message.type || !message.timestamp) {
    return false;
  }
  
  // Validate timestamp (not too old or future)
  const timestamp = new Date(message.timestamp);
  const now = new Date();
  const diff = Math.abs(now.getTime() - timestamp.getTime());
  
  if (diff > 300000) { // 5 minutes
    return false;
  }
  
  // Validate message size
  const size = JSON.stringify(message).length;
  if (size > 1048576) { // 1MB
    return false;
  }
  
  return true;
}
```

### Command Authorization

```typescript
async authorizeCommand(userId: string, vmId: string, command: any): Promise<boolean> {
  // Check user permissions
  const user = await this.prisma.user.findUnique({
    where: { id: userId },
    include: { permissions: true }
  });
  
  // Check VM ownership
  const vm = await this.prisma.vm.findUnique({
    where: { id: vmId }
  });
  
  if (vm.ownerId !== userId && !user.isAdmin) {
    return false;
  }
  
  // Check command type permissions
  if (command.type === 'UnsafeCommand' && !user.permissions.includes('unsafe_commands')) {
    return false;
  }
  
  return true;
}
```