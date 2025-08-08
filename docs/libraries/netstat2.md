# netstat2 Library Documentation

## Overview
`netstat2` is a cross-platform Rust library for retrieving network socket information. It provides functionality similar to the traditional `netstat` command-line tool, allowing us to monitor network connections and port usage by applications.

## Version
- **Current Version**: 0.11.1
- **Trust Level**: ✅ **TRUSTABLE** - Well-maintained crate with good community adoption

## Key Features
- **Cross-platform support**: Windows, Linux, macOS
- **Socket information**: TCP and UDP connections
- **Port monitoring**: Listening ports and active connections
- **Process association**: Link network connections to specific processes
- **Connection states**: Track connection status (LISTEN, ESTABLISHED, etc.)

## Use Cases in Infiniservice
1. **Port Usage Monitoring**
   - Identify which applications are using specific ports
   - Monitor listening services
   - Track outbound connections

2. **Network Security Analysis**
   - Detect unauthorized network connections
   - Monitor for suspicious port usage
   - Track application network behavior

3. **Application Network Profiling**
   - Analyze network usage patterns per application
   - Identify network-intensive applications
   - Monitor connection lifecycle

## Basic Usage Examples

### List All Network Connections
```rust
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};

// Get all TCP and UDP sockets
let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

match get_sockets_info(af_flags, proto_flags) {
    Ok(sockets) => {
        for socket in sockets {
            println!(
                "Protocol: {:?}, Local: {}:{}, Remote: {}:{}, State: {:?}, PID: {:?}",
                socket.protocol_socket_info.protocol,
                socket.local_addr(),
                socket.local_port(),
                socket.remote_addr().unwrap_or_default(),
                socket.remote_port().unwrap_or_default(),
                socket.state,
                socket.associated_pids
            );
        }
    }
    Err(e) => eprintln!("Error getting socket info: {}", e),
}
```

### Monitor Listening Ports
```rust
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, TcpState};

let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
let proto_flags = ProtocolFlags::TCP;

match get_sockets_info(af_flags, proto_flags) {
    Ok(sockets) => {
        let listening_sockets: Vec<_> = sockets
            .into_iter()
            .filter(|socket| socket.state == TcpState::Listen)
            .collect();

        for socket in listening_sockets {
            println!(
                "Listening on port {}, PID: {:?}",
                socket.local_port(),
                socket.associated_pids
            );
        }
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

### Track Application Network Usage
```rust
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};
use std::collections::HashMap;

fn get_network_usage_by_process() -> Result<HashMap<u32, Vec<String>>, Box<dyn std::error::Error>> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    
    let sockets = get_sockets_info(af_flags, proto_flags)?;
    let mut process_connections: HashMap<u32, Vec<String>> = HashMap::new();
    
    for socket in sockets {
        if let Some(pids) = socket.associated_pids {
            for pid in pids {
                let connection_info = format!(
                    "{}:{}->{}:{}",
                    socket.local_addr(),
                    socket.local_port(),
                    socket.remote_addr().unwrap_or_default(),
                    socket.remote_port().unwrap_or_default()
                );
                
                process_connections
                    .entry(pid)
                    .or_insert_with(Vec::new)
                    .push(connection_info);
            }
        }
    }
    
    Ok(process_connections)
}
```

## Integration Strategy
1. **Periodic Scanning**: Regularly scan for network connections to track changes
2. **Process Correlation**: Combine with `sysinfo` to get process names and details
3. **Port Monitoring**: Track which applications bind to specific ports
4. **Connection Tracking**: Monitor connection establishment and termination

## Data Collection Goals
- **Inbound Connections**: Track which ports applications are listening on
- **Outbound Connections**: Monitor external connections made by applications
- **Connection Patterns**: Analyze network behavior over time
- **Security Monitoring**: Detect unusual network activity

## Performance Considerations
- **Scan Frequency**: Balance between real-time monitoring and system load
- **Filtering**: Focus on relevant protocols and address families
- **Caching**: Cache results to avoid excessive system calls

## Platform-Specific Notes
- **Windows**: Uses Windows API for socket enumeration
- **Linux**: Reads from `/proc/net/` files for socket information
- **Permissions**: May require elevated privileges for complete process information

## Error Handling
- Handle cases where process information is not available
- Gracefully handle permission errors
- Implement retry logic for transient failures

## Documentation Links
- [Crates.io Page](https://crates.io/crates/netstat2)
- [GitHub Repository](https://github.com/zhongzc/netstat2)
