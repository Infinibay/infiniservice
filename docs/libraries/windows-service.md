# windows-service Library Documentation

## Overview
`windows-service` is a Rust library that provides facilities for management and implementation of Windows services. It's essential for monitoring Windows services and detecting unused system services in our infiniservice project.

## Version
- **Current Version**: 0.8.0
- **Platform**: Windows only
- **Trust Level**: ✅ **TRUSTABLE** - Specialized Windows service crate

## Key Features
- **Service Management**: Start, stop, query, and configure Windows services
- **Service Implementation**: Create new Windows services in Rust
- **Service Enumeration**: List all installed services and their states
- **Service Information**: Get detailed information about service configuration
- **Event Handling**: Handle service control events

## Use Cases in Infiniservice
1. **Service Monitoring**
   - List all installed Windows services
   - Monitor service states (running, stopped, disabled)
   - Track service startup types (automatic, manual, disabled)

2. **Unused Service Detection**
   - Identify services that haven't been used for extended periods
   - Detect default Windows services that are not being utilized
   - Analyze service dependencies and usage patterns

3. **System Optimization**
   - Provide recommendations for disabling unused services
   - Monitor service resource consumption
   - Track service lifecycle events

## Basic Usage Examples

### Enumerate All Services
```rust
use windows_service::{
    service_manager::{ServiceManager, ServiceManagerAccess},
    service::{ServiceAccess, ServiceState, ServiceType},
};

fn list_all_services() -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
    )?;

    let services = manager.enumerate_services(
        ServiceType::WIN32,
        ServiceState::All,
    )?;

    for service in services {
        println!(
            "Service: {} - Display Name: {} - State: {:?}",
            service.service_name,
            service.display_name,
            service.service_status.current_state
        );
    }

    Ok(())
}
```

### Get Detailed Service Information
```rust
use windows_service::{
    service_manager::{ServiceManager, ServiceManagerAccess},
    service::{ServiceAccess, ServiceInfo},
};

fn get_service_details(service_name: &str) -> windows_service::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )?;

    let service = manager.open_service(
        service_name,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
    )?;

    // Get service configuration
    let config = service.query_config()?;
    println!("Service Type: {:?}", config.service_type);
    println!("Start Type: {:?}", config.start_type);
    println!("Error Control: {:?}", config.error_control);
    println!("Binary Path: {:?}", config.executable_path);
    println!("Dependencies: {:?}", config.dependencies);

    // Get service status
    let status = service.query_status()?;
    println!("Current State: {:?}", status.current_state);
    println!("Process ID: {:?}", status.process_id);

    Ok(())
}
```

### Service Usage Tracker
```rust
use windows_service::{
    service_manager::{ServiceManager, ServiceManagerAccess},
    service::{ServiceAccess, ServiceState, ServiceType, ServiceStartType},
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

struct ServiceUsageTracker {
    service_states: HashMap<String, ServiceState>,
    last_check: u64,
}

impl ServiceUsageTracker {
    fn new() -> Self {
        Self {
            service_states: HashMap::new(),
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    fn scan_services(&mut self) -> windows_service::Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
        )?;

        let services = manager.enumerate_services(
            ServiceType::WIN32,
            ServiceState::All,
        )?;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for service in services {
            let service_name = service.service_name.clone();
            let current_state = service.service_status.current_state;

            // Check if service state changed
            if let Some(&previous_state) = self.service_states.get(&service_name) {
                if previous_state != current_state {
                    self.record_state_change(&service_name, previous_state, current_state, current_time);
                }
            }

            self.service_states.insert(service_name, current_state);
        }

        self.last_check = current_time;
        Ok(())
    }

    fn record_state_change(
        &self,
        service_name: &str,
        from_state: ServiceState,
        to_state: ServiceState,
        timestamp: u64,
    ) {
        println!(
            "Service {} changed from {:?} to {:?} at {}",
            service_name, from_state, to_state, timestamp
        );
        
        // Record in database or log file
        // This indicates service usage/activity
    }

    fn find_unused_services(&self) -> windows_service::Result<Vec<String>> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::ENUMERATE_SERVICE,
        )?;

        let services = manager.enumerate_services(
            ServiceType::WIN32,
            ServiceState::All,
        )?;

        let mut unused_services = Vec::new();

        for service in services {
            let service_name = &service.service_name;
            
            // Open service to get detailed configuration
            if let Ok(svc) = manager.open_service(
                service_name,
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            ) {
                if let Ok(config) = svc.query_config() {
                    // Check if service is set to automatic but not running
                    if config.start_type == ServiceStartType::AutoStart
                        && service.service_status.current_state == ServiceState::Stopped
                    {
                        unused_services.push(service_name.clone());
                    }
                }
            }
        }

        Ok(unused_services)
    }

    fn get_default_windows_services(&self) -> Vec<&'static str> {
        // List of common Windows services that might be unused
        vec![
            "Fax",
            "TapiSrv",
            "WSearch",
            "SysMain",
            "Themes",
            "TabletInputService",
            "WbioSrvc",
            "WMPNetworkSvc",
            "WerSvc",
            "Wecsvc",
            "WinRM",
            "WwanSvc",
            "XblAuthManager",
            "XblGameSave",
            "XboxGipSvc",
            "XboxNetApiSvc",
        ]
    }

    fn analyze_default_service_usage(&self) -> windows_service::Result<HashMap<String, bool>> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )?;

        let mut usage_analysis = HashMap::new();
        let default_services = self.get_default_windows_services();

        for service_name in default_services {
            if let Ok(service) = manager.open_service(
                service_name,
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            ) {
                if let Ok(status) = service.query_status() {
                    let is_used = status.current_state == ServiceState::Running;
                    usage_analysis.insert(service_name.to_string(), is_used);
                }
            }
        }

        Ok(usage_analysis)
    }
}
```

### Service Dependency Analysis
```rust
use windows_service::{
    service_manager::{ServiceManager, ServiceManagerAccess},
    service::ServiceAccess,
};

struct ServiceDependencyAnalyzer;

impl ServiceDependencyAnalyzer {
    fn analyze_service_dependencies(service_name: &str) -> windows_service::Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        )?;

        let service = manager.open_service(
            service_name,
            ServiceAccess::QUERY_CONFIG,
        )?;

        let config = service.query_config()?;
        
        println!("Service: {}", service_name);
        println!("Dependencies: {:?}", config.dependencies);
        
        // Analyze if dependencies are also running
        for dependency in &config.dependencies {
            if let Ok(dep_service) = manager.open_service(
                dependency,
                ServiceAccess::QUERY_STATUS,
            ) {
                if let Ok(status) = dep_service.query_status() {
                    println!("  Dependency {} is {:?}", dependency, status.current_state);
                }
            }
        }

        Ok(())
    }
}
```

## Integration Strategy
1. **Periodic Monitoring**: Regularly scan service states to detect changes
2. **Usage Pattern Analysis**: Track service start/stop patterns over time
3. **Default Service Analysis**: Focus on commonly unused Windows services
4. **Dependency Mapping**: Understand service relationships for optimization

## Windows Service Categories to Monitor
- **System Services**: Core Windows functionality
- **Application Services**: Third-party application services
- **Network Services**: Network-related services
- **Hardware Services**: Device and hardware-related services

## Performance Considerations
- **Permission Requirements**: Requires appropriate Windows privileges
- **Scan Frequency**: Balance between monitoring and system impact
- **Service Access**: Use minimal required access rights

## Error Handling
- Handle access denied errors gracefully
- Implement retry logic for transient failures
- Log service enumeration errors appropriately

## Documentation Links
- [Official Documentation](https://docs.rs/windows-service/)
- [GitHub Repository](https://github.com/mullvad/windows-service-rs)
- [Crates.io Page](https://crates.io/crates/windows-service)
