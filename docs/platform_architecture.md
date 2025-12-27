# Platform Abstraction Architecture

This document describes the platform abstraction layer in InfiniService, which enables cross-platform support for Windows and Linux through a unified interface.

## Overview

The platform abstraction layer separates platform-specific implementation details from the high-level command execution logic, making the codebase more maintainable, testable, and extensible.

```
┌─────────────────────────────────────────────────────────────────┐
│                      SafeCommandExecutor                        │
│   High-level command dispatcher and response builder            │
└───────────────────────────┬─────────────────────────────────────┘
                            │ delegates to
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      PlatformFactory                            │
│   Creates platform-specific implementations at runtime          │
└───────────────────────────┬─────────────────────────────────────┘
                            │ creates
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SystemOperations                           │
│   Trait defining all platform-specific operations               │
└───────────────────────────┬─────────────────────────────────────┘
                            │ implemented by
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│   LinuxSystemOperations  │  WindowsSystemOperations             │
│   Linux-specific impl    │  Windows-specific impl               │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### SystemOperations Trait

Located in: `src/commands/traits/system_operations.rs`

Defines the interface for all platform-specific operations:

- **Services**: list, control (start/stop/restart/enable/disable/status)
- **Packages**: list, install, remove, update, search
- **Processes**: list, kill, get top
- **Users**: list
- **Updates**: check, get history, get pending
- **Security**: check, firewall status, security updates
- **Health**: disk space, disk cleanup

### PlatformFactory

Located in: `src/commands/platform_factory.rs`

Factory pattern implementation that creates the appropriate `SystemOperations` implementation based on the current platform using conditional compilation:

```rust
#[cfg(target_os = "linux")]
pub fn create_system_operations() -> Box<dyn SystemOperations> {
    Box::new(LinuxSystemOperations::new())
}

#[cfg(target_os = "windows")]
pub fn create_system_operations() -> Box<dyn SystemOperations> {
    Box::new(WindowsSystemOperations::new())
}
```

### LinuxSystemOperations

Located in: `src/commands/linux/system_operations.rs`

Implements `SystemOperations` for Linux, using:
- `systemctl` for service management
- `apt-get`/`dpkg` (Debian/Ubuntu) or `dnf`/`yum` (Fedora/RHEL) for packages
- `sysinfo` crate for process management
- `/etc/passwd` parsing for user listing
- `linux_updates` and `linux_security` modules for updates and security

### WindowsSystemOperations

Located in: `src/commands/windows/system_operations.rs`

Implements `SystemOperations` for Windows, using:
- PowerShell `Get-Service`/`Start-Service`/etc. for service management
- `winget` for package management
- `sysinfo` crate for process management
- WMI `Win32_UserAccount` for user listing
- `windows_updates` and `windows_defender` modules for updates and security

## Execution Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Sequence Diagram                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Client              SafeExecutor       PlatformFactory      SystemOps     │
│     │                      │                    │                 │         │
│     │  execute(ServiceList)│                    │                 │         │
│     │ ─────────────────────>                    │                 │         │
│     │                      │                    │                 │         │
│     │                      │ create_system_ops()│                 │         │
│     │                      │ ───────────────────>                 │         │
│     │                      │                    │                 │         │
│     │                      │   Box<dyn SystemOps>                 │         │
│     │                      │ <───────────────────                 │         │
│     │                      │                    │                 │         │
│     │                      │                    │ list_services() │         │
│     │                      │ ────────────────────────────────────>│         │
│     │                      │                    │                 │         │
│     │                      │                    │  (stdout, data) │         │
│     │                      │ <────────────────────────────────────│         │
│     │                      │                    │                 │         │
│     │     CommandResponse  │                    │                 │         │
│     │ <─────────────────────                    │                 │         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Adding Support for a New Platform

To add support for a new operating system (e.g., macOS):

1. **Create the implementation file**:
   ```
   src/commands/macos/system_operations.rs
   ```

2. **Implement the `SystemOperations` trait**:
   ```rust
   pub struct MacOSSystemOperations {
       os_info: &'static OsInfo,
   }

   #[async_trait]
   impl SystemOperations for MacOSSystemOperations {
       async fn list_services(&self) -> SystemOperationResult {
           // Use launchctl for macOS services
       }
       // ... implement all other methods
   }
   ```

3. **Update `PlatformFactory`**:
   ```rust
   #[cfg(target_os = "macos")]
   pub fn create_system_operations() -> Box<dyn SystemOperations> {
       Box::new(MacOSSystemOperations::new())
   }
   ```

4. **Add conditional compilation in `mod.rs`**:
   ```rust
   #[cfg(target_os = "macos")]
   pub mod macos;
   ```

5. **Add platform-specific tests** in `tests/platform_integration_tests.rs`

## Testing

### Unit Tests

Each implementation file contains unit tests for parsing and validation logic:

```bash
cargo test linux::system_operations
cargo test windows::system_operations
```

### Integration Tests

Platform integration tests are in `tests/platform_integration_tests.rs`:

```bash
cargo test --test platform_integration_tests
```

These tests verify:
- Factory creates correct implementation
- Basic operations work on the current platform
- Cross-platform functionality (process listing, disk space checks)

## Benefits of This Architecture

1. **Separation of Concerns**: Platform-specific logic is isolated in dedicated modules
2. **Testability**: Each platform can be tested independently with mock implementations
3. **Extensibility**: Adding new platforms only requires implementing the trait
4. **Maintainability**: `SafeCommandExecutor` is a thin dispatcher, not a monolithic file
5. **Type Safety**: Compile-time checks ensure platform compatibility
6. **Reusability**: `SystemOperations` can be used by other modules beyond `SafeCommandExecutor`

## File Structure

```
src/commands/
├── traits/
│   ├── mod.rs
│   ├── command_executor.rs
│   ├── package_manager.rs
│   ├── platform_operations.rs
│   └── system_operations.rs    # NEW: SystemOperations trait
│
├── linux/
│   ├── mod.rs
│   ├── apt_manager.rs
│   ├── rpm_manager.rs
│   ├── snap_manager.rs
│   ├── flatpak_manager.rs
│   └── system_operations.rs    # NEW: Linux implementation
│
├── windows/
│   ├── mod.rs
│   ├── registry_manager.rs
│   ├── store_manager.rs
│   ├── update_agent_manager.rs
│   └── system_operations.rs    # NEW: Windows implementation
│
├── platform_factory.rs         # NEW: Factory for creating implementations
├── safe_executor.rs            # REFACTORED: Now delegates to SystemOperations
└── mod.rs
```
