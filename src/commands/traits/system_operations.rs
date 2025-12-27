//! System Operations trait abstraction
//!
//! This module defines the `SystemOperations` trait which abstracts all
//! platform-specific system operations, enabling a unified interface for
//! services, packages, processes, users, updates, security, and health checks.
//!
//! # Design Principles
//!
//! - **Platform abstraction**: Hide OS-specific details behind a common interface
//! - **Separation of concerns**: Each operation category is isolated
//! - **Extensibility**: Easy to add new platforms (macOS, BSD, etc.)
//! - **Testability**: Implementations can be mocked for testing
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      SafeCommandExecutor                        │
//! │   High-level command dispatcher and response builder            │
//! └───────────────────────────┬─────────────────────────────────────┘
//!                             │ delegates to
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      SystemOperations                           │
//! │   Abstracts all platform-specific system operations             │
//! └───────────────────────────┬─────────────────────────────────────┘
//!                             │ implemented by
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │   LinuxSystemOperations  |  WindowsSystemOperations             │
//! │   Platform-specific implementations                             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Operation Categories
//!
//! | Category | Operations |
//! |----------|------------|
//! | Services | list, control (start/stop/restart/enable/disable/status) |
//! | Packages | list, install, remove, update, search |
//! | Processes | list, kill, get top |
//! | Users | list |
//! | Updates | check, get history, get pending |
//! | Security | check, firewall status, security updates |
//! | Health | disk space, disk cleanup |

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use super::super::ServiceOperation;

/// Result type alias for system operations
/// Returns (stdout, stderr, optional structured data)
pub type SystemOperationResult = Result<(String, String, Option<Value>)>;

/// Trait for platform-specific system operations
///
/// This trait provides an abstraction layer for all operations that differ
/// between operating systems, including service management, package management,
/// process control, user listing, updates, security checks, and health checks.
///
/// # Implementation Guide
///
/// To implement support for a new platform:
///
/// 1. Create a struct that holds any necessary state (os_info, caches, etc.)
/// 2. Implement all methods of the `SystemOperations` trait
/// 3. Register your implementation in `PlatformFactory::create_system_operations()`
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow concurrent access
/// from multiple threads. Use interior mutability (Arc<Mutex<>>) if needed.
#[async_trait]
pub trait SystemOperations: Send + Sync {
    // ===== Service Operations =====

    /// List all system services
    ///
    /// # Returns
    ///
    /// - stdout: Human-readable summary
    /// - stderr: Empty on success
    /// - data: JSON array of service objects with name, status, start_type, etc.
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Uses `systemctl list-units --type=service`
    /// - **Windows**: Uses PowerShell `Get-Service`
    async fn list_services(&self) -> SystemOperationResult;

    /// Control a system service (start, stop, restart, enable, disable, status)
    ///
    /// # Parameters
    ///
    /// - `service`: Service name (validated for injection attacks)
    /// - `operation`: Operation to perform
    ///
    /// # Returns
    ///
    /// - stdout: Operation result or status output
    /// - stderr: Error messages if operation failed
    /// - data: Optional JSON with service state after operation
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Uses `systemctl <operation> <service>`
    /// - **Windows**: Uses PowerShell Start-Service, Stop-Service, etc.
    async fn control_service(
        &self,
        service: &str,
        operation: &ServiceOperation,
    ) -> SystemOperationResult;

    // ===== Package Operations =====

    /// List all installed packages
    ///
    /// # Returns
    ///
    /// - stdout: Summary with package count
    /// - stderr: Empty on success
    /// - data: JSON object with "packages" array
    ///
    /// # Platform Notes
    ///
    /// - **Linux (APT)**: Uses `dpkg -l`
    /// - **Linux (RPM)**: Uses `rpm -qa`
    /// - **Windows**: Uses `winget list` with fallback to PowerShell `Get-Package`
    async fn list_packages(&self) -> SystemOperationResult;

    /// Install a package
    ///
    /// # Parameters
    ///
    /// - `package`: Package name (validated for injection attacks)
    ///
    /// # Returns
    ///
    /// - stdout: Installation output
    /// - stderr: Error messages if installation failed
    ///
    /// # Platform Notes
    ///
    /// - **Linux (APT)**: Uses `apt-get install -y`
    /// - **Linux (DNF/YUM)**: Uses `dnf/yum install -y`
    /// - **Windows**: Uses `winget install --accept-source-agreements --accept-package-agreements`
    async fn install_package(&self, package: &str) -> SystemOperationResult;

    /// Remove a package
    ///
    /// # Parameters
    ///
    /// - `package`: Package name (validated for injection attacks)
    ///
    /// # Returns
    ///
    /// - stdout: Removal output
    /// - stderr: Error messages if removal failed
    ///
    /// # Platform Notes
    ///
    /// - **Linux (APT)**: Uses `apt-get remove -y`
    /// - **Linux (DNF/YUM)**: Uses `dnf/yum remove -y`
    /// - **Windows**: Uses `winget uninstall --disable-interactivity`
    async fn remove_package(&self, package: &str) -> SystemOperationResult;

    /// Update a package
    ///
    /// # Parameters
    ///
    /// - `package`: Package name (validated for injection attacks)
    ///
    /// # Returns
    ///
    /// - stdout: Update output
    /// - stderr: Error messages if update failed
    ///
    /// # Platform Notes
    ///
    /// - **Linux (APT)**: Uses `apt-get install --only-upgrade -y`
    /// - **Linux (DNF/YUM)**: Uses `dnf/yum upgrade -y`
    /// - **Windows**: Uses `winget upgrade --accept-source-agreements --accept-package-agreements`
    async fn update_package(&self, package: &str) -> SystemOperationResult;

    /// Search for packages
    ///
    /// # Parameters
    ///
    /// - `query`: Search query (validated for injection attacks)
    ///
    /// # Returns
    ///
    /// - stdout: Summary with match count
    /// - stderr: Empty on success
    /// - data: JSON object with "packages" array
    ///
    /// # Platform Notes
    ///
    /// - **Linux (APT)**: Uses `apt-cache search`
    /// - **Linux (DNF/YUM)**: Uses `dnf/yum search`
    /// - **Windows**: Uses `winget search`
    async fn search_packages(&self, query: &str) -> SystemOperationResult;

    // ===== Process Operations =====

    /// List running processes
    ///
    /// # Parameters
    ///
    /// - `limit`: Optional limit on number of processes returned
    ///
    /// # Returns
    ///
    /// - stdout: Summary with process count
    /// - stderr: Empty on success
    /// - data: JSON array of process objects with pid, name, cpu_usage, memory_kb
    ///
    /// # Implementation Notes
    ///
    /// Uses `sysinfo` crate for cross-platform process enumeration
    async fn list_processes(&self, limit: Option<usize>) -> SystemOperationResult;

    /// Kill a process
    ///
    /// # Parameters
    ///
    /// - `pid`: Process ID to kill
    /// - `force`: If true, skip protection for system processes
    ///
    /// # Returns
    ///
    /// - stdout: Success message
    /// - stderr: Error if process not found or kill failed
    ///
    /// # Implementation Notes
    ///
    /// Uses `sysinfo` crate for cross-platform process termination
    /// Protects system processes unless force=true
    async fn kill_process(&self, pid: u32, force: bool) -> SystemOperationResult;

    /// Get top processes by CPU or memory usage
    ///
    /// # Parameters
    ///
    /// - `limit`: Number of top processes to return
    /// - `sort_by`: Sort by "cpu" (default) or "memory"/"mem"
    ///
    /// # Returns
    ///
    /// - stdout: Summary with process count
    /// - stderr: Empty on success
    /// - data: JSON array of top process objects
    async fn get_top_processes(
        &self,
        limit: usize,
        sort_by: Option<&str>,
    ) -> SystemOperationResult;

    // ===== User Operations =====

    /// List system users
    ///
    /// # Returns
    ///
    /// - stdout: Summary with user count
    /// - stderr: Empty on success
    /// - data: JSON object with "users" array and "count"
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Parses `/etc/passwd`, returns users with UID >= 1000 or UID 0
    /// - **Windows**: Uses WMI `Win32_UserAccount` query for local users
    async fn list_users(&self) -> SystemOperationResult;

    // ===== Update Operations =====

    /// Check for system updates
    ///
    /// # Returns
    ///
    /// - stdout: Summary of available updates
    /// - stderr: Empty on success
    /// - data: JSON with update details
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Delegates to linux_updates module
    /// - **Windows**: Delegates to windows_updates module
    async fn check_updates(&self) -> SystemOperationResult;

    /// Get update history
    ///
    /// # Parameters
    ///
    /// - `days`: Number of days of history to retrieve
    ///
    /// # Returns
    ///
    /// - stdout: Summary of update history
    /// - stderr: Empty on success
    /// - data: JSON with history entries
    async fn get_update_history(&self, days: u32) -> SystemOperationResult;

    /// Get pending updates
    ///
    /// # Returns
    ///
    /// - stdout: Summary of pending updates
    /// - stderr: Empty on success
    /// - data: JSON with pending update details
    async fn get_pending_updates(&self) -> SystemOperationResult;

    // ===== Security Operations =====

    /// Check overall security status
    ///
    /// # Returns
    ///
    /// - stdout: Security status summary
    /// - stderr: Empty on success
    /// - data: JSON with security check results
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Delegates to linux_security module
    /// - **Windows**: Delegates to windows_defender module
    async fn check_security(&self) -> SystemOperationResult;

    /// Get firewall status
    ///
    /// # Returns
    ///
    /// - stdout: Firewall status summary
    /// - stderr: Empty on success
    /// - data: JSON with firewall configuration
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Checks ufw, firewalld, or iptables
    /// - **Windows**: Uses PowerShell `Get-NetFirewallProfile`
    async fn get_firewall_status(&self) -> SystemOperationResult;

    /// Get security updates
    ///
    /// # Returns
    ///
    /// - stdout: Security updates summary
    /// - stderr: Empty on success
    /// - data: JSON with security update details
    async fn get_security_updates(&self) -> SystemOperationResult;

    /// Run a security scan
    ///
    /// # Returns
    ///
    /// - stdout: Scan progress and results
    /// - stderr: Empty on success
    /// - data: JSON with scan results
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Returns unsupported (no equivalent to Defender quick scan)
    /// - **Windows**: Runs Windows Defender quick scan
    async fn run_security_scan(&self) -> SystemOperationResult;

    /// Get threat/malware history
    ///
    /// # Returns
    ///
    /// - stdout: Threat history summary
    /// - stderr: Empty on success
    /// - data: JSON with threat details
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Returns unsupported (no centralized threat history)
    /// - **Windows**: Gets Windows Defender threat history
    async fn get_threat_history(&self) -> SystemOperationResult;

    /// Check security modules (kernel security)
    ///
    /// # Returns
    ///
    /// - stdout: Security modules status
    /// - stderr: Empty on success
    /// - data: JSON with module details
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Checks AppArmor, SELinux, and other LSM modules
    /// - **Windows**: Returns unsupported (no equivalent kernel modules)
    async fn check_security_modules(&self) -> SystemOperationResult;

    // ===== Health Check Operations =====

    /// Check disk space
    ///
    /// # Parameters
    ///
    /// - `warning_threshold`: Usage percentage for warning (default: 80%)
    /// - `critical_threshold`: Usage percentage for critical (default: 90%)
    ///
    /// # Returns
    ///
    /// - stdout: Disk space status message
    /// - stderr: Empty on success
    /// - data: JSON with disk space details
    async fn check_disk_space(
        &self,
        warning_threshold: f64,
        critical_threshold: f64,
    ) -> SystemOperationResult;

    /// Perform disk cleanup
    ///
    /// # Parameters
    ///
    /// - `drive`: Mount point (Linux: "/") or drive letter (Windows: "C:")
    /// - `targets`: Cleanup targets: "cache", "old-kernels", "temp-files", "logs"
    ///
    /// # Returns
    ///
    /// - stdout: Cleanup summary with space freed
    /// - stderr: Warnings about elevated privileges if needed
    /// - data: JSON with detailed cleanup results
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Distribution-specific cleanup (APT/DNF/YUM)
    /// - **Windows**: Uses Windows Disk Cleanup utility
    async fn disk_cleanup(&self, drive: &str, targets: &[String]) -> SystemOperationResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation for testing
    struct MockSystemOperations;

    #[async_trait]
    impl SystemOperations for MockSystemOperations {
        async fn list_services(&self) -> SystemOperationResult {
            Ok(("2 services".to_string(), String::new(), Some(serde_json::json!([
                {"name": "service1", "status": "running"},
                {"name": "service2", "status": "stopped"}
            ]))))
        }

        async fn control_service(&self, service: &str, operation: &ServiceOperation) -> SystemOperationResult {
            Ok((format!("Service {} {:?}", service, operation), String::new(), None))
        }

        async fn list_packages(&self) -> SystemOperationResult {
            Ok(("10 packages".to_string(), String::new(), Some(serde_json::json!({"packages": []}))))
        }

        async fn install_package(&self, package: &str) -> SystemOperationResult {
            Ok((format!("Installed {}", package), String::new(), None))
        }

        async fn remove_package(&self, package: &str) -> SystemOperationResult {
            Ok((format!("Removed {}", package), String::new(), None))
        }

        async fn update_package(&self, package: &str) -> SystemOperationResult {
            Ok((format!("Updated {}", package), String::new(), None))
        }

        async fn search_packages(&self, query: &str) -> SystemOperationResult {
            Ok((format!("Found 5 packages matching '{}'", query), String::new(), Some(serde_json::json!({"packages": []}))))
        }

        async fn list_processes(&self, _limit: Option<usize>) -> SystemOperationResult {
            Ok(("100 processes".to_string(), String::new(), Some(serde_json::json!([]))))
        }

        async fn kill_process(&self, pid: u32, _force: bool) -> SystemOperationResult {
            Ok((format!("Killed process {}", pid), String::new(), None))
        }

        async fn get_top_processes(&self, limit: usize, _sort_by: Option<&str>) -> SystemOperationResult {
            Ok((format!("Top {} processes", limit), String::new(), Some(serde_json::json!([]))))
        }

        async fn list_users(&self) -> SystemOperationResult {
            Ok(("5 users".to_string(), String::new(), Some(serde_json::json!({"users": [], "count": 5}))))
        }

        async fn check_updates(&self) -> SystemOperationResult {
            Ok(("No updates".to_string(), String::new(), None))
        }

        async fn get_update_history(&self, _days: u32) -> SystemOperationResult {
            Ok(("Update history".to_string(), String::new(), None))
        }

        async fn get_pending_updates(&self) -> SystemOperationResult {
            Ok(("No pending updates".to_string(), String::new(), None))
        }

        async fn check_security(&self) -> SystemOperationResult {
            Ok(("Security OK".to_string(), String::new(), None))
        }

        async fn get_firewall_status(&self) -> SystemOperationResult {
            Ok(("Firewall active".to_string(), String::new(), None))
        }

        async fn get_security_updates(&self) -> SystemOperationResult {
            Ok(("No security updates".to_string(), String::new(), None))
        }

        async fn run_security_scan(&self) -> SystemOperationResult {
            Ok(("Scan complete".to_string(), String::new(), None))
        }

        async fn get_threat_history(&self) -> SystemOperationResult {
            Ok(("No threats".to_string(), String::new(), None))
        }

        async fn check_security_modules(&self) -> SystemOperationResult {
            Ok(("Modules OK".to_string(), String::new(), None))
        }

        async fn check_disk_space(&self, _warning: f64, _critical: f64) -> SystemOperationResult {
            Ok(("Disk OK".to_string(), String::new(), None))
        }

        async fn disk_cleanup(&self, drive: &str, _targets: &[String]) -> SystemOperationResult {
            Ok((format!("Cleaned {}", drive), String::new(), None))
        }
    }

    #[tokio::test]
    async fn test_mock_list_services() {
        let ops = MockSystemOperations;
        let result = ops.list_services().await;
        assert!(result.is_ok());
        let (stdout, _, data) = result.unwrap();
        assert!(stdout.contains("services"));
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_mock_control_service() {
        let ops = MockSystemOperations;
        let result = ops.control_service("test", &ServiceOperation::Start).await;
        assert!(result.is_ok());
        let (stdout, _, _) = result.unwrap();
        assert!(stdout.contains("test"));
        assert!(stdout.contains("Start"));
    }

    #[test]
    fn test_trait_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn SystemOperations>>();
    }
}
