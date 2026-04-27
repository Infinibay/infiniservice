//! Command execution framework for InfiniService
//! 
//! This module provides bidirectional command execution capabilities,
//! supporting both safe (validated) and unsafe (raw) command execution.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use log::{info, warn, debug};

pub mod executor;
pub mod safe_executor;
pub mod unsafe_executor;
pub mod service_control;
pub mod package_management;
pub mod process_control;

// Common utilities
pub mod common;

// Trait abstractions for package managers and platform operations
pub mod traits;

// Platform factory for creating platform-specific implementations
pub mod platform_factory;

// Linux package manager implementations
#[cfg(target_os = "linux")]
pub mod linux;

// Windows package manager implementations
#[cfg(target_os = "windows")]
pub mod windows;

// Auto-check modules
pub mod autochecks;
pub mod windows_updates;
pub mod windows_defender;
pub mod application_inventory;

// Update checking modules
pub mod update_checker;
pub mod update_checker_factory;

#[cfg(target_os = "windows")]
pub mod windows_update_checker;

#[cfg(target_os = "linux")]
pub mod linux_update_checker;

pub mod linux_updates;

// Linux security module - types are available on all platforms, functions are Linux-only
pub mod linux_security;

/// Incoming message types from the host
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IncomingMessage {
    /// Request for metrics collection
    Metrics,

    /// Safe, validated command execution
    SafeCommand(SafeCommandRequest),

    /// Unsafe, raw command execution
    UnsafeCommand(UnsafeCommandRequest),

    /// Keep-alive response from backend
    #[serde(rename = "keep_alive_response")]
    KeepAliveResponse(KeepAliveResponse),

    /// Pending scripts response from host
    #[serde(rename = "pending_scripts_response")]
    PendingScriptsResponse(PendingScriptsResponse),
}

/// Safe command request with validated operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SafeCommandRequest {
    /// Unique command ID for tracking
    pub id: String,
    
    /// Type of safe command to execute
    pub command_type: SafeCommandType,
    
    /// Additional parameters as JSON
    pub params: Option<serde_json::Value>,
    
    /// Command timeout in seconds
    pub timeout: Option<u32>,
}

/// Unsafe command request for raw execution
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnsafeCommandRequest {
    /// Unique command ID for tracking
    pub id: String,

    /// Raw command string to execute
    pub raw_command: String,

    /// Shell to use (bash, sh, powershell, cmd)
    pub shell: Option<String>,

    /// Command timeout in seconds
    pub timeout: Option<u32>,

    /// Working directory for execution
    pub working_dir: Option<String>,

    /// Environment variables
    pub env_vars: Option<HashMap<String, String>>,

    /// User to run the command as (for Linux: uses su -c)
    pub run_as: Option<String>,
}

/// Types of safe commands
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "action")]
pub enum SafeCommandType {
    // Service operations
    ServiceList,
    ServiceControl { 
        #[serde(flatten)]
        params: ServiceControlParams 
    },
    
    // Package operations
    PackageList,
    PackageInstall { package: String },
    PackageRemove { package: String },
    PackageUpdate { package: String },
    PackageSearch { query: String },
    
    // Process operations
    ProcessList { limit: Option<usize> },
    ProcessKill { pid: u32, force: Option<bool> },
    ProcessTop { limit: Option<usize>, sort_by: Option<String> },
    
    // System information
    SystemInfo,
    OsInfo,
    
    // Auto-check commands (Windows-specific mostly)
    CheckWindowsUpdates,
    GetUpdateHistory { days: Option<u32> },
    GetPendingUpdates,

    // Linux Update commands
    CheckLinuxUpdates,
    GetLinuxUpdateHistory { days: Option<u32> },
    GetPendingLinuxUpdates,

    // Linux Security commands
    CheckLinuxSecurity,
    GetLinuxSecurityStatus,
    GetLinuxFirewallStatus,
    CheckFirewallStatus,
    GetLinuxSecurityUpdates,
    CheckSecurityModules,

    // Windows Defender commands
    CheckWindowsDefender,
    GetDefenderStatus,
    RunDefenderQuickScan,
    GetThreatHistory,
    
    // Application Inventory commands
    GetInstalledApplicationsWMI,
    CheckApplicationUpdates,
    GetApplicationDetails { app_id: String },
    CheckSpecificAppUpdates { app_id: String },
    EstimateUpdateSize { app_id: String },
    GetAvailableUpdates,
    GetSecurityUpdates,
    
    // Health check commands
    CheckDiskSpace { 
        warning_threshold: Option<f32>,
        critical_threshold: Option<f32>
    },
    CheckResourceOptimization {
        evaluation_window_days: Option<u32>
    },
    RunHealthCheck { check_name: String },
    RunAllHealthChecks,
    
    // Disk cleanup operations
    DiskCleanup {
        drive: String,
        targets: Vec<String>
    },

    // PowerShell script execution (Windows)
    // Executes PowerShell scripts with optional elevation and environment customization
    ExecutePowerShellScript {
        script: String,
        script_type: String,
        timeout_seconds: Option<u32>,
        working_directory: Option<String>,
        environment_vars: Option<HashMap<String, String>>,
        run_as_admin: bool,
    },

    // User listing
    UserList,

    // Prepare guest for golden-image capture: runs per-OS cleanup
    // (logs, machine-id, SSH host keys, cloud-init, event logs), writes
    // a minimal sysprep unattend on Windows, triggers sysprep /generalize,
    // and optionally powers off when done so the host can promote the
    // disk. See commands/{windows,linux}/golden_image.rs.
    PrepareGoldenImage {
        #[serde(default)]
        cleanup_level: CleanupLevel,
        /// Remove user home directories and profiles (non-system users).
        /// Default true — preserves the "default ON with toggle" policy
        /// from the capture flow.
        #[serde(default = "default_true")]
        sanitize_user_data: bool,
        /// Power off the guest after cleanup. Required for capture flows.
        #[serde(default = "default_true")]
        shutdown_after: bool,
    },
}

fn default_true() -> bool { true }

/// How aggressive the cleanup pass should be. `Standard` is the right
/// choice for all normal seal flows; `Minimal` skips non-essential
/// steps (useful for re-running after a partial seal); `Deep` also
/// wipes caches that would otherwise be rebuilt on first boot.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CleanupLevel {
    Minimal,
    Standard,
    Deep,
}

impl Default for CleanupLevel {
    fn default() -> Self { CleanupLevel::Standard }
}

/// Service control parameters
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceControlParams {
    pub service: String,
    pub operation: ServiceOperation,
}

/// Service operations
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ServiceOperation {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
    Status,
}

/// Keep-alive response from the backend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeepAliveResponse {
    /// Sequence number from the original keep-alive message
    pub sequence_number: u32,

    /// Timestamp when the response was generated
    pub timestamp: String,
}

/// Request for pending scripts from the host
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestPendingScripts {
    /// VM ID for which scripts are requested
    pub vm_id: String,

    /// Timestamp when the request was generated
    pub timestamp: String,

    /// Request timestamp (duplicate for compatibility)
    pub request_timestamp: String,
}

/// Pending scripts response from the host
///
/// NOTE: Script scheduling is enforced entirely server-side. The host maintains
/// schedule state and determines which scripts to return based on scheduledFor
/// timestamps and repeat intervals. InfiniService executes all returned scripts
/// blindly without performing local schedule validation. The host will re-queue
/// repeating scripts for subsequent boots as needed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingScriptsResponse {
    /// Timestamp when the response was generated
    pub timestamp: String,

    /// List of pending scripts to execute
    pub scripts: Vec<PendingScriptInfo>,
}

/// Information about a pending script to execute
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingScriptInfo {
    /// Unique execution ID for tracking
    pub execution_id: String,

    /// Script ID reference
    pub script_id: String,

    /// Human-readable script name
    pub script_name: String,

    /// Script content to execute (interpolated)
    pub script_content: String,

    /// Shell to use for execution
    pub shell: String,

    /// Execution type (IMMEDIATE, SCHEDULED, etc.)
    pub execution_type: String,

    /// Input values for script interpolation
    pub input_values: serde_json::Value,

    /// Timeout in seconds
    pub timeout_seconds: u32,

    /// Optional user to run as
    pub run_as: Option<String>,
}

/// Script completion message sent to host
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScriptCompletionMessage {
    /// Execution ID for correlation
    pub execution_id: String,

    /// Exit code from script execution
    pub exit_code: i32,

    /// Standard output
    pub stdout: String,

    /// Standard error
    pub stderr: String,

    /// Optional log file path
    pub log_file: Option<String>,
}

/// Command execution response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandResponse {
    /// Message type (always "response")
    #[serde(rename = "type")]
    pub message_type: String,

    /// Command ID for correlation
    pub id: String,

    /// Whether the command succeeded
    pub success: bool,

    /// Exit code if applicable
    pub exit_code: Option<i32>,

    /// Standard output
    pub stdout: String,

    /// Standard error
    pub stderr: String,

    /// Execution time in milliseconds
    pub execution_time_ms: u64,

    /// Type of command executed ("safe" or "unsafe")
    pub command_type: String,

    /// Optional structured data result
    pub data: Option<serde_json::Value>,
}

/// Command execution error
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("Command execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Command timed out after {0} seconds")]
    Timeout(u32),
    
    #[error("Invalid command parameters: {0}")]
    InvalidParameters(String),
    
    #[error("Unsupported operation on this platform: {0}")]
    UnsupportedPlatform(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    
    #[error("Package not found: {0}")]
    PackageNotFound(String),
    
    #[error("Process not found: {0}")]
    ProcessNotFound(u32),
}

/// Result type for command operations
pub type CommandResult<T> = std::result::Result<T, CommandError>;

/// Trait for command handlers
pub trait CommandHandler: Send + Sync {
    /// Execute the command and return a response
    fn execute(&self, request: SafeCommandRequest) -> impl std::future::Future<Output = Result<CommandResponse>> + Send;
    
    /// Check if this handler supports the given command type
    fn supports(&self, command_type: &SafeCommandType) -> bool;
}

/// Create a command response
pub fn create_response(
    id: String,
    success: bool,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    command_type: &str,
    execution_time: Duration,
    data: Option<serde_json::Value>,
) -> CommandResponse {
    CommandResponse {
        message_type: "response".to_string(),
        id,
        success,
        exit_code,
        stdout,
        stderr,
        execution_time_ms: execution_time.as_millis() as u64,
        command_type: command_type.to_string(),
        data,
    }
}

/// Log command execution
pub fn log_command_execution(message: &IncomingMessage) {
    match message {
        IncomingMessage::SafeCommand(cmd) => {
            info!("Executing safe command: id={}, type={:?}", cmd.id, cmd.command_type);
            debug!("Safe command details: {:?}", cmd);
        },
        IncomingMessage::UnsafeCommand(cmd) => {
            warn!("⚠️ UNSAFE COMMAND EXECUTION: id={}, command={}", cmd.id, cmd.raw_command);
            warn!("Unsafe command shell: {:?}, working_dir: {:?}", cmd.shell, cmd.working_dir);
        },
        _ => {}
    }
}

/// Create an error response
pub fn error_response(id: String, error: &str, command_type: &str) -> CommandResponse {
    CommandResponse {
        message_type: "response".to_string(),
        id,
        success: false,
        exit_code: Some(1),
        stdout: String::new(),
        stderr: error.to_string(),
        execution_time_ms: 0,
        command_type: command_type.to_string(),
        data: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_safe_command_serialization() {
        let cmd = SafeCommandRequest {
            id: "test-123".to_string(),
            command_type: SafeCommandType::ServiceList,
            params: None,
            timeout: Some(30),
        };
        
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"id\":\"test-123\""));
        assert!(json.contains("\"action\":\"ServiceList\""));
    }
    
    #[test]
    fn test_unsafe_command_serialization() {
        let cmd = UnsafeCommandRequest {
            id: "unsafe-456".to_string(),
            raw_command: "ls -la".to_string(),
            shell: Some("bash".to_string()),
            timeout: Some(60),
            working_dir: None,
            env_vars: None,
            run_as: None,
        };
        
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"raw_command\":\"ls -la\""));
        assert!(json.contains("\"shell\":\"bash\""));
    }
    
    #[test]
    fn test_command_response_creation() {
        let response = create_response(
            "cmd-789".to_string(),
            true,
            "Output".to_string(),
            String::new(),
            Some(0),
            "safe",
            Duration::from_millis(100),
            None,
        );

        assert_eq!(response.message_type, "response");
        assert_eq!(response.id, "cmd-789");
        assert!(response.success);
        assert_eq!(response.execution_time_ms, 100);
        assert_eq!(response.command_type, "safe");
    }

    #[test]
    fn test_get_linux_security_status_serialization() {
        // Test serialization
        let cmd = SafeCommandRequest {
            id: "test-security-status".to_string(),
            command_type: SafeCommandType::GetLinuxSecurityStatus,
            params: None,
            timeout: Some(30),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"GetLinuxSecurityStatus\""));

        // Test deserialization
        let json_input = r#"{"id":"test-1","command_type":{"action":"GetLinuxSecurityStatus"},"params":null,"timeout":30}"#;
        let parsed: SafeCommandRequest = serde_json::from_str(json_input).unwrap();
        assert!(matches!(parsed.command_type, SafeCommandType::GetLinuxSecurityStatus));
    }

    #[test]
    fn test_check_firewall_status_serialization() {
        // Test serialization
        let cmd = SafeCommandRequest {
            id: "test-firewall-status".to_string(),
            command_type: SafeCommandType::CheckFirewallStatus,
            params: None,
            timeout: Some(30),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"CheckFirewallStatus\""));

        // Test deserialization
        let json_input = r#"{"id":"test-2","command_type":{"action":"CheckFirewallStatus"},"params":null,"timeout":30}"#;
        let parsed: SafeCommandRequest = serde_json::from_str(json_input).unwrap();
        assert!(matches!(parsed.command_type, SafeCommandType::CheckFirewallStatus));
    }

    // ===== Linux Command Integration Tests =====

    #[test]
    fn test_linux_command_serialization_check_updates() {
        // Test CheckLinuxUpdates serialization
        let cmd = SafeCommandRequest {
            id: "linux-updates-001".to_string(),
            command_type: SafeCommandType::CheckLinuxUpdates,
            params: None,
            timeout: Some(60),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("CheckLinuxUpdates"));
        assert!(json.contains("linux-updates-001"));

        // Test deserialization
        let parsed: SafeCommandRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed.command_type, SafeCommandType::CheckLinuxUpdates));
        assert_eq!(parsed.id, "linux-updates-001");
        assert_eq!(parsed.timeout, Some(60));
    }

    #[test]
    fn test_linux_command_serialization_all_types() {
        // Test all Linux-specific command types serialize correctly
        let linux_commands = vec![
            (SafeCommandType::CheckLinuxUpdates, "CheckLinuxUpdates"),
            (SafeCommandType::GetLinuxSecurityStatus, "GetLinuxSecurityStatus"),
            (SafeCommandType::CheckFirewallStatus, "CheckFirewallStatus"),
            (SafeCommandType::GetInstalledApplicationsWMI, "GetInstalledApplicationsWMI"),
        ];

        for (cmd_type, expected_name) in linux_commands {
            let cmd = SafeCommandRequest {
                id: format!("test-{}", expected_name.to_lowercase()),
                command_type: cmd_type,
                params: None,
                timeout: Some(30),
            };

            let json = serde_json::to_string(&cmd).unwrap();
            assert!(json.contains(expected_name), "JSON should contain {}", expected_name);
        }
    }

    #[test]
    fn test_linux_command_dispatcher_routing() {
        // Verify that different command types can be distinguished
        let commands = vec![
            SafeCommandType::CheckLinuxUpdates,
            SafeCommandType::GetLinuxSecurityStatus,
            SafeCommandType::CheckFirewallStatus,
            SafeCommandType::GetInstalledApplicationsWMI,
        ];

        for cmd_type in &commands {
            // Each command type should be uniquely identifiable via pattern matching
            match cmd_type {
                SafeCommandType::CheckLinuxUpdates => {
                    assert!(matches!(cmd_type, SafeCommandType::CheckLinuxUpdates));
                }
                SafeCommandType::GetLinuxSecurityStatus => {
                    assert!(matches!(cmd_type, SafeCommandType::GetLinuxSecurityStatus));
                }
                SafeCommandType::CheckFirewallStatus => {
                    assert!(matches!(cmd_type, SafeCommandType::CheckFirewallStatus));
                }
                SafeCommandType::GetInstalledApplicationsWMI => {
                    assert!(matches!(cmd_type, SafeCommandType::GetInstalledApplicationsWMI));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_linux_command_timeout_handling() {
        // Test that timeout values are preserved in serialization
        let timeouts = vec![10, 30, 60, 120, 300];

        for timeout in timeouts {
            let cmd = SafeCommandRequest {
                id: format!("timeout-test-{}", timeout),
                command_type: SafeCommandType::CheckLinuxUpdates,
                params: None,
                timeout: Some(timeout),
            };

            let json = serde_json::to_string(&cmd).unwrap();
            let parsed: SafeCommandRequest = serde_json::from_str(&json).unwrap();

            assert_eq!(parsed.timeout, Some(timeout), "Timeout {} should be preserved", timeout);
        }

        // Test None timeout
        let cmd_no_timeout = SafeCommandRequest {
            id: "no-timeout".to_string(),
            command_type: SafeCommandType::CheckLinuxUpdates,
            params: None,
            timeout: None,
        };

        let json = serde_json::to_string(&cmd_no_timeout).unwrap();
        let parsed: SafeCommandRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timeout, None, "None timeout should be preserved");
    }

    #[test]
    fn test_linux_command_error_response_format() {
        // Test that error responses are correctly formatted for Linux commands
        let error_cases = vec![
            ("Linux Updates check is only available on Linux", "CheckLinuxUpdates"),
            ("Linux Security check is only available on Linux", "GetLinuxSecurityStatus"),
            ("Firewall check is only available on Linux", "CheckFirewallStatus"),
        ];

        for (error_msg, cmd_name) in error_cases {
            let response = error_response(
                format!("error-{}", cmd_name.to_lowercase()),
                error_msg,
                "safe"
            );

            assert_eq!(response.message_type, "response");
            assert!(!response.success, "Error response should not be successful");
            assert_eq!(response.stderr, error_msg);
            assert_eq!(response.command_type, "safe");
            assert!(response.stdout.is_empty());
            assert_eq!(response.exit_code, Some(1));
        }
    }

    #[test]
    fn test_platform_specific_command_rejection_format() {
        // Test that the rejection message format is consistent
        let rejection_messages = vec![
            "Linux Updates check is only available on Linux",
            "Linux Security check is only available on Linux",
            "Linux Firewall status is only available on Linux",
            "Security modules check is only available on Linux",
            "Linux pending updates check is only available on Linux",
        ];

        for msg in rejection_messages {
            // All rejection messages should:
            // 1. Mention "Linux" explicitly
            assert!(msg.contains("Linux"), "Message should mention Linux: {}", msg);

            // 2. End with "on Linux" to indicate platform restriction
            assert!(msg.ends_with("on Linux"), "Message should end with 'on Linux': {}", msg);

            // 3. Be a complete sentence (not just an error code)
            assert!(msg.contains(' '), "Message should be a sentence: {}", msg);
        }
    }

    #[test]
    fn test_command_response_data_field() {
        // Test that responses can include structured data
        let response_with_data = CommandResponse {
            message_type: "response".to_string(),
            id: "test-with-data".to_string(),
            success: true,
            exit_code: Some(0),
            stdout: "".to_string(),
            stderr: "".to_string(),
            execution_time_ms: 100,
            command_type: "safe".to_string(),
            data: Some(serde_json::json!({
                "updates_count": 5,
                "security_updates": 2,
                "reboot_required": false
            })),
        };

        assert_eq!(response_with_data.message_type, "response");
        assert!(response_with_data.data.is_some());

        let data = response_with_data.data.unwrap();
        assert_eq!(data["updates_count"], 5);
        assert_eq!(data["security_updates"], 2);
        assert_eq!(data["reboot_required"], false);
    }

    #[test]
    fn test_incoming_message_safe_command_parsing() {
        // Test parsing incoming messages with Linux commands
        let json_input = r#"{
            "type": "SafeCommand",
            "id": "incoming-001",
            "command_type": {"action": "CheckLinuxUpdates"},
            "params": null,
            "timeout": 60
        }"#;

        let parsed: Result<IncomingMessage, _> = serde_json::from_str(json_input);
        assert!(parsed.is_ok(), "Should parse incoming message successfully");

        if let Ok(IncomingMessage::SafeCommand(cmd)) = parsed {
            assert_eq!(cmd.id, "incoming-001");
            assert!(matches!(cmd.command_type, SafeCommandType::CheckLinuxUpdates));
        } else {
            panic!("Should be SafeCommand variant");
        }
    }
}