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

/// Command execution response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandResponse {
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
    async fn execute(&self, request: SafeCommandRequest) -> Result<CommandResponse>;
    
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
        
        assert_eq!(response.id, "cmd-789");
        assert!(response.success);
        assert_eq!(response.execution_time_ms, 100);
        assert_eq!(response.command_type, "safe");
    }
}