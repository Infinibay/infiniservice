//! Main command executor that routes between safe and unsafe execution

use super::{IncomingMessage, CommandResponse, error_response, log_command_execution};
use crate::commands::safe_executor::SafeCommandExecutor;
use crate::commands::unsafe_executor::UnsafeCommandExecutor;
use anyhow::{Result, anyhow};
use log::{info, warn, error};
use std::time::Instant;

/// Main command executor that handles both safe and unsafe commands
pub struct CommandExecutor {
    safe_executor: SafeCommandExecutor,
    unsafe_executor: UnsafeCommandExecutor,
}

impl CommandExecutor {
    /// Create a new command executor
    pub fn new() -> Result<Self> {
        Ok(Self {
            safe_executor: SafeCommandExecutor::new()?,
            unsafe_executor: UnsafeCommandExecutor::new(),
        })
    }
    
    /// Execute an incoming message and return a response
    pub async fn execute(&self, message: IncomingMessage) -> Result<CommandResponse> {
        // Log the command execution
        log_command_execution(&message);
        
        let start_time = Instant::now();
        
        match message {
            IncomingMessage::SafeCommand(cmd) => {
                info!("Routing to safe command executor: {}", cmd.id);
                
                // Execute with validation and restrictions
                match self.safe_executor.execute(cmd.clone()).await {
                    Ok(mut response) => {
                        response.execution_time_ms = start_time.elapsed().as_millis() as u64;
                        Ok(response)
                    },
                    Err(e) => {
                        error!("Safe command execution failed: {}", e);
                        Ok(error_response(
                            cmd.id,
                            &format!("Command execution failed: {}", e),
                            "safe"
                        ))
                    }
                }
            },
            IncomingMessage::UnsafeCommand(cmd) => {
                warn!("⚠️ Routing to UNSAFE command executor: {}", cmd.id);
                warn!("⚠️ Executing raw command: {}", cmd.raw_command);
                
                // Execute raw command without restrictions
                match self.unsafe_executor.execute(cmd.clone()).await {
                    Ok(mut response) => {
                        response.execution_time_ms = start_time.elapsed().as_millis() as u64;
                        Ok(response)
                    },
                    Err(e) => {
                        error!("Unsafe command execution failed: {}", e);
                        Ok(error_response(
                            cmd.id,
                            &format!("Command execution failed: {}", e),
                            "unsafe"
                        ))
                    }
                }
            },
            IncomingMessage::Metrics => {
                // Metrics requests are handled separately in the main loop
                Err(anyhow!("Metrics requests should be handled in the main service loop"))
            }
        }
    }
    
    /// Check if the executor is ready
    pub fn is_ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{SafeCommandRequest, UnsafeCommandRequest, SafeCommandType};
    
    #[tokio::test]
    async fn test_executor_creation() {
        let executor = CommandExecutor::new();
        assert!(executor.is_ok());
        
        let executor = executor.unwrap();
        assert!(executor.is_ready());
    }
    
    #[tokio::test]
    async fn test_safe_command_routing() {
        let executor = CommandExecutor::new().unwrap();
        
        let cmd = SafeCommandRequest {
            id: "test-safe-123".to_string(),
            command_type: SafeCommandType::SystemInfo,
            params: None,
            timeout: Some(30),
        };
        
        let message = IncomingMessage::SafeCommand(cmd);
        let result = executor.execute(message).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.command_type, "safe");
    }
    
    #[tokio::test]
    async fn test_unsafe_command_routing() {
        let executor = CommandExecutor::new().unwrap();
        
        let cmd = UnsafeCommandRequest {
            id: "test-unsafe-456".to_string(),
            raw_command: "echo 'test'".to_string(),
            shell: Some("sh".to_string()),
            timeout: Some(5),
            working_dir: None,
            env_vars: None,
        };
        
        let message = IncomingMessage::UnsafeCommand(cmd);
        let result = executor.execute(message).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.command_type, "unsafe");
    }
}