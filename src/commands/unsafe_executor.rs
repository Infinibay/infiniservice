//! Unsafe command executor for raw command execution without restrictions

use super::{UnsafeCommandRequest, CommandResponse, create_response};
use crate::os_detection::get_os_info;
use anyhow::{Result, Context};
use log::{warn, error, debug};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::path::PathBuf;

/// Executor for unsafe, raw commands - NO RESTRICTIONS
pub struct UnsafeCommandExecutor {
    os_info: &'static crate::os_detection::OsInfo,
}

impl UnsafeCommandExecutor {
    /// Create a new unsafe command executor
    pub fn new() -> Self {
        Self {
            os_info: get_os_info(),
        }
    }
    
    /// Execute an unsafe command request
    /// WARNING: This executes raw commands without any validation or sanitization
    pub async fn execute(&self, request: UnsafeCommandRequest) -> Result<CommandResponse> {
        let start_time = Instant::now();
        
        warn!("⚠️ UNSAFE COMMAND EXECUTION STARTED");
        warn!("⚠️ Command ID: {}", request.id);
        warn!("⚠️ Raw command: {}", request.raw_command);
        warn!("⚠️ Shell: {:?}", request.shell);
        warn!("⚠️ Working directory: {:?}", request.working_dir);
        
        // Get shell command based on OS and request
        let (shell_cmd, shell_args) = self.os_info.get_shell_command(request.shell.as_deref());
        
        debug!("Using shell: {} with args: {:?}", shell_cmd, shell_args);
        
        // Build the command
        let mut cmd = Command::new(shell_cmd);
        
        // Add shell arguments and the command
        for arg in shell_args {
            cmd.arg(arg);
        }
        cmd.arg(&request.raw_command);
        
        // Set working directory if specified
        if let Some(working_dir) = &request.working_dir {
            let path = PathBuf::from(working_dir);
            if path.exists() && path.is_dir() {
                cmd.current_dir(path);
                debug!("Set working directory to: {}", working_dir);
            } else {
                warn!("Working directory does not exist or is not a directory: {}", working_dir);
            }
        }
        
        // Set environment variables if specified
        if let Some(env_vars) = &request.env_vars {
            for (key, value) in env_vars {
                cmd.env(key, value);
                debug!("Set environment variable: {}={}", key, value);
            }
        }
        
        // Configure stdio
        cmd.stdin(Stdio::null())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());
        
        // Execute the command with timeout if specified
        let result = if let Some(timeout_secs) = request.timeout {
            self.execute_with_timeout(cmd, Duration::from_secs(timeout_secs as u64)).await
        } else {
            self.execute_without_timeout(cmd).await
        };
        
        // Build response
        match result {
            Ok((stdout, stderr, exit_code)) => {
                let success = exit_code == 0;
                
                if success {
                    warn!("⚠️ UNSAFE COMMAND COMPLETED SUCCESSFULLY");
                } else {
                    warn!("⚠️ UNSAFE COMMAND FAILED WITH EXIT CODE: {}", exit_code);
                }
                
                Ok(create_response(
                    request.id,
                    success,
                    stdout,
                    stderr,
                    Some(exit_code),
                    "unsafe",
                    start_time.elapsed(),
                    None,
                ))
            },
            Err(e) => {
                error!("⚠️ UNSAFE COMMAND EXECUTION ERROR: {}", e);
                
                Ok(create_response(
                    request.id,
                    false,
                    String::new(),
                    format!("Command execution failed: {}", e),
                    Some(1),
                    "unsafe",
                    start_time.elapsed(),
                    None,
                ))
            }
        }
    }
    
    /// Execute command without timeout
    async fn execute_without_timeout(&self, mut cmd: Command) -> Result<(String, String, i32)> {
        debug!("Executing command without timeout");
        
        let output = cmd.output()
            .context("Failed to execute command")?;
        
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);
        
        debug!("Command completed with exit code: {}", exit_code);
        debug!("Stdout length: {} bytes", stdout.len());
        debug!("Stderr length: {} bytes", stderr.len());
        
        Ok((stdout, stderr, exit_code))
    }
    
    /// Execute command with timeout
    async fn execute_with_timeout(&self, mut cmd: Command, timeout: Duration) -> Result<(String, String, i32)> {
        debug!("Executing command with timeout: {:?}", timeout);
        
        // Configure the command to capture output
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped())
           .stdin(Stdio::null());
        
        // Spawn the child process using tokio
        let child = tokio::process::Command::from(cmd)
            .spawn()
            .context("Failed to spawn command")?;
        
        // Get the PID before moving child
        let pid = child.id().unwrap_or(0);
        
        // Use tokio for async timeout
        let result = tokio::time::timeout(timeout, async {
            let output = child.wait_with_output().await
                .context("Failed to wait for command")?;
            
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);
            
            Ok::<_, anyhow::Error>((stdout, stderr, exit_code))
        }).await;
        
        match result {
            Ok(Ok((stdout, stderr, exit_code))) => {
                debug!("Command completed within timeout with exit code: {}", exit_code);
                Ok((stdout, stderr, exit_code))
            },
            Ok(Err(e)) => {
                error!("Command execution error: {}", e);
                Err(e)
            },
            Err(_) => {
                // Timeout occurred, try to kill the process
                warn!("Command timed out after {:?}, attempting to kill process PID {}", timeout, pid);
                
                // Try to kill the process using the PID we saved earlier
                if pid > 0 {
                    #[cfg(unix)]
                    {
                        let _ = std::process::Command::new("kill")
                            .arg("-TERM")
                            .arg(pid.to_string())
                            .output();
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let _ = std::process::Command::new("kill")
                            .arg("-KILL")
                            .arg(pid.to_string())
                            .output();
                    }
                    
                    #[cfg(windows)]
                    {
                        // On Windows, we need to use taskkill with the PID
                        let _ = std::process::Command::new("taskkill")
                            .args(&["/PID", &pid.to_string(), "/F"])
                            .output();
                    }
                }
                
                Err(anyhow::anyhow!("Command timed out after {:?}", timeout))
            }
        }
    }
}

/// Audit log for unsafe commands (can be extended to write to file)
#[allow(dead_code)]
pub fn audit_unsafe_command(request: &UnsafeCommandRequest) {
    warn!("===== UNSAFE COMMAND AUDIT LOG =====");
    warn!("Timestamp: {}", chrono::Utc::now().to_rfc3339());
    warn!("Command ID: {}", request.id);
    warn!("Raw Command: {}", request.raw_command);
    warn!("Shell: {:?}", request.shell);
    warn!("Working Dir: {:?}", request.working_dir);
    warn!("Timeout: {:?} seconds", request.timeout);
    warn!("Environment Variables: {} variables set", request.env_vars.as_ref().map(|e| e.len()).unwrap_or(0));
    warn!("=====================================");
    
    // TODO: Write to audit log file if configured
    // This could be extended to write to a separate audit log file
    // with rotation and retention policies
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_unsafe_executor_creation() {
        let executor = UnsafeCommandExecutor::new();
        // Just verify it can be created
        assert!(executor.os_info.os_type != crate::os_detection::OsType::Unknown);
    }
    
    #[tokio::test]
    async fn test_unsafe_command_echo() {
        let executor = UnsafeCommandExecutor::new();
        
        let request = UnsafeCommandRequest {
            id: "test-echo".to_string(),
            raw_command: "echo 'Hello from unsafe command'".to_string(),
            shell: Some("sh".to_string()),
            timeout: Some(5),
            working_dir: None,
            env_vars: None,
        };
        
        let result = executor.execute(request).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(response.success);
        assert!(response.stdout.contains("Hello from unsafe command"));
        assert_eq!(response.command_type, "unsafe");
    }
    
    #[tokio::test]
    async fn test_unsafe_command_with_env_vars() {
        let executor = UnsafeCommandExecutor::new();
        
        let mut env_vars = std::collections::HashMap::new();
        env_vars.insert("TEST_VAR".to_string(), "test_value".to_string());
        
        #[cfg(unix)]
        let cmd = "echo $TEST_VAR";
        #[cfg(windows)]
        let cmd = "echo %TEST_VAR%";
        
        let request = UnsafeCommandRequest {
            id: "test-env".to_string(),
            raw_command: cmd.to_string(),
            shell: None,
            timeout: Some(5),
            working_dir: None,
            env_vars: Some(env_vars),
        };
        
        let result = executor.execute(request).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(response.stdout.contains("test_value"));
    }
    
    #[tokio::test]
    async fn test_unsafe_command_timeout() {
        let executor = UnsafeCommandExecutor::new();
        
        // Use a command that definitely takes longer than timeout
        // Use a simple infinite loop that will definitely not complete
        #[cfg(unix)]
        let cmd = "while true; do sleep 0.1; done";
        #[cfg(windows)]
        let cmd = "ping -t 127.0.0.1"; // continuous ping on Windows
        
        let request = UnsafeCommandRequest {
            id: "test-timeout".to_string(),
            raw_command: cmd.to_string(),
            shell: Some("bash".to_string()), // Explicit shell
            timeout: Some(1), // 1 second timeout
            working_dir: None,
            env_vars: None,
        };
        
        let start = std::time::Instant::now();
        let result = executor.execute(request).await;
        let elapsed = start.elapsed();
        
        println!("Test result: {:?}", result);
        println!("Elapsed time: {:?}", elapsed);
        
        assert!(result.is_ok(), "Command execution should return Ok even on timeout");
        
        let response = result.unwrap();
        println!("Response success: {}", response.success);
        println!("Response stdout: {}", response.stdout);
        println!("Response stderr: {}", response.stderr);
        println!("Response exit_code: {:?}", response.exit_code);
        
        // The command should fail due to timeout
        assert!(
            !response.success || response.stderr.contains("timed out"),
            "Command should either fail or have timeout message. Success: {}, stderr: {}",
            response.success,
            response.stderr
        );
        
        // Check that it actually timed out (should complete in ~1-2 seconds, not more)
        assert!(
            elapsed.as_secs() <= 2,
            "Command should timeout in ~1 second, but took {:?}",
            elapsed
        );
    }
}
