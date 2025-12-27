//! Shell command execution utilities for Linux systems
//!
//! This module provides common functions for executing shell commands
//! with proper error handling and logging. All functions are Linux-only
//! and marked with `#[cfg(target_os = "linux")]`.
//!
//! # Functions
//!
//! - `execute_command()`: Execute a command and return stdout on success.
//!   Has special handling for dnf/yum commands that return exit code 100.
//!
//! - `execute_command_allow_failure()`: Execute a command and return output
//!   even if the exit code is non-zero. Useful for status commands.
//!
//! - `command_exists()`: Check if a command is available in PATH using `which`.
//!
//! # Example
//!
//! ```rust,no_run
//! use crate::commands::common::shell::execute_command;
//!
//! let output = execute_command("apt", &["list", "--upgradable"])?;
//! println!("Available updates: {}", output);
//! ```

use anyhow::{Result, anyhow};
use log::debug;

#[cfg(target_os = "linux")]
use std::process::Command;

/// Execute a command and return stdout if successful
///
/// # Special Behavior
/// - For `dnf` and `yum` commands, exit code 100 is treated as success
///   (these package managers return 100 when updates are available)
#[cfg(target_os = "linux")]
pub fn execute_command(cmd: &str, args: &[&str]) -> Result<String> {
    debug!("Executing command: {} {:?}", cmd, args);

    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow!("Failed to execute command {} {:?}: {}", cmd, args, e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        // Some commands like dnf check-update return exit code 100 when updates are available
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // dnf/yum check-update returns 100 if updates are available, 0 if not
        if cmd == "dnf" || cmd == "yum" {
            if let Some(code) = output.status.code() {
                if code == 100 {
                    return Ok(stdout.to_string());
                }
            }
        }

        debug!("Command failed with stderr: {}", stderr);
        Err(anyhow!("Command {} failed: {}", cmd, stderr))
    }
}

/// Execute a command and return stdout even if exit code is non-zero (for status commands)
///
/// Returns `Some(output)` with stdout (or stderr if stdout is empty) even on failure.
/// Returns `None` only if the command cannot be executed at all.
#[cfg(target_os = "linux")]
pub fn execute_command_allow_failure(cmd: &str, args: &[&str]) -> Option<String> {
    debug!("Executing command (allow failure): {} {:?}", cmd, args);

    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if !stdout.is_empty() {
                Some(stdout)
            } else {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            }
        }
        Err(e) => {
            debug!("Command {} not available: {}", cmd, e);
            None
        }
    }
}

/// Check if a command exists in PATH
///
/// Uses the `which` command to verify availability.
#[cfg(target_os = "linux")]
pub fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
