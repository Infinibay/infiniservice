//! Command Executor trait abstraction
//!
//! This module defines the `CommandExecutor` trait which abstracts shell command
//! execution. This abstraction enables:
//!
//! - **Testability**: Mock command execution in unit tests
//! - **Flexibility**: Different implementations for different contexts
//! - **Consistency**: Unified interface across package managers
//!
//! # Default Implementation
//!
//! The trait provides default implementations for optional methods:
//!
//! - `execute_allow_failure()` -> Calls `execute()` and returns `None` on error
//! - `check_availability()` -> Returns `false` (platform-agnostic, safe default)
//!
//! Platform-specific implementations like `ShellExecutor` on Linux delegate to
//! the existing functions in `crate::commands::common::shell`:
//!
//! - `execute()` -> `shell::execute_command()`
//! - `execute_allow_failure()` -> `shell::execute_command_allow_failure()`
//! - `check_availability()` -> `shell::command_exists()` (uses `which`)
//!
//! # Usage in Package Managers
//!
//! Package managers can accept a `CommandExecutor` implementation to execute
//! shell commands, making them testable with mock implementations:
//!
//! ```rust,ignore
//! struct AptUpdateChecker<E: CommandExecutor> {
//!     executor: E,
//!     cache: HashMap<String, PackageInfo>,
//! }
//!
//! impl<E: CommandExecutor> AptUpdateChecker<E> {
//!     fn build_cache(&mut self) -> Result<()> {
//!         let output = self.executor.execute("apt", &["list", "--upgradable"])?;
//!         // Parse output...
//!     }
//! }
//!
//! // In production:
//! let checker = AptUpdateChecker::new(ShellExecutor::new());
//!
//! // In tests:
//! let checker = AptUpdateChecker::new(MockExecutor::with_responses(...));
//! ```

use anyhow::Result;

/// Trait for executing shell commands
///
/// This trait abstracts command execution to enable testing package managers
/// without actually running system commands. The default implementation
/// delegates to the shell utilities in `crate::commands::common::shell`.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to support use in async contexts.
///
/// # Example Implementation (Production)
///
/// ```rust,ignore
/// struct ShellExecutor;
///
/// impl CommandExecutor for ShellExecutor {
///     fn execute(&self, cmd: &str, args: &[&str]) -> Result<String> {
///         use std::process::Command;
///         let output = Command::new(cmd).args(args).output()?;
///         if output.status.success() {
///             Ok(String::from_utf8_lossy(&output.stdout).to_string())
///         } else {
///             Err(anyhow::anyhow!("Command failed: {}",
///                 String::from_utf8_lossy(&output.stderr)))
///         }
///     }
/// }
/// ```
///
/// # Example Implementation (Testing)
///
/// ```rust,ignore
/// struct MockExecutor {
///     responses: HashMap<String, String>,
///     available_commands: HashSet<String>,
/// }
///
/// impl CommandExecutor for MockExecutor {
///     fn execute(&self, cmd: &str, args: &[&str]) -> Result<String> {
///         let key = format!("{} {}", cmd, args.join(" "));
///         self.responses.get(&key)
///             .cloned()
///             .ok_or_else(|| anyhow::anyhow!("No mock response for: {}", key))
///     }
///
///     fn check_availability(&self, cmd: &str) -> bool {
///         self.available_commands.contains(cmd)
///     }
/// }
/// ```
pub trait CommandExecutor: Send + Sync {
    /// Execute a command and return its output
    ///
    /// Runs the specified command with the given arguments and returns
    /// the standard output if successful.
    ///
    /// # Parameters
    ///
    /// - `cmd`: The command to execute
    /// - `args`: Arguments to pass to the command
    ///
    /// # Returns
    ///
    /// - `Ok(String)` with stdout content on success
    /// - `Err` if the command fails or returns non-zero exit code
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let output = executor.execute("apt", &["list", "--upgradable"])?;
    /// for line in output.lines() {
    ///     println!("Upgradable: {}", line);
    /// }
    /// ```
    fn execute(&self, cmd: &str, args: &[&str]) -> Result<String>;

    /// Execute a command and return output even on failure
    ///
    /// Similar to `execute()`, but returns the output even if the command
    /// exits with a non-zero status code. Useful for commands where a
    /// non-zero exit code carries meaning (e.g., `dnf check-update` returns
    /// 100 when updates are available).
    ///
    /// # Parameters
    ///
    /// - `cmd`: The command to execute
    /// - `args`: Arguments to pass to the command
    ///
    /// # Returns
    ///
    /// - `Some(String)` with stdout (or stderr if stdout is empty)
    /// - `None` only if the command cannot be executed at all
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // dnf check-update returns exit code 100 when updates are available
    /// if let Some(output) = executor.execute_allow_failure("dnf", &["check-update"]) {
    ///     // Parse available updates from output
    /// }
    /// ```
    fn execute_allow_failure(&self, cmd: &str, args: &[&str]) -> Option<String> {
        // Default implementation: try execute(), return None on error
        self.execute(cmd, args).ok()
    }

    /// Check if a command is available in the system
    ///
    /// Verifies that the specified command exists and is executable.
    ///
    /// # Parameters
    ///
    /// - `cmd`: The command name to check
    ///
    /// # Returns
    ///
    /// - `true` if the command is available
    /// - `false` if the command is not found or not executable
    ///
    /// # Default Implementation
    ///
    /// Returns `false` by default. Platform-specific implementations (like
    /// `ShellExecutor` on Linux) should override this method to provide
    /// OS-appropriate command availability checking.
    ///
    /// - **Linux**: Use `which` command or PATH search
    /// - **Windows**: Use `where` command or PATH + common locations
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if executor.check_availability("apt") {
    ///     // Use APT for package management
    /// } else if executor.check_availability("dnf") {
    ///     // Use DNF for package management
    /// }
    /// ```
    fn check_availability(&self, _cmd: &str) -> bool {
        // Default implementation returns false for cross-platform safety.
        // Platform-specific implementations (ShellExecutor on Linux, etc.)
        // should override this with OS-appropriate logic.
        false
    }
}

/// Default shell command executor implementation
///
/// This implementation uses the standard library's `std::process::Command`
/// to execute shell commands. It's the production implementation used
/// when not in a testing context.
///
/// # Platform Support
///
/// This implementation is only available on Linux. For Windows, a separate
/// implementation would be needed that uses PowerShell or cmd.exe.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct ShellExecutor;

#[cfg(target_os = "linux")]
impl ShellExecutor {
    /// Create a new ShellExecutor instance
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
impl CommandExecutor for ShellExecutor {
    fn execute(&self, cmd: &str, args: &[&str]) -> Result<String> {
        // Delegate to the existing shell utilities
        super::super::common::shell::execute_command(cmd, args)
    }

    fn execute_allow_failure(&self, cmd: &str, args: &[&str]) -> Option<String> {
        super::super::common::shell::execute_command_allow_failure(cmd, args)
    }

    fn check_availability(&self, cmd: &str) -> bool {
        super::super::common::shell::command_exists(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Mock command executor for testing
    struct MockExecutor {
        responses: HashMap<String, Result<String, String>>,
        available_commands: Vec<String>,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                responses: HashMap::new(),
                available_commands: Vec::new(),
            }
        }

        fn with_response(mut self, cmd: &str, args: &[&str], response: &str) -> Self {
            let key = format!("{} {}", cmd, args.join(" "));
            self.responses.insert(key, Ok(response.to_string()));
            self
        }

        fn with_failure(mut self, cmd: &str, args: &[&str], error: &str) -> Self {
            let key = format!("{} {}", cmd, args.join(" "));
            self.responses.insert(key, Err(error.to_string()));
            self
        }

        fn with_available_command(mut self, cmd: &str) -> Self {
            self.available_commands.push(cmd.to_string());
            self
        }
    }

    impl CommandExecutor for MockExecutor {
        fn execute(&self, cmd: &str, args: &[&str]) -> Result<String> {
            let key = format!("{} {}", cmd, args.join(" "));
            match self.responses.get(&key) {
                Some(Ok(output)) => Ok(output.clone()),
                Some(Err(error)) => Err(anyhow::anyhow!("{}", error)),
                None => Err(anyhow::anyhow!("No mock response for: {}", key)),
            }
        }

        fn execute_allow_failure(&self, cmd: &str, args: &[&str]) -> Option<String> {
            let key = format!("{} {}", cmd, args.join(" "));
            self.responses.get(&key).and_then(|r| r.as_ref().ok().cloned())
        }

        fn check_availability(&self, cmd: &str) -> bool {
            self.available_commands.contains(&cmd.to_string())
        }
    }

    #[test]
    fn test_mock_executor_success() {
        let executor = MockExecutor::new()
            .with_response("apt", &["list", "--upgradable"], "vim/focal 8.2 amd64 [upgradable from: 8.1]");

        let result = executor.execute("apt", &["list", "--upgradable"]);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("vim"));
    }

    #[test]
    fn test_mock_executor_failure() {
        let executor = MockExecutor::new()
            .with_failure("apt", &["update"], "Permission denied");

        let result = executor.execute("apt", &["update"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Permission denied"));
    }

    #[test]
    fn test_mock_executor_no_response() {
        let executor = MockExecutor::new();

        let result = executor.execute("unknown", &["command"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No mock response"));
    }

    #[test]
    fn test_mock_executor_allow_failure_success() {
        let executor = MockExecutor::new()
            .with_response("dnf", &["check-update"], "Package updates available");

        let result = executor.execute_allow_failure("dnf", &["check-update"]);
        assert!(result.is_some());
        assert!(result.unwrap().contains("updates available"));
    }

    #[test]
    fn test_mock_executor_allow_failure_on_error() {
        let executor = MockExecutor::new()
            .with_failure("dnf", &["check-update"], "Error");

        let result = executor.execute_allow_failure("dnf", &["check-update"]);
        assert!(result.is_none());
    }

    #[test]
    fn test_mock_executor_check_availability() {
        let executor = MockExecutor::new()
            .with_available_command("apt")
            .with_available_command("snap");

        assert!(executor.check_availability("apt"));
        assert!(executor.check_availability("snap"));
        assert!(!executor.check_availability("dnf"));
    }

    #[test]
    fn test_trait_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockExecutor>();
    }

    /// Minimal executor that only implements required method, using defaults for the rest
    struct MinimalExecutor;

    impl CommandExecutor for MinimalExecutor {
        fn execute(&self, _cmd: &str, _args: &[&str]) -> Result<String> {
            Ok("output".to_string())
        }
        // Uses default implementations for execute_allow_failure and check_availability
    }

    #[test]
    fn test_default_check_availability_returns_false() {
        // The default implementation should return false for cross-platform safety
        let executor = MinimalExecutor;
        assert!(!executor.check_availability("any_command"));
        assert!(!executor.check_availability("apt"));
        assert!(!executor.check_availability("dnf"));
    }

    #[test]
    fn test_default_execute_allow_failure() {
        // The default implementation should delegate to execute()
        let executor = MinimalExecutor;
        let result = executor.execute_allow_failure("test", &[]);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "output");
    }

    #[test]
    fn test_trait_object() {
        let executor: Box<dyn CommandExecutor> = Box::new(
            MockExecutor::new()
                .with_response("echo", &["hello"], "hello")
                .with_available_command("echo"),
        );

        assert!(executor.check_availability("echo"));
        assert_eq!(executor.execute("echo", &["hello"]).unwrap(), "hello");
    }

    #[test]
    fn test_multiple_responses() {
        let executor = MockExecutor::new()
            .with_response("apt", &["list", "--upgradable"], "vim 8.2")
            .with_response("apt", &["show", "vim"], "Package: vim\nVersion: 8.2")
            .with_response("snap", &["list"], "firefox 120.0");

        assert!(executor.execute("apt", &["list", "--upgradable"]).unwrap().contains("vim"));
        assert!(executor.execute("apt", &["show", "vim"]).unwrap().contains("Version: 8.2"));
        assert!(executor.execute("snap", &["list"]).unwrap().contains("firefox"));
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn test_shell_executor_creation() {
            let executor = ShellExecutor::new();
            // Just verify it can be created
            let _: &dyn CommandExecutor = &executor;
        }

        #[test]
        fn test_shell_executor_check_availability() {
            let executor = ShellExecutor::new();
            // 'ls' should always be available on Linux
            assert!(executor.check_availability("ls"));
            // Random command should not exist
            assert!(!executor.check_availability("nonexistent_command_12345"));
        }

        #[test]
        fn test_shell_executor_execute_success() {
            let executor = ShellExecutor::new();
            let result = executor.execute("echo", &["hello"]);
            assert!(result.is_ok());
            assert!(result.unwrap().trim() == "hello");
        }

        #[test]
        fn test_shell_executor_execute_failure() {
            let executor = ShellExecutor::new();
            let result = executor.execute("false", &[]);
            // 'false' command always exits with non-zero
            assert!(result.is_err());
        }

        #[test]
        fn test_shell_executor_allow_failure() {
            let executor = ShellExecutor::new();
            // 'false' would fail normally but should still return something
            let result = executor.execute_allow_failure("echo", &["test"]);
            assert!(result.is_some());
        }

        #[test]
        fn test_shell_executor_as_trait_object() {
            let executor: Box<dyn CommandExecutor> = Box::new(ShellExecutor::new());
            assert!(executor.check_availability("ls"));
        }
    }
}
