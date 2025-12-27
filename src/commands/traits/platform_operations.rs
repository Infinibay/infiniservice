//! Platform Operations trait abstraction
//!
//! This module defines the `PlatformOperations` trait which abstracts
//! platform-specific operations, primarily serving as a factory for
//! creating platform-appropriate package managers.
//!
//! # Design Principles
//!
//! - **Platform abstraction**: Hide OS-specific details behind a common interface
//! - **Factory pattern**: Centralized creation of package manager instances
//! - **Extensibility**: Easy to add new platforms (macOS, BSD, etc.)
//! - **Testability**: Implementations can be mocked for testing
//!
//! # Platform Comparison
//!
//! | Operation | Linux | Windows |
//! |-----------|-------|---------|
//! | `execute_command` | Uses sh/bash | Uses cmd/PowerShell |
//! | `command_exists` | `which` command | Registry + PATH search |
//! | `get_available_package_managers` | APT/DNF/Snap/Flatpak | WinGet/Store/Registry |
//! | `get_os_type` | `OsType::Linux` | `OsType::Windows` |
//!
//! # Conditional Compilation Notes
//!
//! When implementing `PlatformOperations`, use `#[cfg(target_os)]` attributes
//! to provide platform-specific implementations:
//!
//! ```rust,ignore
//! #[cfg(target_os = "linux")]
//! impl PlatformOperations for LinuxPlatform {
//!     // Linux-specific implementation
//! }
//!
//! #[cfg(target_os = "windows")]
//! impl PlatformOperations for WindowsPlatform {
//!     // Windows-specific implementation
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::os_detection::OsType;

use super::package_manager::PackageManager;

/// Enumeration of supported package manager types
///
/// This enum identifies all package managers that the system can potentially
/// support. Not all managers are available on all platforms.
///
/// # Platform Availability
///
/// | Type | Linux | Windows |
/// |------|-------|---------|
/// | `Apt` | Debian/Ubuntu | ❌ |
/// | `Rpm` | Fedora/RHEL/CentOS | ❌ |
/// | `Snap` | Most distros | ❌ |
/// | `Flatpak` | Most distros | ❌ |
/// | `WinGet` | ❌ | Windows 10+ |
/// | `WindowsStore` | ❌ | Windows 8+ |
/// | `WindowsRegistry` | ❌ | All Windows |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackageManagerType {
    // Linux package managers
    /// Debian/Ubuntu APT package manager
    Apt,
    /// RPM-based package manager (dnf/yum)
    Rpm,
    /// Snap universal package manager
    Snap,
    /// Flatpak universal package manager
    Flatpak,
    /// Pacman (Arch Linux) package manager
    Pacman,
    /// Zypper (openSUSE) package manager
    Zypper,
    /// APK (Alpine Linux) package manager
    Apk,

    // Windows package managers
    /// Windows Package Manager (winget)
    WinGet,
    /// Microsoft Store applications
    WindowsStore,
    /// Windows Registry-based applications
    WindowsRegistry,
    /// Chocolatey package manager
    Chocolatey,
    /// Scoop package manager
    Scoop,
}

impl PackageManagerType {
    /// Get a human-readable name for this package manager type
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Apt => "APT (Debian/Ubuntu)",
            Self::Rpm => "RPM (dnf/yum)",
            Self::Snap => "Snap",
            Self::Flatpak => "Flatpak",
            Self::Pacman => "Pacman",
            Self::Zypper => "Zypper",
            Self::Apk => "APK",
            Self::WinGet => "Windows Package Manager",
            Self::WindowsStore => "Microsoft Store",
            Self::WindowsRegistry => "Windows Registry",
            Self::Chocolatey => "Chocolatey",
            Self::Scoop => "Scoop",
        }
    }

    /// Check if this package manager type is available on Linux
    pub fn is_linux(&self) -> bool {
        matches!(
            self,
            Self::Apt
                | Self::Rpm
                | Self::Snap
                | Self::Flatpak
                | Self::Pacman
                | Self::Zypper
                | Self::Apk
        )
    }

    /// Check if this package manager type is available on Windows
    pub fn is_windows(&self) -> bool {
        matches!(
            self,
            Self::WinGet | Self::WindowsStore | Self::WindowsRegistry | Self::Chocolatey | Self::Scoop
        )
    }
}

/// Trait for platform-specific operations
///
/// This trait provides an abstraction layer for operations that differ
/// between operating systems, primarily focused on package manager
/// discovery and command execution.
///
/// # Implementation Example (Linux)
///
/// ```rust,ignore
/// struct LinuxPlatform;
///
/// #[async_trait]
/// impl PlatformOperations for LinuxPlatform {
///     fn execute_command(&self, cmd: &str, args: &[&str]) -> Result<String> {
///         use std::process::Command;
///         let output = Command::new(cmd).args(args).output()?;
///         Ok(String::from_utf8_lossy(&output.stdout).to_string())
///     }
///
///     fn command_exists(&self, cmd: &str) -> bool {
///         std::process::Command::new("which")
///             .arg(cmd)
///             .output()
///             .map(|o| o.status.success())
///             .unwrap_or(false)
///     }
///
///     fn get_available_package_managers(&self) -> Vec<PackageManagerType> {
///         let mut managers = Vec::new();
///         if self.command_exists("apt") { managers.push(PackageManagerType::Apt); }
///         if self.command_exists("dnf") { managers.push(PackageManagerType::Rpm); }
///         if self.command_exists("snap") { managers.push(PackageManagerType::Snap); }
///         if self.command_exists("flatpak") { managers.push(PackageManagerType::Flatpak); }
///         managers
///     }
///
///     fn get_os_type(&self) -> OsType {
///         OsType::Linux
///     }
///
///     async fn create_package_managers(&self) -> Vec<Box<dyn PackageManager>> {
///         let mut managers: Vec<Box<dyn PackageManager>> = Vec::new();
///         for pm_type in self.get_available_package_managers() {
///             match pm_type {
///                 PackageManagerType::Apt => managers.push(Box::new(AptUpdateChecker::new())),
///                 PackageManagerType::Snap => managers.push(Box::new(SnapUpdateChecker::new())),
///                 // ... other managers
///                 _ => {}
///             }
///         }
///         managers
///     }
/// }
/// ```
///
/// # Implementation Example (Windows)
///
/// ```rust,ignore
/// struct WindowsPlatform;
///
/// #[async_trait]
/// impl PlatformOperations for WindowsPlatform {
///     fn execute_command(&self, cmd: &str, args: &[&str]) -> Result<String> {
///         // Use PowerShell or cmd.exe
///         use std::process::Command;
///         let output = Command::new("powershell")
///             .args(["-Command", &format!("{} {}", cmd, args.join(" "))])
///             .output()?;
///         Ok(String::from_utf8_lossy(&output.stdout).to_string())
///     }
///
///     fn command_exists(&self, cmd: &str) -> bool {
///         // Check PATH and common locations
///         std::process::Command::new("where")
///             .arg(cmd)
///             .output()
///             .map(|o| o.status.success())
///             .unwrap_or(false)
///     }
///
///     fn get_available_package_managers(&self) -> Vec<PackageManagerType> {
///         vec![
///             PackageManagerType::WindowsRegistry, // Always available
///             PackageManagerType::WindowsStore,    // Windows 8+
///             // Check for optional managers
///         ]
///     }
///
///     fn get_os_type(&self) -> OsType {
///         OsType::Windows
///     }
///
///     async fn create_package_managers(&self) -> Vec<Box<dyn PackageManager>> {
///         // Create Windows-specific checkers
///         vec![
///             Box::new(RegistryUpdateChecker::new()),
///             Box::new(StoreUpdateChecker::new()),
///         ]
///     }
/// }
/// ```
#[async_trait]
pub trait PlatformOperations: Send + Sync {
    /// Execute a shell command and return its output
    ///
    /// # Parameters
    ///
    /// - `cmd`: The command to execute
    /// - `args`: Arguments to pass to the command
    ///
    /// # Returns
    ///
    /// - `Ok(String)` with stdout on success
    /// - `Err` if the command fails or returns non-zero exit code
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Executes command directly via fork/exec
    /// - **Windows**: May need to use cmd.exe or PowerShell wrapper
    fn execute_command(&self, cmd: &str, args: &[&str]) -> Result<String>;

    /// Check if a command exists and is executable
    ///
    /// # Parameters
    ///
    /// - `cmd`: The command name to check
    ///
    /// # Returns
    ///
    /// - `true` if the command exists in PATH
    /// - `false` otherwise
    ///
    /// # Platform Notes
    ///
    /// - **Linux**: Uses `which` command or PATH search
    /// - **Windows**: Uses `where` command or PATH + common locations
    fn command_exists(&self, cmd: &str) -> bool;

    /// Get list of available package managers on this system
    ///
    /// Detects which package managers are installed and available
    /// on the current system.
    ///
    /// # Returns
    ///
    /// A vector of `PackageManagerType` values for available managers
    ///
    /// # Example Return Values
    ///
    /// - Ubuntu: `[Apt, Snap, Flatpak]`
    /// - Fedora: `[Rpm, Flatpak]`
    /// - Windows 10: `[WindowsRegistry, WindowsStore, WinGet]`
    fn get_available_package_managers(&self) -> Vec<PackageManagerType>;

    /// Get the operating system type
    ///
    /// # Returns
    ///
    /// The `OsType` for the current platform
    fn get_os_type(&self) -> OsType;

    /// Create package manager instances for all available managers
    ///
    /// This is the factory method that creates concrete implementations
    /// of `PackageManager` for each available package manager on the system.
    ///
    /// # Returns
    ///
    /// A vector of boxed `PackageManager` trait objects, one for each
    /// available package manager.
    ///
    /// # Usage
    ///
    /// ```rust,ignore
    /// let platform = get_platform_operations();
    /// let managers = platform.create_package_managers().await;
    ///
    /// for mut manager in managers {
    ///     manager.initialize().await?;
    ///     // Use manager for update checks
    /// }
    /// ```
    async fn create_package_managers(&self) -> Vec<Box<dyn PackageManager>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::update_checker::{UpdateCheckResult, UpdateInfo};

    /// Mock PackageManager for testing
    struct MockPM {
        name: &'static str,
    }

    #[async_trait]
    impl PackageManager for MockPM {
        async fn initialize(&mut self) -> UpdateCheckResult<()> {
            Ok(())
        }

        async fn check_update(
            &self,
            _app: &crate::commands::application_inventory::Application,
        ) -> UpdateCheckResult<Option<UpdateInfo>> {
            Ok(None)
        }

        fn generate_package_names(&self, app_name: &str) -> Vec<String> {
            vec![app_name.to_lowercase()]
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    /// Mock PlatformOperations for testing
    struct MockPlatform {
        os_type: OsType,
        available_managers: Vec<PackageManagerType>,
        commands: Vec<String>,
    }

    impl MockPlatform {
        fn linux() -> Self {
            Self {
                os_type: OsType::Linux,
                available_managers: vec![
                    PackageManagerType::Apt,
                    PackageManagerType::Snap,
                    PackageManagerType::Flatpak,
                ],
                commands: vec![
                    "apt".to_string(),
                    "snap".to_string(),
                    "flatpak".to_string(),
                ],
            }
        }

        fn windows() -> Self {
            Self {
                os_type: OsType::Windows,
                available_managers: vec![
                    PackageManagerType::WindowsRegistry,
                    PackageManagerType::WindowsStore,
                    PackageManagerType::WinGet,
                ],
                commands: vec!["winget".to_string()],
            }
        }
    }

    #[async_trait]
    impl PlatformOperations for MockPlatform {
        fn execute_command(&self, cmd: &str, args: &[&str]) -> Result<String> {
            Ok(format!("Executed: {} {:?}", cmd, args))
        }

        fn command_exists(&self, cmd: &str) -> bool {
            self.commands.contains(&cmd.to_string())
        }

        fn get_available_package_managers(&self) -> Vec<PackageManagerType> {
            self.available_managers.clone()
        }

        fn get_os_type(&self) -> OsType {
            self.os_type.clone()
        }

        async fn create_package_managers(&self) -> Vec<Box<dyn PackageManager>> {
            self.available_managers
                .iter()
                .map(|pm_type| {
                    let name = match pm_type {
                        PackageManagerType::Apt => "apt",
                        PackageManagerType::Snap => "snap",
                        PackageManagerType::Flatpak => "flatpak",
                        PackageManagerType::WinGet => "winget",
                        PackageManagerType::WindowsStore => "store",
                        PackageManagerType::WindowsRegistry => "registry",
                        _ => "unknown",
                    };
                    Box::new(MockPM { name }) as Box<dyn PackageManager>
                })
                .collect()
        }
    }

    #[test]
    fn test_package_manager_type_display_name() {
        assert_eq!(PackageManagerType::Apt.display_name(), "APT (Debian/Ubuntu)");
        assert_eq!(PackageManagerType::Snap.display_name(), "Snap");
        assert_eq!(
            PackageManagerType::WinGet.display_name(),
            "Windows Package Manager"
        );
    }

    #[test]
    fn test_package_manager_type_platform() {
        // Linux managers
        assert!(PackageManagerType::Apt.is_linux());
        assert!(PackageManagerType::Rpm.is_linux());
        assert!(PackageManagerType::Snap.is_linux());
        assert!(!PackageManagerType::Apt.is_windows());

        // Windows managers
        assert!(PackageManagerType::WinGet.is_windows());
        assert!(PackageManagerType::WindowsStore.is_windows());
        assert!(!PackageManagerType::WinGet.is_linux());
    }

    #[test]
    fn test_mock_platform_linux() {
        let platform = MockPlatform::linux();

        assert_eq!(platform.get_os_type(), OsType::Linux);
        assert!(platform.command_exists("apt"));
        assert!(platform.command_exists("snap"));
        assert!(!platform.command_exists("winget"));

        let managers = platform.get_available_package_managers();
        assert!(managers.contains(&PackageManagerType::Apt));
        assert!(managers.contains(&PackageManagerType::Snap));
        assert!(!managers.contains(&PackageManagerType::WinGet));
    }

    #[test]
    fn test_mock_platform_windows() {
        let platform = MockPlatform::windows();

        assert_eq!(platform.get_os_type(), OsType::Windows);
        assert!(platform.command_exists("winget"));
        assert!(!platform.command_exists("apt"));

        let managers = platform.get_available_package_managers();
        assert!(managers.contains(&PackageManagerType::WinGet));
        assert!(managers.contains(&PackageManagerType::WindowsStore));
        assert!(!managers.contains(&PackageManagerType::Apt));
    }

    #[test]
    fn test_execute_command() {
        let platform = MockPlatform::linux();
        let result = platform.execute_command("apt", &["update"]);

        assert!(result.is_ok());
        assert!(result.unwrap().contains("apt"));
    }

    #[tokio::test]
    async fn test_create_package_managers() {
        let platform = MockPlatform::linux();
        let managers = platform.create_package_managers().await;

        assert_eq!(managers.len(), 3);

        let names: Vec<&str> = managers.iter().map(|m| m.name()).collect();
        assert!(names.contains(&"apt"));
        assert!(names.contains(&"snap"));
        assert!(names.contains(&"flatpak"));
    }

    #[tokio::test]
    async fn test_trait_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn PlatformOperations>>();
    }

    #[test]
    fn test_package_manager_type_serialization() {
        let pm_type = PackageManagerType::Apt;
        let json = serde_json::to_string(&pm_type).unwrap();
        assert_eq!(json, "\"Apt\"");

        let deserialized: PackageManagerType = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, PackageManagerType::Apt);
    }

    #[test]
    fn test_all_package_manager_types_have_display_name() {
        let all_types = [
            PackageManagerType::Apt,
            PackageManagerType::Rpm,
            PackageManagerType::Snap,
            PackageManagerType::Flatpak,
            PackageManagerType::Pacman,
            PackageManagerType::Zypper,
            PackageManagerType::Apk,
            PackageManagerType::WinGet,
            PackageManagerType::WindowsStore,
            PackageManagerType::WindowsRegistry,
            PackageManagerType::Chocolatey,
            PackageManagerType::Scoop,
        ];

        for pm_type in all_types {
            let display_name = pm_type.display_name();
            assert!(!display_name.is_empty(), "{:?} should have a display name", pm_type);
        }
    }

    #[test]
    fn test_all_package_manager_types_have_platform() {
        let all_types = [
            PackageManagerType::Apt,
            PackageManagerType::Rpm,
            PackageManagerType::Snap,
            PackageManagerType::Flatpak,
            PackageManagerType::Pacman,
            PackageManagerType::Zypper,
            PackageManagerType::Apk,
            PackageManagerType::WinGet,
            PackageManagerType::WindowsStore,
            PackageManagerType::WindowsRegistry,
            PackageManagerType::Chocolatey,
            PackageManagerType::Scoop,
        ];

        for pm_type in all_types {
            // Each type should be either Linux or Windows (not both, not neither)
            let is_linux = pm_type.is_linux();
            let is_windows = pm_type.is_windows();
            assert!(
                is_linux ^ is_windows,
                "{:?} should be exactly one of Linux or Windows",
                pm_type
            );
        }
    }
}
