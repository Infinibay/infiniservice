//! Platform Factory for creating platform-specific implementations
//!
//! This module provides a factory pattern for instantiating platform-specific
//! implementations of `SystemOperations` and `PlatformOperations` traits.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       PlatformFactory                           │
//! │   Centralized factory for creating platform implementations     │
//! └───────────────────────────┬─────────────────────────────────────┘
//!                             │ creates
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │   LinuxSystemOperations  |  WindowsSystemOperations             │
//! │   Platform-specific implementations                             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::commands::platform_factory::PlatformFactory;
//!
//! // Get the appropriate system operations for the current platform
//! let system_ops = PlatformFactory::create_system_operations();
//!
//! // Use the operations
//! let services = system_ops.list_services().await?;
//! let packages = system_ops.list_packages().await?;
//! ```
//!
//! # Platform Detection
//!
//! The factory uses Rust's conditional compilation (`#[cfg(target_os)]`)
//! to include only the relevant implementation at compile time, ensuring
//! minimal binary size and no runtime overhead for platform detection.

use crate::commands::traits::SystemOperations;

#[cfg(target_os = "linux")]
use crate::commands::linux::LinuxSystemOperations;

#[cfg(target_os = "windows")]
use crate::commands::windows::WindowsSystemOperations;

/// Factory for creating platform-specific implementations
///
/// This struct provides static methods for creating implementations
/// of various platform abstraction traits. It uses conditional compilation
/// to ensure type safety and optimal binary size.
pub struct PlatformFactory;

impl PlatformFactory {
    /// Create platform-specific system operations implementation
    ///
    /// Returns a boxed trait object implementing `SystemOperations` for
    /// the current platform.
    ///
    /// # Platform Support
    ///
    /// - **Linux**: Returns `LinuxSystemOperations`
    /// - **Windows**: Returns `WindowsSystemOperations`
    /// - **Other**: Compilation error (unsupported platform)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let system_ops = PlatformFactory::create_system_operations();
    ///
    /// // List services (works on any supported platform)
    /// let result = system_ops.list_services().await?;
    ///
    /// // Install a package
    /// system_ops.install_package("vim").await?;
    /// ```
    ///
    /// # Panics
    ///
    /// This function will cause a compilation error on unsupported platforms.
    #[cfg(target_os = "linux")]
    pub fn create_system_operations() -> Box<dyn SystemOperations> {
        Box::new(LinuxSystemOperations::new())
    }

    #[cfg(target_os = "windows")]
    pub fn create_system_operations() -> Box<dyn SystemOperations> {
        Box::new(WindowsSystemOperations::new())
    }

    /// Check if the current platform is supported
    ///
    /// Returns `true` if the current platform has a `SystemOperations`
    /// implementation available.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// if PlatformFactory::is_platform_supported() {
    ///     let ops = PlatformFactory::create_system_operations();
    ///     // ... use operations
    /// } else {
    ///     eprintln!("Platform not supported");
    /// }
    /// ```
    pub fn is_platform_supported() -> bool {
        cfg!(any(target_os = "linux", target_os = "windows"))
    }

    /// Get the name of the current platform
    ///
    /// Returns a human-readable string identifying the current platform.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// println!("Running on: {}", PlatformFactory::platform_name());
    /// // Output: "Linux" or "Windows"
    /// ```
    pub fn platform_name() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            "Linux"
        }
        #[cfg(target_os = "windows")]
        {
            "Windows"
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            "Unsupported"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_platform_supported() {
        // On Linux or Windows, this should return true
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        assert!(PlatformFactory::is_platform_supported());
    }

    #[test]
    fn test_platform_name() {
        #[cfg(target_os = "linux")]
        assert_eq!(PlatformFactory::platform_name(), "Linux");

        #[cfg(target_os = "windows")]
        assert_eq!(PlatformFactory::platform_name(), "Windows");
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_create_system_operations() {
        // Should not panic
        let _ops = PlatformFactory::create_system_operations();
    }

    #[test]
    fn test_trait_object_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn SystemOperations>>();
    }
}
