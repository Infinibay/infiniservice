//! Package Manager trait abstraction
//!
//! This module defines the `PackageManager` trait which abstracts the common
//! operations performed by individual package managers (APT, RPM, Snap, Flatpak,
//! WinGet, etc.).
//!
//! # Design Principles
//!
//! - **Async-first**: All I/O operations are async for better concurrency
//! - **Trait object safe**: Can be used as `Box<dyn PackageManager>`
//! - **Testable**: Default implementations and clear interfaces enable mocking
//! - **Extensible**: New package managers can be added without modifying existing code
//!
//! # Required Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `initialize()` | Build internal cache and prepare for queries |
//! | `check_update()` | Check if an application has available updates |
//! | `generate_package_names()` | Generate possible package names for lookup |
//! | `name()` | Return the package manager's identifier |
//!
//! # Optional Methods (with defaults)
//!
//! | Method | Default | Description |
//! |--------|---------|-------------|
//! | `build_cache()` | calls `initialize()` | Alias for initialize, matches existing checker API |
//! | `can_handle()` | `true` | Check if this manager can handle an application |
//! | `get_package_size()` | `None` | Get download size for a package |
//! | `is_security_update()` | `false` | Check if update is security-related |
//!
//! # Migration Guide
//!
//! To migrate an existing checker (e.g., `AptUpdateChecker`) to implement this trait:
//!
//! 1. Keep the existing struct and its fields
//! 2. Add `#[async_trait]` attribute and implement `PackageManager`
//! 3. Move `build_cache()` logic to `initialize()`
//! 4. Move `check_update()` logic to the trait's `check_update()`
//! 5. Keep `generate_package_names()` as-is (already matches the trait)
//! 6. Add `name()` returning the package manager identifier
//!
//! ## Before (existing code pattern):
//!
//! ```rust,ignore
//! struct AptUpdateChecker {
//!     cache: HashMap<String, AptPackageInfo>,
//! }
//!
//! impl AptUpdateChecker {
//!     fn build_cache(&mut self) -> Result<()> { ... }
//!     fn check_update(&self, app: &Application) -> Option<UpdateInfo> { ... }
//!     fn generate_package_names(&self, name: &str) -> Vec<String> { ... }
//! }
//! ```
//!
//! ## After (implementing trait):
//!
//! ```rust,ignore
//! #[async_trait]
//! impl PackageManager for AptUpdateChecker {
//!     async fn initialize(&mut self) -> UpdateCheckResult<()> {
//!         self.build_cache().map_err(|e| UpdateCheckError::PlatformError(e.to_string()))
//!     }
//!
//!     async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
//!         Ok(self.internal_check_update(app))
//!     }
//!
//!     fn generate_package_names(&self, app_name: &str) -> Vec<String> {
//!         // Existing implementation
//!     }
//!
//!     fn name(&self) -> &'static str {
//!         "apt"
//!     }
//! }
//! ```

use async_trait::async_trait;

use crate::commands::application_inventory::Application;
use crate::commands::update_checker::{UpdateCheckResult, UpdateInfo};

/// Trait for individual package manager implementations
///
/// This trait abstracts the common operations performed by package managers,
/// allowing for a unified interface regardless of the underlying package
/// management system (APT, RPM, Snap, Flatpak, WinGet, etc.).
///
/// # Implementation Notes
///
/// - Implementations should be `Send + Sync` for use in async contexts
/// - The `initialize()` method should be called before any queries
/// - Implementations may cache package information for performance
///
/// # Example Implementation
///
/// ```rust,ignore
/// use async_trait::async_trait;
/// use std::collections::HashMap;
///
/// struct SnapUpdateChecker {
///     installed_snaps: HashMap<String, SnapInfo>,
/// }
///
/// #[async_trait]
/// impl PackageManager for SnapUpdateChecker {
///     async fn initialize(&mut self) -> UpdateCheckResult<()> {
///         // Run 'snap list' and parse output
///         self.installed_snaps = self.query_installed_snaps().await?;
///         Ok(())
///     }
///
///     async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
///         for name in self.generate_package_names(&app.name) {
///             if let Some(snap_info) = self.installed_snaps.get(&name) {
///                 if snap_info.has_update {
///                     return Ok(Some(UpdateInfo { ... }));
///                 }
///             }
///         }
///         Ok(None)
///     }
///
///     fn generate_package_names(&self, app_name: &str) -> Vec<String> {
///         vec![
///             app_name.to_lowercase(),
///             app_name.to_lowercase().replace(' ', "-"),
///         ]
///     }
///
///     fn name(&self) -> &'static str {
///         "snap"
///     }
/// }
/// ```
#[async_trait]
pub trait PackageManager: Send + Sync {
    /// Initialize the package manager and build internal cache
    ///
    /// This method should be called before any other operations. It typically
    /// involves querying the system for installed packages and available updates,
    /// then caching this information for subsequent queries.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if initialization succeeded
    /// - `Err(UpdateCheckError)` if initialization failed (e.g., package manager
    ///   not available, permission denied, network error)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// async fn initialize(&mut self) -> UpdateCheckResult<()> {
    ///     // For APT: run 'apt update' and parse package lists
    ///     self.refresh_package_lists().await?;
    ///     self.cache = self.build_package_cache().await?;
    ///     Ok(())
    /// }
    /// ```
    async fn initialize(&mut self) -> UpdateCheckResult<()>;

    /// Build the internal package cache
    ///
    /// This is an alias for `initialize()` that matches the existing checker API
    /// pattern used in `linux_update_checker.rs`. Implementations can override
    /// this method if they need different behavior, but the default simply
    /// delegates to `initialize()`.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if cache building succeeded
    /// - `Err(UpdateCheckError)` if cache building failed
    ///
    /// # Default Implementation
    ///
    /// Calls `self.initialize()` to maintain backward compatibility with
    /// existing checker implementations that use `build_cache()`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Both of these are equivalent:
    /// manager.initialize().await?;
    /// manager.build_cache().await?;
    /// ```
    async fn build_cache(&mut self) -> UpdateCheckResult<()> {
        self.initialize().await
    }

    /// Check if an application has an available update
    ///
    /// This method queries the package manager (typically using cached data)
    /// to determine if the given application has an update available.
    ///
    /// # Parameters
    ///
    /// - `app`: The application to check for updates
    ///
    /// # Returns
    ///
    /// - `Ok(Some(UpdateInfo))` if an update is available
    /// - `Ok(None)` if no update is available or the package is not found
    /// - `Err(UpdateCheckError)` if an error occurred during the check
    ///
    /// # Implementation Notes
    ///
    /// Implementations should:
    /// 1. Generate possible package names using `generate_package_names()`
    /// 2. Look up each name in the cache/repository
    /// 3. Compare versions to determine if an update is available
    /// 4. Return detailed `UpdateInfo` if an update is found
    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>>;

    /// Generate possible package names for the given application name
    ///
    /// Different package managers have different naming conventions. This method
    /// generates a list of possible package names that might match the application.
    ///
    /// # Parameters
    ///
    /// - `app_name`: The human-readable application name
    ///
    /// # Returns
    ///
    /// A vector of possible package names to search for
    ///
    /// # Example
    ///
    /// For an application named "Visual Studio Code":
    /// - APT might return: `["code", "vscode", "visual-studio-code"]`
    /// - Snap might return: `["code", "vscode"]`
    /// - Flatpak might return: `["com.visualstudio.code"]`
    fn generate_package_names(&self, app_name: &str) -> Vec<String>;

    /// Get the name/identifier of this package manager
    ///
    /// This is used for logging, debugging, and identifying which package
    /// manager handled a particular update check.
    ///
    /// # Returns
    ///
    /// A static string identifying the package manager (e.g., "apt", "dnf", "snap")
    fn name(&self) -> &'static str;

    /// Check if this package manager can handle the given application
    ///
    /// This method allows package managers to filter applications based on
    /// install type or other criteria. For example, an APT checker might
    /// only handle applications with `install_type == "DEB"`.
    ///
    /// # Parameters
    ///
    /// - `app`: The application to check
    ///
    /// # Returns
    ///
    /// - `true` if this package manager should attempt to check updates
    /// - `false` if this package manager should skip this application
    ///
    /// # Default Implementation
    ///
    /// Returns `true` for all applications. Override to filter by install type.
    fn can_handle(&self, _app: &Application) -> bool {
        true
    }

    /// Get the download size for a package update
    ///
    /// If available, returns the size in bytes of the update package.
    /// This can be used to show users how much data will be downloaded.
    ///
    /// # Parameters
    ///
    /// - `package_name`: The name of the package to check
    ///
    /// # Returns
    ///
    /// - `Some(size)` with size in bytes if known
    /// - `None` if size information is not available
    ///
    /// # Default Implementation
    ///
    /// Returns `None`. Override to provide size information.
    async fn get_package_size(&self, _package_name: &str) -> Option<u64> {
        None
    }

    /// Check if an update is a security update
    ///
    /// Determines whether the available update for a package is classified
    /// as a security update. This is useful for prioritizing critical updates.
    ///
    /// # Parameters
    ///
    /// - `package_name`: The name of the package to check
    ///
    /// # Returns
    ///
    /// - `true` if the update is security-related
    /// - `false` if not a security update or unknown
    ///
    /// # Default Implementation
    ///
    /// Returns `false`. Override to provide security classification.
    async fn is_security_update(&self, _package_name: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    /// Mock implementation for testing trait object functionality
    struct MockPackageManager {
        name: &'static str,
        initialized: bool,
        packages: Vec<(String, String, String)>, // (name, current, available)
    }

    impl MockPackageManager {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                initialized: false,
                packages: vec![
                    ("firefox".to_string(), "120.0".to_string(), "121.0".to_string()),
                    ("vim".to_string(), "8.2".to_string(), "9.0".to_string()),
                ],
            }
        }
    }

    #[async_trait]
    impl PackageManager for MockPackageManager {
        async fn initialize(&mut self) -> UpdateCheckResult<()> {
            self.initialized = true;
            Ok(())
        }

        async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
            for (name, current, available) in &self.packages {
                if app.name.to_lowercase() == name.to_lowercase() {
                    return Ok(Some(UpdateInfo {
                        current_version: Some(current.clone()),
                        available_version: available.clone(),
                        update_size_bytes: Some(10_000_000),
                        update_source: format!("{} repository", self.name),
                        update_url: None,
                        is_security_update: false,
                        release_notes: None,
                        last_checked: SystemTime::now(),
                    }));
                }
            }
            Ok(None)
        }

        fn generate_package_names(&self, app_name: &str) -> Vec<String> {
            vec![
                app_name.to_lowercase(),
                app_name.to_lowercase().replace(' ', "-"),
                app_name.to_lowercase().replace(' ', "_"),
            ]
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn can_handle(&self, app: &Application) -> bool {
            app.install_type == "DEB" || app.install_type == "Mock"
        }

        async fn get_package_size(&self, package_name: &str) -> Option<u64> {
            if package_name == "firefox" {
                Some(50_000_000)
            } else {
                None
            }
        }

        async fn is_security_update(&self, package_name: &str) -> bool {
            package_name == "vim" // Pretend vim has a security update
        }
    }

    #[tokio::test]
    async fn test_trait_object_creation() {
        let manager: Box<dyn PackageManager> = Box::new(MockPackageManager::new("mock-apt"));
        assert_eq!(manager.name(), "mock-apt");
    }

    #[tokio::test]
    async fn test_initialize() {
        let mut manager = MockPackageManager::new("test");
        assert!(!manager.initialized);

        manager.initialize().await.unwrap();
        assert!(manager.initialized);
    }

    #[tokio::test]
    async fn test_build_cache_calls_initialize() {
        let mut manager = MockPackageManager::new("test");
        assert!(!manager.initialized);

        // build_cache() should delegate to initialize()
        manager.build_cache().await.unwrap();
        assert!(manager.initialized);
    }

    #[tokio::test]
    async fn test_check_update_found() {
        let manager = MockPackageManager::new("test");
        let app = Application {
            name: "Firefox".to_string(),
            version: Some("120.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "DEB".to_string(),
            can_update: false,
            install_location: None,
            size_mb: None,
            registry_key: None,
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        };

        let result = manager.check_update(&app).await.unwrap();
        assert!(result.is_some());

        let update = result.unwrap();
        assert_eq!(update.available_version, "121.0");
        assert_eq!(update.current_version, Some("120.0".to_string()));
    }

    #[tokio::test]
    async fn test_check_update_not_found() {
        let manager = MockPackageManager::new("test");
        let app = Application {
            name: "NonExistentApp".to_string(),
            version: None,
            vendor: None,
            install_date: None,
            install_type: "DEB".to_string(),
            can_update: false,
            install_location: None,
            size_mb: None,
            registry_key: None,
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        };

        let result = manager.check_update(&app).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_generate_package_names() {
        let manager = MockPackageManager::new("test");
        let names = manager.generate_package_names("Visual Studio Code");

        assert!(names.contains(&"visual studio code".to_string()));
        assert!(names.contains(&"visual-studio-code".to_string()));
        assert!(names.contains(&"visual_studio_code".to_string()));
    }

    #[tokio::test]
    async fn test_can_handle() {
        let manager = MockPackageManager::new("test");

        let deb_app = Application {
            name: "test".to_string(),
            version: None,
            vendor: None,
            install_date: None,
            install_type: "DEB".to_string(),
            can_update: false,
            install_location: None,
            size_mb: None,
            registry_key: None,
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        };
        assert!(manager.can_handle(&deb_app));

        let snap_app = Application {
            name: "test".to_string(),
            version: None,
            vendor: None,
            install_date: None,
            install_type: "Snap".to_string(),
            can_update: false,
            install_location: None,
            size_mb: None,
            registry_key: None,
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        };
        assert!(!manager.can_handle(&snap_app));
    }

    #[tokio::test]
    async fn test_get_package_size() {
        let manager = MockPackageManager::new("test");

        let firefox_size = manager.get_package_size("firefox").await;
        assert_eq!(firefox_size, Some(50_000_000));

        let unknown_size = manager.get_package_size("unknown").await;
        assert_eq!(unknown_size, None);
    }

    #[tokio::test]
    async fn test_is_security_update() {
        let manager = MockPackageManager::new("test");

        assert!(manager.is_security_update("vim").await);
        assert!(!manager.is_security_update("firefox").await);
    }

    #[tokio::test]
    async fn test_trait_send_sync() {
        // Verify that PackageManager is Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn PackageManager>>();
    }

    #[tokio::test]
    async fn test_multiple_managers_as_trait_objects() {
        let managers: Vec<Box<dyn PackageManager>> = vec![
            Box::new(MockPackageManager::new("apt")),
            Box::new(MockPackageManager::new("snap")),
            Box::new(MockPackageManager::new("flatpak")),
        ];

        let names: Vec<&str> = managers.iter().map(|m| m.name()).collect();
        assert_eq!(names, vec!["apt", "snap", "flatpak"]);
    }
}
