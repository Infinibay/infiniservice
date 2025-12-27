//! Linux-specific application update checking
//!
//! This module provides update checking for Linux applications by coordinating
//! multiple package managers through the `PackageManager` trait.
//!
//! # Architecture
//!
//! ```text
//! LinuxUpdateChecker
//!        ↓
//!   Vec<Box<dyn PackageManager>>
//!        ↓
//! [AptUpdateChecker, RpmUpdateChecker, SnapUpdateChecker, FlatpakUpdateChecker]
//! ```
//!
//! The `LinuxUpdateChecker` automatically detects available package managers
//! on the system and creates appropriate checker instances. Updates are checked
//! by iterating through all available managers until one finds a match.
//!
//! # Supported Package Managers
//!
//! - **APT**: Debian/Ubuntu systems (via `apt list --upgradable`)
//! - **RPM**: Red Hat/Fedora/CentOS (via `dnf check-update` or `yum check-update`)
//! - **Snap**: Snap packages (via `snap refresh --list`)
//! - **Flatpak**: Flatpak packages (via `flatpak remote-ls --updates`)
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::commands::linux_update_checker::LinuxUpdateChecker;
//! use crate::commands::update_checker::UpdateChecker;
//!
//! let mut checker = LinuxUpdateChecker::new()?;
//! checker.initialize().await?;
//!
//! for app in applications {
//!     if let Some(update) = checker.check_app_update(&app, &config).await? {
//!         println!("{} has update: {} -> {}", app.name,
//!                  update.current_version.unwrap_or_default(),
//!                  update.available_version);
//!     }
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};

use super::application_inventory::Application;
use super::linux::{AptUpdateChecker, FlatpakUpdateChecker, RpmUpdateChecker, SnapUpdateChecker};
use super::traits::PackageManager;
use super::update_checker::{UpdateCheckConfig, UpdateCheckResult, UpdateChecker, UpdateInfo};
use crate::os_detection::{get_os_info, PackageManager as OsPackageManager};

/// Linux-specific update checker
///
/// Coordinates multiple package managers to check for application updates.
/// Automatically detects and initializes package managers available on the system.
pub struct LinuxUpdateChecker {
    /// Collection of available package managers
    managers: Vec<Box<dyn PackageManager>>,
}

impl LinuxUpdateChecker {
    /// Create a new Linux update checker
    ///
    /// Detects available package managers on the system and creates
    /// appropriate checker instances for each.
    ///
    /// # Returns
    ///
    /// A new `LinuxUpdateChecker` with all available package managers
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let checker = LinuxUpdateChecker::new()?;
    /// // On Ubuntu: will have APT, Snap, Flatpak (if installed)
    /// // On Fedora: will have RPM, Snap (if installed), Flatpak (if installed)
    /// ```
    pub fn new() -> Result<Self> {
        let os_info = get_os_info();
        let mut managers: Vec<Box<dyn PackageManager>> = Vec::new();

        // Create APT checker if available
        if os_info
            .available_package_managers
            .contains(&OsPackageManager::Apt)
        {
            if let Ok(checker) = AptUpdateChecker::new() {
                managers.push(Box::new(checker));
                debug!("Added APT update checker");
            }
        }

        // Create RPM checker if yum or dnf is available
        if os_info
            .available_package_managers
            .iter()
            .any(|pm| matches!(pm, OsPackageManager::Yum | OsPackageManager::Dnf))
        {
            if let Ok(checker) = RpmUpdateChecker::new() {
                managers.push(Box::new(checker));
                debug!("Added RPM update checker");
            }
        }

        // Create Snap checker if available
        if os_info
            .available_package_managers
            .contains(&OsPackageManager::Snap)
        {
            if let Ok(checker) = SnapUpdateChecker::new() {
                managers.push(Box::new(checker));
                debug!("Added Snap update checker");
            }
        }

        // Create Flatpak checker if available
        if os_info
            .available_package_managers
            .contains(&OsPackageManager::Flatpak)
        {
            if let Ok(checker) = FlatpakUpdateChecker::new() {
                managers.push(Box::new(checker));
                debug!("Added Flatpak update checker");
            }
        }

        debug!(
            "Created LinuxUpdateChecker with {} package managers",
            managers.len()
        );

        Ok(Self { managers })
    }

    /// Get the number of active package managers
    pub fn manager_count(&self) -> usize {
        self.managers.len()
    }

    /// Get the names of active package managers
    pub fn manager_names(&self) -> Vec<&'static str> {
        self.managers.iter().map(|m| m.name()).collect()
    }
}

#[async_trait]
impl UpdateChecker for LinuxUpdateChecker {
    async fn check_app_update(
        &mut self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!(
            "Checking updates for Linux app: {} ({})",
            app.name, app.install_type
        );

        // Try each available checker until one finds an update
        for manager in &self.managers {
            if let Ok(Some(info)) = manager.check_update(app).await {
                debug!(
                    "Found update via {}: {} -> {}",
                    manager.name(),
                    info.current_version.as_deref().unwrap_or("unknown"),
                    info.available_version
                );
                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    fn name(&self) -> &'static str {
        "LinuxUpdateChecker"
    }

    fn can_handle(&self, _app: &Application) -> bool {
        // Linux update checker can attempt to handle any application
        // Individual checkers will determine if they can actually check the app
        true
    }

    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Linux update checker");

        // Track indices of managers that failed to initialize
        let mut failed_indices = Vec::new();

        for (i, manager) in self.managers.iter_mut().enumerate() {
            if let Err(e) = manager.initialize().await {
                warn!("Failed to initialize {} checker: {}", manager.name(), e);
                failed_indices.push(i);
            } else {
                debug!("Successfully initialized {} checker", manager.name());
            }
        }

        // Remove failed managers in reverse order to preserve indices
        for i in failed_indices.into_iter().rev() {
            let removed = self.managers.remove(i);
            debug!("Removed failed {} checker", removed.name());
        }

        debug!(
            "Linux update checker initialized with {} active managers",
            self.managers.len()
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_linux_update_checker_creation() {
        let checker = LinuxUpdateChecker::new();
        assert!(checker.is_ok());
    }

    #[test]
    fn test_can_handle() {
        let checker = LinuxUpdateChecker::new().unwrap();

        let app = Application {
            name: "Test App".to_string(),
            version: Some("1.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "APT".to_string(),
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

        assert!(checker.can_handle(&app));
    }

    #[test]
    fn test_name() {
        let checker = LinuxUpdateChecker::new().unwrap();
        assert_eq!(checker.name(), "LinuxUpdateChecker");
    }

    #[test]
    fn test_manager_count() {
        let checker = LinuxUpdateChecker::new().unwrap();
        // The count depends on what's available on the system
        // Just verify it doesn't panic
        let _ = checker.manager_count();
    }

    #[test]
    fn test_manager_names() {
        let checker = LinuxUpdateChecker::new().unwrap();
        let names = checker.manager_names();
        // Verify all names are non-empty valid identifiers
        for name in names {
            assert!(!name.is_empty());
            assert!(name.chars().all(|c| c.is_alphanumeric() || c == '-'));
        }
    }
}
