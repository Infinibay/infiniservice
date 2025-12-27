//! Windows-specific application update checking
//!
//! This module provides update checking for Windows applications using a modular
//! architecture with multiple backend managers:
//!
//! - **WinGet** (`windows::WinGetManager`): Store apps, WinGet packages, common apps
//! - **PowerShell** (`windows::PowerShellManager`): MSI apps via Windows Update Agent
//! - **Registry** (`windows::RegistryManager`): Known apps (Chrome, Firefox, Edge, Java, Adobe)
//!
//! # Architecture
//!
//! ```text
//! WindowsUpdateChecker
//!        ↓
//!   Vec<Box<dyn PackageManager>>
//!        ↓
//! [WinGetManager, PowerShellManager, RegistryManager]
//! ```
//!
//! Managers are queried in priority order (WinGet → PowerShell → Registry)
//! until one returns an update, or all return None.

use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{debug, warn};

use super::application_inventory::Application;
use super::traits::PackageManager;
use super::update_checker::{UpdateCheckConfig, UpdateCheckError, UpdateCheckResult, UpdateChecker, UpdateInfo};
use super::windows::{PowerShellManager, RegistryManager, WinGetManager};

/// Windows-specific update checker using modular package managers
///
/// This coordinator creates and manages multiple package manager backends,
/// querying them in priority order to find available updates.
pub struct WindowsUpdateChecker {
    /// Package managers in priority order
    managers: Vec<Box<dyn PackageManager>>,
}

impl WindowsUpdateChecker {
    /// Create a new Windows update checker
    ///
    /// Initializes all available package managers:
    /// 1. WinGet (most comprehensive, covers Store + common apps)
    /// 2. PowerShell (Windows Updates for MSI packages)
    /// 3. Registry (fallback for known apps)
    ///
    /// # Returns
    ///
    /// A new `WindowsUpdateChecker` instance with available managers
    ///
    /// # Errors
    ///
    /// Returns an error only if critical initialization fails
    pub fn new() -> Result<Self> {
        let mut managers: Vec<Box<dyn PackageManager>> = Vec::new();

        // Try to create each manager (some may fail on certain systems)
        if let Ok(winget) = WinGetManager::new() {
            debug!("WinGet manager created successfully");
            managers.push(Box::new(winget));
        } else {
            debug!("WinGet manager not available");
        }

        if let Ok(powershell) = PowerShellManager::new() {
            debug!("PowerShell manager created successfully");
            managers.push(Box::new(powershell));
        } else {
            debug!("PowerShell manager not available");
        }

        // Registry manager always succeeds
        managers.push(Box::new(RegistryManager::new()));
        debug!("Registry manager created successfully");

        debug!(
            "WindowsUpdateChecker initialized with {} managers",
            managers.len()
        );

        Ok(Self { managers })
    }
}

#[async_trait]
impl UpdateChecker for WindowsUpdateChecker {
    async fn check_app_update(
        &mut self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!(
            "Checking updates for Windows app: {} ({})",
            app.name, app.install_type
        );

        // Query managers in priority order until one returns an update
        for manager in &self.managers {
            // Skip managers that can't handle this app type
            if !manager.can_handle(app) {
                debug!(
                    "Manager {} cannot handle app {} (type: {})",
                    manager.name(),
                    app.name,
                    app.install_type
                );
                continue;
            }

            debug!("Checking {} via {} manager", app.name, manager.name());

            match manager.check_update(app).await {
                Ok(Some(update_info)) => {
                    debug!(
                        "Found update for {} via {}: {} -> {}",
                        app.name,
                        manager.name(),
                        update_info
                            .current_version
                            .as_deref()
                            .unwrap_or("unknown"),
                        update_info.available_version
                    );
                    return Ok(Some(update_info));
                }
                Ok(None) => {
                    debug!("No update found for {} via {}", app.name, manager.name());
                }
                Err(e) => {
                    warn!(
                        "Error checking {} via {}: {}",
                        app.name,
                        manager.name(),
                        e
                    );
                    // Continue to next manager on error
                }
            }
        }

        debug!("No updates found for {} from any manager", app.name);
        Ok(None)
    }

    fn name(&self) -> &'static str {
        "WindowsUpdateChecker"
    }

    fn can_handle(&self, app: &Application) -> bool {
        // Check if any manager can handle this app
        self.managers.iter().any(|m| m.can_handle(app))
    }

    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Windows update checker");

        // Initialize all managers, removing those that fail
        let mut failed_managers = Vec::new();

        for (i, manager) in self.managers.iter_mut().enumerate() {
            if let Err(e) = manager.initialize().await {
                warn!("Failed to initialize {} manager: {}", manager.name(), e);
                failed_managers.push(i);
            } else {
                debug!("{} manager initialized successfully", manager.name());
            }
        }

        // Remove failed managers (in reverse order to preserve indices)
        for i in failed_managers.into_iter().rev() {
            let removed = self.managers.remove(i);
            debug!("Removed failed manager: {}", removed.name());
        }

        if self.managers.is_empty() {
            return Err(UpdateCheckError::PlatformError(
                "No Windows update managers available".to_string(),
            ));
        }

        debug!(
            "{} managers available after initialization",
            self.managers.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_windows_update_checker_creation() {
        let checker = WindowsUpdateChecker::new();
        assert!(checker.is_ok());

        let checker = checker.unwrap();
        // Should have at least the Registry manager
        assert!(!checker.managers.is_empty());
    }

    #[test]
    fn test_can_handle_store() {
        let checker = WindowsUpdateChecker::new().unwrap();

        let store_app = Application {
            name: "Test Store App".to_string(),
            version: Some("1.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "Store".to_string(),
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

        assert!(checker.can_handle(&store_app));
    }

    #[test]
    fn test_can_handle_msi() {
        let checker = WindowsUpdateChecker::new().unwrap();

        let msi_app = Application {
            name: "Test MSI App".to_string(),
            version: Some("1.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "MSI".to_string(),
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

        assert!(checker.can_handle(&msi_app));
    }

    #[test]
    fn test_can_handle_registry() {
        let checker = WindowsUpdateChecker::new().unwrap();

        let registry_app = Application {
            name: "Google Chrome".to_string(), // Known app
            version: Some("120.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "Registry".to_string(),
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

        assert!(checker.can_handle(&registry_app));
    }

    #[test]
    fn test_name() {
        let checker = WindowsUpdateChecker::new().unwrap();
        assert_eq!(checker.name(), "WindowsUpdateChecker");
    }

    #[tokio::test]
    async fn test_initialize() {
        let mut checker = WindowsUpdateChecker::new().unwrap();

        // Initialize should succeed (at least Registry manager will work)
        let result = checker.initialize().await;
        assert!(result.is_ok());
    }
}
