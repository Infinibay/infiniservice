//! PowerShell-based Windows Update Agent manager implementation
//!
//! This module provides update checking for MSI applications using PowerShell
//! and the Windows Update Agent API. It caches the list of available Windows
//! updates and provides efficient lookups.
//!
//! # Update Sources
//!
//! - PSWindowsUpdate module (if available): `Get-WUList -MicrosoftUpdate`
//! - Get-HotFix fallback: Shows installed updates when PSWindowsUpdate is unavailable

use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

use crate::commands::application_inventory::Application;
use crate::commands::common::cache::AsyncCache;
use crate::commands::common::package_names::generate_windows_package_names;
use crate::commands::traits::PackageManager;
use crate::commands::update_checker::{UpdateCheckError, UpdateCheckResult, UpdateInfo};

/// PowerShell-based Windows Update Agent manager for MSI applications
///
/// Uses PowerShell commands to query Windows Update for available updates
/// and caches the results for efficient lookups.
pub struct PowerShellManager {
    /// Cache of update_title (lowercase) -> update_title (10 minute TTL)
    /// Wrapped in Mutex for interior mutability to allow cache refresh in check_update
    cache: Mutex<AsyncCache<String, String>>,
}

impl PowerShellManager {
    /// Create a new PowerShell update manager
    ///
    /// # Returns
    ///
    /// A new `PowerShellManager` instance with an empty cache
    ///
    /// # Errors
    ///
    /// Returns an error if the manager cannot be created
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: Mutex::new(AsyncCache::with_ttl("powershell-updates", Duration::from_secs(600))),
        })
    }

    /// Parse Windows Update PowerShell output (PSWindowsUpdate module)
    ///
    /// # Arguments
    ///
    /// * `output` - JSON output from Get-WUList command
    ///
    /// # Returns
    ///
    /// A HashMap mapping update titles (lowercase) to their original titles
    fn parse_windows_update_output(output: &str) -> UpdateCheckResult<HashMap<String, String>> {
        let mut updates = HashMap::new();

        // Try to parse JSON output
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(array) = json_value.as_array() {
                for item in array {
                    if let Some(title) = item.get("Title").and_then(|t| t.as_str()) {
                        updates.insert(title.to_lowercase(), title.to_string());
                    }
                }
            } else if let Some(title) = json_value.get("Title").and_then(|t| t.as_str()) {
                updates.insert(title.to_lowercase(), title.to_string());
            }
        }

        debug!("Parsed {} Windows Updates", updates.len());
        Ok(updates)
    }

    /// Parse Get-HotFix output as fallback
    ///
    /// # Arguments
    ///
    /// * `output` - JSON output from Get-HotFix command
    ///
    /// # Returns
    ///
    /// A HashMap mapping hotfix IDs (lowercase) to their descriptions
    fn parse_hotfix_output(output: &str) -> UpdateCheckResult<HashMap<String, String>> {
        let mut updates = HashMap::new();

        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(array) = json_value.as_array() {
                for item in array {
                    if let (Some(hotfix_id), Some(description)) = (
                        item.get("HotFixID").and_then(|h| h.as_str()),
                        item.get("Description").and_then(|d| d.as_str()),
                    ) {
                        let combined = format!("{}: {}", hotfix_id, description);
                        updates.insert(combined.to_lowercase(), combined);
                    }
                }
            }
        }

        debug!("Parsed {} HotFix entries", updates.len());
        Ok(updates)
    }

    /// Build the Windows Update cache by running PowerShell commands
    #[cfg(target_os = "windows")]
    fn build_update_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        use std::process::Command;

        debug!("Building PowerShell Windows Update cache");

        // Try with PSWindowsUpdate module first
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "try { Get-WUList -MicrosoftUpdate | Select-Object Title, Size | ConvertTo-Json } catch { Write-Output 'PSWindowsUpdate_NOT_AVAILABLE' }",
            ])
            .output()
            .map_err(|e| {
                UpdateCheckError::PlatformError(format!("Failed to execute PowerShell: {}", e))
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.contains("PSWindowsUpdate_NOT_AVAILABLE") {
                return Self::parse_windows_update_output(&stdout);
            }
        }

        // Fallback: use built-in Get-HotFix to show installed updates
        let fallback_output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-HotFix | Select-Object -First 10 HotFixID, Description, InstalledOn | ConvertTo-Json",
            ])
            .output()
            .map_err(|e| {
                UpdateCheckError::PlatformError(format!(
                    "Failed to execute fallback PowerShell: {}",
                    e
                ))
            })?;

        if fallback_output.status.success() {
            let stdout = String::from_utf8_lossy(&fallback_output.stdout);
            return Self::parse_hotfix_output(&stdout);
        }

        Ok(HashMap::new())
    }

    #[cfg(not(target_os = "windows"))]
    fn build_update_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        debug!("PowerShell Windows Update not available on non-Windows platforms");
        Ok(HashMap::new())
    }

    /// Verify PowerShell is available and working
    #[cfg(target_os = "windows")]
    async fn verify_powershell_available() -> UpdateCheckResult<()> {
        let output = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$PSVersionTable.PSVersion.Major",
            ])
            .output()
            .await;

        match output {
            Ok(output) if output.status.success() => {
                let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                debug!("PowerShell version {} detected and ready", version);
                Ok(())
            }
            _ => Err(UpdateCheckError::PlatformError(
                "PowerShell not available or not working".to_string(),
            )),
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn verify_powershell_available() -> UpdateCheckResult<()> {
        debug!("PowerShell not available on non-Windows platforms");
        Ok(())
    }
}

#[async_trait]
impl PackageManager for PowerShellManager {
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing PowerShell Windows Update manager");

        // Verify PowerShell is available
        Self::verify_powershell_available().await?;

        let mut cache = self.cache.lock().await;
        cache
            .build_or_refresh(Self::build_update_cache_blocking)
            .await?;

        Ok(())
    }

    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Refresh cache if expired before reading
        {
            let mut cache = self.cache.lock().await;
            cache
                .build_or_refresh(Self::build_update_cache_blocking)
                .await?;
        }

        // Get all updates from cache
        let cache = self.cache.lock().await;
        let all_updates = match cache.get_all() {
            Some(updates) => updates,
            None => {
                debug!("PowerShell Windows Update cache not available");
                return Ok(None);
            }
        };

        if all_updates.is_empty() {
            debug!("No Windows Updates found in cache");
            return Ok(None);
        }

        // Look for updates that might be related to this application
        let app_name_lower = app.name.to_lowercase();
        for (key, update_title) in all_updates {
            if key.contains(&app_name_lower) || app_name_lower.contains(key.as_str()) {
                debug!(
                    "Found potential Windows Update for {}: {}",
                    app.name, update_title
                );

                let is_security = update_title.to_lowercase().contains("security");

                return Ok(Some(UpdateInfo {
                    current_version: app.version.clone(),
                    available_version: "Available via Windows Update".to_string(),
                    update_size_bytes: None,
                    update_source: "Windows Update".to_string(),
                    update_url: None,
                    is_security_update: is_security,
                    release_notes: Some(update_title.clone()),
                    last_checked: SystemTime::now(),
                }));
            }
        }

        debug!("No Windows Update found for application: {}", app.name);
        Ok(None)
    }

    fn generate_package_names(&self, app_name: &str) -> Vec<String> {
        generate_windows_package_names(app_name)
    }

    fn name(&self) -> &'static str {
        "powershell"
    }

    fn can_handle(&self, app: &Application) -> bool {
        // PowerShell manager handles MSI applications
        app.install_type == "MSI"
    }

    async fn get_package_size(&self, _package_name: &str) -> Option<u64> {
        // PowerShell doesn't typically provide package size
        None
    }

    async fn is_security_update(&self, package_name: &str) -> bool {
        // Check if the update title contains "security"
        let cache = self.cache.lock().await;
        if let Some(updates) = cache.get_all() {
            for (key, title) in updates {
                if key.contains(&package_name.to_lowercase()) {
                    return title.to_lowercase().contains("security");
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_powershell_manager_creation() {
        let manager = PowerShellManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_parse_windows_update_output_array() {
        let output = r#"[
            {"Title": "Security Update for Windows (KB12345)", "Size": 1234567},
            {"Title": "Cumulative Update for .NET Framework", "Size": 2345678}
        ]"#;

        let result = PowerShellManager::parse_windows_update_output(output).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("security update for windows (kb12345)"));
        assert!(result.contains_key("cumulative update for .net framework"));
    }

    #[test]
    fn test_parse_windows_update_output_single() {
        let output = r#"{"Title": "Security Update for Windows (KB12345)", "Size": 1234567}"#;

        let result = PowerShellManager::parse_windows_update_output(output).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("security update for windows (kb12345)"));
    }

    #[test]
    fn test_parse_windows_update_output_empty() {
        let output = "[]";
        let result = PowerShellManager::parse_windows_update_output(output).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_hotfix_output() {
        let output = r#"[
            {"HotFixID": "KB12345", "Description": "Security Update"},
            {"HotFixID": "KB67890", "Description": "Critical Update"}
        ]"#;

        let result = PowerShellManager::parse_hotfix_output(output).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("kb12345: security update"));
        assert!(result.contains_key("kb67890: critical update"));
    }

    #[test]
    fn test_parse_hotfix_output_empty() {
        let output = "[]";
        let result = PowerShellManager::parse_hotfix_output(output).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_generate_package_names() {
        let manager = PowerShellManager::new().unwrap();
        let names = manager.generate_package_names("Microsoft Office");

        assert!(names.contains(&"microsoft office".to_string()));
        assert!(names.contains(&"office".to_string()));
    }

    #[test]
    fn test_name() {
        let manager = PowerShellManager::new().unwrap();
        assert_eq!(manager.name(), "powershell");
    }

    #[test]
    fn test_can_handle() {
        let manager = PowerShellManager::new().unwrap();

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
        assert!(manager.can_handle(&msi_app));

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
        assert!(!manager.can_handle(&store_app));
    }
}
