//! WinGet package manager implementation
//!
//! This module provides update checking for Windows applications using WinGet CLI.
//! It caches the list of available updates and provides efficient lookups.
//!
//! # Command Output Format
//!
//! The `winget upgrade` command outputs packages in this format:
//! ```text
//! Name               Id                     Version     Available   Source
//! -------------------------------------------------------------------------------
//! Microsoft Terminal Microsoft.WindowsTerminal 1.17.11461.0 1.18.3181.0 winget
//! Visual Studio Code Microsoft.VisualStudioCode 1.75.1      1.76.0      winget
//! ```
//!
//! Each line contains:
//! - Package name (display name)
//! - Package ID (WinGet identifier)
//! - Current version
//! - Available version
//! - Source (winget, msstore, etc.)

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

/// Information about a package from WinGet CLI
#[derive(Debug, Clone)]
pub struct WinGetPackageInfo {
    /// WinGet package identifier
    pub package_id: String,
    /// Latest available version
    pub latest_version: String,
    /// Optional installer size in bytes
    pub installer_size: Option<u64>,
    /// Optional download URL
    pub download_url: Option<String>,
    /// Source of the update (WinGet, msstore, etc.)
    pub source: String,
    /// Optional release notes
    pub release_notes: Option<String>,
}

/// WinGet update checker for Windows Store and WinGet applications
///
/// Uses `winget upgrade` to detect available package updates
/// and caches the results for efficient lookups.
pub struct WinGetManager {
    /// Cache of package_name -> WinGetPackageInfo (5 minute TTL)
    /// Wrapped in Mutex for interior mutability to allow cache refresh in check_update
    cache: Mutex<AsyncCache<String, WinGetPackageInfo>>,
}

impl WinGetManager {
    /// Create a new WinGet update manager
    ///
    /// # Returns
    ///
    /// A new `WinGetManager` instance with an empty cache
    ///
    /// # Errors
    ///
    /// Returns an error if the manager cannot be created
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: Mutex::new(AsyncCache::with_ttl("winget-updates", Duration::from_secs(300))),
        })
    }

    /// Parse winget upgrade output to get all available updates
    ///
    /// # Arguments
    ///
    /// * `output` - The stdout from the winget upgrade command
    ///
    /// # Returns
    ///
    /// A HashMap mapping package names (lowercase) to their WinGetPackageInfo
    ///
    /// # Parsing Strategy
    ///
    /// WinGet output format has multi-word names, so we parse from the end:
    /// - Last token: Source (optional, e.g., "winget", "msstore")
    /// - Second to last: Available version
    /// - Third to last: Current version
    /// - Fourth to last: Package ID (single token like "Microsoft.WindowsTerminal")
    /// - Remaining tokens: Package name (can be multi-word like "Microsoft Terminal")
    fn parse_winget_output(output: &str) -> UpdateCheckResult<HashMap<String, WinGetPackageInfo>> {
        let mut updates = HashMap::new();

        debug!("Parsing WinGet upgrade output...");

        // Skip header lines and parse table format
        let mut found_header = false;
        for line in output.lines() {
            // Skip until we find the header line
            if line.contains("Name") && line.contains("Id") && line.contains("Version") {
                found_header = true;
                continue;
            }

            // Skip separator lines
            if !found_header || line.starts_with('-') || line.trim().is_empty() {
                continue;
            }

            // Parse from the end to handle multi-word package names
            // Format: Name (multi-word)    Id    Version    Available    Source
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Need at least 4 tokens: name, id, version, available
            // Source is optional (5th token from end if present)
            if parts.len() < 4 {
                continue;
            }

            // Determine if source column is present by checking if last token
            // looks like a source (winget, msstore, etc.) rather than a version
            let last_token = parts[parts.len() - 1];
            let has_source = !last_token.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
                && !last_token.contains('.');

            let (source, available_version, current_version, id, name_parts) = if has_source && parts.len() >= 5 {
                // With source: Name... Id Version Available Source
                let source = parts[parts.len() - 1];
                let available = parts[parts.len() - 2];
                let current = parts[parts.len() - 3];
                let id = parts[parts.len() - 4];
                let name_parts = &parts[..parts.len() - 4];
                (source, available, current, id, name_parts)
            } else if parts.len() >= 4 {
                // Without source: Name... Id Version Available
                let available = parts[parts.len() - 1];
                let current = parts[parts.len() - 2];
                let id = parts[parts.len() - 3];
                let name_parts = &parts[..parts.len() - 3];
                ("winget", available, current, id, name_parts)
            } else {
                continue;
            };

            // Skip if name is empty
            if name_parts.is_empty() {
                continue;
            }

            // Join name parts to get full multi-word name
            let name = name_parts.join(" ");

            // Only include if there's actually an update available
            if available_version != current_version
                && available_version != "<"
                && available_version != "Unknown"
            {
                let package_info = WinGetPackageInfo {
                    package_id: id.to_string(),
                    latest_version: available_version.to_string(),
                    installer_size: None,
                    download_url: None,
                    source: format!("WinGet ({})", source),
                    release_notes: Some(format!(
                        "Update available: {} -> {}",
                        current_version, available_version
                    )),
                };

                // Index by both name and ID for flexible lookup
                updates.insert(name.to_lowercase(), package_info.clone());
                updates.insert(id.to_lowercase(), package_info);

                debug!(
                    "Found update: {} ({}) {} -> {}",
                    name, id, current_version, available_version
                );
            }
        }

        debug!(
            "Parsed {} available updates from WinGet",
            updates.len() / 2
        ); // Divide by 2 because we store each twice
        Ok(updates)
    }

    /// Build the package upgrade cache by running winget upgrade
    #[cfg(target_os = "windows")]
    fn build_upgrade_cache_blocking() -> UpdateCheckResult<HashMap<String, WinGetPackageInfo>> {
        use std::process::Command;

        debug!("Building WinGet upgrade cache");

        let output = Command::new("winget")
            .args(["upgrade", "--accept-source-agreements", "--disable-interactivity"])
            .output()
            .map_err(|e| {
                UpdateCheckError::PlatformError(format!("Failed to execute winget: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            debug!("WinGet upgrade listing failed: {}", stderr);
            return Ok(HashMap::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_winget_output(&stdout)
    }

    #[cfg(not(target_os = "windows"))]
    fn build_upgrade_cache_blocking() -> UpdateCheckResult<HashMap<String, WinGetPackageInfo>> {
        debug!("WinGet not available on non-Windows platforms");
        Ok(HashMap::new())
    }

    /// Create UpdateInfo from WinGet package info if version is newer
    fn create_update_info(
        app: &Application,
        package_info: &WinGetPackageInfo,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        let current_version = app.version.as_deref().unwrap_or("Unknown");

        // Compare versions using our utility function
        if crate::commands::update_checker::utils::is_version_newer(
            current_version,
            &package_info.latest_version,
        ) {
            Ok(Some(UpdateInfo {
                current_version: app.version.clone(),
                available_version: package_info.latest_version.clone(),
                update_size_bytes: package_info.installer_size,
                update_source: package_info.source.clone(),
                update_url: package_info.download_url.clone(),
                is_security_update: false, // WinGet doesn't typically mark security updates
                release_notes: package_info.release_notes.clone(),
                last_checked: SystemTime::now(),
            }))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl PackageManager for WinGetManager {
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing WinGet update manager");

        let mut cache = self.cache.lock().await;
        cache
            .build_or_refresh(Self::build_upgrade_cache_blocking)
            .await?;

        Ok(())
    }

    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Refresh cache if expired before reading
        {
            let mut cache = self.cache.lock().await;
            cache
                .build_or_refresh(Self::build_upgrade_cache_blocking)
                .await?;
        }

        // Try to match the application name to a package name
        let possible_names = self.generate_package_names(&app.name);

        // Get all updates from cache
        let cache = self.cache.lock().await;
        let all_updates = match cache.get_all() {
            Some(updates) => updates,
            None => {
                debug!("WinGet cache not available");
                return Ok(None);
            }
        };

        // Strategy 1: Direct name match
        for package_name in &possible_names {
            if let Some(package_info) = all_updates.get(package_name) {
                if let Some(update_info) = Self::create_update_info(app, package_info)? {
                    debug!("Found direct match for {} in WinGet cache", app.name);
                    return Ok(Some(update_info));
                }
            }
        }

        // Strategy 2: Partial name matching (for apps like "Google Chrome" -> "Chrome")
        let app_name_lower = app.name.to_lowercase();
        for (cached_name, package_info) in all_updates {
            if cached_name.contains(&app_name_lower) || app_name_lower.contains(cached_name) {
                debug!("Found partial match: {} -> {}", app.name, cached_name);
                if let Some(update_info) = Self::create_update_info(app, package_info)? {
                    return Ok(Some(update_info));
                }
            }
        }

        Ok(None)
    }

    fn generate_package_names(&self, app_name: &str) -> Vec<String> {
        generate_windows_package_names(app_name)
    }

    fn name(&self) -> &'static str {
        "winget"
    }

    fn can_handle(&self, app: &Application) -> bool {
        // WinGet can handle Store apps and most common Windows applications
        matches!(app.install_type.as_str(), "Store" | "MSI" | "Registry")
    }

    async fn get_package_size(&self, package_name: &str) -> Option<u64> {
        let cache = self.cache.lock().await;
        cache
            .get(&package_name.to_lowercase())
            .and_then(|info| info.installer_size)
    }

    async fn is_security_update(&self, _package_name: &str) -> bool {
        // WinGet doesn't typically mark security updates
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_winget_manager_creation() {
        let manager = WinGetManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_parse_winget_output() {
        let output = r#"Name               Id                     Version     Available   Source
-------------------------------------------------------------------------------
Microsoft Terminal Microsoft.WindowsTerminal 1.17.11461.0 1.18.3181.0 winget
Visual Studio Code Microsoft.VisualStudioCode 1.75.1      1.76.0      winget"#;

        let result = WinGetManager::parse_winget_output(output).unwrap();

        // Should have 4 entries (2 packages × 2 indexes each)
        assert_eq!(result.len(), 4);

        // Check by name
        assert!(result.contains_key("microsoft terminal"));
        let terminal = result.get("microsoft terminal").unwrap();
        assert_eq!(terminal.latest_version, "1.18.3181.0");
        assert_eq!(terminal.package_id, "Microsoft.WindowsTerminal");

        // Check by ID
        assert!(result.contains_key("microsoft.windowsterminal"));
    }

    #[test]
    fn test_parse_winget_output_no_updates() {
        let output = r#"Name               Id                     Version     Available   Source
-------------------------------------------------------------------------------
Microsoft Terminal Microsoft.WindowsTerminal 1.18.3181.0 1.18.3181.0 winget"#;

        let result = WinGetManager::parse_winget_output(output).unwrap();

        // Should be empty since current == available
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_winget_output_empty() {
        let output = "No installed package found matching input criteria.";
        let result = WinGetManager::parse_winget_output(output).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_winget_output_malformed() {
        let output = "Some random text that doesn't match expected format";
        let result = WinGetManager::parse_winget_output(output).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_generate_package_names() {
        let manager = WinGetManager::new().unwrap();
        let names = manager.generate_package_names("Google Chrome");

        assert!(names.contains(&"google chrome".to_string()));
        assert!(names.contains(&"chrome".to_string()));
    }

    #[test]
    fn test_name() {
        let manager = WinGetManager::new().unwrap();
        assert_eq!(manager.name(), "winget");
    }

    #[test]
    fn test_can_handle() {
        let manager = WinGetManager::new().unwrap();

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
        assert!(manager.can_handle(&store_app));

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

        let unknown_app = Application {
            name: "Test Unknown App".to_string(),
            version: Some("1.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "Unknown".to_string(),
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
        assert!(!manager.can_handle(&unknown_app));
    }

    #[tokio::test]
    async fn test_is_security_update() {
        let manager = WinGetManager::new().unwrap();
        assert!(!manager.is_security_update("any-package").await);
    }
}
