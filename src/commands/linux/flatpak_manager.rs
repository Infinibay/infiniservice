//! Flatpak package manager implementation
//!
//! This module provides update checking for Flatpak packages using the `flatpak` command.
//!
//! # Command Output Format
//!
//! The `flatpak remote-ls --updates --columns=application,version` command outputs:
//! ```text
//! com.visualstudio.code	1.85.0
//! org.mozilla.firefox	121.0
//! org.videolan.VLC	3.0.18
//! ```
//!
//! Each line (tab-separated) contains:
//! - Application ID (e.g., `com.visualstudio.code`)
//! - Available version
//!
//! # Notes
//!
//! - Flatpak uses reverse-domain app IDs (e.g., `com.visualstudio.code`)
//! - The `registry_key` field in Application often contains the Flatpak app ID
//! - Name matching uses substring search for flexibility
//! - Flatpak doesn't have a concept of security-specific updates

use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::commands::application_inventory::Application;
use crate::commands::common::cache::AsyncCache;
use crate::commands::common::package_names::generate_flatpak_package_names;
use crate::commands::traits::PackageManager;
use crate::commands::update_checker::{UpdateCheckResult, UpdateInfo};

/// Flatpak update checker
///
/// Uses `flatpak remote-ls --updates` to detect available Flatpak updates
/// and caches the results for efficient lookups.
pub struct FlatpakUpdateChecker {
    /// Cache of app_id -> available_version
    cache: AsyncCache<String, String>,
}

impl FlatpakUpdateChecker {
    /// Create a new Flatpak update checker
    ///
    /// # Returns
    ///
    /// A new `FlatpakUpdateChecker` instance with an empty cache
    ///
    /// # Errors
    ///
    /// Returns an error if the checker cannot be created (currently infallible)
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: AsyncCache::new("flatpak-packages"),
        })
    }

    /// Parse the output of `flatpak remote-ls --updates --columns=application,version`
    ///
    /// # Arguments
    ///
    /// * `output` - The stdout from the flatpak command
    ///
    /// # Returns
    ///
    /// A HashMap mapping app IDs to their available versions
    fn parse_flatpak_output(output: &str) -> HashMap<String, String> {
        let mut packages = HashMap::new();

        for line in output.lines() {
            if line.is_empty() {
                continue;
            }

            // Format: app_id\tversion
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let app_id = parts[0].to_string();
                let version = parts[1].to_string();
                packages.insert(app_id, version);
            } else if parts.len() == 1 && !parts[0].is_empty() {
                // Sometimes only app_id is returned without version
                packages.insert(parts[0].to_string(), "available".to_string());
            }
        }

        packages
    }

    /// Build the flatpak update cache by running flatpak remote-ls --updates
    #[cfg(target_os = "linux")]
    fn build_update_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        use crate::commands::common::shell::execute_command_allow_failure;

        debug!("Building Flatpak update cache");

        let stdout = match execute_command_allow_failure(
            "flatpak",
            &["remote-ls", "--updates", "--columns=application,version"],
        ) {
            Some(output) => output,
            None => {
                debug!("flatpak remote-ls --updates failed, returning empty cache");
                return Ok(HashMap::new());
            }
        };

        let packages = Self::parse_flatpak_output(&stdout);

        debug!("Found {} flatpaks with pending updates", packages.len());
        Ok(packages)
    }

    #[cfg(not(target_os = "linux"))]
    fn build_update_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        debug!("Flatpak not available on non-Linux platforms");
        Ok(HashMap::new())
    }
}

#[async_trait]
impl PackageManager for FlatpakUpdateChecker {
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Flatpak update checker");

        self.cache
            .build_cache(Self::build_update_cache_blocking)
            .await?;

        Ok(())
    }

    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Try to match by registry_key (which contains the app_id for flatpaks)
        // or by name
        let app_id = app.registry_key.as_ref().unwrap_or(&app.name);

        // First try exact match with app_id
        if let Some(available_version) = self.cache.get(app_id) {
            debug!(
                "Found flatpak update for {}: {} -> {}",
                app.name,
                app.version.as_deref().unwrap_or("unknown"),
                available_version
            );

            return Ok(Some(UpdateInfo {
                current_version: app.version.clone(),
                available_version,
                update_size_bytes: None,
                update_source: "Flathub".to_string(),
                update_url: None,
                is_security_update: false,
                release_notes: None,
                last_checked: SystemTime::now(),
            }));
        }

        // Also try matching by name (case-insensitive substring match)
        let app_name_lower = app.name.to_lowercase();
        if let Some(all_packages) = self.cache.get_all() {
            for (cached_id, available_version) in all_packages.iter() {
                if cached_id.to_lowercase().contains(&app_name_lower) {
                    debug!(
                        "Found flatpak update for {} (matched by name): {} -> {}",
                        app.name,
                        app.version.as_deref().unwrap_or("unknown"),
                        available_version
                    );

                    return Ok(Some(UpdateInfo {
                        current_version: app.version.clone(),
                        available_version: available_version.clone(),
                        update_size_bytes: None,
                        update_source: "Flathub".to_string(),
                        update_url: None,
                        is_security_update: false,
                        release_notes: None,
                        last_checked: SystemTime::now(),
                    }));
                }
            }
        }

        Ok(None)
    }

    fn generate_package_names(&self, app_name: &str) -> Vec<String> {
        generate_flatpak_package_names(app_name)
    }

    fn name(&self) -> &'static str {
        "flatpak"
    }

    // Flatpak doesn't have security update classification
    async fn is_security_update(&self, _package_name: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_flatpak_output() {
        let output = "com.visualstudio.code\t1.85.0\norg.mozilla.firefox\t121.0\norg.videolan.VLC\t3.0.18\n";

        let packages = FlatpakUpdateChecker::parse_flatpak_output(output);

        assert_eq!(packages.len(), 3);
        assert_eq!(
            packages.get("com.visualstudio.code"),
            Some(&"1.85.0".to_string())
        );
        assert_eq!(
            packages.get("org.mozilla.firefox"),
            Some(&"121.0".to_string())
        );
        assert_eq!(
            packages.get("org.videolan.VLC"),
            Some(&"3.0.18".to_string())
        );
    }

    #[test]
    fn test_parse_flatpak_output_without_version() {
        let output = "com.visualstudio.code\norg.mozilla.firefox\t121.0\n";

        let packages = FlatpakUpdateChecker::parse_flatpak_output(output);

        assert_eq!(packages.len(), 2);
        // App without version gets "available" as placeholder
        assert_eq!(
            packages.get("com.visualstudio.code"),
            Some(&"available".to_string())
        );
        assert_eq!(
            packages.get("org.mozilla.firefox"),
            Some(&"121.0".to_string())
        );
    }

    #[test]
    fn test_parse_flatpak_output_empty() {
        let output = "";
        let packages = FlatpakUpdateChecker::parse_flatpak_output(output);
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_flatpak_output_with_empty_lines() {
        let output = "\ncom.visualstudio.code\t1.85.0\n\norg.mozilla.firefox\t121.0\n";

        let packages = FlatpakUpdateChecker::parse_flatpak_output(output);
        assert_eq!(packages.len(), 2);
    }

    #[test]
    fn test_flatpak_checker_creation() {
        let checker = FlatpakUpdateChecker::new();
        assert!(checker.is_ok());
    }

    #[test]
    fn test_generate_package_names() {
        let checker = FlatpakUpdateChecker::new().unwrap();
        let names = checker.generate_package_names("Visual Studio Code");

        // Flatpak uses simple names for matching
        assert_eq!(names.len(), 1);
        assert!(names.contains(&"visual studio code".to_string()));
    }

    #[test]
    fn test_name() {
        let checker = FlatpakUpdateChecker::new().unwrap();
        assert_eq!(checker.name(), "flatpak");
    }

    #[tokio::test]
    async fn test_is_security_update_always_false() {
        let checker = FlatpakUpdateChecker::new().unwrap();

        // Flatpak doesn't have security update classification
        assert!(!checker.is_security_update("com.visualstudio.code").await);
        assert!(!checker.is_security_update("any-package").await);
    }

    #[tokio::test]
    async fn test_check_update_by_registry_key() {
        let mut checker = FlatpakUpdateChecker::new().unwrap();

        // Manually set cache for testing
        let mut cache_data = HashMap::new();
        cache_data.insert("com.visualstudio.code".to_string(), "1.85.0".to_string());

        checker
            .cache
            .build_cache(|| Ok(cache_data))
            .await
            .unwrap();

        let app = Application {
            name: "Visual Studio Code".to_string(),
            version: Some("1.84.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "Flatpak".to_string(),
            can_update: false,
            install_location: None,
            size_mb: None,
            registry_key: Some("com.visualstudio.code".to_string()),
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        };

        let result = checker.check_update(&app).await.unwrap();
        assert!(result.is_some());

        let update = result.unwrap();
        assert_eq!(update.available_version, "1.85.0");
        assert_eq!(update.update_source, "Flathub");
    }

    #[tokio::test]
    async fn test_check_update_by_name_substring() {
        let mut checker = FlatpakUpdateChecker::new().unwrap();

        // Manually set cache for testing
        let mut cache_data = HashMap::new();
        cache_data.insert("org.mozilla.firefox".to_string(), "121.0".to_string());

        checker
            .cache
            .build_cache(|| Ok(cache_data))
            .await
            .unwrap();

        let app = Application {
            name: "Firefox".to_string(),
            version: Some("120.0".to_string()),
            vendor: None,
            install_date: None,
            install_type: "Flatpak".to_string(),
            can_update: false,
            install_location: None,
            size_mb: None,
            registry_key: None, // No registry key, should match by name
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        };

        let result = checker.check_update(&app).await.unwrap();
        assert!(result.is_some());

        let update = result.unwrap();
        assert_eq!(update.available_version, "121.0");
    }
}
