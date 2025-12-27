//! Snap package manager implementation
//!
//! This module provides update checking for Snap packages using the `snap` command.
//!
//! # Command Output Format
//!
//! The `snap refresh --list` command outputs packages in this format:
//! ```text
//! Name      Version  Rev  Publisher  Notes
//! firefox   121.0    123  mozilla    -
//! vlc       3.0.18   456  videolan   -
//! ```
//!
//! Each line (after header) contains:
//! - Name: Snap package name
//! - Version: Available version
//! - Rev: Snap revision number
//! - Publisher: Package publisher
//! - Notes: Additional info
//!
//! # Notes
//!
//! - Snap uses simple lowercase package names
//! - Snap doesn't have a concept of security-specific updates

use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::commands::application_inventory::Application;
use crate::commands::common::cache::AsyncCache;
use crate::commands::common::package_names::generate_snap_package_names;
use crate::commands::traits::PackageManager;
use crate::commands::update_checker::{UpdateCheckResult, UpdateInfo};

/// Snap update checker
///
/// Uses `snap refresh --list` to detect available snap updates
/// and caches the results for efficient lookups.
pub struct SnapUpdateChecker {
    /// Cache of snap_name -> available_version
    cache: AsyncCache<String, String>,
}

impl SnapUpdateChecker {
    /// Create a new Snap update checker
    ///
    /// # Returns
    ///
    /// A new `SnapUpdateChecker` instance with an empty cache
    ///
    /// # Errors
    ///
    /// Returns an error if the checker cannot be created (currently infallible)
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: AsyncCache::new("snap-packages"),
        })
    }

    /// Parse the output of `snap refresh --list`
    ///
    /// # Arguments
    ///
    /// * `output` - The stdout from the snap command
    ///
    /// # Returns
    ///
    /// A HashMap mapping snap names to their available versions
    fn parse_snap_output(output: &str) -> HashMap<String, String> {
        let mut packages = HashMap::new();
        let mut is_header = true;

        for line in output.lines() {
            if line.is_empty() {
                continue;
            }

            // Skip header line
            if is_header {
                is_header = false;
                continue;
            }

            // Format: Name  Version  Rev  Publisher  Notes
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let version = parts[1].to_string();
                packages.insert(name, version);
            }
        }

        packages
    }

    /// Build the snap refresh cache by running snap refresh --list
    #[cfg(target_os = "linux")]
    fn build_refresh_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        use crate::commands::common::shell::execute_command_allow_failure;

        debug!("Building Snap refresh cache");

        let stdout = match execute_command_allow_failure("snap", &["refresh", "--list"]) {
            Some(output) => output,
            None => {
                debug!("snap refresh --list failed, returning empty cache");
                return Ok(HashMap::new());
            }
        };

        let packages = Self::parse_snap_output(&stdout);

        debug!("Found {} snaps with pending updates", packages.len());
        Ok(packages)
    }

    #[cfg(not(target_os = "linux"))]
    fn build_refresh_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        debug!("Snap not available on non-Linux platforms");
        Ok(HashMap::new())
    }
}

#[async_trait]
impl PackageManager for SnapUpdateChecker {
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Snap update checker");

        self.cache
            .build_cache(Self::build_refresh_cache_blocking)
            .await?;

        Ok(())
    }

    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Try multiple name variations to improve matching
        let possible_names = self.generate_package_names(&app.name);

        for snap_name in possible_names {
            if let Some(available_version) = self.cache.get(&snap_name) {
                debug!(
                    "Found snap update for {} (matched as {}): {} -> {}",
                    app.name,
                    snap_name,
                    app.version.as_deref().unwrap_or("unknown"),
                    available_version
                );

                return Ok(Some(UpdateInfo {
                    current_version: app.version.clone(),
                    available_version,
                    update_size_bytes: None,
                    update_source: "Snap Store".to_string(),
                    update_url: None,
                    is_security_update: false, // Snap doesn't have security update classification
                    release_notes: None,
                    last_checked: SystemTime::now(),
                }));
            }
        }

        Ok(None)
    }

    fn generate_package_names(&self, app_name: &str) -> Vec<String> {
        generate_snap_package_names(app_name)
    }

    fn name(&self) -> &'static str {
        "snap"
    }

    // Snap doesn't have security update classification
    async fn is_security_update(&self, _package_name: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_snap_output() {
        let output = r#"Name      Version  Rev  Publisher  Notes
firefox   121.0    123  mozilla    -
vlc       3.0.18   456  videolan   -
code      1.85.0   789  microsoft  classic
"#;

        let packages = SnapUpdateChecker::parse_snap_output(output);

        assert_eq!(packages.len(), 3);
        assert_eq!(packages.get("firefox"), Some(&"121.0".to_string()));
        assert_eq!(packages.get("vlc"), Some(&"3.0.18".to_string()));
        assert_eq!(packages.get("code"), Some(&"1.85.0".to_string()));
    }

    #[test]
    fn test_parse_snap_output_empty() {
        let output = "Name      Version  Rev  Publisher  Notes\n";
        let packages = SnapUpdateChecker::parse_snap_output(output);
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_snap_output_with_empty_lines() {
        let output = r#"Name      Version  Rev  Publisher  Notes

firefox   121.0    123  mozilla    -

vlc       3.0.18   456  videolan   -
"#;

        let packages = SnapUpdateChecker::parse_snap_output(output);
        assert_eq!(packages.len(), 2);
    }

    #[test]
    fn test_snap_checker_creation() {
        let checker = SnapUpdateChecker::new();
        assert!(checker.is_ok());
    }

    #[test]
    fn test_generate_package_names() {
        let checker = SnapUpdateChecker::new().unwrap();
        let names = checker.generate_package_names("Firefox Browser");

        // Snap uses multiple variations for better matching
        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));
        assert!(names.contains(&"firefox".to_string())); // First word only
    }

    #[test]
    fn test_name() {
        let checker = SnapUpdateChecker::new().unwrap();
        assert_eq!(checker.name(), "snap");
    }

    #[tokio::test]
    async fn test_is_security_update_always_false() {
        let checker = SnapUpdateChecker::new().unwrap();

        // Snap doesn't have security update classification
        assert!(!checker.is_security_update("firefox").await);
        assert!(!checker.is_security_update("any-package").await);
    }
}
