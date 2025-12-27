//! APT package manager implementation
//!
//! This module provides update checking for Debian/Ubuntu systems using APT.
//!
//! # Command Output Format
//!
//! The `apt list --upgradable` command outputs packages in this format:
//! ```text
//! Listing... (header)
//! vim/jammy-updates 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]
//! firefox/jammy-security 121.0+build1-0ubuntu0.22.04.1 amd64 [upgradable from: 120.0+build2-0ubuntu0.22.04.1]
//! ```
//!
//! Each line contains:
//! - Package name (before `/`)
//! - Repository (between `/` and first whitespace)
//! - Available version (first whitespace-separated token after repo)
//! - Architecture
//! - Current version info (in brackets)

use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::commands::application_inventory::Application;
use crate::commands::common::cache::AsyncCache;
use crate::commands::common::package_names::generate_debian_package_names;
use crate::commands::traits::PackageManager;
use crate::commands::update_checker::{UpdateCheckResult, UpdateInfo};

/// APT update checker for Debian/Ubuntu systems
///
/// Uses `apt list --upgradable` to detect available package updates
/// and caches the results for efficient lookups.
pub struct AptUpdateChecker {
    /// Cache of package_name -> available_version
    cache: AsyncCache<String, String>,
    /// List of packages with security updates
    security_packages: Vec<String>,
}

impl AptUpdateChecker {
    /// Create a new APT update checker
    ///
    /// # Returns
    ///
    /// A new `AptUpdateChecker` instance with an empty cache
    ///
    /// # Errors
    ///
    /// Returns an error if the checker cannot be created (currently infallible)
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: AsyncCache::new("apt-packages"),
            security_packages: Vec::new(),
        })
    }

    /// Parse the output of `apt list --upgradable`
    ///
    /// # Arguments
    ///
    /// * `output` - The stdout from the apt command
    ///
    /// # Returns
    ///
    /// A HashMap mapping package names to their available versions
    fn parse_apt_output(output: &str) -> HashMap<String, String> {
        let mut packages = HashMap::new();

        for line in output.lines() {
            // Skip header and empty lines
            if line.starts_with("Listing") || line.is_empty() {
                continue;
            }

            // Format: package/repo version arch [upgradable from: old_version]
            // Example: vim/jammy-updates 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]
            if let Some((package_part, rest)) = line.split_once('/') {
                let package_name = package_part.to_string();

                // Extract version: skip repo info, get first whitespace-separated token
                if let Some(version_start) = rest.find(char::is_whitespace) {
                    let after_repo = rest[version_start..].trim();
                    if let Some(version) = after_repo.split_whitespace().next() {
                        packages.insert(package_name, version.to_string());
                    }
                }
            }
        }

        packages
    }

    /// Build the package upgrade cache by running apt list --upgradable
    #[cfg(target_os = "linux")]
    fn build_upgrade_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        use crate::commands::common::shell::execute_command_allow_failure;

        debug!("Building APT upgrade cache");

        let stdout = match execute_command_allow_failure("apt", &["list", "--upgradable"]) {
            Some(output) => output,
            None => {
                debug!("apt list --upgradable failed, returning empty cache");
                return Ok(HashMap::new());
            }
        };

        let packages = Self::parse_apt_output(&stdout);

        debug!("Found {} upgradeable packages via apt", packages.len());
        Ok(packages)
    }

    #[cfg(not(target_os = "linux"))]
    fn build_upgrade_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        debug!("APT not available on non-Linux platforms");
        Ok(HashMap::new())
    }
}

#[async_trait]
impl PackageManager for AptUpdateChecker {
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing APT update checker");

        self.cache
            .build_cache(Self::build_upgrade_cache_blocking)
            .await?;

        Ok(())
    }

    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Try to match the application name to a package name
        let possible_names = self.generate_package_names(&app.name);

        for package_name in possible_names {
            if let Some(available_version) = self.cache.get(&package_name) {
                // Check if this is actually an update
                if let Some(ref current_version) = app.version {
                    if !crate::commands::update_checker::utils::is_version_newer(
                        current_version,
                        &available_version,
                    ) {
                        continue;
                    }
                }

                debug!(
                    "Found update for {}: {} -> {}",
                    app.name,
                    app.version.as_deref().unwrap_or("unknown"),
                    available_version
                );

                return Ok(Some(UpdateInfo {
                    current_version: app.version.clone(),
                    available_version,
                    update_size_bytes: self.get_package_size(&package_name).await,
                    update_source: "APT Repository".to_string(),
                    update_url: None,
                    is_security_update: self.is_security_update(&package_name).await,
                    release_notes: None,
                    last_checked: SystemTime::now(),
                }));
            }
        }

        Ok(None)
    }

    fn generate_package_names(&self, app_name: &str) -> Vec<String> {
        generate_debian_package_names(app_name)
    }

    fn name(&self) -> &'static str {
        "apt"
    }

    async fn get_package_size(&self, _package_name: &str) -> Option<u64> {
        // TODO: Use native APT library to get package information
        // For now, return None since we're transitioning away from command-line tools
        None
    }

    async fn is_security_update(&self, package_name: &str) -> bool {
        self.security_packages.contains(&package_name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apt_output() {
        let output = r#"Listing... Up to date
vim/jammy-updates 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]
firefox/jammy-security 121.0+build1-0ubuntu0.22.04.1 amd64 [upgradable from: 120.0]
curl/jammy-updates 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]
"#;

        let packages = AptUpdateChecker::parse_apt_output(output);

        assert_eq!(packages.len(), 3);
        assert_eq!(
            packages.get("vim"),
            Some(&"2:8.2.3995-1ubuntu2.17".to_string())
        );
        assert_eq!(
            packages.get("firefox"),
            Some(&"121.0+build1-0ubuntu0.22.04.1".to_string())
        );
        assert_eq!(
            packages.get("curl"),
            Some(&"7.81.0-1ubuntu1.16".to_string())
        );
    }

    #[test]
    fn test_parse_apt_output_empty() {
        let output = "Listing... Up to date\n";
        let packages = AptUpdateChecker::parse_apt_output(output);
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_apt_output_with_empty_lines() {
        let output = r#"Listing... Up to date

vim/jammy-updates 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: old]

firefox/jammy-security 121.0 amd64 [upgradable from: 120.0]
"#;

        let packages = AptUpdateChecker::parse_apt_output(output);
        assert_eq!(packages.len(), 2);
    }

    #[test]
    fn test_apt_checker_creation() {
        let checker = AptUpdateChecker::new();
        assert!(checker.is_ok());
    }

    #[test]
    fn test_generate_package_names() {
        let checker = AptUpdateChecker::new().unwrap();
        let names = checker.generate_package_names("Firefox Browser");

        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));
        assert!(names.contains(&"libfirefox-browser".to_string()));
    }

    #[test]
    fn test_name() {
        let checker = AptUpdateChecker::new().unwrap();
        assert_eq!(checker.name(), "apt");
    }

    #[tokio::test]
    async fn test_is_security_update() {
        let mut checker = AptUpdateChecker::new().unwrap();
        checker.security_packages = vec!["vim".to_string()];

        assert!(checker.is_security_update("vim").await);
        assert!(!checker.is_security_update("curl").await);
    }
}
