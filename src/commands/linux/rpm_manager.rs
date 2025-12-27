//! RPM package manager implementation
//!
//! This module provides update checking for Red Hat/Fedora/CentOS systems
//! using dnf (preferred) or yum (fallback).
//!
//! # Command Output Format
//!
//! The `dnf check-update -q` command outputs packages in this format:
//! ```text
//! vim-enhanced.x86_64                   2:8.2.4975-1.fc38              updates
//! firefox.x86_64                        121.0-1.fc38                   updates
//! ```
//!
//! Each line contains:
//! - Package name with architecture (e.g., `vim-enhanced.x86_64`)
//! - Available version
//! - Repository name
//!
//! # Exit Codes
//!
//! - Exit code 0: No updates available
//! - Exit code 100: Updates are available (this is treated as success)
//! - Other exit codes: Error

use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::commands::application_inventory::Application;
use crate::commands::common::cache::AsyncCache;
use crate::commands::common::package_names::generate_rpm_package_names;
use crate::commands::traits::PackageManager;
use crate::commands::update_checker::{UpdateCheckError, UpdateCheckResult, UpdateInfo};

/// RPM update checker for Red Hat/Fedora/CentOS systems
///
/// Uses `dnf check-update` (or `yum check-update` as fallback) to detect
/// available package updates and caches the results for efficient lookups.
pub struct RpmUpdateChecker {
    /// Cache of package_name -> available_version
    cache: AsyncCache<String, String>,
    /// List of packages with security updates
    security_packages: Vec<String>,
}

impl RpmUpdateChecker {
    /// Create a new RPM update checker
    ///
    /// # Returns
    ///
    /// A new `RpmUpdateChecker` instance with an empty cache
    ///
    /// # Errors
    ///
    /// Returns an error if the checker cannot be created (currently infallible)
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: AsyncCache::new("rpm-packages"),
            security_packages: Vec::new(),
        })
    }

    /// Parse the output of `dnf check-update` or `yum check-update`
    ///
    /// # Arguments
    ///
    /// * `output` - The stdout from the dnf/yum command
    ///
    /// # Returns
    ///
    /// A HashMap mapping package names to their available versions
    fn parse_rpm_output(output: &str) -> HashMap<String, String> {
        let mut packages = HashMap::new();
        let mut in_obsoleting_section = false;

        for line in output.lines() {
            // Skip empty lines
            if line.is_empty() {
                continue;
            }

            // Check for section headers
            if line.starts_with("Obsoleting") {
                // Stop parsing when we hit the obsoleting section
                // All packages after this are obsoleted, not available updates
                in_obsoleting_section = true;
                continue;
            }

            // Skip if we're in the obsoleting section
            if in_obsoleting_section {
                continue;
            }

            // Skip metadata lines
            if line.starts_with("Last metadata") || !line.contains('.') {
                continue;
            }

            // Format: package_name.arch   version   repository
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let package_arch = parts[0];
                let available_version = parts[1].to_string();

                // Split package name and architecture (e.g., "vim-enhanced.x86_64" -> "vim-enhanced")
                let package_name = if let Some(pos) = package_arch.rfind('.') {
                    package_arch[..pos].to_string()
                } else {
                    package_arch.to_string()
                };

                packages.insert(package_name, available_version);
            }
        }

        packages
    }

    /// Extract package name from NEVRA format (Name-Epoch:Version-Release.Arch)
    ///
    /// # Arguments
    ///
    /// * `nevra` - The full NEVRA string
    ///
    /// # Returns
    ///
    /// The package name extracted from the NEVRA, or None if parsing fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let name = extract_rpm_package_name("vim-enhanced-2:8.2.4975-1.fc38.x86_64");
    /// assert_eq!(name, Some("vim-enhanced".to_string()));
    /// ```
    fn extract_rpm_package_name(nevra: &str) -> Option<String> {
        if nevra.is_empty() {
            return None;
        }

        let parts: Vec<&str> = nevra.split('-').collect();
        let mut name_parts = Vec::new();

        for part in parts.iter() {
            // Skip empty parts
            if part.is_empty() {
                continue;
            }
            // If this part starts with a digit or contains ':', it's likely the version
            if part
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                || part.contains(':')
            {
                break;
            }
            name_parts.push(*part);
        }

        if name_parts.is_empty() {
            None
        } else {
            Some(name_parts.join("-"))
        }
    }

    /// Build the package upgrade cache by running dnf/yum check-update
    #[cfg(target_os = "linux")]
    fn build_upgrade_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        use crate::commands::common::shell::execute_command;

        debug!("Building RPM upgrade cache");

        // Try dnf first, fall back to yum
        // execute_command already handles dnf/yum exit code 100
        let stdout = match execute_command("dnf", &["check-update", "-q"]) {
            Ok(output) => output,
            Err(_) => {
                // Fall back to yum
                match execute_command("yum", &["check-update", "-q"]) {
                    Ok(output) => output,
                    Err(e) => {
                        debug!("Failed to run dnf/yum: {}", e);
                        return Ok(HashMap::new());
                    }
                }
            }
        };

        let packages = Self::parse_rpm_output(&stdout);

        debug!("Found {} upgradeable packages via dnf/yum", packages.len());
        Ok(packages)
    }

    #[cfg(not(target_os = "linux"))]
    fn build_upgrade_cache_blocking() -> UpdateCheckResult<HashMap<String, String>> {
        debug!("RPM not available on non-Linux platforms");
        Ok(HashMap::new())
    }

    /// Get the list of security packages
    #[cfg(target_os = "linux")]
    async fn fetch_security_packages(&self) -> UpdateCheckResult<Vec<String>> {
        use crate::commands::common::shell::execute_command_allow_failure;

        tokio::task::spawn_blocking(move || -> UpdateCheckResult<Vec<String>> {
            let mut security_packages = Vec::new();

            // Try to get security updates
            if let Some(stdout) =
                execute_command_allow_failure("dnf", &["updateinfo", "list", "security", "-q"])
            {
                for line in stdout.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    // Extract package name from security advisory line
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let package_full = parts[2];
                        // Extract package name (before version)
                        if let Some(name) = Self::extract_rpm_package_name(package_full) {
                            security_packages.push(name);
                        }
                    }
                }
            }

            Ok(security_packages)
        })
        .await
        .map_err(|e| {
            UpdateCheckError::PlatformError(format!("Failed to get security packages: {}", e))
        })?
    }

    #[cfg(not(target_os = "linux"))]
    async fn fetch_security_packages(&self) -> UpdateCheckResult<Vec<String>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl PackageManager for RpmUpdateChecker {
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing RPM update checker");

        self.cache
            .build_cache(Self::build_upgrade_cache_blocking)
            .await?;

        // Also check for security updates
        self.security_packages = self.fetch_security_packages().await?;

        Ok(())
    }

    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
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

                let is_security = self
                    .security_packages
                    .iter()
                    .any(|sp| sp == &package_name);

                debug!(
                    "Found update for {}: {} -> {}",
                    app.name,
                    app.version.as_deref().unwrap_or("unknown"),
                    available_version
                );

                return Ok(Some(UpdateInfo {
                    current_version: app.version.clone(),
                    available_version,
                    update_size_bytes: None,
                    update_source: "RPM Repository".to_string(),
                    update_url: None,
                    is_security_update: is_security,
                    release_notes: None,
                    last_checked: SystemTime::now(),
                }));
            }
        }

        Ok(None)
    }

    fn generate_package_names(&self, app_name: &str) -> Vec<String> {
        generate_rpm_package_names(app_name)
    }

    fn name(&self) -> &'static str {
        "rpm"
    }

    async fn is_security_update(&self, package_name: &str) -> bool {
        self.security_packages.contains(&package_name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rpm_output() {
        let output = r#"Last metadata expiration check: 0:30:15 ago on Sat Dec 14 10:00:00 2024.

vim-enhanced.x86_64                   2:8.2.4975-1.fc38              updates
firefox.x86_64                        121.0-1.fc38                   updates
curl.x86_64                           7.81.0-1.fc38                  updates
"#;

        let packages = RpmUpdateChecker::parse_rpm_output(output);

        assert_eq!(packages.len(), 3);
        assert_eq!(
            packages.get("vim-enhanced"),
            Some(&"2:8.2.4975-1.fc38".to_string())
        );
        assert_eq!(packages.get("firefox"), Some(&"121.0-1.fc38".to_string()));
        assert_eq!(packages.get("curl"), Some(&"7.81.0-1.fc38".to_string()));
    }

    #[test]
    fn test_parse_rpm_output_empty() {
        let output = "Last metadata expiration check: 0:30:15 ago.\n";
        let packages = RpmUpdateChecker::parse_rpm_output(output);
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_rpm_output_with_obsoleting() {
        let output = r#"
vim-enhanced.x86_64                   2:8.2.4975-1.fc38              updates
Obsoleting Packages
old-package.x86_64                    1.0-1.fc38                     updates
"#;

        let packages = RpmUpdateChecker::parse_rpm_output(output);
        // Should only get vim-enhanced, skip obsoleting section
        assert_eq!(packages.len(), 1);
        assert!(packages.contains_key("vim-enhanced"));
    }

    #[test]
    fn test_extract_rpm_package_name() {
        assert_eq!(
            RpmUpdateChecker::extract_rpm_package_name("vim-enhanced-2:8.2.4975-1.fc38.x86_64"),
            Some("vim-enhanced".to_string())
        );
        assert_eq!(
            RpmUpdateChecker::extract_rpm_package_name("firefox-121.0-1.fc38.x86_64"),
            Some("firefox".to_string())
        );
        assert_eq!(
            RpmUpdateChecker::extract_rpm_package_name("python3-pip-21.3.1-1.fc38.noarch"),
            Some("python3-pip".to_string())
        );
    }

    #[test]
    fn test_extract_rpm_package_name_edge_cases() {
        // Empty string
        assert_eq!(RpmUpdateChecker::extract_rpm_package_name(""), None);

        // Just a version number
        assert_eq!(RpmUpdateChecker::extract_rpm_package_name("1.0.0"), None);

        // Single component name
        assert_eq!(
            RpmUpdateChecker::extract_rpm_package_name("curl"),
            Some("curl".to_string())
        );
    }

    #[test]
    fn test_rpm_checker_creation() {
        let checker = RpmUpdateChecker::new();
        assert!(checker.is_ok());
    }

    #[test]
    fn test_generate_package_names() {
        let checker = RpmUpdateChecker::new().unwrap();
        let names = checker.generate_package_names("Firefox Browser");

        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));
        // RPM doesn't add lib prefix
        assert!(!names.contains(&"libfirefox-browser".to_string()));
    }

    #[test]
    fn test_name() {
        let checker = RpmUpdateChecker::new().unwrap();
        assert_eq!(checker.name(), "rpm");
    }

    #[tokio::test]
    async fn test_is_security_update() {
        let mut checker = RpmUpdateChecker::new().unwrap();
        checker.security_packages = vec!["vim-enhanced".to_string()];

        assert!(checker.is_security_update("vim-enhanced").await);
        assert!(!checker.is_security_update("curl").await);
    }
}
