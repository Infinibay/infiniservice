//! Registry-based update checker for known Windows applications
//!
//! This module provides update checking for known applications by querying
//! the Windows Registry for version information and update URLs.
//!
//! # Supported Applications
//!
//! | Application | Registry Path | Notes |
//! |-------------|---------------|-------|
//! | Google Chrome | HKCU\Software\Google\Chrome\BLBeacon | Auto-updates |
//! | Mozilla Firefox | HKLM\SOFTWARE\Mozilla\Mozilla Firefox | Auto-updates |
//! | Microsoft Edge | MSIX package query | Windows Update |
//! | Java | java -version | Manual check |
//! | Adobe Reader | HKLM\SOFTWARE\Adobe\Acrobat Reader | Adobe Updater |

use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::commands::application_inventory::Application;
use crate::commands::common::package_names::generate_windows_package_names;
use crate::commands::traits::PackageManager;
use crate::commands::update_checker::{UpdateCheckResult, UpdateInfo};

/// Information about a known application's registry configuration
#[derive(Debug, Clone)]
struct KnownAppInfo {
    /// Display name for update source
    update_source: &'static str,
    /// Optional URL for manual updates
    update_url: Option<&'static str>,
    /// Whether updates are security-related
    is_security_update: bool,
    /// Release notes template
    release_notes: &'static str,
}

/// Registry-based update checker for known Windows applications
///
/// This manager doesn't use AsyncCache because registry queries are
/// synchronous and fast. Instead, it uses a static HashMap of known
/// applications with their registry paths and update information.
pub struct RegistryManager {
    /// Known applications with their update configuration
    known_apps: HashMap<String, KnownAppInfo>,
}

impl RegistryManager {
    /// Create a new Registry update manager
    ///
    /// # Returns
    ///
    /// A new `RegistryManager` instance with known app configurations
    pub fn new() -> Self {
        let mut known_apps = HashMap::new();

        // Chrome
        known_apps.insert(
            "chrome".to_string(),
            KnownAppInfo {
                update_source: "Google Chrome Auto-Update",
                update_url: Some("chrome://settings/help"),
                is_security_update: false,
                release_notes: "Chrome updates automatically. Visit chrome://settings/help to check for updates.",
            },
        );
        known_apps.insert(
            "google chrome".to_string(),
            KnownAppInfo {
                update_source: "Google Chrome Auto-Update",
                update_url: Some("chrome://settings/help"),
                is_security_update: false,
                release_notes: "Chrome updates automatically. Visit chrome://settings/help to check for updates.",
            },
        );

        // Firefox
        known_apps.insert(
            "firefox".to_string(),
            KnownAppInfo {
                update_source: "Mozilla Firefox Auto-Update",
                update_url: Some("about:preferences#general"),
                is_security_update: false,
                release_notes: "Firefox updates automatically. Check Help > About Firefox for updates.",
            },
        );
        known_apps.insert(
            "mozilla firefox".to_string(),
            KnownAppInfo {
                update_source: "Mozilla Firefox Auto-Update",
                update_url: Some("about:preferences#general"),
                is_security_update: false,
                release_notes: "Firefox updates automatically. Check Help > About Firefox for updates.",
            },
        );

        // Edge
        known_apps.insert(
            "edge".to_string(),
            KnownAppInfo {
                update_source: "Windows Update",
                update_url: None,
                is_security_update: false,
                release_notes: "Microsoft Edge is updated automatically through Windows Update.",
            },
        );
        known_apps.insert(
            "microsoft edge".to_string(),
            KnownAppInfo {
                update_source: "Windows Update",
                update_url: None,
                is_security_update: false,
                release_notes: "Microsoft Edge is updated automatically through Windows Update.",
            },
        );

        // Java
        known_apps.insert(
            "java".to_string(),
            KnownAppInfo {
                update_source: "Oracle Java Update Scheduler",
                update_url: Some("https://www.java.com/en/download/"),
                is_security_update: true, // Java updates are often security-related
                release_notes: "Java updates should be checked regularly for security patches.",
            },
        );

        // Adobe Reader
        known_apps.insert(
            "adobe reader".to_string(),
            KnownAppInfo {
                update_source: "Adobe Updater",
                update_url: Some("https://get.adobe.com/reader/"),
                is_security_update: true, // Adobe updates are often security-related
                release_notes: "Adobe Reader updates should be checked regularly for security patches.",
            },
        );
        known_apps.insert(
            "acrobat reader".to_string(),
            KnownAppInfo {
                update_source: "Adobe Updater",
                update_url: Some("https://get.adobe.com/reader/"),
                is_security_update: true,
                release_notes: "Adobe Reader updates should be checked regularly for security patches.",
            },
        );

        Self { known_apps }
    }

    /// Check if we have configuration for a known app
    fn get_known_app_info(&self, app_name: &str) -> Option<&KnownAppInfo> {
        let app_name_lower = app_name.to_lowercase();

        // Try direct lookup first
        if let Some(info) = self.known_apps.get(&app_name_lower) {
            return Some(info);
        }

        // Try partial matching
        for (key, info) in &self.known_apps {
            if app_name_lower.contains(key) || key.contains(&app_name_lower) {
                return Some(info);
            }
        }

        None
    }

    /// Check Chrome version via registry
    #[cfg(target_os = "windows")]
    async fn check_chrome_version() -> Option<String> {
        let output = tokio::process::Command::new("reg")
            .args([
                "query",
                "HKEY_CURRENT_USER\\Software\\Google\\Chrome\\BLBeacon",
                "/v",
                "version",
            ])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("version") {
                    if let Some(version) = line.split_whitespace().last() {
                        debug!("Found Chrome version: {}", version);
                        return Some(version.to_string());
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    async fn check_chrome_version() -> Option<String> {
        None
    }

    /// Check Firefox version via registry
    #[cfg(target_os = "windows")]
    async fn check_firefox_version() -> Option<String> {
        let output = tokio::process::Command::new("reg")
            .args([
                "query",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Mozilla\\Mozilla Firefox",
                "/s",
            ])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("CurrentVersion") {
                    if let Some(version) = line.split_whitespace().last() {
                        debug!("Found Firefox version: {}", version);
                        return Some(version.to_string());
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    async fn check_firefox_version() -> Option<String> {
        None
    }

    /// Check Edge version via PowerShell
    #[cfg(target_os = "windows")]
    async fn check_edge_version() -> Option<String> {
        let output = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-AppxPackage -Name Microsoft.MicrosoftEdge.Stable).Version",
            ])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !version.is_empty() {
                debug!("Found Edge version: {}", version);
                return Some(version);
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    async fn check_edge_version() -> Option<String> {
        None
    }

    /// Check Java version
    #[cfg(target_os = "windows")]
    async fn check_java_version() -> Option<String> {
        let output = tokio::process::Command::new("java")
            .args(["-version"])
            .output()
            .await
            .ok()?;

        if output.status.success() {
            // Java version is typically in stderr
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stderr.lines() {
                if line.contains("java version") || line.contains("openjdk version") {
                    // Extract version number between quotes
                    if let Some(start) = line.find('"') {
                        if let Some(end) = line[start + 1..].find('"') {
                            let version = &line[start + 1..start + 1 + end];
                            debug!("Found Java version: {}", version);
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    async fn check_java_version() -> Option<String> {
        None
    }

    /// Get the current version of a known application
    async fn get_app_version(&self, app_name: &str) -> Option<String> {
        let app_name_lower = app_name.to_lowercase();

        if app_name_lower.contains("chrome") {
            return Self::check_chrome_version().await;
        }
        if app_name_lower.contains("firefox") {
            return Self::check_firefox_version().await;
        }
        if app_name_lower.contains("edge") {
            return Self::check_edge_version().await;
        }
        if app_name_lower.contains("java") {
            return Self::check_java_version().await;
        }

        None
    }
}

impl Default for RegistryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackageManager for RegistryManager {
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!(
            "Initializing Registry manager with {} known apps",
            self.known_apps.len()
        );
        // No initialization needed - registry queries are done on-demand
        Ok(())
    }

    async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Check if this is a known app
        let known_app = match self.get_known_app_info(&app.name) {
            Some(info) => info,
            None => {
                debug!("App {} not recognized by Registry manager", app.name);
                return Ok(None);
            }
        };

        debug!("Checking registry-based update for: {}", app.name);

        // Try to get the current version from registry
        let current_version = self.get_app_version(&app.name).await;

        // If we found a version, return update info
        // (for known apps, we indicate they have their own update mechanisms)
        if current_version.is_some() || app.version.is_some() {
            return Ok(Some(UpdateInfo {
                current_version: current_version.or_else(|| app.version.clone()),
                available_version: "Check application for updates".to_string(),
                update_size_bytes: None,
                update_source: known_app.update_source.to_string(),
                update_url: known_app.update_url.map(|s| s.to_string()),
                is_security_update: known_app.is_security_update,
                release_notes: Some(known_app.release_notes.to_string()),
                last_checked: SystemTime::now(),
            }));
        }

        Ok(None)
    }

    fn generate_package_names(&self, app_name: &str) -> Vec<String> {
        generate_windows_package_names(app_name)
    }

    fn name(&self) -> &'static str {
        "registry"
    }

    fn can_handle(&self, app: &Application) -> bool {
        // Only handle if we recognize the app
        self.get_known_app_info(&app.name).is_some()
    }

    async fn get_package_size(&self, _package_name: &str) -> Option<u64> {
        // Registry queries don't provide package size
        None
    }

    async fn is_security_update(&self, package_name: &str) -> bool {
        self.get_known_app_info(package_name)
            .map(|info| info.is_security_update)
            .unwrap_or(false)
    }
}

/// Windows-specific utilities for registry reading
#[cfg(target_os = "windows")]
mod windows_utils {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::*;

    /// Read update URL from registry for a given application
    pub unsafe fn read_update_url_from_registry(app_name: &str) -> Option<String> {
        // Common registry paths where update URLs might be stored
        let registry_paths = [
            format!("SOFTWARE\\{}", app_name),
            format!(
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}",
                app_name
            ),
        ];

        for path in &registry_paths {
            if let Some(url) = read_registry_string_value(path, "UpdateURL")
                .or_else(|| read_registry_string_value(path, "URLUpdateInfo"))
                .or_else(|| read_registry_string_value(path, "HelpLink"))
            {
                return Some(url);
            }
        }

        None
    }

    /// Read a string value from the Windows registry
    unsafe fn read_registry_string_value(key_path: &str, value_name: &str) -> Option<String> {
        let mut key_handle = HKEY::default();

        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            &HSTRING::from(key_path),
            0,
            KEY_READ,
            &mut key_handle,
        );

        if result != ERROR_SUCCESS {
            return None;
        }

        let mut buffer = [0u16; 512];
        let mut buffer_size = (buffer.len() * 2) as u32;
        let mut reg_type = REG_VALUE_TYPE(0);

        let result = RegQueryValueExW(
            key_handle,
            &HSTRING::from(value_name),
            None,
            Some(&mut reg_type),
            Some(buffer.as_mut_ptr() as *mut u8),
            Some(&mut buffer_size),
        );

        let _ = RegCloseKey(key_handle);

        if result == ERROR_SUCCESS && reg_type == REG_SZ {
            let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
            Some(String::from_utf16_lossy(&buffer[..len]))
        } else {
            None
        }
    }

    /// Get file version information from an executable
    pub fn get_file_version(_file_path: &str) -> Option<String> {
        // This would use Windows API to read version information from PE files
        // For now, return None
        None
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_utils {
    /// Stub implementations for non-Windows platforms
    pub unsafe fn read_update_url_from_registry(_app_name: &str) -> Option<String> {
        None
    }

    pub fn get_file_version(_file_path: &str) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_manager_creation() {
        let manager = RegistryManager::new();
        assert!(!manager.known_apps.is_empty());
    }

    #[test]
    fn test_get_known_app_info_direct() {
        let manager = RegistryManager::new();

        // Direct match
        let chrome_info = manager.get_known_app_info("chrome");
        assert!(chrome_info.is_some());
        assert_eq!(chrome_info.unwrap().update_source, "Google Chrome Auto-Update");
    }

    #[test]
    fn test_get_known_app_info_partial() {
        let manager = RegistryManager::new();

        // Partial match
        let chrome_info = manager.get_known_app_info("Google Chrome Browser");
        assert!(chrome_info.is_some());
    }

    #[test]
    fn test_get_known_app_info_unknown() {
        let manager = RegistryManager::new();

        // Unknown app
        let unknown_info = manager.get_known_app_info("Random Unknown App");
        assert!(unknown_info.is_none());
    }

    #[test]
    fn test_generate_package_names() {
        let manager = RegistryManager::new();
        let names = manager.generate_package_names("Google Chrome");

        assert!(names.contains(&"google chrome".to_string()));
        assert!(names.contains(&"chrome".to_string()));
    }

    #[test]
    fn test_name() {
        let manager = RegistryManager::new();
        assert_eq!(manager.name(), "registry");
    }

    #[test]
    fn test_can_handle() {
        let manager = RegistryManager::new();

        let chrome_app = Application {
            name: "Google Chrome".to_string(),
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
        assert!(manager.can_handle(&chrome_app));

        let unknown_app = Application {
            name: "Random Unknown App".to_string(),
            version: Some("1.0".to_string()),
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
        assert!(!manager.can_handle(&unknown_app));
    }

    #[tokio::test]
    async fn test_is_security_update() {
        let manager = RegistryManager::new();

        // Java should be marked as security update
        assert!(manager.is_security_update("java").await);

        // Chrome should not be marked as security update
        assert!(!manager.is_security_update("chrome").await);

        // Unknown app should not be marked as security update
        assert!(!manager.is_security_update("unknown").await);
    }

    #[test]
    fn test_default_impl() {
        let manager = RegistryManager::default();
        assert!(!manager.known_apps.is_empty());
    }
}
