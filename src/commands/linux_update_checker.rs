//! Linux-specific application update checking
//!
//! This module provides update checking for Linux applications using:
//! - APT for Debian/Ubuntu systems
//! - RPM/YUM/DNF for Red Hat/Fedora/CentOS systems  
//! - Pacman for Arch Linux systems
//! - Snap and Flatpak for universal packages

use anyhow::Result;
use async_trait::async_trait;
use log::{debug, warn};
use std::time::SystemTime;
use std::collections::HashMap;

use super::update_checker::{UpdateChecker, UpdateCheckConfig, UpdateInfo, UpdateCheckError, UpdateCheckResult};
use super::application_inventory::Application;
use crate::os_detection::{get_os_info, PackageManager};

/// Linux-specific update checker
pub struct LinuxUpdateChecker {
    apt_checker: Option<AptUpdateChecker>,
    rpm_checker: Option<RpmUpdateChecker>,
    snap_checker: Option<SnapUpdateChecker>,
    flatpak_checker: Option<FlatpakUpdateChecker>,
}

impl LinuxUpdateChecker {
    /// Create a new Linux update checker
    pub fn new() -> Result<Self> {
        let os_info = get_os_info();
        
        let apt_checker = if os_info.available_package_managers.contains(&PackageManager::Apt) {
            AptUpdateChecker::new().ok()
        } else {
            None
        };
        
        let rpm_checker = if os_info.available_package_managers.iter()
            .any(|pm| matches!(pm, PackageManager::Yum | PackageManager::Dnf)) {
            RpmUpdateChecker::new().ok()
        } else {
            None
        };
        
        let snap_checker = if os_info.available_package_managers.contains(&PackageManager::Snap) {
            SnapUpdateChecker::new().ok()
        } else {
            None
        };
        
        let flatpak_checker = if os_info.available_package_managers.contains(&PackageManager::Flatpak) {
            FlatpakUpdateChecker::new().ok()
        } else {
            None
        };
        
        Ok(Self {
            apt_checker,
            rpm_checker,
            snap_checker,
            flatpak_checker,
        })
    }
}

#[async_trait]
impl UpdateChecker for LinuxUpdateChecker {
    async fn check_app_update(
        &mut self,
        app: &Application,
        config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!("Checking updates for Linux app: {} ({})", app.name, app.install_type);
        
        // Try each available checker based on install type and package name patterns
        if let Some(ref checker) = self.apt_checker {
            if let Ok(Some(info)) = checker.check_package_update(app, config).await {
                return Ok(Some(info));
            }
        }
        
        if let Some(ref checker) = self.rpm_checker {
            if let Ok(Some(info)) = checker.check_package_update(app, config).await {
                return Ok(Some(info));
            }
        }
        
        if let Some(ref checker) = self.snap_checker {
            if let Ok(Some(info)) = checker.check_snap_update(app, config).await {
                return Ok(Some(info));
            }
        }
        
        if let Some(ref checker) = self.flatpak_checker {
            if let Ok(Some(info)) = checker.check_flatpak_update(app, config).await {
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
        
        if let Some(ref mut checker) = self.apt_checker {
            if let Err(e) = checker.initialize().await {
                warn!("Failed to initialize APT checker: {}", e);
                self.apt_checker = None;
            }
        }
        
        if let Some(ref mut checker) = self.rpm_checker {
            if let Err(e) = checker.initialize().await {
                warn!("Failed to initialize RPM checker: {}", e);
                self.rpm_checker = None;
            }
        }
        
        if let Some(ref mut checker) = self.snap_checker {
            if let Err(e) = checker.initialize().await {
                warn!("Failed to initialize Snap checker: {}", e);
                self.snap_checker = None;
            }
        }
        
        if let Some(ref mut checker) = self.flatpak_checker {
            if let Err(e) = checker.initialize().await {
                warn!("Failed to initialize Flatpak checker: {}", e);
                self.flatpak_checker = None;
            }
        }
        
        Ok(())
    }
}

/// APT update checker for Debian/Ubuntu systems
struct AptUpdateChecker {
    cache: Option<HashMap<String, String>>, // package_name -> available_version
    security_packages: Vec<String>,         // packages with security updates
}

impl AptUpdateChecker {
    fn new() -> Result<Self> {
        Ok(Self {
            cache: None,
            security_packages: Vec::new(),
        })
    }

    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing APT update checker");

        // Build cache of upgradeable packages using apt list --upgradable
        self.cache = Some(self.build_upgrade_cache().await?);

        Ok(())
    }

    async fn build_upgrade_cache(&mut self) -> UpdateCheckResult<HashMap<String, String>> {
        debug!("Building APT upgrade cache");

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            let cache = tokio::task::spawn_blocking(move || -> UpdateCheckResult<HashMap<String, String>> {
                let mut packages = HashMap::new();

                // Run apt list --upgradable to get available updates
                let output = Command::new("apt")
                    .args(["list", "--upgradable"])
                    .output()
                    .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to run apt list: {}", e)))?;

                if !output.status.success() {
                    debug!("apt list --upgradable failed, returning empty cache");
                    return Ok(packages);
                }

                let stdout = String::from_utf8_lossy(&output.stdout);

                for line in stdout.lines() {
                    // Skip header and empty lines
                    if line.starts_with("Listing") || line.is_empty() {
                        continue;
                    }

                    // Format: package/repo version arch [upgradable from: old_version]
                    // Example: vim/jammy-updates 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]
                    if let Some((package_part, rest)) = line.split_once('/') {
                        let package_name = package_part.to_string();
                        let parts: Vec<&str> = rest.split_whitespace().collect();

                        if parts.len() >= 2 {
                            // parts[0] contains repo info, parts[1] contains version
                            // Need to extract version from the line more carefully
                            // The version is the first whitespace-separated item after the slash
                            if let Some(version_start) = rest.find(char::is_whitespace) {
                                let after_repo = rest[version_start..].trim();
                                if let Some(version) = after_repo.split_whitespace().next() {
                                    packages.insert(package_name, version.to_string());
                                }
                            }
                        }
                    }
                }

                debug!("Found {} upgradeable packages via apt", packages.len());
                Ok(packages)
            }).await
            .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to spawn APT cache building task: {}", e)))?
            .map_err(|e| e)?;

            return Ok(cache);
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!("APT not available on non-Linux platforms");
            Ok(HashMap::new())
        }
    }
    
    async fn check_package_update(
        &self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        let cache = match &self.cache {
            Some(cache) => cache,
            None => return Ok(None),
        };
        
        // Try to match the application name to a package name
        let possible_names = self.generate_package_names(&app.name);
        
        for package_name in possible_names {
            if let Some(available_version) = cache.get(&package_name) {
                // Check if this is actually an update
                if let Some(ref current_version) = app.version {
                    if !super::update_checker::utils::is_version_newer(current_version, available_version) {
                        continue;
                    }
                }
                
                debug!("Found update for {}: {} -> {}", 
                       app.name, app.version.as_deref().unwrap_or("unknown"), available_version);
                
                return Ok(Some(UpdateInfo {
                    current_version: app.version.clone(),
                    available_version: available_version.clone(),
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
        let mut names = Vec::new();
        let normalized = app_name.to_lowercase()
            .replace(' ', "-")
            .replace('_', "-");
        
        names.push(normalized.clone());
        names.push(app_name.to_lowercase().replace(' ', ""));
        names.push(app_name.to_lowercase());
        
        // Add common package name patterns
        if !normalized.is_empty() {
            names.push(format!("lib{}", normalized));
            names.push(format!("{}-dev", normalized));
            names.push(format!("{}-common", normalized));
        }
        
        names
    }
    
    async fn get_package_size(&self, package_name: &str) -> Option<u64> {
        // Use native APT library to get package information instead of command-line
        #[cfg(target_os = "linux")]
        {
            debug!("Getting package size for {} via native APT library", package_name);
            
            // This would use apt-pkg-native library to query package information
            // For now, return None since we're transitioning away from command-line tools
            
            // In a full implementation, this would:
            // 1. Query APT cache for the package
            // 2. Get the package size from metadata
            // 3. Return the size in bytes
            
            None
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
    
    fn get_package_size_from_output(&self, output_str: &str) -> Option<u64> {
        for line in output_str.lines() {
            if line.starts_with("Size: ") {
                if let Ok(size) = line[6..].trim().parse::<u64>() {
                    return Some(size);
                }
            }
        }
        
        None
    }
    
    async fn is_security_update(&self, _package_name: &str) -> bool {
        // This would require checking if the update is from security repositories
        // For now, return false
        false
    }
}

/// RPM update checker for Red Hat/Fedora/CentOS systems
struct RpmUpdateChecker {
    cache: Option<HashMap<String, String>>, // package_name -> available_version
    security_packages: Vec<String>,         // packages with security updates
}

impl RpmUpdateChecker {
    fn new() -> Result<Self> {
        Ok(Self {
            cache: None,
            security_packages: Vec::new(),
        })
    }

    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing RPM update checker");

        // Build cache of upgradeable packages
        self.cache = Some(self.build_upgrade_cache().await?);

        Ok(())
    }

    async fn build_upgrade_cache(&mut self) -> UpdateCheckResult<HashMap<String, String>> {
        debug!("Building RPM upgrade cache");

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            // Try dnf first, fall back to yum
            let cache = tokio::task::spawn_blocking(move || -> UpdateCheckResult<HashMap<String, String>> {
                let mut packages = HashMap::new();

                // Try dnf check-update first
                let output = Command::new("dnf")
                    .args(["check-update", "-q"])
                    .output();

                let output = match output {
                    Ok(o) => o,
                    Err(_) => {
                        // Fall back to yum
                        Command::new("yum")
                            .args(["check-update", "-q"])
                            .output()
                            .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to run yum/dnf: {}", e)))?
                    }
                };

                // dnf/yum check-update returns exit code 100 if updates are available
                let stdout = String::from_utf8_lossy(&output.stdout);

                for line in stdout.lines() {
                    // Skip empty lines, headers, and metadata lines
                    if line.is_empty()
                        || line.starts_with("Last metadata")
                        || line.starts_with("Obsoleting")
                        || !line.contains('.')
                    {
                        continue;
                    }

                    // Format: package_name.arch   version   repository
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let package_arch = parts[0];
                        let available_version = parts[1].to_string();

                        // Split package name and architecture
                        let package_name = if let Some(pos) = package_arch.rfind('.') {
                            package_arch[..pos].to_string()
                        } else {
                            package_arch.to_string()
                        };

                        packages.insert(package_name, available_version);
                    }
                }

                debug!("Found {} upgradeable packages via dnf/yum", packages.len());
                Ok(packages)
            }).await
            .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to spawn RPM cache building task: {}", e)))?
            .map_err(|e| e)?;

            // Also check for security updates
            self.security_packages = self.get_security_packages().await?;

            return Ok(cache);
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!("RPM not available on non-Linux platforms");
            Ok(HashMap::new())
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_security_packages(&self) -> UpdateCheckResult<Vec<String>> {
        use std::process::Command;

        tokio::task::spawn_blocking(move || -> UpdateCheckResult<Vec<String>> {
            let mut security_packages = Vec::new();

            // Try to get security updates
            let output = Command::new("dnf")
                .args(["updateinfo", "list", "security", "-q"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.is_empty() {
                            continue;
                        }
                        // Extract package name from security advisory line
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let package_full = parts[2];
                            // Extract package name (before version)
                            if let Some(name) = extract_rpm_package_name(package_full) {
                                security_packages.push(name);
                            }
                        }
                    }
                }
            }

            Ok(security_packages)
        }).await
        .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to get security packages: {}", e)))?
    }

    async fn check_package_update(
        &self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        let cache = match &self.cache {
            Some(cache) => cache,
            None => return Ok(None),
        };

        let possible_names = self.generate_package_names(&app.name);

        for package_name in possible_names {
            if let Some(available_version) = cache.get(&package_name) {
                // Check if this is actually an update
                if let Some(ref current_version) = app.version {
                    if !super::update_checker::utils::is_version_newer(current_version, available_version) {
                        continue;
                    }
                }

                let is_security = self.security_packages.iter().any(|sp| sp == &package_name);

                debug!("Found update for {}: {} -> {}",
                       app.name, app.version.as_deref().unwrap_or("unknown"), available_version);

                return Ok(Some(UpdateInfo {
                    current_version: app.version.clone(),
                    available_version: available_version.clone(),
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
        let mut names = Vec::new();
        let normalized = app_name.to_lowercase().replace(' ', "-");

        names.push(normalized.clone());
        names.push(app_name.to_lowercase().replace(' ', ""));
        names.push(app_name.to_lowercase());

        names
    }
}

/// Extract package name from NEVRA format (Name-Epoch:Version-Release.Arch)
#[cfg(target_os = "linux")]
fn extract_rpm_package_name(nevra: &str) -> Option<String> {
    let parts: Vec<&str> = nevra.split('-').collect();
    let mut name_parts = Vec::new();

    for part in parts.iter() {
        // If this part starts with a digit or contains ':', it's likely the version
        if part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
           || part.contains(':') {
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

/// Snap update checker
struct SnapUpdateChecker {
    cache: Option<HashMap<String, String>>, // snap_name -> available_version
}

impl SnapUpdateChecker {
    fn new() -> Result<Self> {
        Ok(Self { cache: None })
    }

    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Snap update checker");

        // Build cache of snaps with pending updates
        self.cache = Some(self.build_refresh_cache().await?);

        Ok(())
    }

    async fn build_refresh_cache(&self) -> UpdateCheckResult<HashMap<String, String>> {
        debug!("Building Snap refresh cache");

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            let cache = tokio::task::spawn_blocking(move || -> UpdateCheckResult<HashMap<String, String>> {
                let mut packages = HashMap::new();

                // Run snap refresh --list to get pending updates
                let output = Command::new("snap")
                    .args(["refresh", "--list"])
                    .output();

                let output = match output {
                    Ok(o) => o,
                    Err(e) => {
                        debug!("snap refresh --list failed: {}", e);
                        return Ok(packages);
                    }
                };

                if !output.status.success() {
                    // No updates available or snap not available
                    return Ok(packages);
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut is_header = true;

                for line in stdout.lines() {
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

                debug!("Found {} snaps with pending updates", packages.len());
                Ok(packages)
            }).await
            .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to spawn Snap cache building task: {}", e)))?
            .map_err(|e| e)?;

            return Ok(cache);
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!("Snap not available on non-Linux platforms");
            Ok(HashMap::new())
        }
    }

    async fn check_snap_update(
        &self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        let cache = match &self.cache {
            Some(cache) => cache,
            None => return Ok(None),
        };

        let snap_name = app.name.to_lowercase();

        if let Some(available_version) = cache.get(&snap_name) {
            debug!("Found snap update for {}: {} -> {}",
                   app.name, app.version.as_deref().unwrap_or("unknown"), available_version);

            return Ok(Some(UpdateInfo {
                current_version: app.version.clone(),
                available_version: available_version.clone(),
                update_size_bytes: None,
                update_source: "Snap Store".to_string(),
                update_url: None,
                is_security_update: false,
                release_notes: None,
                last_checked: SystemTime::now(),
            }));
        }

        Ok(None)
    }
}

/// Flatpak update checker
struct FlatpakUpdateChecker {
    cache: Option<HashMap<String, String>>, // app_id -> available_version
}

impl FlatpakUpdateChecker {
    fn new() -> Result<Self> {
        Ok(Self { cache: None })
    }

    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Flatpak update checker");

        // Build cache of flatpaks with pending updates
        self.cache = Some(self.build_update_cache().await?);

        Ok(())
    }

    async fn build_update_cache(&self) -> UpdateCheckResult<HashMap<String, String>> {
        debug!("Building Flatpak update cache");

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            let cache = tokio::task::spawn_blocking(move || -> UpdateCheckResult<HashMap<String, String>> {
                let mut packages = HashMap::new();

                // Run flatpak remote-ls --updates to get pending updates
                let output = Command::new("flatpak")
                    .args(["remote-ls", "--updates", "--columns=application,version"])
                    .output();

                let output = match output {
                    Ok(o) => o,
                    Err(e) => {
                        debug!("flatpak remote-ls --updates failed: {}", e);
                        return Ok(packages);
                    }
                };

                if !output.status.success() {
                    // No updates available or flatpak not available
                    return Ok(packages);
                }

                let stdout = String::from_utf8_lossy(&output.stdout);

                for line in stdout.lines() {
                    if line.is_empty() {
                        continue;
                    }

                    // Format: app_id\tversion
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 2 {
                        let app_id = parts[0].to_string();
                        let version = parts[1].to_string();
                        packages.insert(app_id, version);
                    } else if parts.len() == 1 {
                        // Sometimes only app_id is returned
                        packages.insert(parts[0].to_string(), "available".to_string());
                    }
                }

                debug!("Found {} flatpaks with pending updates", packages.len());
                Ok(packages)
            }).await
            .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to spawn Flatpak cache building task: {}", e)))?
            .map_err(|e| e)?;

            return Ok(cache);
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!("Flatpak not available on non-Linux platforms");
            Ok(HashMap::new())
        }
    }

    async fn check_flatpak_update(
        &self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        let cache = match &self.cache {
            Some(cache) => cache,
            None => return Ok(None),
        };

        // Try to match by registry_key (which contains the app_id for flatpaks)
        // or by name
        let app_id = app.registry_key.as_ref().unwrap_or(&app.name);

        if let Some(available_version) = cache.get(app_id) {
            debug!("Found flatpak update for {}: {} -> {}",
                   app.name, app.version.as_deref().unwrap_or("unknown"), available_version);

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

        // Also try matching by name (case-insensitive)
        let app_name_lower = app.name.to_lowercase();
        for (cached_id, available_version) in cache.iter() {
            if cached_id.to_lowercase().contains(&app_name_lower) {
                debug!("Found flatpak update for {} (matched by name): {} -> {}",
                       app.name, app.version.as_deref().unwrap_or("unknown"), available_version);

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

        Ok(None)
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
    fn test_generate_package_names() {
        let checker = AptUpdateChecker::new().unwrap();
        let names = checker.generate_package_names("Firefox Browser");
        
        assert!(names.contains(&"firefox-browser".to_string()));
        assert!(names.contains(&"firefoxbrowser".to_string()));
        assert!(names.contains(&"firefox browser".to_string()));
    }
}