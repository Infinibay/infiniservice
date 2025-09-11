//! Windows-specific application update checking
//!
//! This module provides update checking for Windows applications using:
//! - Windows Update Agent API for MSI applications
//! - Microsoft Store API for Store applications 
//! - Registry-based update URL detection for other applications

use anyhow::{Context, Result};
use async_trait::async_trait;
use log::{debug, warn};
use std::time::SystemTime;

use super::update_checker::{UpdateChecker, UpdateCheckConfig, UpdateInfo, UpdateCheckError, UpdateCheckResult};
use super::application_inventory::Application;

/// Windows-specific update checker
pub struct WindowsUpdateChecker {
    client: reqwest::Client,
    store_checker: Option<WindowsStoreChecker>,
    windows_update_checker: Option<WindowsUpdateAgentChecker>,
    registry_checker: WindowsRegistryChecker,
}

impl WindowsUpdateChecker {
    /// Create a new Windows update checker
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;
            
        let store_checker = WindowsStoreChecker::new().ok();
        let windows_update_checker = WindowsUpdateAgentChecker::new().ok();
        let registry_checker = WindowsRegistryChecker::new();
        
        Ok(Self {
            client,
            store_checker,
            windows_update_checker,
            registry_checker,
        })
    }
}

#[async_trait]
impl UpdateChecker for WindowsUpdateChecker {
    async fn check_app_update(
        &mut self,
        app: &Application,
        config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!("Checking updates for Windows app: {} ({})", app.name, app.install_type);
        
        // First, try to find this app in WinGet cache regardless of install type
        // This will catch applications like Chrome, Firefox, etc. that are available via WinGet
        if let Some(ref mut store_checker) = self.store_checker {
            debug!("Checking WinGet cache for app: {}", app.name);
            if let Ok(Some(update_info)) = store_checker.check_winget_cache(app).await {
                debug!("Found {} in WinGet cache", app.name);
                return Ok(Some(update_info));
            }
        }
        
        // If not found in WinGet, fall back to specific install type checking
        match app.install_type.as_str() {
            "Store" => {
                if let Some(ref mut checker) = self.store_checker {
                    return checker.check_store_app_update(app, config).await;
                }
            }
            "MSI" => {
                if let Some(ref mut checker) = self.windows_update_checker {
                    if let Ok(Some(info)) = checker.check_msi_app_update(app, config).await {
                        return Ok(Some(info));
                    }
                }
                // Fallback to registry-based checking
                return self.registry_checker.check_registry_app_update(app, config).await;
            }
            "Registry" => {
                return self.registry_checker.check_registry_app_update(app, config).await;
            }
            _ => {
                return Err(UpdateCheckError::NotSupported(
                    format!("Update checking not supported for install type: {}", app.install_type)
                ));
            }
        }
        
        Ok(None)
    }
    
    fn name(&self) -> &'static str {
        "WindowsUpdateChecker"
    }
    
    fn can_handle(&self, app: &Application) -> bool {
        matches!(app.install_type.as_str(), "Store" | "MSI" | "Registry")
    }
    
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Windows update checker");
        
        if let Some(ref mut checker) = self.store_checker {
            if let Err(e) = checker.initialize().await {
                warn!("Failed to initialize Store checker: {}", e);
                self.store_checker = None;
            }
        }
        
        if let Some(ref mut checker) = self.windows_update_checker {
            if let Err(e) = checker.initialize().await {
                warn!("Failed to initialize Windows Update checker: {}", e);
                self.windows_update_checker = None;
            }
        }
        
        Ok(())
    }
}

/// Windows Store and WinGet application update checker using WinGet CLI
struct WindowsStoreChecker {
    client: reqwest::Client,  // Keep for future HTTP-based checks
    cached_updates: Option<std::collections::HashMap<String, WinGetPackageInfo>>,
    cache_timestamp: Option<std::time::SystemTime>,
    cache_duration: std::time::Duration,
}

impl WindowsStoreChecker {
    fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Infiniservice Update Checker")
            .build()
            .context("Failed to create HTTP client")?;
            
        Ok(Self { 
            client,
            cached_updates: None,
            cache_timestamp: None,
            cache_duration: std::time::Duration::from_secs(300), // 5 minutes cache
        })
    }
    
    /// Get all available updates from WinGet at once
    async fn get_all_available_updates(&mut self) -> UpdateCheckResult<std::collections::HashMap<String, WinGetPackageInfo>> {
        // Check if cache is still valid
        if let (Some(ref cache), Some(timestamp)) = (&self.cached_updates, self.cache_timestamp) {
            if timestamp.elapsed().unwrap_or(std::time::Duration::MAX) < self.cache_duration {
                debug!("Using cached WinGet updates (age: {:?})", timestamp.elapsed().unwrap_or_default());
                return Ok(cache.clone());
            }
        }
        
        debug!("Fetching all available updates from WinGet CLI...");
        
        #[cfg(target_os = "windows")]
        {
            // Get list of all upgradeable packages in one command
            let output = tokio::process::Command::new("winget")
                .args(["upgrade", "--accept-source-agreements", "--disable-interactivity"])
                .output()
                .await
                .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to execute winget upgrade: {}", e)))?;
                
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                debug!("WinGet upgrade listing failed: {}", stderr);
                // Create empty cache on failure
                self.cached_updates = Some(std::collections::HashMap::new());
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout);
                self.cached_updates = Some(self.parse_all_winget_upgrades(&stdout)?);
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            debug!("WinGet CLI not available on non-Windows platforms");
            self.cached_updates = Some(std::collections::HashMap::new());
        }
        
        self.cache_timestamp = Some(std::time::SystemTime::now());
        Ok(self.cached_updates.as_ref().unwrap().clone())
    }
    
    /// Parse winget upgrade output to get all available updates
    fn parse_all_winget_upgrades(&self, output: &str) -> UpdateCheckResult<std::collections::HashMap<String, WinGetPackageInfo>> {
        let mut updates = std::collections::HashMap::new();
        
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
            
            // Parse each package line
            // Format: Name    Id    Version    Available    Source
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let name = parts[0];
                let id = parts[1];
                let current_version = parts[2];
                let available_version = parts[3];
                let source = if parts.len() > 4 { parts[4] } else { "winget" };
                
                // Only include if there's actually an update available
                if available_version != current_version && available_version != "<" && available_version != "Unknown" {
                    let package_info = WinGetPackageInfo {
                        package_id: id.to_string(),
                        latest_version: available_version.to_string(),
                        installer_size: None,
                        download_url: None,
                        source: format!("WinGet ({})", source),
                        release_notes: Some(format!("Update available: {} -> {}", current_version, available_version)),
                    };
                    
                    // Index by both name and ID for flexible lookup
                    updates.insert(name.to_lowercase(), package_info.clone());
                    updates.insert(id.to_lowercase(), package_info);
                    
                    debug!("Found update: {} ({}) {} -> {}", name, id, current_version, available_version);
                }
            }
        }
        
        debug!("Parsed {} available updates from WinGet", updates.len() / 2); // Divide by 2 because we store each twice
        Ok(updates)
    }
    
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Windows Store update checker via WinGet REST API");
        Ok(())
    }
    
    /// Check if an app is available for update in the WinGet cache
    /// This method is used by all app types to check WinGet first
    async fn check_winget_cache(
        &mut self,
        app: &Application,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!("Checking WinGet cache for: {}", app.name);
        
        // Get all available updates (uses cache if available)
        let all_updates = self.get_all_available_updates().await?;
        
        // Try to find this app in the cached updates using multiple matching strategies
        let app_name_lower = app.name.to_lowercase();
        
        // Strategy 1: Direct name match
        if let Some(package_info) = all_updates.get(&app_name_lower) {
            if let Some(update_info) = self.create_update_info_from_winget(app, package_info)? {
                return Ok(Some(update_info));
            }
        }
        
        // Strategy 2: Partial name matching (for apps like "Google Chrome" -> "Chrome")
        for (cached_name, package_info) in &all_updates {
            if cached_name.contains(&app_name_lower) || app_name_lower.contains(cached_name) {
                debug!("Found partial match: {} -> {}", app.name, cached_name);
                if let Some(update_info) = self.create_update_info_from_winget(app, package_info)? {
                    return Ok(Some(update_info));
                }
            }
        }
        
        // Strategy 3: Common name variations (Chrome -> Google Chrome, etc.)
        let common_variations = self.get_common_app_name_variations(&app_name_lower);
        for variation in common_variations {
            if let Some(package_info) = all_updates.get(&variation) {
                debug!("Found variation match: {} -> {}", app.name, variation);
                if let Some(update_info) = self.create_update_info_from_winget(app, package_info)? {
                    return Ok(Some(update_info));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Create UpdateInfo from WinGet package info if version is newer
    fn create_update_info_from_winget(
        &self,
        app: &Application,
        package_info: &WinGetPackageInfo,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        let current_version = app.version.as_deref().unwrap_or("Unknown");
        
        // Compare versions using our utility function
        if super::update_checker::utils::is_version_newer(current_version, &package_info.latest_version) {
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
    
    /// Get common variations of application names for better matching
    fn get_common_app_name_variations(&self, app_name: &str) -> Vec<String> {
        let mut variations = Vec::new();
        
        // Remove common prefixes/suffixes
        let clean_name = app_name
            .replace("microsoft ", "")
            .replace("google ", "")
            .replace("adobe ", "")
            .replace(" browser", "")
            .replace(" app", "");
            
        variations.push(clean_name);
        
        // Add specific common mappings
        match app_name {
            name if name.contains("chrome") => {
                variations.extend_from_slice(&[
                    "chrome".to_string(),
                    "google chrome".to_string(),
                ]);
            }
            name if name.contains("firefox") => {
                variations.extend_from_slice(&[
                    "firefox".to_string(),
                    "mozilla firefox".to_string(),
                ]);
            }
            name if name.contains("edge") => {
                variations.extend_from_slice(&[
                    "edge".to_string(),
                    "microsoft edge".to_string(),
                ]);
            }
            _ => {}
        }
        
        variations
    }

    async fn check_store_app_update(
        &mut self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!("Checking Store app update for: {} (fallback after WinGet)", app.name);
        
        // Note: WinGet cache should have already been checked by the main method
        // This is a fallback for Store-specific logic
        self.check_microsoft_store_directly(app).await
    }
    
    /// Search for a package using WinGet CLI
    async fn search_winget_cli(
        &self,
        app_name: &str,
    ) -> UpdateCheckResult<Option<WinGetPackageInfo>> {
        #[cfg(target_os = "windows")]
        {
            debug!("Searching WinGet CLI for package: {}", app_name);
            
            // Use winget search command with JSON output
            let output = tokio::process::Command::new("winget")
                .args(["search", app_name, "--accept-source-agreements", "--disable-interactivity"])
                .output()
                .await
                .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to execute winget: {}", e)))?;
                
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                debug!("WinGet search failed: {}", stderr);
                return Ok(None);
            }
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            return self.parse_winget_cli_output(&stdout, app_name);
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            debug!("WinGet CLI not available on non-Windows platforms");
            Ok(None)
        }
    }
    
    /// Parse WinGet CLI output to extract package information
    fn parse_winget_cli_output(&self, output: &str, app_name: &str) -> UpdateCheckResult<Option<WinGetPackageInfo>> {
        debug!("Parsing WinGet CLI output for: {}", app_name);
        
        // WinGet CLI output is typically in table format
        // Look for lines that contain our app name
        for line in output.lines() {
            if line.to_lowercase().contains(&app_name.to_lowercase()) {
                // Parse the line to extract package info
                // Format is typically: Name   Id    Version   Available  Source
                let parts: Vec<&str> = line.split_whitespace().collect();
                
                if parts.len() >= 4 {
                    let package_name = parts[0];
                    let package_id = parts[1];
                    let current_ver = parts[2];
                    let available_ver = if parts.len() > 3 && parts[3] != "<" { parts[3] } else { current_ver };
                    let source = if parts.len() > 4 { parts[4] } else { "winget" };
                    
                    // Only return if there's actually a newer version available
                    if available_ver != current_ver && available_ver != "Unknown" {
                        return Ok(Some(WinGetPackageInfo {
                            package_id: package_id.to_string(),
                            latest_version: available_ver.to_string(),
                            installer_size: None,
                            download_url: None,
                            source: format!("WinGet ({})", source),
                            release_notes: Some(format!("Update available for {} from {}", package_name, source)),
                        }));
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    /// Fallback method for Microsoft Store apps not in WinGet
    async fn check_microsoft_store_directly(
        &self,
        app: &Application,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!("Checking Microsoft Store directly for: {}", app.name);
        
        // For Microsoft Store apps not found in WinGet, we can only provide limited information
        // Since Store apps auto-update, we indicate updates are managed by the Store
        if app.version.is_some() {
            Ok(Some(UpdateInfo {
                current_version: app.version.clone(),
                available_version: "Managed by Microsoft Store".to_string(),
                update_size_bytes: None,
                update_source: "Microsoft Store".to_string(),
                update_url: None,
                is_security_update: false,
                release_notes: Some("Updates are automatically managed by Microsoft Store. Check the Store app for update status.".to_string()),
                last_checked: SystemTime::now(),
            }))
        } else {
            Ok(None)
        }
    }
}

/// Information about a package from WinGet CLI
#[derive(Debug, Clone)]
struct WinGetPackageInfo {
    package_id: String,
    latest_version: String,
    installer_size: Option<u64>,
    download_url: Option<String>,
    source: String,
    release_notes: Option<String>,
}

/// Windows Update Agent checker for MSI applications using PowerShell
struct WindowsUpdateAgentChecker {
    cached_updates: Option<Vec<String>>,
    cache_timestamp: Option<std::time::SystemTime>,
    cache_duration: std::time::Duration,
}

impl WindowsUpdateAgentChecker {
    fn new() -> Result<Self> {
        Ok(Self {
            cached_updates: None,
            cache_timestamp: None,
            cache_duration: std::time::Duration::from_secs(600), // 10 minutes cache for Windows Updates
        })
    }
    
    /// Parse Windows Update PowerShell output
    fn parse_windows_update_output(&self, output: &str) -> UpdateCheckResult<Vec<String>> {
        let mut updates = Vec::new();
        
        // Try to parse JSON output
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(array) = json_value.as_array() {
                for item in array {
                    if let Some(title) = item.get("Title").and_then(|t| t.as_str()) {
                        updates.push(title.to_string());
                    }
                }
            } else if let Some(title) = json_value.get("Title").and_then(|t| t.as_str()) {
                updates.push(title.to_string());
            }
        }
        
        debug!("Parsed {} Windows Updates", updates.len());
        Ok(updates)
    }
    
    /// Parse Get-HotFix output as fallback
    fn parse_hotfix_output(&self, output: &str) -> UpdateCheckResult<Vec<String>> {
        let mut updates = Vec::new();
        
        if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(array) = json_value.as_array() {
                for item in array {
                    if let (Some(hotfix_id), Some(description)) = (
                        item.get("HotFixID").and_then(|h| h.as_str()),
                        item.get("Description").and_then(|d| d.as_str())
                    ) {
                        updates.push(format!("{}: {}", hotfix_id, description));
                    }
                }
            }
        }
        
        debug!("Parsed {} HotFix entries", updates.len());
        Ok(updates)
    }
    
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        debug!("Initializing Windows Update Agent checker via PowerShell");
        
        #[cfg(target_os = "windows")]
        {
            // Test if PowerShell is available and working
            let test_output = tokio::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.Major"])
                .output()
                .await;
                
            match test_output {
                Ok(output) if output.status.success() => {
                    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    debug!("PowerShell version {} detected and ready", version);
                },
                _ => {
                    return Err(UpdateCheckError::PlatformError(
                        "PowerShell not available or not working".to_string()
                    ));
                }
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            debug!("Windows Update Agent not available on non-Windows platforms");
        }
        
        Ok(())
    }
    
    async fn check_msi_app_update(
        &mut self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!("Checking Windows Update for MSI app: {} using cached updates", app.name);
        
        // Get all available Windows Updates (uses cache if available)
        let available_updates = self.get_all_windows_updates().await?;
        
        if !available_updates.is_empty() {
            // Look for updates that might be related to this application
            for update_title in available_updates {
                if update_title.to_lowercase().contains(&app.name.to_lowercase()) {
                    debug!("Found potential Windows Update for {}: {}", app.name, update_title);
                    
                    return Ok(Some(UpdateInfo {
                        current_version: app.version.clone(),
                        available_version: "Available via Windows Update".to_string(),
                        update_size_bytes: None,
                        update_source: "Windows Update".to_string(),
                        update_url: None,
                        is_security_update: update_title.to_lowercase().contains("security"),
                        release_notes: Some(update_title.clone()),
                        last_checked: SystemTime::now(),
                    }));
                }
            }
        }
        
        debug!("No Windows Update found for application: {}", app.name);
        Ok(None)
    }
    
    /// Get all available Windows Updates at once (with caching)
    async fn get_all_windows_updates(&mut self) -> UpdateCheckResult<Vec<String>> {
        // Check if cache is still valid
        if let (Some(ref cache), Some(timestamp)) = (&self.cached_updates, self.cache_timestamp) {
            if timestamp.elapsed().unwrap_or(std::time::Duration::MAX) < self.cache_duration {
                debug!("Using cached Windows Updates (age: {:?})", timestamp.elapsed().unwrap_or_default());
                return Ok(cache.clone());
            }
        }
        
        debug!("Fetching all available Windows Updates...");
        
        // Fetch all Windows Updates at once
        let updates = self.fetch_windows_updates().await?;
        self.cached_updates = Some(updates);
        self.cache_timestamp = Some(std::time::SystemTime::now());
        
        Ok(self.cached_updates.as_ref().unwrap().clone())
    }
    
    /// Fetch all Windows Updates using PowerShell
    async fn fetch_windows_updates(&self) -> UpdateCheckResult<Vec<String>> {
        #[cfg(target_os = "windows")]
        {
            debug!("Fetching Windows Updates using PowerShell");
            
            // Try with PSWindowsUpdate module first
            let output = tokio::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "try { Get-WUList -MicrosoftUpdate | Select-Object Title, Size | ConvertTo-Json } catch { Write-Output 'PSWindowsUpdate_NOT_AVAILABLE' }"
                ])
                .output()
                .await
                .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to execute PowerShell: {}", e)))?;
                
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.contains("PSWindowsUpdate_NOT_AVAILABLE") {
                    return self.parse_windows_update_output(&stdout);
                }
            }
            
            // Fallback: use built-in Get-HotFix to show installed updates
            let fallback_output = tokio::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive", 
                    "-Command",
                    "Get-HotFix | Select-Object -First 10 HotFixID, Description, InstalledOn | ConvertTo-Json"
                ])
                .output()
                .await
                .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to execute fallback PowerShell: {}", e)))?;
                
            if fallback_output.status.success() {
                let stdout = String::from_utf8_lossy(&fallback_output.stdout);
                return self.parse_hotfix_output(&stdout);
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            debug!("Windows Update checking not available on non-Windows platforms");
        }
        
        Ok(vec![])
    }
    
    #[cfg(target_os = "windows")]
    async fn search_windows_update_for_app(
        &self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        use windows::Win32::System::UpdateAgent::*;
        use windows::Win32::System::Com::*;
        
        // Create COM objects locally to avoid thread safety issues
        unsafe {
            // Create Update Session locally
            let update_session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to create UpdateSession: {:?}", e)))?;
            
            // Create Update Searcher locally
            let searcher = update_session.CreateUpdateSearcher()
                .map_err(|e| UpdateCheckError::PlatformError(format!("Failed to create UpdateSearcher: {:?}", e)))?;
        
            // Search for updates that might be related to this application
            // Windows Update primarily handles OS updates, but some MSI packages might be available
            let _search_criteria = format!("IsInstalled=0 AND Type='Software' AND CategoryIDs contains '0fa1201d-4330-4fa8-8ae9-b877473b6441'");
            
            debug!("Windows Update search would use criteria: {}", _search_criteria);
            
            // This method is no longer used - moved to check_msi_app_update with PowerShell implementation
            debug!("Direct Windows Update search method deprecated - using PowerShell approach instead");
            return Ok(None);
        }
        
        debug!("No Windows Update found for application: {}", app.name);
        Ok(None)
    }
    
    #[cfg(target_os = "windows")]
    fn is_security_update(&self, update: &windows::Win32::System::UpdateAgent::IUpdate) -> bool {
        // Check if this is a security update by examining categories
        unsafe {
            if let Ok(categories) = update.Categories() {
                if let Ok(count) = categories.Count() {
                    for i in 0..count {
                        if let Ok(category) = categories.get_Item(i) {
                            if let Ok(category_id) = category.CategoryID() {
                                let id_str = category_id.to_string();
                                // Microsoft Security Updates category ID
                                if id_str == "0fa1201d-4330-4fa8-8ae9-b877473b6441" {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

// No longer need Drop implementation since we're not using COM objects

/// Registry-based update checker for applications with update mechanisms
struct WindowsRegistryChecker;

impl WindowsRegistryChecker {
    fn new() -> Self {
        Self
    }
    
    async fn check_registry_app_update(
        &self,
        app: &Application,
        config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        debug!("Checking registry-based updates for: {}", app.name);
        
        // Look for common update URL patterns in the registry
        if let Some(update_info) = self.check_common_updaters(app).await? {
            return Ok(Some(update_info));
        }
        
        // Check for specific application update patterns
        if let Some(update_info) = self.check_known_applications(app, config).await? {
            return Ok(Some(update_info));
        }
        
        Ok(None)
    }
    
    async fn check_common_updaters(
        &self,
        app: &Application,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Check for common update mechanisms sequentially to avoid type issues
        if app.name.contains("Google Chrome") {
            if let Some(info) = self.check_chrome_updates().await? {
                return Ok(Some(info));
            }
        }
        
        if app.name.contains("Mozilla Firefox") {
            if let Some(info) = self.check_firefox_updates().await? {
                return Ok(Some(info));
            }
        }
        
        if app.name.contains("Microsoft Edge") {
            if let Some(info) = self.check_edge_updates().await? {
                return Ok(Some(info));
            }
        }
        
        if app.name.contains("Adobe") {
            if let Some(info) = self.check_adobe_updates().await? {
                return Ok(Some(info));
            }
        }
        
        if app.name.contains("Java") {
            if let Some(info) = self.check_java_updates().await? {
                return Ok(Some(info));
            }
        }
        
        Ok(None)
    }
    
    async fn check_chrome_updates(&self) -> UpdateCheckResult<Option<UpdateInfo>> {
        #[cfg(target_os = "windows")]
        {
            // Check Chrome version via registry or executable
            let output = tokio::process::Command::new("reg")
                .args([
                    "query", 
                    "HKEY_CURRENT_USER\\Software\\Google\\Chrome\\BLBeacon", 
                    "/v", "version"
                ])
                .output()
                .await;
                
            if let Ok(result) = output {
                if result.status.success() {
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    if let Some(version_line) = stdout.lines().find(|line| line.contains("version")) {
                        // Extract version from registry output
                        if let Some(version) = version_line.split_whitespace().last() {
                            debug!("Found Chrome version: {}", version);
                            
                            return Ok(Some(UpdateInfo {
                                current_version: Some(version.to_string()),
                                available_version: "Check Chrome for updates".to_string(),
                                update_size_bytes: None,
                                update_source: "Google Chrome Auto-Update".to_string(),
                                update_url: Some("chrome://settings/help".to_string()),
                                is_security_update: false,
                                release_notes: Some("Chrome updates automatically. Visit chrome://settings/help to check for updates.".to_string()),
                                last_checked: SystemTime::now(),
                            }));
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    async fn check_firefox_updates(&self) -> UpdateCheckResult<Option<UpdateInfo>> {
        #[cfg(target_os = "windows")]
        {
            // Check Firefox version via registry
            let output = tokio::process::Command::new("reg")
                .args([
                    "query", 
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Mozilla\\Mozilla Firefox", 
                    "/s"
                ])
                .output()
                .await;
                
            if let Ok(result) = output {
                if result.status.success() {
                    let stdout = String::from_utf8_lossy(&result.stdout);
                    // Look for version information in the registry output
                    for line in stdout.lines() {
                        if line.contains("CurrentVersion") {
                            if let Some(version) = line.split_whitespace().last() {
                                debug!("Found Firefox version: {}", version);
                                
                                return Ok(Some(UpdateInfo {
                                    current_version: Some(version.to_string()),
                                    available_version: "Check Firefox for updates".to_string(),
                                    update_size_bytes: None,
                                    update_source: "Mozilla Firefox Auto-Update".to_string(),
                                    update_url: Some("about:preferences#general".to_string()),
                                    is_security_update: false,
                                    release_notes: Some("Firefox updates automatically. Check Help > About Firefox for updates.".to_string()),
                                    last_checked: SystemTime::now(),
                                }));
                            }
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    async fn check_edge_updates(&self) -> UpdateCheckResult<Option<UpdateInfo>> {
        #[cfg(target_os = "windows")]
        {
            // Edge is updated through Windows Update, so we can check its version
            let output = tokio::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-AppxPackage -Name Microsoft.MicrosoftEdge.Stable).Version"
                ])
                .output()
                .await;
                
            if let Ok(result) = output {
                if result.status.success() {
                    let version = String::from_utf8_lossy(&result.stdout).trim().to_string();
                    if !version.is_empty() && version != "" {
                        debug!("Found Edge version: {}", version);
                        
                        return Ok(Some(UpdateInfo {
                            current_version: Some(version),
                            available_version: "Updated via Windows Update".to_string(),
                            update_size_bytes: None,
                            update_source: "Windows Update".to_string(),
                            update_url: None,
                            is_security_update: false,
                            release_notes: Some("Microsoft Edge is updated automatically through Windows Update.".to_string()),
                            last_checked: SystemTime::now(),
                        }));
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    async fn check_adobe_updates(&self) -> UpdateCheckResult<Option<UpdateInfo>> {
        // Adobe products use Adobe Updater
        // We could check Adobe's update services
        Ok(None)
    }
    
    async fn check_java_updates(&self) -> UpdateCheckResult<Option<UpdateInfo>> {
        #[cfg(target_os = "windows")]
        {
            // Check Java version using java command
            let output = tokio::process::Command::new("java")
                .args(["-version"])
                .output()
                .await;
                
            if let Ok(result) = output {
                if result.status.success() {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    // Java version is typically in stderr
                    if let Some(version_line) = stderr.lines().next() {
                        if version_line.contains("java version") || version_line.contains("openjdk version") {
                            // Extract version number
                            if let Some(start) = version_line.find('"') {
                                if let Some(end) = version_line[start + 1..].find('"') {
                                    let version = &version_line[start + 1..start + 1 + end];
                                    debug!("Found Java version: {}", version);
                                    
                                    return Ok(Some(UpdateInfo {
                                        current_version: Some(version.to_string()),
                                        available_version: "Check Java Control Panel".to_string(),
                                        update_size_bytes: None,
                                        update_source: "Oracle Java Update Scheduler".to_string(),
                                        update_url: Some("https://www.java.com/en/download/".to_string()),
                                        is_security_update: true, // Java updates are often security-related
                                        release_notes: Some("Java updates should be checked regularly for security patches.".to_string()),
                                        last_checked: SystemTime::now(),
                                    }));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    async fn check_known_applications(
        &self,
        app: &Application,
        _config: &UpdateCheckConfig,
    ) -> UpdateCheckResult<Option<UpdateInfo>> {
        // For applications with known update patterns, we could:
        // 1. Read update URLs from registry
        // 2. Parse version information from executable metadata
        // 3. Check manufacturer websites for updates
        
        debug!("Checking known application patterns for: {}", app.name);
        
        // This is a simplified implementation
        // In a real scenario, we would have a database of known applications
        // and their update mechanisms
        
        Ok(None)
    }
}

/// Windows-specific utilities for update checking
#[cfg(target_os = "windows")]
mod windows_utils {
    use super::*;
    use windows::Win32::System::Registry::*;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    
    /// Read update URL from registry for a given application
    pub unsafe fn read_update_url_from_registry(app_name: &str) -> Option<String> {
        // Common registry paths where update URLs might be stored
        let registry_paths = [
            format!("SOFTWARE\\{}", app_name),
            format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}", app_name),
        ];
        
        for path in &registry_paths {
            if let Some(url) = read_registry_string_value(&path, "UpdateURL").or_else(|| {
                read_registry_string_value(&path, "URLUpdateInfo")
            }).or_else(|| {
                read_registry_string_value(&path, "HelpLink")
            }) {
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
    use super::{WindowsUpdateChecker, Application, UpdateCheckError, WinGetPackageInfo, WindowsStoreChecker};
    
    #[tokio::test]
    async fn test_windows_update_checker_creation() {
        let checker = WindowsUpdateChecker::new();
        assert!(checker.is_ok());
    }
    
    #[test]
    fn test_can_handle() {
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
        
        assert!(checker.can_handle(&store_app));
        assert!(checker.can_handle(&msi_app));
        assert!(!checker.can_handle(&unknown_app));
    }
    
    #[test]
    fn test_winget_store_checker_creation() {
        let checker = WindowsStoreChecker::new();
        assert!(checker.is_ok());
        
        // No longer checking winget_api_base since we're using CLI now
        let _checker = checker.unwrap();
    }
    
    #[test]
    fn test_winget_cli_output_parsing() {
        let checker = WindowsStoreChecker::new().unwrap();
        
        // Create mock WinGet CLI output
        let cli_output = "Name               Id                Version    Available  Source\n----               --                -------    ---------  ------\nMicrosoft Terminal Microsoft.WindowsTerminal 1.17.11461.0 1.18.3181.0 winget\nVisual Studio Code Microsoft.VisualStudioCode 1.75.1       1.76.0      winget";
        
        let result = checker.parse_winget_cli_output(cli_output, "Microsoft Terminal").unwrap();
        assert!(result.is_some());
        
        let package_info = result.unwrap();
        assert_eq!(package_info.package_id, "Microsoft.WindowsTerminal");
        assert_eq!(package_info.latest_version, "1.18.3181.0");
        assert_eq!(package_info.source, "WinGet (winget)");
        assert!(package_info.release_notes.is_some());
    }
    
    #[test]
    fn test_winget_cli_output_no_updates() {
        let checker = WindowsStoreChecker::new().unwrap();
        
        // Mock CLI output with no updates available
        let cli_output = "Name               Id                Version    Available  Source\n----               --                -------    ---------  ------\nMicrosoft Terminal Microsoft.WindowsTerminal 1.18.3181.0 1.18.3181.0 winget";
        
        let result = checker.parse_winget_cli_output(cli_output, "Microsoft Terminal").unwrap();
        // Should return None because current version == available version
        assert!(result.is_none());
    }
    
    #[test]
    fn test_winget_cli_output_parsing_edge_cases() {
        let checker = WindowsStoreChecker::new().unwrap();
        
        // Test with malformed output
        let malformed_output = "Some random text that doesn't match expected format";
        let result = checker.parse_winget_cli_output(malformed_output, "SomeApp").unwrap();
        assert!(result.is_none());
        
        // Test with empty output
        let empty_output = "";
        let result = checker.parse_winget_cli_output(empty_output, "SomeApp").unwrap();
        assert!(result.is_none());
    }
}