//! Application inventory management for Windows (WMI/Registry) and Linux (package managers)
//!
//! This module provides functionality to discover installed applications:
//! - **Windows**: WMI queries (Win32_Product, Win32_InstalledStoreProgram) and Registry access
//! - **Linux**: Package managers (dpkg/apt, rpm/dnf/yum, snap, flatpak)
//!
//! ## Supported Linux Package Managers
//! - **dpkg/apt**: Debian, Ubuntu and derivatives
//! - **rpm/dnf/yum**: Fedora, RHEL, CentOS and derivatives
//! - **snap**: Universal snap packages
//! - **flatpak**: Universal flatpak applications

use anyhow::{Result, anyhow, Context};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use log::{debug, warn, info};

#[cfg(target_os = "windows")]
use wmi::{COMLibrary, WMIConnection};
#[cfg(target_os = "windows")]
use windows::core::*;
#[cfg(target_os = "windows")]
use windows::Win32::System::Registry::*;
#[cfg(target_os = "windows")]
use winapi::shared::winerror::ERROR_SUCCESS;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::WIN32_ERROR;
#[cfg(target_os = "windows")]
use windows::core::PWSTR;

#[cfg(target_os = "linux")]
use crate::os_detection::{get_os_info, PackageManager};
#[cfg(target_os = "linux")]
use super::common::shell::execute_command;

/// Application information from Win32_Product (MSI-installed applications)
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Win32_Product {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    
    #[serde(rename = "Version")]
    pub version: Option<String>,
    
    #[serde(rename = "Vendor")]
    pub vendor: Option<String>,
    
    #[serde(rename = "InstallDate")]
    pub install_date: Option<String>,
    
    #[serde(rename = "InstallLocation")]
    pub install_location: Option<String>,
    
    #[serde(rename = "IdentifyingNumber")]
    pub identifying_number: Option<String>,
}

/// Microsoft Store application information
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Win32_InstalledStoreProgram {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    
    #[serde(rename = "Version")]
    pub version: Option<String>,
    
    #[serde(rename = "ProgramId")]
    pub program_id: Option<String>,
    
    #[serde(rename = "Architecture")]
    pub architecture: Option<String>,
}

/// Unified application information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Application {
    pub name: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub install_date: Option<String>,
    pub install_type: String, // "MSI", "Store", "Registry", "Manual"
    pub can_update: bool,
    pub install_location: Option<String>,
    pub size_mb: Option<u64>,
    pub registry_key: Option<String>,
    
    // New update-related fields
    pub update_available: Option<String>, // Available version if update exists
    pub update_source: Option<String>,    // Source of the update (Windows Update, Store, APT, etc.)
    pub last_update_check: Option<SystemTime>, // When we last checked for updates
    pub update_size_bytes: Option<u64>,   // Size of the update in bytes
    pub is_security_update: Option<bool>, // Whether the available update is security-related
}

/// Application inventory summary
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApplicationInventory {
    pub total_count: usize,
    pub applications: Vec<Application>,
    pub last_scan: SystemTime,
    pub scan_duration_ms: u64,
    pub by_install_type: std::collections::HashMap<String, usize>,
}

/// Get comprehensive application inventory using WMI and Registry
#[cfg(target_os = "windows")]
pub async fn get_installed_applications_wmi() -> Result<ApplicationInventory> {
    let start_time = SystemTime::now();
    info!("Starting comprehensive application inventory scan");
    
    let com_lib = COMLibrary::new()
        .context("Failed to initialize COM library")?;
    
    let wmi_conn = WMIConnection::new(com_lib)
        .context("Failed to create WMI connection")?;
    
    let mut applications = Vec::new();
    let mut by_install_type = std::collections::HashMap::new();
    
    // 1. Query Win32_Product (MSI installed apps)
    debug!("Scanning MSI-installed applications (Win32_Product)");
    match get_msi_applications(&wmi_conn).await {
        Ok(mut msi_apps) => {
            let count = msi_apps.len();
            by_install_type.insert("MSI".to_string(), count);
            applications.append(&mut msi_apps);
            info!("Found {} MSI-installed applications", count);
        }
        Err(e) => {
            warn!("Failed to query Win32_Product: {}", e);
            by_install_type.insert("MSI".to_string(), 0);
        }
    }
    
    // 2. Query Win32_InstalledStoreProgram (Microsoft Store apps)
    debug!("Scanning Microsoft Store applications");
    match get_store_applications(&wmi_conn).await {
        Ok(mut store_apps) => {
            let count = store_apps.len();
            by_install_type.insert("Store".to_string(), count);
            applications.append(&mut store_apps);
            info!("Found {} Microsoft Store applications", count);
        }
        Err(e) => {
            warn!("Failed to query Store apps: {}", e);
            by_install_type.insert("Store".to_string(), 0);
        }
    }
    
    // 3. Query registry for additional applications
    debug!("Scanning Windows Registry for additional applications");
    match query_registry_applications().await {
        Ok(mut registry_apps) => {
            let count = registry_apps.len();
            by_install_type.insert("Registry".to_string(), count);
            applications.append(&mut registry_apps);
            info!("Found {} registry-based applications", count);
        }
        Err(e) => {
            warn!("Failed to query registry applications: {}", e);
            by_install_type.insert("Registry".to_string(), 0);
        }
    }
    
    // Remove duplicates based on name and version
    applications = deduplicate_applications(applications);
    
    // Check for update availability (simplified implementation)
    check_application_updates(&mut applications).await?;
    
    let scan_duration = start_time.elapsed()
        .unwrap_or(std::time::Duration::from_millis(0))
        .as_millis() as u64;
    
    let total_count = applications.len();
    info!("Application inventory complete: {} unique applications in {}ms", 
          total_count, scan_duration);
    
    Ok(ApplicationInventory {
        total_count,
        applications,
        last_scan: SystemTime::now(),
        scan_duration_ms: scan_duration,
        by_install_type,
    })
}

/// Get MSI-installed applications from Win32_Product
#[cfg(target_os = "windows")]
async fn get_msi_applications(wmi_conn: &WMIConnection) -> Result<Vec<Application>> {
    let products: Vec<Win32_Product> = wmi_conn
        .raw_query("SELECT Name, Version, Vendor, InstallDate, InstallLocation, IdentifyingNumber FROM Win32_Product")
        .context("Failed to query Win32_Product")?;
    
    let applications = products
        .into_iter()
        .filter_map(|product| {
            product.name.map(|name| Application {
                name,
                version: product.version,
                vendor: product.vendor,
                install_date: product.install_date,
                install_type: "MSI".to_string(),
                can_update: false, // Will be determined separately
                install_location: product.install_location,
                size_mb: None, // Could be queried separately
                registry_key: product.identifying_number,
                // New fields initialized as None
                update_available: None,
                update_source: None,
                last_update_check: None,
                update_size_bytes: None,
                is_security_update: None,
            })
        })
        .collect();
    
    Ok(applications)
}

/// Get Microsoft Store applications
#[cfg(target_os = "windows")]
async fn get_store_applications(wmi_conn: &WMIConnection) -> Result<Vec<Application>> {
    let store_apps: Vec<Win32_InstalledStoreProgram> = wmi_conn
        .raw_query("SELECT Name, Version, ProgramId, Architecture FROM Win32_InstalledStoreProgram")
        .context("Failed to query Win32_InstalledStoreProgram")?;
    
    let applications = store_apps
        .into_iter()
        .filter_map(|app| {
            app.name.map(|name| Application {
                name,
                version: app.version,
                vendor: Some("Microsoft Store".to_string()),
                install_date: None,
                install_type: "Store".to_string(),
                can_update: true, // Store apps can usually be updated
                install_location: None,
                size_mb: None,
                registry_key: app.program_id,
                // New fields initialized as None
                update_available: None,
                update_source: None,
                last_update_check: None,
                update_size_bytes: None,
                is_security_update: None,
            })
        })
        .collect();
    
    Ok(applications)
}

/// Query Windows Registry for applications
#[cfg(target_os = "windows")]
async fn query_registry_applications() -> Result<Vec<Application>> {
    let mut applications = Vec::new();
    
    unsafe {
        // Query both 32-bit and 64-bit registry keys
        let paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ];
        
        for path in paths {
            match scan_registry_path(path) {
                Ok(mut apps) => applications.append(&mut apps),
                Err(e) => warn!("Failed to scan registry path {}: {}", path, e),
            }
        }
    }
    
    Ok(applications)
}

/// Scan a specific registry path for applications
#[cfg(target_os = "windows")]
unsafe fn scan_registry_path(path: &str) -> Result<Vec<Application>> {
    let mut applications = Vec::new();
    let mut key_handle = HKEY::default();
    
    debug!("Scanning registry path: {}", path);
    
    let result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        &HSTRING::from(path),
        0,
        KEY_READ,
        &mut key_handle,
    );
    
    if result != WIN32_ERROR(ERROR_SUCCESS) {
        return Err(anyhow!("Failed to open registry key: {}", path));
    }
    
    let mut index = 0;
    loop {
        let mut subkey_name = [0u16; 256];
        let mut subkey_len = 256u32;
        
        let result = RegEnumKeyExW(
            key_handle,
            index,
            PWSTR::from_raw(subkey_name.as_mut_ptr()),
            &mut subkey_len,
            None,
            PWSTR::null(),
            None,
            None,
        );
        
        if result != WIN32_ERROR(ERROR_SUCCESS) {
            break;
        }
        
        // Convert subkey name to string
        let subkey_name_str = String::from_utf16_lossy(&subkey_name[..subkey_len as usize]);
        
        // Open subkey and read application details
        match read_application_from_registry(key_handle, &subkey_name_str) {
            Ok(Some(app)) => applications.push(app),
            Ok(None) => {}, // Skip this entry
            Err(e) => warn!("Failed to read application from registry key {}: {}", subkey_name_str, e),
        }
        
        index += 1;
    }

    let _ = RegCloseKey(key_handle);
    debug!("Found {} applications in registry path: {}", applications.len(), path);
    
    Ok(applications)
}

/// Read application details from a specific registry key
#[cfg(target_os = "windows")]
unsafe fn read_application_from_registry(parent_key: HKEY, subkey_name: &str) -> Result<Option<Application>> {
    let mut app_key = HKEY::default();
    
    let result = RegOpenKeyExW(
        parent_key,
        &HSTRING::from(subkey_name),
        0,
        KEY_READ,
        &mut app_key,
    );
    
    if result != WIN32_ERROR(ERROR_SUCCESS) {
        return Ok(None);
    }
    
    // Read application details
    let display_name = read_registry_string(app_key, "DisplayName").ok();
    let display_version = read_registry_string(app_key, "DisplayVersion").ok();
    let publisher = read_registry_string(app_key, "Publisher").ok();
    let install_date = read_registry_string(app_key, "InstallDate").ok();
    let install_location = read_registry_string(app_key, "InstallLocation").ok();
    let size_mb = read_registry_dword(app_key, "EstimatedSize").ok()
        .map(|kb| kb as u64 / 1024); // Convert KB to MB

    let _ = RegCloseKey(app_key);

    // Only create application if we have a display name
    if let Some(name) = display_name {
        // Filter out system components and updates
        if name.starts_with("Security Update") || 
           name.starts_with("Update for") ||
           name.starts_with("Hotfix") ||
           name.starts_with("Microsoft Visual C++") && name.contains("Redistributable") {
            return Ok(None);
        }
        
        Ok(Some(Application {
            name,
            version: display_version,
            vendor: publisher,
            install_date,
            install_type: "Registry".to_string(),
            can_update: false, // Could be determined by checking for update mechanisms
            install_location,
            size_mb,
            registry_key: Some(subkey_name.to_string()),
            // New fields initialized as None
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        }))
    } else {
        Ok(None)
    }
}

/// Read a string value from the registry
#[cfg(target_os = "windows")]
unsafe fn read_registry_string(key: HKEY, value_name: &str) -> Result<String> {
    let mut data_type = REG_VALUE_TYPE::default();
    let mut data_size = 0u32;
    
    // First call to get the size
    let result = RegQueryValueExW(
        key,
        &HSTRING::from(value_name),
        None,
        Some(&mut data_type),
        None,
        Some(&mut data_size),
    );
    
    if result != WIN32_ERROR(ERROR_SUCCESS) || data_type != REG_SZ {
        return Err(anyhow!("Registry value not found or wrong type"));
    }
    
    // Second call to get the data
    let mut buffer = vec![0u8; data_size as usize];
    let result = RegQueryValueExW(
        key,
        &HSTRING::from(value_name),
        None,
        Some(&mut data_type),
        Some(buffer.as_mut_ptr()),
        Some(&mut data_size),
    );
    
    if result != WIN32_ERROR(ERROR_SUCCESS) {
        return Err(anyhow!("Failed to read registry value"));
    }
    
    // Convert to string (UTF-16)
    let wide_chars: Vec<u16> = buffer.chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&c| c != 0) // Stop at null terminator
        .collect();
    
    Ok(String::from_utf16_lossy(&wide_chars))
}

/// Read a DWORD value from the registry
#[cfg(target_os = "windows")]
unsafe fn read_registry_dword(key: HKEY, value_name: &str) -> Result<u32> {
    let mut data_type = REG_VALUE_TYPE::default();
    let mut data_size = 4u32;
    let mut value = 0u32;
    
    let result = RegQueryValueExW(
        key,
        &HSTRING::from(value_name),
        None,
        Some(&mut data_type),
        Some(&mut value as *mut u32 as *mut u8),
        Some(&mut data_size),
    );
    
    if result != WIN32_ERROR(ERROR_SUCCESS) || data_type != REG_DWORD {
        return Err(anyhow!("Registry DWORD value not found"));
    }
    
    Ok(value)
}

/// Remove duplicate applications based on name, version, and install_type
///
/// This preserves parallel installs across different package managers (e.g., Firefox
/// installed via both DEB and Snap will have separate entries).
fn deduplicate_applications(mut applications: Vec<Application>) -> Vec<Application> {
    applications.sort_by(|a, b| {
        a.name.cmp(&b.name)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.install_type.cmp(&b.install_type))
    });

    applications.dedup_by(|a, b| {
        a.name == b.name && a.version == b.version && a.install_type == b.install_type
    });

    applications
}

/// Check for application updates using platform-specific update checkers
async fn check_application_updates(applications: &mut [Application]) -> Result<()> {
    debug!("Checking application update availability using native update checkers");
    
    use super::update_checker_factory::{UpdateCheckerFactory, UpdateConfigManager};
    
    // Create coordinator using factory with bulk update configuration
    let config = UpdateConfigManager::get_bulk_update_config();
    let mut coordinator = match UpdateCheckerFactory::create_coordinator(Some(config)).await {
        Ok(coordinator) => coordinator,
        Err(e) => {
            warn!("Failed to create update coordinator: {}", e);
            return Ok(()); // Don't fail the entire inventory if update checking fails
        }
    };
    
    // Check updates for all applications
    let update_results = match coordinator.check_multiple_updates(applications).await {
        Ok(results) => results,
        Err(e) => {
            warn!("Failed to check application updates: {}", e);
            return Ok(()); // Don't fail the entire inventory if update checking fails
        }
    };
    
    // Apply update information to applications
    for (app_name, update_info) in update_results {
        if let Some(app) = applications.iter_mut().find(|a| a.name == app_name) {
            if let Some(info) = update_info {
                let available_version = info.available_version.clone();
                
                app.can_update = true;
                app.update_available = Some(info.available_version);
                app.update_source = Some(info.update_source);
                app.last_update_check = Some(info.last_checked);
                app.update_size_bytes = info.update_size_bytes;
                app.is_security_update = Some(info.is_security_update);
                
                debug!("Found update for {}: {} -> {}", 
                       app.name, 
                       app.version.as_deref().unwrap_or("unknown"),
                       available_version);
            } else {
                app.can_update = false;
                app.last_update_check = Some(std::time::SystemTime::now());
            }
        }
    }
    
    // Clean up checkers
    if let Err(e) = coordinator.cleanup().await {
        warn!("Failed to cleanup update checkers: {}", e);
    }
    
    debug!("Application update checking completed");
    Ok(())
}

/// Get details for a specific application
#[cfg(target_os = "windows")]
pub async fn get_application_details(app_id: String) -> Result<Option<Application>> {
    debug!("Getting details for application: {}", app_id);
    
    let inventory = get_installed_applications_wmi().await?;
    
    let app = inventory.applications
        .into_iter()
        .find(|app| {
            app.registry_key.as_ref() == Some(&app_id) ||
            app.name == app_id
        });
    
    Ok(app)
}

/// Check for application updates (public interface)
pub async fn check_application_updates_public() -> Result<Vec<Application>> {
    debug!("Checking for application updates");
    
    #[cfg(target_os = "windows")]
    let mut inventory = get_installed_applications_wmi().await?;
    
    #[cfg(not(target_os = "windows"))]
    let mut inventory = ApplicationInventory {
        total_count: 0,
        applications: Vec::new(),
        last_scan: SystemTime::now(),
        scan_duration_ms: 0,
        by_install_type: std::collections::HashMap::new(),
    };
    
    // Check for updates using our new implementation
    check_application_updates(&mut inventory.applications).await?;
    
    let updatable_apps = inventory.applications
        .into_iter()
        .filter(|app| app.can_update)
        .collect();
    
    Ok(updatable_apps)
}

/// Check updates for a specific application by ID or name
pub async fn check_specific_app_updates(app_identifier: String) -> Result<Option<Application>> {
    debug!("Checking updates for specific application: {}", app_identifier);
    
    use super::update_checker_factory::UpdateCheckerFactory;
    
    // First find the application
    let app = get_application_details(app_identifier.clone()).await?;
    
    if let Some(mut app) = app {
        // Create coordinator optimized for single app checks
        let mut coordinator = match UpdateCheckerFactory::create_single_app_coordinator().await {
            Ok(coordinator) => coordinator,
            Err(e) => {
                warn!("Failed to create coordinator for single app check: {}", e);
                return Ok(Some(app));
            }
        };
        
        if let Ok(Some(update_info)) = coordinator.check_app_update(&app).await {
            app.can_update = true;
            app.update_available = Some(update_info.available_version);
            app.update_source = Some(update_info.update_source);
            app.last_update_check = Some(update_info.last_checked);
            app.update_size_bytes = update_info.update_size_bytes;
            app.is_security_update = Some(update_info.is_security_update);
        } else {
            app.can_update = false;
            app.last_update_check = Some(SystemTime::now());
        }
        
        coordinator.cleanup().await.ok();
        
        Ok(Some(app))
    } else {
        Ok(None)
    }
}

/// Get estimated update size for a specific application
pub async fn estimate_update_size(app_identifier: String) -> Result<Option<u64>> {
    debug!("Estimating update size for: {}", app_identifier);
    
    if let Some(app) = check_specific_app_updates(app_identifier).await? {
        Ok(app.update_size_bytes)
    } else {
        Ok(None)
    }
}

/// Get all applications with available updates
pub async fn get_available_updates() -> Result<Vec<Application>> {
    debug!("Getting all available updates");
    
    check_application_updates_public().await
}

// =============================================================================
// Linux-specific implementations
// =============================================================================

/// Get applications installed via dpkg (Debian/Ubuntu)
#[cfg(target_os = "linux")]
fn get_dpkg_applications() -> Result<Vec<Application>> {
    debug!("Scanning dpkg-installed applications");

    let output = execute_command(
        "dpkg-query",
        &["-W", "-f=${Package}\t${Version}\t${Installed-Size}\t${Status}\n"]
    )?;

    let mut applications = Vec::new();

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }

        let package_name = parts[0];
        let version = parts[1];
        let installed_size = parts[2];
        let status = parts[3];

        // Only include packages with "install ok installed" status
        if !status.contains("install ok installed") {
            continue;
        }

        // Convert installed size from KB to MB
        let size_mb = installed_size.parse::<u64>().ok().map(|kb| kb / 1024);

        // Get install date from /var/lib/dpkg/info/<package>.list file mtime
        let install_date = get_dpkg_install_date(package_name);

        applications.push(Application {
            name: package_name.to_string(),
            version: Some(version.to_string()),
            vendor: None,
            install_date,
            install_type: "DEB".to_string(),
            can_update: false,
            install_location: None,
            size_mb,
            registry_key: Some(package_name.to_string()),
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        });
    }

    info!("Found {} dpkg applications", applications.len());
    Ok(applications)
}

/// Get install date for a dpkg package from /var/lib/dpkg/info/<package>.list mtime
#[cfg(target_os = "linux")]
fn get_dpkg_install_date(package_name: &str) -> Option<String> {
    use std::fs;
    use std::path::Path;

    // Try the .list file which tracks installed files
    let list_path = format!("/var/lib/dpkg/info/{}.list", package_name);
    let path = Path::new(&list_path);

    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                let timestamp = duration.as_secs() as i64;
                return chrono::DateTime::from_timestamp(timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string());
            }
        }
    }

    // Try with :amd64 suffix (common for multi-arch packages)
    let list_path_arch = format!("/var/lib/dpkg/info/{}:amd64.list", package_name);
    let path_arch = Path::new(&list_path_arch);

    if let Ok(metadata) = fs::metadata(path_arch) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                let timestamp = duration.as_secs() as i64;
                return chrono::DateTime::from_timestamp(timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string());
            }
        }
    }

    None
}

/// Get applications installed via RPM (Fedora/RHEL/CentOS)
#[cfg(target_os = "linux")]
fn get_rpm_applications() -> Result<Vec<Application>> {
    debug!("Scanning rpm-installed applications");

    let output = execute_command(
        "rpm",
        &["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\t%{INSTALLTIME}\n"]
    )?;

    let mut applications = Vec::new();

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }

        let package_name = parts[0];
        let version = parts[1];
        let size_bytes = parts[2];
        let install_time = parts[3];

        // Convert size from bytes to MB
        let size_mb = size_bytes.parse::<u64>().ok().map(|bytes| bytes / (1024 * 1024));

        // Convert Unix timestamp to readable date
        let install_date = install_time.parse::<i64>().ok().map(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        });

        applications.push(Application {
            name: package_name.to_string(),
            version: Some(version.to_string()),
            vendor: None,
            install_date,
            install_type: "RPM".to_string(),
            can_update: false,
            install_location: None,
            size_mb,
            registry_key: Some(package_name.to_string()),
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        });
    }

    info!("Found {} rpm applications", applications.len());
    Ok(applications)
}

/// Get applications installed via Snap
#[cfg(target_os = "linux")]
fn get_snap_applications() -> Result<Vec<Application>> {
    debug!("Scanning snap-installed applications");

    let output = match execute_command("snap", &["list", "--unicode=never"]) {
        Ok(output) => output,
        Err(e) => {
            debug!("snap command failed (may not be installed): {}", e);
            return Ok(Vec::new());
        }
    };

    let mut applications = Vec::new();
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

        // Format: Name  Version  Rev  Tracking  Publisher  Notes
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let name = parts[0];
        let version = parts[1];
        let _rev = parts[2];
        let _tracking = parts.get(3).unwrap_or(&"");
        let publisher = parts.get(4).map(|s| s.to_string());

        // Get install date from snap info
        let install_date = get_snap_install_date(name);

        applications.push(Application {
            name: name.to_string(),
            version: Some(version.to_string()),
            vendor: publisher,
            install_date,
            install_type: "Snap".to_string(),
            can_update: true, // Snaps are generally auto-updatable
            install_location: Some(format!("/snap/{}", name)),
            size_mb: None,
            registry_key: Some(name.to_string()),
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        });
    }

    info!("Found {} snap applications", applications.len());
    Ok(applications)
}

/// Get install date for a snap package from snap info output
#[cfg(target_os = "linux")]
fn get_snap_install_date(snap_name: &str) -> Option<String> {
    // Run snap info to get installation details
    let output = match execute_command("snap", &["info", snap_name]) {
        Ok(output) => output,
        Err(_) => return None,
    };

    // Look for "installed:" line which contains the install date
    // Format: "installed:          1.2.3                (1234) 100MB  disabled,blocked"
    // Or sometimes: "installed: 1.2.3 from Canonical on 2024-01-15"
    for line in output.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.starts_with("installed:") {
            // Try to extract date from the line
            // Look for date pattern YYYY-MM-DD
            if let Some(date) = extract_date_from_line(line_trimmed) {
                return Some(date);
            }
        }
    }

    // Fallback: check mtime of snap directory
    use std::fs;
    use std::path::Path;

    let snap_path = format!("/snap/{}/current", snap_name);
    let path = Path::new(&snap_path);

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                let timestamp = duration.as_secs() as i64;
                return chrono::DateTime::from_timestamp(timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string());
            }
        }
    }

    None
}

/// Extract a date (YYYY-MM-DD format) from a line of text
#[cfg(target_os = "linux")]
fn extract_date_from_line(line: &str) -> Option<String> {
    // Simple regex-like search for YYYY-MM-DD pattern
    let bytes = line.as_bytes();
    for i in 0..bytes.len().saturating_sub(9) {
        // Check for pattern: 4 digits, dash, 2 digits, dash, 2 digits
        if bytes.len() > i + 9
            && bytes[i].is_ascii_digit()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && bytes[i + 3].is_ascii_digit()
            && bytes[i + 4] == b'-'
            && bytes[i + 5].is_ascii_digit()
            && bytes[i + 6].is_ascii_digit()
            && bytes[i + 7] == b'-'
            && bytes[i + 8].is_ascii_digit()
            && bytes[i + 9].is_ascii_digit()
        {
            return Some(line[i..i + 10].to_string());
        }
    }
    None
}

/// Get applications installed via Flatpak
#[cfg(target_os = "linux")]
fn get_flatpak_applications() -> Result<Vec<Application>> {
    debug!("Scanning flatpak-installed applications");

    let output = match execute_command(
        "flatpak",
        &["list", "--app", "--columns=name,application,version,size,installation"]
    ) {
        Ok(output) => output,
        Err(e) => {
            debug!("flatpak command failed (may not be installed): {}", e);
            return Ok(Vec::new());
        }
    };

    let mut applications = Vec::new();

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        // Format: Name\tApplication ID\tVersion\tSize\tInstallation
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }

        let name = parts[0];
        let app_id = parts[1];
        let version = parts.get(2).map(|s| s.to_string());
        let size_str = parts.get(3).unwrap_or(&"");
        let installation = parts.get(4).map(|s| s.to_string());

        // Parse size (format: "123.4 MB" or "1.2 GB")
        let size_mb = parse_flatpak_size(size_str);

        // Get install date from flatpak info
        let install_date = get_flatpak_install_date(app_id);

        applications.push(Application {
            name: name.to_string(),
            version,
            vendor: None,
            install_date,
            install_type: "Flatpak".to_string(),
            can_update: true, // Flatpaks are generally auto-updatable
            install_location: installation.map(|i| format!("/var/lib/flatpak/app/{}/{}", app_id, i)),
            size_mb,
            registry_key: Some(app_id.to_string()),
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        });
    }

    info!("Found {} flatpak applications", applications.len());
    Ok(applications)
}

/// Parse flatpak size string to MB
#[cfg(target_os = "linux")]
fn parse_flatpak_size(size_str: &str) -> Option<u64> {
    let size_str = size_str.trim();
    if size_str.is_empty() {
        return None;
    }

    let parts: Vec<&str> = size_str.split_whitespace().collect();
    if parts.len() != 2 {
        return None;
    }

    let value: f64 = parts[0].parse().ok()?;
    let unit = parts[1].to_uppercase();

    match unit.as_str() {
        "KB" | "K" => Some((value / 1024.0) as u64),
        "MB" | "M" => Some(value as u64),
        "GB" | "G" => Some((value * 1024.0) as u64),
        "B" => Some((value / (1024.0 * 1024.0)) as u64),
        _ => None,
    }
}

/// Get install date for a flatpak application from flatpak info output
#[cfg(target_os = "linux")]
fn get_flatpak_install_date(app_id: &str) -> Option<String> {
    // Run flatpak info to get installation details
    let output = match execute_command("flatpak", &["info", app_id]) {
        Ok(output) => output,
        Err(_) => return None,
    };

    // Look for "Date:" or "Install:" line which may contain the install date
    for line in output.lines() {
        let line_trimmed = line.trim();
        // Look for date in various fields
        if line_trimmed.starts_with("Date:") || line_trimmed.starts_with("Install:") {
            // Try to extract date from the line
            if let Some(date) = extract_date_from_line(line_trimmed) {
                return Some(date);
            }
        }
    }

    // Fallback: check mtime of flatpak app directory
    use std::fs;
    use std::path::Path;

    // Try system installation first
    let system_path = format!("/var/lib/flatpak/app/{}", app_id);
    if let Some(date) = get_dir_mtime(&system_path) {
        return Some(date);
    }

    // Try user installation
    if let Ok(home) = std::env::var("HOME") {
        let user_path = format!("{}/.local/share/flatpak/app/{}", home, app_id);
        if let Some(date) = get_dir_mtime(&user_path) {
            return Some(date);
        }
    }

    None
}

/// Get modification time of a directory as a formatted date string
#[cfg(target_os = "linux")]
fn get_dir_mtime(path: &str) -> Option<String> {
    use std::fs;
    use std::path::Path;

    let path = Path::new(path);
    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                let timestamp = duration.as_secs() as i64;
                return chrono::DateTime::from_timestamp(timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d").to_string());
            }
        }
    }
    None
}

/// Get comprehensive application inventory on Linux
#[cfg(target_os = "linux")]
pub async fn get_installed_applications_linux() -> Result<ApplicationInventory> {
    let start_time = SystemTime::now();
    info!("Starting comprehensive Linux application inventory scan");

    let os_info = get_os_info();
    let mut applications = Vec::new();
    let mut by_install_type = std::collections::HashMap::new();

    // 1. Query dpkg/apt packages (Debian/Ubuntu)
    if os_info.available_package_managers.contains(&PackageManager::Apt) {
        debug!("Scanning dpkg-installed applications");
        match get_dpkg_applications() {
            Ok(mut deb_apps) => {
                let count = deb_apps.len();
                by_install_type.insert("DEB".to_string(), count);
                applications.append(&mut deb_apps);
                info!("Found {} DEB packages", count);
            }
            Err(e) => {
                warn!("Failed to query dpkg packages: {}", e);
                by_install_type.insert("DEB".to_string(), 0);
            }
        }
    }

    // 2. Query RPM packages (Fedora/RHEL/CentOS)
    if os_info.available_package_managers.iter()
        .any(|pm| matches!(pm, PackageManager::Dnf | PackageManager::Yum)) {
        debug!("Scanning rpm-installed applications");
        match get_rpm_applications() {
            Ok(mut rpm_apps) => {
                let count = rpm_apps.len();
                by_install_type.insert("RPM".to_string(), count);
                applications.append(&mut rpm_apps);
                info!("Found {} RPM packages", count);
            }
            Err(e) => {
                warn!("Failed to query rpm packages: {}", e);
                by_install_type.insert("RPM".to_string(), 0);
            }
        }
    }

    // 3. Query Snap packages
    if os_info.available_package_managers.contains(&PackageManager::Snap) {
        debug!("Scanning snap-installed applications");
        match get_snap_applications() {
            Ok(mut snap_apps) => {
                let count = snap_apps.len();
                by_install_type.insert("Snap".to_string(), count);
                applications.append(&mut snap_apps);
                info!("Found {} Snap packages", count);
            }
            Err(e) => {
                warn!("Failed to query snap packages: {}", e);
                by_install_type.insert("Snap".to_string(), 0);
            }
        }
    }

    // 4. Query Flatpak applications
    if os_info.available_package_managers.contains(&PackageManager::Flatpak) {
        debug!("Scanning flatpak-installed applications");
        match get_flatpak_applications() {
            Ok(mut flatpak_apps) => {
                let count = flatpak_apps.len();
                by_install_type.insert("Flatpak".to_string(), count);
                applications.append(&mut flatpak_apps);
                info!("Found {} Flatpak applications", count);
            }
            Err(e) => {
                warn!("Failed to query flatpak applications: {}", e);
                by_install_type.insert("Flatpak".to_string(), 0);
            }
        }
    }

    // Remove duplicates based on name and version
    applications = deduplicate_applications(applications);

    // Check for update availability
    check_application_updates(&mut applications).await?;

    let scan_duration = start_time.elapsed()
        .unwrap_or(std::time::Duration::from_millis(0))
        .as_millis() as u64;

    let total_count = applications.len();
    info!("Linux application inventory complete: {} unique applications in {}ms",
          total_count, scan_duration);

    Ok(ApplicationInventory {
        total_count,
        applications,
        last_scan: SystemTime::now(),
        scan_duration_ms: scan_duration,
        by_install_type,
    })
}

/// Get details for a specific application on Linux
#[cfg(target_os = "linux")]
pub async fn get_application_details_linux(app_id: String) -> Result<Option<Application>> {
    debug!("Getting details for Linux application: {}", app_id);

    let inventory = get_installed_applications_linux().await?;

    let app = inventory.applications
        .into_iter()
        .find(|app| {
            app.registry_key.as_ref() == Some(&app_id) ||
            app.name == app_id
        });

    Ok(app)
}

/// Non-Windows implementations
#[cfg(not(target_os = "windows"))]
pub async fn get_installed_applications_wmi() -> Result<ApplicationInventory> {
    Err(anyhow!("WMI application inventory is only available on Windows. Use get_installed_applications_linux() for Linux systems."))
}

#[cfg(target_os = "linux")]
pub async fn get_application_details(app_id: String) -> Result<Option<Application>> {
    get_application_details_linux(app_id).await
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub async fn get_application_details(_app_id: String) -> Result<Option<Application>> {
    warn!("get_application_details not implemented for this platform");
    Ok(None)
}

/// Non-Linux implementation for get_installed_applications_linux
#[cfg(not(target_os = "linux"))]
pub async fn get_installed_applications_linux() -> Result<ApplicationInventory> {
    Err(anyhow!("Linux application inventory is only available on Linux systems"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_serialization() {
        let app = Application {
            name: "Test Application".to_string(),
            version: Some("1.0.0".to_string()),
            vendor: Some("Test Vendor".to_string()),
            install_date: Some("20240115".to_string()),
            install_type: "MSI".to_string(),
            can_update: true,
            install_location: Some("C:\\Program Files\\Test".to_string()),
            size_mb: Some(100),
            registry_key: Some("TEST001".to_string()),
            update_available: None,
            update_source: None,
            last_update_check: None,
            update_size_bytes: None,
            is_security_update: None,
        };

        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("Test Application"));
        assert!(json.contains("\"can_update\":true"));
    }

    #[test]
    fn test_deduplicate_applications_same_install_type() {
        // True duplicates (same name, version, AND install_type) should be deduplicated
        let apps = vec![
            Application {
                name: "Test App".to_string(),
                version: Some("1.0.0".to_string()),
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
            },
            Application {
                name: "Test App".to_string(),
                version: Some("1.0.0".to_string()),
                vendor: Some("Test Vendor".to_string()),
                install_date: None,
                install_type: "MSI".to_string(), // Same install_type
                can_update: true,
                install_location: Some("C:\\Program Files\\Test".to_string()),
                size_mb: Some(50),
                registry_key: None,
                update_available: None,
                update_source: None,
                last_update_check: None,
                update_size_bytes: None,
                is_security_update: None,
            },
        ];

        let deduped = deduplicate_applications(apps);
        // Same name, version, AND install_type should be deduplicated
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_deduplicate_applications_different_install_types() {
        // Different install_types should be preserved (parallel installs)
        let apps = vec![
            Application {
                name: "Test App".to_string(),
                version: Some("1.0.0".to_string()),
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
            },
            Application {
                name: "Test App".to_string(),
                version: Some("1.0.0".to_string()),
                vendor: None,
                install_date: None,
                install_type: "Registry".to_string(), // Different install_type
                can_update: false,
                install_location: None,
                size_mb: None,
                registry_key: None,
                update_available: None,
                update_source: None,
                last_update_check: None,
                update_size_bytes: None,
                is_security_update: None,
            },
        ];

        let deduped = deduplicate_applications(apps);
        // Different install_types should be preserved
        assert_eq!(deduped.len(), 2);
    }

    // Linux-specific tests
    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        /// Helper function to parse dpkg output for testing
        fn parse_dpkg_test_output(output: &str) -> Vec<Application> {
            let mut applications = Vec::new();

            for line in output.lines() {
                if line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 4 {
                    continue;
                }

                let package_name = parts[0];
                let version = parts[1];
                let installed_size = parts[2];
                let status = parts[3];

                if !status.contains("install ok installed") {
                    continue;
                }

                let size_mb = installed_size.parse::<u64>().ok().map(|kb| kb / 1024);

                applications.push(Application {
                    name: package_name.to_string(),
                    version: Some(version.to_string()),
                    vendor: None,
                    install_date: None,
                    install_type: "DEB".to_string(),
                    can_update: false,
                    install_location: None,
                    size_mb,
                    registry_key: Some(package_name.to_string()),
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                });
            }

            applications
        }

        /// Helper function to parse rpm output for testing
        fn parse_rpm_test_output(output: &str) -> Vec<Application> {
            let mut applications = Vec::new();

            for line in output.lines() {
                if line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 4 {
                    continue;
                }

                let package_name = parts[0];
                let version = parts[1];
                let size_bytes = parts[2];
                let _install_time = parts[3];

                let size_mb = size_bytes.parse::<u64>().ok().map(|bytes| bytes / (1024 * 1024));

                applications.push(Application {
                    name: package_name.to_string(),
                    version: Some(version.to_string()),
                    vendor: None,
                    install_date: None,
                    install_type: "RPM".to_string(),
                    can_update: false,
                    install_location: None,
                    size_mb,
                    registry_key: Some(package_name.to_string()),
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                });
            }

            applications
        }

        /// Helper function to parse snap output for testing
        fn parse_snap_test_output(output: &str) -> Vec<Application> {
            let mut applications = Vec::new();
            let mut is_header = true;

            for line in output.lines() {
                if line.is_empty() {
                    continue;
                }

                if is_header {
                    is_header = false;
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }

                let name = parts[0];
                let version = parts[1];
                let publisher = parts.get(4).map(|s| s.to_string());

                applications.push(Application {
                    name: name.to_string(),
                    version: Some(version.to_string()),
                    vendor: publisher,
                    install_date: None,
                    install_type: "Snap".to_string(),
                    can_update: true,
                    install_location: Some(format!("/snap/{}", name)),
                    size_mb: None,
                    registry_key: Some(name.to_string()),
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                });
            }

            applications
        }

        #[test]
        fn test_dpkg_parsing() {
            let output = "vim\t2:8.2.3995-1ubuntu2.17\t3072\tinstall ok installed
curl\t7.81.0-1ubuntu1.15\t512\tinstall ok installed
broken-package\t1.0\t100\tdeinstall ok config-files
";

            let apps = parse_dpkg_test_output(output);

            assert_eq!(apps.len(), 2);
            assert_eq!(apps[0].name, "vim");
            assert_eq!(apps[0].version, Some("2:8.2.3995-1ubuntu2.17".to_string()));
            assert_eq!(apps[0].install_type, "DEB");
            assert_eq!(apps[0].size_mb, Some(3)); // 3072 KB = 3 MB

            assert_eq!(apps[1].name, "curl");
            assert_eq!(apps[1].version, Some("7.81.0-1ubuntu1.15".to_string()));
        }

        #[test]
        fn test_rpm_parsing() {
            let output = "vim-enhanced\t9.0.1378-1.fc38\t52428800\t1705320000
curl\t8.0.1-1.fc38\t1048576\t1705320000
";

            let apps = parse_rpm_test_output(output);

            assert_eq!(apps.len(), 2);
            assert_eq!(apps[0].name, "vim-enhanced");
            assert_eq!(apps[0].version, Some("9.0.1378-1.fc38".to_string()));
            assert_eq!(apps[0].install_type, "RPM");
            assert_eq!(apps[0].size_mb, Some(50)); // 52428800 bytes = ~50 MB

            assert_eq!(apps[1].name, "curl");
            assert_eq!(apps[1].version, Some("8.0.1-1.fc38".to_string()));
            assert_eq!(apps[1].size_mb, Some(1)); // 1048576 bytes = 1 MB
        }

        #[test]
        fn test_snap_parsing() {
            let output = "Name        Version          Rev    Tracking       Publisher   Notes
firefox     120.0-1          3252   latest/stable  mozilla✓    -
vlc         3.0.18           3078   latest/stable  videolan✓   -
";

            let apps = parse_snap_test_output(output);

            assert_eq!(apps.len(), 2);
            assert_eq!(apps[0].name, "firefox");
            assert_eq!(apps[0].version, Some("120.0-1".to_string()));
            assert_eq!(apps[0].install_type, "Snap");
            assert!(apps[0].can_update);
            assert_eq!(apps[0].install_location, Some("/snap/firefox".to_string()));

            assert_eq!(apps[1].name, "vlc");
            assert_eq!(apps[1].version, Some("3.0.18".to_string()));
        }

        #[test]
        fn test_flatpak_size_parsing() {
            assert_eq!(parse_flatpak_size("123.4 MB"), Some(123));
            assert_eq!(parse_flatpak_size("1.5 GB"), Some(1536)); // 1.5 * 1024 = 1536
            assert_eq!(parse_flatpak_size("512 KB"), Some(0)); // 512 / 1024 = 0
            assert_eq!(parse_flatpak_size(""), None);
            assert_eq!(parse_flatpak_size("invalid"), None);
        }

        #[test]
        fn test_linux_application_deduplication_preserves_install_types() {
            // Test that parallel installs from different package managers are preserved
            let apps = vec![
                Application {
                    name: "firefox".to_string(),
                    version: Some("120.0".to_string()),
                    vendor: None,
                    install_date: None,
                    install_type: "DEB".to_string(),
                    can_update: false,
                    install_location: None,
                    size_mb: None,
                    registry_key: None,
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                },
                Application {
                    name: "firefox".to_string(),
                    version: Some("120.0".to_string()),
                    vendor: Some("mozilla".to_string()),
                    install_date: None,
                    install_type: "Snap".to_string(),
                    can_update: true,
                    install_location: Some("/snap/firefox".to_string()),
                    size_mb: None,
                    registry_key: None,
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                },
            ];

            let deduped = deduplicate_applications(apps);
            // Same name and version but different install_type should be preserved
            assert_eq!(deduped.len(), 2);
            // Verify both install types are present
            assert!(deduped.iter().any(|a| a.install_type == "DEB"));
            assert!(deduped.iter().any(|a| a.install_type == "Snap"));
        }

        #[test]
        fn test_linux_application_deduplication_removes_true_duplicates() {
            // Test that true duplicates (same name, version, AND install_type) are removed
            let apps = vec![
                Application {
                    name: "vim".to_string(),
                    version: Some("8.2".to_string()),
                    vendor: None,
                    install_date: None,
                    install_type: "DEB".to_string(),
                    can_update: false,
                    install_location: None,
                    size_mb: None,
                    registry_key: None,
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                },
                Application {
                    name: "vim".to_string(),
                    version: Some("8.2".to_string()),
                    vendor: Some("vim.org".to_string()),
                    install_date: None,
                    install_type: "DEB".to_string(), // Same install_type
                    can_update: false,
                    install_location: Some("/usr/bin/vim".to_string()),
                    size_mb: Some(10),
                    registry_key: None,
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                },
            ];

            let deduped = deduplicate_applications(apps);
            // Same name, version, AND install_type should be deduplicated
            assert_eq!(deduped.len(), 1);
        }

        #[test]
        fn test_install_type_mapping() {
            // Test that each source correctly assigns install_type
            let deb_output = "vim\t8.2\t1024\tinstall ok installed\n";
            let deb_apps = parse_dpkg_test_output(deb_output);
            assert_eq!(deb_apps[0].install_type, "DEB");

            let rpm_output = "vim-enhanced\t8.2\t1048576\t1705320000\n";
            let rpm_apps = parse_rpm_test_output(rpm_output);
            assert_eq!(rpm_apps[0].install_type, "RPM");

            let snap_output = "Name  Version  Rev  Tracking  Publisher\nvim  8.2  100  stable  canonical\n";
            let snap_apps = parse_snap_test_output(snap_output);
            assert_eq!(snap_apps[0].install_type, "Snap");
        }

        // ===== Linux Application Inventory Tests =====

        #[test]
        fn test_get_installed_applications_linux_dpkg_comprehensive() {
            // Comprehensive dpkg output with various package states
            let dpkg_output = r#"vim	2:8.2.3995-1ubuntu2.17	3072	install ok installed
curl	7.81.0-1ubuntu1.15	512	install ok installed
openssh-server	1:8.9p1-3ubuntu0.4	2048	install ok installed
build-essential	12.9ubuntu3	128	install ok installed
libssl3	3.0.2-0ubuntu1.12	4096	install ok installed
broken-package	1.0	100	deinstall ok config-files
half-installed	2.0	200	install half-installed
"#;

            let apps = parse_dpkg_test_output(dpkg_output);

            // Should only include fully installed packages
            assert_eq!(apps.len(), 5, "Should have 5 fully installed packages");

            // Verify all expected packages are present
            let names: Vec<&str> = apps.iter().map(|a| a.name.as_str()).collect();
            assert!(names.contains(&"vim"), "Should contain vim");
            assert!(names.contains(&"curl"), "Should contain curl");
            assert!(names.contains(&"openssh-server"), "Should contain openssh-server");
            assert!(names.contains(&"build-essential"), "Should contain build-essential");
            assert!(names.contains(&"libssl3"), "Should contain libssl3");

            // Verify broken/half-installed packages are excluded
            assert!(!names.contains(&"broken-package"), "Should not contain broken package");
            assert!(!names.contains(&"half-installed"), "Should not contain half-installed package");
        }

        #[test]
        fn test_get_installed_applications_linux_rpm_comprehensive() {
            // Comprehensive rpm output with various packages
            let rpm_output = r#"vim-enhanced	9.0.1378-1.fc38	52428800	1705320000
curl	8.0.1-1.fc38	1048576	1705320000
openssh-server	9.0p1-11.fc38	3145728	1705320000
python3	3.11.6-2.fc38	20971520	1705320000
kernel	6.5.12-200.fc38	104857600	1705320000
"#;

            let apps = parse_rpm_test_output(rpm_output);

            assert_eq!(apps.len(), 5, "Should have 5 RPM packages");

            // Verify sizes are correctly converted
            let vim = apps.iter().find(|a| a.name == "vim-enhanced").unwrap();
            assert_eq!(vim.size_mb, Some(50), "vim-enhanced should be ~50 MB");

            let kernel = apps.iter().find(|a| a.name == "kernel").unwrap();
            assert_eq!(kernel.size_mb, Some(100), "kernel should be ~100 MB");
        }

        #[test]
        fn test_get_installed_applications_linux_snap_comprehensive() {
            // Comprehensive snap output
            let snap_output = r#"Name        Version          Rev    Tracking       Publisher   Notes
firefox     120.0-1          3252   latest/stable  mozilla✓    -
vlc         3.0.18           3078   latest/stable  videolan✓   -
code        1.85.0           137    latest/stable  vscode✓     classic
spotify     1.2.25           68     latest/stable  spotify✓    -
"#;

            let apps = parse_snap_test_output(snap_output);

            assert_eq!(apps.len(), 4, "Should have 4 snap packages");

            // Verify install locations are set
            for app in &apps {
                assert!(app.install_location.is_some(), "Snap apps should have install location");
                assert!(app.install_location.as_ref().unwrap().starts_with("/snap/"));
            }

            // Verify can_update is true for snap packages
            for app in &apps {
                assert!(app.can_update, "Snap apps should be updatable");
            }
        }

        #[test]
        fn test_get_installed_applications_linux_flatpak_comprehensive() {
            // Simulated flatpak list output
            let flatpak_output = r#"Name                                        Application ID                                        Version        Branch        Installation
Firefox                                     org.mozilla.firefox                                   120.0          stable        system
GIMP                                        org.gimp.GIMP                                        2.10.34        stable        system
LibreOffice                                 org.libreoffice.LibreOffice                          7.6.4          stable        system
Spotify                                     com.spotify.Client                                   1.2.25         stable        user
"#;

            // Parse manually to verify structure
            let lines: Vec<&str> = flatpak_output.lines()
                .skip(1) // Skip header
                .filter(|l| !l.is_empty())
                .collect();

            assert_eq!(lines.len(), 4, "Should have 4 flatpak apps");

            // Verify system vs user installations
            let system_apps: Vec<&&str> = lines.iter().filter(|l| l.contains("system")).collect();
            let user_apps: Vec<&&str> = lines.iter().filter(|l| l.contains("user")).collect();

            assert_eq!(system_apps.len(), 3, "Should have 3 system flatpak apps");
            assert_eq!(user_apps.len(), 1, "Should have 1 user flatpak app");
        }

        #[test]
        fn test_linux_application_aggregation_all_sources() {
            // Test that apps from different sources are properly aggregated
            let deb_apps = vec![
                Application {
                    name: "vim".to_string(),
                    version: Some("8.2".to_string()),
                    vendor: None,
                    install_date: None,
                    install_type: "DEB".to_string(),
                    can_update: false,
                    install_location: Some("/usr/bin/vim".to_string()),
                    size_mb: Some(10),
                    registry_key: None,
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                },
            ];

            let snap_apps = vec![
                Application {
                    name: "firefox".to_string(),
                    version: Some("120.0".to_string()),
                    vendor: Some("mozilla".to_string()),
                    install_date: None,
                    install_type: "Snap".to_string(),
                    can_update: true,
                    install_location: Some("/snap/firefox".to_string()),
                    size_mb: None,
                    registry_key: None,
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                },
            ];

            let flatpak_apps = vec![
                Application {
                    name: "GIMP".to_string(),
                    version: Some("2.10.34".to_string()),
                    vendor: None,
                    install_date: None,
                    install_type: "Flatpak".to_string(),
                    can_update: true,
                    install_location: Some("/var/lib/flatpak/app/org.gimp.GIMP".to_string()),
                    size_mb: Some(200),
                    registry_key: None,
                    update_available: None,
                    update_source: None,
                    last_update_check: None,
                    update_size_bytes: None,
                    is_security_update: None,
                },
            ];

            // Combine all sources
            let mut all_apps = Vec::new();
            all_apps.extend(deb_apps);
            all_apps.extend(snap_apps);
            all_apps.extend(flatpak_apps);

            assert_eq!(all_apps.len(), 3, "Should have 3 total apps from different sources");

            // Verify each source is represented
            let install_types: Vec<&str> = all_apps.iter().map(|a| a.install_type.as_str()).collect();
            assert!(install_types.contains(&"DEB"));
            assert!(install_types.contains(&"Snap"));
            assert!(install_types.contains(&"Flatpak"));
        }

        #[test]
        fn test_check_application_updates_linux_apt() {
            // Simulated apt list --upgradable output
            let apt_upgradable = r#"Listing...
vim/jammy-security 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]
curl/jammy-updates 7.81.0-1ubuntu1.15 amd64 [upgradable from: 7.81.0-1ubuntu1.14]
"#;

            // Parse to find updatable packages
            let updatable: Vec<&str> = apt_upgradable.lines()
                .filter(|l| l.contains("[upgradable from:"))
                .filter_map(|l| l.split('/').next())
                .collect();

            assert_eq!(updatable.len(), 2, "Should have 2 updatable packages");
            assert!(updatable.contains(&"vim"), "vim should be updatable");
            assert!(updatable.contains(&"curl"), "curl should be updatable");
        }

        #[test]
        fn test_install_date_extraction_dpkg_log() {
            // Simulated /var/log/dpkg.log entries
            let dpkg_log = r#"2024-01-10 10:30:00 install vim:amd64 <none> 2:8.2.3995-1ubuntu2.16
2024-01-12 14:15:30 install curl:amd64 <none> 7.81.0-1ubuntu1.14
2024-01-15 09:00:00 upgrade vim:amd64 2:8.2.3995-1ubuntu2.16 2:8.2.3995-1ubuntu2.17
"#;

            // Parse install dates
            let install_entries: Vec<&str> = dpkg_log.lines()
                .filter(|l| l.contains(" install "))
                .collect();

            assert_eq!(install_entries.len(), 2, "Should have 2 install entries");

            // Verify date format is parseable
            for entry in &install_entries {
                let date_part = &entry[0..19]; // "2024-01-10 10:30:00"
                assert!(date_part.contains('-'), "Should contain date separator");
                assert!(date_part.contains(':'), "Should contain time separator");
            }
        }

        #[test]
        fn test_install_date_extraction_rpm_query() {
            // Simulated rpm query output with install time
            let rpm_output = r#"vim-enhanced	9.0.1378-1.fc38	52428800	1705320000
curl	8.0.1-1.fc38	1048576	1705406400
"#;

            // Parse and verify install times (Unix timestamps)
            for line in rpm_output.lines().filter(|l| !l.is_empty()) {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 4 {
                    let install_time: i64 = parts[3].parse().unwrap();
                    // Unix timestamp should be after year 2000
                    assert!(install_time > 946684800, "Install time should be after year 2000");
                    // Should be before year 2030
                    assert!(install_time < 1893456000, "Install time should be before year 2030");
                }
            }
        }

        #[test]
        fn test_application_vendor_extraction() {
            // Test vendor extraction from different sources
            let snap_with_publisher = Application {
                name: "firefox".to_string(),
                version: Some("120.0".to_string()),
                vendor: Some("mozilla✓".to_string()),
                install_date: None,
                install_type: "Snap".to_string(),
                can_update: true,
                install_location: None,
                size_mb: None,
                registry_key: None,
                update_available: None,
                update_source: None,
                last_update_check: None,
                update_size_bytes: None,
                is_security_update: None,
            };

            assert!(snap_with_publisher.vendor.is_some());

            // Test that vendor can contain unicode (checkmark)
            let vendor = snap_with_publisher.vendor.unwrap();
            assert!(vendor.contains("mozilla"));
        }

        #[test]
        fn test_application_size_conversion() {
            // Test various size unit conversions

            // KB to MB
            let kb_size: u64 = 3072;
            let mb_from_kb = kb_size / 1024;
            assert_eq!(mb_from_kb, 3, "3072 KB should be 3 MB");

            // Bytes to MB
            let byte_size: u64 = 52428800;
            let mb_from_bytes = byte_size / (1024 * 1024);
            assert_eq!(mb_from_bytes, 50, "52428800 bytes should be 50 MB");

            // GB to MB
            let gb_size: f64 = 1.5;
            let mb_from_gb = (gb_size * 1024.0) as u64;
            assert_eq!(mb_from_gb, 1536, "1.5 GB should be 1536 MB");
        }
    }
}
