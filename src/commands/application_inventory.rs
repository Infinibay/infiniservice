//! Application inventory management via WMI and Registry
//!
//! This module provides functionality to discover installed applications
//! using WMI queries and Windows Registry access.

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
    
    if result != ERROR_SUCCESS {
        return Err(anyhow!("Failed to open registry key: {}", path));
    }
    
    let mut index = 0;
    loop {
        let mut subkey_name = [0u16; 256];
        let mut subkey_len = 256u32;
        
        let result = RegEnumKeyExW(
            key_handle,
            index,
            &mut subkey_name,
            &mut subkey_len,
            None,
            None,
            None,
            None,
        );
        
        if result != ERROR_SUCCESS {
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
    
    RegCloseKey(key_handle);
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
    
    if result != ERROR_SUCCESS {
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
    
    RegCloseKey(app_key);
    
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
    
    if result != ERROR_SUCCESS || data_type != REG_SZ {
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
    
    if result != ERROR_SUCCESS {
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
    
    if result != ERROR_SUCCESS || data_type != REG_DWORD {
        return Err(anyhow!("Registry DWORD value not found"));
    }
    
    Ok(value)
}

/// Remove duplicate applications based on name and version
fn deduplicate_applications(mut applications: Vec<Application>) -> Vec<Application> {
    applications.sort_by(|a, b| {
        a.name.cmp(&b.name)
            .then_with(|| a.version.cmp(&b.version))
    });
    
    applications.dedup_by(|a, b| {
        a.name == b.name && a.version == b.version
    });
    
    applications
}

/// Check for application updates (simplified implementation)
async fn check_application_updates(applications: &mut [Application]) -> Result<()> {
    debug!("Checking application update availability");
    
    // This is a simplified implementation
    // In a real implementation, we would:
    // 1. Check Windows Update for available app updates
    // 2. Query Microsoft Store for app updates
    // 3. Check with package managers like Chocolatey, Scoop, etc.
    
    for app in applications.iter_mut() {
        // For now, mark store apps as updatable
        if app.install_type == "Store" {
            app.can_update = true;
        } else {
            // Could implement more sophisticated update checking here
            app.can_update = false;
        }
    }
    
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
#[cfg(target_os = "windows")]
pub async fn check_application_updates_public() -> Result<Vec<Application>> {
    debug!("Checking for application updates");
    
    let inventory = get_installed_applications_wmi().await?;
    
    let updatable_apps = inventory.applications
        .into_iter()
        .filter(|app| app.can_update)
        .collect();
    
    Ok(updatable_apps)
}

/// Non-Windows implementations (stubs)
#[cfg(not(target_os = "windows"))]
pub async fn get_installed_applications_wmi() -> Result<ApplicationInventory> {
    Err(anyhow!("Application inventory via WMI is only available on Windows"))
}

#[cfg(not(target_os = "windows"))]
pub async fn get_application_details(_app_id: String) -> Result<Option<Application>> {
    Err(anyhow!("Application details via WMI is only available on Windows"))
}

#[cfg(not(target_os = "windows"))]
pub async fn check_application_updates_public() -> Result<Vec<Application>> {
    Err(anyhow!("Application update check is only available on Windows"))
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
        };

        let json = serde_json::to_string(&app).unwrap();
        assert!(json.contains("Test Application"));
        assert!(json.contains("\"can_update\":true"));
    }

    #[test]
    fn test_deduplicate_applications() {
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
            },
            Application {
                name: "Test App".to_string(),
                version: Some("1.0.0".to_string()),
                vendor: None,
                install_date: None,
                install_type: "Registry".to_string(),
                can_update: false,
                install_location: None,
                size_mb: None,
                registry_key: None,
            },
        ];

        let deduped = deduplicate_applications(apps);
        assert_eq!(deduped.len(), 1);
    }
}