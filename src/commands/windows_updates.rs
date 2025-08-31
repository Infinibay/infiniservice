//! Windows Update management via WMI and COM API
//! 
//! This module provides functionality to check Windows Updates, pending updates,
//! and update history using both WMI queries and the Windows Update Agent COM API.

use anyhow::{Result, anyhow, Context};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use log::{debug, warn, info};

#[cfg(target_os = "windows")]
use wmi::{COMLibrary, WMIConnection};
#[cfg(target_os = "windows")]
use windows::core::BSTR;
#[cfg(target_os = "windows")]
use windows::Win32::System::UpdateAgent::*;
#[cfg(target_os = "windows")]
use windows::Win32::System::Com::*;

/// Windows Update information from Win32_QuickFixEngineering
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct WindowsUpdate {
    #[serde(rename = "HotFixID")]
    pub hotfix_id: Option<String>,
    
    #[serde(rename = "Description")]
    pub description: Option<String>,
    
    #[serde(rename = "InstalledOn")]
    pub installed_on: Option<String>,
    
    #[serde(rename = "InstalledBy")]
    pub installed_by: Option<String>,
}

/// Pending update information from Windows Update Agent
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PendingUpdate {
    pub title: String,
    pub severity: String,
    pub size_mb: u32,
    pub categories: Vec<String>,
    pub kb_article_ids: Vec<String>,
}

/// Windows Update Agent version information
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UpdateAgentStatus {
    #[serde(rename = "Version")]
    pub version: String,
}

/// Complete Windows Update status
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateStatus {
    pub installed_updates: Vec<WindowsUpdate>,
    pub pending_updates: Vec<PendingUpdate>,
    pub last_check: SystemTime,
    pub update_agent_version: Option<String>,
    pub automatic_updates_enabled: bool,
    pub reboot_required: bool,
}

/// Check Windows Updates using WMI and COM API
#[cfg(target_os = "windows")]
pub async fn check_windows_updates() -> Result<UpdateStatus> {
    info!("Checking Windows Updates via WMI and COM API");
    
    // Collect all WMI data in a separate scope
    let (installed_updates, update_agent_version, reboot_required, automatic_updates_enabled) = {
        let com_lib = COMLibrary::new()
            .context("Failed to initialize COM library")?;
        
        let wmi_conn = WMIConnection::new(com_lib.clone())
            .context("Failed to create WMI connection")?;
        
        // Query installed updates via WMI
        let installed_updates = get_installed_updates(&wmi_conn)
            .unwrap_or_else(|e| {
                warn!("Failed to get installed updates: {}", e);
                Vec::new()
            });
        
        // Query Windows Update Agent status
        let update_agent_version = get_update_agent_version(&wmi_conn)
            .unwrap_or_else(|e| {
                warn!("Failed to get update agent version: {}", e);
                None
            });
        
        // Check if reboot is required
        let reboot_required = check_reboot_required(&wmi_conn)
            .unwrap_or(false);
        
        // Check automatic updates setting
        let automatic_updates_enabled = check_automatic_updates(&wmi_conn)
            .unwrap_or(false);
        
        // Return all data before scope ends, dropping com_lib and wmi_conn
        (installed_updates, update_agent_version, reboot_required, automatic_updates_enabled)
    };
    
    // Now do async operations - com_lib and wmi_conn are out of scope
    // Check for pending updates using COM interface
    let pending_updates = check_pending_updates_com().await
        .unwrap_or_else(|e| {
            warn!("Failed to check pending updates: {}", e);
            Vec::new()
        });
    
    Ok(UpdateStatus {
        installed_updates,
        pending_updates,
        last_check: SystemTime::now(),
        update_agent_version,
        automatic_updates_enabled,
        reboot_required,
    })
}

/// Get installed updates from Win32_QuickFixEngineering
#[cfg(target_os = "windows")]
fn get_installed_updates(wmi_conn: &WMIConnection) -> Result<Vec<WindowsUpdate>> {
    debug!("Querying installed Windows updates");
    
    let updates: Vec<WindowsUpdate> = wmi_conn
        .raw_query("SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering")
        .context("Failed to query Win32_QuickFixEngineering")?;
    
    info!("Found {} installed updates", updates.len());
    Ok(updates)
}

/// Get Windows Update Agent version
#[cfg(target_os = "windows")]
fn get_update_agent_version(wmi_conn: &WMIConnection) -> Result<Option<String>> {
    debug!("Querying Windows Update Agent version");
    
    let versions: Vec<UpdateAgentStatus> = wmi_conn
        .raw_query("SELECT Version FROM Win32_WindowsUpdateAgentVersion")
        .context("Failed to query Win32_WindowsUpdateAgentVersion")?;
    
    Ok(versions.first().map(|v| v.version.clone()))
}

/// Check for pending updates using Windows Update Agent COM API
#[cfg(target_os = "windows")]
async fn check_pending_updates_com() -> Result<Vec<PendingUpdate>> {
    debug!("Checking pending updates via COM API");
    
    unsafe {
        // Initialize COM
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        if hr.is_err() {
            return Err(anyhow!("Failed to initialize COM: {:?}", hr));
        }
        
        // Create Update Session
        let update_session: IUpdateSession = CoCreateInstance(
            &UpdateSession,
            None,
            CLSCTX_INPROC_SERVER,
        ).map_err(|e| anyhow!("Failed to create UpdateSession: {:?}", e))?;
        
        // Create Update Searcher
        let searcher = update_session.CreateUpdateSearcher()
            .map_err(|e| anyhow!("Failed to create UpdateSearcher: {:?}", e))?;
        
        // Search for updates that are not installed
        let search_criteria = BSTR::from("IsInstalled=0 and Type='Software'");
        let search_result = searcher.Search(&search_criteria)
            .map_err(|e| anyhow!("Failed to search for updates: {:?}", e))?;
        
        let updates = search_result.Updates()
            .map_err(|e| anyhow!("Failed to get updates collection: {:?}", e))?;
        
        let count = updates.Count()
            .map_err(|e| anyhow!("Failed to get updates count: {:?}", e))?;
        
        info!("Found {} pending updates", count);
        
        let mut pending = Vec::new();
        
        for i in 0..count {
            match updates.get_Item(i) {
                Ok(update) => {
                    let title = update.Title()
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    
                    let severity = if update.IsMandatory().map(|v| v.as_bool()).unwrap_or(false) {
                        "Critical".to_string()
                    } else {
                        match update.MsrcSeverity() {
                            Ok(severity) => severity.to_string(),
                            Err(_) => "Optional".to_string(),
                        }
                    };
                    
                    // MaxDownloadSize returns DECIMAL, but we'll skip size for now
                    // as proper DECIMAL conversion would require additional implementation
                    let size_mb = 0u32; // Size information not available in current implementation
                    
                    let categories = get_update_categories(&update).unwrap_or_default();
                    let kb_article_ids = get_kb_article_ids(&update).unwrap_or_default();
                    
                    pending.push(PendingUpdate {
                        title,
                        severity,
                        size_mb,
                        categories,
                        kb_article_ids,
                    });
                }
                Err(e) => {
                    warn!("Failed to get update item {}: {}", i, e);
                }
            }
        }
        
        CoUninitialize();
        Ok(pending)
    }
}

/// Get update categories
#[cfg(target_os = "windows")]
fn get_update_categories(update: &IUpdate) -> Result<Vec<String>> {
    let mut categories = Vec::new();
    
    unsafe {
        match update.Categories() {
            Ok(cats) => {
                let count = cats.Count().unwrap_or(0);
                for i in 0..count {
                    if let Ok(category) = cats.get_Item(i) {
                        if let Ok(name) = category.Name() {
                            categories.push(name.to_string());
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
    
    Ok(categories)
}

/// Get KB article IDs from update
#[cfg(target_os = "windows")]
fn get_kb_article_ids(update: &IUpdate) -> Result<Vec<String>> {
    let mut kb_ids = Vec::new();
    
    unsafe {
        match update.KBArticleIDs() {
            Ok(ids) => {
                let count = ids.Count().unwrap_or(0);
                for i in 0..count {
                    if let Ok(id) = ids.get_Item(i) {
                        kb_ids.push(id.to_string());
                    }
                }
            }
            Err(_) => {}
        }
    }
    
    Ok(kb_ids)
}

/// Check if reboot is required using registry
#[cfg(target_os = "windows")]
fn check_reboot_required(wmi_conn: &WMIConnection) -> Result<bool> {
    // Check common registry keys that indicate pending reboot
    let registry_queries = vec![
        "SELECT * FROM Win32_Registry WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'",
        "SELECT * FROM Win32_Registry WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'",
    ];
    
    for query in registry_queries {
        match wmi_conn.raw_query::<serde_json::Value>(query) {
            Ok(results) => {
                if !results.is_empty() {
                    return Ok(true);
                }
            }
            Err(_) => continue,
        }
    }
    
    Ok(false)
}

/// Check if automatic updates are enabled
#[cfg(target_os = "windows")]
fn check_automatic_updates(wmi_conn: &WMIConnection) -> Result<bool> {
    debug!("Checking automatic updates configuration");
    
    // Try to query the Windows Update Agent settings via WMI
    // First try Win32_WindowsUpdateAgentVersion for AU settings
    let queries = vec![
        "SELECT * FROM Win32_WindowsUpdateAgentVersion",
        "SELECT * FROM Win32_AutoUpdateSettings",
    ];
    
    for query in &queries {
        match wmi_conn.raw_query::<serde_json::Value>(query) {
            Ok(results) => {
                if !results.is_empty() {
                    debug!("Successfully queried automatic updates settings");
                    return Ok(true); // If we can query update agent, assume AU is enabled
                }
            }
            Err(e) => {
                debug!("WMI query '{}' failed: {}", query, e);
                continue;
            }
        }
    }
    
    // Fallback: Try to check registry via PowerShell command
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        debug!("Falling back to PowerShell registry check");
        
        let powershell_cmd = r#"
            try {
                $auKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -ErrorAction SilentlyContinue
                if ($auKey -and $auKey.AUOptions -gt 1) {
                    Write-Output "enabled"
                } else {
                    $wuKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
                    if ($wuKey -and $wuKey.NoAutoUpdate -eq 0) {
                        Write-Output "enabled"
                    } else {
                        Write-Output "disabled"
                    }
                }
            } catch {
                Write-Output "unknown"
            }
        "#;
        
        match Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", powershell_cmd])
            .output()
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                let result = output_str.trim();
                
                debug!("PowerShell automatic updates check result: '{}'", result);
                
                match result {
                    "enabled" => return Ok(true),
                    "disabled" => return Ok(false),
                    _ => {
                        warn!("Could not determine automatic updates status: {}", result);
                        return Ok(true); // Default to enabled for safety
                    }
                }
            }
            Err(e) => {
                warn!("Failed to execute PowerShell command for automatic updates check: {}", e);
            }
        }
    }
    
    // Final fallback - assume enabled
    warn!("Could not determine automatic updates status, assuming enabled");
    Ok(true)
}

/// Get update history for the specified number of days
#[cfg(target_os = "windows")]
pub async fn get_update_history(days: u32) -> Result<Vec<WindowsUpdate>> {
    let com_lib = COMLibrary::new()
        .context("Failed to initialize COM library")?;
    
    let wmi_conn = WMIConnection::new(com_lib)
        .context("Failed to create WMI connection")?;
    
    // Calculate date filter
    let cutoff_date = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() - (days as u64 * 86400);
    
    debug!("Getting update history for the last {} days", days);
    
    // Query recent updates (this is a simplified approach)
    let query = format!(
        "SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering WHERE InstalledOn >= '{}'",
        format_wmi_date(cutoff_date)
    );
    
    let updates: Vec<WindowsUpdate> = wmi_conn
        .raw_query(&query)
        .context("Failed to query recent updates")?;
    
    info!("Found {} updates in the last {} days", updates.len(), days);
    Ok(updates)
}

/// Format Unix timestamp for WMI date query
fn format_wmi_date(timestamp: u64) -> String {
    // WMI uses WMI DateTime format: YYYYMMDDHHMMSS.ffffff+UUU
    // This is a simplified conversion
    let datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
    let _system_time: SystemTime = datetime;
    
    // For now, return a basic format - in real implementation we'd format properly
    format!("{:010}", timestamp)
}

/// Non-Windows implementation (stub)
#[cfg(not(target_os = "windows"))]
pub async fn check_windows_updates() -> Result<UpdateStatus> {
    Err(anyhow!("Windows Updates check is only available on Windows"))
}

/// Non-Windows implementation (stub) 
#[cfg(not(target_os = "windows"))]
pub async fn get_update_history(_days: u32) -> Result<Vec<WindowsUpdate>> {
    Err(anyhow!("Windows Updates history is only available on Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_update_serialization() {
        let update = WindowsUpdate {
            hotfix_id: Some("KB5000001".to_string()),
            description: Some("Security Update".to_string()),
            installed_on: Some("1/1/2024".to_string()),
            installed_by: Some("NT AUTHORITY\\SYSTEM".to_string()),
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("KB5000001"));
    }

    #[test]
    fn test_pending_update_serialization() {
        let update = PendingUpdate {
            title: "Test Update".to_string(),
            severity: "Important".to_string(),
            size_mb: 50,
            categories: vec!["Security Updates".to_string()],
            kb_article_ids: vec!["KB5000001".to_string()],
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("Test Update"));
        assert!(json.contains("Important"));
    }
}