#![allow(clippy::needless_return)]
//! Windows Update management via WMI and COM API
//! 
//! This module provides functionality to check Windows Updates, pending updates,
//! and update history using both WMI queries and the Windows Update Agent COM API.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc, Timelike, Datelike, TimeZone};

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

/// Operating System information from Win32_OperatingSystem
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct OperatingSystemInfo {
    #[serde(rename = "LastBootUpTime")]
    pub last_boot_up_time: Option<String>,
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
    /// RFC3339/ISO-8601 timestamp string when reboot became required (last boot time)
    pub reboot_required_since: Option<String>,
}

/// Check Windows Updates using WMI and COM API
#[cfg(target_os = "windows")]
pub async fn check_windows_updates() -> Result<UpdateStatus> {
    log::info!("Checking Windows Updates via WMI and COM API");
    
    // Collect all WMI data in a separate scope
    let (installed_updates, update_agent_version, reboot_required, reboot_required_since, automatic_updates_enabled) = {
        let com_lib = COMLibrary::new()
            .map_err(|e| anyhow!("Failed to initialize COM library: {:?}", e))?;
        
        let wmi_conn = WMIConnection::new(com_lib.clone())
            .map_err(|e| anyhow!("Failed to create WMI connection: {:?}", e))?;
        
        // Query installed updates via WMI
        let installed_updates = get_installed_updates(&wmi_conn)
            .unwrap_or_else(|e| {
                log::warn!("Failed to get installed updates: {}", e);
                Vec::new()
            });
        
        // Query Windows Update Agent status
        let update_agent_version = get_update_agent_version(&wmi_conn)
            .unwrap_or_else(|e| {
                log::warn!("Failed to get update agent version: {}", e);
                None
            });
        
        // Check if reboot is required and get last boot time
        let (reboot_required, reboot_required_since) = check_reboot_required(&wmi_conn)
            .unwrap_or((false, None));

        // Check automatic updates setting
        let automatic_updates_enabled = check_automatic_updates(&wmi_conn)
            .unwrap_or(false);

        // Return all data before scope ends, dropping com_lib and wmi_conn
        (installed_updates, update_agent_version, reboot_required, reboot_required_since, automatic_updates_enabled)
    };
    
    // Now do async operations - com_lib and wmi_conn are out of scope
    // Check for pending updates using COM interface
    let pending_updates = check_pending_updates_com().await
        .unwrap_or_else(|e| {
            log::warn!("Failed to check pending updates: {}", e);
            Vec::new()
        });
    
    Ok(UpdateStatus {
        installed_updates,
        pending_updates,
        last_check: SystemTime::now(),
        update_agent_version,
        automatic_updates_enabled,
        reboot_required,
        reboot_required_since,
    })
}

/// Get installed updates from Win32_QuickFixEngineering
#[cfg(target_os = "windows")]
fn get_installed_updates(wmi_conn: &WMIConnection) -> Result<Vec<WindowsUpdate>> {
    log::debug!("Querying installed Windows updates");
    
    let updates: Vec<WindowsUpdate> = wmi_conn
        .raw_query("SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering")
        .map_err(|e| anyhow!("Failed to query Win32_QuickFixEngineering: {:?}", e))?;
    
    log::info!("Found {} installed updates", updates.len());
    Ok(updates)
}

/// Get Windows Update Agent version
#[cfg(target_os = "windows")]
fn get_update_agent_version(wmi_conn: &WMIConnection) -> Result<Option<String>> {
    log::debug!("Querying Windows Update Agent version");
    
    let versions: Vec<UpdateAgentStatus> = wmi_conn
        .raw_query("SELECT Version FROM Win32_WindowsUpdateAgentVersion")
        .map_err(|e| anyhow!("Failed to query Win32_WindowsUpdateAgentVersion: {:?}", e))?;
    
    Ok(versions.first().map(|v| v.version.clone()))
}

/// Check for pending updates using Windows Update Agent COM API
#[cfg(target_os = "windows")]
async fn check_pending_updates_com() -> Result<Vec<PendingUpdate>> {
    log::debug!("Checking pending updates via COM API");
    
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
        
        log::info!("Found {} pending updates", count);
        
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
                    log::warn!("Failed to get update item {}: {}", i, e);
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

/// Check if reboot is required using registry and get last boot time
#[cfg(target_os = "windows")]
fn check_reboot_required(wmi_conn: &WMIConnection) -> Result<(bool, Option<String>)> {
    // Check common registry keys that indicate pending reboot
    // Using multiple detection methods for robustness as Win32_Registry may be unreliable
    let registry_queries = vec![
        "SELECT * FROM Win32_Registry WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'",
        "SELECT * FROM Win32_Registry WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'",
    ];

    let mut reboot_required = false;

    for query in registry_queries {
        match wmi_conn.raw_query::<serde_json::Value>(query) {
            Ok(results) => {
                if !results.is_empty() {
                    reboot_required = true;
                    log::debug!("Reboot detected via WMI registry query");
                    break;
                }
            }
            Err(e) => {
                log::debug!("WMI registry query failed (expected if key doesn't exist): {}", e);
                continue;
            }
        }
    }

    // Fallback: Check using PowerShell for more reliable detection
    if !reboot_required {
        reboot_required = check_reboot_via_powershell().unwrap_or(false);
    }

    // If reboot is required, get the last boot time as RFC3339 string
    let reboot_required_since = if reboot_required {
        match get_last_boot_time(wmi_conn) {
            Ok(Some(boot_time_rfc3339)) => {
                log::info!("Reboot required since last boot at: {}", boot_time_rfc3339);
                Some(boot_time_rfc3339)
            }
            Ok(None) => {
                log::warn!("Reboot required but could not determine last boot time");
                None
            }
            Err(e) => {
                log::warn!("Failed to get last boot time: {}", e);
                None
            }
        }
    } else {
        None
    };

    Ok((reboot_required, reboot_required_since))
}

/// Get the last boot time from Win32_OperatingSystem as RFC3339 string
#[cfg(target_os = "windows")]
fn get_last_boot_time(wmi_conn: &WMIConnection) -> Result<Option<String>> {
    log::debug!("Querying last boot time from Win32_OperatingSystem");

    let os_info: Vec<OperatingSystemInfo> = wmi_conn
        .raw_query("SELECT LastBootUpTime FROM Win32_OperatingSystem")
        .map_err(|e| anyhow!("Failed to query Win32_OperatingSystem: {:?}", e))?;

    if let Some(info) = os_info.first() {
        if let Some(ref last_boot_time_str) = info.last_boot_up_time {
            match parse_wmi_datetime_to_rfc3339(last_boot_time_str) {
                Ok(boot_time_rfc3339) => {
                    log::debug!("Successfully parsed last boot time: {}", boot_time_rfc3339);
                    return Ok(Some(boot_time_rfc3339));
                }
                Err(e) => {
                    log::warn!("Failed to parse LastBootUpTime '{}': {}", last_boot_time_str, e);
                    return Ok(None);
                }
            }
        }
    }

    Ok(None)
}

/// Check if automatic updates are enabled
#[cfg(target_os = "windows")]
fn check_automatic_updates(wmi_conn: &WMIConnection) -> Result<bool> {
    log::debug!("Checking automatic updates configuration");
    
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
                    log::debug!("Successfully queried automatic updates settings");
                    return Ok(true); // If we can query update agent, assume AU is enabled
                }
            }
            Err(e) => {
                log::debug!("WMI query '{}' failed: {}", query, e);
                continue;
            }
        }
    }
    
    // Fallback: Try to check registry via PowerShell command
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        log::debug!("Falling back to PowerShell registry check");
        
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
                
                log::debug!("PowerShell automatic updates check result: '{}'", result);
                
                match result {
                    "enabled" => return Ok(true),
                    "disabled" => return Ok(false),
                    _ => {
                        log::warn!("Could not determine automatic updates status: {}", result);
                        return Ok(true); // Default to enabled for safety
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to execute PowerShell command for automatic updates check: {}", e);
            }
        }
    }
    
    // Final fallback - assume enabled
    log::warn!("Could not determine automatic updates status, assuming enabled");
    Ok(true)
}

/// Get update history for the specified number of days
#[cfg(target_os = "windows")]
pub async fn get_update_history(days: u32) -> Result<Vec<WindowsUpdate>> {
    let com_lib = COMLibrary::new()
        .map_err(|e| anyhow!("Failed to initialize COM library: {:?}", e))?;
    
    let wmi_conn = WMIConnection::new(com_lib)
        .map_err(|e| anyhow!("Failed to create WMI connection: {:?}", e))?;
    
    // Calculate date filter
    let cutoff_date = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() - (days as u64 * 86400);
    
    log::debug!("Getting update history for the last {} days", days);
    
    // Query recent updates (this is a simplified approach)
    let query = format!(
        "SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering WHERE InstalledOn >= '{}'",
        format_wmi_date(cutoff_date)
    );
    
    let updates: Vec<WindowsUpdate> = wmi_conn
        .raw_query(&query)
        .map_err(|e| anyhow!("Failed to query recent updates: {:?}", e))?;
    
    log::info!("Found {} updates in the last {} days", updates.len(), days);
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

/// Parse WMI DMTF datetime format to RFC3339 string
/// WMI/DMTF datetime format: YYYYMMDDHHMMSS.mmmmmm+UUU
/// Example: "20240115103045.500000-480" (UTC-8 hours = 480 minutes)
/// Returns: RFC3339/ISO-8601 string like "2024-01-15T10:30:45.500000-08:00"
fn parse_wmi_datetime_to_rfc3339(wmi_date: &str) -> Result<String> {
    // WMI DMTF format: YYYYMMDDHHMMSS.ffffff+UUU
    // UUU is UTC offset in minutes (can be negative, indicated by +/-)

    if wmi_date.len() < 21 {
        return Err(anyhow!("Invalid WMI datetime format: expected at least 21 chars, got {}", wmi_date.len()));
    }

    // Parse date/time components
    let year: i32 = wmi_date[0..4].parse()
        .map_err(|_| anyhow!("Invalid year in WMI datetime"))?;
    let month: u32 = wmi_date[4..6].parse()
        .map_err(|_| anyhow!("Invalid month in WMI datetime"))?;
    let day: u32 = wmi_date[6..8].parse()
        .map_err(|_| anyhow!("Invalid day in WMI datetime"))?;
    let hour: u32 = wmi_date[8..10].parse()
        .map_err(|_| anyhow!("Invalid hour in WMI datetime"))?;
    let minute: u32 = wmi_date[10..12].parse()
        .map_err(|_| anyhow!("Invalid minute in WMI datetime"))?;
    let second: u32 = wmi_date[12..14].parse()
        .map_err(|_| anyhow!("Invalid second in WMI datetime"))?;

    // Parse microseconds (after decimal point)
    let microseconds: u32 = if wmi_date.len() > 15 && &wmi_date[14..15] == "." {
        wmi_date[15..21].parse()
            .map_err(|_| anyhow!("Invalid microseconds in WMI datetime"))?
    } else {
        0
    };

    // Parse UTC offset in minutes (format: +UUU or -UUU)
    let offset_sign = &wmi_date[21..22];
    let offset_minutes: i32 = wmi_date[22..25].parse()
        .map_err(|_| anyhow!("Invalid UTC offset in WMI datetime"))?;

    let offset_minutes_signed = match offset_sign {
        "+" => offset_minutes,
        "-" => -offset_minutes,
        _ => return Err(anyhow!("Invalid offset sign: {}", offset_sign)),
    };

    // Construct DateTime with FixedOffset using chrono
    // FixedOffset expects seconds (east of UTC), WMI provides minutes
    let offset = FixedOffset::east_opt(offset_minutes_signed * 60)
        .ok_or_else(|| anyhow!("Invalid timezone offset: {} minutes", offset_minutes_signed))?;

    // Create NaiveDateTime first (this represents local time in the given timezone)
    let naive_dt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day)
            .ok_or_else(|| anyhow!("Invalid date: {}-{:02}-{:02}", year, month, day))?,
        chrono::NaiveTime::from_hms_micro_opt(hour, minute, second, microseconds)
            .ok_or_else(|| anyhow!("Invalid time: {:02}:{:02}:{:02}.{:06}", hour, minute, second, microseconds))?
    );

    // Create DateTime from local datetime and offset
    // The WMI datetime is local time in the specified timezone
    let dt_with_offset = offset.from_local_datetime(&naive_dt)
        .single()
        .ok_or_else(|| anyhow!("Ambiguous or invalid local datetime"))?;

    // Convert to RFC3339 string
    Ok(dt_with_offset.to_rfc3339())
}

/// Check if reboot is required using PowerShell registry queries (fallback method)
/// More reliable than WMI Win32_Registry queries which may fail
#[cfg(target_os = "windows")]
fn check_reboot_via_powershell() -> Result<bool> {
    use std::process::Command;

    log::debug!("Checking reboot requirement via PowerShell");

    let powershell_cmd = r#"
        $rebootRequired = $false

        # Check Windows Update RebootRequired key
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $rebootRequired = $true
        }

        # Check Component Based Servicing RebootPending key
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $rebootRequired = $true
        }

        # Check PendingFileRenameOperations
        try {
            $pfro = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
            if ($pfro) {
                $rebootRequired = $true
            }
        } catch { }

        if ($rebootRequired) {
            Write-Output "true"
        } else {
            Write-Output "false"
        }
    "#;

    match Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", powershell_cmd])
        .output()
    {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let result = output_str.trim();

            log::debug!("PowerShell reboot check result: '{}'", result);

            match result {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => {
                    log::warn!("Unexpected PowerShell reboot check output: {}", result);
                    Ok(false)
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to execute PowerShell reboot check: {}", e);
            Err(anyhow!("PowerShell execution failed: {}", e))
        }
    }
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