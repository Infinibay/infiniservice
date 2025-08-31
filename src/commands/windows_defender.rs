//! Windows Defender integration via WMI
//!
//! This module provides functionality to check Windows Defender status,
//! run scans, and get threat history using WMI queries.

use anyhow::{Result, anyhow, Context};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use log::{debug, warn, info};

#[cfg(target_os = "windows")]
use wmi::{COMLibrary, WMIConnection};

// Product state bit masks for AntiVirusProduct
#[cfg(target_os = "windows")]
const AV_PRODUCT_STATE_ENABLED: u32 = 0x1000;  // Bit 12: AV enabled
#[cfg(target_os = "windows")]
const AV_PRODUCT_STATE_REALTIME: u32 = 0x10;   // Bit 4: Real-time protection

/// Windows Defender computer status from MSFT_MpComputerStatus
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MSFT_MpComputerStatus {
    #[serde(rename = "AMIEnabled")]
    pub ami_enabled: Option<bool>,
    pub antispyware_enabled: Option<bool>,
    pub antivirus_enabled: Option<bool>,
    pub behavior_monitor_enabled: Option<bool>,
    pub full_scan_age: Option<u32>,
    pub last_full_scan_date_time: Option<String>,
    pub last_quick_scan_date_time: Option<String>,
    #[serde(rename = "NISEnabled")]
    pub nis_enabled: Option<bool>,
    pub on_access_protection_enabled: Option<bool>,
    pub quick_scan_age: Option<u32>,
    pub real_time_protection_enabled: Option<bool>,
    pub signature_age: Option<u32>,
    pub signature_last_updated: Option<String>,
}

/// Windows Defender threat information from MSFT_MpThreat
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MSFT_MpThreat {
    pub threat_id: Option<i64>,
    pub threat_name: Option<String>,
    pub severity_id: Option<u8>,
    pub detection_time: Option<String>,
    pub initial_detection_method: Option<String>,
    pub current_threat_status: Option<u8>,
}

/// Windows Defender scan information from MSFT_MpScan
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MSFT_MpScan {
    pub scan_id: Option<String>,
    pub scan_type: Option<u32>,
    pub scan_start_time: Option<String>,
    pub scan_end_time: Option<String>,
    pub threats_detected: Option<u32>,
}

/// Defender scan types
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DefenderScanType {
    Quick,
    Full,
    Custom(String),
}

impl DefenderScanType {
    /// Convert to WMI scan type value
    pub fn to_wmi_value(&self) -> u32 {
        match self {
            DefenderScanType::Quick => 1,
            DefenderScanType::Full => 2,
            DefenderScanType::Custom(_) => 3,
        }
    }
}

/// Scan status
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ScanStatus {
    NotStarted,
    Running,
    Completed,
    Failed,
}

/// Scan result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanResult {
    pub scan_type: DefenderScanType,
    pub started_at: SystemTime,
    pub status: ScanStatus,
    pub threats_found: Option<u32>,
    pub scan_duration_ms: Option<u64>,
}

/// Complete Windows Defender status
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DefenderStatus {
    pub enabled: bool,
    pub real_time_protection: bool,
    pub signature_age_days: u32,
    pub last_full_scan: Option<String>,
    pub last_quick_scan: Option<String>,
    pub threats_detected: usize,
    pub recent_threats: Vec<MSFT_MpThreat>,
    pub recent_scans: Vec<MSFT_MpScan>,
    pub engine_version: Option<String>,
    pub antivirus_signature_version: Option<String>,
}

/// Get Windows Defender status
/// 
/// This function attempts to get Windows Defender status using multiple approaches:
/// 1. Primary: Use the Windows Defender WMI namespace (root\Microsoft\Windows\Defender)
/// 2. Fallback: Use SecurityCenter2 namespace (root\SecurityCenter2) 
/// 3. Final fallback: Return unknown status if no method works
///
/// This multi-tiered approach ensures compatibility across different Windows versions
/// and configurations where Defender WMI may not be available.
#[cfg(target_os = "windows")]
pub async fn get_defender_status() -> Result<DefenderStatus> {
    info!("Checking Windows Defender status via WMI");
    
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        Err(e) => {
            warn!("Failed to initialize COM library: {}", e);
            return Err(anyhow!("COM initialization failed: {}", e));
        }
    };
    
    // Try to connect to Windows Defender WMI namespace
    // Note: This namespace may not be available on all Windows versions or configurations
    let defender_conn = match WMIConnection::with_namespace_path(
        "root\\Microsoft\\Windows\\Defender",
        com_lib.clone(),
    ) {
        Ok(conn) => conn,
        Err(e) => {
            // If the Defender namespace is not available, try the standard WMI namespace
            // and return a basic status
            warn!("Windows Defender WMI namespace not available: {}. Trying fallback approach.", e);
            return get_defender_status_fallback(com_lib);
        }
    };
    
    // Get computer status
    let status = match get_computer_status(&defender_conn) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to get Defender computer status: {}. Using fallback.", e);
            return get_defender_status_fallback(com_lib);
        }
    };
    
    // Get threat history
    let threats = get_threat_history(&defender_conn)
        .unwrap_or_else(|e| {
            warn!("Failed to get threat history: {}", e);
            Vec::new()
        });
    
    // Get scan history
    let scans = get_scan_history(&defender_conn)
        .unwrap_or_else(|e| {
            warn!("Failed to get scan history: {}", e);
            Vec::new()
        });
    
    // Get signature versions
    let (engine_version, signature_version) = get_signature_versions(&defender_conn)
        .unwrap_or_else(|e| {
            warn!("Failed to get signature versions: {}", e);
            (None, None)
        });
    
    let defender_status = DefenderStatus {
        enabled: status.antivirus_enabled.unwrap_or(false),
        real_time_protection: status.real_time_protection_enabled.unwrap_or(false),
        signature_age_days: status.signature_age.unwrap_or(0),
        last_full_scan: status.last_full_scan_date_time,
        last_quick_scan: status.last_quick_scan_date_time,
        threats_detected: threats.len(),
        recent_threats: threats.into_iter().take(10).collect(),
        recent_scans: scans.into_iter().take(5).collect(),
        engine_version,
        antivirus_signature_version: signature_version,
    };
    
    info!("Defender status: enabled={}, real_time={}, signature_age={} days", 
          defender_status.enabled, 
          defender_status.real_time_protection,
          defender_status.signature_age_days);
    
    Ok(defender_status)
}

/// Create a default DefenderStatus when we cannot determine the actual status
#[cfg(target_os = "windows")]
fn create_unknown_defender_status() -> DefenderStatus {
    DefenderStatus {
        enabled: false,
        real_time_protection: false,
        signature_age_days: 999,  // Unknown
        last_full_scan: None,
        last_quick_scan: None,
        threats_detected: 0,
        recent_threats: Vec::new(),
        recent_scans: Vec::new(),
        engine_version: None,
        antivirus_signature_version: None,
    }
}

/// Fallback method to get Windows Defender status using standard WMI
#[cfg(target_os = "windows")]
fn get_defender_status_fallback(com_lib: COMLibrary) -> Result<DefenderStatus> {
    info!("Using fallback method to check Windows Defender status");
    
    // Try to connect to standard WMI namespace
    let wmi_conn = match WMIConnection::new(com_lib) {
        Ok(conn) => conn,
        Err(e) => {
            warn!("Failed to connect to standard WMI: {}", e);
            return Ok(create_unknown_defender_status());
        }
    };
    
    // Try to query AntiVirusProduct from SecurityCenter2 namespace
    let security_conn = match WMIConnection::with_namespace_path(
        "root\\SecurityCenter2",
        com_lib.clone(),
    ) {
        Ok(conn) => conn,
        Err(e) => {
            info!("SecurityCenter2 namespace not available: {}. Returning minimal status.", e);
            return Ok(create_unknown_defender_status());
        }
    };
    
    // Query for Windows Defender in AntiVirusProduct
    #[derive(Deserialize, Debug)]
    #[allow(non_snake_case)]
    struct AntiVirusProduct {
        displayName: Option<String>,
        productState: Option<u32>,
    }
    
    let av_products: Vec<AntiVirusProduct> = security_conn
        .raw_query("SELECT displayName, productState FROM AntiVirusProduct WHERE displayName LIKE '%Windows Defender%'")
        .unwrap_or_else(|e| {
            warn!("Failed to query AntiVirusProduct: {}", e);
            Vec::new()
        });
    
    if let Some(defender) = av_products.into_iter().next() {
        // Parse productState to determine status
        // productState is a hex value that encodes various states
        let product_state = defender.productState.unwrap_or(0);
        let enabled = (product_state & AV_PRODUCT_STATE_ENABLED) != 0;
        let real_time = (product_state & AV_PRODUCT_STATE_REALTIME) != 0;
        
        info!("Found Windows Defender via SecurityCenter2: enabled={}, real_time={}", enabled, real_time);
        
        // Try to get additional information from standard WMI namespace
        let mut defender_status = DefenderStatus {
            enabled,
            real_time_protection: real_time,
            signature_age_days: 0,
            last_full_scan: None,
            last_quick_scan: None,
            threats_detected: 0,
            recent_threats: Vec::new(),
            recent_scans: Vec::new(),
            engine_version: None,
            antivirus_signature_version: None,
        };
        
        // Try to get version information from Win32_Product or registry
        if let Ok(version_info) = get_defender_version_info(&wmi_conn) {
            defender_status.engine_version = version_info.0;
            defender_status.antivirus_signature_version = version_info.1;
        }
        
        // Try to get scan information from Event Log or other sources
        if let Ok(scan_info) = get_defender_scan_info_fallback() {
            defender_status.last_full_scan = scan_info.0;
            defender_status.last_quick_scan = scan_info.1;
        }
        
        // Try to get signature age
        if let Ok(sig_age) = get_signature_age_fallback() {
            defender_status.signature_age_days = sig_age;
        }
        
        Ok(defender_status)
    } else {
        info!("Windows Defender not found in SecurityCenter2");
        Ok(create_unknown_defender_status())
    }
}

/// Execute a PowerShell command and return the output
#[cfg(target_os = "windows")]
fn execute_powershell_command(command: &str) -> Option<String> {
    use std::process::Command;
    
    match Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
    {
        Ok(output) if output.status.success() => {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !result.is_empty() {
                Some(result)
            } else {
                None
            }
        }
        Ok(output) => {
            debug!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr));
            None
        }
        Err(e) => {
            debug!("Failed to execute PowerShell: {}", e);
            None
        }
    }
}

/// Try to get Windows Defender version information
#[cfg(target_os = "windows")]
fn get_defender_version_info(_wmi_conn: &WMIConnection) -> Result<(Option<String>, Option<String>)> {
    debug!("Attempting to get Defender version information");
    
    // Try to get version from MpCmdRun.exe file properties
    let ps_cmd = r#"
        try {
            # Try standard location first
            $paths = @(
                "$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
                "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
            )
            
            foreach ($path in $paths) {
                $files = Get-Item $path -ErrorAction SilentlyContinue
                if ($files) {
                    $file = $files | Select-Object -First 1
                    $version = $file.VersionInfo.FileVersion
                    if ($version) {
                        Write-Output "VERSION:$version"
                        
                        # Also try to get signature version from registry
                        $sigVer = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates' -Name 'AVSignatureVersion' -ErrorAction SilentlyContinue
                        if ($sigVer) {
                            Write-Output "|SIGNATURE:$($sigVer.AVSignatureVersion)"
                        }
                        break
                    }
                }
            }
        }
        catch {
            # Silent fail
        }
    "#;
    
    if let Some(output) = execute_powershell_command(ps_cmd) {
        let mut engine_version = None;
        let mut signature_version = None;
        
        for part in output.split('|') {
            if let Some(version) = part.strip_prefix("VERSION:") {
                engine_version = Some(version.to_string());
                info!("Found Defender engine version: {}", version);
            } else if let Some(sig) = part.strip_prefix("SIGNATURE:") {
                signature_version = Some(sig.to_string());
                info!("Found Defender signature version: {}", sig);
            }
        }
        
        if engine_version.is_some() || signature_version.is_some() {
            return Ok((engine_version, signature_version));
        }
    }
    
    Ok((None, None))
}

/// Try to get scan information using Event Log
#[cfg(target_os = "windows")]
fn get_defender_scan_info_fallback() -> Result<(Option<String>, Option<String>)> {
    debug!("Attempting to get scan information from Event Log");
    
    let ps_cmd = r#"
        try {
            # Query Windows Defender operational log for scan completion events
            $events = Get-WinEvent -FilterHashtable @{
                LogName='Microsoft-Windows-Windows Defender/Operational'
                ID=1001  # Scan finished event
            } -MaxEvents 20 -ErrorAction SilentlyContinue
            
            $fullScan = $null
            $quickScan = $null
            
            foreach ($event in $events) {
                $xml = [xml]$event.ToXml()
                $scanType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Scan Type'} | Select-Object -ExpandProperty '#text'
                $time = $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                
                if ($scanType -eq '1' -and -not $quickScan) {  # Quick scan
                    $quickScan = $time
                }
                elseif ($scanType -eq '2' -and -not $fullScan) {  # Full scan
                    $fullScan = $time
                }
                
                if ($fullScan -and $quickScan) { break }
            }
            
            if ($fullScan -or $quickScan) {
                Write-Output "FULL:$fullScan|QUICK:$quickScan"
            }
        }
        catch {
            # Silent fail
        }
    "#;
    
    if let Some(output) = execute_powershell_command(ps_cmd) {
        let mut full_scan = None;
        let mut quick_scan = None;
        
        for part in output.split('|') {
            if let Some(full) = part.strip_prefix("FULL:") {
                if !full.is_empty() && full != "null" {
                    full_scan = Some(full.to_string());
                    debug!("Found last full scan: {}", full);
                }
            } else if let Some(quick) = part.strip_prefix("QUICK:") {
                if !quick.is_empty() && quick != "null" {
                    quick_scan = Some(quick.to_string());
                    debug!("Found last quick scan: {}", quick);
                }
            }
        }
        
        return Ok((full_scan, quick_scan));
    }
    
    Ok((None, None))
}

/// Try to get signature age from registry or Event Log
#[cfg(target_os = "windows")]
fn get_signature_age_fallback() -> Result<u32> {
    debug!("Attempting to get signature age");
    
    let ps_cmd = r#"
        try {
            # Method 1: Get from registry (most reliable)
            $regPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates',
                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Defender\Signature Updates'
            )
            
            foreach ($regPath in $regPaths) {
                if (Test-Path $regPath) {
                    # Try different registry values that might contain the date
                    $props = @('SignaturesLastUpdated', 'AVSignatureApplied', 'ASSignatureApplied')
                    
                    foreach ($prop in $props) {
                        $sigDate = Get-ItemProperty -Path $regPath -Name $prop -ErrorAction SilentlyContinue
                        if ($sigDate.$prop) {
                            # Handle both FileTime and DateTime formats
                            try {
                                $lastUpdate = [DateTime]::FromFileTime($sigDate.$prop)
                            }
                            catch {
                                $lastUpdate = [DateTime]::Parse($sigDate.$prop)
                            }
                            
                            $daysSince = [Math]::Floor(([DateTime]::Now - $lastUpdate).TotalDays)
                            if ($daysSince -ge 0) {
                                Write-Output $daysSince
                                exit
                            }
                        }
                    }
                }
            }
            
            # Method 2: Check definition update events in Event Log
            $events = Get-WinEvent -FilterHashtable @{
                LogName='Microsoft-Windows-Windows Defender/Operational'
                ID=2000,2001  # Definition update events
            } -MaxEvents 1 -ErrorAction SilentlyContinue
            
            if ($events) {
                $lastUpdate = $events[0].TimeCreated
                $daysSince = [Math]::Floor(([DateTime]::Now - $lastUpdate).TotalDays)
                Write-Output $daysSince
            }
            else {
                Write-Output "999"  # Unknown
            }
        }
        catch {
            Write-Output "999"  # Unknown
        }
    "#;
    
    if let Some(output) = execute_powershell_command(ps_cmd) {
        if let Ok(days) = output.parse::<u32>() {
            if days == 999 {
                debug!("Could not determine signature age");
            } else {
                info!("Signature age: {} days", days);
            }
            return Ok(days);
        }
    }
    
    Ok(999)  // Unknown
}

/// Get computer status from MSFT_MpComputerStatus
#[cfg(target_os = "windows")]
fn get_computer_status(defender_conn: &WMIConnection) -> Result<MSFT_MpComputerStatus> {
    debug!("Querying MSFT_MpComputerStatus from Windows Defender WMI namespace");
    
    let status: Vec<MSFT_MpComputerStatus> = match defender_conn
        .raw_query("SELECT * FROM MSFT_MpComputerStatus") {
        Ok(s) => s,
        Err(e) => {
            // Provide more detailed error information
            warn!("WMI query failed for MSFT_MpComputerStatus. This may indicate:");
            warn!("  - Windows Defender is not installed or disabled");
            warn!("  - The WMI provider is not registered");
            warn!("  - Insufficient permissions to access Defender WMI namespace");
            warn!("  - Running on a Windows Server Core or Nano Server edition");
            warn!("Error details: {}", e);
            return Err(anyhow!("Failed to query MSFT_MpComputerStatus: {}", e));
        }
    };
    
    if status.is_empty() {
        warn!("MSFT_MpComputerStatus query returned empty result set");
        return Err(anyhow!("No Defender computer status found - query returned empty"));
    }
    
    debug!("Successfully retrieved MSFT_MpComputerStatus");
    status.into_iter().next()
        .ok_or_else(|| anyhow!("No Defender computer status found"))
}

/// Get threat history from MSFT_MpThreat
#[cfg(target_os = "windows")]
fn get_threat_history(defender_conn: &WMIConnection) -> Result<Vec<MSFT_MpThreat>> {
    debug!("Querying MSFT_MpThreat");
    
    let threats: Vec<MSFT_MpThreat> = defender_conn
        .raw_query("SELECT * FROM MSFT_MpThreat ORDER BY DetectionTime DESC")
        .context("Failed to query MSFT_MpThreat")?;
    
    info!("Found {} threats in history", threats.len());
    Ok(threats)
}

/// Get scan history from MSFT_MpScan
#[cfg(target_os = "windows")]
fn get_scan_history(defender_conn: &WMIConnection) -> Result<Vec<MSFT_MpScan>> {
    debug!("Querying MSFT_MpScan");
    
    let scans: Vec<MSFT_MpScan> = defender_conn
        .raw_query("SELECT * FROM MSFT_MpScan ORDER BY ScanStartTime DESC")
        .context("Failed to query MSFT_MpScan")?;
    
    info!("Found {} scans in history", scans.len());
    Ok(scans)
}

/// Get signature versions
#[cfg(target_os = "windows")]
fn get_signature_versions(defender_conn: &WMIConnection) -> Result<(Option<String>, Option<String>)> {
    debug!("Querying signature versions");
    
    // Query signature information
    let signatures: Vec<serde_json::Value> = defender_conn
        .raw_query("SELECT * FROM MSFT_MpSignature")
        .context("Failed to query MSFT_MpSignature")?;
    
    let engine_version = signatures.first()
        .and_then(|s| s.get("EngineVersion"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    let signature_version = signatures.first()
        .and_then(|s| s.get("AntivirusSignatureVersion"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    Ok((engine_version, signature_version))
}

/// Run a Windows Defender scan
#[cfg(target_os = "windows")]
pub async fn run_defender_scan(scan_type: DefenderScanType) -> Result<ScanResult> {
    info!("Starting Windows Defender scan: {:?}", scan_type);
    
    let com_lib = COMLibrary::new()
        .context("Failed to initialize COM library")?;
    
    let defender_conn = WMIConnection::with_namespace_path(
        "root\\Microsoft\\Windows\\Defender",
        com_lib,
    ).context("Failed to connect to Windows Defender WMI namespace")?;
    
    let start_time = SystemTime::now();
    
    // Execute scan through WMI method invocation
    match scan_type {
        DefenderScanType::Quick => {
            execute_wmi_method(&defender_conn, "MSFT_MpScan", "Start", vec![("ScanType", 1)]).await?;
        }
        DefenderScanType::Full => {
            execute_wmi_method(&defender_conn, "MSFT_MpScan", "Start", vec![("ScanType", 2)]).await?;
        }
        DefenderScanType::Custom(path) => {
            return run_custom_scan(&defender_conn, path);
        }
    }
    
    Ok(ScanResult {
        scan_type,
        started_at: start_time,
        status: ScanStatus::Running,
        threats_found: None,
        scan_duration_ms: None,
    })
}

/// Execute WMI method
#[cfg(target_os = "windows")]
async fn execute_wmi_method(
    _conn: &WMIConnection,
    class: &str,
    method: &str,
    params: Vec<(&str, i32)>
) -> Result<()> {
    debug!("Executing WMI method {}.{} with params: {:?}", class, method, params);
    
    // Use PowerShell to trigger Windows Defender scans since WMI method invocation
    // is complex and requires specific privileges
    match (class, method) {
        ("MSFT_MpScan", "Start") => {
            let scan_type = params.iter()
                .find(|(name, _)| *name == "ScanType")
                .map(|(_, value)| *value)
                .unwrap_or(1);
            
            let powershell_cmd = match scan_type {
                1 => "Start-MpScan -ScanType QuickScan", // Quick scan
                2 => "Start-MpScan -ScanType FullScan",  // Full scan
                _ => return Err(anyhow!("Unsupported scan type: {}", scan_type)),
            };
            
            info!("Executing PowerShell command: {}", powershell_cmd);
            
            use std::process::Command;
            
            match Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", powershell_cmd])
                .output()
            {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    
                    if output.status.success() {
                        info!("Windows Defender scan started successfully");
                        if !stdout.is_empty() {
                            debug!("PowerShell output: {}", stdout);
                        }
                        Ok(())
                    } else {
                        let error_msg = if !stderr.is_empty() {
                            format!("PowerShell error: {}", stderr)
                        } else if !stdout.is_empty() {
                            format!("PowerShell output: {}", stdout)
                        } else {
                            format!("Command failed with exit code: {}", output.status)
                        };
                        
                        warn!("Failed to start Windows Defender scan: {}", error_msg);
                        Err(anyhow!("Failed to start scan: {}", error_msg))
                    }
                }
                Err(e) => {
                    let error_msg = format!("Failed to execute PowerShell command: {}", e);
                    warn!("{}", error_msg);
                    Err(anyhow!(error_msg))
                }
            }
        }
        _ => {
            let error_msg = format!("Unsupported WMI method: {}.{}", class, method);
            warn!("{}", error_msg);
            Err(anyhow!(error_msg))
        }
    }
}

/// Run custom path scan
#[cfg(target_os = "windows")]
fn run_custom_scan(_defender_conn: &WMIConnection, path: String) -> Result<ScanResult> {
    debug!("Running custom scan on path: {}", path);
    
    // Validate path
    if path.is_empty() {
        return Err(anyhow!("Custom scan path cannot be empty"));
    }
    
    // Use PowerShell to run custom path scan
    let powershell_cmd = format!("Start-MpScan -ScanType CustomScan -ScanPath '{}'", path.replace("'", "''"));
    
    info!("Executing PowerShell command: {}", powershell_cmd);
    
    use std::process::Command;
    
    match Command::new("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", &powershell_cmd])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            if output.status.success() {
                info!("Windows Defender custom scan started successfully for path: {}", path);
                if !stdout.is_empty() {
                    debug!("PowerShell output: {}", stdout);
                }
                
                Ok(ScanResult {
                    scan_type: DefenderScanType::Custom(path),
                    started_at: SystemTime::now(),
                    status: ScanStatus::Running,
                    threats_found: None,
                    scan_duration_ms: None,
                })
            } else {
                let error_msg = if !stderr.is_empty() {
                    format!("PowerShell error: {}", stderr)
                } else if !stdout.is_empty() {
                    format!("PowerShell output: {}", stdout)
                } else {
                    format!("Command failed with exit code: {}", output.status)
                };
                
                warn!("Failed to start Windows Defender custom scan: {}", error_msg);
                Err(anyhow!("Failed to start custom scan: {}", error_msg))
            }
        }
        Err(e) => {
            let error_msg = format!("Failed to execute PowerShell command for custom scan: {}", e);
            warn!("{}", error_msg);
            Err(anyhow!(error_msg))
        }
    }
}

/// Check Windows Defender (simplified interface)
#[cfg(target_os = "windows")]
pub async fn check_windows_defender() -> Result<DefenderStatus> {
    get_defender_status().await
}

/// Non-Windows implementation (stub)
#[cfg(not(target_os = "windows"))]
pub async fn get_defender_status() -> Result<DefenderStatus> {
    Err(anyhow!("Windows Defender status is only available on Windows"))
}

/// Non-Windows implementation (stub)
#[cfg(not(target_os = "windows"))]
pub async fn run_defender_scan(_scan_type: DefenderScanType) -> Result<ScanResult> {
    Err(anyhow!("Windows Defender scan is only available on Windows"))
}

/// Non-Windows implementation (stub)
#[cfg(not(target_os = "windows"))]
pub async fn check_windows_defender() -> Result<DefenderStatus> {
    Err(anyhow!("Windows Defender is only available on Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defender_status_serialization() {
        let status = DefenderStatus {
            enabled: true,
            real_time_protection: true,
            signature_age_days: 1,
            last_full_scan: Some("2024-01-15T10:30:00Z".to_string()),
            last_quick_scan: Some("2024-01-15T10:00:00Z".to_string()),
            threats_detected: 0,
            recent_threats: vec![],
            recent_scans: vec![],
            engine_version: Some("1.1.20700.4".to_string()),
            antivirus_signature_version: Some("1.383.1196.0".to_string()),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"real_time_protection\":true"));
    }

    #[test]
    fn test_scan_type_wmi_value() {
        assert_eq!(DefenderScanType::Quick.to_wmi_value(), 1);
        assert_eq!(DefenderScanType::Full.to_wmi_value(), 2);
        assert_eq!(DefenderScanType::Custom("C:\\test".to_string()).to_wmi_value(), 3);
    }

    #[test]
    fn test_threat_serialization() {
        let threat = MSFT_MpThreat {
            threat_id: Some(123456),
            threat_name: Some("Test.Threat".to_string()),
            severity_id: Some(4),
            detection_time: Some("2024-01-15T10:30:00Z".to_string()),
            initial_detection_method: Some("Real-time Protection".to_string()),
            current_threat_status: Some(2),
        };

        let json = serde_json::to_string(&threat).unwrap();
        assert!(json.contains("Test.Threat"));
    }
}