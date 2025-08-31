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
#[cfg(target_os = "windows")]
pub async fn get_defender_status() -> Result<DefenderStatus> {
    info!("Checking Windows Defender status via WMI");
    
    let com_lib = COMLibrary::new()
        .context("Failed to initialize COM library")?;
    
    // Connect to Windows Defender WMI namespace
    let defender_conn = WMIConnection::with_namespace_path(
        "root\\Microsoft\\Windows\\Defender",
        com_lib,
    ).context("Failed to connect to Windows Defender WMI namespace")?;
    
    // Get computer status
    let status = get_computer_status(&defender_conn).await?;
    
    // Get threat history
    let threats = get_threat_history(&defender_conn).await
        .unwrap_or_else(|e| {
            warn!("Failed to get threat history: {}", e);
            Vec::new()
        });
    
    // Get scan history
    let scans = get_scan_history(&defender_conn).await
        .unwrap_or_else(|e| {
            warn!("Failed to get scan history: {}", e);
            Vec::new()
        });
    
    // Get signature versions
    let (engine_version, signature_version) = get_signature_versions(&defender_conn).await
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

/// Get computer status from MSFT_MpComputerStatus
#[cfg(target_os = "windows")]
async fn get_computer_status(defender_conn: &WMIConnection) -> Result<MSFT_MpComputerStatus> {
    debug!("Querying MSFT_MpComputerStatus");
    
    let status: Vec<MSFT_MpComputerStatus> = defender_conn
        .raw_query("SELECT * FROM MSFT_MpComputerStatus")
        .context("Failed to query MSFT_MpComputerStatus")?;
    
    status.into_iter().next()
        .ok_or_else(|| anyhow!("No Defender computer status found"))
}

/// Get threat history from MSFT_MpThreat
#[cfg(target_os = "windows")]
async fn get_threat_history(defender_conn: &WMIConnection) -> Result<Vec<MSFT_MpThreat>> {
    debug!("Querying MSFT_MpThreat");
    
    let threats: Vec<MSFT_MpThreat> = defender_conn
        .raw_query("SELECT * FROM MSFT_MpThreat ORDER BY DetectionTime DESC")
        .context("Failed to query MSFT_MpThreat")?;
    
    info!("Found {} threats in history", threats.len());
    Ok(threats)
}

/// Get scan history from MSFT_MpScan
#[cfg(target_os = "windows")]
async fn get_scan_history(defender_conn: &WMIConnection) -> Result<Vec<MSFT_MpScan>> {
    debug!("Querying MSFT_MpScan");
    
    let scans: Vec<MSFT_MpScan> = defender_conn
        .raw_query("SELECT * FROM MSFT_MpScan ORDER BY ScanStartTime DESC")
        .context("Failed to query MSFT_MpScan")?;
    
    info!("Found {} scans in history", scans.len());
    Ok(scans)
}

/// Get signature versions
#[cfg(target_os = "windows")]
async fn get_signature_versions(defender_conn: &WMIConnection) -> Result<(Option<String>, Option<String>)> {
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
            return run_custom_scan(&defender_conn, path).await;
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
async fn run_custom_scan(_defender_conn: &WMIConnection, path: String) -> Result<ScanResult> {
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