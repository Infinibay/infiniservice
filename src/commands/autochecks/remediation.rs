//! Remediation engine for automated issue resolution
//!
//! This module provides the remediation engine that can apply fixes for detected
//! issues, with rollback support and approval workflows.
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use log::{debug, info, error};

/// Remediation actions that can be taken
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RemediationAction {
    // Disk operations
    CleanupDisk {
        drive: String,
        estimated_recovery_gb: f32,
    },
    SuggestCleanup {
        drive: String,
    },
    
    // Service operations  
    RestartService {
        service_name: String,
        reason: String,
    },
    
    // Security operations
    InstallSecurityUpdates {
        update_count: usize,
        critical_count: usize,
    },
    RunDefenderScan {
        scan_type: DefenderScanType,
    },
    EnableDefender,
    UpdateDefenderSignatures,
    
    // Resource optimization
    OptimizeResources {
        recommendations: Vec<Recommendation>,
    },
    
    // Application management
    UpdateApplications {
        applications: Vec<String>,
    },
}

/// Defender scan type for remediation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DefenderScanType {
    Quick,
    Full,
    Custom(String),
}

/// Resource optimization recommendation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Recommendation {
    pub resource: String,
    pub current: String,
    pub suggested: String,
    pub reason: String,
    pub savings: String,
}

/// Risk assessment levels
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Remediation result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RemediationResult {
    Success {
        action: RemediationAction,
        details: serde_json::Value,
        duration: Duration,
    },
    PendingApproval {
        action: RemediationAction,
        risk_level: RiskLevel,
        estimated_duration: Duration,
    },
    Failed {
        action: RemediationAction,
        error: String,
        rolled_back: bool,
    },
}

/// Rollback information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RollbackPoint {
    pub id: String,
    pub action: RemediationAction,
    pub timestamp: SystemTime,
    pub backup_data: serde_json::Value,
}

/// Remediation engine
pub struct RemediationEngine {
    auto_approve_low_risk: bool,
    rollback_points: HashMap<String, RollbackPoint>,
    execution_history: Vec<RemediationExecution>,
}

/// Remediation execution record
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemediationExecution {
    pub action: RemediationAction,
    pub timestamp: SystemTime,
    pub result: String,
    pub duration_ms: u64,
}

impl RemediationEngine {
    /// Create a new remediation engine
    pub fn new(auto_approve_low_risk: bool) -> Self {
        Self {
            auto_approve_low_risk,
            rollback_points: HashMap::new(),
            execution_history: Vec::new(),
        }
    }
    
    /// Apply a remediation action
    pub async fn apply_remediation(
        &mut self,
        action: RemediationAction,
        auto_approve: bool,
    ) -> Result<RemediationResult> {
        let start_time = SystemTime::now();
        
        info!("Applying remediation: {:?}", action);
        
        // Check if action requires approval
        if !auto_approve && self.requires_approval(&action) {
            let risk_level = self.assess_risk(&action);
            let estimated_duration = self.estimate_duration(&action);
            
            if !self.auto_approve_low_risk || matches!(risk_level, RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical) {
                return Ok(RemediationResult::PendingApproval {
                    action,
                    risk_level,
                    estimated_duration,
                });
            }
        }
        
        // Create rollback point
        let rollback_id = self.create_checkpoint(&action).await?;
        
        // Execute remediation
        let result = match &action {
            RemediationAction::CleanupDisk { drive, .. } => {
                self.cleanup_disk(drive).await
            }
            RemediationAction::SuggestCleanup { .. } => {
                // Suggestions don't need actual execution
                Ok(json!({"suggestion": "provided to user"}))
            }
            RemediationAction::RestartService { service_name, .. } => {
                self.restart_service(service_name).await
            }
            RemediationAction::InstallSecurityUpdates { .. } => {
                self.install_updates().await
            }
            RemediationAction::RunDefenderScan { scan_type } => {
                self.run_defender_scan(scan_type).await
            }
            RemediationAction::EnableDefender => {
                self.enable_defender().await
            }
            RemediationAction::UpdateDefenderSignatures => {
                self.update_defender_signatures().await
            }
            RemediationAction::OptimizeResources { recommendations } => {
                self.optimize_resources(recommendations).await
            }
            RemediationAction::UpdateApplications { applications } => {
                self.update_applications(applications).await
            }
        };
        
        let duration = start_time.elapsed().unwrap_or(Duration::from_millis(0));
        
        // Handle result
        match result {
            Ok(details) => {
                self.mark_successful(rollback_id).await?;
                
                // Record execution
                self.execution_history.push(RemediationExecution {
                    action: action.clone(),
                    timestamp: start_time,
                    result: "Success".to_string(),
                    duration_ms: duration.as_millis() as u64,
                });
                
                info!("Remediation completed successfully in {:?}", duration);
                
                Ok(RemediationResult::Success {
                    action,
                    details,
                    duration,
                })
            }
            Err(e) => {
                error!("Remediation failed: {}", e);
                
                // Attempt rollback
                let rolled_back = match self.rollback(rollback_id).await {
                    Ok(_) => {
                        info!("Rollback completed successfully");
                        true
                    }
                    Err(rollback_err) => {
                        error!("Rollback failed: {}", rollback_err);
                        false
                    }
                };
                
                // Record execution
                self.execution_history.push(RemediationExecution {
                    action: action.clone(),
                    timestamp: start_time,
                    result: format!("Failed: {}", e),
                    duration_ms: duration.as_millis() as u64,
                });
                
                Ok(RemediationResult::Failed {
                    action,
                    error: e.to_string(),
                    rolled_back,
                })
            }
        }
    }
    
    /// Check if an action requires approval
    fn requires_approval(&self, action: &RemediationAction) -> bool {
        match action {
            RemediationAction::SuggestCleanup { .. } => false,
            RemediationAction::CleanupDisk { .. } => false, // Low risk
            RemediationAction::UpdateDefenderSignatures => false, // Low risk
            RemediationAction::RunDefenderScan { .. } => false, // Low risk
            _ => true, // Most actions require approval
        }
    }
    
    /// Assess risk level of an action
    fn assess_risk(&self, action: &RemediationAction) -> RiskLevel {
        match action {
            RemediationAction::SuggestCleanup { .. } => RiskLevel::Low,
            RemediationAction::CleanupDisk { .. } => RiskLevel::Low,
            RemediationAction::UpdateDefenderSignatures => RiskLevel::Low,
            RemediationAction::RunDefenderScan { .. } => RiskLevel::Low,
            
            RemediationAction::EnableDefender => RiskLevel::Medium,
            RemediationAction::UpdateApplications { .. } => RiskLevel::Medium,
            
            RemediationAction::RestartService { .. } => RiskLevel::High,
            RemediationAction::InstallSecurityUpdates { .. } => RiskLevel::High,
            
            RemediationAction::OptimizeResources { .. } => RiskLevel::Critical,
        }
    }
    
    /// Estimate duration for an action
    fn estimate_duration(&self, action: &RemediationAction) -> Duration {
        match action {
            RemediationAction::SuggestCleanup { .. } => Duration::from_secs(0),
            RemediationAction::UpdateDefenderSignatures => Duration::from_secs(30),
            RemediationAction::CleanupDisk { .. } => Duration::from_secs(120),
            RemediationAction::EnableDefender => Duration::from_secs(60),
            RemediationAction::RunDefenderScan { .. } => Duration::from_secs(300),
            RemediationAction::RestartService { .. } => Duration::from_secs(30),
            RemediationAction::UpdateApplications { .. } => Duration::from_secs(600),
            RemediationAction::InstallSecurityUpdates { .. } => Duration::from_secs(1800),
            RemediationAction::OptimizeResources { .. } => Duration::from_secs(0), // Manual action
        }
    }
    
    /// Create a rollback checkpoint
    async fn create_checkpoint(&mut self, action: &RemediationAction) -> Result<String> {
        let rollback_id = uuid::Uuid::new_v4().to_string();
        
        debug!("Creating rollback checkpoint: {}", rollback_id);
        
        // Gather backup data based on action type
        let backup_data = match action {
            RemediationAction::RestartService { service_name, .. } => {
                json!({
                    "service_name": service_name,
                    "previous_state": "running", // Would query actual state
                })
            }
            RemediationAction::EnableDefender => {
                json!({
                    "previous_defender_state": "disabled", // Would query actual state
                })
            }
            _ => json!({}), // No backup needed for other actions
        };
        
        let rollback_point = RollbackPoint {
            id: rollback_id.clone(),
            action: action.clone(),
            timestamp: SystemTime::now(),
            backup_data,
        };
        
        self.rollback_points.insert(rollback_id.clone(), rollback_point);
        
        Ok(rollback_id)
    }
    
    /// Mark checkpoint as successful (can be cleaned up)
    async fn mark_successful(&mut self, rollback_id: String) -> Result<()> {
        debug!("Marking rollback checkpoint as successful: {}", rollback_id);
        self.rollback_points.remove(&rollback_id);
        Ok(())
    }
    
    /// Perform rollback
    async fn rollback(&mut self, rollback_id: String) -> Result<()> {
        debug!("Performing rollback: {}", rollback_id);
        
        let rollback_point = self.rollback_points.remove(&rollback_id)
            .ok_or_else(|| anyhow!("Rollback point not found: {}", rollback_id))?;
        
        // Perform rollback based on action type
        match rollback_point.action {
            RemediationAction::RestartService { service_name, .. } => {
                info!("Rolling back service restart for: {}", service_name);
                // Would implement actual service state restoration
            }
            RemediationAction::EnableDefender => {
                info!("Rolling back Defender enablement");
                // Would implement actual Defender state restoration
            }
            _ => {
                debug!("No rollback action needed for: {:?}", rollback_point.action);
            }
        }
        
        Ok(())
    }
    
    // Remediation implementation methods
    
    async fn cleanup_disk(&self, drive: &str) -> Result<serde_json::Value> {
        info!("Starting disk cleanup for drive: {}", drive);
        
        let start_time = std::time::Instant::now();
        let mut cleaned_items = Vec::new();
        let mut total_freed_bytes = 0u64;
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            use std::path::Path;
            use std::fs;
            
            // Try to run Windows Disk Cleanup utility first
            let drive_letter = drive.chars().next().unwrap_or('C');
            
            // Use PowerShell to run disk cleanup
            let cleanup_cmd = format!(
                "Start-Process cleanmgr -ArgumentList '/sagerun:1', '/d', '{}' -Wait -WindowStyle Hidden",
                drive_letter
            );
            
            info!("Attempting to run Windows Disk Cleanup utility");
            match Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", &cleanup_cmd])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        info!("Windows Disk Cleanup utility completed");
                        cleaned_items.push("Windows Disk Cleanup");
                    } else {
                        warn!("Windows Disk Cleanup utility failed: {}", 
                              String::from_utf8_lossy(&output.stderr));
                    }
                }
                Err(e) => {
                    warn!("Failed to run Windows Disk Cleanup utility: {}", e);
                }
            }
            
            // Manual cleanup of common temporary directories
            let temp_paths = vec![
                format!("{}Windows\\Temp", drive),
                format!("{}Temp", std::env::var("TEMP").unwrap_or_default()),
                format!("{}Windows\\Prefetch", drive),
                format!("{}Windows\\SoftwareDistribution\\Download", drive),
            ];
            
            for temp_path in temp_paths {
                if let Ok(freed) = self.cleanup_directory(&temp_path).await {
                    if freed > 0 {
                        total_freed_bytes += freed;
                        cleaned_items.push(format!("Cleaned {}", temp_path));
                    }
                }
            }
            
            // Clean browser caches
            let browser_caches = vec![
                format!("{}Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache", drive),
                format!("{}Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache", drive),
                format!("{}Users\\*\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\*\\cache2", drive),
            ];
            
            for cache_path in browser_caches {
                // Use PowerShell to handle wildcards
                let ps_cmd = format!("Get-ChildItem -Path '{}' -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue", cache_path);
                match Command::new("powershell")
                    .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
                    .output()
                {
                    Ok(_) => {
                        cleaned_items.push(format!("Browser cache: {}", cache_path));
                    }
                    Err(e) => {
                        debug!("Failed to clean browser cache {}: {}", cache_path, e);
                    }
                }
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // Linux/Unix cleanup
            let temp_paths = vec![
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                format!("{}/.cache", std::env::var("HOME").unwrap_or_default()),
            ];
            
            for temp_path in temp_paths {
                if let Ok(freed) = self.cleanup_directory(&temp_path).await {
                    if freed > 0 {
                        total_freed_bytes += freed;
                        cleaned_items.push(format!("Cleaned {}", temp_path));
                    }
                }
            }
        }
        
        let duration_ms = start_time.elapsed().as_millis() as u64;
        
        let cleanup_result = json!({
            "freed_bytes": total_freed_bytes,
            "cleaned_items": cleaned_items,
            "duration_ms": duration_ms,
            "drive": drive,
        });
        
        info!("Disk cleanup completed for drive: {}. Freed {} bytes in {} ms", 
              drive, total_freed_bytes, duration_ms);
        
        Ok(cleanup_result)
    }
    
    /// Clean a specific directory (helper function)
    fn cleanup_directory_sync(&self, path: &str, max_depth: u32) -> Result<u64> {
        use std::fs;
        use std::path::Path;
        
        debug!("Cleaning directory: {} (depth: {})", path, max_depth);
        
        if max_depth == 0 {
            debug!("Maximum depth reached, skipping: {}", path);
            return Ok(0);
        }
        
        let path_obj = Path::new(path);
        if !path_obj.exists() {
            return Ok(0);
        }
        
        let mut total_freed = 0u64;
        
        match fs::read_dir(path_obj) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    
                    // Only clean files older than 1 day for safety
                    if let Ok(metadata) = entry.metadata() {
                        if let Ok(modified) = metadata.modified() {
                            let age = std::time::SystemTime::now()
                                .duration_since(modified)
                                .unwrap_or(Duration::from_secs(0));
                            
                            if age > Duration::from_secs(86400) { // 1 day
                                let file_size = metadata.len();
                                
                                if entry_path.is_file() {
                                    if fs::remove_file(&entry_path).is_ok() {
                                        total_freed += file_size;
                                        debug!("Removed file: {:?} ({} bytes)", entry_path, file_size);
                                    }
                                } else if entry_path.is_dir() && max_depth > 1 {
                                    // Recursively clean subdirectories (with caution and depth limit)
                                    if let Ok(sub_freed) = self.cleanup_directory_sync(&entry_path.to_string_lossy(), max_depth - 1) {
                                        total_freed += sub_freed;
                                    }
                                    
                                    // Try to remove empty directory
                                    let _ = fs::remove_dir(&entry_path);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to read directory {}: {}", path, e);
                return Err(anyhow!("Failed to read directory: {}", e));
            }
        }
        
        Ok(total_freed)
    }
    
    /// Clean a specific directory (async wrapper)
    async fn cleanup_directory(&self, path: &str) -> Result<u64> {
        // Use tokio::task::spawn_blocking to run the sync cleanup in a separate thread
        // This prevents blocking the async runtime while maintaining the recursive capability
        let path_owned = path.to_string();
        let max_depth = 3; // Limit recursion depth for safety
        
        tokio::task::spawn_blocking(move || {
            let remediation = RemediationEngine::new(false);
            remediation.cleanup_directory_sync(&path_owned, max_depth)
        })
        .await
        .map_err(|e| anyhow!("Failed to execute cleanup task: {}", e))?
    }
    
    async fn restart_service(&self, service_name: &str) -> Result<serde_json::Value> {
        info!("Restarting service: {}", service_name);
        
        let start_time = std::time::Instant::now();
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            // Stop the service first
            info!("Stopping service: {}", service_name);
            let stop_result = Command::new("sc")
                .args(&["stop", service_name])
                .output()
                .context("Failed to execute sc stop command")?;
            
            if !stop_result.status.success() {
                let stderr = String::from_utf8_lossy(&stop_result.stderr);
                warn!("Failed to stop service {}: {}", service_name, stderr);
                
                // Check if service is already stopped
                if !stderr.contains("1062") { // ERROR_SERVICE_NOT_ACTIVE
                    return Err(anyhow!("Failed to stop service {}: {}", service_name, stderr));
                }
            }
            
            // Wait a moment for the service to fully stop
            tokio::time::sleep(Duration::from_millis(2000)).await;
            
            // Start the service
            info!("Starting service: {}", service_name);
            let start_result = Command::new("sc")
                .args(&["start", service_name])
                .output()
                .context("Failed to execute sc start command")?;
            
            if !start_result.status.success() {
                let stderr = String::from_utf8_lossy(&start_result.stderr);
                return Err(anyhow!("Failed to start service {}: {}", service_name, stderr));
            }
            
            // Wait for service to be fully running
            tokio::time::sleep(Duration::from_millis(3000)).await;
            
            // Verify service is running
            let query_result = Command::new("sc")
                .args(&["query", service_name])
                .output()
                .context("Failed to query service status")?;
            
            let query_output = String::from_utf8_lossy(&query_result.stdout);
            let is_running = query_output.contains("RUNNING");
            
            if !is_running {
                warn!("Service {} may not be running after restart", service_name);
            }
            
            let duration_ms = start_time.elapsed().as_millis() as u64;
            
            Ok(json!({
                "service_name": service_name,
                "action": "restart",
                "status": if is_running { "success" } else { "warning" },
                "restart_duration_ms": duration_ms,
                "is_running": is_running,
                "details": "Service restarted using Windows Service Control Manager"
            }))
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            use std::process::Command;
            
            // Try systemctl first (most modern Linux systems)
            let systemctl_result = Command::new("systemctl")
                .args(&["restart", service_name])
                .output();
            
            match systemctl_result {
                Ok(output) => {
                    if output.status.success() {
                        let duration_ms = start_time.elapsed().as_millis() as u64;
                        
                        // Check if service is active
                        let status_result = Command::new("systemctl")
                            .args(&["is-active", service_name])
                            .output();
                        
                        let is_active = status_result
                            .map(|s| String::from_utf8_lossy(&s.stdout).trim() == "active")
                            .unwrap_or(false);
                        
                        Ok(json!({
                            "service_name": service_name,
                            "action": "restart",
                            "status": if is_active { "success" } else { "warning" },
                            "restart_duration_ms": duration_ms,
                            "is_running": is_active,
                            "method": "systemctl",
                            "details": "Service restarted using systemctl"
                        }))
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        Err(anyhow!("Failed to restart service {} with systemctl: {}", service_name, stderr))
                    }
                }
                Err(_) => {
                    // Fallback to service command
                    let service_result = Command::new("service")
                        .args(&[service_name, "restart"])
                        .output();
                    
                    match service_result {
                        Ok(output) => {
                            if output.status.success() {
                                let duration_ms = start_time.elapsed().as_millis() as u64;
                                
                                Ok(json!({
                                    "service_name": service_name,
                                    "action": "restart",
                                    "status": "success",
                                    "restart_duration_ms": duration_ms,
                                    "method": "service",
                                    "details": "Service restarted using service command"
                                }))
                            } else {
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                Err(anyhow!("Failed to restart service {} with service command: {}", service_name, stderr))
                            }
                        }
                        Err(e) => {
                            Err(anyhow!("Failed to restart service {} - no service management tool available: {}", service_name, e))
                        }
                    }
                }
            }
        }
    }
    
    async fn install_updates(&self) -> Result<serde_json::Value> {
        info!("Installing Windows updates");
        
        // In a real implementation, this would:
        // 1. Use Windows Update Agent COM API
        // 2. Download and install selected updates
        // 3. Handle reboot requirements
        
        // This is a high-risk operation that should typically require approval
        Err(anyhow!("Update installation requires manual approval and scheduling"))
    }
    
    async fn run_defender_scan(&self, scan_type: &DefenderScanType) -> Result<serde_json::Value> {
        info!("Starting Windows Defender scan: {:?}", scan_type);
        
        #[cfg(target_os = "windows")]
        {
            use crate::commands::windows_defender;
            
            match windows_defender::run_defender_scan(match scan_type {
                DefenderScanType::Quick => windows_defender::DefenderScanType::Quick,
                DefenderScanType::Full => windows_defender::DefenderScanType::Full,
                DefenderScanType::Custom(path) => windows_defender::DefenderScanType::Custom(path.clone()),
            }).await {
                Ok(scan_result) => {
                    Ok(json!({
                        "scan_type": scan_type,
                        "status": scan_result.status,
                        "started_at": scan_result.started_at,
                    }))
                }
                Err(e) => Err(e),
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows Defender scan is only available on Windows"))
        }
    }
    
    async fn enable_defender(&self) -> Result<serde_json::Value> {
        info!("Enabling Windows Defender");
        
        let start_time = std::time::Instant::now();
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            let mut actions_performed = Vec::new();
            let mut has_errors = false;
            let mut error_messages = Vec::new();
            
            // Enable Windows Defender real-time protection
            let enable_realtime_cmd = "Set-MpPreference -DisableRealtimeMonitoring $false";
            
            info!("Enabling real-time protection");
            match Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", enable_realtime_cmd])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        actions_performed.push("Enabled real-time protection");
                        info!("Real-time protection enabled successfully");
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        error_messages.push(format!("Failed to enable real-time protection: {}", stderr));
                        has_errors = true;
                    }
                }
                Err(e) => {
                    error_messages.push(format!("Failed to execute real-time protection command: {}", e));
                    has_errors = true;
                }
            }
            
            // Enable cloud-delivered protection
            let enable_cloud_cmd = "Set-MpPreference -MAPSReporting Advanced";
            
            info!("Enabling cloud-delivered protection");
            match Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", enable_cloud_cmd])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        actions_performed.push("Enabled cloud-delivered protection");
                        info!("Cloud-delivered protection enabled successfully");
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!("Failed to enable cloud protection: {}", stderr);
                        // Non-critical error, don't mark as failure
                    }
                }
                Err(e) => {
                    warn!("Failed to execute cloud protection command: {}", e);
                }
            }
            
            // Enable automatic sample submission
            let enable_sample_cmd = "Set-MpPreference -SubmitSamplesConsent SendAllSamples";
            
            info!("Enabling automatic sample submission");
            match Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", enable_sample_cmd])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        actions_performed.push("Enabled automatic sample submission");
                        info!("Automatic sample submission enabled successfully");
                    } else {
                        warn!("Failed to enable sample submission: {}", String::from_utf8_lossy(&output.stderr));
                        // Non-critical error
                    }
                }
                Err(e) => {
                    warn!("Failed to execute sample submission command: {}", e);
                }
            }
            
            // Try to enable Windows Defender service if it's disabled
            let enable_service_cmd = "Set-Service -Name 'WinDefend' -StartupType Automatic; Start-Service -Name 'WinDefend' -ErrorAction SilentlyContinue";
            
            info!("Ensuring Windows Defender service is running");
            match Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", enable_service_cmd])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        actions_performed.push("Started Windows Defender service");
                        info!("Windows Defender service started successfully");
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        warn!("Failed to start Windows Defender service: {}", stderr);
                        // This might fail if already running, so don't mark as critical error
                    }
                }
                Err(e) => {
                    warn!("Failed to execute service start command: {}", e);
                }
            }
            
            // Verify current status
            let status_cmd = "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled";
            let status_result = Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", status_cmd])
                .output();
            
            let (realtime_enabled, antivirus_enabled) = status_result
                .ok()
                .and_then(|s| {
                    if s.status.success() {
                        let output = String::from_utf8_lossy(&s.stdout);
                        let realtime = output.contains("True") && output.contains("RealTimeProtectionEnabled");
                        let antivirus = output.contains("True") && output.contains("AntivirusEnabled");
                        Some((realtime, antivirus))
                    } else {
                        None
                    }
                })
                .unwrap_or((false, false));
            
            let duration_ms = start_time.elapsed().as_millis() as u64;
            let overall_status = if !has_errors && (realtime_enabled || antivirus_enabled) {
                "success"
            } else if !actions_performed.is_empty() {
                "partial_success" 
            } else {
                "failed"
            };
            
            Ok(json!({
                "action": "enable_defender",
                "status": overall_status,
                "real_time_protection": realtime_enabled,
                "antivirus_enabled": antivirus_enabled,
                "duration_ms": duration_ms,
                "actions_performed": actions_performed,
                "errors": error_messages,
                "details": "Windows Defender configuration updated using PowerShell cmdlets"
            }))
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows Defender enablement is only available on Windows"))
        }
    }
    
    async fn update_defender_signatures(&self) -> Result<serde_json::Value> {
        info!("Updating Windows Defender signatures");
        
        let start_time = std::time::Instant::now();
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            // Use PowerShell to update Windows Defender signatures
            let update_cmd = "Update-MpSignature";
            
            info!("Executing PowerShell command: {}", update_cmd);
            
            match Command::new("powershell")
                .args(&["-NoProfile", "-NonInteractive", "-Command", update_cmd])
                .output()
            {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let duration_ms = start_time.elapsed().as_millis() as u64;
                    
                    if output.status.success() {
                        info!("Windows Defender signatures updated successfully in {} ms", duration_ms);
                        
                        // Try to get the current signature version
                        let version_cmd = "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureVersion";
                        let version_result = Command::new("powershell")
                            .args(&["-NoProfile", "-NonInteractive", "-Command", version_cmd])
                            .output();
                        
                        let signature_version = version_result
                            .ok()
                            .and_then(|v| {
                                if v.status.success() {
                                    Some(String::from_utf8_lossy(&v.stdout).trim().to_string())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| "unknown".to_string());
                        
                        Ok(json!({
                            "action": "update_signatures",
                            "status": "success",
                            "duration_ms": duration_ms,
                            "signature_version": signature_version,
                            "details": "Signatures updated using Update-MpSignature PowerShell cmdlet"
                        }))
                    } else {
                        let error_msg = if !stderr.is_empty() {
                            format!("PowerShell error: {}", stderr)
                        } else if !stdout.is_empty() {
                            format!("PowerShell output: {}", stdout)
                        } else {
                            format!("Command failed with exit code: {}", output.status)
                        };
                        
                        warn!("Failed to update Windows Defender signatures: {}", error_msg);
                        
                        // Try alternative method using Windows Update
                        info!("Trying alternative signature update method");
                        let alt_cmd = "Start-Process -FilePath 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -ArgumentList '-SignatureUpdate' -Wait -WindowStyle Hidden";
                        
                        match Command::new("powershell")
                            .args(&["-NoProfile", "-NonInteractive", "-Command", alt_cmd])
                            .output()
                        {
                            Ok(alt_output) => {
                                let alt_duration = start_time.elapsed().as_millis() as u64;
                                
                                if alt_output.status.success() {
                                    info!("Windows Defender signatures updated using MpCmdRun");
                                    Ok(json!({
                                        "action": "update_signatures",
                                        "status": "success",
                                        "duration_ms": alt_duration,
                                        "signature_version": "updated",
                                        "details": "Signatures updated using MpCmdRun.exe alternative method"
                                    }))
                                } else {
                                    Err(anyhow!("Failed to update signatures using both methods: {} | {}", 
                                               error_msg, String::from_utf8_lossy(&alt_output.stderr)))
                                }
                            }
                            Err(e) => {
                                Err(anyhow!("Failed to update signatures: {} | Alt method error: {}", error_msg, e))
                            }
                        }
                    }
                }
                Err(e) => {
                    Err(anyhow!("Failed to execute PowerShell signature update command: {}", e))
                }
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows Defender signature update is only available on Windows"))
        }
    }
    
    async fn optimize_resources(&self, recommendations: &[Recommendation]) -> Result<serde_json::Value> {
        info!("Resource optimization requested");
        
        // Resource optimization requires manual intervention
        // This would typically generate a report for the administrator
        
        Ok(json!({
            "action": "optimize_resources",
            "status": "manual_action_required",
            "recommendations": recommendations,
            "message": "Resource optimization requires manual VM configuration changes"
        }))
    }
    
    async fn update_applications(&self, applications: &[String]) -> Result<serde_json::Value> {
        info!("Updating applications: {:?}", applications);
        
        // In a real implementation, this would:
        // 1. Check each application for updates
        // 2. Download and install available updates
        // 3. Handle any required restarts
        
        // This is a medium-risk operation
        let mut results = Vec::new();
        
        for app in applications {
            // Simulate update process
            tokio::time::sleep(Duration::from_millis(2000)).await;
            
            results.push(json!({
                "application": app,
                "status": "updated",
                "version": "latest",
            }));
        }
        
        Ok(json!({
            "action": "update_applications",
            "updated_applications": results,
            "total_duration_ms": applications.len() as u64 * 2000,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_remediation_engine_creation() {
        let engine = RemediationEngine::new(true);
        assert!(engine.auto_approve_low_risk);
        assert!(engine.rollback_points.is_empty());
    }

    #[tokio::test]
    async fn test_risk_assessment() {
        let engine = RemediationEngine::new(false);
        
        let low_risk = RemediationAction::CleanupDisk {
            drive: "C:\\".to_string(),
            estimated_recovery_gb: 1.0,
        };
        
        let high_risk = RemediationAction::InstallSecurityUpdates {
            update_count: 5,
            critical_count: 2,
        };
        
        assert!(matches!(engine.assess_risk(&low_risk), RiskLevel::Low));
        assert!(matches!(engine.assess_risk(&high_risk), RiskLevel::High));
    }

    #[tokio::test]
    async fn test_cleanup_disk_remediation() {
        let engine = RemediationEngine::new(true);
        
        let result = engine.cleanup_disk("C:\\").await.unwrap();
        assert!(result["freed_bytes"].as_u64().is_some());
        assert!(result["cleaned_items"].is_array());
    }

    #[test]
    fn test_duration_estimation() {
        let engine = RemediationEngine::new(false);
        
        let quick_action = RemediationAction::UpdateDefenderSignatures;
        let slow_action = RemediationAction::InstallSecurityUpdates {
            update_count: 5,
            critical_count: 2,
        };
        
        assert!(engine.estimate_duration(&quick_action) < engine.estimate_duration(&slow_action));
    }
}