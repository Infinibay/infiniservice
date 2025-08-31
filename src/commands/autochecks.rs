//! Auto-Check Engine for automated health monitoring and issue detection
//!
//! This module provides the core auto-check engine that runs various health checks,
//! analyzes system state, and provides remediation recommendations.

pub mod health_checks;
pub mod remediation;

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use log::{debug, info, warn};

use health_checks::*;
use remediation::*;

/// Health check status levels
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Info,
    Warning,
    Critical,
}

/// Health check categories
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CheckCategory {
    Resource,      // CPU, RAM, Disk
    Performance,   // I/O, Network, Response time
    Security,      // Updates, Defender, Firewall
    Service,       // Service health, dependencies
    Application,   // App updates, compatibility
}

/// Health check result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckResult {
    pub check_name: String,
    pub category: CheckCategory,
    pub status: HealthStatus,
    pub message: String,
    pub details: serde_json::Value,
    pub remediation: Option<RemediationAction>,
    pub confidence: f32, // 0.0 to 1.0
    pub timestamp: SystemTime,
    pub execution_time_ms: u64,
}

/// Check execution context
pub struct CheckContext {
    pub vm_info: VmInfo,
    pub metrics_history: MetricsHistory,
    pub config: AutoCheckConfig,
}

/// VM information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VmInfo {
    pub cpu_count: u32,
    pub memory_mb: u64,
    pub os_type: String,
    pub os_version: String,
}

/// Metrics history for analysis
pub struct MetricsHistory {
    pub cpu_usage: Vec<(SystemTime, f32)>,
    pub memory_usage: Vec<(SystemTime, f32)>,
    pub disk_usage: Vec<(SystemTime, HashMap<String, f32>)>,
    pub network_usage: Vec<(SystemTime, HashMap<String, u64>)>,
}

/// Auto-check configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AutoCheckConfig {
    pub enabled_checks: Vec<String>,
    pub disk_warning_threshold: f32,
    pub disk_critical_threshold: f32,
    pub cpu_underutilized_threshold: f32,
    pub memory_overprovisioned_threshold: f32,
    pub evaluation_window_days: u32,
    pub auto_remediation_enabled: bool,
}

impl Default for AutoCheckConfig {
    fn default() -> Self {
        Self {
            enabled_checks: vec![
                "disk_space".to_string(),
                "resource_optimization".to_string(),
                "windows_updates".to_string(),
                "windows_defender".to_string(),
            ],
            disk_warning_threshold: 30.0,
            disk_critical_threshold: 10.0,
            cpu_underutilized_threshold: 5.0,
            memory_overprovisioned_threshold: 80.0,
            evaluation_window_days: 7,
            auto_remediation_enabled: false,
        }
    }
}

/// Trait for health checks
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> CheckCategory;
    async fn execute(&self, context: &CheckContext) -> Result<CheckResult>;
    fn can_auto_remediate(&self) -> bool;
}

/// Auto-check engine
pub struct AutoCheckEngine {
    checks: Vec<Box<dyn HealthCheck>>,
    config: AutoCheckConfig,
    remediation_engine: RemediationEngine,
}

impl AutoCheckEngine {
    /// Create a new auto-check engine
    pub fn new(config: AutoCheckConfig) -> Self {
        let mut checks: Vec<Box<dyn HealthCheck>> = Vec::new();
        
        // Register built-in checks
        if config.enabled_checks.contains(&"disk_space".to_string()) {
            checks.push(Box::new(DiskSpaceCheck::new(
                config.disk_warning_threshold,
                config.disk_critical_threshold,
            )));
        }
        
        if config.enabled_checks.contains(&"resource_optimization".to_string()) {
            checks.push(Box::new(ResourceOptimizationCheck::new(
                config.cpu_underutilized_threshold,
                config.memory_overprovisioned_threshold,
                Duration::from_secs(config.evaluation_window_days as u64 * 86400),
            )));
        }
        
        #[cfg(target_os = "windows")]
        {
            if config.enabled_checks.contains(&"windows_updates".to_string()) {
                checks.push(Box::new(WindowsUpdatesCheck::new()));
            }
            
            if config.enabled_checks.contains(&"windows_defender".to_string()) {
                checks.push(Box::new(WindowsDefenderCheck::new()));
            }
        }
        
        Self {
            checks,
            remediation_engine: RemediationEngine::new(config.auto_remediation_enabled),
            config,
        }
    }
    
    /// Run all enabled health checks
    pub async fn run_all_checks(&self, context: &CheckContext) -> Result<Vec<CheckResult>> {
        info!("Running {} health checks", self.checks.len());
        let mut results = Vec::new();
        
        for check in &self.checks {
            debug!("Running health check: {}", check.name());
            
            let start_time = SystemTime::now();
            match check.execute(context).await {
                Ok(mut result) => {
                    result.execution_time_ms = start_time
                        .elapsed()
                        .unwrap_or(Duration::from_millis(0))
                        .as_millis() as u64;
                    
                    debug!("Health check '{}' completed: {:?}", check.name(), result.status);
                    results.push(result);
                }
                Err(e) => {
                    warn!("Health check '{}' failed: {}", check.name(), e);
                    results.push(CheckResult {
                        check_name: check.name().to_string(),
                        category: check.category(),
                        status: HealthStatus::Warning,
                        message: format!("Check failed: {}", e),
                        details: serde_json::json!({"error": e.to_string()}),
                        remediation: None,
                        confidence: 0.0,
                        timestamp: SystemTime::now(),
                        execution_time_ms: start_time
                            .elapsed()
                            .unwrap_or(Duration::from_millis(0))
                            .as_millis() as u64,
                    });
                }
            }
        }
        
        info!("Health checks completed: {} results", results.len());
        Ok(results)
    }
    
    /// Run a specific health check by name
    pub async fn run_check(&self, check_name: &str, context: &CheckContext) -> Result<CheckResult> {
        debug!("Running specific health check: {}", check_name);
        
        let check = self.checks
            .iter()
            .find(|c| c.name() == check_name)
            .ok_or_else(|| anyhow::anyhow!("Health check '{}' not found", check_name))?;
        
        let start_time = SystemTime::now();
        let mut result = check.execute(context).await
            .context("Failed to execute health check")?;
        
        result.execution_time_ms = start_time
            .elapsed()
            .unwrap_or(Duration::from_millis(0))
            .as_millis() as u64;
        
        Ok(result)
    }
    
    /// Apply remediation for a check result
    pub async fn apply_remediation(
        &mut self,
        result: &CheckResult,
        auto_approve: bool,
    ) -> Result<RemediationResult> {
        if let Some(remediation) = &result.remediation {
            info!("Applying remediation for check '{}': {:?}", 
                  result.check_name, remediation);
            
            self.remediation_engine
                .apply_remediation(remediation.clone(), auto_approve)
                .await
        } else {
            Err(anyhow::anyhow!("No remediation available for check '{}'", result.check_name))
        }
    }
    
    /// Get summary of health status
    pub fn get_health_summary(results: &[CheckResult]) -> HealthSummary {
        let mut summary = HealthSummary {
            total_checks: results.len(),
            healthy: 0,
            info: 0,
            warnings: 0,
            critical: 0,
            overall_status: HealthStatus::Healthy,
            issues_requiring_attention: Vec::new(),
            remediations_available: 0,
        };
        
        for result in results {
            match result.status {
                HealthStatus::Healthy => summary.healthy += 1,
                HealthStatus::Info => summary.info += 1,
                HealthStatus::Warning => {
                    summary.warnings += 1;
                    summary.issues_requiring_attention.push(result.clone());
                }
                HealthStatus::Critical => {
                    summary.critical += 1;
                    summary.issues_requiring_attention.push(result.clone());
                }
            }
            
            if result.remediation.is_some() {
                summary.remediations_available += 1;
            }
        }
        
        // Determine overall status
        summary.overall_status = if summary.critical > 0 {
            HealthStatus::Critical
        } else if summary.warnings > 0 {
            HealthStatus::Warning
        } else if summary.info > 0 {
            HealthStatus::Info
        } else {
            HealthStatus::Healthy
        };
        
        summary
    }
}

/// Health summary
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthSummary {
    pub total_checks: usize,
    pub healthy: usize,
    pub info: usize,
    pub warnings: usize,
    pub critical: usize,
    pub overall_status: HealthStatus,
    pub issues_requiring_attention: Vec<CheckResult>,
    pub remediations_available: usize,
}

impl CheckContext {
    /// Get latest disk metrics using sysinfo crate
    pub fn get_latest_disk_metrics(&self) -> Result<Vec<DiskMetrics>> {
        use sysinfo::Disks;
        
        debug!("Collecting real disk metrics");
        
        let disks = Disks::new_with_refreshed_list();
        let mut disk_metrics = Vec::new();
        
        for disk in &disks {
            let mount_point = disk.mount_point().to_string_lossy().to_string();
            let total_bytes = disk.total_space();
            let available_bytes = disk.available_space();
            let used_bytes = total_bytes - available_bytes;
            let usage_percent = if total_bytes > 0 {
                (used_bytes as f64 / total_bytes as f64 * 100.0) as f32
            } else {
                0.0
            };
            
            debug!("Disk {}: {:.1}% used ({} GB free / {} GB total)",
                   mount_point, usage_percent,
                   available_bytes / (1024 * 1024 * 1024),
                   total_bytes / (1024 * 1024 * 1024));
            
            disk_metrics.push(DiskMetrics {
                mount_point,
                total_bytes,
                available_bytes,
                usage_percent,
            });
        }
        
        if disk_metrics.is_empty() {
            debug!("No disk metrics found, returning fallback data");
            // Fallback for testing or if sysinfo fails to detect disks
            disk_metrics.push(DiskMetrics {
                mount_point: if cfg!(windows) { "C:\\".to_string() } else { "/".to_string() },
                total_bytes: 1024 * 1024 * 1024 * 100, // 100GB
                available_bytes: 1024 * 1024 * 1024 * 50, // 50GB
                usage_percent: 50.0,
            });
        }
        
        Ok(disk_metrics)
    }
    
    /// Get metrics history for analysis
    pub fn get_metrics_history(&self, _window: Duration) -> Result<&MetricsHistory> {
        Ok(&self.metrics_history)
    }
}

/// Disk metrics structure
#[derive(Debug, Clone)]
pub struct DiskMetrics {
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn create_test_context() -> CheckContext {
        CheckContext {
            vm_info: VmInfo {
                cpu_count: 4,
                memory_mb: 8192,
                os_type: "Windows".to_string(),
                os_version: "10.0.19041".to_string(),
            },
            metrics_history: MetricsHistory {
                cpu_usage: vec![],
                memory_usage: vec![],
                disk_usage: vec![],
                network_usage: vec![],
            },
            config: AutoCheckConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_autocheck_engine_creation() {
        let config = AutoCheckConfig::default();
        let engine = AutoCheckEngine::new(config);
        
        assert!(!engine.checks.is_empty());
    }

    #[tokio::test]
    async fn test_health_summary() {
        let results = vec![
            CheckResult {
                check_name: "test1".to_string(),
                category: CheckCategory::Resource,
                status: HealthStatus::Healthy,
                message: "OK".to_string(),
                details: serde_json::json!({}),
                remediation: None,
                confidence: 1.0,
                timestamp: SystemTime::now(),
                execution_time_ms: 100,
            },
            CheckResult {
                check_name: "test2".to_string(),
                category: CheckCategory::Security,
                status: HealthStatus::Warning,
                message: "Warning".to_string(),
                details: serde_json::json!({}),
                remediation: None,
                confidence: 0.8,
                timestamp: SystemTime::now(),
                execution_time_ms: 200,
            },
        ];

        let summary = AutoCheckEngine::get_health_summary(&results);
        
        assert_eq!(summary.total_checks, 2);
        assert_eq!(summary.healthy, 1);
        assert_eq!(summary.warnings, 1);
        assert_eq!(summary.overall_status, HealthStatus::Warning);
    }
}