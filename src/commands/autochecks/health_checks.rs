//! Health check implementations
//!
//! This module contains implementations of specific health checks that can be
//! run by the auto-check engine.

use super::*;
use anyhow::Result;
use serde_json::json;
use std::time::Duration;

#[cfg(target_os = "windows")]
use crate::commands::windows_updates;
#[cfg(target_os = "windows")]
use crate::commands::windows_defender;

/// Disk space health check
pub struct DiskSpaceCheck {
    warning_threshold: f32,  // % free space
    critical_threshold: f32, // % free space
}

impl DiskSpaceCheck {
    pub fn new(warning_threshold: f32, critical_threshold: f32) -> Self {
        Self {
            warning_threshold,
            critical_threshold,
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for DiskSpaceCheck {
    fn name(&self) -> &str {
        "disk_space"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Resource
    }

    async fn execute(&self, context: &CheckContext) -> Result<CheckResult> {
        debug!("Executing disk space health check");
        
        let disk_metrics = context.get_latest_disk_metrics()?;
        
        for disk in &disk_metrics {
            let free_percent = 100.0 - disk.usage_percent;
            
            if free_percent < self.critical_threshold {
                return Ok(CheckResult {
                    check_name: self.name().to_string(),
                    category: self.category(),
                    status: HealthStatus::Critical,
                    message: format!(
                        "Critical: Drive {} has only {:.1}% free space",
                        disk.mount_point, free_percent
                    ),
                    details: json!({
                        "drive": disk.mount_point,
                        "free_gb": disk.available_bytes / 1_073_741_824,
                        "total_gb": disk.total_bytes / 1_073_741_824,
                        "free_percent": free_percent,
                        "usage_percent": disk.usage_percent,
                    }),
                    remediation: Some(RemediationAction::CleanupDisk {
                        drive: disk.mount_point.clone(),
                        estimated_recovery_gb: estimate_cleanup_potential(disk),
                    }),
                    confidence: 1.0,
                    timestamp: SystemTime::now(),
                    execution_time_ms: 0,
                });
            } else if free_percent < self.warning_threshold {
                return Ok(CheckResult {
                    check_name: self.name().to_string(),
                    category: self.category(),
                    status: HealthStatus::Warning,
                    message: format!(
                        "Warning: Drive {} has {:.1}% free space",
                        disk.mount_point, free_percent
                    ),
                    details: json!({
                        "drive": disk.mount_point,
                        "free_gb": disk.available_bytes / 1_073_741_824,
                        "total_gb": disk.total_bytes / 1_073_741_824,
                        "free_percent": free_percent,
                        "recommendation": "Consider cleaning temporary files",
                    }),
                    remediation: Some(RemediationAction::SuggestCleanup {
                        drive: disk.mount_point.clone(),
                    }),
                    confidence: 0.8,
                    timestamp: SystemTime::now(),
                    execution_time_ms: 0,
                });
            }
        }
        
        Ok(CheckResult {
            check_name: self.name().to_string(),
            category: self.category(),
            status: HealthStatus::Healthy,
            message: "All disks have adequate free space".to_string(),
            details: json!({
                "disks": disk_metrics.len(),
                "total_capacity_gb": disk_metrics.iter()
                    .map(|d| d.total_bytes / 1_073_741_824)
                    .sum::<u64>(),
            }),
            remediation: None,
            confidence: 1.0,
            timestamp: SystemTime::now(),
            execution_time_ms: 0,
        })
    }

    fn can_auto_remediate(&self) -> bool {
        true
    }
}

/// Resource optimization health check
pub struct ResourceOptimizationCheck {
    cpu_underutilized_threshold: f32,    // < N% average
    ram_overprovisioned_threshold: f32,  // > N% free average
    evaluation_window: Duration,         // Time period to analyze
}

impl ResourceOptimizationCheck {
    pub fn new(
        cpu_underutilized_threshold: f32,
        ram_overprovisioned_threshold: f32,
        evaluation_window: Duration,
    ) -> Self {
        Self {
            cpu_underutilized_threshold,
            ram_overprovisioned_threshold,
            evaluation_window,
        }
    }
}

#[async_trait::async_trait]
impl HealthCheck for ResourceOptimizationCheck {
    fn name(&self) -> &str {
        "resource_optimization"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Performance
    }

    async fn execute(&self, context: &CheckContext) -> Result<CheckResult> {
        debug!("Executing resource optimization health check");
        
        let history = context.get_metrics_history(self.evaluation_window)?;
        
        // Calculate averages over evaluation window
        let avg_cpu = calculate_average_cpu(history);
        let avg_ram_free = calculate_average_ram_free(history);
        
        let mut recommendations = Vec::new();
        
        if avg_cpu < self.cpu_underutilized_threshold {
            recommendations.push(Recommendation {
                resource: "CPU".to_string(),
                current: format!("{} vCPUs", context.vm_info.cpu_count),
                suggested: format!("{} vCPUs", context.vm_info.cpu_count / 2),
                reason: format!("Average CPU usage is only {:.1}%", avg_cpu),
                savings: "Reduce compute costs by 50%".to_string(),
            });
        }
        
        if avg_ram_free > self.ram_overprovisioned_threshold {
            let current_ram_gb = context.vm_info.memory_mb / 1024;
            let suggested_ram_gb = (current_ram_gb as f32 * 0.5) as u64;
            
            recommendations.push(Recommendation {
                resource: "Memory".to_string(),
                current: format!("{} GB", current_ram_gb),
                suggested: format!("{} GB", suggested_ram_gb),
                reason: format!("Average free RAM is {:.1}%", avg_ram_free),
                savings: "Reduce memory allocation by 50%".to_string(),
            });
        }
        
        if !recommendations.is_empty() {
            Ok(CheckResult {
                check_name: self.name().to_string(),
                category: self.category(),
                status: HealthStatus::Info,
                message: "Resource optimization opportunities detected".to_string(),
                details: json!({
                    "recommendations": recommendations,
                    "evaluation_period_days": self.evaluation_window.as_secs() / 86400,
                    "avg_cpu_usage": avg_cpu,
                    "avg_ram_free": avg_ram_free,
                    "potential_savings": calculate_savings(&recommendations),
                }),
                remediation: Some(RemediationAction::OptimizeResources {
                    recommendations: recommendations.clone(),
                }),
                confidence: 0.85,
                timestamp: SystemTime::now(),
                execution_time_ms: 0,
            })
        } else {
            Ok(CheckResult {
                check_name: self.name().to_string(),
                category: self.category(),
                status: HealthStatus::Healthy,
                message: "Resource allocation is optimal".to_string(),
                details: json!({
                    "avg_cpu_usage": avg_cpu,
                    "avg_ram_free": avg_ram_free,
                    "evaluation_period_days": self.evaluation_window.as_secs() / 86400,
                }),
                remediation: None,
                confidence: 0.9,
                timestamp: SystemTime::now(),
                execution_time_ms: 0,
            })
        }
    }

    fn can_auto_remediate(&self) -> bool {
        false // Resource changes require manual approval
    }
}

/// Windows Updates health check
#[cfg(target_os = "windows")]
pub struct WindowsUpdatesCheck;

#[cfg(target_os = "windows")]
impl WindowsUpdatesCheck {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl HealthCheck for WindowsUpdatesCheck {
    fn name(&self) -> &str {
        "windows_updates"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Security
    }

    async fn execute(&self, _context: &CheckContext) -> Result<CheckResult> {
        debug!("Executing Windows Updates health check");
        
        match windows_updates::check_windows_updates().await {
            Ok(update_status) => {
                let pending_count = update_status.pending_updates.len();
                let critical_count = update_status.pending_updates
                    .iter()
                    .filter(|u| u.severity == "Critical")
                    .count();
                
                let status = if critical_count > 0 {
                    HealthStatus::Critical
                } else if pending_count > 0 {
                    HealthStatus::Warning
                } else {
                    HealthStatus::Healthy
                };
                
                let message = if pending_count == 0 {
                    "Windows is up to date".to_string()
                } else {
                    format!("{} pending updates ({} critical)", pending_count, critical_count)
                };
                
                let remediation = if pending_count > 0 {
                    Some(RemediationAction::InstallSecurityUpdates {
                        update_count: pending_count,
                        critical_count,
                    })
                } else {
                    None
                };
                
                Ok(CheckResult {
                    check_name: self.name().to_string(),
                    category: self.category(),
                    status,
                    message,
                    details: json!({
                        "installed_updates": update_status.installed_updates.len(),
                        "pending_updates": pending_count,
                        "critical_updates": critical_count,
                        "automatic_updates_enabled": update_status.automatic_updates_enabled,
                        "reboot_required": update_status.reboot_required,
                        "last_check": update_status.last_check,
                    }),
                    remediation,
                    confidence: 0.95,
                    timestamp: SystemTime::now(),
                    execution_time_ms: 0,
                })
            }
            Err(e) => Ok(CheckResult {
                check_name: self.name().to_string(),
                category: self.category(),
                status: HealthStatus::Warning,
                message: format!("Failed to check Windows Updates: {}", e),
                details: json!({"error": e.to_string()}),
                remediation: None,
                confidence: 0.0,
                timestamp: SystemTime::now(),
                execution_time_ms: 0,
            })
        }
    }

    fn can_auto_remediate(&self) -> bool {
        false // Updates require manual approval due to potential disruption
    }
}

/// Windows Defender health check
#[cfg(target_os = "windows")]
pub struct WindowsDefenderCheck;

#[cfg(target_os = "windows")]
impl WindowsDefenderCheck {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl HealthCheck for WindowsDefenderCheck {
    fn name(&self) -> &str {
        "windows_defender"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Security
    }

    async fn execute(&self, _context: &CheckContext) -> Result<CheckResult> {
        debug!("Executing Windows Defender health check");
        
        match windows_defender::get_defender_status().await {
            Ok(defender_status) => {
                let mut issues = Vec::new();
                let mut status = HealthStatus::Healthy;
                
                // Check if Defender is enabled
                if !defender_status.enabled {
                    issues.push("Windows Defender is disabled");
                    status = HealthStatus::Critical;
                }
                
                // Check real-time protection
                if !defender_status.real_time_protection {
                    issues.push("Real-time protection is disabled");
                    if status != HealthStatus::Critical {
                        status = HealthStatus::Warning;
                    }
                }
                
                // Check signature age
                if defender_status.signature_age_days > 7 {
                    issues.push("Antivirus signatures are outdated");
                    if status == HealthStatus::Healthy {
                        status = HealthStatus::Warning;
                    }
                }
                
                // Check recent threats
                if defender_status.threats_detected > 0 {
                    issues.push(&format!("{} threats detected recently", defender_status.threats_detected));
                    if status == HealthStatus::Healthy {
                        status = HealthStatus::Info;
                    }
                }
                
                let message = if issues.is_empty() {
                    "Windows Defender is functioning properly".to_string()
                } else {
                    format!("Windows Defender issues detected: {}", issues.join(", "))
                };
                
                let remediation = if !defender_status.enabled || !defender_status.real_time_protection {
                    Some(RemediationAction::EnableDefender)
                } else if defender_status.signature_age_days > 7 {
                    Some(RemediationAction::UpdateDefenderSignatures)
                } else {
                    None
                };
                
                Ok(CheckResult {
                    check_name: self.name().to_string(),
                    category: self.category(),
                    status,
                    message,
                    details: json!({
                        "enabled": defender_status.enabled,
                        "real_time_protection": defender_status.real_time_protection,
                        "signature_age_days": defender_status.signature_age_days,
                        "threats_detected": defender_status.threats_detected,
                        "last_full_scan": defender_status.last_full_scan,
                        "last_quick_scan": defender_status.last_quick_scan,
                        "engine_version": defender_status.engine_version,
                        "issues": issues,
                    }),
                    remediation,
                    confidence: 0.9,
                    timestamp: SystemTime::now(),
                    execution_time_ms: 0,
                })
            }
            Err(e) => Ok(CheckResult {
                check_name: self.name().to_string(),
                category: self.category(),
                status: HealthStatus::Warning,
                message: format!("Failed to check Windows Defender: {}", e),
                details: json!({"error": e.to_string()}),
                remediation: None,
                confidence: 0.0,
                timestamp: SystemTime::now(),
                execution_time_ms: 0,
            })
        }
    }

    fn can_auto_remediate(&self) -> bool {
        true // Can enable Defender and update signatures automatically
    }
}

// Helper functions

/// Estimate disk cleanup potential
fn estimate_cleanup_potential(disk: &DiskMetrics) -> f32 {
    // This is a simplified estimation
    // In a real implementation, we would scan for:
    // - Temporary files
    // - Browser caches
    // - System cache files
    // - Old log files
    // - Recycle bin contents
    
    // For now, estimate 5% of total disk space can be cleaned
    (disk.total_bytes as f32 * 0.05) / 1_073_741_824.0 // Convert to GB
}

/// Calculate average CPU usage from history
fn calculate_average_cpu(history: &MetricsHistory) -> f32 {
    if history.cpu_usage.is_empty() {
        return 50.0; // Default assumption
    }
    
    let total: f32 = history.cpu_usage.iter().map(|(_, usage)| usage).sum();
    total / history.cpu_usage.len() as f32
}

/// Calculate average free RAM percentage from history
fn calculate_average_ram_free(history: &MetricsHistory) -> f32 {
    if history.memory_usage.is_empty() {
        return 40.0; // Default assumption
    }
    
    let total: f32 = history.memory_usage.iter().map(|(_, usage)| 100.0 - usage).sum();
    total / history.memory_usage.len() as f32
}

/// Calculate potential cost savings from recommendations
fn calculate_savings(recommendations: &[Recommendation]) -> serde_json::Value {
    json!({
        "cpu_reduction": recommendations.iter()
            .any(|r| r.resource == "CPU"),
        "memory_reduction": recommendations.iter()
            .any(|r| r.resource == "Memory"),
        "estimated_monthly_savings": "20-50%",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_disk_space_check_healthy() {
        let check = DiskSpaceCheck::new(30.0, 10.0);
        
        // Mock context with healthy disk space
        let context = CheckContext {
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
        };
        
        let result = check.execute(&context).await.unwrap();
        assert_eq!(result.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_estimate_cleanup_potential() {
        let disk = DiskMetrics {
            mount_point: "C:\\".to_string(),
            total_bytes: 100 * 1024 * 1024 * 1024, // 100GB
            available_bytes: 10 * 1024 * 1024 * 1024, // 10GB
            usage_percent: 90.0,
        };
        
        let cleanup_gb = estimate_cleanup_potential(&disk);
        assert!(cleanup_gb > 0.0);
        assert!(cleanup_gb < 10.0); // Should be reasonable estimate
    }
}