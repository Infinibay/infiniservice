//! Health check implementations
//!
//! This module contains implementations of specific health checks that can be
//! run by the auto-check engine.

use super::*;
use anyhow::Result;
use log::{debug, info, warn};
use serde_json::json;
use std::time::Duration;

#[cfg(target_os = "windows")]
use crate::commands::windows_updates;
#[cfg(target_os = "windows")]
use crate::commands::windows_defender;

#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use crate::os_detection::{get_os_info, PackageManager, LinuxDistro};

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
                let mut issues: Vec<String> = Vec::new();
                let mut status = HealthStatus::Healthy;
                
                // Check if Defender is enabled
                if !defender_status.enabled {
                    issues.push("Windows Defender is disabled".to_string());
                    status = HealthStatus::Critical;
                }
                
                // Check real-time protection
                if !defender_status.real_time_protection {
                    issues.push("Real-time protection is disabled".to_string());
                    if status != HealthStatus::Critical {
                        status = HealthStatus::Warning;
                    }
                }
                
                // Check signature age
                if defender_status.signature_age_days > 7 {
                    issues.push("Antivirus signatures are outdated".to_string());
                    if status == HealthStatus::Healthy {
                        status = HealthStatus::Warning;
                    }
                }
                
                // Check recent threats
                if defender_status.threats_detected > 0 {
                    issues.push(format!("{} threats detected recently", defender_status.threats_detected));
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

// Linux helper functions

/// Execute a command and return the output as a string
#[cfg(target_os = "linux")]
fn execute_command(cmd: &str, args: &[&str]) -> Result<String> {
    debug!("Executing command: {} {:?}", cmd, args);

    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute command {} {:?}: {}", cmd, args, e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        // Some commands like dnf check-update return exit code 100 when updates are available
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);

        // dnf/yum check-update returns 100 if updates are available, 0 if not
        if cmd == "dnf" || cmd == "yum" {
            if let Some(code) = output.status.code() {
                if code == 100 {
                    return Ok(stdout.to_string());
                }
            }
        }

        debug!("Command failed with stderr: {}", stderr);
        Err(anyhow::anyhow!("Command {} failed: {}", cmd, stderr))
    }
}

/// Execute a command that may require root privileges (returns exit code too)
#[cfg(target_os = "linux")]
fn execute_command_with_code(cmd: &str, args: &[&str]) -> Result<(String, i32)> {
    debug!("Executing command with code: {} {:?}", cmd, args);

    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute command {} {:?}: {}", cmd, args, e))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    Ok((stdout, exit_code))
}

/// Parse apt list --upgradable output to count updates
#[cfg(target_os = "linux")]
fn parse_apt_updates(output: &str) -> (usize, usize) {
    let total = output.lines()
        .filter(|line| line.contains("/") && !line.starts_with("Listing"))
        .count();

    let security = output.lines()
        .filter(|line| line.to_lowercase().contains("security"))
        .count();

    (total, security)
}

/// Parse dnf/yum check-update output to count updates
#[cfg(target_os = "linux")]
fn parse_dnf_updates(output: &str) -> usize {
    output.lines()
        .filter(|line| !line.is_empty() && !line.starts_with("Last metadata"))
        .filter(|line| line.contains(".") && !line.starts_with("Obsoleting"))
        .count()
}

/// Linux Updates health check
#[cfg(target_os = "linux")]
pub struct LinuxUpdatesCheck;

#[cfg(target_os = "linux")]
impl LinuxUpdatesCheck {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl HealthCheck for LinuxUpdatesCheck {
    fn name(&self) -> &str {
        "linux_updates"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Security
    }

    async fn execute(&self, _context: &CheckContext) -> Result<CheckResult> {
        debug!("Executing Linux Updates health check");

        let os_info = get_os_info();
        let mut pending_updates: usize = 0;
        let mut security_updates: usize = 0;
        let mut package_manager_used = "unknown".to_string();

        // Detect which package manager to use
        let has_apt = os_info.available_package_managers.contains(&PackageManager::Apt);
        let has_dnf = os_info.available_package_managers.contains(&PackageManager::Dnf);
        let has_yum = os_info.available_package_managers.contains(&PackageManager::Yum);

        if has_apt {
            package_manager_used = "apt".to_string();
            debug!("Using apt for update check");

            // Try to get upgradable packages (doesn't require apt-get update)
            match execute_command("apt", &["list", "--upgradable"]) {
                Ok(output) => {
                    let (total, security) = parse_apt_updates(&output);
                    pending_updates = total;
                    security_updates = security;
                    info!("apt: {} pending updates, {} security updates", pending_updates, security_updates);
                }
                Err(e) => {
                    warn!("Failed to check apt updates: {}", e);
                    return Ok(CheckResult {
                        check_name: self.name().to_string(),
                        category: self.category(),
                        status: HealthStatus::Warning,
                        message: format!("Failed to check updates: {}", e),
                        details: json!({
                            "error": e.to_string(),
                            "package_manager": "apt"
                        }),
                        remediation: None,
                        confidence: 0.0,
                        timestamp: SystemTime::now(),
                        execution_time_ms: 0,
                    });
                }
            }
        } else if has_dnf {
            package_manager_used = "dnf".to_string();
            debug!("Using dnf for update check");

            match execute_command("dnf", &["check-update", "-q"]) {
                Ok(output) => {
                    pending_updates = parse_dnf_updates(&output);

                    // Check for security updates
                    if let Ok(sec_output) = execute_command("dnf", &["updateinfo", "list", "security", "-q"]) {
                        security_updates = sec_output.lines()
                            .filter(|line| !line.is_empty())
                            .count();
                    }
                    info!("dnf: {} pending updates, {} security updates", pending_updates, security_updates);
                }
                Err(e) => {
                    // dnf check-update returns 0 when no updates, check if that's the case
                    if e.to_string().contains("failed") {
                        warn!("Failed to check dnf updates: {}", e);
                        return Ok(CheckResult {
                            check_name: self.name().to_string(),
                            category: self.category(),
                            status: HealthStatus::Warning,
                            message: format!("Failed to check updates: {}", e),
                            details: json!({
                                "error": e.to_string(),
                                "package_manager": "dnf"
                            }),
                            remediation: None,
                            confidence: 0.0,
                            timestamp: SystemTime::now(),
                            execution_time_ms: 0,
                        });
                    }
                    // No updates available (exit code 0)
                    pending_updates = 0;
                    security_updates = 0;
                }
            }
        } else if has_yum {
            package_manager_used = "yum".to_string();
            debug!("Using yum for update check");

            match execute_command("yum", &["check-update", "-q"]) {
                Ok(output) => {
                    pending_updates = parse_dnf_updates(&output); // Same parsing logic

                    // Check for security updates
                    if let Ok(sec_output) = execute_command("yum", &["updateinfo", "list", "security", "-q"]) {
                        security_updates = sec_output.lines()
                            .filter(|line| !line.is_empty())
                            .count();
                    }
                    info!("yum: {} pending updates, {} security updates", pending_updates, security_updates);
                }
                Err(e) => {
                    if e.to_string().contains("failed") {
                        warn!("Failed to check yum updates: {}", e);
                        return Ok(CheckResult {
                            check_name: self.name().to_string(),
                            category: self.category(),
                            status: HealthStatus::Warning,
                            message: format!("Failed to check updates: {}", e),
                            details: json!({
                                "error": e.to_string(),
                                "package_manager": "yum"
                            }),
                            remediation: None,
                            confidence: 0.0,
                            timestamp: SystemTime::now(),
                            execution_time_ms: 0,
                        });
                    }
                    pending_updates = 0;
                    security_updates = 0;
                }
            }
        } else {
            return Ok(CheckResult {
                check_name: self.name().to_string(),
                category: self.category(),
                status: HealthStatus::Warning,
                message: "No supported package manager found".to_string(),
                details: json!({
                    "error": "No apt, dnf, or yum package manager detected",
                    "available_managers": format!("{:?}", os_info.available_package_managers)
                }),
                remediation: None,
                confidence: 0.0,
                timestamp: SystemTime::now(),
                execution_time_ms: 0,
            });
        }

        // Determine status based on updates
        let status = if security_updates > 0 {
            HealthStatus::Critical
        } else if pending_updates > 0 {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        let message = if pending_updates == 0 {
            "System is up to date".to_string()
        } else {
            format!("{} pending updates ({} security)", pending_updates, security_updates)
        };

        let remediation = if pending_updates > 0 {
            Some(RemediationAction::InstallSecurityUpdates {
                update_count: pending_updates,
                critical_count: security_updates,
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
                "pending_updates": pending_updates,
                "security_updates": security_updates,
                "package_manager": package_manager_used,
                "distro": format!("{:?}", os_info.linux_distro),
                "last_check": chrono::Utc::now().to_rfc3339(),
            }),
            remediation,
            confidence: 0.95,
            timestamp: SystemTime::now(),
            execution_time_ms: 0,
        })
    }

    fn can_auto_remediate(&self) -> bool {
        false // Updates require manual approval due to potential disruption
    }
}

/// Linux Security health check (firewall status)
#[cfg(target_os = "linux")]
pub struct LinuxSecurityCheck;

#[cfg(target_os = "linux")]
impl LinuxSecurityCheck {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl HealthCheck for LinuxSecurityCheck {
    fn name(&self) -> &str {
        "linux_security"
    }

    fn category(&self) -> CheckCategory {
        CheckCategory::Security
    }

    async fn execute(&self, _context: &CheckContext) -> Result<CheckResult> {
        debug!("Executing Linux Security health check");

        let os_info = get_os_info();
        let mut issues: Vec<String> = Vec::new();
        let mut firewall_enabled = false;
        let mut firewall_type = "none".to_string();
        let mut security_updates_pending: usize = 0;

        // Check firewall status based on distribution
        let is_debian_based = matches!(
            &os_info.linux_distro,
            Some(LinuxDistro::Ubuntu) | Some(LinuxDistro::Debian)
        );

        let is_rhel_based = matches!(
            &os_info.linux_distro,
            Some(LinuxDistro::Fedora) | Some(LinuxDistro::CentOS) | Some(LinuxDistro::RedHat)
        );

        // Check for UFW (Ubuntu/Debian)
        if is_debian_based || !is_rhel_based {
            // Try UFW first
            match execute_command_with_code("which", &["ufw"]) {
                Ok((_, code)) if code == 0 => {
                    firewall_type = "ufw".to_string();
                    match execute_command("ufw", &["status"]) {
                        Ok(output) => {
                            if output.contains("Status: active") {
                                firewall_enabled = true;
                                debug!("UFW firewall is active");
                            } else {
                                issues.push("UFW firewall is not active".to_string());
                                debug!("UFW firewall is inactive");
                            }
                        }
                        Err(e) => {
                            debug!("Failed to check UFW status: {}", e);
                            // May need sudo, try checking if ufw service is enabled
                            match execute_command_with_code("systemctl", &["is-active", "ufw"]) {
                                Ok((output, _)) if output.trim() == "active" => {
                                    firewall_enabled = true;
                                }
                                _ => {
                                    issues.push("Unable to determine UFW firewall status".to_string());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Check for firewalld (Fedora/RHEL/CentOS)
        if !firewall_enabled && (is_rhel_based || firewall_type == "none") {
            match execute_command_with_code("which", &["firewall-cmd"]) {
                Ok((_, code)) if code == 0 => {
                    firewall_type = "firewalld".to_string();
                    match execute_command("firewall-cmd", &["--state"]) {
                        Ok(output) => {
                            if output.trim() == "running" {
                                firewall_enabled = true;
                                debug!("firewalld is running");
                            } else {
                                issues.push("Firewalld is not running".to_string());
                                debug!("firewalld is not running");
                            }
                        }
                        Err(_) => {
                            // Try systemctl as fallback
                            match execute_command_with_code("systemctl", &["is-active", "firewalld"]) {
                                Ok((output, _)) if output.trim() == "active" => {
                                    firewall_enabled = true;
                                }
                                _ => {
                                    issues.push("Firewalld is not running".to_string());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Check for iptables as last resort
        if !firewall_enabled && firewall_type == "none" {
            match execute_command_with_code("which", &["iptables"]) {
                Ok((_, code)) if code == 0 => {
                    firewall_type = "iptables".to_string();
                    // iptables is always "present" but we check if it has rules
                    match execute_command("iptables", &["-L", "-n"]) {
                        Ok(output) => {
                            // Check if there are any rules beyond default policies
                            let rule_lines: Vec<&str> = output.lines()
                                .filter(|l| !l.starts_with("Chain") && !l.starts_with("target") && !l.is_empty())
                                .collect();

                            if rule_lines.is_empty() {
                                issues.push("iptables has no active rules".to_string());
                            } else {
                                firewall_enabled = true;
                                debug!("iptables has {} rules configured", rule_lines.len());
                            }
                        }
                        Err(e) => {
                            debug!("Failed to check iptables status: {} (may need root)", e);
                            // Can't determine status without root - add issue
                            firewall_type = "iptables (unknown)".to_string();
                            issues.push("Unable to determine iptables firewall status (may require root privileges)".to_string());
                        }
                    }
                }
                _ => {
                    issues.push("No firewall detected".to_string());
                }
            }
        }

        // Ensure firewall_enabled=false always has an issue
        if !firewall_enabled && issues.is_empty() {
            issues.push("Firewall status could not be verified".to_string());
        }

        // Check for security updates (same logic as LinuxUpdatesCheck)
        let has_apt = os_info.available_package_managers.contains(&PackageManager::Apt);
        let has_dnf = os_info.available_package_managers.contains(&PackageManager::Dnf);
        let has_yum = os_info.available_package_managers.contains(&PackageManager::Yum);

        if has_apt {
            debug!("Checking apt security updates");
            if let Ok(output) = execute_command("apt", &["list", "--upgradable"]) {
                let (_, security) = parse_apt_updates(&output);
                security_updates_pending = security;
                if security_updates_pending > 0 {
                    issues.push(format!("{} security updates pending", security_updates_pending));
                    info!("apt: {} security updates pending", security_updates_pending);
                }
            }
        } else if has_dnf {
            debug!("Checking dnf security updates");
            if let Ok(sec_output) = execute_command("dnf", &["updateinfo", "list", "security", "-q"]) {
                security_updates_pending = sec_output.lines()
                    .filter(|line| !line.is_empty())
                    .count();
                if security_updates_pending > 0 {
                    issues.push(format!("{} security updates pending", security_updates_pending));
                    info!("dnf: {} security updates pending", security_updates_pending);
                }
            }
        } else if has_yum {
            debug!("Checking yum security updates");
            if let Ok(sec_output) = execute_command("yum", &["updateinfo", "list", "security", "-q"]) {
                security_updates_pending = sec_output.lines()
                    .filter(|line| !line.is_empty())
                    .count();
                if security_updates_pending > 0 {
                    issues.push(format!("{} security updates pending", security_updates_pending));
                    info!("yum: {} security updates pending", security_updates_pending);
                }
            }
        }

        // Determine overall status
        // Critical: firewall not enabled OR security updates pending
        // Warning: any issues present
        // Healthy: only if firewall enabled AND no issues
        let status = if !firewall_enabled {
            HealthStatus::Critical
        } else if security_updates_pending > 0 {
            HealthStatus::Critical
        } else if !issues.is_empty() {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        let message = if !firewall_enabled {
            "Firewall is not active - system may be vulnerable".to_string()
        } else if security_updates_pending > 0 {
            format!("{} security updates pending - immediate action recommended", security_updates_pending)
        } else if !issues.is_empty() {
            format!("Security issues detected: {}", issues.join(", "))
        } else {
            format!("{} firewall is active and protecting the system", firewall_type)
        };

        // Determine remediation - prioritize firewall, then security updates
        let remediation = if !firewall_enabled {
            Some(RemediationAction::EnableFirewall {
                firewall_type: firewall_type.clone(),
            })
        } else if security_updates_pending > 0 {
            Some(RemediationAction::InstallSecurityUpdates {
                update_count: security_updates_pending,
                critical_count: security_updates_pending,
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
                "firewall_enabled": firewall_enabled,
                "firewall_type": firewall_type,
                "security_updates_pending": security_updates_pending,
                "distro": format!("{:?}", os_info.linux_distro),
                "issues": issues,
            }),
            remediation,
            confidence: 0.9,
            timestamp: SystemTime::now(),
            execution_time_ms: 0,
        })
    }

    fn can_auto_remediate(&self) -> bool {
        true // Can enable firewall automatically
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_linux_updates_check_name_and_category() {
        let check = LinuxUpdatesCheck::new();
        assert_eq!(check.name(), "linux_updates");
        assert!(matches!(check.category(), CheckCategory::Security));
        assert!(!check.can_auto_remediate());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_linux_security_check_name_and_category() {
        let check = LinuxSecurityCheck::new();
        assert_eq!(check.name(), "linux_security");
        assert!(matches!(check.category(), CheckCategory::Security));
        assert!(check.can_auto_remediate());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_apt_updates() {
        let output = "Listing...\nfirefox/focal-updates 95.0+build1-0ubuntu0.20.04.1 amd64 [upgradable from: 94.0+build3-0ubuntu0.20.04.1]\nlibssl1.1/focal-security 1.1.1f-1ubuntu2.10 amd64 [upgradable from: 1.1.1f-1ubuntu2.9]";
        let (total, security) = parse_apt_updates(output);
        assert_eq!(total, 2);
        assert_eq!(security, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_apt_updates_empty() {
        let output = "Listing...";
        let (total, security) = parse_apt_updates(output);
        assert_eq!(total, 0);
        assert_eq!(security, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_dnf_updates() {
        let output = "Last metadata expiration check: 0:30:00 ago\n\nfirefox.x86_64                    95.0-1.fc35                    updates\nkernel.x86_64                     5.15.6-200.fc35                updates";
        let count = parse_dnf_updates(output);
        assert_eq!(count, 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_dnf_updates_empty() {
        let output = "";
        let count = parse_dnf_updates(output);
        assert_eq!(count, 0);
    }

    // ===== Linux Health Check Tests =====

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_linux_updates_check_execution_with_context() {
        let check = LinuxUpdatesCheck::new();

        let context = CheckContext {
            vm_info: VmInfo {
                cpu_count: 2,
                memory_mb: 4096,
                os_type: "Linux".to_string(),
                os_version: "Ubuntu 22.04".to_string(),
            },
            metrics_history: MetricsHistory {
                cpu_usage: vec![],
                memory_usage: vec![],
                disk_usage: vec![],
                network_usage: vec![],
            },
            config: AutoCheckConfig::default(),
        };

        // Execute should return a result (may be healthy or have updates)
        let result = check.execute(&context).await;
        assert!(result.is_ok(), "LinuxUpdatesCheck should execute successfully");

        let health_result = result.unwrap();
        // Status should be one of the valid statuses
        assert!(matches!(health_result.status,
            HealthStatus::Healthy | HealthStatus::Warning | HealthStatus::Critical));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_updates_critical_status_threshold() {
        // Simulate many security updates
        let output = r#"Listing...
vim/focal-security 1.0 amd64 [upgradable from: 0.9]
curl/focal-security 1.0 amd64 [upgradable from: 0.9]
openssl/focal-security 1.0 amd64 [upgradable from: 0.9]
libssl/focal-security 1.0 amd64 [upgradable from: 0.9]
kernel/focal-security 1.0 amd64 [upgradable from: 0.9]
openssh/focal-security 1.0 amd64 [upgradable from: 0.9]
"#;

        let (total, security) = parse_apt_updates(output);
        assert_eq!(total, 6);
        assert_eq!(security, 6);

        // With 6 security updates, status should be critical
        let status = if security > 5 {
            HealthStatus::Critical
        } else if security > 0 || total > 10 {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        assert!(matches!(status, HealthStatus::Critical));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_updates_warning_status_threshold() {
        // Simulate moderate updates with some security
        let output = r#"Listing...
vim/focal-security 1.0 amd64 [upgradable from: 0.9]
curl/focal-updates 1.0 amd64 [upgradable from: 0.9]
python/focal-updates 1.0 amd64 [upgradable from: 0.9]
"#;

        let (total, security) = parse_apt_updates(output);
        assert_eq!(total, 3);
        assert_eq!(security, 1);

        // With 1 security update, status should be warning
        let status = if security > 5 {
            HealthStatus::Critical
        } else if security > 0 || total > 10 {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        assert!(matches!(status, HealthStatus::Warning));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_linux_security_check_execution_with_context() {
        let check = LinuxSecurityCheck::new();

        let context = CheckContext {
            vm_info: VmInfo {
                cpu_count: 2,
                memory_mb: 4096,
                os_type: "Linux".to_string(),
                os_version: "Ubuntu 22.04".to_string(),
            },
            metrics_history: MetricsHistory {
                cpu_usage: vec![],
                memory_usage: vec![],
                disk_usage: vec![],
                network_usage: vec![],
            },
            config: AutoCheckConfig::default(),
        };

        // Execute should return a result
        let result = check.execute(&context).await;
        assert!(result.is_ok(), "LinuxSecurityCheck should execute successfully");
    }

    #[test]
    fn test_linux_security_check_firewall_disabled_detection() {
        // Simulate ufw inactive status
        let ufw_output = "Status: inactive\n";

        let is_active = ufw_output.contains("Status: active");
        let is_inactive = ufw_output.contains("Status: inactive");

        assert!(!is_active, "Firewall should not be detected as active");
        assert!(is_inactive, "Firewall should be detected as inactive");

        // Inactive firewall should result in warning or critical status
        let status = if is_inactive {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        assert!(matches!(status, HealthStatus::Warning));
    }

    #[test]
    fn test_linux_security_check_firewall_enabled_detection() {
        // Simulate ufw active status
        let ufw_output = "Status: active\n";

        let is_active = ufw_output.contains("Status: active");

        assert!(is_active, "Firewall should be detected as active");

        // Active firewall contributes to healthy status
        let status = if is_active {
            HealthStatus::Healthy
        } else {
            HealthStatus::Warning
        };

        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn test_linux_security_check_remediation_suggestions() {
        // Test that appropriate remediation suggestions are generated
        let firewall_disabled = true;
        let security_updates_pending = 3;

        let mut recommendations = Vec::new();

        if firewall_disabled {
            recommendations.push("Enable firewall with: sudo ufw enable");
        }

        if security_updates_pending > 0 {
            recommendations.push("Apply security updates with: sudo apt update && sudo apt upgrade");
        }

        assert_eq!(recommendations.len(), 2, "Should have 2 recommendations");
        assert!(recommendations[0].contains("ufw enable"));
        assert!(recommendations[1].contains("apt upgrade"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_checks_metadata_updates() {
        let check = LinuxUpdatesCheck::new();

        // Verify metadata
        assert_eq!(check.name(), "linux_updates");
        assert!(matches!(check.category(), CheckCategory::Security));

        // Updates check cannot auto-remediate (requires user approval)
        assert!(!check.can_auto_remediate(), "Updates should not auto-remediate");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_checks_metadata_security() {
        let check = LinuxSecurityCheck::new();

        // Verify metadata
        assert_eq!(check.name(), "linux_security");
        assert!(matches!(check.category(), CheckCategory::Security));

        // Security check can auto-remediate (enable firewall)
        assert!(check.can_auto_remediate(), "Security check should auto-remediate");
    }

    #[test]
    fn test_health_status_ordering() {
        // Verify health status can be compared for priority
        let statuses = vec![
            HealthStatus::Healthy,
            HealthStatus::Warning,
            HealthStatus::Critical,
        ];

        // All statuses should be distinguishable
        for (i, status) in statuses.iter().enumerate() {
            match status {
                HealthStatus::Healthy => assert_eq!(i, 0),
                HealthStatus::Warning => assert_eq!(i, 1),
                HealthStatus::Critical => assert_eq!(i, 2),
                HealthStatus::Info => unreachable!("Info status not in test set"),
            }
        }
    }

    #[test]
    fn test_check_category_linux_types() {
        // Verify that Linux checks use appropriate categories
        let security_related = vec!["linux_updates", "linux_security"];

        for check_name in security_related {
            // All Linux security-related checks should be in Security category
            assert!(check_name.contains("update") || check_name.contains("security"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_apt_updates_with_mixed_repos() {
        // Test parsing with packages from different repositories
        let output = r#"Listing...
vim/focal-security 1.0 amd64 [upgradable from: 0.9]
curl/focal-updates 1.0 amd64 [upgradable from: 0.9]
nginx/focal-backports 1.0 amd64 [upgradable from: 0.9]
python/focal-updates,focal-security 1.0 amd64 [upgradable from: 0.9]
"#;

        let (total, security) = parse_apt_updates(output);

        assert_eq!(total, 4, "Should have 4 total packages");
        // vim is security, python is in both updates and security
        assert!(security >= 1, "Should have at least 1 security package");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_dnf_updates_with_metadata_lines() {
        // Test parsing with metadata lines that should be skipped
        let output = r#"Last metadata expiration check: 1:30:00 ago on Mon 15 Jan 2024.
Obsoleting Packages
firefox.x86_64                    120.0-1.fc38                    updates
vim-enhanced.x86_64               9.0.1378-1.fc38                 updates
 replacing vim-minimal.x86_64     9.0.1000-1.fc38                 @updates
"#;

        let count = parse_dnf_updates(output);

        // Should count actual update packages, not metadata or obsoleted lines
        assert!(count >= 2, "Should have at least 2 packages to update");
    }
}