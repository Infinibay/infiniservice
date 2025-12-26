#![allow(clippy::needless_return)]
//! Linux Security status checking via system tools
//!
//! This module provides functionality to check Linux security status including:
//! - Firewall status (ufw, firewalld, iptables)
//! - Security modules (SELinux, AppArmor)
//! - Security-specific updates

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use log::{debug, info};

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use crate::os_detection::{get_os_info, LinuxDistro};

/// Type of firewall detected on the system
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallType {
    Ufw,
    Firewalld,
    Iptables,
    Nftables,
    None,
}

/// Type of security module detected on the system
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityModuleType {
    SELinux,
    AppArmor,
    None,
}

/// SELinux enforcement mode
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SELinuxMode {
    Enforcing,
    Permissive,
    Disabled,
    Unknown,
}

/// AppArmor mode
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AppArmorMode {
    Enabled,
    Disabled,
    Unknown,
}

/// Firewall status information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirewallStatus {
    /// Type of firewall detected
    pub firewall_type: FirewallType,

    /// Whether the firewall is enabled/active
    pub enabled: bool,

    /// Current status string (active, inactive, unknown)
    pub status: String,

    /// Number of active rules
    pub rules_count: usize,

    /// Default incoming policy (deny, allow, reject)
    pub default_incoming: Option<String>,

    /// Default outgoing policy
    pub default_outgoing: Option<String>,

    /// Service status (running, stopped, etc.)
    pub service_status: Option<String>,

    /// Active zone (for firewalld)
    pub active_zone: Option<String>,

    /// List of allowed services/ports
    pub allowed_services: Vec<String>,
}

/// Security module status information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityModuleStatus {
    /// Type of security module detected
    pub module_type: SecurityModuleType,

    /// Whether the module is enabled
    pub enabled: bool,

    /// SELinux mode (if applicable)
    pub selinux_mode: Option<SELinuxMode>,

    /// AppArmor mode (if applicable)
    pub apparmor_mode: Option<AppArmorMode>,

    /// Number of loaded profiles (for AppArmor)
    pub profiles_loaded: Option<usize>,

    /// Number of profiles in enforce mode
    pub profiles_enforce: Option<usize>,

    /// Number of profiles in complain mode
    pub profiles_complain: Option<usize>,

    /// SELinux policy type (targeted, mls, etc.)
    pub selinux_policy: Option<String>,
}

/// Security update information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityUpdate {
    /// Package name
    pub package_name: String,

    /// Current version
    pub current_version: Option<String>,

    /// Available version
    pub available_version: String,

    /// Severity level (Critical, Important, Moderate, Low)
    pub severity: Option<String>,

    /// Advisory ID (e.g., RHSA-2024-1234)
    pub advisory_id: Option<String>,
}

/// Complete Linux Security status
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxSecurityStatus {
    /// Firewall status
    pub firewall: FirewallStatus,

    /// Security module status
    pub security_module: SecurityModuleStatus,

    /// Pending security updates
    pub security_updates: Vec<SecurityUpdate>,

    /// Number of security updates available
    pub security_updates_count: usize,

    /// When this check was performed
    pub last_check: SystemTime,

    /// Linux distribution name
    pub distro: String,
}

/// Execute a command and return stdout if successful
#[cfg(target_os = "linux")]
fn execute_command(cmd: &str, args: &[&str]) -> Result<String> {
    debug!("Executing command: {} {:?}", cmd, args);

    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow!("Failed to execute command {} {:?}: {}", cmd, args, e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Command {} failed with stderr: {}", cmd, stderr);
        Err(anyhow!("Command {} failed: {}", cmd, stderr))
    }
}

/// Execute a command and return stdout even if exit code is non-zero (for status commands)
#[cfg(target_os = "linux")]
fn execute_command_allow_failure(cmd: &str, args: &[&str]) -> Option<String> {
    debug!("Executing command (allow failure): {} {:?}", cmd, args);

    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if !stdout.is_empty() {
                Some(stdout)
            } else {
                Some(String::from_utf8_lossy(&output.stderr).to_string())
            }
        }
        Err(e) => {
            debug!("Command {} not available: {}", cmd, e);
            None
        }
    }
}

/// Check if a command exists in PATH
#[cfg(target_os = "linux")]
fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Detect which firewall is in use on the system
#[cfg(target_os = "linux")]
fn detect_firewall_type() -> FirewallType {
    // Check for ufw first (Ubuntu/Debian)
    if command_exists("ufw") {
        if let Some(output) = execute_command_allow_failure("ufw", &["status"]) {
            if output.contains("Status:") {
                debug!("Detected ufw firewall");
                return FirewallType::Ufw;
            }
        }
    }

    // Check for firewalld (Fedora/RHEL/CentOS)
    // Use execute_command_allow_failure because firewall-cmd --state returns non-zero when stopped
    if command_exists("firewall-cmd") {
        if let Some(output) = execute_command_allow_failure("firewall-cmd", &["--state"]) {
            let output_lower = output.trim().to_lowercase();
            if output_lower.contains("running") || output_lower.contains("not running") {
                debug!("Detected firewalld (state: {})", output.trim());
                return FirewallType::Firewalld;
            }
        }
    }

    // Check for nftables
    if command_exists("nft") {
        if let Ok(output) = execute_command("nft", &["list", "tables"]) {
            if !output.is_empty() {
                debug!("Detected nftables");
                return FirewallType::Nftables;
            }
        }
    }

    // Check for iptables as fallback
    if command_exists("iptables") {
        debug!("Detected iptables (fallback)");
        return FirewallType::Iptables;
    }

    debug!("No firewall detected");
    FirewallType::None
}

/// Check ufw firewall status
#[cfg(target_os = "linux")]
fn check_ufw_status() -> Result<FirewallStatus> {
    debug!("Checking ufw status");

    let output = execute_command_allow_failure("ufw", &["status", "verbose"])
        .ok_or_else(|| anyhow!("Failed to execute ufw status"))?;

    let mut status = FirewallStatus {
        firewall_type: FirewallType::Ufw,
        enabled: false,
        status: "unknown".to_string(),
        rules_count: 0,
        default_incoming: None,
        default_outgoing: None,
        service_status: None,
        active_zone: None,
        allowed_services: Vec::new(),
    };

    for line in output.lines() {
        let line_lower = line.to_lowercase();

        if line_lower.contains("status:") {
            if line_lower.contains("active") {
                status.enabled = true;
                status.status = "active".to_string();
            } else if line_lower.contains("inactive") {
                status.enabled = false;
                status.status = "inactive".to_string();
            }
        }

        if line_lower.contains("default:") {
            // Parse default policies: "Default: deny (incoming), allow (outgoing), disabled (routed)"
            if line_lower.contains("deny (incoming)") || line_lower.contains("reject (incoming)") {
                status.default_incoming = Some("deny".to_string());
            } else if line_lower.contains("allow (incoming)") {
                status.default_incoming = Some("allow".to_string());
            }

            if line_lower.contains("deny (outgoing)") || line_lower.contains("reject (outgoing)") {
                status.default_outgoing = Some("deny".to_string());
            } else if line_lower.contains("allow (outgoing)") {
                status.default_outgoing = Some("allow".to_string());
            }
        }

        // Count rules (lines with ALLOW/DENY/REJECT and port numbers)
        if (line.contains("ALLOW") || line.contains("DENY") || line.contains("REJECT"))
            && !line.contains("Default:")
        {
            status.rules_count += 1;

            // Extract service/port
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                status.allowed_services.push(parts[0].to_string());
            }
        }
    }

    // Get service status via systemctl
    if let Some(service_output) = execute_command_allow_failure("systemctl", &["is-active", "ufw"]) {
        status.service_status = Some(service_output.trim().to_string());
    }

    info!("ufw status: enabled={}, rules={}", status.enabled, status.rules_count);
    Ok(status)
}

/// Check firewalld status
#[cfg(target_os = "linux")]
fn check_firewalld_status() -> Result<FirewallStatus> {
    debug!("Checking firewalld status");

    let mut status = FirewallStatus {
        firewall_type: FirewallType::Firewalld,
        enabled: false,
        status: "unknown".to_string(),
        rules_count: 0,
        default_incoming: None,
        default_outgoing: None,
        service_status: None,
        active_zone: None,
        allowed_services: Vec::new(),
    };

    // Check firewall state using execute_command_allow_failure since --state returns non-zero when stopped
    if let Some(state_output) = execute_command_allow_failure("firewall-cmd", &["--state"]) {
        let state = state_output.trim().to_lowercase();
        if state.contains("running") && !state.contains("not running") {
            status.enabled = true;
            status.status = "active".to_string();
        } else if state.contains("not running") {
            status.enabled = false;
            status.status = "inactive".to_string();
        }
    }

    // Get active zone (may work even when stopped as it's a config query)
    if let Some(zone_output) = execute_command_allow_failure("firewall-cmd", &["--get-default-zone"]) {
        let zone = zone_output.trim();
        if !zone.is_empty() && !zone.contains("not running") {
            status.active_zone = Some(zone.to_string());
        }
    }

    // Only query runtime state if firewalld is active
    if status.enabled {
        // Get list of services in active zone
        if let Ok(services_output) = execute_command("firewall-cmd", &["--list-services"]) {
            status.allowed_services = services_output
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            status.rules_count = status.allowed_services.len();
        }

        // Get default zone target (default policy)
        if let Some(zone) = &status.active_zone {
            if let Ok(target_output) = execute_command("firewall-cmd", &["--zone", zone, "--get-target"]) {
                let target = target_output.trim().to_lowercase();
                if target == "accept" {
                    status.default_incoming = Some("allow".to_string());
                } else if target == "drop" || target == "reject" {
                    status.default_incoming = Some("deny".to_string());
                } else {
                    status.default_incoming = Some(target);
                }
            }
        }
    }

    // Get service status via systemctl
    if let Some(service_output) = execute_command_allow_failure("systemctl", &["is-active", "firewalld"]) {
        status.service_status = Some(service_output.trim().to_string());
    }

    info!("firewalld status: enabled={}, zone={:?}, services={}",
          status.enabled, status.active_zone, status.rules_count);
    Ok(status)
}

/// Check iptables status (fallback)
#[cfg(target_os = "linux")]
fn check_iptables_status() -> Result<FirewallStatus> {
    debug!("Checking iptables status");

    let mut status = FirewallStatus {
        firewall_type: FirewallType::Iptables,
        enabled: false,
        status: "unknown".to_string(),
        rules_count: 0,
        default_incoming: None,
        default_outgoing: None,
        service_status: None,
        active_zone: None,
        allowed_services: Vec::new(),
    };

    // Get iptables rules
    if let Ok(output) = execute_command("iptables", &["-L", "-n", "--line-numbers"]) {
        // Count rules (skip chain headers and empty lines)
        status.rules_count = output
            .lines()
            .filter(|line| {
                !line.is_empty()
                    && !line.starts_with("Chain")
                    && !line.starts_with("num")
                    && !line.starts_with("target")
            })
            .count();

        // If we have rules, consider it enabled
        status.enabled = status.rules_count > 0;
        status.status = if status.enabled { "active" } else { "inactive" }.to_string();

        // Parse default policies from chain headers
        for line in output.lines() {
            if line.starts_with("Chain INPUT") {
                if line.contains("policy ACCEPT") {
                    status.default_incoming = Some("allow".to_string());
                } else if line.contains("policy DROP") || line.contains("policy REJECT") {
                    status.default_incoming = Some("deny".to_string());
                }
            }
            if line.starts_with("Chain OUTPUT") {
                if line.contains("policy ACCEPT") {
                    status.default_outgoing = Some("allow".to_string());
                } else if line.contains("policy DROP") || line.contains("policy REJECT") {
                    status.default_outgoing = Some("deny".to_string());
                }
            }
        }
    }

    info!("iptables status: rules={}", status.rules_count);
    Ok(status)
}

/// Check nftables status
#[cfg(target_os = "linux")]
fn check_nftables_status() -> Result<FirewallStatus> {
    debug!("Checking nftables status");

    let mut status = FirewallStatus {
        firewall_type: FirewallType::Nftables,
        enabled: false,
        status: "unknown".to_string(),
        rules_count: 0,
        default_incoming: None,
        default_outgoing: None,
        service_status: None,
        active_zone: None,
        allowed_services: Vec::new(),
    };

    // Get nftables ruleset
    if let Ok(output) = execute_command("nft", &["list", "ruleset"]) {
        // Count rules (lines containing "rule" or specific patterns)
        // Each rule typically contains keywords like "accept", "drop", "reject", or "counter"
        let rules_count = output
            .lines()
            .filter(|line| {
                let line_trimmed = line.trim();
                // Count actual rules, not table/chain definitions
                !line_trimmed.is_empty()
                    && !line_trimmed.starts_with("table")
                    && !line_trimmed.starts_with("chain")
                    && !line_trimmed.starts_with('{')
                    && !line_trimmed.starts_with('}')
                    && !line_trimmed.starts_with("type")
                    && !line_trimmed.starts_with("policy")
                    && !line_trimmed.starts_with("flags")
                    && (line_trimmed.contains("accept")
                        || line_trimmed.contains("drop")
                        || line_trimmed.contains("reject")
                        || line_trimmed.contains("counter")
                        || line_trimmed.contains("jump")
                        || line_trimmed.contains("goto")
                        || line_trimmed.contains("masquerade")
                        || line_trimmed.contains("dnat")
                        || line_trimmed.contains("snat"))
            })
            .count();

        status.rules_count = rules_count;
        status.enabled = rules_count > 0;
        status.status = if status.enabled { "active" } else { "inactive" }.to_string();

        // Parse default policies from chain definitions
        for line in output.lines() {
            let line_lower = line.to_lowercase();
            // Look for input chain policy
            if line_lower.contains("chain input") || (line_lower.contains("chain") && line_lower.contains("input")) {
                // Check following lines for policy
                continue;
            }
            if line_lower.contains("policy accept") {
                if status.default_incoming.is_none() {
                    status.default_incoming = Some("allow".to_string());
                }
            } else if line_lower.contains("policy drop") || line_lower.contains("policy reject") {
                if status.default_incoming.is_none() {
                    status.default_incoming = Some("deny".to_string());
                }
            }
        }

        // Extract allowed ports/services from rules
        for line in output.lines() {
            // Look for dport (destination port) in accept rules
            if line.contains("accept") && line.contains("dport") {
                if let Some(port_section) = line.split("dport").nth(1) {
                    let parts: Vec<&str> = port_section.split_whitespace().collect();
                    if !parts.is_empty() {
                        status.allowed_services.push(parts[0].to_string());
                    }
                }
            }
        }
    } else {
        // nft list ruleset failed, but nft command exists - might need root
        // Try just listing tables to confirm nftables is available
        if let Some(tables_output) = execute_command_allow_failure("nft", &["list", "tables"]) {
            if !tables_output.is_empty() && !tables_output.contains("Error") {
                status.status = "active".to_string();
                status.enabled = true;
            }
        }
    }

    // Check if nftables service is running via systemctl
    if let Some(service_output) = execute_command_allow_failure("systemctl", &["is-active", "nftables"]) {
        status.service_status = Some(service_output.trim().to_string());
    }

    info!("nftables status: enabled={}, rules={}", status.enabled, status.rules_count);
    Ok(status)
}

/// Check SELinux status
#[cfg(target_os = "linux")]
fn check_selinux_status() -> SecurityModuleStatus {
    debug!("Checking SELinux status");

    let mut status = SecurityModuleStatus {
        module_type: SecurityModuleType::SELinux,
        enabled: false,
        selinux_mode: Some(SELinuxMode::Unknown),
        apparmor_mode: None,
        profiles_loaded: None,
        profiles_enforce: None,
        profiles_complain: None,
        selinux_policy: None,
    };

    // Check if SELinux is available
    if !command_exists("getenforce") {
        status.module_type = SecurityModuleType::None;
        status.selinux_mode = None;
        return status;
    }

    // Get enforcement mode
    if let Some(output) = execute_command_allow_failure("getenforce", &[]) {
        let mode = output.trim().to_lowercase();
        match mode.as_str() {
            "enforcing" => {
                status.enabled = true;
                status.selinux_mode = Some(SELinuxMode::Enforcing);
            }
            "permissive" => {
                status.enabled = true;
                status.selinux_mode = Some(SELinuxMode::Permissive);
            }
            "disabled" => {
                status.enabled = false;
                status.selinux_mode = Some(SELinuxMode::Disabled);
            }
            _ => {
                status.selinux_mode = Some(SELinuxMode::Unknown);
            }
        }
    }

    // Get detailed status from sestatus
    if let Some(output) = execute_command_allow_failure("sestatus", &[]) {
        for line in output.lines() {
            if line.contains("Loaded policy name:") || line.contains("Policy name:") {
                if let Some(policy) = line.split(':').nth(1) {
                    status.selinux_policy = Some(policy.trim().to_string());
                }
            }
        }
    }

    info!("SELinux status: mode={:?}, policy={:?}", status.selinux_mode, status.selinux_policy);
    status
}

/// Check AppArmor status
#[cfg(target_os = "linux")]
fn check_apparmor_status() -> SecurityModuleStatus {
    debug!("Checking AppArmor status");

    let mut status = SecurityModuleStatus {
        module_type: SecurityModuleType::AppArmor,
        enabled: false,
        selinux_mode: None,
        apparmor_mode: Some(AppArmorMode::Unknown),
        profiles_loaded: None,
        profiles_enforce: None,
        profiles_complain: None,
        selinux_policy: None,
    };

    // Check if AppArmor is available
    if !command_exists("aa-status") {
        // Try checking if AppArmor kernel module is loaded
        if let Some(output) = execute_command_allow_failure("cat", &["/sys/module/apparmor/parameters/enabled"]) {
            if output.trim() == "Y" {
                status.enabled = true;
                status.apparmor_mode = Some(AppArmorMode::Enabled);
            } else {
                status.module_type = SecurityModuleType::None;
                status.apparmor_mode = None;
            }
        } else {
            status.module_type = SecurityModuleType::None;
            status.apparmor_mode = None;
        }
        return status;
    }

    // Get detailed status from aa-status (requires root, but try anyway)
    if let Some(output) = execute_command_allow_failure("aa-status", &[]) {
        status.enabled = true;
        status.apparmor_mode = Some(AppArmorMode::Enabled);

        for line in output.lines() {
            // Parse lines like "X profiles are loaded."
            if line.contains("profiles are loaded") {
                if let Some(num_str) = line.split_whitespace().next() {
                    if let Ok(num) = num_str.parse::<usize>() {
                        status.profiles_loaded = Some(num);
                    }
                }
            }
            // Parse lines like "X profiles are in enforce mode."
            if line.contains("profiles are in enforce mode") {
                if let Some(num_str) = line.split_whitespace().next() {
                    if let Ok(num) = num_str.parse::<usize>() {
                        status.profiles_enforce = Some(num);
                    }
                }
            }
            // Parse lines like "X profiles are in complain mode."
            if line.contains("profiles are in complain mode") {
                if let Some(num_str) = line.split_whitespace().next() {
                    if let Ok(num) = num_str.parse::<usize>() {
                        status.profiles_complain = Some(num);
                    }
                }
            }
        }
    } else {
        // aa-status requires root, check if module is loaded
        if let Some(output) = execute_command_allow_failure("cat", &["/sys/module/apparmor/parameters/enabled"]) {
            if output.trim() == "Y" {
                status.enabled = true;
                status.apparmor_mode = Some(AppArmorMode::Enabled);
            }
        }
    }

    info!("AppArmor status: enabled={}, profiles={:?}", status.enabled, status.profiles_loaded);
    status
}

/// Get security updates from apt (Ubuntu/Debian)
#[cfg(target_os = "linux")]
fn get_apt_security_updates() -> Vec<SecurityUpdate> {
    debug!("Checking apt security updates");
    let mut updates = Vec::new();

    // Use apt list --upgradable and filter for security
    if let Ok(output) = execute_command("apt", &["list", "--upgradable"]) {
        for line in output.lines() {
            // Skip header
            if line.starts_with("Listing") || line.is_empty() {
                continue;
            }

            // Check if this is a security update
            let line_lower = line.to_lowercase();
            if line_lower.contains("security") {
                // Format: package/repo version arch [upgradable from: old_version]
                if let Some((package_part, rest)) = line.split_once('/') {
                    let package_name = package_part.to_string();
                    let parts: Vec<&str> = rest.split_whitespace().collect();

                    if parts.len() >= 2 {
                        let available_version = parts[1].to_string();
                        let current_version = if let Some(pos) = line.find("upgradable from:") {
                            Some(line[pos + 16..].trim().trim_end_matches(']').to_string())
                        } else {
                            None
                        };

                        updates.push(SecurityUpdate {
                            package_name,
                            current_version,
                            available_version,
                            severity: None,
                            advisory_id: None,
                        });
                    }
                }
            }
        }
    }

    info!("Found {} apt security updates", updates.len());
    updates
}

/// Get security updates from dnf/yum (Fedora/RHEL/CentOS)
#[cfg(target_os = "linux")]
fn get_dnf_security_updates() -> Vec<SecurityUpdate> {
    debug!("Checking dnf/yum security updates");
    let mut updates = Vec::new();

    // Try dnf first, then yum
    let cmd = if command_exists("dnf") { "dnf" } else { "yum" };

    if let Ok(output) = execute_command(cmd, &["updateinfo", "list", "security", "-q"]) {
        for line in output.lines() {
            if line.is_empty() {
                continue;
            }

            // Format varies but typically: ADVISORY_ID severity package
            // Example: FEDORA-2024-abc123 Important vim-enhanced-2:9.0.1378-1.fc38.x86_64
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let advisory_id = parts[0].to_string();
                let severity = parts[1].to_string();
                let package_full = parts[2];

                // Extract package name from NEVRA format
                let package_name = extract_package_name_from_nevra(package_full);
                let available_version = extract_version_from_nevra(package_full);

                if !package_name.is_empty() {
                    updates.push(SecurityUpdate {
                        package_name,
                        current_version: None,
                        available_version,
                        severity: Some(severity),
                        advisory_id: Some(advisory_id),
                    });
                }
            }
        }
    }

    info!("Found {} dnf/yum security updates", updates.len());
    updates
}

/// Extract package name from NEVRA format
#[cfg(target_os = "linux")]
fn extract_package_name_from_nevra(nevra: &str) -> String {
    // NEVRA format: name-[epoch:]version-release.arch
    let parts: Vec<&str> = nevra.split('-').collect();
    let mut name_parts = Vec::new();

    for part in parts.iter() {
        // If this part starts with a digit or contains ':', it's likely the version
        if part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
           || part.contains(':') {
            break;
        }
        name_parts.push(*part);
    }

    name_parts.join("-")
}

/// Extract version from NEVRA format
#[cfg(target_os = "linux")]
fn extract_version_from_nevra(nevra: &str) -> String {
    let name = extract_package_name_from_nevra(nevra);
    if nevra.len() > name.len() + 1 {
        // Remove the trailing .arch part
        let version_release = &nevra[name.len() + 1..];
        if let Some(dot_pos) = version_release.rfind('.') {
            return version_release[..dot_pos].to_string();
        }
        return version_release.to_string();
    }
    String::new()
}

/// Check complete Linux security status
#[cfg(target_os = "linux")]
pub async fn check_linux_security() -> Result<LinuxSecurityStatus> {
    info!("Checking Linux Security status");

    let os_info = get_os_info();
    let distro = format!("{:?}", os_info.linux_distro.clone().unwrap_or(LinuxDistro::Unknown("unknown".to_string())));

    // Detect and check firewall
    let firewall_type = detect_firewall_type();
    let firewall = match firewall_type {
        FirewallType::Ufw => check_ufw_status()?,
        FirewallType::Firewalld => check_firewalld_status()?,
        FirewallType::Iptables => check_iptables_status()?,
        FirewallType::Nftables => check_nftables_status()?,
        FirewallType::None => FirewallStatus {
            firewall_type: FirewallType::None,
            enabled: false,
            status: "not installed".to_string(),
            rules_count: 0,
            default_incoming: None,
            default_outgoing: None,
            service_status: None,
            active_zone: None,
            allowed_services: Vec::new(),
        },
    };

    // Check security module based on distribution
    let security_module = match &os_info.linux_distro {
        Some(LinuxDistro::Fedora) | Some(LinuxDistro::RedHat) | Some(LinuxDistro::CentOS) => {
            check_selinux_status()
        }
        Some(LinuxDistro::Ubuntu) | Some(LinuxDistro::Debian) => {
            check_apparmor_status()
        }
        _ => {
            // Try both and use whichever is available
            let selinux = check_selinux_status();
            if selinux.enabled {
                selinux
            } else {
                let apparmor = check_apparmor_status();
                if apparmor.enabled {
                    apparmor
                } else {
                    SecurityModuleStatus {
                        module_type: SecurityModuleType::None,
                        enabled: false,
                        selinux_mode: None,
                        apparmor_mode: None,
                        profiles_loaded: None,
                        profiles_enforce: None,
                        profiles_complain: None,
                        selinux_policy: None,
                    }
                }
            }
        }
    };

    // Get security updates based on package manager
    let security_updates = match &os_info.linux_distro {
        Some(LinuxDistro::Ubuntu) | Some(LinuxDistro::Debian) => {
            get_apt_security_updates()
        }
        Some(LinuxDistro::Fedora) | Some(LinuxDistro::RedHat) | Some(LinuxDistro::CentOS) => {
            get_dnf_security_updates()
        }
        _ => {
            // Try apt first, then dnf
            let apt_updates = get_apt_security_updates();
            if !apt_updates.is_empty() {
                apt_updates
            } else {
                get_dnf_security_updates()
            }
        }
    };

    let security_updates_count = security_updates.len();

    info!("Security check complete: firewall={}, security_module={:?}, updates={}",
          firewall.status, security_module.module_type, security_updates_count);

    Ok(LinuxSecurityStatus {
        firewall,
        security_module,
        security_updates,
        security_updates_count,
        last_check: SystemTime::now(),
        distro,
    })
}

/// Get only firewall status
#[cfg(target_os = "linux")]
pub async fn get_linux_firewall_status() -> Result<FirewallStatus> {
    info!("Getting Linux firewall status");

    let firewall_type = detect_firewall_type();
    match firewall_type {
        FirewallType::Ufw => check_ufw_status(),
        FirewallType::Firewalld => check_firewalld_status(),
        FirewallType::Iptables => check_iptables_status(),
        FirewallType::Nftables => check_nftables_status(),
        FirewallType::None => Ok(FirewallStatus {
            firewall_type: FirewallType::None,
            enabled: false,
            status: "not installed".to_string(),
            rules_count: 0,
            default_incoming: None,
            default_outgoing: None,
            service_status: None,
            active_zone: None,
            allowed_services: Vec::new(),
        }),
    }
}

/// Get only security updates
#[cfg(target_os = "linux")]
pub async fn get_linux_security_updates() -> Result<Vec<SecurityUpdate>> {
    info!("Getting Linux security updates");

    let os_info = get_os_info();

    let updates = match &os_info.linux_distro {
        Some(LinuxDistro::Ubuntu) | Some(LinuxDistro::Debian) => {
            get_apt_security_updates()
        }
        Some(LinuxDistro::Fedora) | Some(LinuxDistro::RedHat) | Some(LinuxDistro::CentOS) => {
            get_dnf_security_updates()
        }
        _ => {
            let apt_updates = get_apt_security_updates();
            if !apt_updates.is_empty() {
                apt_updates
            } else {
                get_dnf_security_updates()
            }
        }
    };

    Ok(updates)
}

/// Check security modules status
#[cfg(target_os = "linux")]
pub async fn check_security_modules() -> Result<SecurityModuleStatus> {
    info!("Checking security modules");

    let os_info = get_os_info();

    let status = match &os_info.linux_distro {
        Some(LinuxDistro::Fedora) | Some(LinuxDistro::RedHat) | Some(LinuxDistro::CentOS) => {
            check_selinux_status()
        }
        Some(LinuxDistro::Ubuntu) | Some(LinuxDistro::Debian) => {
            check_apparmor_status()
        }
        _ => {
            let selinux = check_selinux_status();
            if selinux.enabled {
                selinux
            } else {
                let apparmor = check_apparmor_status();
                if apparmor.enabled {
                    apparmor
                } else {
                    SecurityModuleStatus {
                        module_type: SecurityModuleType::None,
                        enabled: false,
                        selinux_mode: None,
                        apparmor_mode: None,
                        profiles_loaded: None,
                        profiles_enforce: None,
                        profiles_complain: None,
                        selinux_policy: None,
                    }
                }
            }
        }
    };

    Ok(status)
}

// ===== Non-Linux stubs =====

/// Non-Linux implementation (stub)
#[cfg(not(target_os = "linux"))]
pub async fn check_linux_security() -> Result<LinuxSecurityStatus> {
    Err(anyhow!("Linux Security check is only available on Linux"))
}

/// Non-Linux implementation (stub)
#[cfg(not(target_os = "linux"))]
pub async fn get_linux_firewall_status() -> Result<FirewallStatus> {
    Err(anyhow!("Linux Firewall status is only available on Linux"))
}

/// Non-Linux implementation (stub)
#[cfg(not(target_os = "linux"))]
pub async fn get_linux_security_updates() -> Result<Vec<SecurityUpdate>> {
    Err(anyhow!("Linux Security updates check is only available on Linux"))
}

/// Non-Linux implementation (stub)
#[cfg(not(target_os = "linux"))]
pub async fn check_security_modules() -> Result<SecurityModuleStatus> {
    Err(anyhow!("Security modules check is only available on Linux"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_status_serialization() {
        let status = FirewallStatus {
            firewall_type: FirewallType::Ufw,
            enabled: true,
            status: "active".to_string(),
            rules_count: 5,
            default_incoming: Some("deny".to_string()),
            default_outgoing: Some("allow".to_string()),
            service_status: Some("active".to_string()),
            active_zone: None,
            allowed_services: vec!["ssh".to_string(), "http".to_string()],
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("ufw"));
        assert!(json.contains("active"));
        assert!(json.contains("ssh"));
    }

    #[test]
    fn test_security_module_status_serialization() {
        let status = SecurityModuleStatus {
            module_type: SecurityModuleType::AppArmor,
            enabled: true,
            selinux_mode: None,
            apparmor_mode: Some(AppArmorMode::Enabled),
            profiles_loaded: Some(50),
            profiles_enforce: Some(45),
            profiles_complain: Some(5),
            selinux_policy: None,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("apparmor"));
        assert!(json.contains("50"));
    }

    #[test]
    fn test_security_update_serialization() {
        let update = SecurityUpdate {
            package_name: "openssl".to_string(),
            current_version: Some("1.1.1f-1ubuntu2.16".to_string()),
            available_version: "1.1.1f-1ubuntu2.17".to_string(),
            severity: Some("Critical".to_string()),
            advisory_id: Some("USN-5678-1".to_string()),
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("openssl"));
        assert!(json.contains("Critical"));
    }

    #[test]
    fn test_linux_security_status_serialization() {
        let status = LinuxSecurityStatus {
            firewall: FirewallStatus {
                firewall_type: FirewallType::Ufw,
                enabled: true,
                status: "active".to_string(),
                rules_count: 3,
                default_incoming: Some("deny".to_string()),
                default_outgoing: Some("allow".to_string()),
                service_status: None,
                active_zone: None,
                allowed_services: vec![],
            },
            security_module: SecurityModuleStatus {
                module_type: SecurityModuleType::AppArmor,
                enabled: true,
                selinux_mode: None,
                apparmor_mode: Some(AppArmorMode::Enabled),
                profiles_loaded: Some(50),
                profiles_enforce: None,
                profiles_complain: None,
                selinux_policy: None,
            },
            security_updates: vec![],
            security_updates_count: 0,
            last_check: SystemTime::now(),
            distro: "Ubuntu".to_string(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Ubuntu"));
        assert!(json.contains("firewall"));
        assert!(json.contains("security_module"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_extract_package_name_from_nevra() {
        assert_eq!(extract_package_name_from_nevra("vim-enhanced-2:9.0.1378-1.fc38.x86_64"), "vim-enhanced");
        assert_eq!(extract_package_name_from_nevra("curl-8.0.1-1.fc38.x86_64"), "curl");
        assert_eq!(extract_package_name_from_nevra("python3-pip-21.0.1-1.el9.noarch"), "python3-pip");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_extract_version_from_nevra() {
        assert_eq!(extract_version_from_nevra("vim-enhanced-2:9.0.1378-1.fc38.x86_64"), "2:9.0.1378-1.fc38");
        assert_eq!(extract_version_from_nevra("curl-8.0.1-1.fc38.x86_64"), "8.0.1-1.fc38");
    }
}
