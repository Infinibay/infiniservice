#![allow(clippy::needless_return)]
//! Linux Update management via package managers (apt, dnf, yum)
//!
//! This module provides functionality to check Linux system updates, pending updates,
//! and update history using native package managers.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use std::process::Command;
use log::{debug, info, warn};

use crate::os_detection::{get_os_info, PackageManager, LinuxDistro};

/// Linux package update information (installed update record)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxUpdate {
    /// Package name
    pub package_name: String,

    /// Installed version
    pub version: String,

    /// When the update was installed (RFC3339 format)
    pub installed_on: Option<String>,

    /// Repository source
    pub repository: Option<String>,

    /// Action performed (Install, Upgrade, Remove)
    pub action: Option<String>,
}

/// Pending update information for Linux packages
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxPendingUpdate {
    /// Package name
    pub package_name: String,

    /// Currently installed version
    pub current_version: Option<String>,

    /// Available version
    pub available_version: String,

    /// Repository source
    pub repository: Option<String>,

    /// Whether this is a security update
    pub is_security: bool,

    /// Download size in KB (if available)
    pub size_kb: Option<u64>,

    /// Architecture (e.g., amd64, x86_64)
    pub architecture: Option<String>,
}

/// Complete Linux Update status
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxUpdateStatus {
    /// List of pending updates
    pub pending_updates: Vec<LinuxPendingUpdate>,

    /// Number of security updates
    pub security_updates_count: usize,

    /// Total pending updates count
    pub total_pending_count: usize,

    /// When this check was performed
    pub last_check: SystemTime,

    /// Package manager used for this check
    pub package_manager: String,

    /// Whether a reboot is required
    pub reboot_required: bool,

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
        Err(anyhow!("Command {} failed: {}", cmd, stderr))
    }
}

/// Parse apt list --upgradable output to extract pending updates
///
/// This function is public for testing purposes.
#[cfg(target_os = "linux")]
pub fn parse_apt_upgradable(output: &str) -> Vec<LinuxPendingUpdate> {
    let mut updates = Vec::new();

    for line in output.lines() {
        // Skip header and empty lines
        if line.starts_with("Listing") || line.is_empty() {
            continue;
        }

        // Format: package/repo version arch [upgradable from: old_version]
        // Example: vim/jammy-updates 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]
        if let Some((package_part, rest)) = line.split_once('/') {
            let package_name = package_part.to_string();

            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                let repo_and_version = parts[0];
                let repo = repo_and_version.split_once(' ').map(|(r, _)| r).unwrap_or(repo_and_version);
                let available_version = parts[1].to_string();
                let architecture = parts.get(2).map(|s| s.to_string());

                // Extract current version from "upgradable from: X"
                let current_version = if let Some(pos) = line.find("upgradable from:") {
                    let from_part = &line[pos + 16..];
                    Some(from_part.trim().trim_end_matches(']').to_string())
                } else {
                    None
                };

                // Check if security update (contains "security" in repo name)
                let is_security = repo.to_lowercase().contains("security");

                updates.push(LinuxPendingUpdate {
                    package_name,
                    current_version,
                    available_version,
                    repository: Some(repo.to_string()),
                    is_security,
                    size_kb: None,
                    architecture,
                });
            }
        }
    }

    updates
}

/// Parse dnf/yum check-update output to extract pending updates
///
/// This function is public for testing purposes.
#[cfg(target_os = "linux")]
pub fn parse_dnf_check_update(output: &str) -> Vec<LinuxPendingUpdate> {
    let mut updates = Vec::new();

    for line in output.lines() {
        // Skip empty lines, headers, and metadata lines
        if line.is_empty()
            || line.starts_with("Last metadata")
            || line.starts_with("Obsoleting")
            || !line.contains('.')
        {
            continue;
        }

        // Format: package_name.arch   version   repository
        // Example: vim-enhanced.x86_64   2:9.0.1378-1.fc38   updates
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let package_arch = parts[0];
            let available_version = parts[1].to_string();
            let repository = parts[2].to_string();

            // Split package name and architecture
            let (package_name, architecture) = if let Some(pos) = package_arch.rfind('.') {
                (package_arch[..pos].to_string(), Some(package_arch[pos + 1..].to_string()))
            } else {
                (package_arch.to_string(), None)
            };

            updates.push(LinuxPendingUpdate {
                package_name,
                current_version: None, // dnf check-update doesn't show current version
                available_version,
                repository: Some(repository),
                is_security: false, // Will be updated by security check
                size_kb: None,
                architecture,
            });
        }
    }

    updates
}

/// Parse dnf/yum updateinfo list security output to get security package names
#[cfg(target_os = "linux")]
fn parse_security_updates(output: &str) -> Vec<String> {
    let mut security_packages = Vec::new();

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        // Format varies but typically: ADVISORY_ID severity package_name
        // Example: FEDORA-2024-abc123 Important vim-enhanced-2:9.0.1378-1.fc38.x86_64
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let package_full = parts[2];
            // Extract just the package name without version
            if let Some(pos) = package_full.find('-') {
                // Handle cases like vim-enhanced where - is part of the name
                // Look for version pattern (digits after -)
                let name = extract_package_name_from_nevra(package_full);
                if !name.is_empty() {
                    security_packages.push(name);
                }
            }
        }
    }

    security_packages
}

/// Extract package name from NEVRA (Name-Epoch:Version-Release.Arch) format
#[cfg(target_os = "linux")]
fn extract_package_name_from_nevra(nevra: &str) -> String {
    // NEVRA format: name-[epoch:]version-release.arch
    // We need to find where the name ends and version begins
    // Version typically starts with a digit after a dash

    let parts: Vec<&str> = nevra.split('-').collect();
    let mut name_parts = Vec::new();

    for (i, part) in parts.iter().enumerate() {
        // If this part starts with a digit or contains ':', it's likely the version
        if part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
           || part.contains(':') {
            break;
        }
        name_parts.push(*part);
    }

    name_parts.join("-")
}

/// Check if reboot is required on Linux systems
#[cfg(target_os = "linux")]
fn check_reboot_required() -> bool {
    use std::path::Path;

    // Ubuntu/Debian: check /var/run/reboot-required
    if Path::new("/var/run/reboot-required").exists() {
        return true;
    }

    // RHEL/Fedora: check needs-restarting
    if let Ok(output) = Command::new("needs-restarting")
        .arg("-r")
        .output()
    {
        // Exit code 1 means reboot is needed
        if let Some(code) = output.status.code() {
            if code == 1 {
                return true;
            }
        }
    }

    // Check for /var/run/reboot-required.pkgs as alternative
    if Path::new("/var/run/reboot-required.pkgs").exists() {
        return true;
    }

    false
}

/// Parse apt history log to extract installed/upgraded packages
///
/// This function is public for testing purposes.
#[cfg(target_os = "linux")]
pub fn parse_apt_history(content: &str, days: u32) -> Vec<LinuxUpdate> {
    use chrono::{NaiveDateTime, Utc, Duration};

    let mut updates = Vec::new();
    let cutoff = Utc::now() - Duration::days(days as i64);

    let mut current_date: Option<String> = None;
    let mut current_date_within_range = false;

    for line in content.lines() {
        if line.starts_with("Start-Date:") {
            // Parse date: Start-Date: 2024-01-15  10:30:45
            let date_str = line.strip_prefix("Start-Date:").map(|s| s.trim()).unwrap_or("");
            current_date = Some(date_str.to_string());

            // Parse the date to check if within range
            // Format: "2024-01-15  10:30:45" (note: may have multiple spaces)
            let normalized = date_str.split_whitespace().collect::<Vec<_>>().join(" ");
            current_date_within_range = if let Ok(parsed) = NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S") {
                parsed.and_utc() >= cutoff
            } else {
                // If we can't parse, include it to be safe
                true
            };
        } else if !current_date_within_range {
            // Skip processing lines for entries outside the date range
            continue;
        } else if line.starts_with("Install:") || line.starts_with("Upgrade:") || line.starts_with("Remove:") {
            let action = if line.starts_with("Install:") {
                "Install"
            } else if line.starts_with("Upgrade:") {
                "Upgrade"
            } else {
                "Remove"
            };

            let packages_str = line.split_once(':').map(|(_, p)| p).unwrap_or("");

            // Parse packages: name:arch (version), name:arch (old -> new), ...
            for pkg in packages_str.split(',') {
                let pkg = pkg.trim();
                if pkg.is_empty() {
                    continue;
                }

                // Extract package name and version
                // Format: name:arch (version) or name:arch (old -> new, automatic)
                let (name_part, version_part) = if let Some(pos) = pkg.find('(') {
                    (&pkg[..pos], &pkg[pos..])
                } else {
                    (pkg, "")
                };

                let package_name = name_part.split(':').next().unwrap_or(name_part).trim().to_string();

                // Extract version (handle "old -> new" format)
                let version = if version_part.contains(" -> ") {
                    // Upgrade format: (old -> new, ...)
                    version_part.split("->").last()
                        .and_then(|v| v.split(',').next())
                        .map(|v| v.trim().trim_start_matches('(').trim_end_matches(')').to_string())
                        .unwrap_or_default()
                } else {
                    version_part.trim_start_matches('(')
                        .split(',').next()
                        .unwrap_or("")
                        .trim_end_matches(')')
                        .trim()
                        .to_string()
                };

                if !package_name.is_empty() {
                    updates.push(LinuxUpdate {
                        package_name,
                        version,
                        installed_on: current_date.clone(),
                        repository: None,
                        action: Some(action.to_string()),
                    });
                }
            }
        }
    }

    updates
}

/// Parse dnf/yum history output to extract update records
///
/// This function is public for testing purposes.
#[cfg(target_os = "linux")]
pub fn parse_dnf_history(output: &str, days: u32) -> Vec<LinuxUpdate> {
    use chrono::{NaiveDateTime, NaiveDate, Utc, Duration};

    let mut updates = Vec::new();
    let cutoff = Utc::now() - Duration::days(days as i64);

    for line in output.lines() {
        // Skip header lines
        if line.contains("ID") && line.contains("Command") {
            continue;
        }
        if line.starts_with("--") || line.is_empty() {
            continue;
        }

        // Format varies by version but typically:
        // ID | Command | Date/Time | Action | Altered
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 4 {
            let id = parts[0].trim();
            let command = parts[1].trim();
            let datetime = parts[2].trim();
            let action = parts[3].trim();

            // Parse datetime to check if within range
            // DNF history formats: "2024-01-15 10:30" or "2024-01-15 10:30:45"
            let within_range = if let Ok(parsed) = NaiveDateTime::parse_from_str(datetime, "%Y-%m-%d %H:%M:%S") {
                parsed.and_utc() >= cutoff
            } else if let Ok(parsed) = NaiveDateTime::parse_from_str(datetime, "%Y-%m-%d %H:%M") {
                parsed.and_utc() >= cutoff
            } else if let Ok(parsed) = NaiveDate::parse_from_str(datetime, "%Y-%m-%d") {
                // If only date, use start of day
                parsed.and_hms_opt(0, 0, 0).map(|dt| dt.and_utc() >= cutoff).unwrap_or(true)
            } else {
                // If we can't parse, include it to be safe
                true
            };

            if !within_range {
                continue;
            }

            // For detailed history, we'd need to query each transaction
            // For now, we'll create a summary entry
            if command.contains("update") || command.contains("upgrade") || command.contains("install") {
                updates.push(LinuxUpdate {
                    package_name: format!("Transaction #{}", id),
                    version: String::new(),
                    installed_on: Some(datetime.to_string()),
                    repository: None,
                    action: Some(action.to_string()),
                });
            }
        }
    }

    updates
}

/// Check Linux Updates using package managers
#[cfg(target_os = "linux")]
pub async fn check_linux_updates() -> Result<LinuxUpdateStatus> {
    info!("Checking Linux Updates via package managers");

    let os_info = get_os_info();
    let mut pending_updates: Vec<LinuxPendingUpdate> = Vec::new();
    let mut security_updates_count: usize = 0;
    let mut package_manager_used = "unknown".to_string();

    let has_apt = os_info.available_package_managers.contains(&PackageManager::Apt);
    let has_dnf = os_info.available_package_managers.contains(&PackageManager::Dnf);
    let has_yum = os_info.available_package_managers.contains(&PackageManager::Yum);

    if has_apt {
        package_manager_used = "apt".to_string();
        debug!("Using apt for update check");

        match execute_command("apt", &["list", "--upgradable"]) {
            Ok(output) => {
                pending_updates = parse_apt_upgradable(&output);
                security_updates_count = pending_updates.iter().filter(|u| u.is_security).count();
                info!("apt: {} pending updates, {} security updates",
                      pending_updates.len(), security_updates_count);
            }
            Err(e) => {
                warn!("Failed to check apt updates: {}", e);
                return Err(anyhow!("Failed to check apt updates: {}", e));
            }
        }
    } else if has_dnf {
        package_manager_used = "dnf".to_string();
        debug!("Using dnf for update check");

        match execute_command("dnf", &["check-update", "-q"]) {
            Ok(output) => {
                pending_updates = parse_dnf_check_update(&output);

                // Check for security updates separately
                if let Ok(sec_output) = execute_command("dnf", &["updateinfo", "list", "security", "-q"]) {
                    let security_packages = parse_security_updates(&sec_output);
                    for update in &mut pending_updates {
                        if security_packages.iter().any(|sp| sp == &update.package_name) {
                            update.is_security = true;
                        }
                    }
                    security_updates_count = pending_updates.iter().filter(|u| u.is_security).count();
                }

                info!("dnf: {} pending updates, {} security updates",
                      pending_updates.len(), security_updates_count);
            }
            Err(e) => {
                // dnf check-update returns 0 when no updates available
                if !e.to_string().contains("failed") {
                    pending_updates = Vec::new();
                    security_updates_count = 0;
                } else {
                    warn!("Failed to check dnf updates: {}", e);
                    return Err(anyhow!("Failed to check dnf updates: {}", e));
                }
            }
        }
    } else if has_yum {
        package_manager_used = "yum".to_string();
        debug!("Using yum for update check");

        match execute_command("yum", &["check-update", "-q"]) {
            Ok(output) => {
                pending_updates = parse_dnf_check_update(&output); // Same parsing logic

                // Check for security updates
                if let Ok(sec_output) = execute_command("yum", &["updateinfo", "list", "security", "-q"]) {
                    let security_packages = parse_security_updates(&sec_output);
                    for update in &mut pending_updates {
                        if security_packages.iter().any(|sp| sp == &update.package_name) {
                            update.is_security = true;
                        }
                    }
                    security_updates_count = pending_updates.iter().filter(|u| u.is_security).count();
                }

                info!("yum: {} pending updates, {} security updates",
                      pending_updates.len(), security_updates_count);
            }
            Err(e) => {
                if !e.to_string().contains("failed") {
                    pending_updates = Vec::new();
                    security_updates_count = 0;
                } else {
                    warn!("Failed to check yum updates: {}", e);
                    return Err(anyhow!("Failed to check yum updates: {}", e));
                }
            }
        }
    } else {
        return Err(anyhow!("No supported package manager found (apt, dnf, or yum)"));
    }

    let reboot_required = check_reboot_required();
    let distro = format!("{:?}", os_info.linux_distro.clone().unwrap_or(LinuxDistro::Unknown("unknown".to_string())));
    let total_pending_count = pending_updates.len();

    Ok(LinuxUpdateStatus {
        pending_updates,
        security_updates_count,
        total_pending_count,
        last_check: SystemTime::now(),
        package_manager: package_manager_used,
        reboot_required,
        distro,
    })
}

/// Get Linux update history for the specified number of days
#[cfg(target_os = "linux")]
pub async fn get_linux_update_history(days: u32) -> Result<Vec<LinuxUpdate>> {
    info!("Getting Linux update history for the last {} days", days);

    // Validate days parameter
    if days == 0 || days > 365 {
        return Err(anyhow!("Days parameter must be between 1 and 365"));
    }

    let os_info = get_os_info();
    let has_apt = os_info.available_package_managers.contains(&PackageManager::Apt);
    let has_dnf = os_info.available_package_managers.contains(&PackageManager::Dnf);
    let has_yum = os_info.available_package_managers.contains(&PackageManager::Yum);

    if has_apt {
        debug!("Reading apt history log");

        // Try to read apt history log
        let history_path = "/var/log/apt/history.log";
        match std::fs::read_to_string(history_path) {
            Ok(content) => {
                let updates = parse_apt_history(&content, days);
                info!("Found {} updates in apt history", updates.len());
                return Ok(updates);
            }
            Err(e) => {
                warn!("Failed to read apt history log: {}. Trying dpkg log.", e);

                // Fallback: try dpkg.log
                if let Ok(dpkg_content) = std::fs::read_to_string("/var/log/dpkg.log") {
                    // Parse dpkg log format (simpler format)
                    let updates = parse_dpkg_log(&dpkg_content, days);
                    info!("Found {} updates in dpkg log", updates.len());
                    return Ok(updates);
                }

                warn!("Could not read any apt/dpkg logs");
                return Ok(Vec::new());
            }
        }
    } else if has_dnf {
        debug!("Using dnf history");

        match execute_command("dnf", &["history", "list", "--reverse"]) {
            Ok(output) => {
                let updates = parse_dnf_history(&output, days);
                info!("Found {} updates in dnf history", updates.len());
                return Ok(updates);
            }
            Err(e) => {
                warn!("Failed to get dnf history: {}", e);
                return Ok(Vec::new());
            }
        }
    } else if has_yum {
        debug!("Using yum history");

        match execute_command("yum", &["history", "list"]) {
            Ok(output) => {
                let updates = parse_dnf_history(&output, days); // Same format
                info!("Found {} updates in yum history", updates.len());
                return Ok(updates);
            }
            Err(e) => {
                warn!("Failed to get yum history: {}", e);
                return Ok(Vec::new());
            }
        }
    }

    Err(anyhow!("No supported package manager found for history query"))
}

/// Parse dpkg.log format
#[cfg(target_os = "linux")]
fn parse_dpkg_log(content: &str, days: u32) -> Vec<LinuxUpdate> {
    use chrono::{NaiveDateTime, Utc, Duration};

    let mut updates = Vec::new();
    let cutoff = Utc::now() - Duration::days(days as i64);

    for line in content.lines() {
        // Format: 2024-01-15 10:30:45 status installed package:arch version
        // or: 2024-01-15 10:30:45 upgrade package:arch old-version new-version
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let date = parts[0];
        let time = parts[1];
        let action = parts[2];

        // Parse datetime to check if within range
        let datetime_str = format!("{} {}", date, time);
        let within_range = if let Ok(parsed) = NaiveDateTime::parse_from_str(&datetime_str, "%Y-%m-%d %H:%M:%S") {
            parsed.and_utc() >= cutoff
        } else {
            // If we can't parse, include it to be safe
            true
        };

        if !within_range {
            continue;
        }

        // Only process install/upgrade actions
        if action != "install" && action != "upgrade" && action != "status" {
            continue;
        }

        if action == "status" && parts.len() > 3 && parts[3] != "installed" {
            continue;
        }

        let package_with_arch = if action == "status" { parts[4] } else { parts[3] };
        let package_name = package_with_arch.split(':').next().unwrap_or(package_with_arch).to_string();

        let version = if action == "upgrade" && parts.len() > 5 {
            parts[5].to_string() // new version
        } else if parts.len() > 4 {
            parts[parts.len() - 1].to_string()
        } else {
            String::new()
        };

        let installed_on = format!("{} {}", date, time);

        updates.push(LinuxUpdate {
            package_name,
            version,
            installed_on: Some(installed_on),
            repository: None,
            action: Some(action.to_string()),
        });
    }

    updates
}

/// Get pending Linux updates (convenience wrapper)
#[cfg(target_os = "linux")]
pub async fn get_pending_linux_updates() -> Result<Vec<LinuxPendingUpdate>> {
    let status = check_linux_updates().await?;
    Ok(status.pending_updates)
}

/// Non-Linux implementation (stub)
#[cfg(not(target_os = "linux"))]
pub async fn check_linux_updates() -> Result<LinuxUpdateStatus> {
    Err(anyhow!("Linux Updates check is only available on Linux"))
}

/// Non-Linux implementation (stub)
#[cfg(not(target_os = "linux"))]
pub async fn get_linux_update_history(_days: u32) -> Result<Vec<LinuxUpdate>> {
    Err(anyhow!("Linux Update history is only available on Linux"))
}

/// Non-Linux implementation (stub)
#[cfg(not(target_os = "linux"))]
pub async fn get_pending_linux_updates() -> Result<Vec<LinuxPendingUpdate>> {
    Err(anyhow!("Linux pending updates check is only available on Linux"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_update_serialization() {
        let update = LinuxUpdate {
            package_name: "vim".to_string(),
            version: "2:8.2.3995-1ubuntu2.17".to_string(),
            installed_on: Some("2024-01-15 10:30:45".to_string()),
            repository: Some("jammy-updates".to_string()),
            action: Some("Upgrade".to_string()),
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("vim"));
        assert!(json.contains("jammy-updates"));
    }

    #[test]
    fn test_pending_update_serialization() {
        let update = LinuxPendingUpdate {
            package_name: "vim".to_string(),
            current_version: Some("2:8.2.3995-1ubuntu2.16".to_string()),
            available_version: "2:8.2.3995-1ubuntu2.17".to_string(),
            repository: Some("jammy-security".to_string()),
            is_security: true,
            size_kb: Some(1024),
            architecture: Some("amd64".to_string()),
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("vim"));
        assert!(json.contains("jammy-security"));
        assert!(json.contains("is_security"));
    }

    #[test]
    fn test_update_status_serialization() {
        let status = LinuxUpdateStatus {
            pending_updates: vec![],
            security_updates_count: 0,
            total_pending_count: 0,
            last_check: SystemTime::now(),
            package_manager: "apt".to_string(),
            reboot_required: false,
            distro: "Ubuntu".to_string(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("apt"));
        assert!(json.contains("Ubuntu"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_apt_upgradable() {
        let output = r#"Listing...
vim/jammy-security 2:8.2.3995-1ubuntu2.17 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.16]
curl/jammy-updates 7.81.0-1ubuntu1.15 amd64 [upgradable from: 7.81.0-1ubuntu1.14]
"#;

        let updates = parse_apt_upgradable(output);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].package_name, "vim");
        assert!(updates[0].is_security);
        assert_eq!(updates[1].package_name, "curl");
        assert!(!updates[1].is_security);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_dnf_check_update() {
        let output = r#"Last metadata expiration check: 1:00:00 ago
vim-enhanced.x86_64    2:9.0.1378-1.fc38    updates
curl.x86_64            8.0.1-1.fc38         updates
"#;

        let updates = parse_dnf_check_update(output);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].package_name, "vim-enhanced");
        assert_eq!(updates[0].architecture, Some("x86_64".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_extract_package_name_from_nevra() {
        assert_eq!(extract_package_name_from_nevra("vim-enhanced-2:9.0.1378-1.fc38.x86_64"), "vim-enhanced");
        assert_eq!(extract_package_name_from_nevra("curl-8.0.1-1.fc38.x86_64"), "curl");
        assert_eq!(extract_package_name_from_nevra("python3-pip-21.0.1-1.el9.noarch"), "python3-pip");
    }
}
