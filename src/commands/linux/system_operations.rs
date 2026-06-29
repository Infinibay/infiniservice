//! Linux System Operations implementation
//!
//! This module provides the Linux-specific implementation of `SystemOperations`,
//! encapsulating all Linux system management operations including services,
//! packages, processes, users, updates, security, and health checks.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use serde_json::{json, Value};
use std::process::{Command, Stdio};

use crate::commands::traits::{SystemOperationResult, SystemOperations};
use crate::commands::ServiceOperation;
use crate::os_detection::{get_os_info, OsInfo, PackageManager};

/// Disk space information structure
#[derive(Debug, Clone)]
struct DiskSpaceInfo {
    #[allow(dead_code)]
    mount_point: String,
    #[allow(dead_code)]
    total_gb: f64,
    available_gb: f64,
    #[allow(dead_code)]
    used_gb: f64,
    usage_percent: f64,
}

/// Linux system operations implementation
pub struct LinuxSystemOperations {
    os_info: &'static OsInfo,
}

impl LinuxSystemOperations {
    /// Create a new Linux system operations instance
    pub fn new() -> Self {
        Self {
            os_info: get_os_info(),
        }
    }

    /// Check if an executable is available on the system
    fn is_executable_available(executable_name: &str) -> bool {
        Command::new("which")
            .arg(executable_name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Execute a Linux command and return (stdout, stderr)
    async fn execute_command(&self, command: &str, args: &[&str]) -> Result<(String, String)> {
        debug!("Executing Linux command: {} {:?}", command, args);

        let output = Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context(format!("Failed to execute command: {} {:?}", command, args))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                return Err(anyhow!(
                    "Command '{}' requires elevated privileges (sudo). Error: {}",
                    command,
                    stderr
                ));
            }
            return Err(anyhow!(
                "Command '{}' failed with exit code {:?}: {}",
                command,
                output.status.code(),
                stderr
            ));
        }

        Ok((stdout, stderr))
    }

    /// Validate service/package names for injection attacks.
    /// Strict allowlist (rejects quotes, backtick, whitespace, metacharacters).
    fn validate_name(name: &str, entity_type: &str) -> Result<()> {
        crate::commands::validation::validate_entity_name(name, entity_type)
    }

    /// Parse dpkg -l output
    fn parse_dpkg_list(&self, output: &str) -> Vec<Value> {
        let mut packages = Vec::new();

        for line in output.lines() {
            if line.starts_with("ii ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    packages.push(json!({
                        "name": parts[1],
                        "version": parts[2],
                        "installed": true,
                        "description": parts.get(4..).map(|p| p.join(" ")).unwrap_or_default()
                    }));
                }
            }
        }

        packages
    }

    /// Parse rpm list output
    fn parse_rpm_list(&self, output: &str) -> Vec<Value> {
        let mut packages = Vec::new();

        for line in output.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 {
                packages.push(json!({
                    "name": parts[0],
                    "version": parts[1],
                    "description": parts.get(2).unwrap_or(&""),
                    "installed": true
                }));
            }
        }

        packages
    }

    /// Parse apt-cache search output
    fn parse_apt_search(&self, output: &str) -> Vec<Value> {
        let mut packages = Vec::new();

        for line in output.lines() {
            if let Some(dash_pos) = line.find(" - ") {
                let name = &line[..dash_pos];
                let description = &line[dash_pos + 3..];
                packages.push(json!({
                    "name": name.trim(),
                    "description": description.trim(),
                    "installed": false
                }));
            }
        }

        packages
    }

    /// Parse yum/dnf search output
    fn parse_yum_search(&self, output: &str) -> Vec<Value> {
        let mut packages = Vec::new();

        for line in output.lines() {
            let line = line.trim();

            if line.is_empty() || line.contains("==") || line.contains("Matched:") {
                continue;
            }

            if let Some((left, right)) = line.split_once(" : ") {
                let name = left.split('.').next().unwrap_or(left);
                packages.push(json!({
                    "name": name,
                    "description": right.trim(),
                    "installed": false,
                }));
            }
        }

        packages
    }

    /// Get available package manager command
    fn get_package_manager(&self) -> Option<(&str, &str)> {
        if self.os_info.available_package_managers.contains(&PackageManager::Apt) {
            Some(("apt-get", "dpkg"))
        } else if self.os_info.available_package_managers.contains(&PackageManager::Dnf) {
            Some(("dnf", "rpm"))
        } else if self.os_info.available_package_managers.contains(&PackageManager::Yum) {
            Some(("yum", "rpm"))
        } else {
            None
        }
    }

    /// Get disk space information for a mount point
    fn get_disk_space_info(&self, mount_point: &str) -> Result<DiskSpaceInfo> {
        use sysinfo::Disks;

        let disks = Disks::new_with_refreshed_list();

        let mut best_match: Option<&sysinfo::Disk> = None;
        let mut best_match_len = 0;

        for disk in &disks {
            let disk_mount = disk.mount_point().to_string_lossy();
            if mount_point.starts_with(disk_mount.as_ref()) && disk_mount.len() > best_match_len {
                best_match = Some(disk);
                best_match_len = disk_mount.len();
            }
        }

        if let Some(disk) = best_match {
            let total_bytes = disk.total_space();
            let available_bytes = disk.available_space();
            let used_bytes = total_bytes.saturating_sub(available_bytes);
            let usage_percent = if total_bytes > 0 {
                (used_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };

            Ok(DiskSpaceInfo {
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                total_gb: total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                available_gb: available_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                used_gb: used_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                usage_percent,
            })
        } else {
            Err(anyhow!(
                "Could not find disk information for mount point: {}",
                mount_point
            ))
        }
    }

    /// Detect the Linux package manager available on the system
    fn detect_package_manager(&self) -> Option<PackageManager> {
        if self.os_info.available_package_managers.contains(&PackageManager::Apt) {
            return Some(PackageManager::Apt);
        }
        if self.os_info.available_package_managers.contains(&PackageManager::Dnf) {
            return Some(PackageManager::Dnf);
        }
        if self.os_info.available_package_managers.contains(&PackageManager::Yum) {
            return Some(PackageManager::Yum);
        }

        // Fallback: check executables directly
        if Self::is_executable_available("apt-get") {
            return Some(PackageManager::Apt);
        }
        if Self::is_executable_available("dnf") {
            return Some(PackageManager::Dnf);
        }
        if Self::is_executable_available("yum") {
            return Some(PackageManager::Yum);
        }

        None
    }

    /// Get the current running kernel version
    async fn get_current_kernel_version(&self) -> Option<String> {
        match Command::new("uname").arg("-r").output() {
            Ok(output) if output.status.success() => {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            }
            _ => None,
        }
    }

    /// Count installed kernel packages on APT-based systems
    async fn count_installed_kernels_apt(&self) -> usize {
        match Command::new("dpkg").args(&["-l", "linux-image-*"]).output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout
                    .lines()
                    .filter(|line| {
                        line.starts_with("ii")
                            && line.contains("linux-image-")
                            && !line.contains("-generic ")
                            && !line.contains("-virtual ")
                            && !line.contains("-lowlatency ")
                            && line.chars().any(|c| c.is_ascii_digit())
                    })
                    .count()
            }
            _ => {
                debug!("Failed to count kernels via dpkg, assuming 2 for safety");
                2
            }
        }
    }

    /// Count installed kernel packages on RPM-based systems
    async fn count_installed_kernels_rpm(&self) -> usize {
        match Command::new("rpm").args(&["-q", "kernel"]).output() {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout
                    .lines()
                    .filter(|line| !line.trim().is_empty() && line.starts_with("kernel-"))
                    .count()
            }
            _ => {
                match Command::new("rpm").args(&["-q", "kernel-core"]).output() {
                    Ok(output) if output.status.success() => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        stdout.lines().filter(|line| !line.trim().is_empty()).count()
                    }
                    _ => {
                        debug!("Failed to count kernels via rpm, assuming 2 for safety");
                        2
                    }
                }
            }
        }
    }

    /// Clean temporary files with safety exclusions
    async fn cleanup_temp_files(&self) -> Result<String> {
        use std::fs;

        const EXCLUDED_DIRS: &[&str] = &[
            ".X11-unix",
            ".ICE-unix",
            ".font-unix",
            ".XIM-unix",
            "systemd-private-",
        ];

        let temp_dirs = vec!["/tmp", "/var/tmp"];
        let mut total_freed: u64 = 0;
        let mut files_removed: usize = 0;
        let mut errors = Vec::new();

        for temp_dir in temp_dirs {
            let path = std::path::Path::new(temp_dir);
            if !path.exists() {
                continue;
            }

            match fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        let entry_name = entry.file_name().to_string_lossy().to_string();

                        if EXCLUDED_DIRS.iter().any(|exc| entry_name.starts_with(exc)) {
                            debug!("Skipping excluded entry: {}", entry_name);
                            continue;
                        }

                        if let Ok(metadata) = entry.metadata() {
                            if let Ok(modified) = metadata.modified() {
                                let age = std::time::SystemTime::now()
                                    .duration_since(modified)
                                    .unwrap_or(std::time::Duration::from_secs(0));

                                if age > std::time::Duration::from_secs(86400) {
                                    let size = metadata.len();
                                    let entry_path = entry.path();

                                    let result = if entry_path.is_dir() {
                                        fs::remove_dir_all(&entry_path)
                                    } else {
                                        fs::remove_file(&entry_path)
                                    };

                                    match result {
                                        Ok(_) => {
                                            total_freed += size;
                                            files_removed += 1;
                                            debug!("Removed: {:?} ({} bytes)", entry_path, size);
                                        }
                                        Err(e) => {
                                            if e.kind() != std::io::ErrorKind::PermissionDenied {
                                                debug!("Failed to remove {:?}: {}", entry_path, e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("Failed to read {}: {}", temp_dir, e));
                }
            }
        }

        info!(
            "Temp cleanup: {} files removed, {} bytes freed",
            files_removed, total_freed
        );

        Ok(format!(
            "Removed {} files/directories, freed {} bytes. Errors: {}",
            files_removed,
            total_freed,
            if errors.is_empty() {
                "none".to_string()
            } else {
                errors.join("; ")
            }
        ))
    }

    /// Ubuntu/Debian disk cleanup using APT
    async fn cleanup_disk_ubuntu(&self, targets: &[String]) -> Result<Vec<Value>> {
        let mut operations = Vec::new();

        for target in targets {
            match target.as_str() {
                "cache" => {
                    info!("Cleaning APT package cache");

                    let clean_result = self.execute_command("apt-get", &["clean"]).await;
                    operations.push(json!({
                        "target": "cache",
                        "command": "apt-get clean",
                        "success": clean_result.is_ok(),
                        "output": clean_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                        "error": clean_result.as_ref().err().map(|e| e.to_string())
                    }));

                    let autoclean_result = self.execute_command("apt-get", &["autoclean", "-y"]).await;
                    operations.push(json!({
                        "target": "cache",
                        "command": "apt-get autoclean",
                        "success": autoclean_result.is_ok(),
                        "output": autoclean_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                        "error": autoclean_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                "old-kernels" => {
                    let current_kernel = self.get_current_kernel_version().await;
                    info!(
                        "Current kernel: {:?}. Checking kernel count before removal.",
                        current_kernel
                    );

                    let kernel_count = self.count_installed_kernels_apt().await;
                    info!("Found {} installed kernel(s)", kernel_count);

                    if kernel_count <= 2 {
                        warn!(
                            "Only {} kernel(s) installed. Skipping old kernel removal.",
                            kernel_count
                        );
                        operations.push(json!({
                            "target": "old-kernels",
                            "command": "apt-get autoremove --purge (SKIPPED)",
                            "success": false,
                            "warning": format!(
                                "Skipped: Only {} kernel(s) installed. At least 2 kernels must be kept.",
                                kernel_count
                            ),
                            "current_kernel": current_kernel,
                            "kernel_count": kernel_count
                        }));
                    } else {
                        info!(
                            "Proceeding with old kernel removal. {} kernels installed.",
                            kernel_count
                        );
                        let autoremove_result =
                            self.execute_command("apt-get", &["autoremove", "--purge", "-y"]).await;
                        operations.push(json!({
                            "target": "old-kernels",
                            "command": "apt-get autoremove --purge",
                            "success": autoremove_result.is_ok(),
                            "output": autoremove_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                            "error": autoremove_result.as_ref().err().map(|e| e.to_string()),
                            "current_kernel": current_kernel,
                            "kernel_count_before": kernel_count
                        }));
                    }
                }
                "temp-files" => {
                    info!("Cleaning temporary files");
                    let temp_result = self.cleanup_temp_files().await;
                    operations.push(json!({
                        "target": "temp-files",
                        "command": "rm -rf /tmp/* (with exclusions)",
                        "success": temp_result.is_ok(),
                        "output": temp_result.as_ref().map(|r| r.clone()).unwrap_or_default(),
                        "error": temp_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                "logs" => {
                    info!("Cleaning old journal logs");
                    let journal_result =
                        self.execute_command("journalctl", &["--vacuum-time=7d"]).await;
                    operations.push(json!({
                        "target": "logs",
                        "command": "journalctl --vacuum-time=7d",
                        "success": journal_result.is_ok(),
                        "output": journal_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                        "error": journal_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                _ => {
                    warn!("Unknown cleanup target: {}", target);
                }
            }
        }

        Ok(operations)
    }

    /// Fedora/RHEL disk cleanup using DNF or YUM
    async fn cleanup_disk_fedora(
        &self,
        targets: &[String],
        pkg_mgr: &PackageManager,
    ) -> Result<Vec<Value>> {
        let mut operations = Vec::new();
        let cmd = match pkg_mgr {
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            _ => return Err(anyhow!("Unsupported package manager for Fedora cleanup")),
        };

        for target in targets {
            match target.as_str() {
                "cache" => {
                    info!("Cleaning {} package cache", cmd);
                    let clean_result = self.execute_command(cmd, &["clean", "all", "-y"]).await;
                    operations.push(json!({
                        "target": "cache",
                        "command": format!("{} clean all", cmd),
                        "success": clean_result.is_ok(),
                        "output": clean_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                        "error": clean_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                "old-kernels" => {
                    let current_kernel = self.get_current_kernel_version().await;
                    info!(
                        "Current kernel: {:?}. Checking kernel count before removal.",
                        current_kernel
                    );

                    let kernel_count = self.count_installed_kernels_rpm().await;
                    info!("Found {} installed kernel(s)", kernel_count);

                    if kernel_count <= 2 {
                        warn!(
                            "Only {} kernel(s) installed. Skipping old kernel removal.",
                            kernel_count
                        );
                        operations.push(json!({
                            "target": "old-kernels",
                            "command": format!("{} autoremove (SKIPPED)", cmd),
                            "success": false,
                            "warning": format!(
                                "Skipped: Only {} kernel(s) installed. At least 2 kernels must be kept.",
                                kernel_count
                            ),
                            "current_kernel": current_kernel,
                            "kernel_count": kernel_count
                        }));
                    } else {
                        if Self::is_executable_available("package-cleanup") {
                            info!("Using package-cleanup to safely remove old kernels, keeping 2");
                            let pkg_cleanup_result = self
                                .execute_command("package-cleanup", &["--oldkernels", "--count=2", "-y"])
                                .await;
                            operations.push(json!({
                                "target": "old-kernels",
                                "command": "package-cleanup --oldkernels --count=2",
                                "success": pkg_cleanup_result.is_ok(),
                                "output": pkg_cleanup_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                                "error": pkg_cleanup_result.as_ref().err().map(|e| e.to_string()),
                                "current_kernel": current_kernel,
                                "kernel_count_before": kernel_count
                            }));
                        } else {
                            info!(
                                "Proceeding with {} autoremove. {} kernels installed.",
                                cmd, kernel_count
                            );
                            let autoremove_result =
                                self.execute_command(cmd, &["autoremove", "-y"]).await;
                            operations.push(json!({
                                "target": "old-kernels",
                                "command": format!("{} autoremove", cmd),
                                "success": autoremove_result.is_ok(),
                                "output": autoremove_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                                "error": autoremove_result.as_ref().err().map(|e| e.to_string()),
                                "current_kernel": current_kernel,
                                "kernel_count_before": kernel_count
                            }));
                        }
                    }
                }
                "temp-files" => {
                    info!("Cleaning temporary files");
                    let temp_result = self.cleanup_temp_files().await;
                    operations.push(json!({
                        "target": "temp-files",
                        "command": "rm -rf /tmp/* (with exclusions)",
                        "success": temp_result.is_ok(),
                        "output": temp_result.as_ref().map(|r| r.clone()).unwrap_or_default(),
                        "error": temp_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                "logs" => {
                    info!("Cleaning old journal logs");
                    let journal_result =
                        self.execute_command("journalctl", &["--vacuum-time=7d"]).await;
                    operations.push(json!({
                        "target": "logs",
                        "command": "journalctl --vacuum-time=7d",
                        "success": journal_result.is_ok(),
                        "output": journal_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                        "error": journal_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                _ => {
                    warn!("Unknown cleanup target: {}", target);
                }
            }
        }

        Ok(operations)
    }

    /// Generic Linux cleanup for systems without apt/dnf/yum
    async fn cleanup_disk_generic(&self, targets: &[String]) -> Result<Vec<Value>> {
        let mut operations = Vec::new();

        for target in targets {
            match target.as_str() {
                "cache" => {
                    operations.push(json!({
                        "target": "cache",
                        "command": "N/A",
                        "success": false,
                        "warning": "No supported package manager detected. Cannot clean package cache."
                    }));
                }
                "old-kernels" => {
                    operations.push(json!({
                        "target": "old-kernels",
                        "command": "N/A",
                        "success": false,
                        "warning": "No supported package manager detected. Cannot remove old kernels automatically."
                    }));
                }
                "temp-files" => {
                    info!("Cleaning temporary files");
                    let temp_result = self.cleanup_temp_files().await;
                    operations.push(json!({
                        "target": "temp-files",
                        "command": "rm -rf /tmp/* (with exclusions)",
                        "success": temp_result.is_ok(),
                        "output": temp_result.as_ref().map(|r| r.clone()).unwrap_or_default(),
                        "error": temp_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                "logs" => {
                    info!("Cleaning old journal logs");
                    let journal_result =
                        self.execute_command("journalctl", &["--vacuum-time=7d"]).await;
                    operations.push(json!({
                        "target": "logs",
                        "command": "journalctl --vacuum-time=7d",
                        "success": journal_result.is_ok(),
                        "output": journal_result.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                        "error": journal_result.as_ref().err().map(|e| e.to_string())
                    }));
                }
                _ => {
                    warn!("Unknown cleanup target: {}", target);
                }
            }
        }

        Ok(operations)
    }
}

impl Default for LinuxSystemOperations {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SystemOperations for LinuxSystemOperations {
    // ===== Service Operations =====

    async fn list_services(&self) -> SystemOperationResult {
        // Try JSON output first
        let output = Command::new("systemctl")
            .args(&["list-units", "--type=service", "--all", "--output=json"])
            .output()
            .context("Failed to execute systemctl")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let services = serde_json::from_str(&stdout).ok();
            Ok((stdout.to_string(), String::new(), services))
        } else {
            // Fallback to non-JSON output
            let output = Command::new("systemctl")
                .args(&["list-units", "--type=service", "--all"])
                .output()
                .context("Failed to execute systemctl")?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok((stdout.to_string(), String::new(), None))
        }
    }

    async fn control_service(
        &self,
        service: &str,
        operation: &ServiceOperation,
    ) -> SystemOperationResult {
        Self::validate_name(service, "service")?;

        let systemctl_cmd = match operation {
            ServiceOperation::Start => "start",
            ServiceOperation::Stop => "stop",
            ServiceOperation::Restart => "restart",
            ServiceOperation::Enable => "enable",
            ServiceOperation::Disable => "disable",
            ServiceOperation::Status => "status",
        };

        let output = Command::new("systemctl")
            .args(&[systemctl_cmd, service])
            .output()
            .context("Failed to execute systemctl")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() || matches!(operation, ServiceOperation::Status) {
            Ok((stdout.to_string(), stderr.to_string(), None))
        } else {
            Err(anyhow!("Service control failed: {}", stderr))
        }
    }

    // ===== Package Operations =====

    async fn list_packages(&self) -> SystemOperationResult {
        let packages = if self.os_info.available_package_managers.contains(&PackageManager::Apt) {
            let output = Command::new("dpkg")
                .args(&["-l"])
                .output()
                .context("Failed to list packages")?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            self.parse_dpkg_list(&stdout)
        } else if self
            .os_info
            .available_package_managers
            .iter()
            .any(|p| matches!(p, PackageManager::Yum | PackageManager::Dnf))
        {
            let output = Command::new("rpm")
                .args(&["-qa", "--queryformat", "%{NAME}|%{VERSION}|%{SUMMARY}\n"])
                .output()
                .context("Failed to list packages")?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            self.parse_rpm_list(&stdout)
        } else {
            return Err(anyhow!("No supported package manager found"));
        };

        Ok((
            format!("Found {} packages", packages.len()),
            String::new(),
            Some(json!({ "packages": packages })),
        ))
    }

    async fn install_package(&self, package: &str) -> SystemOperationResult {
        Self::validate_name(package, "package")?;

        let (pkg_mgr, _) = self.get_package_manager().ok_or_else(|| anyhow!("No supported package manager found"))?;

        let output = match pkg_mgr {
            "apt-get" => Command::new("apt-get").args(&["install", "-y", package]).output(),
            "dnf" => Command::new("dnf").args(&["install", "-y", package]).output(),
            "yum" => Command::new("yum").args(&["install", "-y", package]).output(),
            _ => return Err(anyhow!("No supported package manager found")),
        };

        let output = output.context("Failed to install package")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            Ok((stdout.to_string(), stderr.to_string(), None))
        } else {
            Err(anyhow!("Package installation failed: {}", stderr))
        }
    }

    async fn remove_package(&self, package: &str) -> SystemOperationResult {
        Self::validate_name(package, "package")?;

        let (pkg_mgr, _) = self.get_package_manager().ok_or_else(|| anyhow!("No supported package manager found"))?;

        let output = match pkg_mgr {
            "apt-get" => Command::new("apt-get").args(&["remove", "-y", package]).output(),
            "dnf" => Command::new("dnf").args(&["remove", "-y", package]).output(),
            "yum" => Command::new("yum").args(&["remove", "-y", package]).output(),
            _ => return Err(anyhow!("No supported package manager found")),
        };

        let output = output.context("Failed to remove package")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            Ok((stdout.to_string(), stderr.to_string(), None))
        } else {
            Err(anyhow!("Package removal failed: {}", stderr))
        }
    }

    async fn update_package(&self, package: &str) -> SystemOperationResult {
        Self::validate_name(package, "package")?;

        let (pkg_mgr, _) = self.get_package_manager().ok_or_else(|| anyhow!("No supported package manager found"))?;

        let output = match pkg_mgr {
            "apt-get" => Command::new("apt-get")
                .args(&["install", "--only-upgrade", "-y", package])
                .output(),
            "dnf" => Command::new("dnf").args(&["upgrade", "-y", package]).output(),
            "yum" => Command::new("yum").args(&["update", "-y", package]).output(),
            _ => return Err(anyhow!("No supported package manager found")),
        };

        let output = output.context("Failed to update package")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            Ok((stdout.to_string(), stderr.to_string(), None))
        } else {
            Err(anyhow!("Package update failed: {}", stderr))
        }
    }

    async fn search_packages(&self, query: &str) -> SystemOperationResult {
        Self::validate_name(query, "query")?;

        let packages = if self.os_info.available_package_managers.contains(&PackageManager::Apt) {
            let output = Command::new("apt-cache")
                .args(&["search", query])
                .output()
                .context("Failed to search packages")?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            self.parse_apt_search(&stdout)
        } else if self
            .os_info
            .available_package_managers
            .iter()
            .any(|p| matches!(p, PackageManager::Yum | PackageManager::Dnf))
        {
            let cmd = if self.os_info.available_package_managers.contains(&PackageManager::Dnf) {
                "dnf"
            } else {
                "yum"
            };

            let output = Command::new(cmd)
                .args(&["search", query])
                .output()
                .context("Failed to search packages")?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            self.parse_yum_search(&stdout)
        } else {
            return Err(anyhow!("No supported package manager found"));
        };

        Ok((
            format!("Found {} packages matching '{}'", packages.len(), query),
            String::new(),
            Some(json!({ "packages": packages })),
        ))
    }

    // ===== Process Operations =====

    async fn list_processes(&self, limit: Option<usize>) -> SystemOperationResult {
        use sysinfo::System;

        let mut system = System::new();
        system.refresh_all();

        let mut processes: Vec<Value> = system
            .processes()
            .iter()
            .map(|(pid, process)| {
                json!({
                    "pid": pid.as_u32(),
                    "name": process.name().to_string_lossy().to_string(),
                    "cpu_usage": process.cpu_usage(),
                    "memory_kb": process.memory() / 1024,
                    "status": format!("{:?}", process.status()),
                })
            })
            .collect();

        if let Some(limit) = limit {
            processes.truncate(limit);
        }

        Ok((
            format!("Found {} processes", processes.len()),
            String::new(),
            Some(json!(processes)),
        ))
    }

    async fn kill_process(&self, pid: u32, force: bool) -> SystemOperationResult {
        use sysinfo::{Pid, System};

        let mut system = System::new();
        system.refresh_all();

        let pid_struct = Pid::from_u32(pid);

        if let Some(process) = system.process(pid_struct) {
            let name = process.name().to_string_lossy().to_string().to_lowercase();
            if !force
                && (name.contains("system")
                    || name.contains("kernel")
                    || name.contains("init")
                    || name.contains("systemd"))
            {
                return Err(anyhow!(
                    "Cannot kill system process {} ({}). Use force=true to override",
                    pid,
                    name
                ));
            }

            if process.kill_with(sysinfo::Signal::Term).unwrap_or(false) {
                Ok((format!("Process {} killed successfully", pid), String::new(), None))
            } else {
                Err(anyhow!("Failed to kill process {}", pid))
            }
        } else {
            Err(anyhow!("Process {} not found", pid))
        }
    }

    async fn get_top_processes(&self, limit: usize, sort_by: Option<&str>) -> SystemOperationResult {
        use sysinfo::System;

        let mut system = System::new();
        system.refresh_all();

        let mut processes: Vec<_> = system
            .processes()
            .iter()
            .map(|(pid, process)| {
                (
                    pid.as_u32(),
                    process.name().to_string_lossy().to_string(),
                    process.cpu_usage(),
                    process.memory(),
                )
            })
            .collect();

        match sort_by {
            Some("memory") | Some("mem") => {
                processes.sort_by(|a, b| b.3.cmp(&a.3));
            }
            _ => {
                processes.sort_by(|a, b| {
                    b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }

        processes.truncate(limit);

        let data: Vec<Value> = processes
            .iter()
            .map(|(pid, name, cpu, memory)| {
                json!({
                    "pid": pid,
                    "name": name,
                    "cpu_usage": cpu,
                    "memory_kb": memory / 1024,
                })
            })
            .collect();

        Ok((
            format!("Top {} processes", data.len()),
            String::new(),
            Some(json!(data)),
        ))
    }

    // ===== User Operations =====

    async fn list_users(&self) -> SystemOperationResult {
        let passwd_content = tokio::fs::read_to_string("/etc/passwd")
            .await
            .map_err(|e| anyhow!("Failed to read /etc/passwd: {}", e))?;

        let user_list: Vec<Value> = passwd_content
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let uid: u32 = parts[2].parse().unwrap_or(0);
                    let name = parts[0].to_string();

                    if uid >= 1000 || uid == 0 {
                        Some(json!({
                            "name": name,
                            "uid": uid,
                            "gid": parts[3].parse::<u32>().unwrap_or(0),
                            "description": parts[4],
                            "home": parts[5],
                            "shell": parts[6],
                        }))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        let count = user_list.len();
        let data = json!({
            "users": user_list,
            "count": count
        });

        Ok((format!("Found {} users", count), String::new(), Some(data)))
    }

    // ===== Update Operations =====

    async fn check_updates(&self) -> SystemOperationResult {
        use crate::commands::linux_updates;

        match linux_updates::check_linux_updates().await {
            Ok(update_status) => {
                let status_json = serde_json::to_value(&update_status)?;
                let summary = format!(
                    "Found {} pending updates ({} security updates) via {}",
                    update_status.total_pending_count,
                    update_status.security_updates_count,
                    update_status.package_manager
                );
                Ok((summary, String::new(), Some(status_json)))
            }
            Err(e) => Err(anyhow!("Failed to check Linux updates: {}", e)),
        }
    }

    async fn get_update_history(&self, days: u32) -> SystemOperationResult {
        use crate::commands::linux_updates;

        match linux_updates::get_linux_update_history(days).await {
            Ok(updates) => {
                let updates_json = serde_json::to_value(&updates)?;
                let summary = format!("Found {} updates in the last {} days", updates.len(), days);
                Ok((summary, String::new(), Some(updates_json)))
            }
            Err(e) => Err(anyhow!("Failed to get Linux update history: {}", e)),
        }
    }

    async fn get_pending_updates(&self) -> SystemOperationResult {
        use crate::commands::linux_updates;

        match linux_updates::get_pending_linux_updates().await {
            Ok(pending_updates) => {
                let security_count = pending_updates.iter().filter(|u| u.is_security).count();
                let updates_json = serde_json::to_value(&pending_updates)?;
                let summary = format!(
                    "Found {} pending updates ({} security updates)",
                    pending_updates.len(),
                    security_count
                );
                Ok((summary, String::new(), Some(updates_json)))
            }
            Err(e) => Err(anyhow!("Failed to get pending Linux updates: {}", e)),
        }
    }

    // ===== Security Operations =====

    async fn check_security(&self) -> SystemOperationResult {
        use crate::commands::linux_security;

        match linux_security::check_linux_security().await {
            Ok(security_status) => {
                let status_json = serde_json::to_value(&security_status)?;
                let firewall_status = if security_status.firewall.enabled {
                    "active"
                } else {
                    "inactive"
                };
                let security_module = format!("{:?}", security_status.security_module.module_type);
                let summary = format!(
                    "Firewall: {} ({}), Security module: {}, Security updates: {}",
                    firewall_status,
                    format!("{:?}", security_status.firewall.firewall_type).to_lowercase(),
                    security_module.to_lowercase(),
                    security_status.security_updates_count
                );
                Ok((summary, String::new(), Some(status_json)))
            }
            Err(e) => Err(anyhow!("Failed to check Linux security: {}", e)),
        }
    }

    async fn get_firewall_status(&self) -> SystemOperationResult {
        use crate::commands::linux_security;

        match linux_security::get_linux_firewall_status().await {
            Ok(firewall_status) => {
                let status_json = serde_json::to_value(&firewall_status)?;
                let status = if firewall_status.enabled {
                    "active"
                } else {
                    "inactive"
                };
                let summary = format!(
                    "Firewall: {} ({:?}), Rules: {}, Default incoming: {}",
                    status,
                    firewall_status.firewall_type,
                    firewall_status.rules_count,
                    firewall_status.default_incoming.as_deref().unwrap_or("unknown")
                );
                Ok((summary, String::new(), Some(status_json)))
            }
            Err(e) => Err(anyhow!("Failed to get Linux firewall status: {}", e)),
        }
    }

    async fn get_security_updates(&self) -> SystemOperationResult {
        use crate::commands::linux_security;

        match linux_security::get_linux_security_updates().await {
            Ok(security_updates) => {
                let updates_json = serde_json::to_value(&security_updates)?;
                let summary = format!("Found {} security updates", security_updates.len());
                Ok((summary, String::new(), Some(updates_json)))
            }
            Err(e) => Err(anyhow!("Failed to get Linux security updates: {}", e)),
        }
    }

    async fn run_security_scan(&self) -> SystemOperationResult {
        // Linux does not have a built-in equivalent to Windows Defender quick scan
        // Users typically use ClamAV or other third-party tools
        Ok((
            "Security scan not supported on Linux. Consider using ClamAV for malware scanning."
                .to_string(),
            String::new(),
            Some(json!({
                "supported": false,
                "platform": "linux",
                "suggestion": "Install and use ClamAV: apt-get install clamav && clamscan -r /"
            })),
        ))
    }

    async fn get_threat_history(&self) -> SystemOperationResult {
        // Linux does not have a centralized threat history like Windows Defender
        Ok((
            "Threat history not available on Linux. Check logs in /var/log for security events."
                .to_string(),
            String::new(),
            Some(json!({
                "supported": false,
                "platform": "linux",
                "log_locations": ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure"]
            })),
        ))
    }

    async fn check_security_modules(&self) -> SystemOperationResult {
        use crate::commands::linux_security;

        match linux_security::check_security_modules().await {
            Ok(status) => {
                let status_json = serde_json::to_value(&status)?;
                let summary = match status.module_type {
                    linux_security::SecurityModuleType::AppArmor => {
                        format!(
                            "AppArmor: {} (profiles: {} loaded, {} enforce, {} complain)",
                            if status.enabled { "enabled" } else { "disabled" },
                            status.profiles_loaded.unwrap_or(0),
                            status.profiles_enforce.unwrap_or(0),
                            status.profiles_complain.unwrap_or(0)
                        )
                    }
                    linux_security::SecurityModuleType::SELinux => {
                        format!(
                            "SELinux: {} (mode: {:?}, policy: {})",
                            if status.enabled { "enabled" } else { "disabled" },
                            status.selinux_mode.as_ref().map(|m| format!("{:?}", m)).unwrap_or_else(|| "unknown".to_string()),
                            status.selinux_policy.as_deref().unwrap_or("unknown")
                        )
                    }
                    linux_security::SecurityModuleType::None => {
                        "No security module detected (SELinux/AppArmor)".to_string()
                    }
                };
                Ok((summary, String::new(), Some(status_json)))
            }
            Err(e) => Err(anyhow!("Failed to check security modules: {}", e)),
        }
    }

    // ===== Health Check Operations =====

    async fn check_disk_space(
        &self,
        warning_threshold: f64,
        critical_threshold: f64,
    ) -> SystemOperationResult {
        use sysinfo::Disks;

        let disks = Disks::new_with_refreshed_list();
        let mut disk_info = Vec::new();
        let mut has_warning = false;
        let mut has_critical = false;

        for disk in &disks {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            let usage_percent = if total > 0 {
                (used as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let status = if usage_percent >= critical_threshold {
                has_critical = true;
                "critical"
            } else if usage_percent >= warning_threshold {
                has_warning = true;
                "warning"
            } else {
                "ok"
            };

            disk_info.push(json!({
                "mount_point": disk.mount_point().to_string_lossy(),
                "total_gb": total as f64 / (1024.0 * 1024.0 * 1024.0),
                "available_gb": available as f64 / (1024.0 * 1024.0 * 1024.0),
                "used_gb": used as f64 / (1024.0 * 1024.0 * 1024.0),
                "usage_percent": usage_percent,
                "status": status,
            }));
        }

        let overall_status = if has_critical {
            "critical"
        } else if has_warning {
            "warning"
        } else {
            "ok"
        };

        let message = format!(
            "Disk space check: {} (checked {} disk(s))",
            overall_status,
            disk_info.len()
        );

        Ok((
            message,
            String::new(),
            Some(json!({
                "status": overall_status,
                "disks": disk_info,
                "warning_threshold": warning_threshold,
                "critical_threshold": critical_threshold,
            })),
        ))
    }

    async fn disk_cleanup(&self, drive: &str, targets: &[String]) -> SystemOperationResult {
        const VALID_TARGETS: &[&str] = &["cache", "old-kernels", "temp-files", "logs"];

        if targets.is_empty() {
            return Err(anyhow!(
                "No cleanup targets specified. Valid targets: {}",
                VALID_TARGETS.join(", ")
            ));
        }

        let invalid_targets: Vec<&String> = targets
            .iter()
            .filter(|t| !VALID_TARGETS.contains(&t.as_str()))
            .collect();

        if !invalid_targets.is_empty() {
            return Err(anyhow!(
                "Invalid cleanup targets: {:?}. Valid targets: {}",
                invalid_targets,
                VALID_TARGETS.join(", ")
            ));
        }

        let space_before = self.get_disk_space_info(drive)?;

        if space_before.available_gb < 1.0 {
            warn!(
                "Very low disk space ({:.2} GB available). Proceeding with caution.",
                space_before.available_gb
            );
        }

        let package_manager = self.detect_package_manager();
        info!("Using package manager: {:?}", package_manager);

        let operations = match package_manager {
            Some(PackageManager::Apt) => self.cleanup_disk_ubuntu(targets).await?,
            Some(PackageManager::Dnf) | Some(PackageManager::Yum) => {
                self.cleanup_disk_fedora(targets, package_manager.as_ref().unwrap()).await?
            }
            _ => self.cleanup_disk_generic(targets).await?,
        };

        let space_after = self.get_disk_space_info(drive)?;
        let space_freed_gb = space_after.available_gb - space_before.available_gb;

        let targets_processed: Vec<&String> = targets
            .iter()
            .filter(|t| {
                operations
                    .iter()
                    .any(|op| op.get("target").and_then(|v| v.as_str()) == Some(t.as_str()))
            })
            .collect();

        let warnings: Vec<String> = operations
            .iter()
            .filter_map(|op| op.get("warning").and_then(|v| v.as_str()).map(String::from))
            .collect();

        let successful_ops: usize = operations
            .iter()
            .filter(|op| op.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
            .count();
        let failed_ops: usize = operations
            .iter()
            .filter(|op| !op.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
            .count();

        let errors: Vec<String> = operations
            .iter()
            .filter_map(|op| op.get("error").and_then(|v| v.as_str()).map(String::from))
            .filter(|e| !e.is_empty())
            .collect();

        let permission_errors: Vec<&String> = errors
            .iter()
            .filter(|e| {
                e.contains("sudo")
                    || e.contains("Permission denied")
                    || e.contains("Operation not permitted")
            })
            .collect();

        let success = successful_ops > 0;

        let response_data = json!({
            "success": success,
            "drive": drive,
            "targets_processed": targets_processed,
            "successful_operations": successful_ops,
            "failed_operations": failed_ops,
            "space_before": {
                "available_gb": space_before.available_gb,
                "usage_percent": space_before.usage_percent
            },
            "space_after": {
                "available_gb": space_after.available_gb,
                "usage_percent": space_after.usage_percent
            },
            "space_freed_gb": if space_freed_gb > 0.0 { space_freed_gb } else { 0.0 },
            "operations": operations,
            "warnings": warnings,
            "errors": errors,
            "requires_elevation": !permission_errors.is_empty(),
            "package_manager": package_manager.map(|pm| format!("{:?}", pm)).unwrap_or_else(|| "generic".to_string())
        });

        if !success {
            let error_summary = if !permission_errors.is_empty() {
                format!(
                    "All {} cleanup operation(s) failed. {} require elevated privileges (sudo). Errors: {}",
                    failed_ops,
                    permission_errors.len(),
                    errors.join("; ")
                )
            } else if !errors.is_empty() {
                format!(
                    "All {} cleanup operation(s) failed. Errors: {}",
                    failed_ops,
                    errors.join("; ")
                )
            } else {
                format!(
                    "All {} cleanup operation(s) failed or were skipped. Check warnings: {}",
                    failed_ops,
                    warnings.join("; ")
                )
            };

            error!("{}", error_summary);
            return Err(anyhow!(error_summary));
        }

        let message = format!(
            "Disk cleanup completed: {:.2} GB freed on {} ({} succeeded, {} failed)",
            if space_freed_gb > 0.0 {
                space_freed_gb
            } else {
                0.0
            },
            drive,
            successful_ops,
            failed_ops
        );

        let stderr = if !permission_errors.is_empty() {
            format!(
                "Warning: {} operation(s) require elevated privileges (sudo)",
                permission_errors.len()
            )
        } else {
            String::new()
        };

        Ok((message, stderr, Some(response_data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name_valid() {
        assert!(LinuxSystemOperations::validate_name("nginx", "service").is_ok());
        assert!(LinuxSystemOperations::validate_name("my-package", "package").is_ok());
        assert!(LinuxSystemOperations::validate_name("libgtk-3-0", "package").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(LinuxSystemOperations::validate_name("nginx; rm -rf /", "service").is_err());
        assert!(LinuxSystemOperations::validate_name("pkg | cat", "package").is_err());
        assert!(LinuxSystemOperations::validate_name("$(whoami)", "package").is_err());
        assert!(LinuxSystemOperations::validate_name("test`id`", "package").is_err());
    }

    #[test]
    fn test_parse_dpkg_list() {
        let ops = LinuxSystemOperations::new();
        let output = "ii  vim  2:8.2.0-0  amd64  Vi IMproved - enhanced vi editor\nii  git  1:2.39.1  amd64  fast, scalable, distributed revision control system";
        let packages = ops.parse_dpkg_list(output);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0]["name"], "vim");
        assert_eq!(packages[1]["name"], "git");
    }

    #[test]
    fn test_parse_apt_search() {
        let ops = LinuxSystemOperations::new();
        let output = "vim - Vi IMproved\ngit - fast, scalable, distributed revision control system";
        let packages = ops.parse_apt_search(output);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0]["name"], "vim");
        assert_eq!(packages[0]["description"], "Vi IMproved");
    }
}
