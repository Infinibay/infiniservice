//! Safe command executor with validation and restrictions

use super::{SafeCommandRequest, SafeCommandType, CommandResponse, ServiceOperation, create_response};
use crate::os_detection::{get_os_info, OsType};
use anyhow::{Result, anyhow, Context};
use log::debug;
use std::process::Command;
use std::time::{Duration, Instant};
use serde_json::json;

/// Executor for safe, validated commands
pub struct SafeCommandExecutor {
    os_info: &'static crate::os_detection::OsInfo,
}

impl SafeCommandExecutor {
    /// Create a new safe command executor
    pub fn new() -> Result<Self> {
        Ok(Self {
            os_info: get_os_info(),
        })
    }
    
    /// Execute a safe command request
    pub async fn execute(&self, request: SafeCommandRequest) -> Result<CommandResponse> {
        let start_time = Instant::now();
        
        debug!("Executing safe command: {:?}", request.command_type);
        
        // Apply timeout if specified (future enhancement - not yet implemented)
        let _timeout = request.timeout.map(|t| Duration::from_secs(t as u64));
        
        // Route to appropriate handler based on command type
        let result = match &request.command_type {
            SafeCommandType::SystemInfo => self.get_system_info().await,
            SafeCommandType::OsInfo => self.get_os_info().await,
            
            SafeCommandType::ServiceList => self.list_services().await,
            SafeCommandType::ServiceControl { params } => {
                self.control_service(&params.service, &params.operation).await
            },
            
            SafeCommandType::PackageList => self.list_packages().await,
            SafeCommandType::PackageInstall { package } => self.install_package(package).await,
            SafeCommandType::PackageRemove { package } => self.remove_package(package).await,
            SafeCommandType::PackageUpdate { package } => self.update_package(package).await,
            SafeCommandType::PackageSearch { query } => self.search_packages(query).await,
            
            SafeCommandType::ProcessList { limit } => self.list_processes(*limit).await,
            SafeCommandType::ProcessKill { pid, force } => self.kill_process(*pid, *force).await,
            SafeCommandType::ProcessTop { limit, sort_by } => {
                self.get_top_processes(*limit, sort_by.as_deref()).await
            },
        };
        
        // Build response
        match result {
            Ok((stdout, stderr, data)) => {
                Ok(create_response(
                    request.id,
                    true,
                    stdout,
                    stderr,
                    Some(0),
                    "safe",
                    start_time.elapsed(),
                    data,
                ))
            },
            Err(e) => {
                Ok(create_response(
                    request.id,
                    false,
                    String::new(),
                    e.to_string(),
                    Some(1),
                    "safe",
                    start_time.elapsed(),
                    None,
                ))
            }
        }
    }
    
    /// Get system information
    async fn get_system_info(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        let data = json!({
            "os_type": self.os_info.os_type,
            "version": self.os_info.version,
            "architecture": self.os_info.architecture,
            "hostname": self.os_info.hostname,
            "kernel_version": self.os_info.kernel_version,
            "linux_distro": self.os_info.linux_distro,
            "windows_edition": self.os_info.windows_edition,
        });
        
        Ok((
            "System information retrieved successfully".to_string(),
            String::new(),
            Some(data),
        ))
    }
    
    /// Get OS information
    async fn get_os_info(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        let data = serde_json::to_value(self.os_info)?;
        Ok((
            "OS information retrieved successfully".to_string(),
            String::new(),
            Some(data),
        ))
    }
    
    /// List system services
    async fn list_services(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        match self.os_info.os_type {
            OsType::Windows => {
                // Use PowerShell to get services
                let output = Command::new("powershell")
                    .args(&[
                        "-Command",
                        "Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"
                    ])
                    .output()
                    .context("Failed to execute Get-Service")?;
                
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let services: serde_json::Value = serde_json::from_str(&stdout)?;
                    Ok((stdout.to_string(), String::new(), Some(services)))
                } else {
                    Err(anyhow!("Failed to list services: {}", String::from_utf8_lossy(&output.stderr)))
                }
            },
            OsType::Linux => {
                // Use systemctl to list services
                let output = Command::new("systemctl")
                    .args(&["list-units", "--type=service", "--all", "--output=json"])
                    .output()
                    .context("Failed to execute systemctl")?;
                
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // Try to parse as JSON, fallback to plain text
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
            },
            _ => Err(anyhow!("Unsupported OS for service listing")),
        }
    }
    
    /// Control a system service
    async fn control_service(&self, service: &str, operation: &ServiceOperation) -> Result<(String, String, Option<serde_json::Value>)> {
        // Validate service name (basic sanitization)
        if service.contains("&") || service.contains("|") || service.contains(";") || service.contains("$") {
            return Err(anyhow!("Invalid service name"));
        }
        
        match self.os_info.os_type {
            OsType::Windows => {
                let ps_cmd = match operation {
                    ServiceOperation::Start => format!("Start-Service -Name '{}'", service),
                    ServiceOperation::Stop => format!("Stop-Service -Name '{}'", service),
                    ServiceOperation::Restart => format!("Restart-Service -Name '{}'", service),
                    ServiceOperation::Enable => format!("Set-Service -Name '{}' -StartupType Automatic", service),
                    ServiceOperation::Disable => format!("Set-Service -Name '{}' -StartupType Disabled", service),
                    ServiceOperation::Status => format!("Get-Service -Name '{}' | Select-Object Name, Status, StartType | ConvertTo-Json", service),
                };
                
                let output = Command::new("powershell")
                    .args(&["-Command", &ps_cmd])
                    .output()
                    .context("Failed to execute service control")?;
                
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok((stdout.to_string(), String::new(), None))
                } else {
                    Err(anyhow!("Service control failed: {}", String::from_utf8_lossy(&output.stderr)))
                }
            },
            OsType::Linux => {
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
            },
            _ => Err(anyhow!("Unsupported OS for service control")),
        }
    }
    
    /// List installed packages
    async fn list_packages(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        match self.os_info.os_type {
            OsType::Windows => {
                // Try winget first
                let output = Command::new("winget")
                    .args(&["list", "--accept-source-agreements"])
                    .output();
                
                if let Ok(output) = output {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        return Ok((stdout.to_string(), String::new(), None));
                    }
                }
                
                // Fallback to PowerShell
                let output = Command::new("powershell")
                    .args(&[
                        "-Command",
                        "Get-Package | Select-Object Name, Version, Source | ConvertTo-Json"
                    ])
                    .output()
                    .context("Failed to list packages")?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                let packages = serde_json::from_str(&stdout).ok();
                Ok((stdout.to_string(), String::new(), packages))
            },
            OsType::Linux => {
                // Determine package manager
                let cmd = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Apt)) {
                    Command::new("dpkg").args(&["-l"]).output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Yum | crate::os_detection::PackageManager::Dnf)) {
                    Command::new("rpm").args(&["-qa"]).output()
                } else {
                    return Err(anyhow!("No supported package manager found"));
                };
                
                let output = cmd.context("Failed to list packages")?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok((stdout.to_string(), String::new(), None))
            },
            _ => Err(anyhow!("Unsupported OS for package listing")),
        }
    }
    
    /// Install a package
    async fn install_package(&self, package: &str) -> Result<(String, String, Option<serde_json::Value>)> {
        // Validate package name
        if package.contains("&") || package.contains("|") || package.contains(";") || package.contains("$") {
            return Err(anyhow!("Invalid package name"));
        }
        
        match self.os_info.os_type {
            OsType::Windows => {
                let output = Command::new("winget")
                    .args(&["install", "--accept-source-agreements", "--accept-package-agreements", package])
                    .output()
                    .context("Failed to install package")?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                if output.status.success() {
                    Ok((stdout.to_string(), stderr.to_string(), None))
                } else {
                    Err(anyhow!("Package installation failed: {}", stderr))
                }
            },
            OsType::Linux => {
                let output = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Apt)) {
                    Command::new("apt-get")
                        .args(&["install", "-y", package])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Yum)) {
                    Command::new("yum")
                        .args(&["install", "-y", package])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Dnf)) {
                    Command::new("dnf")
                        .args(&["install", "-y", package])
                        .output()
                } else {
                    return Err(anyhow!("No supported package manager found"));
                };
                
                let output = output.context("Failed to install package")?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                if output.status.success() {
                    Ok((stdout.to_string(), stderr.to_string(), None))
                } else {
                    Err(anyhow!("Package installation failed: {}", stderr))
                }
            },
            _ => Err(anyhow!("Unsupported OS for package installation")),
        }
    }
    
    /// Remove a package
    async fn remove_package(&self, package: &str) -> Result<(String, String, Option<serde_json::Value>)> {
        // Validate package name
        if package.contains("&") || package.contains("|") || package.contains(";") || package.contains("$") {
            return Err(anyhow!("Invalid package name"));
        }
        
        match self.os_info.os_type {
            OsType::Windows => {
                let output = Command::new("winget")
                    .args(&["uninstall", package])
                    .output()
                    .context("Failed to remove package")?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                if output.status.success() {
                    Ok((stdout.to_string(), stderr.to_string(), None))
                } else {
                    Err(anyhow!("Package removal failed: {}", stderr))
                }
            },
            OsType::Linux => {
                let output = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Apt)) {
                    Command::new("apt-get")
                        .args(&["remove", "-y", package])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Yum)) {
                    Command::new("yum")
                        .args(&["remove", "-y", package])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Dnf)) {
                    Command::new("dnf")
                        .args(&["remove", "-y", package])
                        .output()
                } else {
                    return Err(anyhow!("No supported package manager found"));
                };
                
                let output = output.context("Failed to remove package")?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                if output.status.success() {
                    Ok((stdout.to_string(), stderr.to_string(), None))
                } else {
                    Err(anyhow!("Package removal failed: {}", stderr))
                }
            },
            _ => Err(anyhow!("Unsupported OS for package removal")),
        }
    }
    
    /// Update a package
    async fn update_package(&self, package: &str) -> Result<(String, String, Option<serde_json::Value>)> {
        // Validate package name
        if package.contains("&") || package.contains("|") || package.contains(";") || package.contains("$") {
            return Err(anyhow!("Invalid package name"));
        }
        
        match self.os_info.os_type {
            OsType::Windows => {
                let output = Command::new("winget")
                    .args(&["upgrade", package])
                    .output()
                    .context("Failed to update package")?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                if output.status.success() {
                    Ok((stdout.to_string(), stderr.to_string(), None))
                } else {
                    Err(anyhow!("Package update failed: {}", stderr))
                }
            },
            OsType::Linux => {
                let output = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Apt)) {
                    Command::new("apt-get")
                        .args(&["install", "--only-upgrade", "-y", package])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Yum)) {
                    Command::new("yum")
                        .args(&["update", "-y", package])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Dnf)) {
                    Command::new("dnf")
                        .args(&["upgrade", "-y", package])
                        .output()
                } else {
                    return Err(anyhow!("No supported package manager found"));
                };
                
                let output = output.context("Failed to update package")?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                
                if output.status.success() {
                    Ok((stdout.to_string(), stderr.to_string(), None))
                } else {
                    Err(anyhow!("Package update failed: {}", stderr))
                }
            },
            _ => Err(anyhow!("Unsupported OS for package update")),
        }
    }
    
    /// Search for packages
    async fn search_packages(&self, query: &str) -> Result<(String, String, Option<serde_json::Value>)> {
        // Validate query
        if query.contains("&") || query.contains("|") || query.contains(";") || query.contains("$") {
            return Err(anyhow!("Invalid search query"));
        }
        
        match self.os_info.os_type {
            OsType::Windows => {
                let output = Command::new("winget")
                    .args(&["search", query])
                    .output()
                    .context("Failed to search packages")?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok((stdout.to_string(), String::new(), None))
            },
            OsType::Linux => {
                let output = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Apt)) {
                    Command::new("apt-cache")
                        .args(&["search", query])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Yum)) {
                    Command::new("yum")
                        .args(&["search", query])
                        .output()
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Dnf)) {
                    Command::new("dnf")
                        .args(&["search", query])
                        .output()
                } else {
                    return Err(anyhow!("No supported package manager found"));
                };
                
                let output = output.context("Failed to search packages")?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok((stdout.to_string(), String::new(), None))
            },
            _ => Err(anyhow!("Unsupported OS for package search")),
        }
    }
    
    /// List running processes
    async fn list_processes(&self, limit: Option<usize>) -> Result<(String, String, Option<serde_json::Value>)> {
        use sysinfo::System;
        
        let mut system = System::new();
        system.refresh_all();
        
        let mut processes: Vec<serde_json::Value> = system.processes()
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
        
        let data = json!(processes);
        Ok((
            format!("Found {} processes", processes.len()),
            String::new(),
            Some(data),
        ))
    }
    
    /// Kill a process
    async fn kill_process(&self, pid: u32, force: Option<bool>) -> Result<(String, String, Option<serde_json::Value>)> {
        use sysinfo::{System, Pid};
        
        let mut system = System::new();
        system.refresh_all();
        
        let pid_struct = Pid::from_u32(pid);
        
        if let Some(process) = system.process(pid_struct) {
            // Check if it's a system process (basic protection)
            let name = process.name().to_string_lossy().to_string().to_lowercase();
            if !force.unwrap_or(false) && (
                name.contains("system") || 
                name.contains("kernel") ||
                name.contains("init") ||
                name.contains("systemd") ||
                name.contains("services") ||
                name.contains("svchost")
            ) {
                return Err(anyhow!("Cannot kill system process {} ({}). Use force=true to override", pid, name));
            }
            
            if process.kill_with(sysinfo::Signal::Term).unwrap_or(false) {
                Ok((
                    format!("Process {} killed successfully", pid),
                    String::new(),
                    None,
                ))
            } else {
                Err(anyhow!("Failed to kill process {}", pid))
            }
        } else {
            Err(anyhow!("Process {} not found", pid))
        }
    }
    
    /// Get top processes by CPU or memory usage
    async fn get_top_processes(&self, limit: Option<usize>, sort_by: Option<&str>) -> Result<(String, String, Option<serde_json::Value>)> {
        use sysinfo::System;
        
        let mut system = System::new();
        system.refresh_all();
        
        let mut processes: Vec<_> = system.processes()
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
        
        // Sort by specified criteria
        match sort_by {
            Some("memory") | Some("mem") => {
                processes.sort_by(|a, b| b.3.cmp(&a.3));
            },
            _ => {
                // Default to CPU usage
                processes.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
            }
        }
        
        // Apply limit
        let limit = limit.unwrap_or(10);
        processes.truncate(limit);
        
        let data: Vec<serde_json::Value> = processes
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
}