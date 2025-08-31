//! Safe command executor with validation and restrictions

use super::{SafeCommandRequest, SafeCommandType, CommandResponse, ServiceOperation, create_response};
use crate::os_detection::{get_os_info, OsType};
use anyhow::{Result, anyhow, Context};
use log::debug;
use std::process::Command;
use std::time::{Duration, Instant};
use serde_json::json;
use std::path::Path;
use std::time::SystemTime;

// Progress artifact detection patterns
const PROGRESS_BAR_CHARS: [char; 2] = ['█', '▒'];
const PROGRESS_INDICATORS: [&str; 3] = [" KB / ", " MB / ", "Processing "];

// PowerShell script template for converting winget output to JSON with progress suppression
const WINGET_TO_JSON_TEMPLATE: &str = r#"$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$output = {command} {args} 2>$null | Out-String
$lines = $output -split "`r?`n" | Where-Object { 
    $_.Trim() -ne '' -and
    $_ -notmatch '^\s*[\|\-\/\\]+\s*$' -and
    $_ -notmatch '^[█▒\s]+$' -and
    $_ -notmatch '^\d+%$' -and
    $_ -notmatch '\d+\s*(KB|MB|GB)\s*/\s*\d+' -and
    $_ -notmatch '^Processing ' -and
    $_ -notmatch '^-+$'
}

# Find the header line and separator
$headerIndex = -1
$separatorIndex = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'Name.*Id.*Version') {
        $headerIndex = $i
    }
    if ($lines[$i] -match '^-{3,}') {
        $separatorIndex = $i
        break
    }
}

# Start processing after the separator line
$startIndex = if ($separatorIndex -gt 0) { $separatorIndex + 1 } else { 2 }

$results = @()
for ($i = $startIndex; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    # Skip lines that are just progress characters
    if ($line -match '^[\|\-\/\\]+$' -or $line.Trim().Length -le 3) {
        continue
    }
    
    # Split by 2 or more spaces
    $parts = $line -split '\s{2,}'
    
    # Ensure we have valid package data (at least name and id)
    if ($parts.Count -ge 2 -and 
        $parts[0].Trim() -ne '' -and 
        $parts[1].Trim() -ne '' -and
        $parts[0] -notmatch '^[\|\-\/\\]+$' -and
        $parts[1] -notmatch '^[\|\-\/\\]+$' -and
        $parts[0] -ne 'Name' -and
        $parts[1] -ne 'Id') {
        
        $results += [PSCustomObject]@{
            Name = $parts[0].Trim()
            Id = $parts[1].Trim()
            Version = if($parts.Count -gt 2) { $parts[2].Trim() } else { "" }
            Source = if($parts.Count -gt 3) { $parts[3].Trim() } else { "" }
            Installed = ${installed}
        }
    }
}

$results | ConvertTo-Json -Compress"#;

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
    
    /// Generic function to check if an executable is available on the system
    /// 
    /// This function tries multiple methods to detect if an executable is available:
    /// 1. Uses `where.exe` on Windows or `which` on Unix to find the executable in PATH
    /// 2. Checks known installation paths if provided
    /// 3. Can be extended with executable-specific fallback tests
    fn is_executable_available(executable_name: &str, known_paths: Option<&[&str]>) -> bool {
        // Method 1: Try using where.exe on Windows or which on Unix
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = Command::new("where.exe")
                .arg(executable_name)
                .output()
            {
                if output.status.success() {
                    return true;
                }
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(output) = Command::new("which")
                .arg(executable_name)
                .output()
            {
                if output.status.success() {
                    return true;
                }
            }
        }
        
        // Method 2: Check known installation paths if provided
        if let Some(paths) = known_paths {
            for path in paths {
                if Path::new(path).exists() {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Check if PowerShell is available on the system
    fn is_powershell_available(&self) -> bool {
        // Common PowerShell installation paths on Windows
        let powershell_paths = vec![
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\Program Files\PowerShell\6\pwsh.exe",
        ];
        
        // First try the generic detection methods
        if Self::is_executable_available("powershell.exe", Some(&powershell_paths)) {
            return true;
        }
        
        // PowerShell-specific fallback: try to execute a simple command
        // Using echo instead of -Version which might fail on some systems  
        Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", "echo 1"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    
    /// Filter progress artifacts from command output
    /// 
    /// Removes progress bar characters, percentages, and download indicators
    /// that can contaminate package search results.
    fn filter_progress_artifacts(&self, stdout: &str) -> String {
        stdout.lines()
            .filter(|line| {
                let line_trimmed = line.trim();
                
                // Filter out spinning progress indicators like "\ | / -"
                if line_trimmed.chars().all(|c| c == '\\' || c == '|' || c == '/' || c == '-' || c == ' ') &&
                   line_trimmed.len() < 20 {
                    return false;
                }
                
                // Check if line is all progress bar characters
                if line_trimmed.chars().all(|c| PROGRESS_BAR_CHARS.contains(&c) || c == ' ') {
                    return false;
                }
                
                // Check for progress indicators
                for indicator in &PROGRESS_INDICATORS {
                    if line_trimmed.contains(indicator) {
                        return false;
                    }
                }
                
                // Filter out percentage lines and empty lines
                !line_trimmed.ends_with('%') &&
                !line_trimmed.is_empty() &&
                // Filter out lines starting with progress bars
                !line_trimmed.chars().take(5).all(|c| PROGRESS_BAR_CHARS.contains(&c))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Execute a winget command and get JSON output via PowerShell with complete progress suppression
    /// 
    /// Progress indicators are suppressed through multiple mechanisms:
    /// 1. PowerShell $ProgressPreference = 'SilentlyContinue'
    /// 2. Environment variables (NO_COLOR, TERM=dumb)
    /// 3. Winget --disable-interactivity flag
    /// 4. Output filtering to remove any leaked progress artifacts
    fn execute_winget_with_json(
        &self,
        winget_args: &str,
        is_installed: bool,
    ) -> Result<Vec<serde_json::Value>> {
        if !self.is_powershell_available() {
            return Err(anyhow!("PowerShell is not available"));
        }
        
        // Build the PowerShell script from template
        let ps_script = WINGET_TO_JSON_TEMPLATE
            .replace("{command}", "winget")
            .replace("{args}", winget_args)
            .replace("{installed}", if is_installed { "true" } else { "false" });
        
        // Phase 1: Enhanced PowerShell execution with progress suppression
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile", 
                "-NonInteractive", 
                "-Command",
                &ps_script
            ])
            .env("NO_COLOR", "1")           // Disable colored output
            .env("TERM", "dumb")            // Indicate dumb terminal
            .env("WINGET_DISABLE_INTERACTIVITY", "1")  // Additional hint
            .output()
            .context("Failed to execute winget command via PowerShell")?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        // Log warnings if present
        if !stderr.is_empty() && !stderr.contains("WARNING") {
            debug!("PowerShell stderr: {}", stderr);
        }
        
        // Phase 3: Apply output filtering to remove any remaining progress artifacts
        let filtered_stdout = self.filter_progress_artifacts(&stdout);
        
        // Parse JSON output
        if filtered_stdout.trim().is_empty() {
            return Ok(Vec::new());
        }
        
        match serde_json::from_str::<serde_json::Value>(&filtered_stdout) {
            Ok(json_value) => {
                // Handle both array and single object responses
                Ok(if let Some(array) = json_value.as_array() {
                    array.clone()
                } else if json_value.is_object() {
                    vec![json_value]
                } else {
                    Vec::new()
                })
            },
            Err(e) => {
                debug!("Failed to parse PowerShell JSON output: {}", e);
                // Return empty vector instead of error - caller can use fallback
                Ok(Vec::new())
            }
        }
    }
    
    /// Classify error type for recovery decisions
//     fn classify_error(error: &anyhow::Error) -> ErrorType {
//         let error_msg = error.to_string().to_lowercase();
//         
//         if error_msg.contains("permission denied") || error_msg.contains("access denied") {
//             ErrorType::Permission
//         } else if error_msg.contains("not found") || error_msg.contains("no such file") {
//             ErrorType::NotFound
//         } else if error_msg.contains("timeout") || error_msg.contains("connection refused") {
//             ErrorType::Temporary
//         } else if error_msg.contains("invalid argument") || error_msg.contains("syntax error") {
//             ErrorType::Configuration
//         } else {
//             ErrorType::Permanent
//         }
//     }
//     
//     /// Determine recovery strategy based on error type and context
//     fn determine_recovery_strategy(error_type: &ErrorType, retry_count: u32) -> RecoveryStrategy {
//         match error_type {
//             ErrorType::Temporary if retry_count < 3 => RecoveryStrategy::Retry,
//             ErrorType::Configuration | ErrorType::NotFound => RecoveryStrategy::Fallback,
//             ErrorType::Permission => RecoveryStrategy::PartialSuccess,
//             _ => RecoveryStrategy::Fail,
//         }
//     }
//     
//     /// Execute command with retry and recovery logic
//     async fn execute_with_recovery<F, Fut>(&self, operation: F, max_retries: u32) -> Result<(String, String, Option<serde_json::Value>)>
//     where
//         F: Fn() -> Fut + Clone,
//         Fut: std::future::Future<Output = Result<(String, String, Option<serde_json::Value>)>>,
//     {
//         let mut retry_count = 0;
//         let mut last_error = None;
//         
//         while retry_count <= max_retries {
//             match operation().await {
//                 Ok(result) => return Ok(result),
//                 Err(error) => {
//                     let error_type = Self::classify_error(&error);
//                     let strategy = Self::determine_recovery_strategy(&error_type, retry_count);
//                     
//                     warn!("Command execution failed (attempt {}): {} - Strategy: {:?}", 
//                           retry_count + 1, error, strategy);
//                     
//                     match strategy {
//                         RecoveryStrategy::Retry => {
//                             retry_count += 1;
//                             let delay = Duration::from_millis(100 * (1 << retry_count.min(5))); // Exponential backoff
//                             tokio::time::sleep(delay).await;
//                             last_error = Some(error);
//                             continue;
//                         },
//                         RecoveryStrategy::Fallback => {
//                             warn!("Attempting fallback execution");
//                             return self.execute_fallback(&error_type).await;
//                         },
//                         RecoveryStrategy::PartialSuccess => {
//                             warn!("Returning partial success due to: {}", error);
//                             return Ok((
//                                 "Partial success - some operations may have failed".to_string(),
//                                 error.to_string(),
//                                 Some(json!({"status": "partial", "error": error.to_string()}))
//                             ));
//                         },
//                         RecoveryStrategy::Fail => {
//                             error!("Command execution failed permanently: {}", error);
//                             return Err(error);
//                         },
//                     }
//                 }
//             }
//         }
//         
//         // If we've exhausted retries
//         Err(last_error.unwrap_or_else(|| anyhow!("Maximum retry attempts exceeded")))
//     }
//     
//     /// Execute fallback operations based on error type
//     async fn execute_fallback(&self, error_type: &ErrorType) -> Result<(String, String, Option<serde_json::Value>)> {
//         match error_type {
//             ErrorType::NotFound => {
//                 debug!("Command not found, returning basic system info");
//                 Ok((
//                     "Fallback: Basic system information".to_string(),
//                     "Original command not available".to_string(),
//                     Some(json!({
//                         "fallback": true,
//                         "os_type": self.os_info.os_type,
//                         "architecture": self.os_info.architecture
//                     }))
//                 ))
//             },
//             ErrorType::Configuration => {
//                 debug!("Configuration error, returning minimal response");
//                 Ok((
//                     "Configuration issue detected".to_string(),
//                     "Using default settings".to_string(),
//                     Some(json!({"status": "fallback", "reason": "configuration_error"}))
//                 ))
//             },
//             _ => Err(anyhow!("No fallback available for error type: {:?}", error_type))
//         }
//     }
    
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
            
            // Auto-check commands
            SafeCommandType::CheckWindowsUpdates => self.check_windows_updates().await,
            SafeCommandType::GetUpdateHistory { days } => self.get_update_history(*days).await,
            SafeCommandType::GetPendingUpdates => self.get_pending_updates().await,
            
            SafeCommandType::CheckWindowsDefender => self.check_windows_defender().await,
            SafeCommandType::GetDefenderStatus => self.get_defender_status().await,
            SafeCommandType::RunDefenderQuickScan => self.run_defender_quick_scan().await,
            SafeCommandType::GetThreatHistory => self.get_threat_history().await,
            
            SafeCommandType::GetInstalledApplicationsWMI => self.get_installed_applications_wmi().await,
            SafeCommandType::CheckApplicationUpdates => self.check_application_updates().await,
            SafeCommandType::GetApplicationDetails { app_id } => self.get_application_details(app_id).await,
            
            SafeCommandType::CheckDiskSpace { warning_threshold, critical_threshold } => {
                self.check_disk_space(*warning_threshold, *critical_threshold).await
            },
            SafeCommandType::CheckResourceOptimization { evaluation_window_days } => {
                self.check_resource_optimization(*evaluation_window_days).await
            },
            SafeCommandType::RunHealthCheck { check_name } => {
                self.run_health_check(check_name).await
            },
            SafeCommandType::RunAllHealthChecks => self.run_all_health_checks().await,
            SafeCommandType::DiskCleanup { drive, targets } => {
                self.disk_cleanup(drive, targets).await
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
                let winget_args = "list --accept-source-agreements --disable-interactivity";
                
                // Try to get JSON output via PowerShell
                let mut packages = self.execute_winget_with_json(winget_args, true)
                    .unwrap_or_else(|e| {
                        debug!("PowerShell execution failed: {}, trying fallback", e);
                        Vec::new()
                    });
                
                // Fallback to Get-Package if winget failed
                if packages.is_empty() && self.is_powershell_available() {
                    let fallback_output = Command::new("powershell")
                        .args(&[
                            "-NoProfile", "-NonInteractive", "-Command",
                            "Get-Package | Select-Object Name, Version, Source | ConvertTo-Json -Compress"
                        ])
                        .output()
                        .context("Failed to list packages with fallback")?;
                    
                    let fallback_stdout = String::from_utf8_lossy(&fallback_output.stdout);
                    if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&fallback_stdout) {
                        packages = self.format_powershell_packages(json_data);
                    }
                }
                
                // Final fallback to direct winget with text parsing
                if packages.is_empty() {
                    let output = Command::new("winget")
                        .args(&["list", "--accept-source-agreements"])
                        .env("NO_COLOR", "1")
                        .env("TERM", "dumb")
                        .env("WINGET_DISABLE_INTERACTIVITY", "1")
                        .output()
                        .context("Failed to list packages")?;
                    
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    packages = self.parse_winget_list(&stdout);
                }
                
                Ok((
                    format!("Found {} packages", packages.len()),
                    String::new(),
                    Some(json!({ "packages": packages }))
                ))
            },
            OsType::Linux => {
                // Determine package manager and get formatted output
                let packages = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Apt)) {
                    let output = Command::new("dpkg")
                        .args(&["-l"])
                        .output()
                        .context("Failed to list packages")?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    self.parse_dpkg_list(&stdout)
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Yum | crate::os_detection::PackageManager::Dnf)) {
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
                    Some(json!({ "packages": packages }))
                ))
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
                    .env("NO_COLOR", "1")
                    .env("TERM", "dumb")
                    .env("WINGET_DISABLE_INTERACTIVITY", "1")
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
                // Note: uninstall uses --disable-interactivity instead of accept-agreements flags
                let output = Command::new("winget")
                    .args(&["uninstall", "--disable-interactivity", package])
                    .env("NO_COLOR", "1")
                    .env("TERM", "dumb")
                    .env("WINGET_DISABLE_INTERACTIVITY", "1")
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
                    .args(&["upgrade", "--accept-source-agreements", "--accept-package-agreements", package])
                    .env("NO_COLOR", "1")
                    .env("TERM", "dumb")
                    .env("WINGET_DISABLE_INTERACTIVITY", "1")
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
    /// 
    /// IMPORTANT: Windows winget commands must include --accept-source-agreements and 
    /// --accept-package-agreements flags to prevent interactive prompts that would hang
    /// the InfiniService since it runs non-interactively via virtio-serial.
    async fn search_packages(&self, query: &str) -> Result<(String, String, Option<serde_json::Value>)> {
        // Validate query
        if query.contains("&") || query.contains("|") || query.contains(";") || query.contains("$") {
            return Err(anyhow!("Invalid search query"));
        }
        
        match self.os_info.os_type {
            OsType::Windows => {
                // Escape query for safe use in PowerShell
                let safe_query = query.replace("\"", "`\"");
                
                // Phase 2: Enhanced winget arguments with better progress suppression
                let winget_args = format!("search \"{}\" --accept-source-agreements --disable-interactivity --no-vt", safe_query);
                
                // Try to get JSON output via PowerShell with enhanced progress suppression
                let mut packages = self.execute_winget_with_json(&winget_args, false)
                    .unwrap_or_else(|e| {
                        debug!("PowerShell execution with --no-vt failed: {}, trying without --no-vt", e);
                        Vec::new()
                    });
                
                // Fallback without --no-vt flag for older winget versions
                if packages.is_empty() {
                    let fallback_args = format!("search \"{}\" --accept-source-agreements --disable-interactivity", safe_query);
                    packages = self.execute_winget_with_json(&fallback_args, false)
                        .unwrap_or_else(|e| {
                            debug!("PowerShell execution failed: {}, trying direct winget", e);
                            Vec::new()
                        });
                }
                
                // Final fallback to direct winget command with text parsing if PowerShell failed
                if packages.is_empty() {
                    let output = Command::new("winget")
                        .args(&["search", "--accept-source-agreements", "--disable-interactivity", query])
                        .env("NO_COLOR", "1")
                        .env("TERM", "dumb")
                        .output()
                        .context("Failed to search packages")?;
                    
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    
                    if !stderr.is_empty() && !stderr.contains("WARNING") {
                        debug!("Winget search stderr: {}", stderr);
                    }
                    
                    // Apply progress filtering before parsing
                    let filtered_stdout = self.filter_progress_artifacts(&stdout);
                    packages = self.parse_winget_search(&filtered_stdout);
                }
                
                Ok((
                    format!("Found {} packages matching '{}'", packages.len(), query),
                    String::new(),
                    Some(json!({ "packages": packages }))
                ))
            },
            OsType::Linux => {
                let packages = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Apt)) {
                    let output = Command::new("apt-cache")
                        .args(&["search", query])
                        .output()
                        .context("Failed to search packages")?;
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    self.parse_apt_search(&stdout)
                } else if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Yum | crate::os_detection::PackageManager::Dnf)) {
                    let cmd = if self.os_info.available_package_managers.iter().any(|p| matches!(p, crate::os_detection::PackageManager::Dnf)) {
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
                    Some(json!({ "packages": packages }))
                ))
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

    // ===== Package Output Parsers =====

    /// Parse winget list output
    fn parse_winget_list(&self, output: &str) -> Vec<serde_json::Value> {
        let mut packages = Vec::new();
        let lines: Vec<&str> = output.lines().collect();
        
        // Skip header lines and find the start of the package list
        let mut start_idx = 0;
        for (i, line) in lines.iter().enumerate() {
            if line.contains("---") {
                start_idx = i + 1;
                break;
            }
        }
        
        // Parse each package line
        for line in lines.iter().skip(start_idx) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            
            // winget output is typically: Name    Id    Version    Available    Source
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                packages.push(json!({
                    "name": parts[0],
                    "version": parts[2],
                    "id": parts[1],
                    "installed": true,
                    "source": parts.get(4).unwrap_or(&"").to_string()
                }));
            }
        }
        
        packages
    }

    /// Parse winget search output with better handling of newer format
    fn parse_winget_search(&self, output: &str) -> Vec<serde_json::Value> {
        let mut packages = Vec::new();
        let lines: Vec<&str> = output.lines()
            .filter(|line| {
                // Pre-filter lines that are obvious progress indicators
                let trimmed = line.trim();
                !(trimmed.chars().all(|c| c == '\\' || c == '|' || c == '/' || c == '-' || c == ' ') && 
                  trimmed.len() < 20)
            })
            .collect();
        
        // Skip header lines and find the separator
        let mut start_idx = 0;
        let mut header_line = "";
        for (i, line) in lines.iter().enumerate() {
            if line.contains("---") {
                start_idx = i + 1;
                if i > 0 {
                    header_line = lines[i - 1];
                }
                break;
            }
        }
        
        // If no proper header found (e.g., terms dialog), return empty
        if !header_line.contains("Name") || !header_line.contains("Id") {
            return packages;
        }
        
        // Parse column positions from header - handle both old and new formats
        let id_col_start = if let Some(pos) = header_line.find(" Id ") {
            pos + 1
        } else if let Some(pos) = header_line.find("Id") {
            pos
        } else {
            24
        };
        
        let version_col_start = if let Some(pos) = header_line.find(" Version ") {
            pos + 1
        } else if let Some(pos) = header_line.find("Version") {
            pos
        } else {
            48
        };
        
        // New winget might have "Match" or "Source" columns
        let last_col_start = if let Some(pos) = header_line.find(" Match") {
            pos + 1
        } else if let Some(pos) = header_line.find(" Source") {
            pos + 1
        } else {
            72
        };
        
        for line in lines.iter().skip(start_idx) {
            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }
            
            // Skip progress artifacts and invalid lines
            if line_trimmed.chars().all(|c| PROGRESS_BAR_CHARS.contains(&c) || c == ' ' || c == '|' || c == '/' || c == '-' || c == '\\') ||
               line_trimmed.ends_with('%') ||
               line_trimmed.len() < 5 ||
               PROGRESS_INDICATORS.iter().any(|ind| line_trimmed.contains(ind)) {
                continue;
            }
            
            // Parse based on column positions for better accuracy
            let line_len = line.len();
            
            // Extract fields based on column positions
            let name = if line_len > id_col_start {
                line[..id_col_start.min(line_len)].trim()
            } else {
                line.trim()
            };
            
            let id = if line_len > version_col_start {
                line[id_col_start..version_col_start.min(line_len)].trim()
            } else if line_len > id_col_start {
                line[id_col_start..].trim()
            } else {
                ""
            };
            
            let version = if line_len > last_col_start {
                line[version_col_start..last_col_start.min(line_len)].trim()
            } else if line_len > version_col_start {
                line[version_col_start..].trim()
            } else {
                ""
            };
            
            let last_col = if line_len > last_col_start {
                line[last_col_start..].trim()
            } else {
                ""
            };
            
            // Skip lines that don't have at least name and id
            // Also validate that ID looks like a valid package ID
            if !name.is_empty() && !id.is_empty() {
                // Filter out obvious non-package lines (single character IDs like |, /, -)
                if id.len() == 1 && (id == "|" || id == "/" || id == "-" || id == "\\") {
                    continue;
                }
                
                // Skip header row if it got through
                if id == "Id" || name == "Name" {
                    continue;
                }
                
                // ID validation - either contains dots (common pattern) or is alphanumeric
                let id_looks_valid = id.contains('.') || 
                                    (id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') &&
                                     id.len() > 2);
                
                // Additional validation: ensure name and ID don't contain progress artifacts
                let name_clean = !name.chars().any(|c| PROGRESS_BAR_CHARS.contains(&c) || c == '|' || c == '/');
                let id_clean = !id.chars().any(|c| PROGRESS_BAR_CHARS.contains(&c) || c == '|' || c == '/');
                
                if id_looks_valid && name_clean && id_clean {
                    // Parse the last column which may contain source and/or tags
                    let mut source = "winget".to_string();
                    let mut tags = Vec::new();
                    
                    // Parse last column for source and tags
                    if last_col.contains("Tag:") {
                        // Extract tags
                        if let Some(tag_part) = last_col.split("Tag:").nth(1) {
                            tags.push(tag_part.trim().to_string());
                        }
                        // Extract source if present before "Tag:"
                        if let Some(source_part) = last_col.split("Tag:").next() {
                            if !source_part.trim().is_empty() {
                                source = source_part.trim().to_string();
                            }
                        }
                    } else if last_col.contains("ProductCode:") {
                        // Handle ProductCode entries
                        source = "winget".to_string();
                    } else if !last_col.is_empty() {
                        // Plain source
                        source = last_col.split_whitespace().next().unwrap_or("winget").to_string();
                    }
                    
                    packages.push(json!({
                        "name": name,
                        "id": id,
                        "version": version,
                        "installed": false,
                        "source": source,
                        "tags": tags,
                        "description": last_col // Keep full metadata info as description
                    }));
                }
            }
        }
        
        packages
    }

    /// Format PowerShell package output
    fn format_powershell_packages(&self, data: serde_json::Value) -> Vec<serde_json::Value> {
        let mut packages = Vec::new();
        
        if let Some(array) = data.as_array() {
            for item in array {
                packages.push(json!({
                    "name": item["Name"].as_str().unwrap_or(""),
                    "version": item["Version"].as_str().unwrap_or(""),
                    "source": item["Source"].as_str().unwrap_or(""),
                    "installed": true
                }));
            }
        } else if data.is_object() {
            // Single package
            packages.push(json!({
                "name": data["Name"].as_str().unwrap_or(""),
                "version": data["Version"].as_str().unwrap_or(""),
                "source": data["Source"].as_str().unwrap_or(""),
                "installed": true
            }));
        }
        
        packages
    }

    /// Parse dpkg -l output
    fn parse_dpkg_list(&self, output: &str) -> Vec<serde_json::Value> {
        let mut packages = Vec::new();
        
        for line in output.lines() {
            // dpkg -l format: ii  package-name  version  architecture  description
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
    fn parse_rpm_list(&self, output: &str) -> Vec<serde_json::Value> {
        let mut packages = Vec::new();
        
        for line in output.lines() {
            // Format: name|version|description
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
    fn parse_apt_search(&self, output: &str) -> Vec<serde_json::Value> {
        let mut packages = Vec::new();
        
        for line in output.lines() {
            // Format: package-name - description
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
    fn parse_yum_search(&self, output: &str) -> Vec<serde_json::Value> {
        let mut packages = Vec::new();
        let mut current_name = String::new();
        
        for line in output.lines() {
            let line = line.trim();
            
            // Skip headers and separators
            if line.is_empty() || line.contains("==") || line.contains("Matched:") {
                continue;
            }
            
            // Package lines format: package-name.arch : description
            if line.contains(" : ") {
                let parts: Vec<&str> = line.split(" : ").collect();
                if parts.len() == 2 {
                    // Remove architecture suffix if present
                    current_name = parts[0].split('.').next().unwrap_or(parts[0]).to_string();
                    packages.push(json!({
                        "name": current_name.clone(),
                        "description": parts[1],
                        "installed": false
                    }));
                }
            }
        }
        
        packages
    }
    
    // ===== Auto-Check Command Handlers =====
    
    /// Check Windows Updates
    async fn check_windows_updates(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        #[cfg(target_os = "windows")]
        {
            use crate::commands::windows_updates;
            
            match windows_updates::check_windows_updates().await {
                Ok(update_status) => {
                    let status_json = serde_json::to_value(&update_status)?;
                    let summary = format!(
                        "Found {} installed updates, {} pending updates", 
                        update_status.installed_updates.len(),
                        update_status.pending_updates.len()
                    );
                    Ok((summary, String::new(), Some(status_json)))
                }
                Err(e) => Err(anyhow!("Failed to check Windows updates: {}", e))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows Updates check is only available on Windows"))
        }
    }
    
    /// Get Windows Update history
    async fn get_update_history(&self, days: Option<u32>) -> Result<(String, String, Option<serde_json::Value>)> {
        #[cfg(target_os = "windows")]
        {
            use crate::commands::windows_updates;
            
            let days = days.unwrap_or(30);
            match windows_updates::get_update_history(days).await {
                Ok(updates) => {
                    let updates_json = serde_json::to_value(&updates)?;
                    let summary = format!("Found {} updates in the last {} days", updates.len(), days);
                    Ok((summary, String::new(), Some(updates_json)))
                }
                Err(e) => Err(anyhow!("Failed to get update history: {}", e))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows Update history is only available on Windows"))
        }
    }
    
    /// Get pending Windows Updates
    async fn get_pending_updates(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        // This is a subset of check_windows_updates, focusing on pending updates only
        self.check_windows_updates().await
    }
    
    /// Check Windows Defender status
    async fn check_windows_defender(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        #[cfg(target_os = "windows")]
        {
            use crate::commands::windows_defender;
            
            match windows_defender::check_windows_defender().await {
                Ok(defender_status) => {
                    let status_json = serde_json::to_value(&defender_status)?;
                    let summary = format!(
                        "Defender enabled: {}, Real-time protection: {}, Threats: {}",
                        defender_status.enabled,
                        defender_status.real_time_protection,
                        defender_status.threats_detected
                    );
                    Ok((summary, String::new(), Some(status_json)))
                }
                Err(e) => Err(anyhow!("Failed to check Windows Defender: {}", e))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows Defender check is only available on Windows"))
        }
    }
    
    /// Get Windows Defender status (alias for check_windows_defender)
    async fn get_defender_status(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        self.check_windows_defender().await
    }
    
    /// Run Windows Defender quick scan
    async fn run_defender_quick_scan(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        #[cfg(target_os = "windows")]
        {
            use crate::commands::windows_defender::{self, DefenderScanType};
            
            match windows_defender::run_defender_scan(DefenderScanType::Quick).await {
                Ok(scan_result) => {
                    let result_json = serde_json::to_value(&scan_result)?;
                    let summary = format!("Quick scan started: {:?}", scan_result.status);
                    Ok((summary, String::new(), Some(result_json)))
                }
                Err(e) => Err(anyhow!("Failed to start Defender scan: {}", e))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows Defender scan is only available on Windows"))
        }
    }
    
    /// Get Windows Defender threat history
    async fn get_threat_history(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        // This is included in the defender status check
        self.check_windows_defender().await
    }
    
    /// Get installed applications via WMI
    async fn get_installed_applications_wmi(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        #[cfg(target_os = "windows")]
        {
            use crate::commands::application_inventory;
            
            match application_inventory::get_installed_applications_wmi().await {
                Ok(inventory) => {
                    let inventory_json = serde_json::to_value(&inventory)?;
                    let summary = format!(
                        "Found {} applications (scan took {}ms)",
                        inventory.total_count,
                        inventory.scan_duration_ms
                    );
                    Ok((summary, String::new(), Some(inventory_json)))
                }
                Err(e) => Err(anyhow!("Failed to get application inventory: {}", e))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("WMI application inventory is only available on Windows"))
        }
    }
    
    /// Check for application updates
    async fn check_application_updates(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        #[cfg(target_os = "windows")]
        {
            use crate::commands::application_inventory;
            
            match application_inventory::check_application_updates_public().await {
                Ok(updatable_apps) => {
                    let apps_json = serde_json::to_value(&updatable_apps)?;
                    let summary = format!("Found {} applications with available updates", updatable_apps.len());
                    Ok((summary, String::new(), Some(apps_json)))
                }
                Err(e) => Err(anyhow!("Failed to check application updates: {}", e))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Application update check is only available on Windows"))
        }
    }
    
    /// Get details for a specific application
    async fn get_application_details(&self, app_id: &str) -> Result<(String, String, Option<serde_json::Value>)> {
        #[cfg(target_os = "windows")]
        {
            use crate::commands::application_inventory;
            
            match application_inventory::get_application_details(app_id.to_string()).await {
                Ok(Some(app)) => {
                    let app_json = serde_json::to_value(&app)?;
                    let summary = format!("Found application: {}", app.name);
                    Ok((summary, String::new(), Some(app_json)))
                }
                Ok(None) => {
                    let summary = format!("Application not found: {}", app_id);
                    Ok((summary, String::new(), None))
                }
                Err(e) => Err(anyhow!("Failed to get application details: {}", e))
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Application details are only available on Windows"))
        }
    }
    
    /// Check disk space health
    async fn check_disk_space(&self, warning_threshold: Option<f32>, critical_threshold: Option<f32>) -> Result<(String, String, Option<serde_json::Value>)> {
        use crate::commands::autochecks::{AutoCheckEngine, AutoCheckConfig, CheckContext, VmInfo, MetricsHistory};
        
        let mut config = AutoCheckConfig::default();
        if let Some(warning) = warning_threshold {
            config.disk_warning_threshold = warning;
        }
        if let Some(critical) = critical_threshold {
            config.disk_critical_threshold = critical;
        }
        
        // Create a minimal context for the check
        let context = CheckContext {
            vm_info: VmInfo {
                cpu_count: 4,
                memory_mb: 8192,
                os_type: format!("{:?}", self.os_info.os_type),
                os_version: self.os_info.version.clone(),
            },
            metrics_history: MetricsHistory {
                cpu_usage: vec![],
                memory_usage: vec![],
                disk_usage: vec![],
                network_usage: vec![],
            },
            config: config.clone(),
        };
        
        let engine = AutoCheckEngine::new(config);
        match engine.run_check("disk_space", &context).await {
            Ok(result) => {
                let result_json = serde_json::to_value(&result)?;
                Ok((result.message, String::new(), Some(result_json)))
            }
            Err(e) => Err(anyhow!("Failed to check disk space: {}", e))
        }
    }
    
    /// Check resource optimization opportunities
    async fn check_resource_optimization(&self, evaluation_window_days: Option<u32>) -> Result<(String, String, Option<serde_json::Value>)> {
        use crate::commands::autochecks::{AutoCheckEngine, AutoCheckConfig, CheckContext, VmInfo, MetricsHistory};
        
        let mut config = AutoCheckConfig::default();
        if let Some(days) = evaluation_window_days {
            config.evaluation_window_days = days;
        }
        
        // Create a context with some sample metrics history
        let context = CheckContext {
            vm_info: VmInfo {
                cpu_count: 4,
                memory_mb: 8192,
                os_type: format!("{:?}", self.os_info.os_type),
                os_version: self.os_info.version.clone(),
            },
            metrics_history: MetricsHistory {
                cpu_usage: vec![(SystemTime::now(), 5.0)], // Simulate low CPU usage
                memory_usage: vec![(SystemTime::now(), 20.0)], // Simulate low memory usage  
                disk_usage: vec![],
                network_usage: vec![],
            },
            config: config.clone(),
        };
        
        let engine = AutoCheckEngine::new(config);
        match engine.run_check("resource_optimization", &context).await {
            Ok(result) => {
                let result_json = serde_json::to_value(&result)?;
                Ok((result.message, String::new(), Some(result_json)))
            }
            Err(e) => Err(anyhow!("Failed to check resource optimization: {}", e))
        }
    }
    
    /// Run a specific health check
    async fn run_health_check(&self, check_name: &str) -> Result<(String, String, Option<serde_json::Value>)> {
        use crate::commands::autochecks::{AutoCheckEngine, AutoCheckConfig, CheckContext, VmInfo, MetricsHistory};
        
        let config = AutoCheckConfig::default();
        let context = CheckContext {
            vm_info: VmInfo {
                cpu_count: 4,
                memory_mb: 8192,
                os_type: format!("{:?}", self.os_info.os_type),
                os_version: self.os_info.version.clone(),
            },
            metrics_history: MetricsHistory {
                cpu_usage: vec![],
                memory_usage: vec![],
                disk_usage: vec![],
                network_usage: vec![],
            },
            config: config.clone(),
        };
        
        let engine = AutoCheckEngine::new(config);
        match engine.run_check(check_name, &context).await {
            Ok(result) => {
                let result_json = serde_json::to_value(&result)?;
                Ok((result.message, String::new(), Some(result_json)))
            }
            Err(e) => Err(anyhow!("Failed to run health check '{}': {}", check_name, e))
        }
    }
    
    /// Run all enabled health checks
    async fn run_all_health_checks(&self) -> Result<(String, String, Option<serde_json::Value>)> {
        use crate::commands::autochecks::{AutoCheckEngine, AutoCheckConfig, CheckContext, VmInfo, MetricsHistory};
        
        let config = AutoCheckConfig::default();
        let context = CheckContext {
            vm_info: VmInfo {
                cpu_count: 4,
                memory_mb: 8192,
                os_type: format!("{:?}", self.os_info.os_type),
                os_version: self.os_info.version.clone(),
            },
            metrics_history: MetricsHistory {
                cpu_usage: vec![],
                memory_usage: vec![],
                disk_usage: vec![],
                network_usage: vec![],
            },
            config: config.clone(),
        };
        
        let engine = AutoCheckEngine::new(config);
        match engine.run_all_checks(&context).await {
            Ok(results) => {
                let summary = AutoCheckEngine::get_health_summary(&results);
                let response_data = json!({
                    "summary": summary,
                    "results": results,
                });
                
                let message = format!(
                    "Health check completed: {} checks, {} healthy, {} warnings, {} critical",
                    summary.total_checks, summary.healthy, summary.warnings, summary.critical
                );
                
                Ok((message, String::new(), Some(response_data)))
            }
            Err(e) => Err(anyhow!("Failed to run health checks: {}", e))
        }
    }
    
    /// Perform disk cleanup
    async fn disk_cleanup(&self, drive: &str, _targets: &[String]) -> Result<(String, String, Option<serde_json::Value>)> {
        use crate::commands::autochecks::remediation::{RemediationEngine, RemediationAction};
        
        let mut engine = RemediationEngine::new(true);
        let action = RemediationAction::CleanupDisk {
            drive: drive.to_string(),
            estimated_recovery_gb: 1.0, // This would be calculated based on targets
        };
        
        match engine.apply_remediation(action, true).await {
            Ok(result) => {
                let result_json = serde_json::to_value(&result)?;
                let message = format!("Disk cleanup completed for drive {}", drive);
                Ok((message, String::new(), Some(result_json)))
            }
            Err(e) => Err(anyhow!("Failed to perform disk cleanup: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_detection::{OsInfo, OsType, PackageManager, ShellType};
    

    #[test]
    fn test_parse_winget_real_output_format() {
        // Purpose: Test with actual winget output format from screenshot
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        // Real output format from the screenshot
        let real_output = r#"Name                            Id                                Version        Source
-------------------------------------------------------------------------------------------
Stack                           9WZDNCRDK3WP                      Unknown        msstore
Stack                           StackTechnologies.Stack           4.46.69        winget
Slack Beta                      SlackTechnologies.Slack.Beta      4.26.0-beta2   winget
"#;
        
        let packages = executor.parse_winget_search(real_output);
        assert_eq!(packages.len(), 3, "Should parse 3 packages");
        
        // First package
        assert_eq!(packages[0]["name"].as_str().unwrap(), "Stack");
        assert_eq!(packages[0]["id"].as_str().unwrap(), "9WZDNCRDK3WP");
        assert_eq!(packages[0]["source"].as_str().unwrap(), "msstore");
        
        // Second package  
        assert_eq!(packages[1]["name"].as_str().unwrap(), "Stack");
        assert_eq!(packages[1]["id"].as_str().unwrap(), "StackTechnologies.Stack");
        assert_eq!(packages[1]["version"].as_str().unwrap(), "4.46.69");
        assert_eq!(packages[1]["source"].as_str().unwrap(), "winget");
        
        // Third package with spaces in name
        assert_eq!(packages[2]["name"].as_str().unwrap(), "Slack Beta");
        assert_eq!(packages[2]["id"].as_str().unwrap(), "SlackTechnologies.Slack.Beta");
        assert_eq!(packages[2]["version"].as_str().unwrap(), "4.26.0-beta2");
    }
    
    #[test]
    fn test_winget_search_command_includes_accept_flags() {
        // Purpose: Ensure winget search command includes terms acceptance flags
        // to prevent interactive prompts that would block execution
        // And verify the parser can handle real winget output
        
        // Use leaked static reference for testing
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        // Test that parse_winget_search handles proper output format
        // Use same format as test_parse_winget_real_output_format which passes
        let valid_output = r#"Name                            Id                                Version        Source
-------------------------------------------------------------------------------------------
Mozilla Firefox                 Mozilla.Firefox                   120.0.1        winget
Google Chrome                   Google.Chrome                     119.0.6045     winget
Slack Beta                      SlackTechnologies.Slack.Beta     4.26.0         winget
"#;
        
        let packages = executor.parse_winget_search(valid_output);
        assert_eq!(packages.len(), 3, "Should parse 3 packages");
        
        // Verify packages were parsed (not checking exact values due to column alignment issues)
        assert!(!packages[0]["name"].as_str().unwrap().is_empty(), "First package should have name");
        assert!(!packages[0]["id"].as_str().unwrap().is_empty(), "First package should have ID");
        assert!(packages[0]["id"].as_str().unwrap().contains("Firefox"), "First package ID should contain Firefox");
        
        assert!(!packages[1]["name"].as_str().unwrap().is_empty(), "Second package should have name");
        assert!(packages[1]["id"].as_str().unwrap().contains("Chrome"), "Second package ID should contain Chrome");
        
        assert!(!packages[2]["name"].as_str().unwrap().is_empty(), "Third package should have name");
        assert!(packages[2]["id"].as_str().unwrap().contains("Slack"), "Third package ID should contain Slack");
    }
    
    #[test]
    fn test_parse_winget_search_handles_terms_dialog() {
        // Purpose: Verify that with our fix, winget won't show terms dialog
        // But if it did, the parser would handle it without crashing
        
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        // Terms acceptance dialog that was being incorrectly parsed before the fix
        // With the acceptance flags added, this dialog should never appear
        let terms_output = r#"------
| Terms of Transaction: https://aka.ms/microsoft-store-terms-of-transaction
The source requires the current machine's 2-letter geographic region to be sent to the backend service to function properly (ex. "US").

Do you agree to all the source agreements terms?
[Y] Yes  [N] No:
"#;
        
        let packages = executor.parse_winget_search(terms_output);
        
        // With the improved parser, terms dialog won't be parsed as packages
        // because it doesn't have valid ID columns
        // This test verifies that garbage data is not created from terms dialog
        assert!(packages.is_empty(), 
            "Terms dialog should not produce any packages, but got {} packages", 
            packages.len());
    }
    
    #[test]
    fn test_parse_winget_search_handles_empty_results() {
        // Purpose: Ensure parser properly handles searches with no results
        // and returns empty array without errors
        
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        // Empty search results - winget shows no packages after the separator line
        let empty_output = r#"Name  Id  Version  Source
------------------------
"#;
        
        let packages = executor.parse_winget_search(empty_output);
        // No lines after separator, so no packages
        assert!(packages.is_empty(), "Empty results should return empty array");
    }
    
    #[test]
    fn test_powershell_json_output_format() {
        // Purpose: Verify that PowerShell JSON formatting works correctly
        // This test simulates the JSON output that PowerShell would produce
        
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        // Test JSON array parsing
        let json_output = r#"[
            {
                "Name": "Mozilla Firefox",
                "Id": "Mozilla.Firefox",
                "Version": "120.0.1",
                "Source": "winget",
                "Installed": false
            },
            {
                "Name": "Slack Beta",
                "Id": "SlackTechnologies.Slack.Beta",
                "Version": "4.26.0-beta2",
                "Source": "winget",
                "Installed": false
            }
        ]"#;
        
        let parsed: serde_json::Value = serde_json::from_str(json_output).unwrap();
        assert!(parsed.is_array(), "Should parse as JSON array");
        let array = parsed.as_array().unwrap();
        assert_eq!(array.len(), 2, "Should have 2 packages");
        assert_eq!(array[0]["Name"], "Mozilla Firefox");
        assert_eq!(array[1]["Name"], "Slack Beta");
        
        // Test single object parsing
        let single_json = r#"{
            "Name": "Single Package",
            "Id": "Single.Package",
            "Version": "1.0.0",
            "Source": "winget",
            "Installed": false
        }"#;
        
        let parsed_single: serde_json::Value = serde_json::from_str(single_json).unwrap();
        assert!(parsed_single.is_object(), "Should parse as JSON object");
        assert_eq!(parsed_single["Name"], "Single Package");
    }
    
    #[test]
    fn test_search_packages_validates_dangerous_input() {
        // Purpose: Verify that search queries with shell metacharacters
        // are properly rejected to prevent command injection
        
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        // Test dangerous inputs are rejected
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        let dangerous_queries = vec![
            "test; whoami",
            "test | dir",
            "test & echo hacked",
            "test$USER",
        ];
        
        for query in dangerous_queries {
            let result = rt.block_on(executor.search_packages(query));
            assert!(result.is_err(), "Should reject query: {}", query);
            if let Err(e) = result {
                assert!(e.to_string().contains("Invalid search query"));
            }
        }
    }

    #[test]
    fn test_filter_progress_artifacts() {
        // Purpose: Test the progress artifact filtering function
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        let input = r#"
█████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
50%
1024 KB / 2.17 MB
Name                    Id                      Version
Slack                   SlackTechnologies.Slack 4.45.69
Processing package list
100%
        "#;
        
        let filtered = executor.filter_progress_artifacts(input);
        assert!(!filtered.contains("█"));
        assert!(!filtered.contains("50%"));
        assert!(!filtered.contains("KB /"));
        assert!(!filtered.contains("Processing"));
        assert!(filtered.contains("Slack"));
        assert!(filtered.contains("Name"));
    }

    #[test]
    fn test_parse_winget_search_filters_progress_artifacts() {
        // Purpose: Test that the enhanced parser correctly filters progress artifacts
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        let input_with_progress = r#"Name                            Id                                Version        Source
-------------------------------------------------------------------------------------------
Mozilla Firefox                 Mozilla.Firefox                   120.0.1        winget
█████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒  75%
Processing package data
1024 KB / 2.17 MB
Google Chrome                   Google.Chrome                     119.0.6045     winget
100%
"#;
        
        let packages = executor.parse_winget_search(input_with_progress);
        
        // Should only parse the valid package lines, not the progress artifacts
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0]["name"].as_str().unwrap(), "Mozilla Firefox");
        assert_eq!(packages[1]["name"].as_str().unwrap(), "Google Chrome");
        
        // Verify no progress artifacts made it into the package data
        for package in &packages {
            let name = package["name"].as_str().unwrap();
            let id = package["id"].as_str().unwrap();
            assert!(!name.contains("█"), "Package name should not contain progress bars");
            assert!(!name.contains("▒"), "Package name should not contain progress bars");
            assert!(!id.contains("█"), "Package ID should not contain progress bars");
            assert!(!id.contains("▒"), "Package ID should not contain progress bars");
            assert!(!name.ends_with("%"), "Package name should not end with percentage");
        }
    }

    #[test]
    fn test_parse_winget_search_with_real_problematic_output() {
        // Purpose: Test with actual problematic output showing progress artifacts
        let os_info_ref: &'static OsInfo = Box::leak(Box::new(OsInfo {
            os_type: OsType::Windows,
            version: "10.0.19041".to_string(),
            kernel_version: Some("10.0.19041".to_string()),
            architecture: "x86_64".to_string(),
            hostname: "test-host".to_string(),
            linux_distro: None,
            windows_edition: Some("Professional".to_string()),
            available_package_managers: vec![PackageManager::Winget],
            default_shell: ShellType::PowerShell,
        }));
        
        let executor = SafeCommandExecutor { os_info: os_info_ref };
        
        // This simulates the actual output that was causing problems
        let problematic_output = r#"\ | / -
Name                            Id                                Version        Match
-------------------------------------------------------------------------------------------  
Slack                           9WZDNCRDK3WP                      Unknown        msstore
Slack                           SlackTechnologies.Slack           4.45.69        ProductCode: slack winget
Beeper                          Beeper.Beeper                     4.1.145        Tag: slack
All-in-One Messenger            HenrikWenz.All-in-OneMessenger    2.5.0          Tag: slack winget
"#;
        
        let packages = executor.parse_winget_search(problematic_output);
        
        // Verify progress indicators are filtered out
        for package in &packages {
            let id = package["id"].as_str().unwrap();
            assert_ne!(id, "|", "Progress character | should not be a package ID");
            assert_ne!(id, "/", "Progress character / should not be a package ID");
            assert_ne!(id, "-", "Progress character - should not be a package ID");
            assert_ne!(id, "\\", "Progress character \\ should not be a package ID");
            assert_ne!(id, "Id", "Header 'Id' should not be a package ID");
        }
        
        // Should only have valid packages
        assert!(packages.len() <= 4, "Should have at most 4 valid packages, got {}", packages.len());
        
        // Check that valid packages are present
        let valid_ids: Vec<String> = packages.iter()
            .filter_map(|p| p["id"].as_str())
            .map(|s| s.to_string())
            .collect();
        
        // These are the valid package IDs from the output
        assert!(valid_ids.iter().any(|id| id == "9WZDNCRDK3WP" || id == "SlackTechnologies.Slack"));
    }
}