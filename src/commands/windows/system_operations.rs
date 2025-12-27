//! Windows System Operations implementation
//!
//! This module provides the Windows-specific implementation of `SystemOperations`,
//! encapsulating all Windows system management operations including services,
//! packages, processes, users, updates, security, and health checks.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::commands::traits::{SystemOperationResult, SystemOperations};
use crate::commands::ServiceOperation;
use crate::os_detection::{get_os_info, OsInfo};

// Progress artifact detection patterns
const PROGRESS_BAR_CHARS: [char; 2] = ['█', '▒'];
const PROGRESS_INDICATORS: [&str; 3] = [" KB / ", " MB / ", "Processing "];

// PowerShell script template for converting winget output to JSON
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

$startIndex = if ($separatorIndex -gt 0) { $separatorIndex + 1 } else { 2 }

$results = @()
for ($i = $startIndex; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ($line -match '^[\|\-\/\\]+$' -or $line.Trim().Length -le 3) {
        continue
    }

    $parts = $line -split '\s{2,}'

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

/// Windows system operations implementation
pub struct WindowsSystemOperations {
    os_info: &'static OsInfo,
}

impl WindowsSystemOperations {
    /// Create a new Windows system operations instance
    pub fn new() -> Self {
        Self {
            os_info: get_os_info(),
        }
    }

    /// Check if an executable is available on the system
    fn is_executable_available(executable_name: &str, known_paths: Option<&[&str]>) -> bool {
        if let Ok(output) = Command::new("where.exe").arg(executable_name).output() {
            if output.status.success() {
                return true;
            }
        }

        if let Some(paths) = known_paths {
            for path in paths {
                if Path::new(path).exists() {
                    return true;
                }
            }
        }

        false
    }

    /// Check if PowerShell is available
    fn is_powershell_available(&self) -> bool {
        self.get_powershell_command().is_some()
    }

    /// Get the best available PowerShell executable command
    fn get_powershell_command(&self) -> Option<&'static str> {
        let pwsh_paths = [
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\Program Files\PowerShell\6\pwsh.exe",
        ];

        if Self::is_executable_available("pwsh.exe", Some(&pwsh_paths)) {
            return Some("pwsh.exe");
        }

        let powershell_paths = [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        ];

        if Self::is_executable_available("powershell.exe", Some(&powershell_paths)) {
            return Some("powershell.exe");
        }

        if Command::new("powershell.exe")
            .args(&["-NoProfile", "-NonInteractive", "-Command", "echo 1"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some("powershell.exe");
        }

        None
    }

    /// Validate service/package names for injection attacks
    fn validate_name(name: &str, entity_type: &str) -> Result<()> {
        if name.contains('&')
            || name.contains('|')
            || name.contains(';')
            || name.contains('$')
            || name.contains('`')
            || name.contains('\n')
        {
            return Err(anyhow!(
                "Invalid {} name: contains forbidden characters",
                entity_type
            ));
        }
        Ok(())
    }

    /// Filter progress artifacts from command output
    fn filter_progress_artifacts(&self, stdout: &str) -> String {
        stdout
            .lines()
            .filter(|line| {
                let line_trimmed = line.trim();

                if line_trimmed
                    .chars()
                    .all(|c| c == '\\' || c == '|' || c == '/' || c == '-' || c == ' ')
                    && line_trimmed.len() < 20
                {
                    return false;
                }

                if line_trimmed
                    .chars()
                    .all(|c| PROGRESS_BAR_CHARS.contains(&c) || c == ' ')
                {
                    return false;
                }

                for indicator in &PROGRESS_INDICATORS {
                    if line_trimmed.contains(indicator) {
                        return false;
                    }
                }

                !line_trimmed.ends_with('%')
                    && !line_trimmed.is_empty()
                    && !line_trimmed
                        .chars()
                        .take(5)
                        .all(|c| PROGRESS_BAR_CHARS.contains(&c))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Execute winget command with JSON output via PowerShell
    fn execute_winget_with_json(
        &self,
        winget_args: &str,
        is_installed: bool,
    ) -> Result<Vec<Value>> {
        if !self.is_powershell_available() {
            return Err(anyhow!("PowerShell is not available"));
        }

        let ps_script = WINGET_TO_JSON_TEMPLATE
            .replace("{command}", "winget")
            .replace("{args}", winget_args)
            .replace("{installed}", if is_installed { "true" } else { "false" });

        let output = Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", &ps_script])
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .env("WINGET_DISABLE_INTERACTIVITY", "1")
            .output()
            .context("Failed to execute winget command via PowerShell")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let filtered_stdout = self.filter_progress_artifacts(&stdout);

        if filtered_stdout.trim().is_empty() || filtered_stdout.trim() == "null" {
            return Ok(Vec::new());
        }

        match serde_json::from_str::<Vec<Value>>(&filtered_stdout) {
            Ok(packages) => Ok(packages),
            Err(_) => match serde_json::from_str::<Value>(&filtered_stdout) {
                Ok(single) => Ok(vec![single]),
                Err(_) => Ok(Vec::new()),
            },
        }
    }

    /// Parse winget list output
    fn parse_winget_list(&self, output: &str) -> Vec<Value> {
        let mut packages = Vec::new();
        let lines: Vec<&str> = output.lines().collect();

        let mut start_idx = 0;
        for (i, line) in lines.iter().enumerate() {
            if line.contains("---") {
                start_idx = i + 1;
                break;
            }
        }

        for line in lines.iter().skip(start_idx) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

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

    /// Parse winget search output
    fn parse_winget_search(&self, output: &str) -> Vec<Value> {
        let mut packages = Vec::new();
        let lines: Vec<&str> = output
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !(trimmed
                    .chars()
                    .all(|c| c == '\\' || c == '|' || c == '/' || c == '-' || c == ' ')
                    && trimmed.len() < 20)
            })
            .collect();

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

        if !header_line.contains("Name") || !header_line.contains("Id") {
            return packages;
        }

        let id_col_start = header_line
            .find(" Id ")
            .map(|pos| pos + 1)
            .or_else(|| header_line.find("Id"))
            .unwrap_or(24);

        let version_col_start = header_line
            .find(" Version ")
            .map(|pos| pos + 1)
            .or_else(|| header_line.find("Version"))
            .unwrap_or(48);

        let last_col_start = header_line
            .find(" Match")
            .or_else(|| header_line.find(" Source"))
            .map(|pos| pos + 1)
            .unwrap_or(72);

        for line in lines.iter().skip(start_idx) {
            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }

            if line_trimmed.chars().all(|c| {
                PROGRESS_BAR_CHARS.contains(&c)
                    || c == ' '
                    || c == '|'
                    || c == '/'
                    || c == '-'
                    || c == '\\'
            }) || line_trimmed.ends_with('%')
                || line_trimmed.len() < 5
                || PROGRESS_INDICATORS
                    .iter()
                    .any(|ind| line_trimmed.contains(ind))
            {
                continue;
            }

            let line_len = line.len();

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

            if !name.is_empty() && !id.is_empty() {
                if id.len() == 1 && (id == "|" || id == "/" || id == "-" || id == "\\") {
                    continue;
                }

                if id == "Id" || name == "Name" {
                    continue;
                }

                let id_looks_valid = id.contains('.')
                    || (id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                        && id.len() > 2);

                let name_clean = !name
                    .chars()
                    .any(|c| PROGRESS_BAR_CHARS.contains(&c) || c == '|' || c == '/');
                let id_clean = !id
                    .chars()
                    .any(|c| PROGRESS_BAR_CHARS.contains(&c) || c == '|' || c == '/');

                if id_looks_valid && name_clean && id_clean {
                    packages.push(json!({
                        "name": name,
                        "id": id,
                        "version": version,
                        "installed": false,
                        "source": "winget"
                    }));
                }
            }
        }

        packages
    }

    /// Format PowerShell package output
    fn format_powershell_packages(&self, data: Value) -> Vec<Value> {
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
            packages.push(json!({
                "name": data["Name"].as_str().unwrap_or(""),
                "version": data["Version"].as_str().unwrap_or(""),
                "source": data["Source"].as_str().unwrap_or(""),
                "installed": true
            }));
        }

        packages
    }
}

impl Default for WindowsSystemOperations {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SystemOperations for WindowsSystemOperations {
    // ===== Service Operations =====

    async fn list_services(&self) -> SystemOperationResult {
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json",
            ])
            .output()
            .context("Failed to execute Get-Service")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let services: Value = serde_json::from_str(&stdout)?;
            Ok((stdout.to_string(), String::new(), Some(services)))
        } else {
            Err(anyhow!(
                "Failed to list services: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    async fn control_service(
        &self,
        service: &str,
        operation: &ServiceOperation,
    ) -> SystemOperationResult {
        Self::validate_name(service, "service")?;

        let ps_cmd = match operation {
            ServiceOperation::Start => format!("Start-Service -Name '{}'", service),
            ServiceOperation::Stop => format!("Stop-Service -Name '{}'", service),
            ServiceOperation::Restart => format!("Restart-Service -Name '{}'", service),
            ServiceOperation::Enable => {
                format!("Set-Service -Name '{}' -StartupType Automatic", service)
            }
            ServiceOperation::Disable => {
                format!("Set-Service -Name '{}' -StartupType Disabled", service)
            }
            ServiceOperation::Status => format!(
                "Get-Service -Name '{}' | Select-Object Name, Status, StartType | ConvertTo-Json",
                service
            ),
        };

        let output = Command::new("powershell")
            .args(&["-Command", &ps_cmd])
            .output()
            .context("Failed to execute service control")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok((stdout.to_string(), String::new(), None))
        } else {
            Err(anyhow!(
                "Service control failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    // ===== Package Operations =====

    async fn list_packages(&self) -> SystemOperationResult {
        let winget_args = "list --accept-source-agreements --disable-interactivity";

        let mut packages = self
            .execute_winget_with_json(winget_args, true)
            .unwrap_or_else(|e| {
                debug!("PowerShell execution failed: {}, trying fallback", e);
                Vec::new()
            });

        if packages.is_empty() && self.is_powershell_available() {
            let fallback_output = Command::new("powershell")
                .args(&[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-Package | Select-Object Name, Version, Source | ConvertTo-Json -Compress",
                ])
                .output()
                .context("Failed to list packages with fallback")?;

            let fallback_stdout = String::from_utf8_lossy(&fallback_output.stdout);
            if let Ok(json_data) = serde_json::from_str::<Value>(&fallback_stdout) {
                packages = self.format_powershell_packages(json_data);
            }
        }

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
            Some(json!({ "packages": packages })),
        ))
    }

    async fn install_package(&self, package: &str) -> SystemOperationResult {
        Self::validate_name(package, "package")?;

        let output = Command::new("winget")
            .args(&[
                "install",
                "--accept-source-agreements",
                "--accept-package-agreements",
                package,
            ])
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
    }

    async fn remove_package(&self, package: &str) -> SystemOperationResult {
        Self::validate_name(package, "package")?;

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
    }

    async fn update_package(&self, package: &str) -> SystemOperationResult {
        Self::validate_name(package, "package")?;

        let output = Command::new("winget")
            .args(&[
                "upgrade",
                "--accept-source-agreements",
                "--accept-package-agreements",
                package,
            ])
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
    }

    async fn search_packages(&self, query: &str) -> SystemOperationResult {
        Self::validate_name(query, "query")?;

        let safe_query = query.replace("\"", "`\"");
        let winget_args = format!(
            "search \"{}\" --accept-source-agreements --disable-interactivity --no-vt",
            safe_query
        );

        let mut packages = self
            .execute_winget_with_json(&winget_args, false)
            .unwrap_or_else(|e| {
                debug!(
                    "PowerShell execution with --no-vt failed: {}, trying without --no-vt",
                    e
                );
                Vec::new()
            });

        if packages.is_empty() {
            let fallback_args = format!(
                "search \"{}\" --accept-source-agreements --disable-interactivity",
                safe_query
            );
            packages = self
                .execute_winget_with_json(&fallback_args, false)
                .unwrap_or_else(|e| {
                    debug!("PowerShell execution failed: {}, trying direct winget", e);
                    Vec::new()
                });
        }

        if packages.is_empty() {
            let output = Command::new("winget")
                .args(&[
                    "search",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                    query,
                ])
                .env("NO_COLOR", "1")
                .env("TERM", "dumb")
                .output()
                .context("Failed to search packages")?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let filtered_stdout = self.filter_progress_artifacts(&stdout);
            packages = self.parse_winget_search(&filtered_stdout);
        }

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
                    || name.contains("services")
                    || name.contains("svchost")
                    || name.contains("csrss")
                    || name.contains("lsass"))
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
        use serde::Deserialize;
        use wmi::{COMLibrary, WMIConnection};

        #[derive(Deserialize, Debug)]
        #[serde(rename = "Win32_UserAccount")]
        #[serde(rename_all = "PascalCase")]
        struct Win32UserAccount {
            name: String,
            full_name: Option<String>,
            description: Option<String>,
            disabled: Option<bool>,
            #[allow(dead_code)]
            local_account: Option<bool>,
            lockout: Option<bool>,
            sid: Option<String>,
            status: Option<String>,
        }

        let com =
            COMLibrary::new().map_err(|e| anyhow!("Failed to initialize COM library: {}", e))?;
        let wmi_conn =
            WMIConnection::new(com).map_err(|e| anyhow!("Failed to create WMI connection: {}", e))?;

        let users: Vec<Win32UserAccount> = wmi_conn
            .raw_query("SELECT * FROM Win32_UserAccount WHERE LocalAccount = True")
            .map_err(|e| anyhow!("WMI query failed: {}", e))?;

        let user_list: Vec<Value> = users
            .iter()
            .map(|user| {
                json!({
                    "name": user.name,
                    "full_name": user.full_name,
                    "description": user.description,
                    "disabled": user.disabled.unwrap_or(false),
                    "locked": user.lockout.unwrap_or(false),
                    "sid": user.sid,
                    "status": user.status,
                })
            })
            .collect();

        let count = user_list.len();
        let data = json!({
            "users": user_list,
            "count": count
        });

        Ok((
            format!("Found {} local users", count),
            String::new(),
            Some(data),
        ))
    }

    // ===== Update Operations =====

    async fn check_updates(&self) -> SystemOperationResult {
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
            Err(e) => Err(anyhow!("Failed to check Windows updates: {}", e)),
        }
    }

    async fn get_update_history(&self, days: u32) -> SystemOperationResult {
        use crate::commands::windows_updates;

        match windows_updates::get_update_history(days).await {
            Ok(updates) => {
                let updates_json = serde_json::to_value(&updates)?;
                let summary = format!("Found {} updates in the last {} days", updates.len(), days);
                Ok((summary, String::new(), Some(updates_json)))
            }
            Err(e) => Err(anyhow!("Failed to get update history: {}", e)),
        }
    }

    async fn get_pending_updates(&self) -> SystemOperationResult {
        self.check_updates().await
    }

    // ===== Security Operations =====

    async fn check_security(&self) -> SystemOperationResult {
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
            Err(e) => Err(anyhow!("Failed to check Windows Defender: {}", e)),
        }
    }

    async fn get_firewall_status(&self) -> SystemOperationResult {
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json",
            ])
            .output()
            .context("Failed to execute Get-NetFirewallProfile")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let profiles: Value = serde_json::from_str(&stdout)?;

            let all_enabled = if let Some(arr) = profiles.as_array() {
                arr.iter()
                    .all(|p| p.get("Enabled").and_then(|v| v.as_bool()).unwrap_or(false))
            } else {
                profiles
                    .get("Enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            };

            let status = if all_enabled { "active" } else { "partial" };
            let summary = format!("Windows Firewall: {} (all profiles checked)", status);

            Ok((
                summary,
                String::new(),
                Some(json!({
                    "enabled": all_enabled,
                    "profiles": profiles,
                })),
            ))
        } else {
            Err(anyhow!(
                "Failed to get firewall status: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    async fn get_security_updates(&self) -> SystemOperationResult {
        use crate::commands::windows_updates;

        match windows_updates::check_windows_updates().await {
            Ok(update_status) => {
                let security_updates: Vec<_> = update_status
                    .pending_updates
                    .iter()
                    .filter(|u| {
                        u.title.to_lowercase().contains("security")
                            || u.categories.iter().any(|c| c.to_lowercase().contains("security"))
                    })
                    .collect();

                let summary = format!("Found {} security updates", security_updates.len());
                Ok((
                    summary,
                    String::new(),
                    Some(json!({
                        "security_updates": security_updates,
                        "count": security_updates.len(),
                    })),
                ))
            }
            Err(e) => Err(anyhow!("Failed to get security updates: {}", e)),
        }
    }

    async fn run_security_scan(&self) -> SystemOperationResult {
        use crate::commands::windows_defender::{self, DefenderScanType};

        match windows_defender::run_defender_scan(DefenderScanType::Quick).await {
            Ok(scan_result) => {
                let result_json = serde_json::to_value(&scan_result)?;
                let summary = format!(
                    "Quick scan started: threats found = {:?}",
                    scan_result.threats_found
                );
                Ok((summary, String::new(), Some(result_json)))
            }
            Err(e) => Err(anyhow!("Failed to run security scan: {}", e)),
        }
    }

    async fn get_threat_history(&self) -> SystemOperationResult {
        use crate::commands::windows_defender;

        match windows_defender::get_threat_history_async().await {
            Ok(history) => {
                let history_json = serde_json::to_value(&history)?;
                let summary = format!("Found {} threat history entries", history.len());
                Ok((summary, String::new(), Some(history_json)))
            }
            Err(e) => Err(anyhow!("Failed to get threat history: {}", e)),
        }
    }

    async fn check_security_modules(&self) -> SystemOperationResult {
        // Windows does not have Linux-style kernel security modules (AppArmor, SELinux)
        Ok((
            "Security modules check not applicable on Windows. Use check_security() for Windows Defender status."
                .to_string(),
            String::new(),
            Some(json!({
                "supported": false,
                "platform": "windows",
                "suggestion": "Use CheckWindowsDefender or GetDefenderStatus for security checks"
            })),
        ))
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

    async fn disk_cleanup(&self, _drive: &str, _targets: &[String]) -> SystemOperationResult {
        Err(anyhow!(
            "Disk cleanup with targets is only supported on Linux. For Windows, use the Windows Disk Cleanup utility (cleanmgr.exe)."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name_valid() {
        assert!(WindowsSystemOperations::validate_name("nginx", "service").is_ok());
        assert!(WindowsSystemOperations::validate_name("my-package", "package").is_ok());
        assert!(WindowsSystemOperations::validate_name("Microsoft.Edge", "package").is_ok());
    }

    #[test]
    fn test_validate_name_invalid() {
        assert!(WindowsSystemOperations::validate_name("nginx; del *", "service").is_err());
        assert!(WindowsSystemOperations::validate_name("pkg | type", "package").is_err());
        assert!(WindowsSystemOperations::validate_name("$(whoami)", "package").is_err());
    }

    #[test]
    fn test_filter_progress_artifacts() {
        let ops = WindowsSystemOperations::new();

        let with_artifacts = "Package Name    Package.Id    1.0.0\n████████████\n50%\nAnother.Package    Another.Id    2.0.0";
        let filtered = ops.filter_progress_artifacts(with_artifacts);

        assert!(!filtered.contains("████████"));
        assert!(!filtered.contains("50%"));
        assert!(filtered.contains("Package Name"));
        assert!(filtered.contains("Another.Package"));
    }
}
