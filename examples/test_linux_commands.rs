/// Test program to verify Linux command functionality
///
/// This example demonstrates the Linux-specific command capabilities
/// of InfiniService, including:
/// - OS detection (Ubuntu vs Fedora)
/// - Update checking and history
/// - Security status (firewall, SELinux/AppArmor)
/// - Application inventory from multiple sources
/// - Disk cleanup estimation
/// - Health checks for Linux systems
/// - Safe Command API usage (SafeCommandRequest/CommandResponse)
///
/// ## Permission Requirements
/// Some operations require elevated privileges:
/// - Update installation: sudo apt upgrade / sudo dnf upgrade
/// - Firewall management: sudo ufw enable / sudo firewall-cmd
/// - Package removal: sudo apt autoremove / sudo dnf autoremove
///
/// Read-only operations (like checking for updates) do not require sudo.
///
/// Run with: cargo run --example test_linux_commands

use anyhow::Result;

#[cfg(target_os = "linux")]
use infiniservice::os_detection::{get_os_info, OsType, LinuxDistro, PackageManager};

#[cfg(target_os = "linux")]
use infiniservice::commands::linux_updates::{check_linux_updates, get_linux_update_history};

#[cfg(target_os = "linux")]
use infiniservice::commands::linux_security::{check_linux_security, FirewallType, SecurityModuleType};

#[cfg(target_os = "linux")]
use infiniservice::commands::{SafeCommandRequest, SafeCommandType, CommandResponse};

#[cfg(target_os = "linux")]
use infiniservice::commands::safe_executor::SafeCommandExecutor;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    println!("=== InfiniService Linux Commands Test ===\n");

    #[cfg(target_os = "linux")]
    {
        run_linux_tests().await?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("This example is designed to run on Linux systems.");
        println!("Current platform is not Linux - skipping tests.");
        println!();
        println!("To test on Linux, run:");
        println!("  cargo run --example test_linux_commands");
    }

    println!("\n=== Test Complete ===");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_linux_tests() -> Result<()> {
    // 1. OS Detection
    println!("1. OS Detection");
    println!("   ============");
    test_os_detection()?;
    println!();

    // 2. Update Checking
    println!("2. Update Checking");
    println!("   ===============");
    test_update_checking().await?;
    println!();

    // 3. Security Status
    println!("3. Security Status");
    println!("   ===============");
    test_security_status().await?;
    println!();

    // 4. Application Inventory
    println!("4. Application Inventory");
    println!("   =====================");
    test_application_inventory()?;
    println!();

    // 5. Disk Cleanup Estimation
    println!("5. Disk Cleanup Estimation");
    println!("   =======================");
    test_disk_cleanup_estimation()?;
    println!();

    // 6. Health Checks
    println!("6. Health Checks");
    println!("   =============");
    test_health_checks().await?;
    println!();

    // 7. Safe Command API Usage
    println!("7. Safe Command API Usage");
    println!("   ======================");
    test_safe_command_api().await?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn test_os_detection() -> Result<()> {
    let os_info = get_os_info();

    println!("   OS Type: {:?}", os_info.os_type);
    println!("   Version: {}", os_info.version);
    println!("   Kernel: {}", os_info.kernel_version.as_deref().unwrap_or("Unknown"));
    println!("   Architecture: {}", os_info.architecture);
    println!("   Hostname: {}", os_info.hostname);

    if let Some(distro) = &os_info.linux_distro {
        println!("   Linux Distro: {:?}", distro);

        match distro {
            LinuxDistro::Ubuntu => println!("   -> Ubuntu detected (apt/dpkg/ufw)"),
            LinuxDistro::Debian => println!("   -> Debian detected (apt/dpkg/ufw)"),
            LinuxDistro::Fedora => println!("   -> Fedora detected (dnf/rpm/firewalld)"),
            LinuxDistro::CentOS => println!("   -> CentOS detected (yum/rpm/firewalld)"),
            LinuxDistro::RedHat => println!("   -> RHEL detected (yum/rpm/firewalld)"),
            LinuxDistro::Arch => println!("   -> Arch detected (pacman)"),
            LinuxDistro::OpenSUSE => println!("   -> OpenSUSE detected (zypper/rpm)"),
            LinuxDistro::Unknown => println!("   -> Unknown Linux distribution"),
        }
    }

    println!("   Available Package Managers:");
    for pm in &os_info.available_package_managers {
        let pm_name = match pm {
            PackageManager::Apt => "apt (Debian/Ubuntu)",
            PackageManager::Dnf => "dnf (Fedora)",
            PackageManager::Yum => "yum (CentOS/RHEL)",
            PackageManager::Pacman => "pacman (Arch)",
            PackageManager::Zypper => "zypper (OpenSUSE)",
            PackageManager::Snap => "snap (Universal)",
            PackageManager::Flatpak => "flatpak (Universal)",
            _ => "Other",
        };
        println!("      - {}", pm_name);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn test_update_checking() -> Result<()> {
    println!("   Checking for updates...");

    match check_linux_updates().await {
        Ok(status) => {
            println!("   Package Manager: {}", status.package_manager);
            println!("   Distribution: {}", status.distro);
            println!("   Total Pending Updates: {}", status.total_pending_count);
            println!("   Security Updates: {}", status.security_updates_count);
            println!("   Reboot Required: {}", if status.reboot_required { "Yes" } else { "No" });

            if !status.pending_updates.is_empty() {
                println!("   Sample Pending Updates (first 5):");
                for update in status.pending_updates.iter().take(5) {
                    let security_marker = if update.is_security { " [SECURITY]" } else { "" };
                    println!("      - {} -> {}{}",
                        update.package_name,
                        update.available_version,
                        security_marker
                    );
                }
            }
        }
        Err(e) => {
            println!("   Error checking updates: {}", e);
        }
    }

    // Check update history
    println!("\n   Recent Update History (last 7 days):");
    match get_linux_update_history(7).await {
        Ok(history) => {
            if history.is_empty() {
                println!("      No recent updates found.");
            } else {
                for update in history.iter().take(5) {
                    let action = update.action.as_deref().unwrap_or("Unknown");
                    let date = update.installed_on.as_deref().unwrap_or("Unknown date");
                    println!("      - [{}] {} {} ({})", action, update.package_name, update.version, date);
                }
            }
        }
        Err(e) => {
            println!("      Error getting history: {}", e);
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn test_security_status() -> Result<()> {
    println!("   Checking security status...");

    match check_linux_security().await {
        Ok(status) => {
            // Firewall Status
            let fw_type = match status.firewall.firewall_type {
                FirewallType::Ufw => "UFW (Ubuntu)",
                FirewallType::Firewalld => "firewalld (Fedora/RHEL)",
                FirewallType::Iptables => "iptables (Direct)",
                FirewallType::Nftables => "nftables",
                FirewallType::None => "None detected",
            };
            println!("   Firewall: {} - {}", fw_type, status.firewall.status);
            println!("   Firewall Enabled: {}", if status.firewall.enabled { "Yes" } else { "No" });
            println!("   Firewall Rules: {}", status.firewall.rules_count);

            if let Some(default_in) = &status.firewall.default_incoming {
                println!("   Default Incoming: {}", default_in);
            }
            if let Some(default_out) = &status.firewall.default_outgoing {
                println!("   Default Outgoing: {}", default_out);
            }

            // Security Module Status
            let sm_type = match status.security_module.module_type {
                SecurityModuleType::SELinux => "SELinux",
                SecurityModuleType::AppArmor => "AppArmor",
                SecurityModuleType::None => "None",
            };
            println!("   Security Module: {} - {}", sm_type,
                if status.security_module.enabled { "Enabled" } else { "Disabled" });

            if let Some(mode) = &status.security_module.selinux_mode {
                println!("   SELinux Mode: {:?}", mode);
            }
            if let Some(profiles) = status.security_module.profiles_loaded {
                println!("   AppArmor Profiles Loaded: {}", profiles);
            }

            // Security Updates
            println!("   Pending Security Updates: {}", status.security_updates_count);
            if !status.security_updates.is_empty() {
                println!("   Security Update Details:");
                for update in status.security_updates.iter().take(3) {
                    let severity = update.severity.as_deref().unwrap_or("Unknown");
                    println!("      - {} ({})", update.package_name, severity);
                }
            }
        }
        Err(e) => {
            println!("   Error checking security: {}", e);
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn test_application_inventory() -> Result<()> {
    use std::process::Command;

    println!("   Scanning installed applications...");

    // Check dpkg (Debian/Ubuntu)
    let dpkg_count = Command::new("dpkg-query")
        .args(["-l"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count().saturating_sub(5))
        .unwrap_or(0);

    if dpkg_count > 0 {
        println!("   DEB packages (dpkg): {} packages", dpkg_count);
    }

    // Check rpm (Fedora/RHEL)
    let rpm_count = Command::new("rpm")
        .args(["-qa"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0);

    if rpm_count > 0 {
        println!("   RPM packages: {} packages", rpm_count);
    }

    // Check snap
    let snap_count = Command::new("snap")
        .args(["list"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count().saturating_sub(1))
        .unwrap_or(0);

    if snap_count > 0 {
        println!("   Snap packages: {} packages", snap_count);
    }

    // Check flatpak
    let flatpak_count = Command::new("flatpak")
        .args(["list", "--app"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0);

    if flatpak_count > 0 {
        println!("   Flatpak applications: {} apps", flatpak_count);
    }

    let total = dpkg_count + rpm_count + snap_count + flatpak_count;
    println!("   Total applications tracked: {}", total);

    Ok(())
}

#[cfg(target_os = "linux")]
fn test_disk_cleanup_estimation() -> Result<()> {
    use std::process::Command;
    use std::path::Path;

    println!("   Estimating cleanup potential...");

    // Check apt cache size
    if Path::new("/var/cache/apt/archives").exists() {
        let apt_cache = Command::new("du")
            .args(["-sh", "/var/cache/apt/archives"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.split_whitespace().next().unwrap_or("0").to_string())
            .unwrap_or_else(|| "N/A".to_string());

        println!("   APT Cache: {}", apt_cache);
    }

    // Check dnf cache size
    if Path::new("/var/cache/dnf").exists() {
        let dnf_cache = Command::new("du")
            .args(["-sh", "/var/cache/dnf"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.split_whitespace().next().unwrap_or("0").to_string())
            .unwrap_or_else(|| "N/A".to_string());

        println!("   DNF Cache: {}", dnf_cache);
    }

    // Check tmp directory
    if Path::new("/tmp").exists() {
        let tmp_size = Command::new("du")
            .args(["-sh", "/tmp"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.split_whitespace().next().unwrap_or("0").to_string())
            .unwrap_or_else(|| "N/A".to_string());

        println!("   /tmp directory: {}", tmp_size);
    }

    // Check old kernels (Ubuntu/Debian)
    let old_kernels = Command::new("dpkg")
        .args(["-l", "linux-image-*"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.starts_with("ii") && l.contains("linux-image"))
                .count()
        })
        .unwrap_or(0);

    if old_kernels > 1 {
        println!("   Old kernel versions: {} (current kept)", old_kernels - 1);
    }

    // Check journal logs size
    if Path::new("/var/log/journal").exists() {
        let journal_size = Command::new("journalctl")
            .args(["--disk-usage"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.lines().last().map(|l| l.to_string()))
            .unwrap_or_else(|| "N/A".to_string());

        println!("   Journal logs: {}", journal_size.trim());
    }

    println!("\n   Cleanup Commands:");
    println!("      APT: sudo apt clean && sudo apt autoremove");
    println!("      DNF: sudo dnf clean all && sudo dnf autoremove");
    println!("      Snap: sudo snap set system refresh.retain=2");
    println!("      Journal: sudo journalctl --vacuum-time=7d");

    Ok(())
}

#[cfg(target_os = "linux")]
async fn test_health_checks() -> Result<()> {
    use infiniservice::commands::autochecks::health_checks::{
        LinuxUpdatesCheck, LinuxSecurityCheck, HealthCheck, CheckContext, VmInfo,
        MetricsHistory, AutoCheckConfig, HealthStatus
    };

    println!("   Running health checks...");

    let context = CheckContext {
        vm_info: VmInfo {
            cpu_count: num_cpus::get() as u32,
            memory_mb: sys_info::mem_info().map(|m| m.total as u64 / 1024).unwrap_or(0),
            os_type: "Linux".to_string(),
            os_version: sys_info::linux_os_release()
                .map(|r| r.pretty_name.unwrap_or_default())
                .unwrap_or_else(|_| "Unknown".to_string()),
        },
        metrics_history: MetricsHistory {
            cpu_usage: vec![],
            memory_usage: vec![],
            disk_usage: vec![],
            network_usage: vec![],
        },
        config: AutoCheckConfig::default(),
    };

    // Linux Updates Check
    let updates_check = LinuxUpdatesCheck::new();
    println!("\n   {} Check:", updates_check.name());
    println!("      Category: {:?}", updates_check.category());
    println!("      Can Auto-Remediate: {}", updates_check.can_auto_remediate());

    match updates_check.execute(&context).await {
        Ok(result) => {
            let status_icon = match result.status {
                HealthStatus::Healthy => "OK",
                HealthStatus::Warning => "WARN",
                HealthStatus::Critical => "CRIT",
            };
            println!("      Status: [{}] {}", status_icon, result.message);
            if !result.details.is_null() {
                println!("      Details: {:?}", result.details);
            }
        }
        Err(e) => println!("      Error: {}", e),
    }

    // Linux Security Check
    let security_check = LinuxSecurityCheck::new();
    println!("\n   {} Check:", security_check.name());
    println!("      Category: {:?}", security_check.category());
    println!("      Can Auto-Remediate: {}", security_check.can_auto_remediate());

    match security_check.execute(&context).await {
        Ok(result) => {
            let status_icon = match result.status {
                HealthStatus::Healthy => "OK",
                HealthStatus::Warning => "WARN",
                HealthStatus::Critical => "CRIT",
            };
            println!("      Status: [{}] {}", status_icon, result.message);
        }
        Err(e) => println!("      Error: {}", e),
    }

    Ok(())
}

/// Demonstrates the Safe Command API for Linux operations
///
/// This function shows how to use SafeCommandRequest and the SafeCommandExecutor
/// to execute Linux commands through the structured API rather than direct function calls.
///
/// **Permission Notes:**
/// - CheckLinuxUpdates: No sudo required (read-only)
/// - GetLinuxSecurityStatus: No sudo required (read-only)
/// - CheckFirewallStatus: No sudo required (read-only)
/// - GetInstalledApplicationsWMI: No sudo required (read-only, Windows only)
#[cfg(target_os = "linux")]
async fn test_safe_command_api() -> Result<()> {
    println!("   Demonstrating SafeCommandRequest API...");
    println!();

    // Create the safe command executor
    let executor = match SafeCommandExecutor::new() {
        Ok(e) => e,
        Err(e) => {
            println!("   Error creating executor: {}", e);
            return Ok(());
        }
    };

    // -------------------------------------------------------------------------
    // 1. CheckLinuxUpdates via SafeCommandRequest
    // -------------------------------------------------------------------------
    println!("   1) CheckLinuxUpdates via SafeCommandRequest:");

    let request = SafeCommandRequest {
        id: "example-updates-001".to_string(),
        command_type: SafeCommandType::CheckLinuxUpdates,
        params: None,
        timeout: Some(60),
    };

    println!("      Request: {:?}", serde_json::to_string(&request).unwrap_or_default());

    match executor.execute(request).await {
        Ok(response) => {
            print_command_response("CheckLinuxUpdates", &response);
        }
        Err(e) => println!("      Error: {}", e),
    }
    println!();

    // -------------------------------------------------------------------------
    // 2. GetLinuxSecurityStatus via SafeCommandRequest
    // -------------------------------------------------------------------------
    println!("   2) GetLinuxSecurityStatus via SafeCommandRequest:");

    let request = SafeCommandRequest {
        id: "example-security-001".to_string(),
        command_type: SafeCommandType::GetLinuxSecurityStatus,
        params: None,
        timeout: Some(30),
    };

    println!("      Request: {:?}", serde_json::to_string(&request).unwrap_or_default());

    match executor.execute(request).await {
        Ok(response) => {
            print_command_response("GetLinuxSecurityStatus", &response);
        }
        Err(e) => println!("      Error: {}", e),
    }
    println!();

    // -------------------------------------------------------------------------
    // 3. CheckFirewallStatus via SafeCommandRequest
    // -------------------------------------------------------------------------
    println!("   3) CheckFirewallStatus via SafeCommandRequest:");

    let request = SafeCommandRequest {
        id: "example-firewall-001".to_string(),
        command_type: SafeCommandType::CheckFirewallStatus,
        params: None,
        timeout: Some(15),
    };

    println!("      Request: {:?}", serde_json::to_string(&request).unwrap_or_default());

    match executor.execute(request).await {
        Ok(response) => {
            print_command_response("CheckFirewallStatus", &response);
        }
        Err(e) => println!("      Error: {}", e),
    }

    println!("\n   Safe Command API demonstration complete.");
    println!("   All commands used structured SafeCommandRequest/CommandResponse API.");

    Ok(())
}

/// Helper to print command response details
#[cfg(target_os = "linux")]
fn print_command_response(cmd_name: &str, response: &CommandResponse) {
    println!("      Response ID: {}", response.id);
    println!("      Success: {}", response.success);
    println!("      Execution Time: {} ms", response.execution_time_ms);
    println!("      Command Type: {}", response.command_type);

    if !response.success {
        if !response.stderr.is_empty() {
            println!("      Error: {}", response.stderr);
        }
    } else {
        if let Some(data) = &response.data {
            // Pretty print a summary of the data
            match cmd_name {
                "CheckLinuxUpdates" => {
                    if let Some(count) = data.get("total_pending_count").and_then(|v| v.as_u64()) {
                        println!("      Pending Updates: {}", count);
                    }
                    if let Some(security) = data.get("security_updates_count").and_then(|v| v.as_u64()) {
                        println!("      Security Updates: {}", security);
                    }
                    if let Some(pm) = data.get("package_manager").and_then(|v| v.as_str()) {
                        println!("      Package Manager: {}", pm);
                    }
                }
                "GetLinuxSecurityStatus" => {
                    if let Some(fw) = data.get("firewall") {
                        if let Some(enabled) = fw.get("enabled").and_then(|v| v.as_bool()) {
                            let status = if enabled { "Enabled" } else { "Disabled" };
                            println!("      Firewall: {}", status);
                        }
                        if let Some(fw_type) = fw.get("firewall_type").and_then(|v| v.as_str()) {
                            println!("      Firewall Type: {}", fw_type);
                        }
                    }
                    if let Some(sm) = data.get("security_module") {
                        if let Some(sm_type) = sm.get("module_type").and_then(|v| v.as_str()) {
                            println!("      Security Module: {}", sm_type);
                        }
                    }
                }
                "CheckFirewallStatus" => {
                    if let Some(enabled) = data.get("enabled").and_then(|v| v.as_bool()) {
                        let status = if enabled { "Enabled" } else { "Disabled" };
                        println!("      Status: {}", status);
                    }
                    if let Some(fw_type) = data.get("firewall_type").and_then(|v| v.as_str()) {
                        println!("      Type: {}", fw_type);
                    }
                    if let Some(rules) = data.get("rules_count").and_then(|v| v.as_u64()) {
                        println!("      Rules: {}", rules);
                    }
                }
                _ => {
                    println!("      Data: {:?}", data);
                }
            }
        }
    }
}

/// Helper to print command response details
#[cfg(target_os = "linux")]
fn print_command_response(cmd_name: &str, response: &CommandResponse) {
    println!("      Response ID: {}", response.id);
    println!("      Success: {}", response.success);
    println!("      Execution Time: {} ms", response.execution_time_ms);
    println!("      Command Type: {}", response.command_type);

    if !response.success {
        if !response.stderr.is_empty() {
            println!("      Error: {}", response.stderr);
        }
    } else {
        if let Some(data) = &response.data {
            // Pretty print a summary of the data
            match cmd_name {
                "CheckLinuxUpdates" => {
                    if let Some(count) = data.get("total_pending_count").and_then(|v| v.as_u64()) {
                        println!("      Pending Updates: {}", count);
                    }
                    if let Some(security) = data.get("security_updates_count").and_then(|v| v.as_u64()) {
                        println!("      Security Updates: {}", security);
                    }
                    if let Some(pm) = data.get("package_manager").and_then(|v| v.as_str()) {
                        println!("      Package Manager: {}", pm);
                    }
                }
                "GetLinuxSecurityStatus" => {
                    if let Some(fw) = data.get("firewall") {
                        if let Some(enabled) = fw.get("enabled").and_then(|v| v.as_bool()) {
                            let status = if enabled { "Enabled" } else { "Disabled" };
                            println!("      Firewall: {}", status);
                        }
                        if let Some(fw_type) = fw.get("firewall_type").and_then(|v| v.as_str()) {
                            println!("      Firewall Type: {}", fw_type);
                        }
                    }
                    if let Some(sm) = data.get("security_module") {
                        if let Some(sm_type) = sm.get("module_type").and_then(|v| v.as_str()) {
                            println!("      Security Module: {}", sm_type);
                        }
                    }
                }
                "CheckFirewallStatus" => {
                    if let Some(enabled) = data.get("enabled").and_then(|v| v.as_bool()) {
                        let status = if enabled { "Enabled" } else { "Disabled" };
                        println!("      Status: {}", status);
                    }
                    if let Some(fw_type) = data.get("firewall_type").and_then(|v| v.as_str()) {
                        println!("      Type: {}", fw_type);
                    }
                    if let Some(rules) = data.get("rules_count").and_then(|v| v.as_u64()) {
                        println!("      Rules: {}", rules);
                    }
                }
                "GetInstalledApplications" => {
                    if let Some(apps) = data.as_array() {
                        println!("      Total Applications: {}", apps.len());
                    }
                }
                _ => {
                    println!("      Data: {:?}", data);
                }
            }
        }
    }
}
