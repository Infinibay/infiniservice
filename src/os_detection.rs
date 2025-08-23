//! OS detection and system information module
//! 
//! Provides detailed operating system detection including distribution,
//! version, architecture, and available package managers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use log::{debug, info};

/// Operating system type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OsType {
    Windows,
    Linux,
    Unknown,
}

/// Linux distribution family
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LinuxDistro {
    Debian,
    Ubuntu,
    RedHat,
    CentOS,
    Fedora,
    Arch,
    OpenSUSE,
    Alpine,
    Unknown(String),
}

/// Available package manager
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PackageManager {
    // Windows
    Winget,
    Chocolatey,
    Scoop,
    
    // Linux
    Apt,
    Yum,
    Dnf,
    Pacman,
    Zypper,
    Apk,
    Snap,
    Flatpak,
}

/// System shell type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ShellType {
    Bash,
    Sh,
    Zsh,
    PowerShell,
    Cmd,
    Fish,
}

/// Complete OS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_type: OsType,
    pub version: String,
    pub kernel_version: Option<String>,
    pub architecture: String,
    pub hostname: String,
    pub linux_distro: Option<LinuxDistro>,
    pub windows_edition: Option<String>,
    pub available_package_managers: Vec<PackageManager>,
    pub default_shell: ShellType,
}

impl OsInfo {
    /// Detect current operating system information
    pub fn detect() -> Result<Self> {
        let os_type = Self::detect_os_type();
        let architecture = Self::detect_architecture();
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        
        let (version, kernel_version, linux_distro, windows_edition) = match os_type {
            OsType::Windows => {
                let (version, edition) = Self::detect_windows_version()?;
                (version, None, None, Some(edition))
            },
            OsType::Linux => {
                let (version, kernel, distro) = Self::detect_linux_info()?;
                (version, Some(kernel), Some(distro), None)
            },
            OsType::Unknown => {
                ("unknown".to_string(), None, None, None)
            }
        };
        
        let available_package_managers = Self::detect_package_managers(&os_type, &linux_distro);
        let default_shell = Self::detect_default_shell(&os_type);
        
        Ok(OsInfo {
            os_type,
            version,
            kernel_version,
            architecture,
            hostname,
            linux_distro,
            windows_edition,
            available_package_managers,
            default_shell,
        })
    }
    
    /// Detect the OS type
    fn detect_os_type() -> OsType {
        #[cfg(target_os = "windows")]
        return OsType::Windows;
        
        #[cfg(target_os = "linux")]
        return OsType::Linux;
        
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        return OsType::Unknown;
    }
    
    /// Detect system architecture
    fn detect_architecture() -> String {
        std::env::consts::ARCH.to_string()
    }
    
    /// Detect Windows version and edition
    #[cfg(target_os = "windows")]
    fn detect_windows_version() -> Result<(String, String)> {
        // Try to get version from registry or WMI
        let output = Command::new("wmic")
            .args(&["os", "get", "Caption,Version", "/format:csv"])
            .output()
            .context("Failed to execute wmic")?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = output_str.lines().collect();
        
        // Parse CSV output
        for line in lines {
            if line.contains("Microsoft Windows") {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    let edition = parts[1].trim().to_string();
                    let version = parts[2].trim().to_string();
                    return Ok((version, edition));
                }
            }
        }
        
        // Fallback to basic detection
        Ok(("Windows".to_string(), "Unknown Edition".to_string()))
    }
    
    #[cfg(not(target_os = "windows"))]
    fn detect_windows_version() -> Result<(String, String)> {
        Ok(("".to_string(), "".to_string()))
    }
    
    /// Detect Linux distribution and kernel version
    #[cfg(target_os = "linux")]
    fn detect_linux_info() -> Result<(String, String, LinuxDistro)> {
        // Get kernel version
        let kernel = fs::read_to_string("/proc/version")
            .unwrap_or_else(|_| "unknown".to_string())
            .split_whitespace()
            .nth(2)
            .unwrap_or("unknown")
            .to_string();
        
        // Try to read /etc/os-release for distribution info
        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            let mut distro_id = String::new();
            let mut version = String::new();
            let mut pretty_name = String::new();
            
            for line in content.lines() {
                if line.starts_with("ID=") {
                    distro_id = line[3..].trim_matches('"').to_string();
                } else if line.starts_with("VERSION_ID=") {
                    version = line[11..].trim_matches('"').to_string();
                } else if line.starts_with("PRETTY_NAME=") {
                    pretty_name = line[12..].trim_matches('"').to_string();
                }
            }
            
            let distro = match distro_id.as_str() {
                "ubuntu" => LinuxDistro::Ubuntu,
                "debian" => LinuxDistro::Debian,
                "rhel" | "redhat" => LinuxDistro::RedHat,
                "centos" => LinuxDistro::CentOS,
                "fedora" => LinuxDistro::Fedora,
                "arch" => LinuxDistro::Arch,
                "opensuse" | "suse" => LinuxDistro::OpenSUSE,
                "alpine" => LinuxDistro::Alpine,
                other => LinuxDistro::Unknown(other.to_string()),
            };
            
            let version_str = if !pretty_name.is_empty() {
                pretty_name
            } else {
                format!("{} {}", distro_id, version)
            };
            
            return Ok((version_str, kernel, distro));
        }
        
        // Fallback detection methods
        if fs::metadata("/etc/debian_version").is_ok() {
            let version = fs::read_to_string("/etc/debian_version")
                .unwrap_or_else(|_| "unknown".to_string());
            return Ok((format!("Debian {}", version.trim()), kernel, LinuxDistro::Debian));
        }
        
        if fs::metadata("/etc/redhat-release").is_ok() {
            let version = fs::read_to_string("/etc/redhat-release")
                .unwrap_or_else(|_| "unknown".to_string());
            return Ok((version.trim().to_string(), kernel, LinuxDistro::RedHat));
        }
        
        Ok(("Linux".to_string(), kernel, LinuxDistro::Unknown("unknown".to_string())))
    }
    
    #[cfg(not(target_os = "linux"))]
    fn detect_linux_info() -> Result<(String, String, LinuxDistro)> {
        Ok(("".to_string(), "".to_string(), LinuxDistro::Unknown("".to_string())))
    }
    
    /// Detect available package managers
    fn detect_package_managers(os_type: &OsType, linux_distro: &Option<LinuxDistro>) -> Vec<PackageManager> {
        let mut managers = Vec::new();
        
        match os_type {
            OsType::Windows => {
                // Check for Windows package managers
                if Self::command_exists("winget") {
                    managers.push(PackageManager::Winget);
                }
                if Self::command_exists("choco") {
                    managers.push(PackageManager::Chocolatey);
                }
                if Self::command_exists("scoop") {
                    managers.push(PackageManager::Scoop);
                }
            },
            OsType::Linux => {
                // Check for Linux package managers based on distro
                match linux_distro {
                    Some(LinuxDistro::Debian) | Some(LinuxDistro::Ubuntu) => {
                        if Self::command_exists("apt-get") || Self::command_exists("apt") {
                            managers.push(PackageManager::Apt);
                        }
                    },
                    Some(LinuxDistro::RedHat) | Some(LinuxDistro::CentOS) => {
                        if Self::command_exists("yum") {
                            managers.push(PackageManager::Yum);
                        }
                        if Self::command_exists("dnf") {
                            managers.push(PackageManager::Dnf);
                        }
                    },
                    Some(LinuxDistro::Fedora) => {
                        if Self::command_exists("dnf") {
                            managers.push(PackageManager::Dnf);
                        }
                    },
                    Some(LinuxDistro::Arch) => {
                        if Self::command_exists("pacman") {
                            managers.push(PackageManager::Pacman);
                        }
                    },
                    Some(LinuxDistro::OpenSUSE) => {
                        if Self::command_exists("zypper") {
                            managers.push(PackageManager::Zypper);
                        }
                    },
                    Some(LinuxDistro::Alpine) => {
                        if Self::command_exists("apk") {
                            managers.push(PackageManager::Apk);
                        }
                    },
                    _ => {
                        // Try to detect any available package manager
                        if Self::command_exists("apt-get") || Self::command_exists("apt") {
                            managers.push(PackageManager::Apt);
                        }
                        if Self::command_exists("yum") {
                            managers.push(PackageManager::Yum);
                        }
                        if Self::command_exists("dnf") {
                            managers.push(PackageManager::Dnf);
                        }
                        if Self::command_exists("pacman") {
                            managers.push(PackageManager::Pacman);
                        }
                        if Self::command_exists("zypper") {
                            managers.push(PackageManager::Zypper);
                        }
                        if Self::command_exists("apk") {
                            managers.push(PackageManager::Apk);
                        }
                    }
                }
                
                // Check for universal package managers
                if Self::command_exists("snap") {
                    managers.push(PackageManager::Snap);
                }
                if Self::command_exists("flatpak") {
                    managers.push(PackageManager::Flatpak);
                }
            },
            _ => {}
        }
        
        managers
    }
    
    /// Detect default shell
    fn detect_default_shell(os_type: &OsType) -> ShellType {
        match os_type {
            OsType::Windows => {
                // Check if PowerShell is available
                if Self::command_exists("powershell") || Self::command_exists("pwsh") {
                    ShellType::PowerShell
                } else {
                    ShellType::Cmd
                }
            },
            OsType::Linux => {
                // Check SHELL environment variable
                if let Ok(shell) = std::env::var("SHELL") {
                    if shell.contains("bash") {
                        ShellType::Bash
                    } else if shell.contains("zsh") {
                        ShellType::Zsh
                    } else if shell.contains("fish") {
                        ShellType::Fish
                    } else {
                        ShellType::Sh
                    }
                } else {
                    ShellType::Bash
                }
            },
            _ => ShellType::Sh,
        }
    }
    
    /// Check if a command exists in PATH
    fn command_exists(cmd: &str) -> bool {
        #[cfg(target_os = "windows")]
        {
            Command::new("where")
                .arg(cmd)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Command::new("which")
                .arg(cmd)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    }
    
    /// Get the appropriate shell command for this OS
    pub fn get_shell_command(&self, shell_hint: Option<&str>) -> (&str, Vec<&str>) {
        let shell = shell_hint.unwrap_or("");
        
        match self.os_type {
            OsType::Windows => {
                match shell {
                    "powershell" | "pwsh" => ("powershell", vec!["-Command"]),
                    "cmd" => ("cmd", vec!["/C"]),
                    _ => {
                        // Use default shell
                        match self.default_shell {
                            ShellType::PowerShell => ("powershell", vec!["-Command"]),
                            _ => ("cmd", vec!["/C"]),
                        }
                    }
                }
            },
            OsType::Linux => {
                match shell {
                    "bash" => ("bash", vec!["-c"]),
                    "sh" => ("sh", vec!["-c"]),
                    "zsh" => ("zsh", vec!["-c"]),
                    "fish" => ("fish", vec!["-c"]),
                    _ => {
                        // Use default shell
                        match self.default_shell {
                            ShellType::Bash => ("bash", vec!["-c"]),
                            ShellType::Zsh => ("zsh", vec!["-c"]),
                            ShellType::Fish => ("fish", vec!["-c"]),
                            _ => ("sh", vec!["-c"]),
                        }
                    }
                }
            },
            _ => ("sh", vec!["-c"]),
        }
    }
}

/// Global OS info cache
static mut OS_INFO_CACHE: Option<OsInfo> = None;
static OS_INFO_INIT: std::sync::Once = std::sync::Once::new();

/// Get cached OS information (initialized once)
pub fn get_os_info() -> &'static OsInfo {
    unsafe {
        OS_INFO_INIT.call_once(|| {
            match OsInfo::detect() {
                Ok(info) => {
                    info!("Detected OS: {:?} - {}", info.os_type, info.version);
                    debug!("Available package managers: {:?}", info.available_package_managers);
                    OS_INFO_CACHE = Some(info);
                },
                Err(e) => {
                    log::error!("Failed to detect OS info: {}", e);
                    OS_INFO_CACHE = Some(OsInfo {
                        os_type: OsType::Unknown,
                        version: "unknown".to_string(),
                        kernel_version: None,
                        architecture: std::env::consts::ARCH.to_string(),
                        hostname: "unknown".to_string(),
                        linux_distro: None,
                        windows_edition: None,
                        available_package_managers: vec![],
                        default_shell: ShellType::Sh,
                    });
                }
            }
        });
        OS_INFO_CACHE.as_ref().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_os_type_detection() {
        let os_type = OsInfo::detect_os_type();
        assert_ne!(os_type, OsType::Unknown);
    }
    
    #[test]
    fn test_architecture_detection() {
        let arch = OsInfo::detect_architecture();
        assert!(!arch.is_empty());
        assert!(["x86_64", "x86", "aarch64", "arm"].contains(&arch.as_str()));
    }
    
    #[test]
    fn test_os_info_detection() {
        let info = OsInfo::detect();
        assert!(info.is_ok());
        
        let info = info.unwrap();
        assert_ne!(info.os_type, OsType::Unknown);
        assert!(!info.version.is_empty());
        assert!(!info.hostname.is_empty());
    }
    
    #[test]
    fn test_get_shell_command() {
        let info = OsInfo::detect().unwrap();
        
        // Test with shell hint
        let (cmd, args) = info.get_shell_command(Some("bash"));
        if info.os_type == OsType::Linux {
            assert_eq!(cmd, "bash");
            assert_eq!(args, vec!["-c"]);
        }
        
        // Test without shell hint (uses default)
        let (cmd, _args) = info.get_shell_command(None);
        assert!(!cmd.is_empty());
    }
    
    #[test]
    fn test_cached_os_info() {
        let info1 = get_os_info();
        let info2 = get_os_info();
        
        // Should return the same cached instance
        assert_eq!(info1 as *const _, info2 as *const _);
    }
}