//! OS detection and system information module
//! 
//! Provides detailed operating system detection including distribution,
//! version, architecture, and available package managers.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use std::fs;
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
        debug!("Starting OS detection");
        
        let os_type = Self::detect_os_type();
        debug!("Detected OS type: {:?}", os_type);
        
        let architecture = Self::detect_architecture();
        debug!("Detected architecture: {}", architecture);
        
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| {
                debug!("Failed to get hostname, using 'unknown'");
                "unknown".to_string()
            });
        debug!("Hostname: {}", hostname);
        
        let (version, kernel_version, linux_distro, windows_edition) = match os_type {
            OsType::Windows => {
                debug!("Detecting Windows version information");
                match Self::detect_windows_version() {
                    Ok((version, edition)) => {
                        debug!("Windows detection successful: {} - {}", version, edition);
                        (version, None, None, Some(edition))
                    },
                    Err(e) => {
                        debug!("Windows detection failed: {}, using fallback", e);
                        ("Windows (version detection failed)".to_string(), None, None, Some("Unknown Edition".to_string()))
                    }
                }
            },
            OsType::Linux => {
                debug!("Detecting Linux distribution information");
                match Self::detect_linux_info() {
                    Ok((version, kernel, distro)) => {
                        debug!("Linux detection successful: {} ({}), kernel: {}", version, format!("{:?}", distro), kernel);
                        (version, Some(kernel), Some(distro), None)
                    },
                    Err(e) => {
                        debug!("Linux detection failed: {}, using fallback", e);
                        ("Linux (detection failed)".to_string(), Some("unknown".to_string()), Some(crate::os_detection::LinuxDistro::Unknown("unknown".to_string())), None)
                    }
                }
            },
            OsType::Unknown => {
                debug!("Unknown OS type detected");
                ("unknown".to_string(), None, None, None)
            }
        };
        
        debug!("Detecting package managers");
        let available_package_managers = Self::detect_package_managers(&os_type, &linux_distro);
        debug!("Found package managers: {:?}", available_package_managers);
        
        debug!("Detecting default shell");
        let default_shell = Self::detect_default_shell(&os_type);
        debug!("Default shell: {:?}", default_shell);
        
        let os_info = OsInfo {
            os_type,
            version,
            kernel_version,
            architecture,
            hostname,
            linux_distro,
            windows_edition,
            available_package_managers,
            default_shell,
        };
        
        debug!("OS detection completed successfully");
        Ok(os_info)
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
    
    /// Detect Windows version and edition using native Windows APIs
    #[cfg(target_os = "windows")]
    fn detect_windows_version() -> Result<(String, String)> {
        use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOEXW};
        use std::mem;

        // First try RtlGetVersion (most reliable method)
        if let Ok((version, edition)) = Self::try_rtl_get_version() {
            return Ok((version, edition));
        }

        debug!("RtlGetVersion failed, falling back to GetVersionExW");

        // Fallback to GetVersionExW (deprecated but still works)
        unsafe {
            let mut osvi: OSVERSIONINFOEXW = mem::zeroed();
            osvi.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOEXW>() as u32;

            let success = GetVersionExW(&mut osvi as *mut _ as *mut _);
            if success.is_err() {
                debug!("GetVersionExW failed, using basic fallback");
                return Self::fallback_version_detection();
            }

            let version_string = format!(
                "{}.{}.{}",
                osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber
            );

            let edition = Self::determine_windows_edition(
                osvi.dwMajorVersion,
                osvi.dwMinorVersion,
                osvi.dwBuildNumber,
                osvi.wProductType,
            );

            debug!("Windows version detected: {} - {}", version_string, edition);
            Ok((version_string, edition))
        }
    }

    /// Try to use RtlGetVersion from ntdll.dll for accurate version info
    #[cfg(target_os = "windows")]
    fn try_rtl_get_version() -> Result<(String, String)> {
        use windows::{
            core::PCSTR,
            Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Win32::Foundation::NTSTATUS,
        };
        use std::mem;

        #[repr(C)]
        struct RTL_OSVERSIONINFOEXW {
            dw_os_version_info_size: u32,
            dw_major_version: u32,
            dw_minor_version: u32,
            dw_build_number: u32,
            dw_platform_id: u32,
            sz_csd_version: [u16; 128],
            w_service_pack_major: u16,
            w_service_pack_minor: u16,
            w_suite_mask: u16,
            w_product_type: u8,
            w_reserved: u8,
        }

        type RtlGetVersionFn = unsafe extern "system" fn(*mut RTL_OSVERSIONINFOEXW) -> NTSTATUS;

        unsafe {
            let ntdll = GetModuleHandleA(PCSTR::from_raw(b"ntdll.dll\0".as_ptr()))?;
            let rtl_get_version = GetProcAddress(
                ntdll,
                PCSTR::from_raw(b"RtlGetVersion\0".as_ptr())
            );

            if let Some(rtl_get_version) = rtl_get_version {
                let rtl_get_version: RtlGetVersionFn = mem::transmute(rtl_get_version);
                let mut osvi: RTL_OSVERSIONINFOEXW = mem::zeroed();
                osvi.dw_os_version_info_size = mem::size_of::<RTL_OSVERSIONINFOEXW>() as u32;

                let status = rtl_get_version(&mut osvi);
                if status.is_ok() {
                    let version_string = format!(
                        "{}.{}.{}",
                        osvi.dw_major_version, osvi.dw_minor_version, osvi.dw_build_number
                    );

                    let edition = Self::determine_windows_edition(
                        osvi.dw_major_version,
                        osvi.dw_minor_version,
                        osvi.dw_build_number,
                        osvi.w_product_type,
                    );

                    debug!("RtlGetVersion successful: {} - {}", version_string, edition);
                    return Ok((version_string, edition));
                }
            }
        }

        Err(anyhow::anyhow!("RtlGetVersion not available or failed"))
    }

    /// Determine Windows edition based on version numbers and product type
    #[cfg(target_os = "windows")]
    fn determine_windows_edition(major: u32, minor: u32, build: u32, product_type: u8) -> String {
        const VER_NT_WORKSTATION: u8 = 1;
        let is_workstation = product_type == VER_NT_WORKSTATION;

        match (major, minor) {
            (10, 0) => {
                if build >= 22000 {
                    if is_workstation { "Windows 11" } else { "Windows Server 2022" }
                } else if build >= 20348 {
                    "Windows Server 2022"
                } else if build >= 19041 {
                    if is_workstation { "Windows 10" } else { "Windows Server 2019" }
                } else if build >= 17763 {
                    if is_workstation { "Windows 10" } else { "Windows Server 2019" }
                } else {
                    if is_workstation { "Windows 10" } else { "Windows Server 2016" }
                }
            },
            (6, 3) => {
                if is_workstation { "Windows 8.1" } else { "Windows Server 2012 R2" }
            },
            (6, 2) => {
                if is_workstation { "Windows 8" } else { "Windows Server 2012" }
            },
            (6, 1) => {
                if is_workstation { "Windows 7" } else { "Windows Server 2008 R2" }
            },
            (6, 0) => {
                if is_workstation { "Windows Vista" } else { "Windows Server 2008" }
            },
            (5, 2) => "Windows XP 64-bit Edition",
            (5, 1) => "Windows XP",
            (5, 0) => "Windows 2000",
            _ => "Unknown Windows Version",
        }.to_string()
    }

    /// Fallback version detection using basic methods
    #[cfg(target_os = "windows")]
    fn fallback_version_detection() -> Result<(String, String)> {
        debug!("Using fallback version detection");
        
        // Try to read from registry as last resort
        if let Ok((version, edition)) = Self::try_registry_version() {
            return Ok((version, edition));
        }

        // Ultimate fallback
        Ok(("Windows".to_string(), "Unknown Edition".to_string()))
    }

    /// Try to read version from Windows Registry
    #[cfg(target_os = "windows")]
    fn try_registry_version() -> Result<(String, String)> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows::{
            core::PCWSTR,
            Win32::System::Registry::{
                RegOpenKeyExW, RegQueryValueExW, RegCloseKey,
                HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE
            },
            Win32::Foundation::ERROR_SUCCESS,
        };

        unsafe {
            let key_path: Vec<u16> = OsStr::new("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut hkey = Default::default();
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(key_path.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            ) != ERROR_SUCCESS {
                return Err(anyhow::anyhow!("Failed to open registry key"));
            }

            let mut version = String::new();
            let mut edition = String::new();

            // Try to get ProductName (edition)
            let product_name: Vec<u16> = OsStr::new("ProductName")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut buffer = vec![0u16; 256];
            let mut buffer_size = (buffer.len() * 2) as u32;
            let mut reg_type = REG_VALUE_TYPE(0);
            
            if RegQueryValueExW(
                hkey,
                PCWSTR::from_raw(product_name.as_ptr()),
                None,
                Some(&mut reg_type),
                Some(buffer.as_mut_ptr() as *mut u8),
                Some(&mut buffer_size),
            ) == ERROR_SUCCESS {
                let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
                edition = String::from_utf16_lossy(&buffer[..len]);
            }

            // Try to get CurrentBuild
            let current_build: Vec<u16> = OsStr::new("CurrentBuild")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            buffer_size = (buffer.len() * 2) as u32;
            if RegQueryValueExW(
                hkey,
                PCWSTR::from_raw(current_build.as_ptr()),
                None,
                Some(&mut reg_type),
                Some(buffer.as_mut_ptr() as *mut u8),
                Some(&mut buffer_size),
            ) == ERROR_SUCCESS {
                let len = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
                let build = String::from_utf16_lossy(&buffer[..len]);
                version = format!("10.0.{}", build); // Assume Windows 10/11 if we can read CurrentBuild
            }

            let _ = RegCloseKey(hkey);

            if !version.is_empty() && !edition.is_empty() {
                debug!("Registry version detection successful: {} - {}", version, edition);
                return Ok((version, edition));
            }
        }

        Err(anyhow::anyhow!("Failed to read version from registry"))
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
        debug!("Detecting package managers for OS type: {:?}", os_type);
        
        match os_type {
            OsType::Windows => {
                debug!("Checking Windows package managers");
                // Check for Windows package managers
                if Self::command_exists("winget") {
                    debug!("Found winget package manager");
                    managers.push(PackageManager::Winget);
                }
                if Self::command_exists("choco") {
                    debug!("Found chocolatey package manager");
                    managers.push(PackageManager::Chocolatey);
                }
                if Self::command_exists("scoop") {
                    debug!("Found scoop package manager");
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
    
    /// Check if a command exists in PATH using filesystem checks
    fn command_exists(cmd: &str) -> bool {
        Self::find_executable(cmd).is_some()
    }
    
    /// Find executable in PATH using filesystem operations
    fn find_executable(cmd: &str) -> Option<std::path::PathBuf> {
        let path_env = std::env::var("PATH").ok()?;
        let path_separator = if cfg!(target_os = "windows") { ';' } else { ':' };
        let executable_extensions = if cfg!(target_os = "windows") {
            vec!["", ".exe", ".bat", ".cmd", ".com"]
        } else {
            vec![""]
        };
        
        for path in path_env.split(path_separator) {
            let path = std::path::Path::new(path);
            if !path.exists() {
                continue;
            }
            
            for ext in &executable_extensions {
                let executable_path = if ext.is_empty() {
                    path.join(cmd)
                } else {
                    path.join(format!("{}{}", cmd, ext))
                };
                
                if executable_path.exists() && Self::is_executable(&executable_path) {
                    debug!("Found executable: {}", executable_path.display());
                    return Some(executable_path);
                }
            }
        }
        
        debug!("Executable not found: {}", cmd);
        None
    }
    
    /// Check if a file is executable
    fn is_executable(path: &std::path::Path) -> bool {
        #[cfg(target_os = "windows")]
        {
            // On Windows, if the file exists and has an executable extension, consider it executable
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                matches!(ext.to_lowercase().as_str(), "exe" | "bat" | "cmd" | "com")
            } else {
                false
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            use std::os::unix::fs::PermissionsExt;
            path.metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
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
    
    #[test]
    fn test_command_exists() {
        // Test with a command that should exist on most systems
        #[cfg(target_os = "linux")]
        assert!(OsInfo::command_exists("ls"));
        
        #[cfg(target_os = "windows")]
        assert!(OsInfo::command_exists("cmd"));
        
        // Test with a command that should not exist
        assert!(!OsInfo::command_exists("nonexistent_command_12345"));
    }
    
    #[test]
    fn test_find_executable() {
        // Test finding a basic command
        #[cfg(target_os = "linux")]
        {
            let result = OsInfo::find_executable("ls");
            assert!(result.is_some());
            let path = result.unwrap();
            assert!(path.exists());
            assert!(path.is_absolute());
        }
        
        #[cfg(target_os = "windows")]
        {
            let result = OsInfo::find_executable("cmd");
            assert!(result.is_some());
            let path = result.unwrap();
            assert!(path.exists());
            assert!(path.is_absolute());
        }
    }
    
    #[test]
    fn test_is_executable() {
        // Test with various file paths
        #[cfg(target_os = "linux")]
        {
            // Test with /bin/sh which should be executable
            let sh_path = std::path::Path::new("/bin/sh");
            if sh_path.exists() {
                assert!(OsInfo::is_executable(sh_path));
            }
            
            // Test with /etc/hosts which should not be executable
            let hosts_path = std::path::Path::new("/etc/hosts");
            if hosts_path.exists() {
                assert!(!OsInfo::is_executable(hosts_path));
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // Test Windows executable detection
            let cmd_path = std::path::Path::new("cmd.exe");
            if let Some(full_path) = OsInfo::find_executable("cmd") {
                assert!(OsInfo::is_executable(&full_path));
            }
        }
    }
    
    #[test]
    fn test_package_manager_detection() {
        let info = OsInfo::detect().unwrap();
        
        // Should detect at least some package managers on most systems
        match info.os_type {
            OsType::Linux => {
                // On Linux, we should find at least one package manager
                assert!(!info.available_package_managers.is_empty());
            },
            OsType::Windows => {
                // On Windows, might not have any package managers installed
                // Just verify the detection doesn't crash
                let _managers = &info.available_package_managers;
            },
            _ => {}
        }
    }
    
    #[test]
    fn test_shell_detection() {
        let info = OsInfo::detect().unwrap();
        
        match info.os_type {
            OsType::Linux => {
                // Should detect a reasonable shell
                assert!(matches!(info.default_shell, 
                    ShellType::Bash | ShellType::Sh | ShellType::Zsh | ShellType::Fish));
            },
            OsType::Windows => {
                // Should detect cmd or PowerShell
                assert!(matches!(info.default_shell, 
                    ShellType::Cmd | ShellType::PowerShell));
            },
            _ => {}
        }
    }
    
    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_edition_detection() {
        let edition = OsInfo::determine_windows_edition(10, 0, 19041, 1);
        assert_eq!(edition, "Windows 10");
        
        let edition = OsInfo::determine_windows_edition(10, 0, 22000, 1);
        assert_eq!(edition, "Windows 11");
        
        let edition = OsInfo::determine_windows_edition(6, 1, 7601, 1);
        assert_eq!(edition, "Windows 7");
        
        // Test server edition
        let edition = OsInfo::determine_windows_edition(10, 0, 19041, 2);
        assert_eq!(edition, "Windows Server 2019");
    }
    
    #[test]
    fn test_path_parsing() {
        // Test PATH environment variable parsing logic
        std::env::set_var("TEST_PATH", "/usr/bin:/bin:/usr/local/bin");
        
        let path_env = std::env::var("TEST_PATH").unwrap();
        let paths: Vec<&str> = path_env.split(':').collect();
        
        assert_eq!(paths.len(), 3);
        assert!(paths.contains(&"/usr/bin"));
        assert!(paths.contains(&"/bin"));
        assert!(paths.contains(&"/usr/local/bin"));
    }
    
    #[test] 
    fn test_version_string_formatting() {
        // Test version string construction
        let version = format!("{}.{}.{}", 10, 0, 19041);
        assert_eq!(version, "10.0.19041");
        
        let version = format!("{}.{}.{}", 6, 1, 7601);
        assert_eq!(version, "6.1.7601");
    }
    
    #[test]
    fn test_os_info_serialization() {
        let info = OsInfo::detect().unwrap();
        
        // Test that OsInfo can be serialized
        let serialized = serde_json::to_string(&info);
        assert!(serialized.is_ok());
        
        // Test that it can be deserialized back
        let json_str = serialized.unwrap();
        let deserialized: Result<OsInfo, _> = serde_json::from_str(&json_str);
        assert!(deserialized.is_ok());
        
        let deserialized_info = deserialized.unwrap();
        assert_eq!(info.os_type, deserialized_info.os_type);
        assert_eq!(info.architecture, deserialized_info.architecture);
        assert_eq!(info.hostname, deserialized_info.hostname);
    }
}