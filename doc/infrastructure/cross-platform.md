# Cross-Platform Implementation

## Overview

InfiniService is designed to run seamlessly on both Linux and Windows platforms. This document details the platform-specific implementations and abstractions used to achieve cross-platform compatibility.

## Platform Detection

### Compile-Time Detection

```rust
// Conditional compilation based on target OS
#[cfg(target_os = "linux")]
const PLATFORM: &str = "linux";

#[cfg(target_os = "windows")]
const PLATFORM: &str = "windows";

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("Unsupported platform");
```

### Runtime Detection

```rust
// src/os_detection.rs
pub fn detect_platform() -> Platform {
    if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::Unknown
    }
}

pub fn get_os_info() -> OsInfo {
    OsInfo {
        name: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        family: std::env::consts::FAMILY,
        version: get_os_version(),
    }
}
```

## Platform Abstractions

### Service Management

```rust
// Platform-agnostic service trait
pub trait ServiceManager {
    fn start(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn restart(&self) -> Result<()>;
    fn status(&self) -> Result<ServiceStatus>;
}

#[cfg(target_os = "linux")]
pub struct SystemdManager;

#[cfg(target_os = "windows")]
pub struct WindowsServiceManager;

impl ServiceManager for SystemdManager {
    fn start(&self) -> Result<()> {
        Command::new("systemctl")
            .args(&["start", &self.name])
            .output()
            .map(|_| ())
    }
    // ...
}

impl ServiceManager for WindowsServiceManager {
    fn start(&self) -> Result<()> {
        // Windows Service API calls
    }
    // ...
}
```

### Metrics Collection

#### Linux Implementation

```rust
#[cfg(target_os = "linux")]
mod linux_collector {
    use std::fs;
    use procfs::Process;
    
    pub fn collect_cpu_metrics() -> Result<CpuMetrics> {
        // Read from /proc/stat
        let stat = fs::read_to_string("/proc/stat")?;
        parse_cpu_stat(&stat)
    }
    
    pub fn collect_memory_metrics() -> Result<MemoryMetrics> {
        // Read from /proc/meminfo
        let meminfo = fs::read_to_string("/proc/meminfo")?;
        parse_meminfo(&meminfo)
    }
    
    pub fn collect_disk_metrics() -> Result<DiskMetrics> {
        // Read from /proc/diskstats and /sys/block/
        let diskstats = fs::read_to_string("/proc/diskstats")?;
        parse_diskstats(&diskstats)
    }
    
    pub fn collect_network_metrics() -> Result<NetworkMetrics> {
        // Read from /proc/net/dev
        let netdev = fs::read_to_string("/proc/net/dev")?;
        parse_netdev(&netdev)
    }
}
```

#### Windows Implementation

```rust
#[cfg(target_os = "windows")]
mod windows_collector {
    use wmi::{COMLibrary, WMIConnection};
    use windows::Win32::System::Performance::*;
    
    pub fn collect_cpu_metrics() -> Result<CpuMetrics> {
        let com = COMLibrary::new()?;
        let wmi = WMIConnection::new(com)?;
        
        let results: Vec<Win32_Processor> = wmi.query()?;
        convert_wmi_cpu_data(results)
    }
    
    pub fn collect_memory_metrics() -> Result<MemoryMetrics> {
        let mut status = MEMORYSTATUSEX::default();
        unsafe {
            GlobalMemoryStatusEx(&mut status);
        }
        convert_memory_status(status)
    }
    
    pub fn collect_disk_metrics() -> Result<DiskMetrics> {
        let results: Vec<Win32_PerfRawData_PerfDisk_PhysicalDisk> = 
            wmi.query()?;
        convert_disk_data(results)
    }
    
    pub fn collect_network_metrics() -> Result<NetworkMetrics> {
        let results: Vec<Win32_NetworkAdapter> = wmi.query()?;
        convert_network_data(results)
    }
}
```

## Device Communication

### Linux VirtIO Access

```rust
#[cfg(target_os = "linux")]
impl VirtioSerial {
    pub fn open(&mut self) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&self.device_path)?;
            
        self.device = Some(file);
        Ok(())
    }
    
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        use std::os::unix::io::AsRawFd;
        
        let fd = self.device.as_raw_fd();
        let n = unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len())
        };
        
        if n < 0 {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(n as usize)
        }
    }
}
```

### Windows COM Port Access

```rust
#[cfg(target_os = "windows")]
impl VirtioSerial {
    pub fn open(&mut self) -> Result<()> {
        use serialport::SerialPort;
        
        let port = serialport::new(&self.device_path, 115200)
            .timeout(Duration::from_millis(100))
            .flow_control(FlowControl::None)
            .open()?;
            
        self.port = Some(port);
        Ok(())
    }
    
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.port.as_mut()
            .ok_or_else(|| anyhow!("Port not open"))?
            .read(buf)
            .map_err(Into::into)
    }
}
```

## Process Management

### Linux Process Operations

```rust
#[cfg(target_os = "linux")]
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    use procfs::process::all_processes;
    
    let mut processes = Vec::new();
    
    for process in all_processes()? {
        if let Ok(proc) = process {
            let stat = proc.stat()?;
            processes.push(ProcessInfo {
                pid: proc.pid,
                name: stat.comm,
                cpu_usage: calculate_cpu_usage(&stat),
                memory_kb: stat.rss * 4, // Pages to KB
                status: format!("{:?}", stat.state),
            });
        }
    }
    
    Ok(processes)
}

#[cfg(target_os = "linux")]
pub fn kill_process(pid: u32, force: bool) -> Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    
    let signal = if force { Signal::SIGKILL } else { Signal::SIGTERM };
    kill(Pid::from_raw(pid as i32), signal)?;
    Ok(())
}
```

### Windows Process Operations

```rust
#[cfg(target_os = "windows")]
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?
    };
    
    let mut processes = Vec::new();
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    
    if unsafe { Process32FirstW(snapshot, &mut entry) }.as_bool() {
        loop {
            processes.push(convert_process_entry(&entry)?);
            
            if !unsafe { Process32NextW(snapshot, &mut entry) }.as_bool() {
                break;
            }
        }
    }
    
    Ok(processes)
}

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32, force: bool) -> Result<()> {
    use windows::Win32::System::Threading::*;
    
    let handle = unsafe {
        OpenProcess(PROCESS_TERMINATE, false, pid)?
    };
    
    unsafe {
        TerminateProcess(handle, 1)?;
        CloseHandle(handle);
    }
    
    Ok(())
}
```

## Package Management

### Linux Package Managers

```rust
#[cfg(target_os = "linux")]
pub fn detect_package_manager() -> PackageManager {
    if Path::new("/usr/bin/apt").exists() {
        PackageManager::Apt
    } else if Path::new("/usr/bin/yum").exists() {
        PackageManager::Yum
    } else if Path::new("/usr/bin/dnf").exists() {
        PackageManager::Dnf
    } else if Path::new("/usr/bin/pacman").exists() {
        PackageManager::Pacman
    } else {
        PackageManager::Unknown
    }
}

#[cfg(target_os = "linux")]
pub fn install_package(name: &str) -> Result<()> {
    let pm = detect_package_manager();
    match pm {
        PackageManager::Apt => {
            Command::new("apt-get")
                .args(&["install", "-y", name])
                .output()?;
        }
        PackageManager::Yum => {
            Command::new("yum")
                .args(&["install", "-y", name])
                .output()?;
        }
        // ...
    }
    Ok(())
}
```

### Windows Package Management

```rust
#[cfg(target_os = "windows")]
pub fn detect_package_manager() -> PackageManager {
    if command_exists("winget") {
        PackageManager::WinGet
    } else if command_exists("choco") {
        PackageManager::Chocolatey
    } else {
        PackageManager::Unknown
    }
}

#[cfg(target_os = "windows")]
pub fn install_package(name: &str) -> Result<()> {
    let pm = detect_package_manager();
    match pm {
        PackageManager::WinGet => {
            Command::new("winget")
                .args(&["install", "--silent", name])
                .output()?;
        }
        PackageManager::Chocolatey => {
            Command::new("choco")
                .args(&["install", "-y", name])
                .output()?;
        }
        // ...
    }
    Ok(())
}
```

## File System Operations

### Path Handling

```rust
use std::path::{Path, PathBuf};

pub fn get_config_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/etc/infiniservice")
    }
    
    #[cfg(target_os = "windows")]
    {
        PathBuf::from("C:\\ProgramData\\InfiniService")
    }
}

pub fn get_log_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/log/infiniservice")
    }
    
    #[cfg(target_os = "windows")]
    {
        PathBuf::from("C:\\Windows\\Logs\\InfiniService")
    }
}
```

### File Permissions

```rust
#[cfg(target_os = "linux")]
pub fn set_file_permissions(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    
    let permissions = Permissions::from_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn set_file_permissions(path: &Path, readonly: bool) -> Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(readonly);
    fs::set_permissions(path, permissions)?;
    Ok(())
}
```

## Network Operations

### Socket Creation

```rust
#[cfg(target_os = "linux")]
pub fn create_unix_socket(path: &Path) -> Result<UnixStream> {
    UnixStream::connect(path).map_err(Into::into)
}

#[cfg(target_os = "windows")]
pub fn create_named_pipe(name: &str) -> Result<NamedPipe> {
    let pipe_name = format!("\\\\.\\pipe\\{}", name);
    NamedPipe::new(&pipe_name).map_err(Into::into)
}
```

## Command Execution

### Shell Selection

```rust
pub fn get_default_shell() -> (&'static str, Vec<&'static str>) {
    #[cfg(target_os = "linux")]
    {
        if Path::new("/bin/bash").exists() {
            ("bash", vec!["-c"])
        } else {
            ("sh", vec!["-c"])
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        ("powershell.exe", vec!["-NoProfile", "-Command"])
    }
}

pub fn execute_command(cmd: &str) -> Result<Output> {
    let (shell, args) = get_default_shell();
    
    Command::new(shell)
        .args(&args)
        .arg(cmd)
        .output()
        .map_err(Into::into)
}
```

## Testing Strategies

### Platform-Specific Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_specific_feature() {
        // Linux-only test
    }
    
    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_specific_feature() {
        // Windows-only test
    }
    
    #[test]
    fn test_cross_platform_feature() {
        // Works on all platforms
    }
}
```

### Mock Platform Detection

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_with_mock_platform() {
        std::env::set_var("INFINISERVICE_TEST_PLATFORM", "linux");
        assert_eq!(detect_platform(), Platform::Linux);
        
        std::env::set_var("INFINISERVICE_TEST_PLATFORM", "windows");
        assert_eq!(detect_platform(), Platform::Windows);
    }
}
```

## Build Configuration

### Cargo.toml Platform Dependencies

```toml
[target.'cfg(target_os = "linux")'.dependencies]
procfs = "0.17"
nix = "0.29"

[target.'cfg(target_os = "windows")'.dependencies]
winapi = { version = "0.3", features = ["winuser", "processthreadsapi"] }
windows-service = "0.8"
serialport = "4.2"
wmi = "0.13"
```

### Build Scripts

```rust
// build.rs
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    match target_os.as_str() {
        "linux" => {
            println!("cargo:rustc-link-lib=systemd");
        }
        "windows" => {
            println!("cargo:rustc-link-lib=advapi32");
            println!("cargo:rustc-link-lib=userenv");
        }
        _ => {}
    }
}
```

## Best Practices

1. **Use Platform Abstractions**: Create traits for platform-specific behavior
2. **Minimize Platform-Specific Code**: Isolate in separate modules
3. **Test on All Platforms**: Use CI/CD for multi-platform testing
4. **Handle Platform Differences Gracefully**: Provide fallbacks
5. **Document Platform Requirements**: Clear dependency documentation
6. **Use Cross-Platform Libraries**: When possible (e.g., sysinfo)
7. **Consistent Error Handling**: Same error types across platforms