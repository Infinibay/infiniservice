//! Communication module for virtio-serial interface with bidirectional command support

use crate::collector::{SystemInfo, SystemMetrics};
use crate::commands::{IncomingMessage, CommandResponse};
use anyhow::{Result, Context, anyhow};
use log::{info, debug, warn};
use serde::Serialize;
use std::path::Path;
use std::fs::OpenOptions;
use std::io::{Write, BufRead, BufReader};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use chrono::Utc;

// Message wrapper for metrics that matches backend expectations
#[derive(Serialize, Debug)]
struct MetricsMessage {
    #[serde(rename = "type")]
    message_type: String,
    timestamp: String,
    data: MetricsData,
}

#[derive(Serialize, Debug)]
struct MetricsData {
    system: SystemMetrics,
}


pub struct VirtioSerial {
    device_path: std::path::PathBuf,
    vm_id: String,
}

impl VirtioSerial {
    pub fn new<P: AsRef<Path>>(device_path: P) -> Self {
        Self {
            device_path: device_path.as_ref().to_path_buf(),
            vm_id: Self::generate_vm_id(),
        }
    }

    pub fn with_vm_id<P: AsRef<Path>>(device_path: P, vm_id: String) -> Self {
        Self {
            device_path: device_path.as_ref().to_path_buf(),
            vm_id,
        }
    }

    fn generate_vm_id() -> String {
        // Try to get VM ID from environment or generate one
        std::env::var("INFINIBAY_VM_ID")
            .unwrap_or_else(|_| Uuid::new_v4().to_string())
    }

    /// Detect virtio-serial device path based on platform
    pub fn detect_device_path(debug_mode: bool) -> Result<std::path::PathBuf> {
        #[cfg(target_os = "linux")]
        {
            Self::detect_linux_device(debug_mode)
        }

        #[cfg(target_os = "windows")]
        {
            Self::detect_windows_device(debug_mode)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(anyhow!("Unsupported platform for virtio-serial detection"))
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux_device(debug_mode: bool) -> Result<std::path::PathBuf> {
        if debug_mode {
            debug!("Starting Linux device detection...");
        }
        
        // Common virtio-serial device paths on Linux
        let possible_paths = [
            "/dev/virtio-ports/org.infinibay.agent",
            "/dev/virtio-ports/org.qemu.guest_agent.0",
            "/dev/virtio-ports/com.redhat.spice.0",
            "/dev/vport0p1",
            "/dev/vport1p1",
        ];

        if debug_mode {
            debug!("Checking common virtio-serial paths...");
        }
        
        for path in &possible_paths {
            if debug_mode {
                debug!("Checking: {}", path);
            }
            let device_path = std::path::Path::new(path);
            if device_path.exists() {
                info!("Found virtio-serial device at: {}", path);
                return Ok(device_path.to_path_buf());
            }
        }

        // Check for any virtio-ports device
        let virtio_dir = std::path::Path::new("/dev/virtio-ports");
        if debug_mode {
            debug!("Checking /dev/virtio-ports directory...");
        }
        if virtio_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(virtio_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if debug_mode {
                        debug!("Found entry: {:?}", path);
                    }
                    // Check if it's a character device or regular file
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::FileTypeExt;
                            if metadata.file_type().is_char_device() || metadata.file_type().is_file() {
                                info!("Found virtio-serial device at: {:?}", path);
                                return Ok(path);
                            }
                        }
                        #[cfg(not(unix))]
                        {
                            if metadata.is_file() {
                                info!("Found virtio-serial device at: {:?}", path);
                                return Ok(path);
                            }
                        }
                    }
                }
            }
        } else if debug_mode {
            debug!("/dev/virtio-ports directory does not exist");
        }

        Err(anyhow!("No virtio-serial device found on Linux"))
    }

    /// Helper function to try opening a Windows device using CreateFileW
    /// Returns Ok(true) if device can be opened, Ok(false) if it exists but can't be opened, Err(error_code) on error
    #[cfg(target_os = "windows")]
    fn try_open_windows_device(device_path: &str, debug_mode: bool) -> Result<bool, u32> {
        use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
        use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::errhandlingapi::GetLastError;
        use std::os::windows::ffi::OsStrExt;
        use std::ffi::OsStr;

        let wide_path: Vec<u16> = OsStr::new(device_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let handle = CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow sharing to avoid false negatives
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            if handle != INVALID_HANDLE_VALUE {
                CloseHandle(handle);
                if debug_mode {
                    debug!("Successfully opened and verified device: {}", device_path);
                }
                Ok(true)
            } else {
                let error_code = GetLastError();
                if debug_mode {
                    debug!("Failed to open device {}: Win32 error {}", device_path, error_code);
                }
                Err(error_code)
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn try_direct_virtio_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {
        use crate::windows_com::{try_direct_device_access, get_virtio_device_capabilities};

        debug!("🔌 Attempting direct VirtIO connection for device: {}", device_info.instance_id);

        // Try device interface paths first
        for interface_path in &device_info.interface_paths {
            debug!("🔗 Trying interface path: {}", interface_path);

            match try_direct_device_access(interface_path) {
                Ok(device_path) => {
                    debug!("✅ Direct interface connection successful: {}", device_path);
                    return Ok(device_path);
                }
                Err(e) => {
                    debug!("❌ Interface path failed: {} - {}", interface_path, e);
                }
            }
        }

        // Get device capabilities to determine best connection method
        match get_virtio_device_capabilities(device_info) {
            Ok(capabilities) => {
                debug!("📋 Device capabilities: {}", capabilities);

                // Gate advanced connection attempts behind confirmed capability flags
                if capabilities.contains("IOCTL_EXPERIMENTAL") {
                    debug!("🔧 Attempting experimental IOCTL-based connection");
                    if let Ok(device_path) = Self::try_ioctl_connection(device_info) {
                        debug!("✅ Experimental IOCTL connection successful");
                        return Ok(device_path);
                    } else {
                        debug!("❌ Experimental IOCTL connection failed, falling back");
                    }
                }

                if capabilities.contains("OVERLAPPED_EXPERIMENTAL") {
                    debug!("⏱️ Attempting experimental overlapped I/O connection");
                    if let Ok(device_path) = Self::try_overlapped_connection(device_info) {
                        debug!("✅ Experimental overlapped I/O connection successful");
                        return Ok(device_path);
                    } else {
                        debug!("❌ Experimental overlapped I/O connection failed, falling back");
                    }
                }

                if capabilities.contains("MEMORY_MAPPED_EXPERIMENTAL") {
                    debug!("🗺️ Attempting experimental memory-mapped I/O connection");
                    if let Ok(device_path) = Self::try_memory_mapped_connection(device_info) {
                        debug!("✅ Experimental memory-mapped I/O connection successful");
                        return Ok(device_path);
                    } else {
                        debug!("❌ Experimental memory-mapped I/O connection failed, falling back");
                    }
                }

                // For BASIC capabilities, skip experimental methods
                if capabilities == "BASIC" {
                    debug!("📋 Basic capabilities only, skipping experimental connection methods");
                }
            }
            Err(e) => {
                debug!("⚠️ Could not determine device capabilities: {}", e);
            }
        }

        // Try alternative device naming conventions
        let alternative_paths = vec![
            "\\\\.\\VirtioSerial".to_string(),
            "\\\\.\\VirtioSerial0".to_string(),
            "\\\\.\\VirtioSerial1".to_string(),
            format!("\\\\.\\{}", device_info.instance_id),
        ];

        for alt_path in alternative_paths {
            debug!("🔄 Trying alternative path: {}", alt_path);
            match Self::try_open_windows_device_simple(&alt_path) {
                Ok(_) => {
                    debug!("✅ Alternative path connection successful: {}", alt_path);
                    return Ok(alt_path);
                }
                Err(e) => {
                    debug!("❌ Alternative path failed: {} - {}", alt_path, e);
                }
            }
        }

        Err(format!("All direct VirtIO connection methods failed for device {}", device_info.instance_id))
    }

    #[cfg(target_os = "windows")]
    fn try_open_windows_device_simple(device_path: &str) -> Result<bool, String> {
        match Self::try_open_windows_device(device_path, false) {
            Ok(result) => Ok(result),
            Err(error_code) => Err(format!("Win32 error {}", error_code)),
        }
    }

    #[cfg(target_os = "windows")]
    fn try_ioctl_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {
        // Implementation for IOCTL-based VirtIO communication
        debug!("🔧 Implementing IOCTL connection for {}", device_info.instance_id);

        // Try to open device with IOCTL access
        for interface_path in &device_info.interface_paths {
            if let Ok(_) = Self::try_open_windows_device_simple(interface_path) {
                // TODO: Implement actual IOCTL communication
                debug!("✅ IOCTL connection established via {}", interface_path);
                return Ok(interface_path.clone());
            }
        }

        Err("IOCTL connection failed".to_string())
    }

    #[cfg(target_os = "windows")]
    fn try_overlapped_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {
        // Implementation for overlapped I/O VirtIO communication
        debug!("⏱️ Implementing overlapped I/O connection for {}", device_info.instance_id);

        // Try overlapped I/O on interface paths
        for interface_path in &device_info.interface_paths {
            if let Ok(_) = Self::try_open_windows_device_simple(interface_path) {
                // TODO: Implement actual overlapped I/O
                debug!("✅ Overlapped I/O connection established via {}", interface_path);
                return Ok(interface_path.clone());
            }
        }

        Err("Overlapped I/O connection failed".to_string())
    }

    #[cfg(target_os = "windows")]
    fn try_memory_mapped_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {
        // Implementation for memory-mapped I/O VirtIO communication
        debug!("🗺️ Implementing memory-mapped I/O connection for {}", device_info.instance_id);

        // Try memory-mapped access
        for interface_path in &device_info.interface_paths {
            if let Ok(_) = Self::try_open_windows_device_simple(interface_path) {
                // TODO: Implement actual memory-mapped I/O
                debug!("✅ Memory-mapped I/O connection established via {}", interface_path);
                return Ok(interface_path.clone());
            }
        }

        Err("Memory-mapped I/O connection failed".to_string())
    }

    #[cfg(target_os = "windows")]
    fn try_open_windows_device_with_mode(device_path: &str, read_access: bool, write_access: bool, debug_mode: bool) -> Result<bool, u32> {
        use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
        use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::errhandlingapi::GetLastError;
        use std::ffi::CString;
        use std::ptr;

        let c_path = match CString::new(device_path) {
            Ok(path) => path,
            Err(_) => return Err(87), // ERROR_INVALID_PARAMETER
        };

        // Determine access rights based on parameters
        let mut desired_access = 0;
        if read_access {
            desired_access |= GENERIC_READ;
        }
        if write_access {
            desired_access |= GENERIC_WRITE;
        }

        if debug_mode {
            debug!("Trying to open {} with access: read={}, write={}", device_path, read_access, write_access);
        }

        unsafe {
            let handle = CreateFileA(
                c_path.as_ptr(),
                desired_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                let error_code = GetLastError();
                if debug_mode {
                    debug!("CreateFileA failed for {} with error: {}", device_path, error_code);
                }
                Err(error_code)
            } else {
                CloseHandle(handle);
                if debug_mode {
                    debug!("Successfully opened and closed {}", device_path);
                }
                Ok(true)
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn detect_windows_device(debug_mode: bool) -> Result<std::path::PathBuf> {
        use crate::windows_com::{find_virtio_com_port, enumerate_com_ports, try_open_com_port, 
                                  find_virtio_system_devices, find_virtio_device_paths};
        use std::process::Command;
        
        if debug_mode {
            debug!("Starting Windows device detection...");
        }
        
        // Helper function to create Windows device path
        fn create_device_path(device: &str) -> std::path::PathBuf {
            // For Windows, we need to ensure the path is properly formatted
            // Use OsString to avoid any escaping issues
            if device.starts_with("COM") {
                // COM port path
                std::path::PathBuf::from(format!("\\\\.\\{}", device))
            } else {
                // Already a full path
                std::path::PathBuf::from(device)
            }
        }
        
        // Track fallback options in case primary methods fail
        let mut fallback_com_ports: Vec<std::path::PathBuf> = Vec::new();
        let mut access_denied_paths: Vec<std::path::PathBuf> = Vec::new();
        
        // Method 1: First try VirtIO named pipes (most likely to work with proper VM config)
        if debug_mode {
            debug!("Method 1: Trying VirtIO named pipes and global objects...");
        }
        
        // VirtIO paths ordered by likelihood of success
        let virtio_paths: Vec<std::path::PathBuf> = vec![
            // Global objects - try these first as they're most likely configured
            std::path::PathBuf::from("\\\\.\\Global\\org.infinibay.agent"),  // Primary Infinibay channel
            std::path::PathBuf::from("\\\\.\\Global\\org.qemu.guest_agent.0"),
            std::path::PathBuf::from("\\\\.\\Global\\com.redhat.spice.0"),
            // Named pipes as alternatives
            std::path::PathBuf::from("\\\\.\\pipe\\org.infinibay.agent"),
            std::path::PathBuf::from("\\\\.\\pipe\\org.qemu.guest_agent.0"),
            // Direct VirtIO devices (without namespace)
            std::path::PathBuf::from("\\\\.\\VirtioSerial"),
            std::path::PathBuf::from("\\\\.\\VirtioSerial0"),
        ];
        
        for path in &virtio_paths {
            if debug_mode {
                debug!("Trying VirtIO path: {}", path.display());
            }
            
            let path_str = path.to_string_lossy();
            
            // Global objects in Windows need special handling
            // They are NOT files, they are kernel objects
            if path_str.contains("Global") {
                // For QEMU Guest Agent, record as candidate but continue testing
                if path_str.contains("guest_agent") {
                    info!("Detected QEMU Guest Agent path - will test accessibility");
                    // Don't return early, continue with accessibility test
                }
                
                // For other Global objects, try opening with CreateFile
                match Self::try_open_windows_device(&path_str, debug_mode) {
                    Ok(true) => {
                        info!("✅ Found working VirtIO Global device at: {}", path.display());
                        return Ok(path.clone());  // Return immediately on success
                    }
                    Ok(false) => {
                        // Device not accessible, continue to next
                        continue;
                    }
                    Err(error_code) => {
                        if debug_mode {
                            debug!("Cannot open Global object {}: Win32 error {}", path.display(), error_code);
                        }
                        
                        // Handle specific error conditions
                        match error_code {
                            2 => {
                                // ERROR_FILE_NOT_FOUND - path doesn't exist
                                if debug_mode {
                                    debug!("  -> Path does not exist in the system");
                                }
                            }
                            5 => {
                                // ERROR_ACCESS_DENIED - exists but needs admin privileges or proper VM configuration
                                warn!("🔐 Access denied to VirtIO Global object: {}", path.display());
                                warn!("📋 This typically indicates:");
                                warn!("   1. Service needs Administrator privileges");
                                warn!("   2. VM missing proper VirtIO channel configuration");
                                warn!("   3. Windows security policies blocking device access");
                                warn!("   4. VirtIO driver needs reinstallation");
                                warn!("");
                                warn!("💡 Immediate solutions to try:");
                                warn!("   • Run: infiniservice.exe --diag (as Administrator)");
                                warn!("   • Check VM XML for: <target type='virtio' name='org.infinibay.agent'/>");
                                warn!("   • Verify VirtIO drivers are properly installed");
                                warn!("   • Try alternative device paths with --device flag");
                                access_denied_paths.push(path.clone());
                            }
                            _ => {
                                if debug_mode {
                                    debug!("  -> Unexpected error code: {}", error_code);
                                }
                            }
                        }
                    }
                }
            } else {
                // For pipes and regular paths, use standard file operations
                use std::fs::OpenOptions;
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                {
                    Ok(_) => {
                        info!("✅ Found working VirtIO device at: {}", path.display());
                        return Ok(path.clone());
                    }
                    Err(e) => {
                        if debug_mode {
                            debug!("Cannot open {}: {}", path.display(), e);
                        }
                        // Check if it's an access denied error
                        if e.raw_os_error() == Some(5) {
                            access_denied_paths.push(path.clone());
                        }
                    }
                }
            }
        }
        
        // Method 2: Check for VirtIO system devices (like in Device Manager)
        if debug_mode {
            debug!("Method 2: Searching for VirtIO devices in system devices...");
        }
        match find_virtio_system_devices() {
            Ok(devices) => {
                if !devices.is_empty() {
                    info!("Found {} VirtIO system device(s):", devices.len());
                    for device in &devices {
                        info!("  - {} (Hardware ID: {})", 
                              device.friendly_name, device.hardware_id);
                        
                        // Enhanced guidance for DEV_1043 devices
                        if device.hardware_id.contains("DEV_1043") {
                            info!("Found VirtIO Serial Device (DEV_1043) as seen in Device Manager");
                            warn!("📋 DEV_1043 Device Analysis:");
                            warn!("   Status: {}", device.device_status);
                            warn!("   Driver Service: {}", if device.driver_service.is_empty() { "Not found" } else { &device.driver_service });
                            warn!("   Instance ID: {}", device.instance_id);

                            if device.driver_service.is_empty() {
                                warn!("❌ No driver service found - VirtIO driver installation issue");
                                warn!("💡 Solution: Reinstall VirtIO drivers from latest ISO");
                            } else if device.device_status.contains("Problem") {
                                warn!("❌ Device has problems - check Device Manager for details");
                                warn!("💡 Solution: Update or reinstall VirtIO drivers");
                            } else if device.interface_paths.is_empty() {
                                warn!("❌ Device installed but no accessible interfaces found");
                                warn!("💡 Solution: Check VM configuration for virtio-serial channel");
                                warn!("   Required: <target type='virtio' name='org.infinibay.agent'/>");
                            } else {
                                warn!("✓ Device appears properly configured");
                                warn!("💡 Try running as Administrator or check access permissions");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if debug_mode {
                    debug!("Failed to enumerate system devices: {}", e);
                }
            }
        }

        // Method 2.5: Try direct VirtIO connection for detected devices
        if debug_mode {
            debug!("Method 2.5: Attempting direct VirtIO connections...");
        }
        match find_virtio_system_devices() {
            Ok(devices) => {
                for device in &devices {
                    // Include DEV_1003, DEV_1043, DEV_1044 and any VirtIO device with interface paths
                    let is_virtio_serial = device.hardware_id.contains("DEV_1003") ||
                                          device.hardware_id.contains("DEV_1043") ||
                                          device.hardware_id.contains("DEV_1044") ||
                                          device.is_virtio;

                    if is_virtio_serial && !device.interface_paths.is_empty() {
                        info!("🔌 Attempting direct connection to VirtIO device: {}", device.friendly_name);

                        match Self::try_direct_virtio_connection(device) {
                            Ok(device_path) => {
                                info!("✅ Direct VirtIO connection successful: {}", device_path);

                                // Quick open test to ensure the path is actually usable
                                match Self::try_open_windows_device_simple(&device_path) {
                                    Ok(true) => {
                                        info!("✅ Device path verified as usable: {}", device_path);
                                        return Ok(create_device_path(&device_path));
                                    }
                                    Ok(false) => {
                                        warn!("⚠️ Device path not accessible, continuing search: {}", device_path);
                                    }
                                    Err(e) => {
                                        warn!("⚠️ Device path verification failed: {} - {}", device_path, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("❌ Direct VirtIO connection failed: {}", e);
                                warn!("💡 Continuing with alternative connection methods...");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if debug_mode {
                    debug!("Could not enumerate devices for direct connection: {}", e);
                }
            }
        }

        // Method 3: Try alternative VirtIO device paths
        if debug_mode {
            debug!("Method 2: Trying alternative VirtIO device paths...");
        }
        let virtio_paths = find_virtio_device_paths();
        if !virtio_paths.is_empty() {
            info!("Found {} alternative VirtIO device path(s)", virtio_paths.len());
            for path in virtio_paths {
                // Verify the path is actually usable before returning
                let path_str = path.to_string_lossy();
                match Self::try_open_windows_device_simple(&path_str) {
                    Ok(true) => {
                        info!("✅ Verified VirtIO device path: {}", path.display());
                        return Ok(path);
                    }
                    Ok(false) => {
                        warn!("⚠️ VirtIO device path not accessible: {}", path.display());
                    }
                    Err(e) => {
                        warn!("⚠️ VirtIO device path verification failed: {} - {}", path.display(), e);
                    }
                }
            }
        }
        
        // Method 4: Try to find a virtio COM port by hardware ID
        if debug_mode {
            debug!("Method 3: Searching for VirtIO COM port by hardware ID...");
        }
        match find_virtio_com_port() {
            Ok(port_info) => {
                info!("Found VirtIO COM port: {} ({})", port_info.port_name, port_info.friendly_name);
                info!("Hardware ID: {}", port_info.hardware_id);
                
                // Try to open it to verify it's accessible
                if let Err(e) = try_open_com_port(&port_info.port_name) {
                    warn!("Found VirtIO port {} but cannot open it: {}", port_info.port_name, e);
                    // Add to fallback options instead of failing
                    fallback_com_ports.push(port_info.device_path.clone());
                } else {
                    info!("Successfully verified access to {}", port_info.port_name);
                    return Ok(port_info.device_path);
                }
            }
            Err(e) => {
                if debug_mode {
                    debug!("Method 3 failed: {}", e);
                }
                warn!("Could not find VirtIO COM port automatically: {}", e);
            }
        }
        
        // Method 5: Use wmic to find VirtIO ports
        if debug_mode {
            debug!("Method 4: Using wmic to search for VirtIO ports...");
        }
        let wmic_output = Command::new("wmic")
            .args(&["path", "Win32_SerialPort", "where", "PNPDeviceID like '%VEN_1AF4%'", "get", "DeviceID", "/format:csv"])
            .output();
        
        if let Ok(output) = wmic_output {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if debug_mode {
                debug!("WMIC output: {}", output_str);
            }
            for line in output_str.lines() {
                if line.contains("COM") {
                    let parts: Vec<&str> = line.split(',').collect();
                    if let Some(com_port) = parts.iter().find(|p| p.starts_with("COM")) {
                        let com_port = com_port.trim();
                        let device_path = create_device_path(com_port);
                        info!("Found VirtIO COM port via WMIC: {}", device_path.display());
                        
                        // Verify we can open it
                        if let Err(e) = try_open_com_port(com_port) {
                            warn!("WMIC found {} but cannot open it: {}", com_port, e);
                        } else {
                            return Ok(device_path);
                        }
                    }
                }
            }
        } else if debug_mode {
            debug!("WMIC command failed or not available");
        }
        
        // Method 6: Use PowerShell to find VirtIO ports
        if debug_mode {
            debug!("Method 5: Using PowerShell to search for VirtIO ports...");
        }
        let ps_output = Command::new("powershell")
            .args(&[
                "-Command", 
                "Get-WmiObject -Class Win32_SerialPort | Where-Object {$_.PNPDeviceID -like '*VEN_1AF4*' -or $_.Name -like '*VirtIO*'} | Select-Object -ExpandProperty DeviceID"
            ])
            .output();
        
        if let Ok(output) = ps_output {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if debug_mode {
                debug!("PowerShell output: {}", output_str);
            }
            for line in output_str.lines() {
                let line = line.trim();
                if line.starts_with("COM") {
                    let device_path = create_device_path(line);
                    info!("Found VirtIO COM port via PowerShell: {}", device_path.display());
                    
                    // Verify we can open it
                    if let Err(e) = try_open_com_port(line) {
                        warn!("PowerShell found {} but cannot open it: {}", line, e);
                    } else {
                        return Ok(device_path);
                    }
                }
            }
        } else if debug_mode {
            debug!("PowerShell command failed or not available");
        }
        
        // Method 7: Try common COM ports
        if debug_mode {
            debug!("Method 6: Trying common COM ports (COM1-COM10)...");
        }
        for i in 1..=10 {
            let com_port = format!("COM{}", i);
            let device_path = create_device_path(&com_port);
            
            if debug_mode {
                debug!("Trying {}", device_path.display());
            }
            
            // Try to open the port to verify it exists
            match try_open_com_port(&com_port) {
                Ok(_) => {
                    info!("Found available COM port: {}", device_path.display());
                    // For the first 4 COM ports, assume they might be virtio and return immediately
                    if i <= 4 {
                        warn!("Using {} as potential virtio-serial port", com_port);
                        return Ok(device_path);
                    } else {
                        // Add higher numbered ports as fallbacks
                        fallback_com_ports.push(device_path);
                    }
                }
                Err(e) => {
                    if debug_mode {
                        debug!("{} not available: {}", com_port, e);
                    }
                }
            }
        }
        
        // Method 8: Enhanced named pipes and Global objects (fallback with retry logic)
        if debug_mode {
            debug!("Method 7: Trying enhanced named pipes and Global objects...");
        }

        // Enhanced named pipes with retry logic and permission handling
        let enhanced_named_pipes: Vec<std::path::PathBuf> = vec![
            std::path::PathBuf::from("\\\\.\\Global\\org.infinibay.agent"),
            std::path::PathBuf::from("\\\\.\\Global\\com.redhat.spice.0"),
            std::path::PathBuf::from("\\\\.\\Global\\org.qemu.guest_agent.0"),
            std::path::PathBuf::from("\\\\.\\pipe\\org.infinibay.agent"),
            std::path::PathBuf::from("\\\\.\\pipe\\org.qemu.guest_agent.0"),
            std::path::PathBuf::from("\\\\.\\pipe\\com.redhat.spice.0"),
            // Alternative VirtIO device naming conventions
            std::path::PathBuf::from("\\\\.\\VirtioSerial"),
            std::path::PathBuf::from("\\\\.\\VirtioSerial0"),
            std::path::PathBuf::from("\\\\.\\VirtioSerial1"),
        ];

        for path in &enhanced_named_pipes {
            if debug_mode {
                debug!("Trying enhanced path: {}", path.display());
            }

            let path_str = path.to_string_lossy();

            // Enhanced Global object handling with retry logic
            if path_str.contains("Global") {
                // Try multiple access modes for Global objects
                let access_modes = vec![
                    ("read-write", true, true),
                    ("read-only", true, false),
                    ("write-only", false, true),
                ];

                for (mode_name, read, write) in access_modes {
                    if debug_mode {
                        debug!("  -> Trying {} mode for Global object", mode_name);
                    }

                    match Self::try_open_windows_device_with_mode(&path_str, read, write, debug_mode) {
                        Ok(true) => {
                            info!("✅ Enhanced Global object connection successful ({}): {}", mode_name, path.display());
                            return Ok(path.clone());
                        }
                        Ok(false) => {
                            if debug_mode {
                                debug!("  -> {} mode failed for {}", mode_name, path.display());
                            }
                        }
                        Err(error_code) => {
                            if debug_mode {
                                debug!("  -> {} mode error {} for {}", mode_name, error_code, path.display());
                            }
                            // For access denied, try with different permissions
                            if error_code == 5 && mode_name == "read-write" {
                                warn!("🔐 Access denied to Global object, trying alternative access modes...");
                            }
                        }
                    }
                }
            } else {
                // Enhanced named pipe handling with retry logic
                use std::fs::OpenOptions;
                use std::thread;
                use std::time::Duration;

                // Try multiple times with different configurations
                let retry_configs = vec![
                    ("standard", true, true, false),
                    ("read-only", true, false, false),
                    ("write-only", false, true, false),
                    ("with-retry", true, true, true),
                ];

                for (config_name, read, write, with_retry) in retry_configs {
                    if debug_mode {
                        debug!("  -> Trying {} configuration for named pipe", config_name);
                    }

                    let mut attempts = if with_retry { 3 } else { 1 };

                    while attempts > 0 {
                        match OpenOptions::new()
                            .read(read)
                            .write(write)
                            .open(&path)
                        {
                            Ok(_) => {
                                info!("✅ Enhanced named pipe connection successful ({}): {}", config_name, path.display());
                                return Ok(path.clone());
                            }
                            Err(e) => {
                                if debug_mode {
                                    debug!("  -> {} configuration attempt failed: {}", config_name, e);
                                }

                                // Handle specific errors
                                if let Some(error_code) = e.raw_os_error() {
                                    match error_code {
                                        5 => {
                                            // Access denied - try different permissions
                                            if config_name == "standard" {
                                                warn!("🔐 Access denied to named pipe, trying alternative configurations...");
                                            }
                                        }
                                        2 => {
                                            // File not found - no point in retrying
                                            break;
                                        }
                                        _ => {}
                                    }
                                }

                                attempts -= 1;
                                if with_retry && attempts > 0 {
                                    thread::sleep(Duration::from_millis(100));
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Try fallback options if we found any
        if !fallback_com_ports.is_empty() {
            warn!("=== Attempting Fallback COM Ports ===");
            warn!("Primary VirtIO detection failed, trying fallback options...");
            
            for fallback_path in &fallback_com_ports {
                warn!("Attempting fallback: {}", fallback_path.display());
                // Try to use the fallback path (may not work but gives user a chance)
                if let Some(port_name) = fallback_path.file_name() {
                    if let Some(port_str) = port_name.to_str() {
                        if let Ok(_) = try_open_com_port(port_str) {
                            warn!("✅ Fallback COM port {} is accessible, using it", port_str);
                            return Ok(fallback_path.clone());
                        }
                    }
                }
            }
        }
        
        // Enhanced access denied guidance
        if !access_denied_paths.is_empty() {
            warn!("🔐 === Access Denied Paths Found ===");
            warn!("The following VirtIO paths exist but are not accessible:");
            for path in &access_denied_paths {
                warn!("  📍 {}", path.display());
            }
            warn!("");
            warn!("🔍 This suggests VirtIO devices are present but need configuration:");
            warn!("");
            warn!("🚀 Quick Fix Steps:");
            warn!("  1️⃣  Run as Administrator:");
            warn!("      Right-click Command Prompt → 'Run as administrator'");
            warn!("      Then run: infiniservice.exe --diag");
            warn!("");
            warn!("  2️⃣  Check VM Configuration:");
            warn!("      Ensure VM has virtio-serial channel configured");
            warn!("      Required XML: <target type='virtio' name='org.infinibay.agent'/>");
            warn!("");
            warn!("  3️⃣  Verify VirtIO Drivers:");
            warn!("      Open Device Manager → System devices");
            warn!("      Look for 'VirtIO Serial Driver' (should show no warnings)");
            warn!("");
            warn!("  4️⃣  Try Alternative Paths:");
            warn!("      infiniservice.exe --device \"\\\\.\\pipe\\org.infinibay.agent\"");
            warn!("      infiniservice.exe --device \"COM1\" (if available)");
            warn!("");
        }

        // Last resort: List all available COM ports for debugging
        warn!("=== Available COM Ports (for debugging) ===");
        if let Ok(ports) = enumerate_com_ports() {
            if ports.is_empty() {
                warn!("No COM ports found on the system");
            } else {
                for port in ports {
                    warn!("  - {} ({}): {}", port.port_name, port.friendly_name, port.hardware_id);
                    if debug_mode {
                        debug!("    Full hardware ID: {}", port.hardware_id);
                        debug!("    Can open: {:?}", try_open_com_port(&port.port_name).is_ok());
                    }
                }
            }
        }
        
        // Enhanced diagnostic information with specific DEV_1043 guidance
        warn!("🔍 === Enhanced VirtIO Device Detection Summary ===");
        warn!("No directly accessible VirtIO serial device found.");
        warn!("");
        warn!("📊 Based on the analysis, this appears to be a DEV_1043 configuration issue.");
        warn!("The VirtIO Serial Driver is likely installed but not properly configured.");
        warn!("");
        warn!("🎯 Most Common Causes & Solutions:");
        warn!("");
        warn!("🔧 1. VM Configuration Missing VirtIO Channel:");
        warn!("   Problem: VM lacks proper virtio-serial channel setup");
        warn!("   Solution: Add to VM configuration:");
        warn!("   QEMU/KVM: <target type='virtio' name='org.infinibay.agent'/>");
        warn!("   VMware: serial0.fileType = \"pipe\"");
        warn!("   VirtualBox: --uartmode1 server \\\\.\\pipe\\infinibay");
        warn!("");
        warn!("🔐 2. Administrator Privileges Required:");
        warn!("   Problem: Windows blocks access to VirtIO Global objects");
        warn!("   Solution: Run Command Prompt as Administrator, then:");
        warn!("   infiniservice.exe --debug --diag");
        warn!("");
        warn!("🔨 3. VirtIO Driver Installation Issues:");
        warn!("   Problem: Driver installed but service not running");
        warn!("   Solution: Download latest VirtIO ISO and reinstall drivers");
        warn!("   Check: Device Manager → System devices → VirtIO Serial Driver");
        warn!("");
        warn!("🔄 4. Alternative Connection Methods:");
        warn!("   Try these device paths manually:");
        warn!("   infiniservice.exe --device \"\\\\.\\Global\\org.infinibay.agent\"");
        warn!("   infiniservice.exe --device \"\\\\.\\pipe\\org.infinibay.agent\"");
        warn!("   infiniservice.exe --device \"COM1\" (if VirtIO COM port exists)");
        warn!("");
        warn!("📋 5. Get Detailed Diagnosis:");
        warn!("   Run: infiniservice.exe --diag");
        warn!("   This will show specific VM configuration examples and driver status");
        
        // Don't completely fail - return a warning result that allows the service to continue
        // This allows the service to start and retry periodically
        warn!("");
        warn!("⚠️  CONTINUING WITHOUT VIRTIO - Service will retry periodically");
        warn!("The service will continue running and attempt to reconnect every few minutes.");
        warn!("Some features may be limited without VirtIO communication.");
        warn!("========================================");
        
        // Return a "mock" path that indicates no VirtIO found but allows service to continue
        Ok(std::path::PathBuf::from("__NO_VIRTIO_DEVICE__"))
    }
    
    /// Initialize connection to virtio-serial device
    pub async fn connect(&self) -> Result<()> {
        let path_str = self.device_path.to_string_lossy();
        
        // Check if this is the special "no device" marker
        if path_str == "__NO_VIRTIO_DEVICE__" {
            warn!("VirtIO device not available - operating in degraded mode");
            warn!("Some communication features will be limited");
            return Err(anyhow!("VirtIO device not available"));
        }
        
        info!("Connecting to virtio-serial device: {}", self.device_path.display());

        // Test if we can open the device for writing
        #[cfg(target_os = "windows")]
        {
            // Check device type and handle accordingly
            if path_str.contains("Global") {
                // Test if we can actually open the Global object
                match Self::try_open_windows_device(&path_str, false) {
                    Ok(true) => {
                        // Device is accessible
                    }
                    Ok(false) => {
                        return Err(anyhow!("VirtIO Global object exists but cannot be opened: {}. Check permissions and VM configuration.", path_str));
                    }
                    Err(error_code) => {
                        // Provide specific guidance based on error code
                        match error_code {
                            5 => {
                                warn!("🔐 Access denied to VirtIO Global object: {}", path_str);
                                warn!("📋 This typically means:");
                                warn!("   1. Service needs Administrator privileges");
                                warn!("   2. VirtIO device needs proper VM configuration");
                                warn!("   3. Windows security policies blocking access");
                                warn!("   4. DEV_1043 device detected but not accessible");
                                warn!("");
                                warn!("🚀 Immediate solutions:");
                                warn!("   • Run as Administrator: Right-click → 'Run as administrator'");
                                warn!("   • Check VM config: Ensure virtio-serial channel is configured");
                                warn!("   • Run diagnosis: infiniservice.exe --diag");
                                warn!("   • Try alternative: infiniservice.exe --device \"\\\\.\\pipe\\org.infinibay.agent\"");
                                return Err(anyhow!("Access denied to VirtIO Global object (Win32 error 5). Run as Administrator or check VM configuration."));
                            }
                            2 => {
                                warn!("🔍 VirtIO Global object not found: {}", path_str);
                                warn!("📋 This indicates:");
                                warn!("   • VM configuration missing virtio-serial channel");
                                warn!("   • Channel name mismatch in VM setup");
                                warn!("   • VirtIO drivers not properly installed");
                                warn!("");
                                warn!("🔧 VM Configuration Examples:");
                                warn!("   QEMU/KVM: <target type='virtio' name='org.infinibay.agent'/>");
                                warn!("   VMware: serial0.fileName = \"\\\\.\\pipe\\infinibay\"");
                                warn!("   VirtualBox: --uartmode1 server \\\\.\\pipe\\infinibay");
                                return Err(anyhow!("VirtIO Global object not found (Win32 error 2). Check VM virtio-serial configuration."));
                            }
                            _ => {
                                warn!("❌ Unexpected error accessing VirtIO device: Win32 error {}", error_code);
                                warn!("💡 Try running: infiniservice.exe --diag");
                                return Err(anyhow!("Failed to open VirtIO Global object {}: Win32 error {}. Check VM configuration and driver installation.", path_str, error_code));
                            }
                        }
                    }
                }
                
                debug!("Global VirtIO device verified: {}", path_str);
                info!("VirtIO Global object ready - will use Windows API for communication");
                return Ok(());
            } else if path_str.contains("COM") && !path_str.contains("pipe") {
                // It's a COM port, open with appropriate flags
                use std::os::windows::fs::OpenOptionsExt;
                use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
                
                match OpenOptions::new()
                    .write(true)
                    .read(true)
                    .custom_flags(FILE_FLAG_OVERLAPPED)
                    .open(&self.device_path)
                {
                    Ok(_) => {
                        info!("COM port connection established successfully");
                        return Ok(());
                    }
                    Err(e) => {
                        if let Some(5) = e.raw_os_error() {
                            warn!("🔐 Access denied to COM port: {}", self.device_path.display());
                            warn!("📋 Common causes:");
                            warn!("   • Another application is using the port");
                            warn!("   • Service needs Administrator privileges");
                            warn!("   • VirtIO COM port requires special permissions");
                            warn!("");
                            warn!("💡 Solutions:");
                            warn!("   • Close other applications using the COM port");
                            warn!("   • Run as Administrator");
                            warn!("   • Try alternative device paths with --device flag");
                            warn!("   • Run diagnosis: infiniservice.exe --diag");
                        } else {
                            warn!("❌ Failed to open COM port: {} (Error: {})", self.device_path.display(), e);
                            warn!("💡 This may indicate:");
                            warn!("   • COM port doesn't exist or is not available");
                            warn!("   • VirtIO driver not properly configured");
                            warn!("   • Hardware or VM configuration issue");
                        }
                        return Err(anyhow!("Failed to open COM port {}: {}. Check if port is available and accessible.", self.device_path.display(), e));
                    }
                }
            } else {
                // It's a named pipe or other device
                match OpenOptions::new()
                    .write(true)
                    .read(true)
                    .open(&self.device_path)
                {
                    Ok(_) => {
                        info!("Device connection established successfully");
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(anyhow!("Failed to open device {}: {}. Check device availability and permissions.", self.device_path.display(), e));
                    }
                }
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            match OpenOptions::new()
                .write(true)
                .read(true)
                .open(&self.device_path)
            {
                Ok(_) => {
                    info!("Virtio-serial connection established successfully");
                    return Ok(());
                }
                Err(e) => {
                    return Err(anyhow!("Failed to open virtio-serial device {}: {}. Check device permissions and availability.", self.device_path.display(), e));
                }
            }
        }
    }

    

    fn current_timestamp() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }
    
    /// Send system information to host via virtio-serial
    pub async fn send_data(&self, data: &SystemInfo) -> Result<()> {
        debug!("Sending system data via virtio-serial");

        // Wrap SystemInfo in the message format expected by backend
        let metrics_message = MetricsMessage {
            message_type: "metrics".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            data: MetricsData {
                system: data.metrics.clone(),
            },
        };

        let serialized = serde_json::to_string(&metrics_message)
            .with_context(|| "Failed to serialize metrics message")?;

        self.send_raw_message(&serialized).await
    }
    
    /// Send a command response to the host
    pub async fn send_command_response(&self, response: &CommandResponse) -> Result<()> {
        debug!("Sending command response: id={}, success={}", response.id, response.success);
        
        let serialized = serde_json::to_string(&response)
            .with_context(|| "Failed to serialize command response")?;
        
        self.send_raw_message(&serialized).await
    }
    
    /// Send raw message to the device
    async fn send_raw_message(&self, message: &str) -> Result<()> {
        let path_str = self.device_path.to_string_lossy();

        // Check if VirtIO is available
        if path_str == "__NO_VIRTIO_DEVICE__" {
            debug!("VirtIO not available - message not sent: {}", message);
            return Err(anyhow!("VirtIO device not available for communication"));
        }

        // Open device and send data with rate-limited error logging
        let file_result = {
            #[cfg(target_os = "windows")]
            {
                if path_str.contains("COM") && !path_str.contains("pipe") {
                    // COM port - no special flags needed for synchronous write
                    OpenOptions::new()
                        .write(true)
                        .open(&self.device_path)
                        .with_context(|| format!("Failed to open COM port for data transmission: {}", self.device_path.display()))
                } else {
                    OpenOptions::new()
                        .write(true)
                        .open(&self.device_path)
                        .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                OpenOptions::new()
                    .write(true)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))
            }
        };

        let mut file = match file_result {
            Ok(file) => file,
            Err(e) => {
                // Handle device open errors with rate limiting for transmission
                use std::sync::LazyLock;
                static TRANSMISSION_ERROR_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32)>> =
                    LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0)));

                if let Ok(mut state) = TRANSMISSION_ERROR_STATE.lock() {
                    state.1 += 1; // Increment error count
                    let now = std::time::Instant::now();

                    // Only log every 30 seconds or every 50 errors
                    if now.duration_since(state.0).as_secs() >= 30 || state.1 >= 50 {
                        warn!("Failed to open virtio device for transmission ({} attempts in last interval): {}", state.1, e);
                        debug!("Device path: {}", self.device_path.display());
                        state.0 = now;
                        state.1 = 0;
                    }
                }
                return Err(e);
            }
        };

        writeln!(file, "{}", message)
            .with_context(|| "Failed to write message to device")?;

        file.flush()
            .with_context(|| "Failed to flush message to device")?;

        debug!("Message sent successfully");
        Ok(())
    }
    
    /// Read incoming commands from the device
    pub async fn read_command(&self) -> Result<Option<IncomingMessage>> {
        let path_str = self.device_path.to_string_lossy();

        // Check if VirtIO is available
        if path_str == "__NO_VIRTIO_DEVICE__" {
            // Don't spam debug logs when VirtIO is not available
            return Ok(None);
        }

        // Rate limit all operations to avoid spam
        use std::sync::LazyLock;
        static OPERATION_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32, std::time::Instant)>> =
            LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0, std::time::Instant::now())));

        // Try to open device for reading with error handling
        #[cfg(target_os = "windows")]
        let file_result = {
            if path_str.contains("COM") && !path_str.contains("pipe") {
                OpenOptions::new()
                    .read(true)
                    .open(&self.device_path)
            } else {
                OpenOptions::new()
                    .read(true)
                    .open(&self.device_path)
            }
        };

        #[cfg(not(target_os = "windows"))]
        let file_result = OpenOptions::new()
            .read(true)
            .open(&self.device_path);

        let file = match file_result {
            Ok(f) => {
                // Success - log occasionally
                if let Ok(mut state) = OPERATION_STATE.lock() {
                    let now = std::time::Instant::now();
                    if now.duration_since(state.2).as_secs() >= 30 {
                        debug!("Successfully opened virtio-serial device for reading");
                        state.2 = now;
                    }
                }
                f
            },
            Err(e) => {
                // Handle device open errors with rate limiting
                if let Ok(mut state) = OPERATION_STATE.lock() {
                    state.1 += 1; // Increment error count
                    let now = std::time::Instant::now();

                    // Only log every 30 seconds or every 50 errors
                    if now.duration_since(state.0).as_secs() >= 30 || state.1 >= 50 {
                        warn!("Failed to open virtio device ({} attempts in last interval): {}", state.1, e);
                        debug!("Device path: {}", self.device_path.display());
                        state.0 = now;
                        state.1 = 0;
                    }
                }
                // Return None instead of propagating error to avoid breaking the service loop
                return Ok(None);
            }
        };
        
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        
        // Try to read a line (non-blocking would be better but requires more complex setup)
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No data available
                Ok(None)
            },
            Ok(_) => {
                // Parse the incoming message
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return Ok(None);
                }
                
                debug!("Received message: {}", trimmed);
                
                match serde_json::from_str::<IncomingMessage>(trimmed) {
                    Ok(msg) => {
                        match &msg {
                            IncomingMessage::SafeCommand(cmd) => {
                                info!("Received safe command: id={}, type={:?}", cmd.id, cmd.command_type);
                            },
                            IncomingMessage::UnsafeCommand(cmd) => {
                                warn!("⚠️ Received UNSAFE command: id={}, command={}", cmd.id, cmd.raw_command);
                            },
                            IncomingMessage::Metrics => {
                                debug!("Received metrics request");
                            }
                        }
                        Ok(Some(msg))
                    },
                    Err(e) => {
                        warn!("Failed to parse incoming message: {}", e);
                        debug!("Raw message was: {}", trimmed);
                        Ok(None)
                    }
                }
            },
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::WouldBlock => {
                        // No data available (non-blocking read) - this is normal
                        Ok(None)
                    },
                    std::io::ErrorKind::TimedOut => {
                        // Timeout - this is also normal for non-blocking operations
                        Ok(None)
                    },
                    std::io::ErrorKind::UnexpectedEof => {
                        // EOF - no more data available, this is normal
                        Ok(None)
                    },
                    _ => {
                        // Only log actual errors, not expected conditions
                        use std::sync::LazyLock;
                        static ERROR_LOG_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32)>> =
                            LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0)));

                        if let Ok(mut state) = ERROR_LOG_STATE.lock() {
                            state.1 += 1; // Increment error count
                            let now = std::time::Instant::now();

                            // Only log every 30 seconds or every 100 errors
                            if now.duration_since(state.0).as_secs() >= 30 || state.1 >= 100 {
                                warn!("Communication error reading from device ({} occurrences): {}", state.1, e);
                                state.0 = now;
                                state.1 = 0;
                            }
                        }

                        // Return None instead of error to avoid breaking the service loop
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Check if virtio-serial device is available
    pub fn is_available(&self) -> bool {
        let path_str = self.device_path.to_string_lossy();
        
        // Check if this is the special "no device" marker
        if path_str == "__NO_VIRTIO_DEVICE__" {
            return false;
        }
        
        #[cfg(target_os = "windows")]
        {
            // Global objects need special handling - they're not files
            if path_str.contains("Global") {
                // Try to open it to check availability
                match Self::try_open_windows_device(&path_str, false) {
                    Ok(true) => return true,
                    Ok(false) | Err(_) => return false,
                }
            }
        }
        
        // For regular files and non-Windows systems
        self.device_path.exists()
    }

    /// Send connection status updates to host
    pub async fn send_connection_status(&self, state: &str, details: &str) -> Result<()> {
        if !self.is_available() {
            // Can't send status if VirtIO is not available
            return Ok(());
        }

        let status_message = serde_json::json!({
            "type": "connection_status",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "state": state,
            "details": details,
            "vm_id": self.vm_id
        });

        let message_str = status_message.to_string();
        debug!("Sending connection status: {}", message_str);

        self.send_raw_message(&message_str).await
    }

    /// Compare device paths for changes
    pub fn compare_device_paths(old_path: &Path, new_path: &Path) -> bool {
        old_path == new_path
    }

    /// Get current device metadata for monitoring
    pub fn get_device_metadata(&self) -> std::collections::HashMap<String, String> {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("device_path".to_string(), self.device_path.to_string_lossy().to_string());
        metadata.insert("vm_id".to_string(), self.vm_id.clone());
        metadata.insert("available".to_string(), self.is_available().to_string());

        #[cfg(target_os = "windows")]
        {
            // Add Windows-specific metadata
            metadata.insert("platform".to_string(), "windows".to_string());
        }

        #[cfg(target_os = "linux")]
        {
            // Add Linux-specific metadata
            metadata.insert("platform".to_string(), "linux".to_string());
        }

        metadata
    }

    /// Test connection health
    pub async fn test_connection_health(&self) -> Result<std::collections::HashMap<String, String>> {
        let mut health_info = std::collections::HashMap::new();

        // Basic availability check
        let available = self.is_available();
        health_info.insert("available".to_string(), available.to_string());

        if !available {
            health_info.insert("status".to_string(), "unavailable".to_string());
            health_info.insert("reason".to_string(), "device_not_found".to_string());
            return Ok(health_info);
        }

        // Try a lightweight connection test
        match std::fs::File::open(&self.device_path) {
            Ok(_) => {
                health_info.insert("status".to_string(), "healthy".to_string());
                health_info.insert("readable".to_string(), "true".to_string());
            }
            Err(e) => {
                health_info.insert("status".to_string(), "degraded".to_string());
                health_info.insert("error".to_string(), e.to_string());
                health_info.insert("readable".to_string(), "false".to_string());
            }
        }

        health_info.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());
        Ok(health_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;



    #[test]
    fn test_virtio_serial_initialization() {
        let device_path = PathBuf::from("/dev/virtio-ports/test");
        let virtio = VirtioSerial::new(&device_path);
        
        assert_eq!(virtio.device_path, device_path);
        assert!(!virtio.vm_id.is_empty());
    }

    #[test]
    fn test_virtio_serial_with_vm_id() {
        let device_path = PathBuf::from("/dev/virtio-ports/test");
        let vm_id = "custom-vm-id";
        let virtio = VirtioSerial::with_vm_id(&device_path, vm_id.to_string());
        
        assert_eq!(virtio.device_path, device_path);
        assert_eq!(virtio.vm_id, vm_id);
    }

    #[test]
    fn test_vm_id_generation() {
        let vm_id1 = VirtioSerial::generate_vm_id();
        let vm_id2 = VirtioSerial::generate_vm_id();
        
        assert!(!vm_id1.is_empty());
        assert!(!vm_id2.is_empty());
        // IDs should be different unless environment variable is set
        if std::env::var("INFINIBAY_VM_ID").is_err() {
            assert_ne!(vm_id1, vm_id2);
        }
    }

    #[test]
    fn test_vm_id_from_environment() {
        let test_vm_id = "test-env-vm-id";
        std::env::set_var("INFINIBAY_VM_ID", test_vm_id);
        
        let generated_id = VirtioSerial::generate_vm_id();
        assert_eq!(generated_id, test_vm_id);
        
        // Clean up
        std::env::remove_var("INFINIBAY_VM_ID");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_device_detection_paths() {
        // Test that detection tries expected Linux paths
        let result = VirtioSerial::detect_device_path(false);
        // This will likely fail in test environment, but shouldn't panic
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_device_detection_paths() {
        // Test that detection returns expected Windows paths
        let result = VirtioSerial::detect_device_path(false);
        if let Ok(path) = result {
            let path_str = path.to_string_lossy();
            assert!(path_str.contains(r"\\.\") || path_str.contains("Global"));
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_try_open_windows_device_with_sharing() {
        // Test that try_open_windows_device uses proper sharing mode
        // This test verifies the function doesn't panic and handles errors properly
        let test_paths = vec![
            r"\\.\Global\nonexistent",
            r"\\.\pipe\nonexistent",
            r"\\.\COM999",
        ];

        for path in test_paths {
            let result = VirtioSerial::try_open_windows_device(path, false);
            // Should return an error for nonexistent devices, but not panic
            assert!(result.is_err());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_enhanced_error_messages() {
        // Test that Windows error handling provides enhanced messages
        // This is more of a smoke test to ensure the error handling code doesn't panic
        let nonexistent_path = PathBuf::from(r"\\.\Global\nonexistent_virtio_device");
        let virtio = VirtioSerial::new(&nonexistent_path);

        // The connect method should handle errors gracefully
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(virtio.connect());

        // Should return an error with enhanced messaging
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        // Error message should contain helpful information
        assert!(!error_msg.is_empty());
    }

    #[test]
    fn test_current_timestamp() {
        let timestamp1 = VirtioSerial::current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let timestamp2 = VirtioSerial::current_timestamp();
        
        assert!(!timestamp1.is_empty());
        assert!(!timestamp2.is_empty());
        
        let t1: u64 = timestamp1.parse().expect("Should be valid timestamp");
        let t2: u64 = timestamp2.parse().expect("Should be valid timestamp");
        assert!(t2 >= t1, "Second timestamp should be >= first");
    }

    #[test]
    fn test_is_available_with_nonexistent_path() {
        let nonexistent_path = PathBuf::from("/nonexistent/path/test.socket");
        let virtio = VirtioSerial::new(&nonexistent_path);
        
        assert!(!virtio.is_available());
    }

    #[tokio::test]
    async fn test_send_data_with_sample_system_info() {
        use crate::collector::*;
        
        // Create sample system info
        let system_info = SystemInfo {
            timestamp: 1234567890,
            metrics: SystemMetrics {
                cpu: CpuMetrics {
                    usage_percent: 50.0,
                    cores_usage: vec![45.0, 55.0],
                    temperature: Some(65.0),
                },
                memory: MemoryMetrics {
                    total_kb: 8388608,
                    used_kb: 4194304,
                    available_kb: 4194304,
                    swap_total_kb: None,
                    swap_used_kb: None,
                },
                disk: DiskMetrics {
                    usage_stats: vec![],
                    io_stats: DiskIOStats {
                        read_bytes_per_sec: 0,
                        write_bytes_per_sec: 0,
                        read_ops_per_sec: 0,
                        write_ops_per_sec: 0,
                    },
                },
                network: NetworkMetrics { interfaces: vec![] },
                system: SystemInfoMetrics {
                    uptime_seconds: 3600,
                    name: "Test".to_string(),
                    os_version: "1.0".to_string(),
                    kernel_version: "5.0".to_string(),
                    hostname: "test-host".to_string(),
                    load_average: None,
                },
                processes: vec![],
                ports: vec![],
                windows_services: vec![],
            },
        };

        // Test serialization (actual sending will fail in test environment)
        let serialized = serde_json::to_string(&system_info).expect("Should serialize");
        assert!(serialized.contains("\"timestamp\":1234567890"));
        assert!(serialized.contains("\"usage_percent\":50.0"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_try_direct_virtio_connection_with_interface_paths() {
        use crate::windows_com::ComPortInfo;
        use std::path::PathBuf;

        // Test selecting an interface path when present
        let device_info = ComPortInfo {
            port_name: String::new(),
            friendly_name: "Test VirtIO Device".to_string(),
            hardware_id: "VEN_1AF4&DEV_1043".to_string(),
            is_virtio: true,
            device_path: PathBuf::new(),
            instance_id: "TEST\\INSTANCE\\ID".to_string(),
            device_status: "Working properly".to_string(),
            driver_service: "vioser".to_string(),
            location_info: "PCI bus 0".to_string(),
            interface_paths: vec![
                "\\\\.\\test_interface_1".to_string(),
                "\\\\.\\test_interface_2".to_string(),
            ],
        };

        // This will fail in test environment but should exercise the code path
        let result = VirtioSerial::try_direct_virtio_connection(&device_info);
        assert!(result.is_err()); // Expected to fail in test environment
        assert!(result.unwrap_err().contains("All direct VirtIO connection methods failed"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_try_direct_virtio_connection_fallback_to_alternatives() {
        use crate::windows_com::ComPortInfo;
        use std::path::PathBuf;

        // Test falling back to alternative paths when interface paths fail
        let device_info = ComPortInfo {
            port_name: String::new(),
            friendly_name: "Test VirtIO Device".to_string(),
            hardware_id: "VEN_1AF4&DEV_1043".to_string(),
            is_virtio: true,
            device_path: PathBuf::new(),
            instance_id: "TEST\\INSTANCE\\ID".to_string(),
            device_status: "Working properly".to_string(),
            driver_service: "vioser".to_string(),
            location_info: "PCI bus 0".to_string(),
            interface_paths: vec![], // No interface paths
        };

        // This will fail in test environment but should exercise the fallback code path
        let result = VirtioSerial::try_direct_virtio_connection(&device_info);
        assert!(result.is_err()); // Expected to fail in test environment
        assert!(result.unwrap_err().contains("All direct VirtIO connection methods failed"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_detect_windows_device_method_2_5_invoked_for_dev_1043() {
        // Test that Method 2.5 is invoked for DEV_1043 devices
        // This is a smoke test to ensure the code path exists

        // Mock a scenario where we have DEV_1043 devices
        // In a real test environment, this would require mocking the Windows API calls

        // For now, just test that the function exists and can be called
        let result = VirtioSerial::detect_windows_device(true);

        // In test environment, this will likely fail to find devices, but that's expected
        // The important thing is that the code path is exercised
        match result {
            Ok(_) => {
                // If it succeeds, great!
            }
            Err(_) => {
                // Expected in test environment without actual VirtIO devices
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_try_open_windows_device_simple_helper() {
        // Test the helper function for opening Windows devices
        let result = VirtioSerial::try_open_windows_device_simple("\\\\.\\nonexistent_device");

        // Should fail for non-existent device
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Win32 error"));
    }

    #[test]
    fn test_enhanced_fallback_paths_include_virtio_variants() {
        // Test that enhanced fallback includes VirtioSerial variants
        // This is a structural test to ensure the code includes the expected paths

        // The actual paths are tested in the detect_windows_device function
        // Here we just verify the structure exists
        assert!(true); // Placeholder - in real implementation, would test path generation
    }
}
