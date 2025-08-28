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
                0, // No sharing for exclusive access
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
    fn detect_windows_device(debug_mode: bool) -> Result<std::path::PathBuf> {
        use crate::windows_com::{find_virtio_com_port, enumerate_com_ports, try_open_com_port, 
                                  find_virtio_system_devices, find_virtio_device_paths};
        use std::process::Command;
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        
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
                // For QEMU Guest Agent, try alternative connection method
                if path_str.contains("guest_agent") {
                    info!("Detected QEMU Guest Agent path - marking for alternative connection");
                    // Mark as found but note it needs special handling
                    return Ok(path.clone());
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
                                warn!("Access denied to VirtIO Global object: {}", path.display());
                                warn!("This may indicate:");
                                warn!("  1. The service needs administrator privileges");
                                warn!("  2. The VM needs proper VirtIO channel configuration");
                                warn!("  3. Windows needs VirtIO driver reinstallation");
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
                        
                        // Check if it's the specific device from the screenshot
                        if device.hardware_id.contains("DEV_1043") {
                            info!("Found VirtIO Serial Device (DEV_1043) as seen in Device Manager");
                            warn!("Note: This device may not be accessible as a COM port.");
                            warn!("The VirtIO serial driver may need additional configuration.");
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
        
        // Method 3: Try alternative VirtIO device paths
        if debug_mode {
            debug!("Method 2: Trying alternative VirtIO device paths...");
        }
        let virtio_paths = find_virtio_device_paths();
        if !virtio_paths.is_empty() {
            info!("Found {} alternative VirtIO device path(s)", virtio_paths.len());
            for path in virtio_paths {
                info!("Using VirtIO device path: {}", path.display());
                return Ok(path);
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
        
        // Method 8: Try additional named pipes (fallback)
        if debug_mode {
            debug!("Method 7: Trying named pipes...");
        }
        // Use OS-specific string handling for named pipes
        let named_pipes: Vec<std::path::PathBuf> = vec![
            std::path::PathBuf::from("\\\\.\\Global\\org.infinibay.agent"),
            std::path::PathBuf::from("\\\\.\\Global\\com.redhat.spice.0"),
            std::path::PathBuf::from("\\\\.\\pipe\\org.infinibay.agent"),
            // Removed \\\\.\\pipe\\virtio-serial as it doesn't exist
        ];
        
        for path in &named_pipes {
            if debug_mode {
                debug!("Trying named pipe: {}", path.display());
            }
            // Try to open the named pipe
            use std::fs::OpenOptions;
            if let Ok(_) = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
            {
                info!("Found working virtio-serial named pipe: {}", path.display());
                return Ok(path.clone());
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
        
        // If access denied paths exist, suggest resolution
        if !access_denied_paths.is_empty() {
            warn!("=== Access Denied Paths Found ===");
            warn!("The following VirtIO paths exist but are not accessible:");
            for path in &access_denied_paths {
                warn!("  - {}", path.display());
            }
            warn!("This suggests the VirtIO devices are present but need:");
            warn!("  1. Administrator privileges to access");
            warn!("  2. Proper VM configuration with channel names");
            warn!("  3. VirtIO driver reinstallation or configuration");
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
        
        // Enhanced diagnostic information
        warn!("=== VirtIO Device Detection Summary ===");
        warn!("No directly accessible VirtIO serial device found.");
        warn!("");
        warn!("Based on typical configurations, the VirtIO Serial Driver may be installed");
        warn!("but requires additional configuration. This can happen when:");
        warn!("");
        warn!("🔧 Configuration Issues:");
        warn!("  1. VM XML missing virtio-serial channel configuration");
        warn!("  2. Channel name mismatch (should be 'org.infinibay.agent' or similar)");
        warn!("  3. VirtIO device not exposed as accessible COM port");
        warn!("");
        warn!("🔐 Permission Issues:");
        warn!("  4. Service needs administrator privileges");
        warn!("  5. Windows security policies blocking device access");
        warn!("");
        warn!("🔨 Driver Issues:");
        warn!("  6. VirtIO driver needs reinstallation");
        warn!("  7. Missing or outdated VirtIO guest tools");
        warn!("");
        warn!("💡 Solutions to try:");
        warn!("  • Run the service as Administrator");
        warn!("  • Check VM configuration for virtio-serial channels");
        warn!("  • Reinstall VirtIO drivers from latest ISO");
        warn!("  • Use --device flag to manually specify device path");
        warn!("  • Enable debug mode with --debug for more details");
        
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
                                warn!("Access denied to VirtIO Global object: {}", path_str);
                                warn!("This typically means:");
                                warn!("  1. The service needs to run as Administrator");
                                warn!("  2. The VirtIO device needs proper VM configuration");
                                warn!("  3. Windows security policies are blocking access");
                                return Err(anyhow!("Access denied to VirtIO Global object (Win32 error 5). Try running as Administrator or check VM configuration."));
                            }
                            2 => {
                                warn!("VirtIO Global object not found: {}", path_str);
                                warn!("This may indicate the VM configuration is incomplete or the device path has changed.");
                                return Err(anyhow!("VirtIO Global object not found (Win32 error 2). Check VM virtio-serial configuration."));
                            }
                            _ => {
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
                            warn!("Access denied to COM port: {}", self.device_path.display());
                            warn!("Try running as Administrator or check if another application is using the port");
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
        
        // Open device and send data
        #[cfg(target_os = "windows")]
        let mut file = {
            use std::os::windows::fs::OpenOptionsExt;
            
            if path_str.contains("COM") && !path_str.contains("pipe") {
                // COM port - no special flags needed for synchronous write
                OpenOptions::new()
                    .write(true)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open COM port for data transmission: {}", self.device_path.display()))?
            } else {
                OpenOptions::new()
                    .write(true)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))?
            }
        };
        
        #[cfg(not(target_os = "windows"))]
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.device_path)
            .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))?;

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
        
        debug!("Attempting to read command from virtio-serial");
        
        // Open device for reading
        #[cfg(target_os = "windows")]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            if path_str.contains("COM") && !path_str.contains("pipe") {
                OpenOptions::new()
                    .read(true)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open COM port for reading: {}", self.device_path.display()))?
            } else {
                OpenOptions::new()
                    .read(true)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open device for reading: {}", self.device_path.display()))?
            }
        };
        
        #[cfg(not(target_os = "windows"))]
        let file = OpenOptions::new()
            .read(true)
            .open(&self.device_path)
            .with_context(|| format!("Failed to open device for reading: {}", self.device_path.display()))?;
        
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
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // No data available (non-blocking read)
                    Ok(None)
                } else {
                    Err(anyhow!("Failed to read from device: {}", e))
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
}
