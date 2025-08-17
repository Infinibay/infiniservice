//! Windows COM port detection module for virtio-serial devices
//! 
//! This module provides functionality to detect and enumerate COM ports on Windows,
//! specifically looking for virtio-serial devices by their vendor ID.

#[cfg(target_os = "windows")]
use winapi::{
    shared::{
        guiddef::GUID,
        minwindef::{DWORD, HKEY, LPBYTE, FALSE},
        winerror::{ERROR_SUCCESS, ERROR_NO_MORE_ITEMS},
    },
    um::{
        setupapi::*,
        winreg::*,
        winnt::{KEY_READ, REG_SZ},
        handleapi::INVALID_HANDLE_VALUE,
    },
};

use anyhow::{Result, anyhow, Context};
use log::{info, debug, warn};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;
use std::mem;

/// Information about a COM port
#[derive(Debug, Clone)]
pub struct ComPortInfo {
    /// The COM port name (e.g., "COM3")
    pub port_name: String,
    /// The friendly name (e.g., "VirtIO Serial Port (COM3)")
    pub friendly_name: String,
    /// The hardware ID (e.g., "PCI\VEN_1AF4&DEV_1003")
    pub hardware_id: String,
    /// Whether this is a virtio device
    pub is_virtio: bool,
    /// The full device path (e.g., "\\.\COM3")
    pub device_path: PathBuf,
}

/// GUID for COM port devices
#[cfg(target_os = "windows")]
const GUID_DEVINTERFACE_COMPORT: GUID = GUID {
    Data1: 0x86E0D1E0,
    Data2: 0x8089,
    Data3: 0x11D0,
    Data4: [0x9C, 0xE4, 0x08, 0x00, 0x3E, 0x30, 0x1F, 0x73],
};

/// GUID for all system devices (to find VirtIO devices that aren't COM ports)
#[cfg(target_os = "windows")]
const GUID_DEVCLASS_SYSTEM: GUID = GUID {
    Data1: 0x4D36E97D,
    Data2: 0xE325,
    Data3: 0x11CE,
    Data4: [0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18],
};

/// VirtIO vendor ID
const VIRTIO_VENDOR_ID: &str = "VEN_1AF4";

/// VirtIO serial device IDs
const VIRTIO_SERIAL_DEVICE_IDS: &[&str] = &[
    "DEV_1003",  // Legacy VirtIO serial
    "DEV_1043",  // Modern VirtIO serial (as seen in your screenshot)
    "DEV_1044",  // VirtIO console
];

/// Enumerate all COM ports on the system
#[cfg(target_os = "windows")]
pub fn enumerate_com_ports() -> Result<Vec<ComPortInfo>> {
    unsafe {
        let mut ports = Vec::new();
        
        // Get device information set for all COM ports
        let h_dev_info = SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_COMPORT,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        
        if h_dev_info == INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to get device information set"));
        }
        
        // Ensure cleanup on exit
        let _cleanup = DevInfoCleanup(h_dev_info);
        
        let mut dev_info_data: SP_DEVINFO_DATA = mem::zeroed();
        dev_info_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as DWORD;
        
        let mut index = 0;
        
        // Enumerate all devices
        while SetupDiEnumDeviceInfo(h_dev_info, index, &mut dev_info_data) != FALSE {
            index += 1;
            
            let mut port_info = ComPortInfo {
                port_name: String::new(),
                friendly_name: String::new(),
                hardware_id: String::new(),
                is_virtio: false,
                device_path: PathBuf::new(),
            };
            
            // Get friendly name
            let mut buffer: [u16; 256] = [0; 256];
            let mut required_size = 0;
            
            if SetupDiGetDeviceRegistryPropertyW(
                h_dev_info,
                &mut dev_info_data,
                SPDRP_FRIENDLYNAME,
                ptr::null_mut(),
                buffer.as_mut_ptr() as LPBYTE,
                (buffer.len() * 2) as DWORD,
                &mut required_size,
            ) != FALSE {
                port_info.friendly_name = OsString::from_wide(&buffer[..])
                    .to_string_lossy()
                    .trim_end_matches('\0')
                    .to_string();
            }
            
            // Get hardware ID
            if SetupDiGetDeviceRegistryPropertyW(
                h_dev_info,
                &mut dev_info_data,
                SPDRP_HARDWAREID,
                ptr::null_mut(),
                buffer.as_mut_ptr() as LPBYTE,
                (buffer.len() * 2) as DWORD,
                &mut required_size,
            ) != FALSE {
                port_info.hardware_id = OsString::from_wide(&buffer[..])
                    .to_string_lossy()
                    .trim_end_matches('\0')
                    .to_string();
                
                // Check if it's a virtio device
                if port_info.hardware_id.contains(VIRTIO_VENDOR_ID) {
                    port_info.is_virtio = true;
                    debug!("Found VirtIO device: {}", port_info.hardware_id);
                    
                    // Check for specific VirtIO serial device IDs
                    for dev_id in VIRTIO_SERIAL_DEVICE_IDS {
                        if port_info.hardware_id.contains(dev_id) {
                            debug!("Confirmed VirtIO serial device with {}", dev_id);
                            break;
                        }
                    }
                }
            }
            
            // Get the actual COM port name from registry
            let h_key = SetupDiOpenDevRegKey(
                h_dev_info,
                &mut dev_info_data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DEV,
                KEY_READ,
            );
            
            if h_key != INVALID_HANDLE_VALUE as HKEY {
                let mut port_name_buffer: [u16; 256] = [0; 256];
                let mut size = (port_name_buffer.len() * 2) as DWORD;
                let mut reg_type = 0;
                
                let port_name_key = "PortName\0".encode_utf16().collect::<Vec<u16>>();
                
                if RegQueryValueExW(
                    h_key,
                    port_name_key.as_ptr(),
                    ptr::null_mut(),
                    &mut reg_type,
                    port_name_buffer.as_mut_ptr() as LPBYTE,
                    &mut size,
                ) == ERROR_SUCCESS as i32 {
                    port_info.port_name = OsString::from_wide(&port_name_buffer[..])
                        .to_string_lossy()
                        .trim_end_matches('\0')
                        .to_string();
                    
                    // Set the device path
                    port_info.device_path = PathBuf::from(format!(r"\\.\{}", port_info.port_name));
                }
                
                RegCloseKey(h_key);
            }
            
            // Only add if we got a valid port name
            if !port_info.port_name.is_empty() {
                debug!("Found COM port: {} (Virtio: {})", port_info.port_name, port_info.is_virtio);
                ports.push(port_info);
            }
        }
        
        Ok(ports)
    }
}

/// Find the first virtio-serial COM port
#[cfg(target_os = "windows")]
pub fn find_virtio_com_port() -> Result<ComPortInfo> {
    let ports = enumerate_com_ports()?;
    
    // First, try to find a port that is explicitly virtio
    for port in &ports {
        if port.is_virtio {
            info!("Found VirtIO COM port: {} ({})", port.port_name, port.friendly_name);
            return Ok(port.clone());
        }
    }
    
    // If no virtio port found, but there's only one COM port, use it
    // (common in VM environments where there's only the virtio port)
    if ports.len() == 1 {
        let port = &ports[0];
        warn!("No explicit VirtIO COM port found, but only one COM port exists: {}", port.port_name);
        info!("Assuming {} is the virtio-serial port", port.port_name);
        return Ok(port.clone());
    }
    
    // If multiple ports exist and none are virtio, we can't determine which to use
    if !ports.is_empty() {
        warn!("Found {} COM ports but none identified as VirtIO:", ports.len());
        for port in &ports {
            warn!("  - {} ({}): {}", port.port_name, port.friendly_name, port.hardware_id);
        }
    }
    
    Err(anyhow!("No virtio-serial COM port found"))
}

/// Try to open a COM port by name (e.g., "COM3")
#[cfg(target_os = "windows")]
pub fn try_open_com_port(port_name: &str) -> Result<()> {
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
    
    unsafe {
        let device_path = format!(r"\\.\{}", port_name);
        let wide_path: Vec<u16> = device_path.encode_utf16().chain(std::iter::once(0)).collect();
        
        let handle = CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );
        
        if handle == INVALID_HANDLE_VALUE {
            use winapi::um::errhandlingapi::GetLastError;
            let error = GetLastError();
            return Err(anyhow!("Failed to open COM port {}: error code {}", port_name, error));
        }
        
        // Close the handle immediately - we just wanted to test if we can open it
        use winapi::um::handleapi::CloseHandle;
        CloseHandle(handle);
        
        Ok(())
    }
}

/// RAII wrapper for SetupDi cleanup
#[cfg(target_os = "windows")]
struct DevInfoCleanup(HDEVINFO);

#[cfg(target_os = "windows")]
impl Drop for DevInfoCleanup {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

/// Fallback function for non-Windows platforms
#[cfg(not(target_os = "windows"))]
pub fn enumerate_com_ports() -> Result<Vec<ComPortInfo>> {
    Err(anyhow!("COM port enumeration is only supported on Windows"))
}

#[cfg(not(target_os = "windows"))]
pub fn find_virtio_com_port() -> Result<ComPortInfo> {
    Err(anyhow!("COM port detection is only supported on Windows"))
}

#[cfg(not(target_os = "windows"))]
pub fn try_open_com_port(_port_name: &str) -> Result<()> {
    Err(anyhow!("COM port operations are only supported on Windows"))
}

/// Find VirtIO devices in system devices (not appearing as COM ports)
#[cfg(target_os = "windows")]
pub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {
    unsafe {
        let mut devices = Vec::new();
        
        info!("Searching for VirtIO devices in system devices...");
        
        // Get device information set for all system devices
        let h_dev_info = SetupDiGetClassDevsW(
            &GUID_DEVCLASS_SYSTEM,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT,
        );
        
        if h_dev_info == INVALID_HANDLE_VALUE {
            return Err(anyhow!("Failed to get system device information set"));
        }
        
        let _cleanup = DevInfoCleanup(h_dev_info);
        
        let mut dev_info_data: SP_DEVINFO_DATA = mem::zeroed();
        dev_info_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as DWORD;
        
        let mut index = 0;
        
        while SetupDiEnumDeviceInfo(h_dev_info, index, &mut dev_info_data) != FALSE {
            index += 1;
            
            let mut buffer: [u16; 256] = [0; 256];
            let mut required_size = 0;
            
            // Get hardware ID
            if SetupDiGetDeviceRegistryPropertyW(
                h_dev_info,
                &mut dev_info_data,
                SPDRP_HARDWAREID,
                ptr::null_mut(),
                buffer.as_mut_ptr() as LPBYTE,
                (buffer.len() * 2) as DWORD,
                &mut required_size,
            ) != FALSE {
                let hardware_id = OsString::from_wide(&buffer[..])
                    .to_string_lossy()
                    .trim_end_matches('\0')
                    .to_string();
                
                // Check if it's a VirtIO serial device
                if hardware_id.contains(VIRTIO_VENDOR_ID) {
                    for dev_id in VIRTIO_SERIAL_DEVICE_IDS {
                        if hardware_id.contains(dev_id) {
                            info!("Found VirtIO serial system device: {}", hardware_id);
                            
                            let mut device_info = ComPortInfo {
                                port_name: String::new(),
                                friendly_name: String::new(),
                                hardware_id: hardware_id.clone(),
                                is_virtio: true,
                                device_path: PathBuf::new(),
                            };
                            
                            // Get friendly name
                            if SetupDiGetDeviceRegistryPropertyW(
                                h_dev_info,
                                &mut dev_info_data,
                                SPDRP_FRIENDLYNAME,
                                ptr::null_mut(),
                                buffer.as_mut_ptr() as LPBYTE,
                                (buffer.len() * 2) as DWORD,
                                &mut required_size,
                            ) != FALSE {
                                device_info.friendly_name = OsString::from_wide(&buffer[..])
                                    .to_string_lossy()
                                    .trim_end_matches('\0')
                                    .to_string();
                            }
                            
                            // Get device instance ID
                            let mut instance_id_buffer: [u16; 256] = [0; 256];
                            if SetupDiGetDeviceInstanceIdW(
                                h_dev_info,
                                &mut dev_info_data,
                                instance_id_buffer.as_mut_ptr(),
                                instance_id_buffer.len() as DWORD,
                                &mut required_size,
                            ) != FALSE {
                                let instance_id = OsString::from_wide(&instance_id_buffer[..])
                                    .to_string_lossy()
                                    .trim_end_matches('\0')
                                    .to_string();
                                debug!("Device instance ID: {}", instance_id);
                            }
                            
                            devices.push(device_info);
                        }
                    }
                }
            }
        }
        
        Ok(devices)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {
    Err(anyhow!("System device enumeration is only supported on Windows"))
}

/// Try to find VirtIO device paths through alternative methods
#[cfg(target_os = "windows")]
pub fn find_virtio_device_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    
    // Common VirtIO device paths on Windows
    let possible_paths = vec![
        PathBuf::from(r"\\.\VirtioSerial"),
        PathBuf::from(r"\\.\Global\VirtioSerial"),
        PathBuf::from(r"\\.\pipe\VirtioSerial"),
        PathBuf::from(r"\\.\Global\org.qemu.guest_agent.0"),
        PathBuf::from(r"\\.\pipe\org.qemu.guest_agent.0"),
        PathBuf::from(r"\\.\Global\org.infinibay.ping"),
        PathBuf::from(r"\\.\pipe\org.infinibay.ping"),
    ];
    
    for path in possible_paths {
        // Try to open the device to check if it exists
        use std::fs::OpenOptions;
        if let Ok(_) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            info!("Found working VirtIO device path: {}", path.display());
            paths.push(path);
        } else {
            debug!("VirtIO device path not accessible: {}", path.display());
        }
    }
    
    // Also try numbered VirtIO devices
    for i in 0..10 {
        let path = PathBuf::from(format!(r"\\.\VirtioSerial{}", i));
        use std::fs::OpenOptions;
        if let Ok(_) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            info!("Found numbered VirtIO device: {}", path.display());
            paths.push(path);
        }
    }
    
    paths
}

#[cfg(not(target_os = "windows"))]
pub fn find_virtio_device_paths() -> Vec<PathBuf> {
    Vec::new()
}

/// Get device interface paths for VirtIO serial devices
#[cfg(target_os = "windows")]
pub fn get_virtio_device_interfaces() -> Result<Vec<String>> {
    use std::process::Command;
    
    let mut interfaces = Vec::new();
    
    // Use PowerShell to get device interfaces
    let ps_cmd = r#"
        $devices = Get-PnpDevice | Where-Object {$_.InstanceId -like '*VEN_1AF4*DEV_1043*'}
        foreach ($device in $devices) {
            $interfaces = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DeviceDesc', 'DEVPKEY_Device_FriendlyName', 'DEVPKEY_Device_InstanceId'
            Write-Output $device.InstanceId
        }
    "#;
    
    match Command::new("powershell")
        .args(&["-Command", ps_cmd])
        .output()
    {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let line = line.trim();
                if !line.is_empty() && line.contains("VEN_1AF4") {
                    interfaces.push(line.to_string());
                    debug!("Found VirtIO device interface: {}", line);
                }
            }
        }
        Err(e) => {
            warn!("Failed to get device interfaces: {}", e);
        }
    }
    
    Ok(interfaces)
}

#[cfg(not(target_os = "windows"))]
pub fn get_virtio_device_interfaces() -> Result<Vec<String>> {
    Err(anyhow!("Device interface enumeration is only supported on Windows"))
}

/// Check if VirtIO drivers are installed and get diagnostic info
#[cfg(target_os = "windows")]
pub fn diagnose_virtio_installation() -> Result<String> {
    use std::process::Command;
    
    let mut diagnosis = String::new();
    diagnosis.push_str("VirtIO Installation Diagnosis\n");
    diagnosis.push_str("============================\n\n");
    
    // Check for VirtIO devices using PowerShell
    let ps_cmd = r#"Get-WmiObject Win32_PnPEntity | Where-Object {$_.DeviceID -like '*VEN_1AF4*'} | Select-Object Name, DeviceID, Status, Service"#;
    
    match Command::new("powershell")
        .args(&["-Command", ps_cmd])
        .output()
    {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.trim().is_empty() {
                diagnosis.push_str("❌ No VirtIO devices found in Device Manager\n");
            } else {
                diagnosis.push_str("✓ VirtIO devices found:\n");
                diagnosis.push_str(&output_str);
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to query VirtIO devices: {}\n", e));
        }
    }
    
    diagnosis.push_str("\n");
    
    // Check for VirtIO serial specific devices
    let serial_cmd = r#"Get-WmiObject Win32_PnPEntity | Where-Object {$_.DeviceID -like '*VEN_1AF4*' -and ($_.DeviceID -like '*DEV_1003*' -or $_.DeviceID -like '*DEV_1043*' -or $_.DeviceID -like '*DEV_1044*')} | Select-Object Name, DeviceID, Status"#;
    
    match Command::new("powershell")
        .args(&["-Command", serial_cmd])
        .output()
    {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.trim().is_empty() {
                diagnosis.push_str("❌ No VirtIO serial devices found\n");
            } else {
                diagnosis.push_str("✓ VirtIO serial devices found:\n");
                diagnosis.push_str(&output_str);
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to query VirtIO serial devices: {}\n", e));
        }
    }
    
    diagnosis.push_str("\n");
    
    // Check COM ports
    match enumerate_com_ports() {
        Ok(ports) => {
            if ports.is_empty() {
                diagnosis.push_str("❌ No COM ports found\n");
            } else {
                diagnosis.push_str(&format!("✓ {} COM port(s) found:\n", ports.len()));
                for port in ports {
                    diagnosis.push_str(&format!("  - {} ({}): {}\n", 
                                               port.port_name, 
                                               port.friendly_name,
                                               if port.is_virtio { "VirtIO" } else { "Non-VirtIO" }));
                }
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to enumerate COM ports: {}\n", e));
        }
    }
    
    diagnosis.push_str("\n");
    
    // Check for alternative VirtIO paths
    let alt_paths = find_virtio_device_paths();
    if alt_paths.is_empty() {
        diagnosis.push_str("❌ No alternative VirtIO device paths found\n");
    } else {
        diagnosis.push_str(&format!("✓ {} alternative VirtIO path(s) found:\n", alt_paths.len()));
        for path in alt_paths {
            diagnosis.push_str(&format!("  - {}\n", path.display()));
        }
    }
    
    diagnosis.push_str("\n");
    
    // Check device interfaces
    match get_virtio_device_interfaces() {
        Ok(interfaces) => {
            if interfaces.is_empty() {
                diagnosis.push_str("❌ No VirtIO device interfaces found\n");
            } else {
                diagnosis.push_str(&format!("✓ {} VirtIO device interface(s) found:\n", interfaces.len()));
                for interface in interfaces {
                    diagnosis.push_str(&format!("  - {}\n", interface));
                }
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to get device interfaces: {}\n", e));
        }
    }
    
    diagnosis.push_str("\n=== Recommendations ===\n");
    diagnosis.push_str("If VirtIO Serial Driver is installed but not accessible:\n");
    diagnosis.push_str("1. Check VM XML configuration for virtio-serial channel\n");
    diagnosis.push_str("2. Ensure channel has: <target type='virtio' name='org.infinibay.ping'/>\n");
    diagnosis.push_str("3. Try adding: <source mode='bind' path='/tmp/infinibay.sock'/>\n");
    diagnosis.push_str("4. Restart the VM after configuration changes\n");
    diagnosis.push_str("5. Consider using QEMU guest agent as alternative\n");
    
    Ok(diagnosis)
}

#[cfg(not(target_os = "windows"))]
pub fn diagnose_virtio_installation() -> Result<String> {
    Err(anyhow!("VirtIO diagnosis is only available on Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_com_port_info_creation() {
        let port = ComPortInfo {
            port_name: "COM3".to_string(),
            friendly_name: "VirtIO Serial Port (COM3)".to_string(),
            hardware_id: r"PCI\VEN_1AF4&DEV_1003".to_string(),
            is_virtio: true,
            device_path: PathBuf::from(r"\\.\COM3"),
        };
        
        assert_eq!(port.port_name, "COM3");
        assert!(port.is_virtio);
        assert!(port.hardware_id.contains("VEN_1AF4"));
    }
    
    #[cfg(target_os = "windows")]
    #[test]
    fn test_enumerate_com_ports_doesnt_panic() {
        // This test just ensures the function doesn't panic
        // It may or may not find ports depending on the system
        let result = enumerate_com_ports();
        assert!(result.is_ok() || result.is_err());
    }
    
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_non_windows_returns_error() {
        let result = enumerate_com_ports();
        assert!(result.is_err());
        
        let result = find_virtio_com_port();
        assert!(result.is_err());
    }
}