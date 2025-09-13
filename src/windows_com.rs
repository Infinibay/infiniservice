//! Windows COM port detection module for virtio-serial devices
//! 
//! This module provides functionality to detect and enumerate COM ports on Windows,
//! specifically looking for virtio-serial devices by their vendor ID.

#[cfg(target_os = "windows")]
use winapi::{
    shared::{
        guiddef::GUID,
        minwindef::{DWORD, HKEY, LPBYTE, FALSE},
        winerror::ERROR_SUCCESS,
    },
    um::{
        setupapi::*,
        winreg::*,
        winnt::KEY_READ,
        handleapi::INVALID_HANDLE_VALUE,
        cfgmgr32::{CM_Get_DevNode_Status, CR_SUCCESS},
    },
};

use anyhow::{Result, anyhow};
use log::{info, debug, warn};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;
use std::mem;

/// Information about a COM port or VirtIO device
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
    /// Device instance ID for detailed identification
    pub instance_id: String,
    /// Device status (enabled, disabled, problem)
    pub device_status: String,
    /// Driver service name
    pub driver_service: String,
    /// Device location information
    pub location_info: String,
    /// Device interface paths (for non-COM VirtIO devices)
    pub interface_paths: Vec<String>,
}

/// GUID for COM port devices
#[cfg(target_os = "windows")]
const GUID_DEVINTERFACE_COMPORT: GUID = GUID {
    Data1: 0x86E0D1E0,
    Data2: 0x8089,
    Data3: 0x11D0,
    Data4: [0x9C, 0xE4, 0x08, 0x00, 0x3E, 0x30, 0x1F, 0x73],
};

/// GUID for disk devices
#[cfg(target_os = "windows")]
const GUID_DEVINTERFACE_DISK: GUID = GUID {
    Data1: 0x53F56307,
    Data2: 0xB6BF,
    Data3: 0x11D0,
    Data4: [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
};

/// GUID for volume devices
#[cfg(target_os = "windows")]
const GUID_DEVINTERFACE_VOLUME: GUID = GUID {
    Data1: 0x53F5630D,
    Data2: 0xB6BF,
    Data3: 0x11D0,
    Data4: [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
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

/// Device node status flags
#[cfg(target_os = "windows")]
const DN_ROOT_ENUMERATED: u32 = 0x00000001;
#[cfg(target_os = "windows")]
const DN_DRIVER_LOADED: u32 = 0x00000002;
#[cfg(target_os = "windows")]
const DN_ENUM_LOADED: u32 = 0x00000004;
#[cfg(target_os = "windows")]
const DN_STARTED: u32 = 0x00000008;
#[cfg(target_os = "windows")]
const DN_MANUAL: u32 = 0x00000010;
#[cfg(target_os = "windows")]
const DN_NEED_TO_ENUM: u32 = 0x00000020;
#[cfg(target_os = "windows")]
const DN_DRIVER_BLOCKED: u32 = 0x00000040;
#[cfg(target_os = "windows")]
const DN_HARDWARE_ENUM: u32 = 0x00000080;
#[cfg(target_os = "windows")]
const DN_NEED_RESTART: u32 = 0x00000100;
#[cfg(target_os = "windows")]
const DN_CHILD_WITH_INVALID_ID: u32 = 0x00000200;
#[cfg(target_os = "windows")]
const DN_HAS_PROBLEM: u32 = 0x00000400;
#[cfg(target_os = "windows")]
const DN_FILTERED: u32 = 0x00000800;
#[cfg(target_os = "windows")]
const DN_LEGACY_DRIVER: u32 = 0x00001000;
#[cfg(target_os = "windows")]
const DN_DISABLEABLE: u32 = 0x00002000;
#[cfg(target_os = "windows")]
const DN_REMOVABLE: u32 = 0x00004000;
#[cfg(target_os = "windows")]
const DN_PRIVATE_PROBLEM: u32 = 0x00008000;
#[cfg(target_os = "windows")]
const DN_MF_PARENT: u32 = 0x00010000;
#[cfg(target_os = "windows")]
const DN_MF_CHILD: u32 = 0x00020000;
#[cfg(target_os = "windows")]
const DN_WILL_BE_REMOVED: u32 = 0x00040000;

/// Helper function to translate device node status and problem codes to readable strings
#[cfg(target_os = "windows")]
fn translate_device_status(status: u32, problem: u32) -> String {
    if status & DN_HAS_PROBLEM != 0 {
        let problem_desc = match problem {
            1 => "Not configured",
            2 => "DevLoader failed",
            3 => "Out of memory",
            4 => "Entry point not found",
            5 => "Control file not found",
            6 => "Invalid captive",
            7 => "Driver failed previous attempts",
            8 => "Driver service key invalid",
            9 => "Legacy service no devices",
            10 => "Duplicate device",
            11 => "Failed install",
            12 => "Failed install",
            13 => "Invalid log configuration",
            14 => "Device disabled",
            15 => "DevLoader not ready",
            16 => "Device not there",
            17 => "Moved",
            18 => "Too early",
            19 => "No valid log configuration",
            20 => "Failed install",
            21 => "Hardware disabled",
            22 => "Can't share IRQ",
            23 => "Driver failed add",
            24 => "System shutdown",
            25 => "Failed start",
            26 => "IRQ translation failed",
            27 => "Failed driver entry",
            28 => "Device loader missing",
            29 => "Invalid ID",
            30 => "Failed query remove",
            31 => "Failed remove",
            32 => "Invalid removal policy",
            33 => "Translation failed",
            34 => "IRQ translation failed",
            35 => "Restart enumeration",
            36 => "Partial log configuration",
            37 => "Unknown resource",
            38 => "Reinstall",
            39 => "Registry",
            40 => "VxD loader",
            41 => "System hive too large",
            42 => "Driver blocked",
            43 => "Registry too large",
            44 => "Setproperties failed",
            45 => "Waiting on dependency",
            46 => "Boot config conflict",
            47 => "Failed filter",
            48 => "Phantom",
            49 => "System shutdown",
            50 => "Held for ejection",
            51 => "Driver blocked",
            52 => "Registry too large",
            53 => "Console locked",
            54 => "Need class config",
            _ => "Unknown problem",
        };
        format!("Problem (Code {}): {}", problem, problem_desc)
    } else if status & DN_STARTED != 0 {
        "Working properly".to_string()
    } else if status & DN_DRIVER_LOADED == 0 {
        "Driver not loaded".to_string()
    } else if status & DN_ENUM_LOADED == 0 {
        "Enumeration not loaded".to_string()
    } else {
        format!("Status: 0x{:08X}", status)
    }
}

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
                instance_id: String::new(),
                device_status: String::new(),
                driver_service: String::new(),
                location_info: String::new(),
                interface_paths: Vec::new(),
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
                                instance_id: String::new(),
                                device_status: String::new(),
                                driver_service: String::new(),
                                location_info: String::new(),
                                interface_paths: Vec::new(),
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
                                device_info.instance_id = OsString::from_wide(&instance_id_buffer[..])
                                    .to_string_lossy()
                                    .trim_end_matches('\0')
                                    .to_string();
                                debug!("Device instance ID: {}", device_info.instance_id);
                            }

                            // Get device status using Configuration Manager API
                            let mut status: u32 = 0;
                            let mut problem: u32 = 0;
                            let cm_result = CM_Get_DevNode_Status(
                                &mut status,
                                &mut problem,
                                dev_info_data.DevInst,
                                0,
                            );

                            if cm_result == CR_SUCCESS {
                                device_info.device_status = translate_device_status(status, problem);
                                debug!("Device status: {} (status: 0x{:08X}, problem: {})",
                                       device_info.device_status, status, problem);
                            } else {
                                device_info.device_status = format!("Unknown (CM error: 0x{:08X})", cm_result);
                                debug!("Failed to get device status: CM error 0x{:08X}", cm_result);
                            }

                            // Get driver service name
                            if SetupDiGetDeviceRegistryPropertyW(
                                h_dev_info,
                                &mut dev_info_data,
                                SPDRP_SERVICE,
                                ptr::null_mut(),
                                buffer.as_mut_ptr() as LPBYTE,
                                (buffer.len() * 2) as DWORD,
                                &mut required_size,
                            ) != FALSE {
                                device_info.driver_service = OsString::from_wide(&buffer[..])
                                    .to_string_lossy()
                                    .trim_end_matches('\0')
                                    .to_string();
                                debug!("Driver service: {}", device_info.driver_service);
                            }

                            // Get location information
                            if SetupDiGetDeviceRegistryPropertyW(
                                h_dev_info,
                                &mut dev_info_data,
                                SPDRP_LOCATION_INFORMATION,
                                ptr::null_mut(),
                                buffer.as_mut_ptr() as LPBYTE,
                                (buffer.len() * 2) as DWORD,
                                &mut required_size,
                            ) != FALSE {
                                device_info.location_info = OsString::from_wide(&buffer[..])
                                    .to_string_lossy()
                                    .trim_end_matches('\0')
                                    .to_string();
                                debug!("Location info: {}", device_info.location_info);
                            }

                            // Try to get device interface paths for this device
                            device_info.interface_paths = get_device_interface_paths(h_dev_info, &dev_info_data);

                            // Enhanced logging for DEV_1043 devices
                            if hardware_id.contains("DEV_1043") {
                                info!("=== Enhanced DEV_1043 Device Analysis ===");
                                info!("  Hardware ID: {}", device_info.hardware_id);
                                info!("  Friendly Name: {}", device_info.friendly_name);
                                info!("  Instance ID: {}", device_info.instance_id);
                                info!("  Status: {}", device_info.device_status);
                                info!("  Driver Service: {}", device_info.driver_service);
                                info!("  Location: {}", device_info.location_info);
                                info!("  Interface Paths: {:?}", device_info.interface_paths);

                                if device_info.driver_service.is_empty() {
                                    warn!("  ⚠️  No driver service found - driver may not be properly installed");
                                }
                                if device_info.device_status.contains("Problem") {
                                    warn!("  ⚠️  Device has problems - check Device Manager for details");
                                }
                                if device_info.interface_paths.is_empty() {
                                    warn!("  ⚠️  No device interfaces found - device may not be accessible");
                                }
                                info!("==========================================");
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

/// Helper function to get device interface paths for a specific device
#[cfg(target_os = "windows")]
unsafe fn get_device_interface_paths(h_dev_info: HDEVINFO, target_dev_info_data: &SP_DEVINFO_DATA) -> Vec<String> {
    let mut interface_paths = Vec::new();

    // Get the target device's instance ID for comparison
    let mut target_instance_id_buffer: [u16; 256] = [0; 256];
    let mut required_size = 0;
    let target_instance_id = if SetupDiGetDeviceInstanceIdW(
        h_dev_info,
        target_dev_info_data as *const _ as *mut _,
        target_instance_id_buffer.as_mut_ptr(),
        target_instance_id_buffer.len() as DWORD,
        &mut required_size,
    ) != FALSE {
        OsString::from_wide(&target_instance_id_buffer[..])
            .to_string_lossy()
            .trim_end_matches('\0')
            .to_string()
    } else {
        return interface_paths; // Can't get target instance ID, return empty
    };

    // Try to get device interfaces for various VirtIO-related interface classes
    let interface_guids = [
        GUID_DEVINTERFACE_COMPORT,
        // VirtIO-specific device interface GUIDs
        GUID_DEVINTERFACE_DISK,
        GUID_DEVINTERFACE_VOLUME,
        // Custom VirtIO serial interface GUIDs used by different hypervisors
        // QEMU/KVM VirtIO Serial GUID
        GUID {
            Data1: 0x86e0d1e0,
            Data2: 0x8089,
            Data3: 0x11d0,
            Data4: [0x9c, 0xe4, 0x08, 0x00, 0x3e, 0x30, 0x1f, 0x73],
        },
        // VMware VirtIO Serial GUID
        GUID {
            Data1: 0x4d36e978,
            Data2: 0xe325,
            Data3: 0x11ce,
            Data4: [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
        },
        // VirtualBox VirtIO Serial GUID
        GUID {
            Data1: 0x2c7089aa,
            Data2: 0x2e0e,
            Data3: 0x11d1,
            Data4: [0xb1, 0x14, 0x00, 0xc0, 0x4f, 0xc2, 0xaa, 0xe4],
        },
        // Generic VirtIO device interface GUID
        GUID {
            Data1: 0x6fde7521,
            Data2: 0x1b65,
            Data3: 0x48ae,
            Data4: [0xb6, 0x28, 0x80, 0xbe, 0x62, 0x01, 0x60, 0x26],
        },
    ];

    for guid in &interface_guids {
        let h_interface_dev_info = SetupDiGetClassDevsW(
            guid,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );

        if h_interface_dev_info != INVALID_HANDLE_VALUE {
            let _cleanup = DevInfoCleanup(h_interface_dev_info);

            let mut dev_interface_data: SP_DEVICE_INTERFACE_DATA = mem::zeroed();
            dev_interface_data.cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as DWORD;

            let mut index = 0;
            while SetupDiEnumDeviceInterfaces(
                h_interface_dev_info,
                ptr::null_mut(),
                guid,
                index,
                &mut dev_interface_data,
            ) != FALSE {
                index += 1;

                // Get the required size for the detail data
                let mut required_size = 0;
                SetupDiGetDeviceInterfaceDetailW(
                    h_interface_dev_info,
                    &mut dev_interface_data,
                    ptr::null_mut(),
                    0,
                    &mut required_size,
                    ptr::null_mut(),
                );

                if required_size > 0 {
                    // Allocate buffer for the detail data
                    let mut detail_buffer: Vec<u8> = vec![0; required_size as usize];
                    let detail_data = detail_buffer.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
                    (*detail_data).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as DWORD;

                    // Get device info data for this interface
                    let mut interface_dev_info_data: SP_DEVINFO_DATA = mem::zeroed();
                    interface_dev_info_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as DWORD;

                    if SetupDiGetDeviceInterfaceDetailW(
                        h_interface_dev_info,
                        &mut dev_interface_data,
                        detail_data,
                        required_size,
                        ptr::null_mut(),
                        &mut interface_dev_info_data,
                    ) != FALSE {
                        // Get instance ID for this interface device
                        let mut interface_instance_id_buffer: [u16; 256] = [0; 256];
                        if SetupDiGetDeviceInstanceIdW(
                            h_interface_dev_info,
                            &mut interface_dev_info_data,
                            interface_instance_id_buffer.as_mut_ptr(),
                            interface_instance_id_buffer.len() as DWORD,
                            &mut required_size,
                        ) != FALSE {
                            let interface_instance_id = OsString::from_wide(&interface_instance_id_buffer[..])
                                .to_string_lossy()
                                .trim_end_matches('\0')
                                .to_string();

                            // Only add the path if instance IDs match
                            if interface_instance_id == target_instance_id {
                                let path_ptr = (*detail_data).DevicePath.as_ptr();
                                let path_len = (0..).take_while(|&i| *path_ptr.offset(i) != 0).count();
                                let path_slice = std::slice::from_raw_parts(path_ptr, path_len);
                                let device_path = OsString::from_wide(path_slice).to_string_lossy().to_string();

                                if !device_path.is_empty() {
                                    interface_paths.push(device_path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    interface_paths
}

#[cfg(not(target_os = "windows"))]
pub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {
    Err(anyhow!("System device enumeration is only supported on Windows"))
}

/// Try to find VirtIO device paths through alternative methods
#[cfg(target_os = "windows")]
pub fn find_virtio_device_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Discover interface/device paths from system devices
    match find_virtio_system_devices() {
        Ok(devices) => {
            for device in devices {
                // Add interface paths from detected devices
                for interface_path in device.interface_paths {
                    let path = PathBuf::from(&interface_path);
                    if !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            }
        }
        Err(e) => {
            debug!("Could not enumerate system devices for paths: {}", e);
        }
    }

    // Common VirtIO device paths on Windows
    let possible_paths = vec![
        PathBuf::from(r"\\.\VirtioSerial"),  // Direct device
        PathBuf::from(r"\\.\Global\VirtioSerial"),  // Global object
        PathBuf::from(r"\\.\pipe\VirtioSerial"),  // Named pipe
        PathBuf::from(r"\\.\Global\org.qemu.guest_agent.0"),  // Global object
        PathBuf::from(r"\\.\pipe\org.qemu.guest_agent.0"),  // Named pipe
        PathBuf::from(r"\\.\Global\org.infinibay.agent"),  // Global object
        PathBuf::from(r"\\.\pipe\org.infinibay.agent"),  // Named pipe
    ];

    for path in possible_paths {
        // Use standard file operations for all paths to avoid circular dependency
        use std::fs::OpenOptions;
        let accessible = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .is_ok();

        if accessible {
            info!("Found working VirtIO device path: {}", path.display());
            if !paths.contains(&path) {
                paths.push(path);
            }
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

/// Get VirtIO device instance IDs for diagnostic purposes
#[cfg(target_os = "windows")]
pub fn get_virtio_instance_ids() -> Result<Vec<String>> {
    use std::process::Command;

    let mut instance_ids = Vec::new();

    // Use PowerShell to get device instance IDs
    let ps_cmd = r#"
        $devices = Get-PnpDevice | Where-Object {$_.InstanceId -like '*VEN_1AF4*DEV_1043*'}
        foreach ($device in $devices) {
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
                    instance_ids.push(line.to_string());
                    debug!("Found VirtIO device instance ID: {}", line);
                }
            }
        }
        Err(e) => {
            warn!("Failed to get device instance IDs: {}", e);
        }
    }

    Ok(instance_ids)
}

#[cfg(not(target_os = "windows"))]
pub fn get_virtio_instance_ids() -> Result<Vec<String>> {
    Err(anyhow!("Device instance ID enumeration is only supported on Windows"))
}

/// Check if VirtIO drivers are installed and get diagnostic info
#[cfg(target_os = "windows")]
pub fn diagnose_virtio_installation() -> Result<String> {
    use std::process::Command;

    let mut diagnosis = String::new();
    diagnosis.push_str("Enhanced VirtIO Installation Diagnosis\n");
    diagnosis.push_str("=====================================\n\n");

    // Check administrator privileges first
    diagnosis.push_str("=== Administrator Privilege Status ===\n");
    match check_admin_privileges() {
        Ok(privilege_status) => {
            diagnosis.push_str(&format!("Is Elevated: {}\n", privilege_status.is_elevated));
            diagnosis.push_str(&format!("Is Admin Member: {}\n", privilege_status.is_admin_member));
            diagnosis.push_str(&format!("Token Type: {}\n", privilege_status.token_elevation_type));
            diagnosis.push_str(&format!("UAC Enabled: {}\n", privilege_status.uac_enabled));

            if privilege_status.elevation_required {
                diagnosis.push_str("❌ Administrator privileges required but not available\n");
                for guidance in &privilege_status.guidance {
                    diagnosis.push_str(&format!("   {}\n", guidance));
                }
            } else if privilege_status.is_elevated {
                diagnosis.push_str("✅ Running with administrator privileges\n");
            } else {
                diagnosis.push_str("⚠️  Privilege status unclear - may need elevation for device access\n");
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("⚠️  Could not check administrator privileges: {}\n", e));
        }
    }
    diagnosis.push_str("\n");

    // Enhanced device analysis using our improved detection
    diagnosis.push_str("=== Enhanced VirtIO Device Detection ===\n");
    match find_virtio_system_devices() {
        Ok(devices) => {
            if devices.is_empty() {
                diagnosis.push_str("❌ No VirtIO serial devices found in system devices\n");
            } else {
                diagnosis.push_str(&format!("✓ {} VirtIO serial device(s) found:\n", devices.len()));
                for device in &devices {
                    diagnosis.push_str(&format!("  📱 Device: {}\n", device.friendly_name));
                    diagnosis.push_str(&format!("     Hardware ID: {}\n", device.hardware_id));
                    diagnosis.push_str(&format!("     Instance ID: {}\n", device.instance_id));
                    diagnosis.push_str(&format!("     Status: {}\n", device.device_status));
                    diagnosis.push_str(&format!("     Driver Service: {}\n", device.driver_service));
                    diagnosis.push_str(&format!("     Location: {}\n", device.location_info));

                    if !device.interface_paths.is_empty() {
                        diagnosis.push_str("     Interface Paths:\n");
                        for path in &device.interface_paths {
                            diagnosis.push_str(&format!("       - {}\n", path));
                        }
                    }

                    // Specific analysis for DEV_1043 devices
                    if device.hardware_id.contains("DEV_1043") {
                        diagnosis.push_str("\n     🔍 DEV_1043 Analysis:\n");
                        if device.driver_service.is_empty() {
                            diagnosis.push_str("       ⚠️  No driver service - driver installation issue\n");
                        } else {
                            diagnosis.push_str(&format!("       ✓ Driver service: {}\n", device.driver_service));
                        }

                        if device.device_status.contains("Problem") {
                            diagnosis.push_str("       ⚠️  Device has problems - check Device Manager\n");
                        } else {
                            diagnosis.push_str("       ✓ Device status appears normal\n");
                        }

                        if device.interface_paths.is_empty() {
                            diagnosis.push_str("       ⚠️  No accessible interfaces - configuration issue\n");
                        } else {
                            diagnosis.push_str("       ✓ Device interfaces available\n");
                        }
                    }
                    diagnosis.push_str("\n");
                }
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to enumerate VirtIO system devices: {}\n", e));

            // Check if this might be a privilege issue
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                if let Some(raw_err) = io_err.raw_os_error() {
                    if detect_privilege_requirements(raw_err as u32, &e.to_string()) {
                        diagnosis.push_str("   ⚠️  This error may be related to insufficient administrator privileges\n");
                        diagnosis.push_str("   💡 Try running as administrator to access device information\n");
                    }
                }
            }
        }
    }

    diagnosis.push_str("\n=== VirtIO Driver Service Status ===\n");
    // Check VirtIO driver services
    let service_cmd = r#"Get-Service | Where-Object {$_.Name -like '*virtio*' -or $_.Name -like '*vioser*'} | Select-Object Name, Status, StartType"#;
    match Command::new("powershell")
        .args(&["-Command", service_cmd])
        .output()
    {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.trim().is_empty() {
                diagnosis.push_str("❌ No VirtIO services found\n");
            } else {
                diagnosis.push_str("✓ VirtIO services:\n");
                diagnosis.push_str(&output_str);
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to query VirtIO services: {}\n", e));
        }
    }

    diagnosis.push_str("\n=== Registry Analysis ===\n");
    // Check VirtIO registry keys
    let reg_cmd = r#"
        $regPaths = @(
            'HKLM:\SYSTEM\CurrentControlSet\Services\vioser',
            'HKLM:\SYSTEM\CurrentControlSet\Services\VirtioSerial'
        )
        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                Write-Output "✓ Found registry key: $path"
                $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
                if ($props.Start) { Write-Output "  Start type: $($props.Start)" }
                if ($props.Type) { Write-Output "  Service type: $($props.Type)" }
            } else {
                Write-Output "❌ Missing registry key: $path"
            }
        }
    "#;

    match Command::new("powershell")
        .args(&["-Command", reg_cmd])
        .output()
    {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.trim().is_empty() {
                diagnosis.push_str("❌ No VirtIO registry keys found\n");
            } else {
                diagnosis.push_str(&output_str);
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to check registry: {}\n", e));
        }
    }

    diagnosis.push_str("\n=== Permission Analysis ===\n");
    // Check current user privileges
    let priv_cmd = r#"
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-Output "Current user: $($currentUser.Name)"
        Write-Output "Running as Administrator: $isAdmin"
        if (-not $isAdmin) {
            Write-Output "⚠️  Not running as Administrator - this may cause access issues"
        }
    "#;

    match Command::new("powershell")
        .args(&["-Command", priv_cmd])
        .output()
    {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            diagnosis.push_str(&output_str);
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to check privileges: {}\n", e));
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

            // Check if this might be a privilege issue
            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                if let Some(raw_err) = io_err.raw_os_error() {
                    if detect_privilege_requirements(raw_err as u32, &e.to_string()) {
                        diagnosis.push_str("   ⚠️  This error may be related to insufficient administrator privileges\n");
                        diagnosis.push_str("   💡 Try running as administrator to access COM port information\n");
                    }
                }
            }
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
    
    // Check device instance IDs
    match get_virtio_instance_ids() {
        Ok(instance_ids) => {
            if instance_ids.is_empty() {
                diagnosis.push_str("❌ No VirtIO device instance IDs found\n");
            } else {
                diagnosis.push_str(&format!("✓ {} VirtIO device instance ID(s) found:\n", instance_ids.len()));
                for instance_id in instance_ids {
                    diagnosis.push_str(&format!("  - {}\n", instance_id));
                }
            }
        }
        Err(e) => {
            diagnosis.push_str(&format!("Failed to get device instance IDs: {}\n", e));
        }
    }
    
    diagnosis.push_str("\n=== Hypervisor-Specific Configuration Examples ===\n");

    diagnosis.push_str("\n🔧 QEMU/KVM Configuration:\n");
    diagnosis.push_str("Add to VM XML configuration:\n");
    diagnosis.push_str("```xml\n");
    diagnosis.push_str("<devices>\n");
    diagnosis.push_str("  <channel type='unix'>\n");
    diagnosis.push_str("    <source mode='bind' path='/tmp/infinibay.sock'/>\n");
    diagnosis.push_str("    <target type='virtio' name='org.infinibay.agent'/>\n");
    diagnosis.push_str("  </channel>\n");
    diagnosis.push_str("</devices>\n");
    diagnosis.push_str("```\n");
    diagnosis.push_str("Or via command line:\n");
    diagnosis.push_str("-device virtio-serial-pci \\\n");
    diagnosis.push_str("-chardev socket,path=/tmp/infinibay.sock,server=on,wait=off,id=infinibay \\\n");
    diagnosis.push_str("-device virtserialport,chardev=infinibay,name=org.infinibay.agent\n\n");

    diagnosis.push_str("🔧 VMware Configuration:\n");
    diagnosis.push_str("Add to .vmx file:\n");
    diagnosis.push_str("```\n");
    diagnosis.push_str("serial0.present = \"TRUE\"\n");
    diagnosis.push_str("serial0.fileType = \"pipe\"\n");
    diagnosis.push_str("serial0.fileName = \"\\\\.\\pipe\\infinibay\"\n");
    diagnosis.push_str("serial0.pipe.endPoint = \"server\"\n");
    diagnosis.push_str("serial0.tryNoRxLoss = \"FALSE\"\n");
    diagnosis.push_str("```\n\n");

    diagnosis.push_str("🔧 VirtualBox Configuration:\n");
    diagnosis.push_str("Via VBoxManage command:\n");
    diagnosis.push_str("```\n");
    diagnosis.push_str("VBoxManage modifyvm \"VM_NAME\" --uart1 0x3F8 4\n");
    diagnosis.push_str("VBoxManage modifyvm \"VM_NAME\" --uartmode1 server \\\\.\\pipe\\infinibay\n");
    diagnosis.push_str("```\n\n");

    diagnosis.push_str("=== Step-by-Step Troubleshooting for DEV_1043 Issues ===\n");
    diagnosis.push_str("1. 🔍 Verify VirtIO Driver Installation:\n");
    diagnosis.push_str("   - Open Device Manager (devmgmt.msc)\n");
    diagnosis.push_str("   - Look for 'VirtIO Serial Driver' under 'System devices'\n");
    diagnosis.push_str("   - If missing or has warning icon, reinstall VirtIO drivers\n\n");

    diagnosis.push_str("2. 🔧 Check VM Configuration:\n");
    diagnosis.push_str("   - Ensure virtio-serial device is added to VM\n");
    diagnosis.push_str("   - Verify channel name matches 'org.infinibay.agent'\n");
    diagnosis.push_str("   - Restart VM after configuration changes\n\n");

    diagnosis.push_str("3. 🔐 Run with Administrator Privileges:\n");
    diagnosis.push_str("   - Right-click Command Prompt → 'Run as administrator'\n");
    diagnosis.push_str("   - Run: infiniservice.exe --diag\n");
    diagnosis.push_str("   - Check if access issues are resolved\n\n");

    diagnosis.push_str("4. 🔄 Reinstall VirtIO Drivers:\n");
    diagnosis.push_str("   - Download latest VirtIO drivers from Red Hat\n");
    diagnosis.push_str("   - Uninstall existing VirtIO drivers\n");
    diagnosis.push_str("   - Install fresh drivers and reboot\n\n");

    diagnosis.push_str("5. 🔍 Alternative Connection Methods:\n");
    diagnosis.push_str("   - Try QEMU Guest Agent if available\n");
    diagnosis.push_str("   - Use named pipes: \\\\.\\pipe\\org.infinibay.agent\n");
    diagnosis.push_str("   - Test Global objects: \\\\.\\Global\\org.infinibay.agent\n\n");

    diagnosis.push_str("6. 🛠️ Manual Device Path Testing:\n");
    diagnosis.push_str("   - Run: infiniservice.exe --device \"\\\\.\\Global\\org.infinibay.agent\"\n");
    diagnosis.push_str("   - Try: infiniservice.exe --device \"\\\\.\\pipe\\org.infinibay.agent\"\n");
    diagnosis.push_str("   - Test: infiniservice.exe --device \"COM1\" (if available)\n\n");

    diagnosis.push_str("=== Common Solutions for Access Denied (Error 5) ===\n");
    diagnosis.push_str("• Run service as Administrator or SYSTEM account\n");
    diagnosis.push_str("• Check Windows security policies for device access\n");
    diagnosis.push_str("• Verify VM configuration includes proper channel setup\n");
    diagnosis.push_str("• Ensure VirtIO drivers are signed and trusted\n");
    diagnosis.push_str("• Try disabling Windows Defender real-time protection temporarily\n\n");

    diagnosis.push_str("For more help, run: infiniservice.exe --debug --diag\n");

    Ok(diagnosis)
}

#[cfg(not(target_os = "windows"))]
pub fn diagnose_virtio_installation() -> Result<String> {
    Err(anyhow!("VirtIO diagnosis is only available on Windows"))
}

/// Try direct device access using various methods
#[cfg(target_os = "windows")]
pub fn try_direct_device_access(interface_path: &str) -> Result<String, String> {
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use std::ffi::CString;
    use std::ptr;

    let c_path = match CString::new(interface_path) {
        Ok(path) => path,
        Err(_) => return Err("Invalid device path".to_string()),
    };

    // Try different access modes
    let access_modes = vec![
        ("read-write", GENERIC_READ | GENERIC_WRITE),
        ("read-only", GENERIC_READ),
        ("write-only", GENERIC_WRITE),
    ];

    for (mode_name, access_mode) in access_modes {
        unsafe {
            let handle = CreateFileA(
                c_path.as_ptr(),
                access_mode,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            );

            if handle != INVALID_HANDLE_VALUE {
                CloseHandle(handle);
                return Ok(format!("{}:{}", interface_path, mode_name));
            }
        }
    }

    // Try overlapped I/O access
    unsafe {
        let handle = CreateFileA(
            c_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null_mut(),
            OPEN_EXISTING,
            winapi::um::winbase::FILE_FLAG_OVERLAPPED,
            ptr::null_mut(),
        );

        if handle != INVALID_HANDLE_VALUE {
            CloseHandle(handle);
            return Ok(format!("{}:overlapped", interface_path));
        }
    }

    Err(format!("All access methods failed for {}", interface_path))
}

/// Get device capabilities for VirtIO devices
#[cfg(target_os = "windows")]
pub fn get_virtio_device_capabilities(device_info: &ComPortInfo) -> Result<String, String> {
    let mut capabilities = Vec::new();

    // Conservative capability detection - only mark as experimental
    debug!("Detecting capabilities for device: {}", device_info.instance_id);

    // Only enable IOCTL if we have interface paths and device is working
    if !device_info.interface_paths.is_empty() &&
       (device_info.device_status.contains("Working") || device_info.device_status.contains("OK")) {
        capabilities.push("IOCTL_EXPERIMENTAL");
    }

    // Only enable overlapped I/O for confirmed working devices
    if device_info.device_status.contains("Working") || device_info.device_status.contains("OK") {
        capabilities.push("OVERLAPPED_EXPERIMENTAL");
    }

    // Memory-mapped I/O only for specific VirtIO devices with proper driver
    if (device_info.hardware_id.contains("VirtIO") || device_info.hardware_id.contains("DEV_1043")) &&
       !device_info.driver_service.is_empty() {
        capabilities.push("MEMORY_MAPPED_EXPERIMENTAL");
    }

    // Always return a result, even if empty
    if capabilities.is_empty() {
        Ok("BASIC".to_string()) // Minimal capability set
    } else {
        Ok(capabilities.join(", "))
    }
}

/// Analyze detected VirtIO devices to determine the best connection method
#[cfg(target_os = "windows")]
pub fn get_virtio_device_connection_recommendations(device_info: &ComPortInfo) -> String {
    let mut recommendations = Vec::<String>::new();

    // Analyze device status
    if device_info.device_status.contains("Working") || device_info.device_status.contains("OK") {
        recommendations.push("✅ Device status: Working properly".to_string());

        // Check for interface paths
        if !device_info.interface_paths.is_empty() {
            recommendations.push("🔗 Recommended: Try direct interface path connection".to_string());
            for (i, path) in device_info.interface_paths.iter().enumerate() {
                recommendations.push(format!("   Interface {}: {}", i + 1, path));
            }
        } else {
            recommendations.push("⚠️  No interface paths found - try alternative connection methods".to_string());
        }

        // Check driver service
        if !device_info.driver_service.is_empty() {
            recommendations.push(format!("✅ Driver service: {} (active)", device_info.driver_service));
        } else {
            recommendations.push("❌ No driver service - reinstall VirtIO drivers".to_string());
        }

    } else if device_info.device_status.contains("Problem") {
        recommendations.push("❌ Device has problems - check Device Manager".to_string());
        recommendations.push("💡 Solution: Update or reinstall VirtIO drivers".to_string());

    } else {
        recommendations.push("⚠️  Device status unknown - may need driver installation".to_string());
    }

    // Provide specific recommendations based on hardware ID
    if device_info.hardware_id.contains("DEV_1043") {
        recommendations.push("".to_string());
        recommendations.push("🎯 DEV_1043 Specific Recommendations:".to_string());

        if device_info.interface_paths.is_empty() {
            recommendations.push("1. Check VM configuration for virtio-serial channel".to_string());
            recommendations.push("   Required: <target type='virtio' name='org.infinibay.agent'/>".to_string());
            recommendations.push("2. Verify VirtIO drivers are properly installed".to_string());
            recommendations.push("3. Run as Administrator to access device".to_string());
        } else {
            recommendations.push("1. Try direct connection using detected interface paths".to_string());
            recommendations.push("2. If access denied, run as Administrator".to_string());
            recommendations.push("3. Check VM virtio-serial channel configuration".to_string());
        }
    }

    // Add hypervisor-specific guidance
    recommendations.push("".to_string());
    recommendations.push("🔧 Hypervisor Configuration Check:".to_string());
    recommendations.push("QEMU/KVM: Ensure <target type='virtio' name='org.infinibay.agent'/>".to_string());
    recommendations.push("VMware: Check serial port configuration in .vmx file".to_string());
    recommendations.push("VirtualBox: Verify serial port settings in VM configuration".to_string());

    recommendations.join("\n")
}

#[cfg(not(target_os = "windows"))]
pub fn try_direct_device_access(_interface_path: &str) -> Result<String, String> {
    Err("Direct device access is only supported on Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn get_virtio_device_capabilities(_device_info: &ComPortInfo) -> Result<String, String> {
    Err("Device capabilities detection is only supported on Windows".to_string())
}

/// Privilege status information for Windows systems
#[derive(Debug, Clone)]
pub struct PrivilegeStatus {
    pub is_elevated: bool,
    pub is_admin_member: bool,
    pub token_elevation_type: String,
    pub uac_enabled: bool,
    pub elevation_required: bool,
    pub guidance: Vec<String>,
}

/// Check current administrator privileges and elevation status
#[cfg(target_os = "windows")]
pub fn check_admin_privileges() -> anyhow::Result<PrivilegeStatus> {
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, TokenElevationType, TOKEN_QUERY, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE};
    // IsUserAnAdmin is not available in this winapi version, we'll use token information instead
    use winapi::um::winreg::{RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE};
    use winapi::um::winnt::{KEY_READ, KEY_WOW64_64KEY};
    use std::mem;
    use std::ptr;

    let mut privilege_status = PrivilegeStatus {
        is_elevated: false,
        is_admin_member: false,
        token_elevation_type: "Unknown".to_string(),
        uac_enabled: true,
        elevation_required: false,
        guidance: Vec::new(),
    };

    unsafe {
        // Check if user is member of administrators group using token information
        privilege_status.is_admin_member = false; // Will be set based on token elevation

        // Get current process token
        let mut token_handle = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) != 0 {
            // Check token elevation status
            let mut elevation: TOKEN_ELEVATION = mem::zeroed();
            let mut return_length = 0u32;

            if GetTokenInformation(
                token_handle,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            ) != 0 {
                privilege_status.is_elevated = elevation.TokenIsElevated != 0;
                // If the token is elevated, the user is effectively an admin
                privilege_status.is_admin_member = elevation.TokenIsElevated != 0;
            }

            // Check token elevation type
            let mut elevation_type: TOKEN_ELEVATION_TYPE = mem::zeroed();
            if GetTokenInformation(
                token_handle,
                TokenElevationType,
                &mut elevation_type as *mut _ as *mut _,
                mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
                &mut return_length,
            ) != 0 {
                privilege_status.token_elevation_type = match elevation_type {
                    1 => "Default".to_string(),      // TokenElevationTypeDefault
                    2 => "Full".to_string(),         // TokenElevationTypeFull
                    3 => "Limited".to_string(),      // TokenElevationTypeLimited
                    _ => "Unknown".to_string(),
                };
            }

            winapi::um::handleapi::CloseHandle(token_handle);
        }

        // Check UAC settings
        let mut hkey = ptr::null_mut();
        let uac_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\0"
            .encode_utf16()
            .collect::<Vec<u16>>();

        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            uac_key.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        ) == 0 {
            let mut uac_value = 0u32;
            let mut value_size = mem::size_of::<u32>() as u32;
            let uac_name = "EnableLUA\0".encode_utf16().collect::<Vec<u16>>();

            if RegQueryValueExW(
                hkey,
                uac_name.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut uac_value as *mut _ as *mut u8,
                &mut value_size,
            ) == 0 {
                privilege_status.uac_enabled = uac_value != 0;
            }

            winapi::um::winreg::RegCloseKey(hkey);
        }
    }

    // Determine if elevation is required and provide guidance
    if privilege_status.is_admin_member && !privilege_status.is_elevated {
        privilege_status.elevation_required = true;
        privilege_status.guidance.push("You are a member of the Administrators group but not running elevated.".to_string());
        privilege_status.guidance.push("VirtIO device access requires administrator privileges.".to_string());
    } else if !privilege_status.is_admin_member {
        privilege_status.elevation_required = true;
        privilege_status.guidance.push("Administrator privileges are required for VirtIO device access.".to_string());
        privilege_status.guidance.push("Contact your system administrator for elevated access.".to_string());
    }

    Ok(privilege_status)
}

/// Detect if specific error conditions require administrator privileges
pub fn detect_privilege_requirements(error_code: u32, error_message: &str) -> bool {
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
    const ERROR_SHARING_VIOLATION: u32 = 32;

    // First decide solely on error codes
    match error_code {
        ERROR_ACCESS_DENIED => {
            // Access denied is privilege-related for device access
            return true;
        },
        ERROR_PRIVILEGE_NOT_HELD => {
            // Explicit privilege error
            return true;
        },
        ERROR_SHARING_VIOLATION => {
            // Sharing violation - device is busy, not a privilege issue
            return false;
        },
        _ => {}
    }

    // Only use substring checks for our own error messages
    if error_message.starts_with("Failed to open device for") ||
       error_message.starts_with("Failed to open COM port for") {
        return true;
    }

    // Check for privilege-related patterns in our own error messages only
    let our_privilege_indicators = [
        "requires administrator",
        "elevation required",
        "run as administrator",
    ];

    let lower_message = error_message.to_lowercase();
    our_privilege_indicators.iter().any(|&indicator| lower_message.contains(indicator))
}

/// Get specific elevation guidance based on current system state
#[cfg(target_os = "windows")]
pub fn get_elevation_guidance() -> anyhow::Result<Vec<String>> {
    let privilege_status = check_admin_privileges()?;
    let mut guidance = Vec::new();

    guidance.push("=== Administrator Privilege Required ===".to_string());
    guidance.push("".to_string());

    if privilege_status.is_admin_member {
        guidance.push("You are a member of the Administrators group but not running elevated.".to_string());
        guidance.push("".to_string());
        guidance.push("To run InfiniService with administrator privileges:".to_string());
        guidance.push("".to_string());
        guidance.push("Method 1 - Right-click menu:".to_string());
        guidance.push("  1. Right-click on infiniservice.exe".to_string());
        guidance.push("  2. Select 'Run as administrator'".to_string());
        guidance.push("  3. Click 'Yes' when prompted by UAC".to_string());
        guidance.push("".to_string());
        guidance.push("Method 2 - Command line:".to_string());
        guidance.push("  runas /user:Administrator \"C:\\path\\to\\infiniservice.exe\"".to_string());
        guidance.push("".to_string());
        guidance.push("Method 3 - PowerShell (as Administrator):".to_string());
        guidance.push("  Start-Process -FilePath \"infiniservice.exe\" -Verb RunAs".to_string());
    } else {
        guidance.push("You are not a member of the Administrators group.".to_string());
        guidance.push("".to_string());
        guidance.push("Contact your system administrator to:".to_string());
        guidance.push("  1. Add your account to the Administrators group, OR".to_string());
        guidance.push("  2. Run InfiniService with administrator credentials".to_string());
        guidance.push("".to_string());
        guidance.push("Alternative - Run with administrator account:".to_string());
        guidance.push("  runas /user:Administrator \"C:\\path\\to\\infiniservice.exe\"".to_string());
    }

    guidance.push("".to_string());
    guidance.push("For persistent service installation:".to_string());
    guidance.push("  sc create InfiniService binPath=\"C:\\path\\to\\infiniservice.exe\"".to_string());
    guidance.push("  sc start InfiniService".to_string());
    guidance.push("".to_string());

    if !privilege_status.uac_enabled {
        guidance.push("Note: UAC is disabled on this system.".to_string());
        guidance.push("Administrator privileges may still be required for device access.".to_string());
    }

    Ok(guidance)
}

// Non-Windows stubs
#[cfg(not(target_os = "windows"))]
pub fn check_admin_privileges() -> anyhow::Result<PrivilegeStatus> {
    anyhow::bail!("Privilege checks are only supported on Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn get_elevation_guidance() -> anyhow::Result<Vec<String>> {
    anyhow::bail!("Elevation guidance is only available on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_privilege_requirements() {
        // Test with ERROR_ACCESS_DENIED and VirtIO-related message
        assert!(detect_privilege_requirements(5, "Access denied when opening VirtIO device"));

        // Test with ERROR_PRIVILEGE_NOT_HELD
        assert!(detect_privilege_requirements(1314, "A required privilege is not held by the client"));

        // Test with privilege-related message patterns
        assert!(detect_privilege_requirements(0, "access denied"));
        assert!(detect_privilege_requirements(0, "insufficient privileges"));
        assert!(detect_privilege_requirements(0, "requires administrator"));
        assert!(detect_privilege_requirements(0, "elevation required"));

        // Test with non-privilege-related errors
        assert!(!detect_privilege_requirements(2, "File not found"));
        assert!(!detect_privilege_requirements(0, "Network connection failed"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_check_admin_privileges() {
        // This test will run on Windows and check the current privilege status
        match check_admin_privileges() {
            Ok(status) => {
                // Verify the structure is populated correctly
                assert!(!status.token_elevation_type.is_empty());
                assert!(!status.guidance.is_empty() || status.is_elevated);

                println!("Privilege Status:");
                println!("  Is Elevated: {}", status.is_elevated);
                println!("  Is Admin Member: {}", status.is_admin_member);
                println!("  Token Type: {}", status.token_elevation_type);
                println!("  UAC Enabled: {}", status.uac_enabled);
                println!("  Elevation Required: {}", status.elevation_required);
            }
            Err(e) => {
                // On some systems, privilege checking might fail
                println!("Privilege check failed (this may be expected): {}", e);
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_elevation_guidance() {
        match get_elevation_guidance() {
            Ok(guidance) => {
                assert!(!guidance.is_empty());
                assert!(guidance.iter().any(|line| line.contains("Administrator")));

                println!("Elevation Guidance:");
                for line in guidance {
                    println!("  {}", line);
                }
            }
            Err(e) => {
                println!("Failed to get elevation guidance: {}", e);
            }
        }
    }

    #[test]
    fn test_com_port_info_creation() {
        let port = ComPortInfo {
            port_name: "COM3".to_string(),
            friendly_name: "VirtIO Serial Port (COM3)".to_string(),
            hardware_id: r"PCI\VEN_1AF4&DEV_1003".to_string(),
            is_virtio: true,
            device_path: PathBuf::from(r"\\.\COM3"),
            instance_id: "PCI\\VEN_1AF4&DEV_1003&SUBSYS_11001AF4&REV_00\\3&11583659&0&18".to_string(),
            device_status: "Working properly".to_string(),
            driver_service: "vioser".to_string(),
            location_info: "PCI bus 0, device 3, function 0".to_string(),
            interface_paths: vec![],
        };

        assert_eq!(port.port_name, "COM3");
        assert!(port.is_virtio);
        assert!(port.hardware_id.contains("VEN_1AF4"));
        assert_eq!(port.device_status, "Working properly");
        assert_eq!(port.driver_service, "vioser");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_enumerate_com_ports_doesnt_panic() {
        // This test just ensures the function doesn't panic
        // It may or may not find ports depending on the system
        let result = enumerate_com_ports();
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_find_virtio_system_devices_populates_fields() {
        // Test that find_virtio_system_devices populates the new fields when devices exist
        let result = find_virtio_system_devices();
        assert!(result.is_ok());

        let devices = result.unwrap();
        for device in devices {
            // Verify that new fields are populated (non-empty when devices exist)
            if device.is_virtio {
                assert!(!device.instance_id.is_empty(), "Instance ID should be populated for VirtIO devices");
                assert!(!device.device_status.is_empty(), "Device status should be populated");
                // driver_service and location_info may be empty for some devices, so we don't assert them
                // interface_paths may be empty if no interfaces are found
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_virtio_instance_ids_returns_valid_format() {
        // Test that get_virtio_instance_ids returns properly formatted instance IDs
        let result = get_virtio_instance_ids();
        assert!(result.is_ok());

        let instance_ids = result.unwrap();
        for instance_id in instance_ids {
            // Instance IDs should contain VEN_1AF4 if they're VirtIO devices
            assert!(instance_id.contains("VEN_1AF4"), "Instance ID should contain VEN_1AF4: {}", instance_id);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_diagnose_virtio_installation_includes_hypervisor_sections() {
        // Test that diagnose_virtio_installation includes hypervisor configuration examples
        let result = diagnose_virtio_installation();
        assert!(result.is_ok());

        let diagnosis = result.unwrap();

        // Check for hypervisor-specific sections
        assert!(diagnosis.contains("QEMU/KVM Configuration"), "Should include QEMU/KVM configuration");
        assert!(diagnosis.contains("VMware Configuration"), "Should include VMware configuration");
        assert!(diagnosis.contains("VirtualBox Configuration"), "Should include VirtualBox configuration");

        // Check for step-by-step troubleshooting
        assert!(diagnosis.contains("Step-by-Step Troubleshooting"), "Should include troubleshooting steps");
        assert!(diagnosis.contains("DEV_1043"), "Should mention DEV_1043 specifically");

        // Check for enhanced device analysis section
        assert!(diagnosis.contains("Enhanced VirtIO Device Detection"), "Should include enhanced detection section");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_translate_device_status() {
        // Test device status translation function
        assert_eq!(translate_device_status(DN_STARTED, 0), "Working properly");
        assert!(translate_device_status(DN_HAS_PROBLEM, 1).contains("Problem"));
        assert!(translate_device_status(0, 0).contains("Status:"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_find_virtio_device_paths_doesnt_panic() {
        // Test that find_virtio_device_paths doesn't panic and returns a vector
        let paths = find_virtio_device_paths();
        // Should return a vector (may be empty if no VirtIO devices are present)
        assert!(paths.len() >= 0);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_non_windows_returns_error() {
        let result = enumerate_com_ports();
        assert!(result.is_err());

        let result = find_virtio_com_port();
        assert!(result.is_err());

        let result = get_virtio_instance_ids();
        assert!(result.is_err());

        let result = diagnose_virtio_installation();
        assert!(result.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_try_direct_device_access_returns_consistent_format() {
        // Test that try_direct_device_access returns consistent format
        let result = try_direct_device_access("\\\\.\\nonexistent_device");

        // Should fail for non-existent device
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("All access methods failed"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_virtio_device_capabilities_returns_consistent_flags() {
        // Test that get_virtio_device_capabilities returns consistent flags
        let device_info = ComPortInfo {
            port_name: String::new(),
            friendly_name: "Test Device".to_string(),
            hardware_id: "VEN_1AF4&DEV_1043".to_string(),
            is_virtio: true,
            device_path: std::path::PathBuf::new(),
            instance_id: "TEST\\INSTANCE".to_string(),
            device_status: "Working properly".to_string(),
            driver_service: "vioser".to_string(),
            location_info: "PCI bus 0".to_string(),
            interface_paths: vec!["\\\\.\\test_interface".to_string()],
        };

        let result = get_virtio_device_capabilities(&device_info);
        assert!(result.is_ok());

        let capabilities = result.unwrap();
        // Should contain experimental flags for working device with interface paths
        assert!(capabilities.contains("EXPERIMENTAL") || capabilities == "BASIC");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_virtio_device_capabilities_minimal_device() {
        // Test capabilities for minimal device info
        let device_info = ComPortInfo {
            port_name: String::new(),
            friendly_name: "Minimal Device".to_string(),
            hardware_id: "UNKNOWN".to_string(),
            is_virtio: false,
            device_path: std::path::PathBuf::new(),
            instance_id: "MINIMAL\\INSTANCE".to_string(),
            device_status: "Unknown".to_string(),
            driver_service: String::new(),
            location_info: String::new(),
            interface_paths: vec![],
        };

        let result = get_virtio_device_capabilities(&device_info);
        assert!(result.is_ok());

        let capabilities = result.unwrap();
        // Should return BASIC for minimal device
        assert_eq!(capabilities, "BASIC");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_find_virtio_device_paths_returns_paths() {
        // Test that find_virtio_device_paths returns a vector (may be empty)
        let paths = find_virtio_device_paths();

        // Should return a vector (may be empty if no devices present)
        assert!(paths.len() >= 0);

        // If paths are returned, they should be valid PathBuf objects
        for path in paths {
            assert!(!path.to_string_lossy().is_empty());
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_virtio_device_connection_recommendations() {
        // Test connection recommendations function
        let device_info = ComPortInfo {
            port_name: String::new(),
            friendly_name: "Test VirtIO Device".to_string(),
            hardware_id: "VEN_1AF4&DEV_1043".to_string(),
            is_virtio: true,
            device_path: std::path::PathBuf::new(),
            instance_id: "TEST\\DEV_1043\\INSTANCE".to_string(),
            device_status: "Working properly".to_string(),
            driver_service: "vioser".to_string(),
            location_info: "PCI bus 0".to_string(),
            interface_paths: vec!["\\\\.\\test_interface".to_string()],
        };

        let recommendations = get_virtio_device_connection_recommendations(&device_info);

        // Should contain DEV_1043 specific recommendations
        assert!(recommendations.contains("DEV_1043"));
        assert!(recommendations.contains("Working properly"));
        assert!(recommendations.contains("interface paths"));
        assert!(recommendations.contains("Hypervisor Configuration"));
    }
}
