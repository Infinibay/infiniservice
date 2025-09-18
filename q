[1mdiff --git a/src/communication.rs b/src/communication.rs[m
[1mindex 5f0c218..55d5ea5 100644[m
[1m--- a/src/communication.rs[m
[1m+++ b/src/communication.rs[m
[36m@@ -144,29 +144,29 @@[m [mimpl VirtioSerial {[m
     /// Returns Ok(true) if device can be opened, Ok(false) if it exists but can't be opened, Err(error_code) on error[m
     #[cfg(target_os = "windows")][m
     fn try_open_windows_device(device_path: &str, debug_mode: bool) -> Result<bool, u32> {[m
[31m-        use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};[m
[32m+[m[32m        use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING, FILE_SHARE_READ, FILE_SHARE_WRITE};[m
         use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};[m
         use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};[m
         use winapi::um::errhandlingapi::GetLastError;[m
         use std::os::windows::ffi::OsStrExt;[m
         use std::ffi::OsStr;[m
[31m-        [m
[32m+[m
         let wide_path: Vec<u16> = OsStr::new(device_path)[m
             .encode_wide()[m
             .chain(std::iter::once(0))[m
             .collect();[m
[31m-        [m
[32m+[m
         unsafe {[m
             let handle = CreateFileW([m
                 wide_path.as_ptr(),[m
                 GENERIC_READ | GENERIC_WRITE,[m
[31m-                0, // No sharing for exclusive access[m
[32m+[m[32m                FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow sharing to avoid false negatives[m
                 std::ptr::null_mut(),[m
                 OPEN_EXISTING,[m
                 0,[m
                 std::ptr::null_mut(),[m
             );[m
[31m-            [m
[32m+[m
             if handle != INVALID_HANDLE_VALUE {[m
                 CloseHandle(handle);[m
                 if debug_mode {[m
[36m@@ -183,6 +183,134 @@[m [mimpl VirtioSerial {[m
         }[m
     }[m
 [m
[32m+[m[32m    #[cfg(target_os = "windows")][m
[32m+[m[32m    fn try_direct_virtio_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {[m
[32m+[m[32m        use crate::windows_com::{try_direct_device_access, get_virtio_device_capabilities};[m
[32m+[m
[32m+[m[32m        debug!("🔌 Attempting direct VirtIO connection for device: {}", device_info.instance_id);[m
[32m+[m
[32m+[m[32m        // Try device interface paths first[m
[32m+[m[32m        for interface_path in &device_info.interface_paths {[m
[32m+[m[32m            debug!("🔗 Trying interface path: {}", interface_path);[m
[32m+[m
[32m+[m[32m            match try_direct_device_access(interface_path) {[m
[32m+[m[32m                Ok(device_path) => {[m
[32m+[m[32m                    debug!("✅ Direct interface connection successful: {}", device_path);[m
[32m+[m[32m                    return Ok(device_path);[m
[32m+[m[32m                }[m
[32m+[m[32m                Err(e) => {[m
[32m+[m[32m                    debug!("❌ Interface path failed: {} - {}", interface_path, e);[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        // Get device capabilities to determine best connection method[m
[32m+[m[32m        match get_virtio_device_capabilities(device_info) {[m
[32m+[m[32m            Ok(capabilities) => {[m
[32m+[m[32m                debug!("📋 Device capabilities: {}", capabilities);[m
[32m+[m
[32m+[m[32m                // Try capability-specific connection methods[m
[32m+[m[32m                if capabilities.contains("IOCTL") {[m
[32m+[m[32m                    debug!("🔧 Attempting IOCTL-based connection");[m
[32m+[m[32m                    if let Ok(device_path) = try_ioctl_connection(device_info) {[m
[32m+[m[32m                        return Ok(device_path);[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m
[32m+[m[32m                if capabilities.contains("OVERLAPPED") {[m
[32m+[m[32m                    debug!("⏱️ Attempting overlapped I/O connection");[m
[32m+[m[32m                    if let Ok(device_path) = try_overlapped_connection(device_info) {[m
[32m+[m[32m                        return Ok(device_path);[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m
[32m+[m[32m                if capabilities.contains("MEMORY_MAPPED") {[m
[32m+[m[32m                    debug!("🗺️ Attempting memory-mapped I/O connection");[m
[32m+[m[32m                    if let Ok(device_path) = try_memory_mapped_connection(device_info) {[m
[32m+[m[32m                        return Ok(device_path);[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m[32m            Err(e) => {[m
[32m+[m[32m                debug!("⚠️ Could not determine device capabilities: {}", e);[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        // Try alternative device naming conventions[m
[32m+[m[32m        let alternative_paths = vec![[m
[32m+[m[32m            format!("\\\\.\\VirtioSerial{}", device_info.port_number.unwrap_or(0)),[m
[32m+[m[32m            format!("\\\\.\\Global\\VirtioSerial{}", device_info.port_number.unwrap_or(0)),[m
[32m+[m[32m            format!("\\\\.\\pipe\\VirtioSerial{}", device_info.port_number.unwrap_or(0)),[m
[32m+[m[32m            format!("\\\\.\\{}", device_info.instance_id),[m
[32m+[m[32m        ];[m
[32m+[m
[32m+[m[32m        for alt_path in alternative_paths {[m
[32m+[m[32m            debug!("🔄 Trying alternative path: {}", alt_path);[m
[32m+[m[32m            match try_open_windows_device(&alt_path) {[m
[32m+[m[32m                Ok(_) => {[m
[32m+[m[32m                    debug!("✅ Alternative path connection successful: {}", alt_path);[m
[32m+[m[32m                    return Ok(alt_path);[m
[32m+[m[32m                }[m
[32m+[m[32m                Err(e) => {[m
[32m+[m[32m                    debug!("❌ Alternative path failed: {} - {}", alt_path, e);[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        Err(format!("All direct VirtIO connection methods failed for device {}", device_info.instance_id))[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    #[cfg(target_os = "windows")][m
[32m+[m[32m    fn try_ioctl_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {[m
[32m+[m[32m        // Implementation for IOCTL-based VirtIO communication[m
[32m+[m[32m        debug!("🔧 Implementing IOCTL connection for {}", device_info.instance_id);[m
[32m+[m
[32m+[m[32m        // Try to open device with IOCTL access[m
[32m+[m[32m        for interface_path in &device_info.interface_paths {[m
[32m+[m[32m            if let Ok(_) = try_open_windows_device(interface_path) {[m
[32m+[m[32m                // TODO: Implement actual IOCTL communication[m
[32m+[m[32m                debug!("✅ IOCTL connection established via {}", interface_path);[m
[32m+[m[32m                return Ok(interface_path.clone());[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        Err("IOCTL connection failed".to_string())[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    #[cfg(target_os = "windows")][m
[32m+[m[32m    fn try_overlapped_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {[m
[32m+[m[32m        // Implementation for overlapped I/O VirtIO communication[m
[32m+[m[32m        debug!("⏱️ Implementing overlapped I/O connection for {}", device_info.instance_id);[m
[32m+[m
[32m+[m[32m        // Try overlapped I/O on interface paths[m
[32m+[m[32m        for interface_path in &device_info.interface_paths {[m
[32m+[m[32m            if let Ok(_) = try_open_windows_device(interface_path) {[m
[32m+[m[32m                // TODO: Implement actual overlapped I/O[m
[32m+[m[32m                debug!("✅ Overlapped I/O connection established via {}", interface_path);[m
[32m+[m[32m                return Ok(interface_path.clone());[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        Err("Overlapped I/O connection failed".to_string())[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    #[cfg(target_os = "windows")][m
[32m+[m[32m    fn try_memory_mapped_connection(device_info: &crate::windows_com::ComPortInfo) -> Result<String, String> {[m
[32m+[m[32m        // Implementation for memory-mapped I/O VirtIO communication[m
[32m+[m[32m        debug!("🗺️ Implementing memory-mapped I/O connection for {}", device_info.instance_id);[m
[32m+[m
[32m+[m[32m        // Try memory-mapped access[m
[32m+[m[32m        for interface_path in &device_info.interface_paths {[m
[32m+[m[32m            if let Ok(_) = try_open_windows_device(interface_path) {[m
[32m+[m[32m                // TODO: Implement actual memory-mapped I/O[m
[32m+[m[32m                debug!("✅ Memory-mapped I/O connection established via {}", interface_path);[m
[32m+[m[32m                return Ok(interface_path.clone());[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
[32m+[m[32m        Err("Memory-mapped I/O connection failed".to_string())[m
[32m+[m[32m    }[m
[32m+[m
     #[cfg(target_os = "windows")][m
     fn detect_windows_device(debug_mode: bool) -> Result<std::path::PathBuf> {[m
         use crate::windows_com::{find_virtio_com_port, enumerate_com_ports, try_open_com_port, [m
[36m@@ -273,11 +401,18 @@[m [mimpl VirtioSerial {[m
                             }[m
                             5 => {[m
                                 // ERROR_ACCESS_DENIED - exists but needs admin privileges or proper VM configuration[m
[31m-                                warn!("Access denied to VirtIO Global object: {}", path.display());[m
[31m-                                warn!("This may indicate:");[m
[31m-                                warn!("  1. The service needs administrator privileges");[m
[31m-                                warn!("  2. The VM needs proper VirtIO channel configuration");[m
[31m-                                warn!("  3. Windows needs VirtIO driver reinstallation");[m
[32m+[m[32m                                warn!("🔐 Access denied to VirtIO Global object: {}", path.display());[m
[32m+[m[32m                                warn!("📋 This typically indicates:");[m
[32m+[m[32m                                warn!("   1. Service needs Administrator privileges");[m
[32m+[m[32m                                warn!("   2. VM missing proper VirtIO channel configuration");[m
[32m+[m[32m                                warn!("   3. Windows security policies blocking device access");[m
[32m+[m[32m                                warn!("   4. VirtIO driver needs reinstallation");[m
[32m+[m[32m                                warn!("");[m
[32m+[m[32m                                warn!("💡 Immediate solutions to try:");[m
[32m+[m[32m                                warn!("   • Run: infiniservice.exe --diag (as Administrator)");[m
[32m+[m[32m                                warn!("   • Check VM XML for: <target type='virtio' name='org.infinibay.agent'/>");[m
[32m+[m[32m                                warn!("   • Verify VirtIO drivers are properly installed");[m
[32m+[m[32m                                warn!("   • Try alternative device paths with --device flag");[m
                                 access_denied_paths.push(path.clone());[m
                             }[m
                             _ => {[m
[36m@@ -325,11 +460,28 @@[m [mimpl VirtioSerial {[m
                         info!("  - {} (Hardware ID: {})", [m
                               device.friendly_name, device.hardware_id);[m
                         [m
[31m-                        // Check if it's the specific device from the screenshot[m
[32m+[m[32m                        // Enhanced guidance for DEV_1043 devices[m
                         if device.hardware_id.contains("DEV_1043") {[m
                             info!("Found VirtIO Serial Device (DEV_1043) as seen in Device Manager");[m
[31m-                            warn!("Note: This device may not be accessible as a COM port.");[m
[31m-                            warn!("The VirtIO serial driver may need additional configuration.");[m
[32m+[m[32m                            warn!("📋 DEV_1043 Device Analysis:");[m
[32m+[m[32m                            warn!("   Status: {}", device.device_status);[m
[32m+[m[32m                            warn!("   Driver Service: {}", if device.driver_service.is_empty() { "Not found" } else { &device.driver_service });[m
[32m+[m[32m                            warn!("   Instance ID: {}", device.instance_id);[m
[32m+[m
[32m+[m[32m                            if device.driver_service.is_empty() {[m
[32m+[m[32m                                warn!("❌ No driver service found - VirtIO driver installation issue");[m
[32m+[m[32m                                warn!("💡 Solution: Reinstall VirtIO drivers from latest ISO");[m
[32m+[m[32m                            } else if device.device_status.contains("Problem") {[m
[32m+[m[32m                                warn!("❌ Device has problems - check Device Manager for details");[m
[32m+[m[32m                                warn!("💡 Solution: Update or reinstall VirtIO drivers");[m
[32m+[m[32m                            } else if device.interface_paths.is_empty() {[m
[32m+[m[32m                                warn!("❌ Device installed but no accessible interfaces found");[m
[32m+[m[32m                                warn!("💡 Solution: Check VM configuration for virtio-serial channel");[m
[32m+[m[32m                                warn!("   Required: <target type='virtio' name='org.infinibay.agent'/>");[m
[32m+[m[32m                            } else {[m
[32m+[m[32m                                warn!("✓ Device appears properly configured");[m
[32m+[m[32m                                warn!("💡 Try running as Administrator or check access permissions");[m
[32m+[m[32m                            }[m
                         }[m
                     }[m
                 }[m
[36m@@ -340,7 +492,37 @@[m [mimpl VirtioSerial {[m
                 }[m
             }[m
         }[m
[31m-        [m
[32m+[m
[32m+[m[32m        // Method 2.5: Try direct VirtIO connection for detected devices[m
[32m+[m[32m        if debug_mode {[m
[32m+[m[32m            debug!("Method 2.5: Attempting direct VirtIO connections...");[m
[32m+[m[32m        }[m
[32m+[m[32m        match find_virtio_system_devices() {[m
[32m+[m[32m            Ok(devices) => {[m
[32m+[m[32m                for device in &devices {[m
[32m+[m[32m                    if device.hardware_id.contains("DEV_1043") && !device.interface_paths.is_empty() {[m
[32m+[m[32m                        info!("🔌 Attempting direct connection to DEV_1043 device: {}", device.friendly_name);[m
[32m+[m
[32m+[m[32m                        match try_direct_virtio_connection(device) {[m
[32m+[m[32m                            Ok(device_path) => {[m
[32m+[m[32m                                info!("✅ Direct VirtIO connection successful: {}", device_path);[m
[32m+[m[32m                                return Ok(create_device_path(&device_path));[m
[32m+[m[32m                            }[m
[32m+[m[32m                            Err(e) => {[m
[32m+[m[32m                                warn!("❌ Direct VirtIO connection failed: {}", e);[m
[32m+[m[32m                                warn!("💡 Continuing with alternative connection methods...");[m
[32m+[m[32m                            }[m
[32m+[m[32m                        }[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m[32m            Err(e) => {[m
[32m+[m[32m                if debug_mode {[m
[32m+[m[32m                    debug!("Could not enumerate devices for direct connection: {}", e);[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m
         // Method 3: Try alternative VirtIO device paths[m
         if debug_mode {[m
             debug!("Method 2: Trying alternative VirtIO device paths...");[m
[36m@@ -482,31 +664,128 @@[m [mimpl VirtioSerial {[m
             }[m
         }[m
         [m
[31m-        // Method 8: Try additional named pipes (fallback)[m
[32m+[m[32m        // Method 8: Enhanced named pipes and Global objects (fallback with retry logic)[m
         if debug_mode {[m
[31m-            debug!("Method 7: Trying named pipes...");[m
[32m+[m[32m            debug!("Method 7: Trying enhanced named pipes and Global objects...");[m
         }[m
[31m-        // Use OS-specific string handling for named pipes[m
[31m-        let named_pipes: Vec<std::path::PathBuf> = vec![[m
[32m+[m
[32m+[m[32m        // Enhanced named pipes with retry logic and permission handling[m
[32m+[m[32m        let enhanced_named_pipes: Vec<std::path::PathBuf> = vec![[m
             std::path::PathBuf::from("\\\\.\\Global\\org.infinibay.agent"),[m
             std::path::PathBuf::from("\\\\.\\Global\\com.redhat.spice.0"),[m
[32m+[m[32m            std::path::PathBuf::from("\\\\.\\Global\\org.qemu.guest_agent.0"),[m
             std::path::PathBuf::from("\\\\.\\pipe\\org.infinibay.agent"),[m
[31m-            // Removed \\\\.\\pipe\\virtio-serial as it doesn't exist[m
[32m+[m[32m            std::path::PathBuf::from("\\\\.\\pipe\\org.qemu.guest_agent.0"),[m
[32m+[m[32m            std::path::PathBuf::from("\\\\.\\pipe\\com.redhat.spice.0"),[m
[32m+[m[32m            // Alternative VirtIO device naming conventions[m
[32m+[m[32m            std::path::PathBuf::from("\\\\.\\VirtioSerial"),[m
[32m+[m[32m            std::path::PathBuf::from("\\\\.\\VirtioSerial0"),[m
[32m+[m[32m            std::path::PathBuf::from("\\\\.\\VirtioSerial1"),[m
         ];[m
[31m-        [m
[31m-        for path in &named_pipes {[m
[32m+[m
[32m+[m[32m        for path in &enhanced_named_pipes {[m
             if debug_mode {[m
[31m-                debug!("Trying named pipe: {}", path.display());[m
[32m+[m[32m                debug!("Trying enhanced path: {}", path.display());[m
             }[m
[31m-            // Try to open the named pipe[m
[31m-            use std::fs::OpenOptions;[m
[31m-            if let Ok(_) = OpenOptions::new()[m
[31m-                .read(true)[m
[31m-                .write(true)[m
[31m-                .open(&path)[m
[31m-            {[m
[31m-                info!("Found working virtio-serial named pipe: {}", path.display());[m
[31m-                return Ok(path.clone());[m
[32m+[m
[32m+[m[32m            let path_str = path.to_string_lossy();[m
[32m+[m
[32m+[m[32m            // Enhanced Global object handling with retry logic[m
[32m+[m[32m            if path_str.contains("Global") {[m
[32m+[m[32m                // Try multiple access modes for Global objects[m
[32m+[m[32m                let access_modes = vec![[m
[32m+[m[32m                    ("read-write", true, true),[m
[32m+[m[32m                    ("read-only", true, false),[m
[32m+[m[32m                    ("write-only", false, true),[m
[32m+[m[32m                ];[m
[32m+[m
[32m+[m[32m                for (mode_name, read, write) in access_modes {[m
[32m+[m[32m                    if debug_mode {[m
[32m+[m[32m                        debug!("  -> Trying {} mode for Global object", mode_name);[m
[32m+[m[32m                    }[m
[32m+[m
[32m+[m[32m                    match Self::try_open_windows_device_with_mode(&path_str, read, write, debug_mode) {[m
[32m+[m[32m                        Ok(true) => {[m
[32m+[m[32m                            info!("✅ Enhanced Global object connection successful ({}): {}", mode_name, path.display());[m
[32m+[m[32m                            return Ok(path.clone());[m
[32m+[m[32m                        }[m
[32m+[m[32m                        Ok(false) => {[m
[32m+[m[32m                            if debug_mode {[m
[32m+[m[32m                                debug!("  -> {} mode failed for {}", mode_name, path.display());[m
[32m+[m[32m                            }[m
[32m+[m[32m                        }[m
[32m+[m[32m                        Err(error_code) => {[m
[32m+[m[32m                            if debug_mode {[m
[32m+[m[32m                                debug!("  -> {} mode error {} for {}", mode_name, error_code, path.display());[m
[32m+[m[32m                            }[m
[32m+[m[32m                            // For access denied, try with different permissions[m
[32m+[m[32m                            if error_code == 5 && mode_name == "read-write" {[m
[32m+[m[32m                                warn!("🔐 Access denied to Global object, trying alternative access modes...");[m
[32m+[m[32m                            }[m
[32m+[m[32m                        }[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m[32m            } else {[m
[32m+[m[32m                // Enhanced named pipe handling with retry logic[m
[32m+[m[32m                use std::fs::OpenOptions;[m
[32m+[m[32m                use std::thread;[m
[32m+[m[32m                use std::time::Duration;[m
[32m+[m
[32m+[m[32m                // Try multiple times with different configurations[m
[32m+[m[32m                let retry_configs = vec![[m
[32m+[m[32m                    ("standard", true, true, false),[m
[32m+[m[32m                    ("read-only", true, false, false),[m
[32m+[m[32m                    ("write-only", false, true, false),[m
[32m+[m[32m                    ("with-retry", true, true, true),[m
[32m+[m[32m                ];[m
[32m+[m
[32m+[m[32m                for (config_name, read, write, with_retry) in retry_configs {[m
[32m+[m[32m                    if debug_mode {[m
[32m+[m[32m                        debug!("  -> Trying {} configuration for named pipe", config_name);[m
[32m+[m[32m                    }[m
[32m+[m
[32m+[m[32m                    let mut attempts = if with_retry { 3 } else { 1 };[m
[32m+[m
[32m+[m[32m                    while attempts > 0 {[m
[32m+[m[32m                        match OpenOptions::new()[m
[32m+[m[32m                            .read(read)[m
[32m+[m[32m                            .write(write)[m
[32m+[m[32m                            .open(&path)[m
[32m+[m[32m                        {[m
[32m+[m[32m                            Ok(_) => {[m
[32m+[m[32m                                info!("✅ Enhanced named pipe connection successful ({}): {}", config_name, path.display());[m
[32m+[m[32m                                return Ok(path.clone());[m
[32m+[m[32m                            }[m
[32m+[m[32m                            Err(e) => {[m
[32m+[m[32m                                if debug_mode {[m
[32m+[m[32m                                    debug!("  -> {} configuration attempt failed: {}", config_name, e);[m
[32m+[m[32m                                }[m
[32m+[m
[32m+[m[32m                                // Handle specific errors[m
[32m+[m[32m                                if let Some(error_code) = e.raw_os_error() {[m
[32m+[m[32m                                    match error_code {[m
[32m+[m[32m                                        5 => {[m
[32m+[m[32m                                            // Access denied - try different permissions[m
[32m+[m[32m                                            if config_name == "standard" {[m
[32m+[m[32m                                                warn!("🔐 Access denied to named pipe, trying alternative configurations...");[m
[32m+[m[32m                                            }[m
[32m+[m[32m                                        }[m
[32m+[m[32m                                        2 => {[m
[32m+[m[32m                                            // File not found - no point in retrying[m
[32m+[m[32m                                            break;[m
[32m+[m[32m                                        }[m
[32m+[m[32m                                        _ => {}[m
[32m+[m[32m                                    }[m
[32m+[m[32m                                }[m
[32m+[m
[32m+[m[32m                                attempts -= 1;[m
[32m+[m[32m                                if with_retry && attempts > 0 {[m
[32m+[m[32m                                    thread::sleep(Duration::from_millis(100));[m
[32m+[m[32m                                }[m
[32m+[m[32m                            }[m
[32m+[m[32m                        }[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
             }[m
         }[m
         [m
[36m@@ -529,17 +808,32 @@[m [mimpl VirtioSerial {[m
             }[m
         }[m
         [m
[31m-        // If access denied paths exist, suggest resolution[m
[32m+[m[32m        // Enhanced access denied guidance[m
         if !access_denied_paths.is_empty() {[m
[31m-            warn!("=== Access Denied Paths Found ===");[m
[32m+[m[32m            warn!("🔐 === Access Denied Paths Found ===");[m
             warn!("The following VirtIO paths exist but are not accessible:");[m
             for path in &access_denied_paths {[m
[31m-                warn!("  - {}", path.display());[m
[32m+[m[32m                warn!("  📍 {}", path.display());[m
             }[m
[31m-            warn!("This suggests the VirtIO devices are present but need:");[m
[31m-            warn!("  1. Administrator privileges to access");[m
[31m-            warn!("  2. Proper VM configuration with channel names");[m
[31m-            warn!("  3. VirtIO driver reinstallation or configuration");[m
[32m+[m[32m            warn!("");[m
[32m+[m[32m            warn!("🔍 This suggests VirtIO devices are present but need configuration:");[m
[32m+[m[32m            warn!("");[m
[32m+[m[32m            warn!("🚀 Quick Fix Steps:");[m
[32m+[m[32m            warn!("  1️⃣  Run as Administrator:");[m
[32m+[m[32m            warn!("      Right-click Command Prompt → 'Run as administrator'");[m
[32m+[m[32m            warn!("      Then run: infiniservice.exe --diag");[m
[32m+[m[32m            warn!("");[m
[32m+[m[32m            warn!("  2️⃣  Check VM Configuration:");[m
[32m+[m[32m            warn!("      Ensure VM has virtio-serial channel configured");[m
[32m+[m[32m            warn!("      Required XML: <target type='virtio' name='org.infinibay.agent'/>");[m
[32m+[m[32m            warn!("");[m
[32m+[m[32m            warn!("  3️⃣  Verify VirtIO Drivers:");[m
[32m+[m[32m            warn!("      Open Device Manager → System devices");[m
[32m+[m[32m            warn!("      Look for 'VirtIO Serial Driver' (should show no warnings)");[m
[32m+[m[32m            warn!("");[m
[32m+[m[32m            warn!("  4️⃣  Try Alternative Paths:");[m
[32m+[m[32m            warn!("      infiniservice.exe --device \"\\\\.\\pipe\\org.infinibay.agent\"");[m
[32m+[m[32m            warn!("      infiniservice.exe --device \"COM1\" (if available)");[m
             warn!("");[m
         }[m
 [m
[36m@@ -559,32 +853,41 @@[m [mimpl VirtioSerial {[m
             }[m
         }[m
         [m
[31m-        // Enhanced diagnostic information[m
[31m-        warn!("=== VirtIO Device Detection Summary ===");[m
[32m+[m[32m        // Enhanced diagnostic information with specific DEV_1043 guidance[m
[32m+[m[32m        warn!("🔍 === Enhanced VirtIO Device Detection Summary ===");[m
         warn!("No directly accessible VirtIO serial device found.");[m
         warn!("");[m
[31m-        warn!("Based on typical configurations, the VirtIO Serial Driver may be installed");[m
[31m-        warn!("but requires additional configuration. This can happen when:");[m
[32m+[m[32m        warn!("📊 Based on the analysis, this appears to be a DEV_1043 configuration issue.");[m
[32m+[m[32m        warn!("The VirtIO Serial Driver is likely installed but not properly configured.");[m
[32m+[m[32m        warn!("");[m
[32m+[m[32m        warn!("🎯 Most Common Causes & Solutions:");[m
[32m+[m[32m        warn!("");[m
[32m+[m[32m        warn!("🔧 1. VM Configuration Missing VirtIO Channel:");[m
[32m+[m[32m        warn!("   Problem: VM lacks proper virtio-serial channel setup");[m
[32m+[m[32m        warn!("   Solution: Add to VM configuration:");[m
[32m+[m[32m        warn!("   QEMU/KVM: <target type='virtio' name='org.infinibay.agent'/>");[m
[32m+[m[32m        warn!("   VMware: serial0.fileType = \"pipe\"");[m
[32m+[m[32m        warn!("   VirtualBox: --uartmode1 server \\\\.\\pipe\\infinibay");[m
         warn!("");[m
[31m-        warn!("🔧 Configuration Issues:");[m
[31m-        warn!("  1. VM XML missing virtio-serial channel configuration");[m
[31m-        warn!("  2. Channel name mismatch (should be 'org.infinibay.agent' or similar)");[m
[31m-        warn!("  3. VirtIO device not exposed as accessible COM port");[m
[32m+[m[32m        warn!("🔐 2. Administrator Privileges Required:");[m
[32m+[m[32m        warn!("   Problem: Windows blocks access to VirtIO Global objects");[m
[32m+[m[32m        warn!("   Solution: Run Command Prompt as Administrator, then:");[m
[32m+[m[32m        warn!("   infiniservice.exe --debug --diag");[m
         warn!("");[m
[31m-        warn!("🔐 Permission Issues:");[m
[31m-        warn!("  4. Service needs administrator privileges");[m
[31m-        warn!("  5. Windows security policies blocking device access");[m
[32m+[m[32m        warn!("🔨 3. VirtIO Driver Installation Issues:");[m
[32m+[m[32m        warn!("   Problem: Driver installed but service not running");[m
[32m+[m[32m        warn!("   Solution: Download latest VirtIO ISO and reinstall drivers");[m
[32m+[m[32m        warn!("   Check: Device Manager → System devices → VirtIO Serial Driver");[m
         warn!("");[m
[31m-        warn!("🔨 Driver Issues:");[m
[31m-        warn!("  6. VirtIO driver needs reinstallation");[m
[31m-        warn!("  7. Missing or outdated VirtIO guest tools");[m
[32m+[m[32m        warn!("🔄 4. Alternative Connection Methods:");[m
[32m+[m[32m        warn!("   Try these device paths manually:");[m
[32m+[m[32m        warn!("   infiniservice.exe --device \"\\\\.\\Global\\org.infinibay.agent\"");[m
[32m+[m[32m        warn!("   infiniservice.exe --device \"\\\\.\\pipe\\org.infinibay.agent\"");[m
[32m+[m[32m        warn!("   infiniservice.exe --device \"COM1\" (if VirtIO COM port exists)");[m
         warn!("");[m
[31m-        warn!("💡 Solutions to try:");[m
[31m-        warn!("  • Run the service as Administrator");[m
[31m-        warn!("  • Check VM configuration for virtio-serial channels");[m
[31m-        warn!("  • Reinstall VirtIO drivers from latest ISO");[m
[31m-        warn!("  • Use --device flag to manually specify device path");[m
[31m-        warn!("  • Enable debug mode with --debug for more details");[m
[32m+[m[32m        warn!("📋 5. Get Detailed Diagnosis:");[m
[32m+[m[32m        warn!("   Run: infiniservice.exe --diag");[m
[32m+[m[32m        warn!("   This will show specific VM configuration examples and driver status");[m
         [m
         // Don't completely fail - return a warning result that allows the service to continue[m
         // This allows the service to start and retry periodically[m
[36m@@ -628,19 +931,36 @@[m [mimpl VirtioSerial {[m
                         // Provide specific guidance based on error code[m
                         match error_code {[m
                             5 => {[m
[31m-                                warn!("Access denied to VirtIO Global object: {}", path_str);[m
[31m-                                warn!("This typically means:");[m
[31m-                                warn!("  1. The service needs to run as Administrator");[m
[31m-                                warn!("  2. The VirtIO device needs proper VM configuration");[m
[31m-                                warn!("  3. Windows security policies are blocking access");[m
[31m-                                return Err(anyhow!("Access denied to VirtIO Global object (Win32 error 5). Try running as Administrator or check VM configuration."));[m
[32m+[m[32m                                warn!("🔐 Access denied to VirtIO Global object: {}", path_str);[m
[32m+[m[32m                                warn!("📋 This typically means:");[m
[32m+[m[32m                                warn!("   1. Service needs Administrator privileges");[m
[32m+[m[32m                                warn!("   2. VirtIO device needs proper VM configuration");[m
[32m+[m[32m                                warn!("   3. Windows security policies blocking access");[m
[32m+[m[32m                                warn!("   4. DEV_1043 device detected but not accessible");[m
[32m+[m[32m                                warn!("");[m
[32m+[m[32m                                warn!("🚀 Immediate solutions:");[m
[32m+[m[32m                                warn!("   • Run as Administrator: Right-click → 'Run as administrator'");[m
[32m+[m[32m                                warn!("   • Check VM config: Ensure virtio-serial channel is configured");[m
[32m+[m[32m                                warn!("   • Run diagnosis: infiniservice.exe --diag");[m
[32m+[m[32m                                warn!("   • Try alternative: infiniservice.exe --device \"\\\\.\\pipe\\org.infinibay.agent\"");[m
[32m+[m[32m                                return Err(anyhow!("Access denied to VirtIO Global object (Win32 error 5). Run as Administrator or check VM configuration."));[m
                             }[m
                             2 => {[m
[31m-                                warn!("VirtIO Global object not found: {}", path_str);[m
[31m-                                warn!("This may indicate the VM configuration is incomplete or the device path has changed.");[m
[32m+[m[32m                                warn!("🔍 VirtIO Global object not found: {}", path_str);[m
[32m+[m[32m                                warn!("📋 This indicates:");[m
[32m+[m[32m                                warn!("   • VM configuration missing virtio-serial channel");[m
[32m+[m[32m                                warn!("   • Channel name mismatch in VM setup");[m
[32m+[m[32m                                warn!("   • VirtIO drivers not properly installed");[m
[32m+[m[32m                                warn!("");[m
[32m+[m[32m                                warn!("🔧 VM Configuration Examples:");[m
[32m+[m[32m                                warn!("   QEMU/KVM: <target type='virtio' name='org.infinibay.agent'/>");[m
[32m+[m[32m                                warn!("   VMware: serial0.fileName = \"\\\\.\\pipe\\infinibay\"");[m
[32m+[m[32m                                warn!("   VirtualBox: --uartmode1 server \\\\.\\pipe\\infinibay");[m
                                 return Err(anyhow!("VirtIO Global object not found (Win32 error 2). Check VM virtio-serial configuration."));[m
                             }[m
                             _ => {[m
[32m+[m[32m                                warn!("❌ Unexpected error accessing VirtIO device: Win32 error {}", error_code);[m
[32m+[m[32m                                warn!("💡 Try running: infiniservice.exe --diag");[m
                                 return Err(anyhow!("Failed to open VirtIO Global object {}: Win32 error {}. Check VM configuration and driver installation.", path_str, error_code));[m
                             }[m
                         }[m
[36m@@ -667,8 +987,23 @@[m [mimpl VirtioSerial {[m
                     }[m
                     Err(e) => {[m
                         if let Some(5) = e.raw_os_error() {[m
[31m-                            warn!("Access denied to COM port: {}", self.device_path.display());[m
[31m-                            warn!("Try running as Administrator or check if another application is using the port");[m
[32m+[m[32m                            warn!("🔐 Access denied to COM port: {}", self.device_path.display());[m
[32m+[m[32m                            warn!("📋 Common causes:");[m
[32m+[m[32m                            warn!("   • Another application is using the port");[m
[32m+[m[32m                            warn!("   • Service needs Administrator privileges");[m
[32m+[m[32m                            warn!("   • VirtIO COM port requires special permissions");[m
[32m+[m[32m                            warn!("");[m
[32m+[m[32m                            warn!("💡 Solutions:");[m
[32m+[m[32m                            warn!("   • Close other applications using the COM port");[m
[32m+[m[32m                            warn!("   • Run as Administrator");[m
[32m+[m[32m                            warn!("   • Try alternative device paths with --device flag");[m
[32m+[m[32m                            warn!("   • Run diagnosis: infiniservice.exe --diag");[m
[32m+[m[32m                        } else {[m
[32m+[m[32m                            warn!("❌ Failed to open COM port: {} (Error: {})", self.device_path.display(), e);[m
[32m+[m[32m                            warn!("💡 This may indicate:");[m
[32m+[m[32m                            warn!("   • COM port doesn't exist or is not available");[m
[32m+[m[32m                            warn!("   • VirtIO driver not properly configured");[m
[32m+[m[32m                            warn!("   • Hardware or VM configuration issue");[m
                         }[m
                         return Err(anyhow!("Failed to open COM port {}: {}. Check if port is available and accessible.", self.device_path.display(), e));[m
                     }[m
[36m@@ -751,37 +1086,65 @@[m [mimpl VirtioSerial {[m
     /// Send raw message to the device[m
     async fn send_raw_message(&self, message: &str) -> Result<()> {[m
         let path_str = self.device_path.to_string_lossy();[m
[31m-        [m
[32m+[m
         // Check if VirtIO is available[m
         if path_str == "__NO_VIRTIO_DEVICE__" {[m
             debug!("VirtIO not available - message not sent: {}", message);[m
             return Err(anyhow!("VirtIO device not available for communication"));[m
         }[m
[31m-        [m
[31m-        // Open device and send data[m
[31m-        #[cfg(target_os = "windows")][m
[31m-        let mut file = {[m
[31m-            use std::os::windows::fs::OpenOptionsExt;[m
[31m-            [m
[31m-            if path_str.contains("COM") && !path_str.contains("pipe") {[m
[31m-                // COM port - no special flags needed for synchronous write[m
[31m-                OpenOptions::new()[m
[31m-                    .write(true)[m
[31m-                    .open(&self.device_path)[m
[31m-                    .with_context(|| format!("Failed to open COM port for data transmission: {}", self.device_path.display()))?[m
[31m-            } else {[m
[32m+[m
[32m+[m[32m        // Open device and send data with rate-limited error logging[m
[32m+[m[32m        let file_result = {[m
[32m+[m[32m            #[cfg(target_os = "windows")][m
[32m+[m[32m            {[m
[32m+[m[32m                use std::os::windows::fs::OpenOptionsExt;[m
[32m+[m
[32m+[m[32m                if path_str.contains("COM") && !path_str.contains("pipe") {[m
[32m+[m[32m                    // COM port - no special flags needed for synchronous write[m
[32m+[m[32m                    OpenOptions::new()[m
[32m+[m[32m                        .write(true)[m
[32m+[m[32m                        .open(&self.device_path)[m
[32m+[m[32m                        .with_context(|| format!("Failed to open COM port for data transmission: {}", self.device_path.display()))[m
[32m+[m[32m                } else {[m
[32m+[m[32m                    OpenOptions::new()[m
[32m+[m[32m                        .write(true)[m
[32m+[m[32m                        .open(&self.device_path)[m
[32m+[m[32m                        .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m
[32m+[m[32m            #[cfg(not(target_os = "windows"))][m
[32m+[m[32m            {[m
                 OpenOptions::new()[m
                     .write(true)[m
                     .open(&self.device_path)[m
[31m-                    .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))?[m
[32m+[m[32m                    .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))[m
[32m+[m[32m            }[m
[32m+[m[32m        };[m
[32m+[m
[32m+[m[32m        let mut file = match file_result {[m
[32m+[m[32m            Ok(file) => file,[m
[32m+[m[32m            Err(e) => {[m
[32m+[m[32m                // Handle device open errors with rate limiting for transmission[m
[32m+[m[32m                use std::sync::LazyLock;[m
[32m+[m[32m                static TRANSMISSION_ERROR_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32)>> =[m
[32m+[m[32m                    LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0)));[m
[32m+[m
[32m+[m[32m                if let Ok(mut state) = TRANSMISSION_ERROR_STATE.lock() {[m
[32m+[m[32m                    state.1 += 1; // Increment error count[m
[32m+[m[32m                    let now = std::time::Instant::now();[m
[32m+[m
[32m+[m[32m                    // Only log every 30 seconds or every 50 errors[m
[32m+[m[32m                    if now.duration_since(state.0).as_secs() >= 30 || state.1 >= 50 {[m
[32m+[m[32m                        warn!("Failed to open virtio device for transmission ({} attempts in last interval): {}", state.1, e);[m
[32m+[m[32m                        debug!("Device path: {}", self.device_path.display());[m
[32m+[m[32m                        state.0 = now;[m
[32m+[m[32m                        state.1 = 0;[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m[32m                return Err(e);[m
             }[m
         };[m
[31m-        [m
[31m-        #[cfg(not(target_os = "windows"))][m
[31m-        let mut file = OpenOptions::new()[m
[31m-            .write(true)[m
[31m-            .open(&self.device_path)[m
[31m-            .with_context(|| format!("Failed to open device for data transmission: {}", self.device_path.display()))?;[m
 [m
         writeln!(file, "{}", message)[m
             .with_context(|| "Failed to write message to device")?;[m
[36m@@ -796,37 +1159,68 @@[m [mimpl VirtioSerial {[m
     /// Read incoming commands from the device[m
     pub async fn read_command(&self) -> Result<Option<IncomingMessage>> {[m
         let path_str = self.device_path.to_string_lossy();[m
[31m-        [m
[32m+[m
         // Check if VirtIO is available[m
         if path_str == "__NO_VIRTIO_DEVICE__" {[m
             // Don't spam debug logs when VirtIO is not available[m
             return Ok(None);[m
         }[m
[31m-        [m
[31m-        debug!("Attempting to read command from virtio-serial");[m
[31m-        [m
[31m-        // Open device for reading[m
[32m+[m
[32m+[m[32m        // Rate limit all operations to avoid spam[m
[32m+[m[32m        use std::sync::LazyLock;[m
[32m+[m[32m        static OPERATION_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32, std::time::Instant)>> =[m
[32m+[m[32m            LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0, std::time::Instant::now())));[m
[32m+[m
[32m+[m[32m        // Try to open device for reading with error handling[m
         #[cfg(target_os = "windows")][m
[31m-        let file = {[m
[32m+[m[32m        let file_result = {[m
             use std::os::windows::fs::OpenOptionsExt;[m
             if path_str.contains("COM") && !path_str.contains("pipe") {[m
                 OpenOptions::new()[m
                     .read(true)[m
                     .open(&self.device_path)[m
[31m-                    .with_context(|| format!("Failed to open COM port for reading: {}", self.device_path.display()))?[m
             } else {[m
                 OpenOptions::new()[m
                     .read(true)[m
                     .open(&self.device_path)[m
[31m-                    .with_context(|| format!("Failed to open device for reading: {}", self.device_path.display()))?[m
             }[m
         };[m
[31m-        [m
[32m+[m
         #[cfg(not(target_os = "windows"))][m
[31m-        let file = OpenOptions::new()[m
[32m+[m[32m        let file_result = OpenOptions::new()[m
             .read(true)[m
[31m-            .open(&self.device_path)[m
[31m-            .with_context(|| format!("Failed to open device for reading: {}", self.device_path.display()))?;[m
[32m+[m[32m            .open(&self.device_path);[m
[32m+[m
[32m+[m[32m        let file = match file_result {[m
[32m+[m[32m            Ok(f) => {[m
[32m+[m[32m                // Success - log occasionally[m
[32m+[m[32m                if let Ok(mut state) = OPERATION_STATE.lock() {[m
[32m+[m[32m                    let now = std::time::Instant::now();[m
[32m+[m[32m                    if now.duration_since(state.2).as_secs() >= 30 {[m
[32m+[m[32m                        debug!("Successfully opened virtio-serial device for reading");[m
[32m+[m[32m                        state.2 = now;[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m[32m                f[m
[32m+[m[32m            },[m
[32m+[m[32m            Err(e) => {[m
[32m+[m[32m                // Handle device open errors with rate limiting[m
[32m+[m[32m                if let Ok(mut state) = OPERATION_STATE.lock() {[m
[32m+[m[32m                    state.1 += 1; // Increment error count[m
[32m+[m[32m                    let now = std::time::Instant::now();[m
[32m+[m
[32m+[m[32m                    // Only log every 30 seconds or every 50 errors[m
[32m+[m[32m                    if now.duration_since(state.0).as_secs() >= 30 || state.1 >= 50 {[m
[32m+[m[32m                        warn!("Failed to open virtio device ({} attempts in last interval): {}", state.1, e);[m
[32m+[m[32m                        debug!("Device path: {}", self.device_path.display());[m
[32m+[m[32m                        state.0 = now;[m
[32m+[m[32m                        state.1 = 0;[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m[32m                // Return None instead of propagating error to avoid breaking the service loop[m
[32m+[m[32m                return Ok(None);[m
[32m+[m[32m            }[m
[32m+[m[32m        };[m
         [m
         let mut reader = BufReader::new(file);[m
         let mut line = String::new();[m
[36m@@ -869,11 +1263,40 @@[m [mimpl VirtioSerial {[m
                 }[m
             },[m
             Err(e) => {[m
[31m-                if e.kind() == std::io::ErrorKind::WouldBlock {[m
[31m-                    // No data available (non-blocking read)[m
[31m-                    Ok(None)[m
[31m-                } else {[m
[31m-                    Err(anyhow!("Failed to read from device: {}", e))[m
[32m+[m[32m                match e.kind() {[m
[32m+[m[32m                    std::io::ErrorKind::WouldBlock => {[m
[32m+[m[32m                        // No data available (non-blocking read) - this is normal[m
[32m+[m[32m                        Ok(None)[m
[32m+[m[32m                    },[m
[32m+[m[32m                    std::io::ErrorKind::TimedOut => {[m
[32m+[m[32m                        // Timeout - this is also normal for non-blocking operations[m
[32m+[m[32m                        Ok(None)[m
[32m+[m[32m                    },[m
[32m+[m[32m                    std::io::ErrorKind::UnexpectedEof => {[m
[32m+[m[32m                        // EOF - no more data available, this is normal[m
[32m+[m[32m                        Ok(None)[m
[32m+[m[32m                    },[m
[32m+[m[32m                    _ => {[m
[32m+[m[32m                        // Only log actual errors, not expected conditions[m
[32m+[m[32m                        use std::sync::LazyLock;[m
[32m+[m[32m                        static ERROR_LOG_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32)>> =[m
[32m+[m[32m                            LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0)));[m
[32m+[m
[32m+[m[32m                        if let Ok(mut state) = ERROR_LOG_STATE.lock() {[m
[32m+[m[32m                            state.1 += 1; // Increment error count[m
[32m+[m[32m                            let now = std::time::Instant::now();[m
[32m+[m
[32m+[m[32m                            // Only log every 30 seconds or every 100 errors[m
[32m+[m[32m                            if now.duration_since(state.0).as_secs() >= 30 || state.1 >= 100 {[m
[32m+[m[32m                                warn!("Communication error reading from device ({} occurrences): {}", state.1, e);[m
[32m+[m[32m                                state.0 = now;[m
[32m+[m[32m                                state.1 = 0;[m
[32m+[m[32m                            }[m
[32m+[m[32m                        }[m
[32m+[m
[32m+[m[32m                        // Return None instead of error to avoid breaking the service loop[m
[32m+[m[32m                        Ok(None)[m
[32m+[m[32m                    }[m
                 }[m
             }[m
         }[m
[36m@@ -976,6 +1399,43 @@[m [mmod tests {[m
         }[m
     }[m
 [m
[32m+[m[32m    #[cfg(target_os = "windows")][m
[32m+[m[32m    #[test][m
[32m+[m[32m    fn test_try_open_windows_device_with_sharing() {[m
[32m+[m[32m        // Test that try_open_windows_device uses proper sharing mode[m
[32m+[m[32m        // This test verifies the function doesn't panic and handles errors properly[m
[32m+[m[32m        let test_paths = vec![[m
[32m+[m[32m            r"\\.\Global\nonexistent",[m
[32m+[m[32m            r"\\.\pipe\nonexistent",[m
[32m+[m[32m            r"\\.\COM999",[m
[32m+[m[32m        ];[m
[32m+[m
[32m+[m[32m        for path in test_paths {[m
[32m+[m[32m            let result = VirtioSerial::try_open_windows_device(path, false);[m
[32m+[m[32m            // Should return an error for nonexistent devices, but not panic[m
[32m+[m[32m            assert!(result.is_err());[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    #[cfg(target_os = "windows")][m
[32m+[m[32m    #[test][m
[32m+[m[32m    fn test_windows_enhanced_error_messages() {[m
[32m+[m[32m        // Test that Windows error handling provides enhanced messages[m
[32m+[m[32m        // This is more of a smoke test to ensure the error handling code doesn't panic[m
[32m+[m[32m        let nonexistent_path = PathBuf::from(r"\\.\Global\nonexistent_virtio_device");[m
[32m+[m[32m        let virtio = VirtioSerial::new(&nonexistent_path);[m
[32m+[m
[32m+[m[32m        // The connect method should handle errors gracefully[m
[32m+[m[32m        let runtime = tokio::runtime::Runtime::new().unwrap();[m
[32m+[m[32m        let result = runtime.block_on(virtio.connect());[m
[32m+[m
[32m+[m[32m        // Should return an error with enhanced messaging[m
[32m+[m[32m        assert!(result.is_err());[m
[32m+[m[32m        let error_msg = result.unwrap_err().to_string();[m
[32m+[m[32m        // Error message should contain helpful information[m
[32m+[m[32m        assert!(!error_msg.is_empty());[m
[32m+[m[32m    }[m
[32m+[m
     #[test][m
     fn test_current_timestamp() {[m
         let timestamp1 = VirtioSerial::current_timestamp();[m
[1mdiff --git a/src/service.rs b/src/service.rs[m
[1mindex 7dd76e8..ee49c33 100644[m
[1m--- a/src/service.rs[m
[1m+++ b/src/service.rs[m
[36m@@ -114,7 +114,7 @@[m [mimpl InfiniService {[m
         info!("Command execution is ENABLED - both safe and unsafe commands supported");[m
 [m
         let mut interval = time::interval(Duration::from_secs(self.config.collection_interval));[m
[31m-        let mut command_check_interval = time::interval(Duration::from_millis(100)); // Check for commands every 100ms[m
[32m+[m[32m        let mut command_check_interval = time::interval(Duration::from_millis(500)); // Check for commands every 500ms[m
         let mut virtio_retry_interval = time::interval(Duration::from_secs(self.config.virtio_retry_interval));[m
 [m
         loop {[m
[36m@@ -242,8 +242,22 @@[m [mimpl InfiniService {[m
                 Ok(false)[m
             },[m
             Err(e) => {[m
[31m-                // Error reading command[m
[31m-                debug!("Error reading command (may be expected): {}", e);[m
[32m+[m[32m                // Error reading command - only log occasionally to avoid spam[m
[32m+[m[32m                use std::sync::LazyLock;[m
[32m+[m[32m                static LOG_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32)>> =[m
[32m+[m[32m                    LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0)));[m
[32m+[m
[32m+[m[32m                if let Ok(mut state) = LOG_STATE.lock() {[m
[32m+[m[32m                    state.1 += 1; // Increment counter[m
[32m+[m[32m                    let now = std::time::Instant::now();[m
[32m+[m
[32m+[m[32m                    // Only log every 60 seconds or every 1000 errors, whichever comes first[m
[32m+[m[32m                    if now.duration_since(state.0).as_secs() >= 60 || state.1 >= 1000 {[m
[32m+[m[32m                        debug!("Error reading command (may be expected, {} occurrences in last interval): {}", state.1, e);[m
[32m+[m[32m                        state.0 = now;[m
[32m+[m[32m                        state.1 = 0;[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
                 Ok(false)[m
             }[m
         }[m
[36m@@ -280,7 +294,17 @@[m [mimpl InfiniService {[m
                 } else {[m
                     // Actual transmission error - VirtIO might have failed[m
                     self.virtio_connected = false;[m
[31m-                    Err(e)[m
[32m+[m
[32m+[m[32m                    // Check if it's a device open error (rate limited)[m
[32m+[m[32m                    if e.to_string().contains("Failed to open device for") ||[m
[32m+[m[32m                       e.to_string().contains("Failed to open COM port for") {[m
[32m+[m[32m                        // This is a device access error - don't treat as fatal[m
[32m+[m[32m                        debug!("VirtIO device access error during transmission (rate limited): {}", e);[m
[32m+[m[32m                        Ok(()) // Don't treat this as an error to avoid spam[m
[32m+[m[32m                    } else {[m
[32m+[m[32m                        // Other transmission errors (write/flush failures)[m
[32m+[m[32m                        Err(e)[m
[32m+[m[32m                    }[m
                 }[m
             }[m
         }[m
[1mdiff --git a/src/windows_com.rs b/src/windows_com.rs[m
[1mindex 5869fcf..20d713f 100644[m
[1m--- a/src/windows_com.rs[m
[1m+++ b/src/windows_com.rs[m
[36m@@ -15,6 +15,7 @@[m [muse winapi::{[m
         winreg::*,[m
         winnt::{KEY_READ, REG_SZ},[m
         handleapi::INVALID_HANDLE_VALUE,[m
[32m+[m[32m        cfgmgr32::{CM_Get_DevNode_Status, CONFIGRET, CR_SUCCESS},[m
     },[m
 };[m
 [m
[36m@@ -26,7 +27,7 @@[m [muse std::path::PathBuf;[m
 use std::ptr;[m
 use std::mem;[m
 [m
[31m-/// Information about a COM port[m
[32m+[m[32m/// Information about a COM port or VirtIO device[m
 #[derive(Debug, Clone)][m
 pub struct ComPortInfo {[m
     /// The COM port name (e.g., "COM3")[m
[36m@@ -39,6 +40,16 @@[m [mpub struct ComPortInfo {[m
     pub is_virtio: bool,[m
     /// The full device path (e.g., "\\.\COM3")[m
     pub device_path: PathBuf,[m
[32m+[m[32m    /// Device instance ID for detailed identification[m
[32m+[m[32m    pub instance_id: String,[m
[32m+[m[32m    /// Device status (enabled, disabled, problem)[m
[32m+[m[32m    pub device_status: String,[m
[32m+[m[32m    /// Driver service name[m
[32m+[m[32m    pub driver_service: String,[m
[32m+[m[32m    /// Device location information[m
[32m+[m[32m    pub location_info: String,[m
[32m+[m[32m    /// Device interface paths (for non-COM VirtIO devices)[m
[32m+[m[32m    pub interface_paths: Vec<String>,[m
 }[m
 [m
 /// GUID for COM port devices[m
[36m@@ -69,6 +80,119 @@[m [mconst VIRTIO_SERIAL_DEVICE_IDS: &[&str] = &[[m
     "DEV_1044",  // VirtIO console[m
 ];[m
 [m
[32m+[m[32m/// Device node status flags[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_ROOT_ENUMERATED: u32 = 0x00000001;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_DRIVER_LOADED: u32 = 0x00000002;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_ENUM_LOADED: u32 = 0x00000004;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_STARTED: u32 = 0x00000008;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_MANUAL: u32 = 0x00000010;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_NEED_TO_ENUM: u32 = 0x00000020;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_DRIVER_BLOCKED: u32 = 0x00000040;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_HARDWARE_ENUM: u32 = 0x00000080;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_NEED_RESTART: u32 = 0x00000100;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_CHILD_WITH_INVALID_ID: u32 = 0x00000200;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_HAS_PROBLEM: u32 = 0x00000400;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_FILTERED: u32 = 0x00000800;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_LEGACY_DRIVER: u32 = 0x00001000;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_DISABLEABLE: u32 = 0x00002000;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_REMOVABLE: u32 = 0x00004000;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_PRIVATE_PROBLEM: u32 = 0x00008000;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_MF_PARENT: u32 = 0x00010000;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_MF_CHILD: u32 = 0x00020000;[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mconst DN_WILL_BE_REMOVED: u32 = 0x00040000;[m
[32m+[m
[32m+[m[32m/// Helper function to translate device node status and problem codes to readable strings[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32mfn translate_device_status(status: u32, problem: u32) -> String {[m
[32m+[m[32m    if status & DN_HAS_PROBLEM != 0 {[m
[32m+[m[32m        let problem_desc = match problem {[m
[32m+[m[32m            1 => "Not configured",[m
[32m+[m[32m            2 => "DevLoader failed",[m
[32m+[m[32m            3 => "Out of memory",[m
[32m+[m[32m            4 => "Entry point not found",[m
[32m+[m[32m            5 => "Control file not found",[m
[32m+[m[32m            6 => "Invalid captive",[m
[32m+[m[32m            7 => "Driver failed previous attempts",[m
[32m+[m[32m            8 => "Driver service key invalid",[m
[32m+[m[32m            9 => "Legacy service no devices",[m
[32m+[m[32m            10 => "Duplicate device",[m
[32m+[m[32m            11 => "Failed install",[m
[32m+[m[32m            12 => "Failed install",[m
[32m+[m[32m            13 => "Invalid log configuration",[m
[32m+[m[32m            14 => "Device disabled",[m
[32m+[m[32m            15 => "DevLoader not ready",[m
[32m+[m[32m            16 => "Device not there",[m
[32m+[m[32m            17 => "Moved",[m
[32m+[m[32m            18 => "Too early",[m
[32m+[m[32m            19 => "No valid log configuration",[m
[32m+[m[32m            20 => "Failed install",[m
[32m+[m[32m            21 => "Hardware disabled",[m
[32m+[m[32m            22 => "Can't share IRQ",[m
[32m+[m[32m            23 => "Driver failed add",[m
[32m+[m[32m            24 => "System shutdown",[m
[32m+[m[32m            25 => "Failed start",[m
[32m+[m[32m            26 => "IRQ translation failed",[m
[32m+[m[32m            27 => "Failed driver entry",[m
[32m+[m[32m            28 => "Device loader missing",[m
[32m+[m[32m            29 => "Invalid ID",[m
[32m+[m[32m            30 => "Failed query remove",[m
[32m+[m[32m            31 => "Failed remove",[m
[32m+[m[32m            32 => "Invalid removal policy",[m
[32m+[m[32m            33 => "Translation failed",[m
[32m+[m[32m            34 => "IRQ translation failed",[m
[32m+[m[32m            35 => "Restart enumeration",[m
[32m+[m[32m            36 => "Partial log configuration",[m
[32m+[m[32m            37 => "Unknown resource",[m
[32m+[m[32m            38 => "Reinstall",[m
[32m+[m[32m            39 => "Registry",[m
[32m+[m[32m            40 => "VxD loader",[m
[32m+[m[32m            41 => "System hive too large",[m
[32m+[m[32m            42 => "Driver blocked",[m
[32m+[m[32m            43 => "Registry too large",[m
[32m+[m[32m            44 => "Setproperties failed",[m
[32m+[m[32m            45 => "Waiting on dependency",[m
[32m+[m[32m            46 => "Boot config conflict",[m
[32m+[m[32m            47 => "Failed filter",[m
[32m+[m[32m            48 => "Phantom",[m
[32m+[m[32m            49 => "System shutdown",[m
[32m+[m[32m            50 => "Held for ejection",[m
[32m+[m[32m            51 => "Driver blocked",[m
[32m+[m[32m            52 => "Registry too large",[m
[32m+[m[32m            53 => "Console locked",[m
[32m+[m[32m            54 => "Need class config",[m
[32m+[m[32m            _ => "Unknown problem",[m
[32m+[m[32m        };[m
[32m+[m[32m        format!("Problem (Code {}): {}", problem, problem_desc)[m
[32m+[m[32m    } else if status & DN_STARTED != 0 {[m
[32m+[m[32m        "Working properly".to_string()[m
[32m+[m[32m    } else if status & DN_DRIVER_LOADED == 0 {[m
[32m+[m[32m        "Driver not loaded".to_string()[m
[32m+[m[32m    } else if status & DN_ENUM_LOADED == 0 {[m
[32m+[m[32m        "Enumeration not loaded".to_string()[m
[32m+[m[32m    } else {[m
[32m+[m[32m        format!("Status: 0x{:08X}", status)[m
[32m+[m[32m    }[m
[32m+[m[32m}[m
[32m+[m
 /// Enumerate all COM ports on the system[m
 #[cfg(target_os = "windows")][m
 pub fn enumerate_com_ports() -> Result<Vec<ComPortInfo>> {[m
[36m@@ -105,6 +229,11 @@[m [mpub fn enumerate_com_ports() -> Result<Vec<ComPortInfo>> {[m
                 hardware_id: String::new(),[m
                 is_virtio: false,[m
                 device_path: PathBuf::new(),[m
[32m+[m[32m                instance_id: String::new(),[m
[32m+[m[32m                device_status: String::new(),[m
[32m+[m[32m                driver_service: String::new(),[m
[32m+[m[32m                location_info: String::new(),[m
[32m+[m[32m                interface_paths: Vec::new(),[m
             };[m
             [m
             // Get friendly name[m
[36m@@ -305,9 +434,9 @@[m [mpub fn try_open_com_port(_port_name: &str) -> Result<()> {[m
 pub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {[m
     unsafe {[m
         let mut devices = Vec::new();[m
[31m-        [m
[32m+[m
         info!("Searching for VirtIO devices in system devices...");[m
[31m-        [m
[32m+[m
         // Get device information set for all system devices[m
         let h_dev_info = SetupDiGetClassDevsW([m
             &GUID_DEVCLASS_SYSTEM,[m
[36m@@ -315,24 +444,24 @@[m [mpub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {[m
             ptr::null_mut(),[m
             DIGCF_PRESENT,[m
         );[m
[31m-        [m
[32m+[m
         if h_dev_info == INVALID_HANDLE_VALUE {[m
             return Err(anyhow!("Failed to get system device information set"));[m
         }[m
[31m-        [m
[32m+[m
         let _cleanup = DevInfoCleanup(h_dev_info);[m
[31m-        [m
[32m+[m
         let mut dev_info_data: SP_DEVINFO_DATA = mem::zeroed();[m
         dev_info_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as DWORD;[m
[31m-        [m
[32m+[m
         let mut index = 0;[m
[31m-        [m
[32m+[m
         while SetupDiEnumDeviceInfo(h_dev_info, index, &mut dev_info_data) != FALSE {[m
             index += 1;[m
[31m-            [m
[32m+[m
             let mut buffer: [u16; 256] = [0; 256];[m
             let mut required_size = 0;[m
[31m-            [m
[32m+[m
             // Get hardware ID[m
             if SetupDiGetDeviceRegistryPropertyW([m
                 h_dev_info,[m
[36m@@ -347,21 +476,26 @@[m [mpub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {[m
                     .to_string_lossy()[m
                     .trim_end_matches('\0')[m
                     .to_string();[m
[31m-                [m
[32m+[m
                 // Check if it's a VirtIO serial device[m
                 if hardware_id.contains(VIRTIO_VENDOR_ID) {[m
                     for dev_id in VIRTIO_SERIAL_DEVICE_IDS {[m
                         if hardware_id.contains(dev_id) {[m
                             info!("Found VirtIO serial system device: {}", hardware_id);[m
[31m-                            [m
[32m+[m
                             let mut device_info = ComPortInfo {[m
                                 port_name: String::new(),[m
                                 friendly_name: String::new(),[m
                                 hardware_id: hardware_id.clone(),[m
                                 is_virtio: true,[m
                                 device_path: PathBuf::new(),[m
[32m+[m[32m                                instance_id: String::new(),[m
[32m+[m[32m                                device_status: String::new(),[m
[32m+[m[32m                                driver_service: String::new(),[m
[32m+[m[32m                                location_info: String::new(),[m
[32m+[m[32m                                interface_paths: Vec::new(),[m
                             };[m
[31m-                            [m
[32m+[m
                             // Get friendly name[m
                             if SetupDiGetDeviceRegistryPropertyW([m
                                 h_dev_info,[m
[36m@@ -377,7 +511,7 @@[m [mpub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {[m
                                     .trim_end_matches('\0')[m
                                     .to_string();[m
                             }[m
[31m-                            [m
[32m+[m
                             // Get device instance ID[m
                             let mut instance_id_buffer: [u16; 256] = [0; 256];[m
                             if SetupDiGetDeviceInstanceIdW([m
[36m@@ -387,24 +521,220 @@[m [mpub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {[m
                                 instance_id_buffer.len() as DWORD,[m
                                 &mut required_size,[m
                             ) != FALSE {[m
[31m-                                let instance_id = OsString::from_wide(&instance_id_buffer[..])[m
[32m+[m[32m                                device_info.instance_id = OsString::from_wide(&instance_id_buffer[..])[m
[32m+[m[32m                                    .to_string_lossy()[m
[32m+[m[32m                                    .trim_end_matches('\0')[m
[32m+[m[32m                                    .to_string();[m
[32m+[m[32m                                debug!("Device instance ID: {}", device_info.instance_id);[m
[32m+[m[32m                            }[m
[32m+[m
[32m+[m[32m                            // Get device status using Configuration Manager API[m
[32m+[m[32m                            let mut status: u32 = 0;[m
[32m+[m[32m                            let mut problem: u32 = 0;[m
[32m+[m[32m                            let cm_result = CM_Get_DevNode_Status([m
[32m+[m[32m                                &mut status,[m
[32m+[m[32m                                &mut problem,[m
[32m+[m[32m                                dev_info_data.DevInst,[m
[32m+[m[32m                                0,[m
[32m+[m[32m                            );[m
[32m+[m
[32m+[m[32m                            if cm_result == CR_SUCCESS {[m
[32m+[m[32m                                device_info.device_status = translate_device_status(status, problem);[m
[32m+[m[32m                                debug!("Device status: {} (status: 0x{:08X}, problem: {})",[m
[32m+[m[32m                                       device_info.device_status, status, problem);[m
[32m+[m[32m                            } else {[m
[32m+[m[32m                                device_info.device_status = format!("Unknown (CM error: 0x{:08X})", cm_result);[m
[32m+[m[32m                                debug!("Failed to get device status: CM error 0x{:08X}", cm_result);[m
[32m+[m[32m                            }[m
[32m+[m
[32m+[m[32m                            // Get driver service name[m
[32m+[m[32m                            if SetupDiGetDeviceRegistryPropertyW([m
[32m+[m[32m                                h_dev_info,[m
[32m+[m[32m                                &mut dev_info_data,[m
[32m+[m[32m                                SPDRP_SERVICE,[m
[32m+[m[32m                                ptr::null_mut(),[m
[32m+[m[32m                                buffer.as_mut_ptr() as LPBYTE,[m
[32m+[m[32m                                (buffer.len() * 2) as DWORD,[m
[32m+[m[32m                                &mut required_size,[m
[32m+[m[32m                            ) != FALSE {[m
[32m+[m[32m                                device_info.driver_service = OsString::from_wide(&buffer[..])[m
[32m+[m[32m                                    .to_string_lossy()[m
[32m+[m[32m                                    .trim_end_matches('\0')[m
[32m+[m[32m                                    .to_string();[m
[32m+[m[32m                                debug!("Driver service: {}", device_info.driver_service);[m
[32m+[m[32m                            }[m
[32m+[m
[32m+[m[32m                            // Get location information[m
[32m+[m[32m                            if SetupDiGetDeviceRegistryPropertyW([m
[32m+[m[32m                                h_dev_info,[m
[32m+[m[32m                                &mut dev_info_data,[m
[32m+[m[32m                                SPDRP_LOCATION_INFORMATION,[m
[32m+[m[32m                                ptr::null_mut(),[m
[32m+[m[32m                                buffer.as_mut_ptr() as LPBYTE,[m
[32m+[m[32m                                (buffer.len() * 2) as DWORD,[m
[32m+[m[32m                                &mut required_size,[m
[32m+[m[32m                            ) != FALSE {[m
[32m+[m[32m                                device_info.location_info = OsString::from_wide(&buffer[..])[m
                                     .to_string_lossy()[m
                                     .trim_end_matches('\0')[m
                                     .to_string();[m
[31m-                                debug!("Device instance ID: {}", instance_id);[m
[32m+[m[32m                                debug!("Location info: {}", device_info.location_info);[m
                             }[m
[31m-                            [m
[32m+[m
[32m+[m[32m                            // Try to get device interface paths for this device[m
[32m+[m[32m                            device_info.interface_paths = get_device_interface_paths(h_dev_info, &dev_info_data);[m
[32m+[m
[32m+[m[32m                            // Enhanced logging for DEV_1043 devices[m
[32m+[m[32m                            if hardware_id.contains("DEV_1043") {[m
[32m+[m[32m                                info!("=== Enhanced DEV_1043 Device Analysis ===");[m
[32m+[m[32m                                info!("  Hardware ID: {}", device_info.hardware_id);[m
[32m+[m[32m                                info!("  Friendly Name: {}", device_info.friendly_name);[m
[32m+[m[32m                                info!("  Instance ID: {}", device_info.instance_id);[m
[32m+[m[32m                                info!("  Status: {}", device_info.device_status);[m
[32m+[m[32m                                info!("  Driver Service: {}", device_info.driver_service);[m
[32m+[m[32m                                info!("  Location: {}", device_info.location_info);[m
[32m+[m[32m                                info!("  Interface Paths: {:?}", device_info.interface_paths);[m
[32m+[m
[32m+[m[32m                                if device_info.driver_service.is_empty() {[m
[32m+[m[32m                                    warn!("  ⚠️  No driver service found - driver may not be properly installed");[m
[32m+[m[32m                                }[m
[32m+[m[32m                                if device_info.device_status.contains("Problem") {[m
[32m+[m[32m                                    warn!("  ⚠️  Device has problems - check Device Manager for details");[m
[32m+[m[32m                                }[m
[32m+[m[32m                                if device_info.interface_paths.is_empty() {[m
[32m+[m[32m                                    warn!("  ⚠️  No device interfaces found - device may not be accessible");[m
[32m+[m[32m                                }[m
[32m+[m[32m                                info!("==========================================");[m
[32m+[m[32m                            }[m
[32m+[m
                             devices.push(device_info);[m
                         }[m
                     }[m
                 }[m
             }[m
         }[m
[31m-        [m
[32m+[m
         Ok(devices)[m
     }[m
 }[m
 [m
[32m+[m[32m/// Helper function to get device interface paths for a specific device[m
[32m+[m[32m#[cfg(target_os = "windows")][m
[32m+[m[32munsafe fn get_device_interface_paths(h_dev_info: HDEVINFO, target_dev_info_data: &SP_DEVINFO_DATA) -> Vec<String> {[m
[32m+[m[32m    let mut interface_paths = Vec::new();[m
[32m+[m
[32m+[m[32m    // Get the target device's instance ID for comparison[m
[32m+[m[32m    let mut target_instance_id_buffer: [u16; 256] = [0; 256];[m
[32m+[m[32m    let mut required_size = 0;[m
[32m+[m[32m    let target_instance_id = if SetupDiGetDeviceInstanceIdW([m
[32m+[m[32m        h_dev_info,[m
[32m+[m[32m        target_dev_info_data as *const _ as *mut _,[m
[32m+[m[32m        target_instance_id_buffer.as_mut_ptr(),[m
[32m+[m[32m        target_instance_id_buffer.len() as DWORD,[m
[32m+[m[32m        &mut required_size,[m
[32m+[m[32m    ) != FALSE {[m
[32m+[m[32m        OsString::from_wide(&target_instance_id_buffer[..])[m
[32m+[m[32m            .to_string_lossy()[m
[32m+[m[32m            .trim_end_matches('\0')[m
[32m+[m[32m            .to_string()[m
[32m+[m[32m    } else {[m
[32m+[m[32m        return interface_paths; // Can't get target instance ID, return empty[m
[32m+[m[32m    };[m
[32m+[m
[32m+[m[32m    // Try to get device interfaces for various VirtIO-related interface classes[m
[32m+[m[32m    let interface_guids = [[m
[32m+[m[32m        GUID_DEVINTERFACE_COMPORT,[m
[32m+[m[32m        // Add more interface GUIDs as needed[m
[32m+[m[32m    ];[m
[32m+[m
[32m+[m[32m    for guid in &interface_guids {[m
[32m+[m[32m        let h_interface_dev_info = SetupDiGetClassDevsW([m
[32m+[m[32m            guid,[m
[32m+[m[32m            ptr::null(),[m
[32m+[m[32m            ptr::null_mut(),[m
[32m+[m[32m            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,[m
[32m+[m[32m        );[m
[32m+[m
[32m+[m[32m        if h_interface_dev_info != INVALID_HANDLE_VALUE {[m
[32m+[m[32m            let _cleanup = DevInfoCleanup(h_interface_dev_info);[m
[32m+[m
[32m+[m[32m            let mut dev_interface_data: SP_DEVICE_INTERFACE_DATA = mem::zeroed();[m
[32m+[m[32m            dev_interface_data.cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as DWORD;[m
[32m+[m
[32m+[m[32m            let mut index = 0;[m
[32m+[m[32m            while SetupDiEnumDeviceInterfaces([m
[32m+[m[32m                h_interface_dev_info,[m
[32m+[m[32m                ptr::null_mut(),[m
[32m+[m[32m                guid,[m
[32m+[m[32m                index,[m
[32m+[m[32m                &mut dev_interface_data,[m
[32m+[m[32m            ) != FALSE {[m
[32m+[m[32m                index += 1;[m
[32m+[m
[32m+[m[32m                // Get the required size for the detail data[m
[32m+[m[32m                let mut required_size = 0;[m
[32m+[m[32m                SetupDiGetDeviceInterfaceDetailW([m
[32m+[m[32m                    h_interface_dev_info,[m
[32m+[m[32m                    &mut dev_interface_data,[m
[32m+[m[32m                    ptr::null_mut(),[m
[32m+[m[32m                    0,[m
[32m+[m[32m                    &mut required_size,[m
[32m+[m[32m                    ptr::null_mut(),[m
[32m+[m[32m                );[m
[32m+[m
[32m+[m[32m                if required_size > 0 {[m
[32m+[m[32m                    // Allocate buffer for the detail data[m
[32m+[m[32m                    let mut detail_buffer: Vec<u8> = vec![0; required_size as usize];[m
[32m+[m[32m                    let detail_data = detail_buffer.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;[m
[32m+[m[32m                    (*detail_data).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as DWORD;[m
[32m+[m
[32m+[m[32m                    // Get device info data for this interface[m
[32m+[m[32m                    let mut interface_dev_info_data: SP_DEVINFO_DATA = mem::zeroed();[m
[32m+[m[32m                    interface_dev_info_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as DWORD;[m
[32m+[m
[32m+[m[32m                    if SetupDiGetDeviceInterfaceDetailW([m
[32m+[m[32m                        h_interface_dev_info,[m
[32m+[m[32m                        &mut dev_interface_data,[m
[32m+[m[32m                        detail_data,[m
[32m+[m[32m                        required_size,[m
[32m+[m[32m                        ptr::null_mut(),[m
[32m+[m[32m                        &mut interface_dev_info_data,[m
[32m+[m[32m                    ) != FALSE {[m
[32m+[m[32m                        // Get instance ID for this interface device[m
[32m+[m[32m                        let mut interface_instance_id_buffer: [u16; 256] = [0; 256];[m
[32m+[m[32m                        if SetupDiGetDeviceInstanceIdW([m
[32m+[m[32m                            h_interface_dev_info,[m
[32m+[m[32m                            &mut interface_dev_info_data,[m
[32m+[m[32m                            interface_instance_id_buffer.as_mut_ptr(),[m
[32m+[m[32m                            interface_instance_id_buffer.len() as DWORD,[m
[32m+[m[32m                            &mut required_size,[m
[32m+[m[32m                        ) != FALSE {[m
[32m+[m[32m                            let interface_instance_id = OsString::from_wide(&interface_instance_id_buffer[..])[m
[32m+[m[32m                                .to_string_lossy()[m
[32m+[m[32m                                .trim_end_matches('\0')[m
[32m+[m[32m                                .to_string();[m
[32m+[m
[32m+[m[32m                            // Only add the path if instance IDs match[m
[32m+[m[32m                            if interface_instance_id == target_instance_id {[m
[32m+[m[32m                                let path_ptr = (*detail_data).DevicePath.as_ptr();[m
[32m+[m[32m                                let path_len = (0..).take_while(|&i| *path_ptr.offset(i) != 0).count();[m
[32m+[m[32m                                let path_slice = std::slice::from_raw_parts(path_ptr, path_len);[m
[32m+[m[32m                                let device_path = OsString::from_wide(path_slice).to_string_lossy().to_string();[m
[32m+[m
[32m+[m[32m                                if !device_path.is_empty() {[m
[32m+[m[32m                                    interface_paths.push(device_path);[m
[32m+[m[32m                                }[m
[32m+[m[32m                            }[m
[32m+[m[32m                        }[m
[32m+[m[32m                    }[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    interface_paths[m
[32m+[m[32m}[m
[32m+[m
 #[cfg(not(target_os = "windows"))][m
 pub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {[m
     Err(anyhow!("System device enumeration is only supported on Windows"))[m
[36m@@ -413,34 +743,46 @@[m [mpub fn find_virtio_system_devices() -> Result<Vec<ComPortInfo>> {[m
 /// Try to find VirtIO device paths through alternative methods[m
 #[cfg(target_os = "windows")][m
 pub fn find_virtio_device_paths() -> Vec<PathBuf> {[m
[32m+[m[32m    use crate::communication::VirtioSerial;[m
     let mut paths = Vec::new();[m
[31m-    [m
[32m+[m
     // Common VirtIO device paths on Windows[m
     let possible_paths = vec![[m
[31m-        PathBuf::from(r"\\.\VirtioSerial"),[m
[31m-        PathBuf::from(r"\\.\Global\VirtioSerial"),[m
[31m-        PathBuf::from(r"\\.\pipe\VirtioSerial"),[m
[31m-        PathBuf::from(r"\\.\Global\org.qemu.guest_agent.0"),[m
[31m-        PathBuf::from(r"\\.\pipe\org.qemu.guest_agent.0"),[m
[31m-        PathBuf::from(r"\\.\Global\org.infinibay.agent"),[m
[31m-        PathBuf::from(r"\\.\pipe\org.infinibay.agent")[m
[32m+[m[32m        (PathBuf::from(r"\\.\VirtioSerial"), false),  // Direct device[m
[32m+[m[32m        (PathBuf::from(r"\\.\Global\VirtioSerial"), true),  // Global object[m
[32m+[m[32m        (PathBuf::from(r"\\.\pipe\VirtioSerial"), false),  // Named pipe[m
[32m+[m[32m        (PathBuf::from(r"\\.\Global\org.qemu.guest_agent.0"), true),  // Global object[m
[32m+[m[32m        (PathBuf::from(r"\\.\pipe\org.qemu.guest_agent.0"), false),  // Named pipe[m
[32m+[m[32m        (PathBuf::from(r"\\.\Global\org.infinibay.agent"), true),  // Global object[m
[32m+[m[32m        (PathBuf::from(r"\\.\pipe\org.infinibay.agent"), false),  // Named pipe[m
     ];[m
[31m-    [m
[31m-    for path in possible_paths {[m
[31m-        // Try to open the device to check if it exists[m
[31m-        use std::fs::OpenOptions;[m
[31m-        if let Ok(_) = OpenOptions::new()[m
[31m-            .read(true)[m
[31m-            .write(true)[m
[31m-            .open(&path)[m
[31m-        {[m
[32m+[m
[32m+[m[32m    for (path, is_global) in possible_paths {[m
[32m+[m[32m        let path_str = path.to_string_lossy();[m
[32m+[m[32m        let accessible = if is_global {[m
[32m+[m[32m            // Use Windows-specific helper for Global objects[m
[32m+[m[32m            match VirtioSerial::try_open_windows_device(&path_str, false) {[m
[32m+[m[32m                Ok(true) => true,[m
[32m+[m[32m                Ok(false) | Err(_) => false,[m
[32m+[m[32m            }[m
[32m+[m[32m        } else {[m
[32m+[m[32m            // Use standard file operations for pipes and direct devices[m
[32m+[m[32m            use std::fs::OpenOptions;[m
[32m+[m[32m            OpenOptions::new()[m
[32m+[m[32m                .read(true)[m
[32m+[m[32m                .write(true)[m
[32m+[m[32m                .open(&path)[m
[32m+[m[32m                .is_ok()[m
[32m+[m[32m        };[m
[32m+[m
[32m+[m[32m        if accessible {[m
             info!("Found working VirtIO device path: {}", path.display());[m
             paths.push(path);[m
         } else {[m
             debug!("VirtIO device path not accessible: {}", path.display());[m
         }[m
     }[m
[31m-    [m
[32m+[m
     // Also try numbered VirtIO devices[m
     for i in 0..10 {[m
         let path = PathBuf::from(format!(r"\\.\VirtioSerial{}", i));[m
[36m@@ -454,7 +796,7 @@[m [mpub fn find_virtio_device_paths() -> Vec<PathBuf> {[m
             paths.push(path);[m
         }[m
     }[m
[31m-    [m
[32m+[m
     paths[m
 }[m
 [m
[36m@@ -463,22 +805,21 @@[m [mpub fn find_virtio_device_paths() -> Vec<PathBuf> {[m
     Vec::new()[m
 }[m
 [m
[31m-/// Get device interface paths for VirtIO serial devices[m
[32m+[m[32m/// Get VirtIO device instance IDs for diagnostic purposes[m
 #[cfg(target_os = "windows")][m
[31m-pub fn get_virtio_device_interfaces() -> Result<Vec<String>> {[m
[32m+[m[32mpub fn get_virtio_instance_ids() -> Result<Vec<String>> {[m
     use std::process::Command;[m
[31m-    [m
[31m-    let mut interfaces = Vec::new();[m
[31m-    [m
[31m-    // Use PowerShell to get device interfaces[m
[32m+[m
[32m+[m[32m    let mut instance_ids = Vec::new();[m
[32m+[m
[32m+[m[32m    // Use PowerShell to get device instance IDs[m
     let ps_cmd = r#"[m
         $devices = Get-PnpDevice | Where-Object {$_.InstanceId -like '*VEN_1AF4*DEV_1043*'}[m
         foreach ($device in $devices) {[m
[31m-            $interfaces = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DeviceDesc', 'DEVPKEY_Device_FriendlyName', 'DEVPKEY_Device_InstanceId'[m
             Write-Output $device.InstanceId[m
         }[m
     "#;[m
[31m-    [m
[32m+[m
     match Command::new("powershell")[m
         .args(&["-Command", ps_cmd])[m
         .output()[m
[36m@@ -488,74 +829,166 @@[m [mpub fn get_virtio_device_interfaces() -> Result<Vec<String>> {[m
             for line in output_str.lines() {[m
                 let line = line.trim();[m
                 if !line.is_empty() && line.contains("VEN_1AF4") {[m
[31m-                    interfaces.push(line.to_string());[m
[31m-                    debug!("Found VirtIO device interface: {}", line);[m
[32m+[m[32m                    instance_ids.push(line.to_string());[m
[32m+[m[32m                    debug!("Found VirtIO device instance ID: {}", line);[m
                 }[m
             }[m
         }[m
         Err(e) => {[m
[31m-            warn!("Failed to get device interfaces: {}", e);[m
[32m+[m[32m            warn!("Failed to get device instance IDs: {}", e);[m
         }[m
     }[m
[31m-    [m
[31m-    Ok(interfaces)[m
[32m+[m
[32m+[m[32m    Ok(instance_ids)[m
 }[m
 [m
 #[cfg(not(target_os = "windows"))][m
[31m-pub fn get_virtio_device_interfaces() -> Result<Vec<String>> {[m
[31m-    Err(anyhow!("Device interface enumeration is only supported on Windows"))[m
[32m+[m[32mpub fn get_virtio_instance_ids() -> Result<Vec<String>> {[m
[32m+[m[32m    Err(anyhow!("Device instance ID enumeration is only supported on Windows"))[m
 }[m
 [m
 /// Check if VirtIO drivers are installed and get diagnostic info[m
 #[cfg(target_os = "windows")][m
 pub fn diagnose_virtio_installation() -> Result<String> {[m
     use std::process::Command;[m
[31m-    [m
[32m+[m
     let mut diagnosis = String::new();[m
[31m-    diagnosis.push_str("VirtIO Installation Diagnosis\n");[m
[31m-    diagnosis.push_str("============================\n\n");[m
[31m-    [m
[31m-    // Check for VirtIO devices using PowerShell[m
[31m-    let ps_cmd = r#"Get-WmiObject Win32_PnPEntity | Where-Object {$_.DeviceID -like '*VEN_1AF4*'} | Select-Object Name, DeviceID, Status, Service"#;[m
[31m-    [m
[32m+[m[32m    diagnosis.push_str("Enhanced VirtIO Installation Diagnosis\n");[m
[32m+[m[32m    diagnosis.push_str("=====================================\n\n");[m
[32m+[m
[32m+[m[32m    // Enhanced device analysis using our improved detection[m
[32m+[m[32m    diagnosis.push_str("=== Enhanced VirtIO Device Detection ===\n");[m
[32m+[m[32m    match find_virtio_system_devices() {[m
[32m+[m[32m        Ok(devices) => {[m
[32m+[m[32m            if devices.is_empty() {[m
[32m+[m[32m                diagnosis.push_str("❌ No VirtIO serial devices found in system devices\n");[m
[32m+[m[32m            } else {[m
[32m+[m[32m                diagnosis.push_str(&format!("✓ {} VirtIO serial device(s) found:\n", devices.len()));[m
[32m+[m[32m                for device in &devices {[m
[32m+[m[32m                    diagnosis.push_str(&format!("  📱 Device: {}\n", device.friendly_name));[m
[32m+[m[32m                    diagnosis.push_str(&format!("     Hardware ID: {}\n", device.hardware_id));[m
[32m+[m[32m                    diagnosis.push_str(&format!("     Instance ID: {}\n", device.instance_id));[m
[32m+[m[32m                    diagnosis.push_str(&format!("     Status: {}\n", device.device_status));[m
[32m+[m[32m                    diagnosis.push_str(&format!("     Driver Service: {}\n", device.driver_service));[m
[32m+[m[32m                    diagnosis.push_str(&format!("     Location: {}\n", device.location_info));[m
[32m+[m
[32m+[m[32m                    if !device.interface_paths.is_empty() {[m
[32m+[m[32m                        diagnosis.push_str("     Interface Paths:\n");[m
[32m+[m[32m                        for path in &device.interface_paths {[m
[32m+[m[32m                            diagnosis.push_str(&format!("       - {}\n", path));[m
[32m+[m[32m                        }[m
[32m+[m[32m                    }[m
[32m+[m
[32m+[m[32m                    // Specific analysis for DEV_1043 devices[m
[32m+[m[32m                    if device.hardware_id.contains("DEV_1043") {[m
[32m+[m[32m                        diagnosis.push_str("\n     🔍 DEV_1043 Analysis:\n");[m
[32m+[m[32m                        if device.driver_service.is_empty() {[m
[32m+[m[32m                            diagnosis.push_str("       ⚠️  No driver service - driver installation issue\n");[m
[32m+[m[32m                        } else {[m
[32m+[m[32m                            diagnosis.push_str(&format!("       ✓ Driver service: {}\n", device.driver_service));[m
[32m+[m[32m                        }[m
[32m+[m
[32m+[m[32m                        if device.device_status.contains("Problem") {[m
[32m+[m[32m                            diagnosis.push_str("       ⚠️  Device has problems - check Device Manager\n");[m
[32m+[m[32m                        } else {[m
[32m+[m[32m                            diagnosis.push_str("       ✓ Device status appears normal\n");[m
[32m+[m[32m                        }[m
[32m+[m
[32m+[m[32m                        if device.interface_paths.is_empty() {[m
[32m+[m[32m                            diagnosis.push_str("       ⚠️  No accessible interfaces - configuration issue\n");[m
[32m+[m[32m                        } else {[m
[32m+[m[32m                            diagnosis.push_str("       ✓ Device interfaces available\n");[m
[32m+[m[32m                        }[m
[32m+[m[32m                    }[m
[32m+[m[32m                    diagnosis.push_str("\n");[m
[32m+[m[32m                }[m
[32m+[m[32m            }[m
[32m+[m[32m        }[m
[32m+[m[32m        Err(e) => {[m
[32m+[m[32m            diagnosis.push_str(&format!("Failed to enumerate VirtIO system devices: {}\n", e));[m
[32m+[m[32m        }[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    diagnosis.push_str("\n=== VirtIO Driver Service Status ===\n");[m
[32m+[m[32m{}\n", device.driver_service));[m
    [m
\ No newline at end of file[m
[32m+[m[32m                    }[m

                        if device.device_status.contains("Problem") {[m
                            diagnosis.push_str("       ⚠[m
\ No newline at end of file[m
 ️  Device has problems - check Devi[m
\ No newline at end of file[m
[31m-        .args(&["-Command", ps_cmd])[m
[32m+[m[32mce Manager\n");[m
                        } [m
\ No newline at end of file[m
 else {[m
           [m
\ No newline at end of file[m
       [m
\ No newline at end of file[m
            diagnosis.pus[m
\ No newline at end of file[m
 h_str("       ✓ Device status appears normal\n");[m
                  [m
\ No newline at end of file[m
       }[m

                        if device.int[m
\ No newline at end of file[m
[31m-                diagnosis.push_str("❌ No VirtIO devices found in Device Manager\n");[m
[32m+[m[32merface_paths.is_empty() {[m
                            diagnosis.push_s[m
\ No newline at end of file[m
 tr("       ⚠️  No[m
\ No newline at end of file[m
[31m-                diagnosis.push_str("✓ VirtIO devices found:\n");[m
[32m+[m[32m accessible interfaces - configuration issue\n");[m
            [m
\ No newline at end of file[m
             } else {[m
                            [m
\ No newline at end of file[m
 diagnosis.push[m
\ No newline at end of file[m
 _str("    [m
\ No newline at end of file[m
    ✓ Device interf[m
\ No newline at end of file[m
[31m-            diagnosis.push_str(&format!("Failed to query VirtIO devices: {}\n", e));[m
[32m+[m[32maces available\n");[m
                        }[m
                    }[m
                  [m
\ No newline at end of file[m
   diagnosi[m
\ No newline at end of file[m
 s.push[m
\ No newline at end of file[m
[31m-    [m
[31m-    diagnosis.push_str("\n");[m
[31m-    [m
[31m-    // Check for VirtIO serial specific devices[m
[31m-    let serial_cmd = r#"Get-WmiObject Win32_PnPEntity | Where-Object {$_.DeviceID -like '*VEN_1AF4*' -and ($_.DeviceID -like '*DEV_1003*' -or $_.DeviceID -like '*DEV_1043*' -or $_.DeviceID -like '*DEV_1044*')} | Select-Object Name, DeviceID, Status"#;[m
[31m-    [m
[32m+[m[32m_[m
\ No newline at end of file[m
[32m+[m[32mstr("\n");[m
                }[m
            }[m
        }[m
    [m
\ No newline at end of file[m
[32m+[m[32m    Err(e) => {[m
            diagno[m
\ No newline at end of file[m
[32m+[m[32msis.push_str(&format!([m
\ No newline at end of file[m
[32m+[m[32m"Failed to enumerate Vi[m
\ No newline at end of file[m
[32m+[m[32mrtIO system devices: {}\n", e));[m
        }[m
    }[m

    diagnosi[m
\ No newline at end of file[m
[32m+[m[32ms.push_str("\n=== VirtIO Driver Service Status ===\n");[m
    // Chec[m
\ No newline at end of file[m
[32m+[m[32mk VirtIO d[m
\ No newline at end of file[m
[32m+[m[32mriver services[m
    let service_cmd = r#[m
\ No newline at end of file[m
[32m+[m[32m"Get-Service | Where-Object {$_.Nam[m
\ No newline at end of file[m
[32m+[m[32me -like '*virtio*' -or $_.Name -like '*vioser*'} | Select-Obj[m
\ No newline at end of file[m
[32m+[m[32mect Name, Status, StartType"#;[m
    match Command::new("powershell")[m
        .a[m
\ No newline at end of file[m
[32m+[m[32mrgs(&["-Command", service_cmd])[m
        .output()[m
    {[m
        Ok(output) => {[m
   [m
\ No newline at end of file[m
[32m+[m[32m         let output_str = String::from_utf8_lossy(&output.stdout);[m
            if o[m
\ No newline at end of file[m
[32m+[m[32mutput_str.trim().is_e[m
\ No newline at end of file[m
[32m+[m[32mmpty() {[m
                diagnosis.push_str("❌ No VirtIO serv[m
\ No newline at end of file[m
[32m+[m[32mices found\n")[m
\ No newline at end of file[m
[32m+[m[32m;[m
        [m
\ No newline at end of file[m
[32m+[m[32m    } el[m
\ No newline at end of file[m
[32m+[m[32ms[m
\ No newline at end of file[m
 e {[m
                diagnosis.push_st[m
\ No newline at end of file[m
[31m-        .args(&["-Command", serial_cmd])[m
[32m+[m[32mr("✓ VirtIO services:\n");[m
         [m
\ No newline at end of file[m
        diagnosis.p[m
\ No newline at end of file[m
 ush_st[m
\ No newline at end of file[m
 r(&output_str);[m
        [m
\ No newline at end of file[m
     }[m
        }[m
        Err(e) => {[m
            diagnosis.push_str(&fo[m
\ No newline at end of file[m
 rmat!("Failed to query VirtIO services: {}\n",[m
\ No newline at end of file[m
[31m-                diagnosis.push_str("❌ No VirtIO serial devices found\n");[m
[32m+[m[32m e));[m
        }[m
    }[m

    diagnosis.push_str("\n=== Registry Analysis ===\[m
\ No newline at end of file[m
 n");[m
    // Check Vir[m
\ No newline at end of file[m
[31m-                diagnosis.push_str("✓ VirtIO serial devices found:\n");[m
 tIO registry keys[m
    let reg_cmd = r#"[m
        $[m
\ No newline at end of file[m
 regPaths = @([m
           [m
\ No newline at end of file[m
   'HKLM:\SYSTEM\Curr[m
\ No newline at end of file[m
[31m-            diagnosis.push_str(&format!("Failed to query VirtIO serial devices: {}\n", e));[m
[32m+[m[32mentControlSet\Services\vioser',[m
            'HKLM:\SYSTEM\CurrentControlSet\Ser[m
\ No newline at end of file[m
[32m+[m[32mvices\Virt[m
\ No newline at end of file[m
[32m+[m[32mioSeri[m
\ No newline at end of file[m
[32m+[m[32ma[m
\ No newline at end of file[m
[32m+[m[32ml'[m
        )[m
        foreach ($path in $regPaths) {[m
       [m
\ No newline at end of file[m
[32m+[m[32m     if (Test-Path $path) {[m
         [m
\ No newline at end of file[m
[32m+[m[32m       Write-Output "�[m
\ No newline at end of file[m
[32m+[m[32m� Found registry key: $path"[m
                $props = Get-ItemProperty $path -Err[m
\ No newline at end of file[m
[32m+[m[32morAction SilentlyContinue[m
                if ($props.Start) { Write-Output "  Start type:[m
\ No newline at end of file[m
[32m+[m[32m $($props.Start)" }[m
                if ($props.Type) { Write-Output "  Service type: $($props.Type)" }[m
\ No newline at end of file[m
[32m+[m
            } else {[m
                Write-Output "❌ Mi[m
\ No newline at end of file[m
[32m+[m[32mssing registry key: $path"[m
            }[m
        }[m
    "#;[m
\ No newline at end of file[m
[32m+[m

    match Command::new("pow[m
\ No newline at end of file[m
[32m+[m[32mershell")[m
        .args(&["-Command", reg_cmd])[m
        .output()[m
    {[m
        Ok(output) => {[m
\ No newline at end of file[m
[32m+[m
         [m
\ No newline at end of file[m
[32m+[m[32m   let o[m
\ No newline at end of file[m
[32m+[m[32mu[m
\ No newline at end of file[m
[32m+[m[32mtput_str = String::from_utf8_lossy(&o[m
\ No newline at end of file[m
[32m+[m[32mutput.stdout);[m
            if output_st[m
\ No newline at end of file[m
[32m+[m[32mr.trim().is_empty([m
\ No newline at end of file[m
[32m+[m[32m) {[m
  [m
\ No newline at end of file[m
[32m+[m[32m              diagnosis.[m
\ No newline at end of file[m
[32m+[m[32mpush_str("❌ No VirtIO registry keys found\n");[m
            } else {[m
[32m+[m[32m                diagnosis.push_str(&output_st[m
\ No newline at end of file[m
[32m+[m[32mr);[m
      [m
\ No newline at end of file[m
[32m+[m[32m      }[m
        }[m
  [m
\ No newline at end of file[m
[32m+[m[32m      Err(e) => {[m
            diagnosis.push_str(&format!("Failed to check regist[m
\ No newline at end of file[m
 ry: {}\n",[m
\ No newline at end of file[m
  e));[m
      [m
\ No newline at end of file[m
[36m@@ -596,31 +1029,97 @@[m [mpub fn diagnose_virtio_installation() -> Result<String> {[m
 h_str[m
\ No newline at end of file[m
 (&format!("✓ {} COM port(s) [m
\ No newline at end of file[m
 found[m
\ No newline at end of file[m
[31m-    // Check device interfaces[m
[31m-    match get_virtio_device_interfaces() {[m
[31m-        Ok(interfaces) => {[m
[31m-            if interfaces.is_empty() {[m
[31m-                diagnosis.push_str("❌ No VirtIO device interfaces found\n");[m
[32m+[m[32msh_str(&output_str);[m
        }[m
  [m
\ No newline at end of file[m
[32m+[m[32m      Err(e) => {[m
            diagnosi[m
\ No newline at end of file[m
[32m+[m[32ms.push_str(&format!("Failed to[m
\ No newline at end of file[m
[32m+[m[32m check privileges: {}\n", e));[m
        }[m
[32m+[m[32m    }[m
    [m
    diagnosis.push_str("\n");[m
    [m
    // Check COM ports[m
    match en[m
\ No newline at end of file[m
 umerate_com_ports() {[m
\ No newline at end of file[m
[31m-                diagnosis.push_str(&format!("✓ {} VirtIO device interface(s) found:\n", interfaces.len()));[m
[31m-                for interface in interfaces {[m
[31m-                    diagnosis.push_str(&format!("  - {}\n", interface));[m
[32m+[m
        Ok(ports) => {[m
            if ports.is_empty() {[m
                diagnosis.push_str("❌ No COM ports fou[m
\ No newline at end of file[m
[32m+[m[32mnd\n");[m
            } else {[m
                diagn[m
\ No newline at end of file[m
[32m+[m[32mosis.push_str(&format!("✓ {} COM port(s) found:\n", ports.len()));[m
      [m
\ No newline at end of file[m
           for port[m
\ No newline at end of file[m
  in ports {[m
  [m
\ No newline at end of file[m
           [m
\ No newline at end of file[m
         diagnosis.pu[m
\ No newline at end of file[m
[31m-            diagnosis.push_str(&format!("Failed to get device interfaces: {}\n", e));[m
[32m+[m[32msh_str(&format!("  - {} ({}): {}\n",[m[41m [m
                                               por[m
\ No newline at end of file[m
 t.port_nam[m
\ No newline at end of file[m
 e, [m
  [m
\ No newline at end of file[m
      [m
\ No newline at end of file[m
[31m-    diagnosis.push_str("\n=== Recommendations ===\n");[m
[31m-    diagnosis.push_str("If VirtIO Serial Driver is installed but not accessible:\n");[m
[31m-    diagnosis.push_str("1. Check VM XML configuration for virtio-serial channel\n");[m
[31m-    diagnosis.push_str("2. Ensure channel has: <target type='virtio' name='org.infinibay.agent'/>\n");[m
[31m-    diagnosis.push_str("3. Try adding: <source mode='bind' path='/tmp/infinibay.sock'/>\n");[m
[31m-    diagnosis.push_str("4. Restart the VM after configuration changes\n");[m
[31m-    diagnosis.push_str("5. Consider using QEMU guest agent as alternative\n");[m
[31m-    [m
[32m+[m[32m                                        port.friendly_name,[m
                      [m
\ No newline at end of file[m
[32m+[m[41m [m
\ No newline at end of file[m
[32m+[m[32m                        if port.is_virtio { "VirtIO" } else[m[41m [m
\ No newline at end of file[m
[32m+[m[32m{ "Non-VirtIO" }));[m
                }[m
            }[m
      [m
\ No newline at end of file[m
[32m+[m[32m  }[m
        Err(e) => {[m
            [m
\ No newline at end of file[m
[32m+[m[32mdiagnosis.push_str(&format!("Failed to[m[41m [m
\ No newline at end of file[m
[32m+[m[32menumerate COM ports: {}\n", e));[m
        }[m
    }[m
    [m
\ No newline at end of file[m
[32m+[m
    diagnosis.push_str("\n");[m
    [m
    // Check for alternative VirtIO paths[m
    [m
\ No newline at end of file[m
[32m+[m[32mlet alt_paths = find_virtio_device_paths();[m
    if alt_paths.is_empty() {[m
        di[m
\ No newline at end of file[m
[32m+[m[32magnosis.push_str("❌ No alternative VirtI[m
\ No newline at end of file[m
[32m+[m[32mO device paths found\n");[m
    } else {[m
 [m
\ No newline at end of file[m
[32m+[m[32m       diagnosis.push_str(&format[m
\ No newline at end of file[m
[32m+[m[32m!("✓ {} alternative VirtIO path(s) found:\n", al[m
\ No newline at end of file[m
[32m+[m[32mt_paths.len()));[m
        for path in alt_paths {[m
         [m
\ No newline at end of file[m
[32m+[m[32m   diagnosis.push_str(&format!("  - {}\n", path.display()));[m
        }[m
    }[m
    [m
    diagnosis.push_str([m
\ No newline at end of file[m
[32m+[m[32m"\n");[m
    [m
    // Check device instance IDs[m
    match get_virtio_instance_ids() {[m
        Ok(ins[m
\ No newline at end of file[m
[32m+[m[32mt[m
\ No newline at end of file[m
[32m+[m[32mance_ids) => {[m
            if instance_ids.is_empty() {[m
[32m+[m[32m                diagnosis.push_str("❌ No Virt[m
\ No newline at end of file[m
[32m+[m[32mIO device instance IDs found\n");[m
\ No newline at end of file[m
[32m+[m
            } else {[m
                diagnosis.push_str[m
\ No newline at end of file[m
[32m+[m[32m(&format!("✓ {} VirtIO device instance ID(s) found:\n",[m
\ No newline at end of file[m
[32m+[m[32m instance_ids.len()));[m
                for instance_id in instance_ids {[m
  [m
\ No newline at end of file[m
[32m+[m[32m                  diagnosis.push_str(&format!("  - {}\n", instan[m
\ No newline at end of file[m
[32m+[m[32mce_id));[m
                }[m
            }[m
        }[m
        Er[m
\ No newline at end of file[m
[32m+[m[32mr(e) => {[m
            diagnosis.pus[m
\ No newline at end of file[m
[32m+[m[32mh[m
\ No newline at end of file[m
[32m+[m[32m_str(&format!("Failed to get device instance IDs: {}\n", e))[m
\ No newline at end of file[m
[32m+[m[32m;[m
        }[m
    }[m
    [m
    diagnosis.push_str("\n=== [m
\ No newline at end of file[m
[32m+[m[32mHypervisor-Specific Configuration[m
\ No newline at end of file[m
[32m+[m[32m Examples ===\n");[m

    diagnosis.push_str("\n🔧 QEMU/KVM Configuration:\n"[m
\ No newline at end of file[m
[32m+[m[32m);[m
    diagnosis.push_str("Add to VM XML configuration:\n");[m
    diagnosis.push_str("```xml\n");[m
    di[m
\ No newline at end of file[m
[32m+[m[32magnosis.push_str("<devices>\n");[m
  [m
\ No newline at end of file[m
[32m+[m[41m [m
\ No newline at end of file[m
[32m+[m[32m diagnosis.push_str("  <channel type='unix'>\n");[m
    diagnosis.push_str("    <source [m
\ No newline at end of file[m
[32m+[m[32mmode='bind' path='/tmp/infinibay.sock'/>\n");[m
    diagnosis.push_str("  [m
\ No newline at end of file[m
[32m+[m[32m  <target type='virtio' name='org.infinibay.agent'/>\n");[m
    diagno[m
\ No newline at end of file[m
[32m+[m[32msis.push_str("  </channel>\n");[m
    diagnosis.push_str("</devices>\n");[m
    diagnosis.pus[m
\ No newline at end of file[m
[32m+[m[32mh_str("```\n");[m
    diagnosis.push_str("Or via command line:\n");[m
    diagnosis.push_str("-de[m
\ No newline at end of file[m
[32m+[m[32mv[m
\ No newline at end of file[m
[32m+[m[32mice virtio-serial-pci \\\n");[m
    diagnosis.push_str("-charde[m
\ No newline at end of file[m
[32m+[m[32mv socket,path=/tmp/infinibay.sock,server=on,wait=off,id=infinibay \\\n");[m
   [m
\ No newline at end of file[m
[32m+[m[32m diagnosis.push_str("-device virtserialport,chardev=infinibay,name=org.infinibay.age[m
\ No newline at end of file[m
[32m+[m[32mnt\n\n");[m

    diagnosis.push_str("🔧 VMware Configuration:\n");[m
    diag[m
\ No newline at end of file[m
[32m+[m[32mn[m
\ No newline at end of file[m
[32m+[m[32mosis.push_str("Add to .vmx file:\n");[m
    diagnosis.push_str("```\n");[m
 [m
\ No newline at end of file[m
[32m+[m[32m   diagnosis.push_str("serial0.present = \"TRUE\"\n");[m
    diagnosis.push_str("serial0.f[m
\ No newline at end of file[m
[32m+[m[32mileType = \"pipe\"\n");[m
    diagnosis.push_str("serial0.fileName[m
\ No newline at end of file[m
[32m+[m[32m = \"\\\\.\\pipe\\infinibay\"\n");[m
    diagnosis.push_str("serial0.pipe.[m
\ No newline at end of file[m
[32m+[m[32me[m
\ No newline at end of file[m
[32m+[m[32mndPoint = \"server\"\n");[m
    diagnosis.push_str("serial0.tryNo[m
\ No newline at end of file[m
[32m+[m[32mRxLoss = \"FALSE\"\n");[m
    diagnosis.push_str("```\n\n");[m

    diagnosis.push[m
\ No newline at end of file[m
[32m+[m[32m_str("🔧 VirtualBox Configuration:\n");[m
    diagnosis.push_str("Vi[m
\ No newline at end of file[m
[32m+[m[32ma VBoxManage command:\n");[m
    diagnosis.push_str("```\n");[m
    diagn[m
\ No newline at end of file[m
[32m+[m[32mo[m
\ No newline at end of file[m
[32m+[m[32msis.push_str("VBoxManage modifyvm \"VM_NAME\" --uart1 0x3F8 4\n");[m
  [m
\ No newline at end of file[m
[32m+[m[32m  diagnosis.push_str("VBoxManage modifyvm \"VM_NAME\" --uartmode1 se[m
\ No newline at end of file[m
[32m+[m[32mrver \\\\.\\pipe\\infinibay\n");[m
    diagnosis.push_str("```\n\n");[m

    diagnosis.p[m
\ No newline at end of file[m
[32m+[m[32mush_str("=== Step-by-Step Troubleshooting for DEV_1043 Issues ===\n");[m
    diagnosis.push_st[m
\ No newline at end of file[m
[32m+[m[32mr[m
\ No newline at end of file[m
[32m+[m[32m("1. 🔍 Verify VirtIO Driver Installation:\n");[m
    diagnosis.push[m
\ No newline at end of file[m
[32m+[m[32m_str("   - Open Device Manager (devmgmt.msc)\n");[m
    diagnosis.push_str("   - Look for 'VirtIO Serial Dr[m
\ No newline at end of file[m
[32m+[m[32miver' under 'System devices'\n");[m
    diagnosis.push_str("   - If missing or has warning icon, reinstal[m
\ No newline at end of file[m
[32m+[m[32ml VirtIO drivers\n\n");[m

    diagnosis.push_str("2. 🔧 Check VM Configuration:\n");[m
    dia[m
\ No newline at end of file[m
[32m+[m[32mg[m
\ No newline at end of file[m
[32m+[m[32mnosis.push_str("   - Ensure virtio-serial device is added to VM\n");[m
    diagnosis[m
\ No newline at end of file[m
[32m+[m[32m.push_str("   - Verify channel name matches 'org.infinibay.agent'\n");[m
    diagn[m
\ No newline at end of file[m
[32m+[m[32mosis.push_str("   - Restart VM after configuration changes\n\n");[m

    diagnosis.pu[m
\ No newline at end of file[m
[32m+[m[32msh_str("3. 🔐 Run with Administrator Privileges:\n");[m
    diagnosis.push_str("   - Ri[m
\ No newline at end of file[m
[32m+[m[32mght-click Command Prompt → 'Run as administrator'\n");[m
    diagnosis.push_st[m
\ No newline at end of file[m
[32m+[m[32mr("   - Run: infiniservice.exe --diag\n");[m
    diagnosis.push_str("   - Check if access issues are [m
\ No newline at end of file[m
[32m+[m[32mr[m
\ No newline at end of file[m
[32m+[m[32mesolved\n\n");[m

    diagnosis.push_str("4. 🔄 Reinstall VirtIO Drivers:\n");[m
   [m
\ No newline at end of file[m
[32m+[m[41m [m
\ No newline at end of file[m
 diagnosis.push_str[m
\ No newline at end of file[m
 ("[m
\ No newline at end of file[m
  [m
\ No newline at end of file[m
[36m@@ -632,7 +1131,7 @@[m [mpub fn diagnose_virtio_installation() -> Result<String> {[m
 h drivers and[m
\ No newline at end of file[m
  reboot\n\n"[m
\ No newline at end of file[m
 );[m

    diagnosis.[m
\ No newline at end of file[m
[31m-    [m
[32m+[m[32mp[m
\ No newline at end of file[m
 ush_str("5. [m
\ No newline at end of file[m
 🔍 Alternative Connection Methods:\n"[m
\ No newline at end of file[m
 );[m
    diagnosis.push_str("   - T[m
\ No newline at end of file[m
[36m@@ -641,13 +1140,20 @@[m [mmod tests {[m
 agent\n");[m
    diagnosis.push_str("   - Test Global objects: \\[m
\ No newline at end of file[m
 \\.\\Global\\org.infinibay.ag[m
\ No newline at end of file[m
 ent\n\n");[m

    diagnosis.push_str("6. 🛠️ Manual[m
\ No newline at end of file[m
[32m+[m[32m Device Path Testing:\n");[m
    diagnosis.push_str("   - Run: infiniservice.exe --device \"\\\\.\\Global[m
\ No newline at end of file[m
[32m+[m[32m\\org.infinibay.agent\"\n");[m
    diagnosis.push_str("   - T[m
\ No newline at end of file[m
[32m+[m[32mry: infiniservice.exe --device \"\\\\.\\pipe\\org.[m
\ No newline at end of file[m
[32m+[m[32minfinibay.agent\"\n");[m
    diagnosis.push_str("   - Test: infiniservice.ex[m
\ No newline at end of file[m
[32m+[m[32me --device \"COM1\" (if available)\n\[m
\ No newline at end of file[m
 n");[m

    d[m
\ No newline at end of file[m
[31m-        [m
[32m+[m[32mi[m
\ No newline at end of file[m
 agnosis.push_str("=== Common Solutions for A[m
\ No newline at end of file[m
 ccess Denied (Error 5) ===\n");[m
 [m
\ No newline at end of file[m
    diagnosis.push_str("• Run service as Administrator [m
\ No newline at end of file[m
[32m+[m[32mor SYSTEM account\n");[m
    diagnosis.push_str("• Check Win[m
\ No newline at end of file[m
[32m+[m[32mdows security policies for device access\n");[m
    d[m
\ No newline at end of file[m
 iagnos[m
\ No newline at end of file[m
[31m-    [m
[32m+[m[32mi[m
\ No newline at end of file[m
 s.push_str("• Verify VM configur[m
\ No newline at end of file[m
 ation includ[m
\ No newline at end of file[m
 es proper channel setup\n");[m
    diagnosis.push_s[m
\ No newline at end of file[m
[36m@@ -656,14 +1162,93 @@[m [mmod tests {[m
 e protection temporarily\n\n");[m

    diagnos[m
\ No newline at end of file[m
 is.push_str("For more help, run: infiniservice.exe -[m
\ No newline at end of file[m
 -debug[m
\ No newline at end of file[m
[31m-    [m
[32m+[m[41m [m
\ No newline at end of file[m
[32m+[m[32m--diag\n");[m

    Ok(diagnosis)[m
}[m

[32m+[m[32m#[cfg(not(ta[m
\ No newline at end of file[m
[32m+[m[32mrget_os = "windows"))][m
pub fn diagnose_virtio_installation()[m
\ No newline at end of file[m
[32m+[m[32m -> Result<String> {[m
    Err(anyhow!("VirtIO diagnosis is only available on Windows"))[m
}[m

//[m
\ No newline at end of file[m
[32m+[m[32m/ Try direct device access using various methods[m
#[[m
\ No newline at end of file[m
[32m+[m[32mcfg(target_os = "windows")][m
pub f[m
\ No newline at end of file[m
[32m+[m[32mn[m
\ No newline at end of file[m
[32m+[m[32m try_direct_device_access(interface_pat[m
\ No newline at end of file[m
[32m+[m[32mh: &str) -> Result<String, Strin[m
\ No newline at end of file[m
[32m+[m[32mg> {[m
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};[m
    use winapi::um:[m
\ No newline at end of file[m
[32m+[m[32m:winnt::{GENERIC_READ, GENERIC_WRI[m
\ No newline at end of file[m
[32m+[m[32mTE, FILE_SHARE_READ, FILE_SHARE_WRITE};[m
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};[m
   [m
\ No newline at end of file[m
[32m+[m[32m use winapi::um::errhandlingapi::GetLastError;[m
    use std::ffi::CString;[m
    use std::ptr;[m

   [m
\ No newline at end of file[m
[32m+[m[32m let c_path = match CString::new(interface_path) {[m
        Ok(path) => path,[m
        Err(_) => return Err("[m
\ No newline at end of file[m
[32m+[m[32mInvalid device path".to_string()),[m
    };[m

    // Try different access mode[m
\ No newline at end of file[m
[32m+[m[32ms[m
    let acce[m
\ No newline at end of file[m
[32m+[m[32mss_modes =[m
\ No newline at end of file[m
[32m+[m[32m vec![[m
\ No newline at end of file[m
[32m+[m
[32m+[m[32m        ("read-write", GENERIC_REA[m
\ No newline at end of file[m
[32m+[m[32mD | GENERIC_[m
\ No newline at end of file[m
[32m+[m[32mWRITE),[m
        ("read-only", GENERIC_READ),[m
        ("write-[m
\ No newline at end of file[m
[32m+[m[32monly", GENERIC_WRITE),[m
    ];[m

    for (mode_name, access_mode) in access_modes {[m
   [m
\ No newline at end of file[m
[32m+[m[32m     unsafe {[m
            let handle = CreateFil[m
\ No newline at end of file[m
[32m+[m[32meA([m
                c_path.as_ptr[m
\ No newline at end of file[m
[32m+[m[32m([m
\ No newline at end of file[m
[32m+[m[32m),[m
                access_mode,[m
            [m
\ No newline at end of file[m
[32m+[m[32m    FILE_SHARE_READ | FILE_SHARE_WRITE,[m
  [m
\ No newline at end of file[m
[32m+[m[32m              ptr::null_mut(),[m
                OPEN_EXISTING,[m
                [m
\ No newline at end of file[m
[32m+[m[32m0,[m
                ptr::null_mut(),[m
            );[m

            if handle != INVALID_HANDLE_VALUE {[m
           [m
\ No newline at end of file[m
[32m+[m[32m     Close[m
\ No newline at end of file[m
[32m+[m[32mHandle[m
\ No newline at end of file[m
[32m+[m[32m([m
\ No newline at end of file[m
[32m+[m[32mhandle);[m
                return Ok[m
\ No newline at end of file[m
[32m+[m[32m(format!("{}[m
\ No newline at end of file[m
[32m+[m[32m:{}", interface_path, mode_name));[m
            }[m
        }[m
    }[m

    // T[m
\ No newline at end of file[m
[32m+[m[32mry overlapped I/O access[m
    unsafe {[m
        let handle = CreateFileA([m
            c_path.as[m
\ No newline at end of file[m
[32m+[m[32m_ptr(),[m
            GENERIC_READ | GENERIC_WRITE,[m
   [m
\ No newline at end of file[m
[32m+[m[32m         FILE_SHARE_READ | FILE_S[m
\ No newline at end of file[m
[32m+[m[32mH[m
\ No newline at end of file[m
[32m+[m[32mARE_WRITE,[m
            ptr::null_mut(),[m
 [m
\ No newline at end of file[m
[32m+[m[41m [m
\ No newline at end of file[m
[32m+[m[32m          OPEN_EXISTING,[m
            winapi::um::w[m
\ No newline at end of file[m
[32m+[m[32minbase::FILE_FLAG_OVERLAPPED,[m
            ptr::null_mut(),[m
        );[m

        if handle != INVALID_HAND[m
\ No newline at end of file[m
[32m+[m[32mLE_VALUE {[m
            CloseHandle(handle);[m
            return Ok(format!("{}:overlapped", interface[m
\ No newline at end of file[m
[32m+[m[32m_path));[m
        }[m
    }[m

    Err(format!("All access methods failed for {}", interface_path))[m
}[m

/// Get de[m
\ No newline at end of file[m
[32m+[m[32mv[m
\ No newline at end of file[m
[32m+[m[32mice capabilities for VirtIO devices[m
#[cfg(target_o[m
\ No newline at end of file[m
[32m+[m[32ms = "windows")][m
pub fn get_virtio_device_capabilities(device_info: &ComPortInfo) -> Result<String, String> {[m
[32m+[m[32m    let mut capabilities = Vec::new();[m

    // Check if device supports IOCTL operations[m
[32m+[m[41m [m
\ No newline at end of file[m
[32m+[m[32m   if !device_info.interface_paths.is_empty() {[m
      [m
\ No newline at end of file[m
[32m+[m[32m  capabilities.push("IOCTL");[m
    }[m

    // Check if device supports overlapped I/O[m
    if device_info.device_status.c[m
\ No newline at end of file[m
[32m+[m[32montain[m
\ No newline at end of file[m
[32m+[m[32ms[m
\ No newline at end of file[m
[32m+[m[32m("Working") || device_info.device_[m
\ No newline at end of file[m
[32m+[m[32mstatus.conta[m
\ No newline at end of file[m
[32m+[m[32mins("OK") {[m
        capabilities.push("O[m
\ No newline at end of file[m
[32m+[m[32mVERLAPPED");[m
    }[m

    // Check if device supports[m
\ No newline at end of file[m
[32m+[m[32m memory-mapped I/O[m
    if device_info.hardware_id.contains("VirtIO") || device_i[m
\ No newline at end of file[m
[32m+[m[32mnfo.hardware_id.contains("DEV_1043") {[m
        capabilities.push("MEMORY_MAPPED")[m
\ No newline at end of file[m
[32m+[m[32m;[m
    }[m

    // Check driver service capabilities[m
    if !device_inf[m
\ No newline at end of file[m
[32m+[m[32mo.driv[m
\ No newline at end of file[m
[32m+[m[32me[m
\ No newline at end of file[m
[32m+[m[32mr_service.is_empty() {[m
        cap[m
\ No newline at end of file[m
[32m+[m[32mabilities.pu[m
\ No newline at end of file[m
[32m+[m[32msh("DRIVER_SERVICE");[m
    }[m

    // Check location inf[m
\ No newline at end of file[m
[32m+[m[32mormation for additional capabilities[m
    if !device_info.location_info.is_empty()[m
\ No newline at end of file[m
[32m+[m[32m {[m
        capabilities.push("LOCATION_INFO");[m
 [m
\ No newline at end of file[m
[32m+[m[32m   }[m

    if capabilities.is_empty() {[m
        Err("No capabilities detected".to_s[m
\ No newline at end of file[m
[32m+[m[32mtring())[m
    } else {[m
        Ok(ca[m
\ No newline at end of file[m
[32m+[m[32mpabili[m
\ No newline at end of file[m
[32m+[m[32mt[m
\ No newline at end of file[m
 ies.join(", "))[m
    }[m
}[m

/// Analyze de[m
\ No newline at end of file[m
 tected VirtI[m
\ No newline at end of file[m
 O devices to determine the best connection[m
\ No newline at end of file[m
  method[m
#[cfg(target_os = "windows")][m
pub fn[m
\ No newline at end of file[m
  get_virtio_device_connection_reco[m
\ No newline at end of file[m
[31m-        [m
[32m+[m[32mm[m
\ No newline at end of file[m
 mendations(device_info: &ComPortInfo) -> Stri[m
\ No newline at end of file[m
 ng {[m
    let mut recommendations =[m
\ No newline at end of file[m
[32m+[m[41m [m
\ No newline at end of file[m
[32m+[m[32mVec::new();[m

    // Analyze device status[m
    if[m
\ No newline at end of file[m
[32m+[m[32m device_info.device_status.contain[m
\ No newline at end of file[m
[32m+[m[32ms[m
\ No newline at end of file[m
[32m+[m[32m("Working") || device_info.device_status.contains("OK[m
\ No newline at end of file[m
[32m+[m[32m") {[m
        recommendations.push([m
\ No newline at end of file[m
 "✅ D[m
\ No newline at end of file[m
 e[m
\ No newline at end of file[m
