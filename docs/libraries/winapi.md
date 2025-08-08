# winapi Library Documentation

## Overview
`winapi` provides raw FFI bindings to Windows APIs. In our infiniservice project, it's primarily used for icon extraction from Windows executables and DLLs, as well as low-level system operations that aren't covered by higher-level libraries.

## Version
- **Current Version**: 0.3.9
- **Platform**: Windows only
- **Trust Level**: ✅ **TRUSTABLE** - Official Windows API bindings for Rust

## Key Features
- **Complete Windows API coverage**: Access to virtually all Windows APIs
- **Raw FFI bindings**: Direct access to Windows system calls
- **Icon extraction**: Extract icons from executables and DLLs
- **System information**: Low-level system and process information
- **Resource access**: Access to embedded resources in executables

## Use Cases in Infiniservice
1. **Icon Extraction**
   - Extract application icons from .exe and .dll files
   - Get different icon sizes and formats
   - Handle icon resources embedded in executables

2. **Advanced System Information**
   - Access detailed process information
   - Get system-specific data not available in higher-level libraries
   - Interact with Windows-specific features

3. **Resource Enumeration**
   - List embedded resources in executables
   - Extract version information and metadata
   - Access application manifests and other resources

## Basic Usage Examples

### Icon Extraction from Executables
```rust
use winapi::um::{
    shellapi::{ExtractIconW, ExtractAssociatedIconW},
    winuser::{LoadImageW, IMAGE_ICON, LR_DEFAULTSIZE},
    winnt::HANDLE,
};
use winapi::shared::windef::{HICON, HINSTANCE};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

struct IconExtractor;

impl IconExtractor {
    fn extract_icon_from_exe(exe_path: &str, icon_index: i32) -> Option<HICON> {
        let wide_path: Vec<u16> = OsStr::new(exe_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let hicon = ExtractIconW(
                ptr::null_mut() as HINSTANCE,
                wide_path.as_ptr(),
                icon_index as u32,
            );

            if hicon.is_null() {
                None
            } else {
                Some(hicon)
            }
        }
    }

    fn get_icon_count(exe_path: &str) -> u32 {
        let wide_path: Vec<u16> = OsStr::new(exe_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            ExtractIconW(
                ptr::null_mut() as HINSTANCE,
                wide_path.as_ptr(),
                0xFFFFFFFF, // Special value to get icon count
            ) as u32
        }
    }

    fn extract_all_icons(exe_path: &str) -> Vec<HICON> {
        let icon_count = Self::get_icon_count(exe_path);
        let mut icons = Vec::new();

        for i in 0..icon_count {
            if let Some(icon) = Self::extract_icon_from_exe(exe_path, i as i32) {
                icons.push(icon);
            }
        }

        icons
    }
}
```

### Advanced Icon Extraction with Size Control
```rust
use winapi::um::{
    shellapi::SHGetFileInfoW,
    winuser::{GetIconInfo, ICONINFO},
    wingdi::{GetObjectW, BITMAP},
};
use winapi::shared::{
    windef::{HICON, HBITMAP},
    minwindef::UINT,
};
use std::mem;

#[repr(C)]
struct SHFILEINFOW {
    hIcon: HICON,
    iIcon: i32,
    dwAttributes: u32,
    szDisplayName: [u16; 260],
    szTypeName: [u16; 80],
}

struct AdvancedIconExtractor;

impl AdvancedIconExtractor {
    fn get_file_icon(file_path: &str, large_icon: bool) -> Option<HICON> {
        let wide_path: Vec<u16> = OsStr::new(file_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut shfi: SHFILEINFOW = unsafe { mem::zeroed() };
        
        let flags = if large_icon {
            0x000000100 // SHGFI_ICON
        } else {
            0x000000100 | 0x000000001 // SHGFI_ICON | SHGFI_SMALLICON
        };

        unsafe {
            let result = SHGetFileInfoW(
                wide_path.as_ptr(),
                0,
                &mut shfi as *mut SHFILEINFOW as *mut _,
                mem::size_of::<SHFILEINFOW>() as UINT,
                flags,
            );

            if result != 0 && !shfi.hIcon.is_null() {
                Some(shfi.hIcon)
            } else {
                None
            }
        }
    }

    fn get_icon_dimensions(hicon: HICON) -> Option<(i32, i32)> {
        unsafe {
            let mut icon_info: ICONINFO = mem::zeroed();
            if GetIconInfo(hicon, &mut icon_info) != 0 {
                let mut bitmap: BITMAP = mem::zeroed();
                if GetObjectW(
                    icon_info.hbmColor as *mut _,
                    mem::size_of::<BITMAP>() as i32,
                    &mut bitmap as *mut _ as *mut _,
                ) != 0 {
                    return Some((bitmap.bmWidth, bitmap.bmHeight));
                }
            }
            None
        }
    }
}
```

### Application Information Extraction
```rust
use winapi::um::{
    winver::{GetFileVersionInfoW, GetFileVersionInfoSizeW, VerQueryValueW},
    winnt::LANG_NEUTRAL,
};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

struct ApplicationInfoExtractor;

impl ApplicationInfoExtractor {
    fn get_file_version(file_path: &str) -> Option<String> {
        let wide_path: Vec<u16> = OsStr::new(file_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            // Get version info size
            let size = GetFileVersionInfoSizeW(wide_path.as_ptr(), ptr::null_mut());
            if size == 0 {
                return None;
            }

            // Allocate buffer and get version info
            let mut buffer = vec![0u8; size as usize];
            if GetFileVersionInfoW(
                wide_path.as_ptr(),
                0,
                size,
                buffer.as_mut_ptr() as *mut _,
            ) == 0 {
                return None;
            }

            // Query for file description
            let sub_block = OsStr::new("\\StringFileInfo\\040904B0\\FileDescription")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>();

            let mut value_ptr: *mut u16 = ptr::null_mut();
            let mut value_len: u32 = 0;

            if VerQueryValueW(
                buffer.as_ptr() as *const _,
                sub_block.as_ptr(),
                &mut value_ptr as *mut _ as *mut *mut _,
                &mut value_len,
            ) != 0 && !value_ptr.is_null() {
                let description = std::slice::from_raw_parts(value_ptr, value_len as usize - 1);
                return Some(String::from_utf16_lossy(description));
            }

            None
        }
    }

    fn get_application_info(exe_path: &str) -> ApplicationInfo {
        ApplicationInfo {
            path: exe_path.to_string(),
            description: Self::get_file_version(exe_path),
            icon_count: IconExtractor::get_icon_count(exe_path),
        }
    }
}

struct ApplicationInfo {
    path: String,
    description: Option<String>,
    icon_count: u32,
}
```

### Process and Window Information
```rust
use winapi::um::{
    processthreadsapi::{GetCurrentProcessId, OpenProcess},
    psapi::{GetModuleFileNameExW, GetProcessImageFileNameW},
    winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    handleapi::CloseHandle,
};
use winapi::shared::minwindef::DWORD;

struct ProcessInfoExtractor;

impl ProcessInfoExtractor {
    fn get_process_executable_path(process_id: DWORD) -> Option<String> {
        unsafe {
            let process_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                0,
                process_id,
            );

            if process_handle.is_null() {
                return None;
            }

            let mut buffer = [0u16; 260];
            let result = GetModuleFileNameExW(
                process_handle,
                ptr::null_mut(),
                buffer.as_mut_ptr(),
                buffer.len() as DWORD,
            );

            CloseHandle(process_handle);

            if result > 0 {
                let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                Some(String::from_utf16_lossy(&buffer[..end]))
            } else {
                None
            }
        }
    }

    fn get_current_process_path() -> Option<String> {
        unsafe {
            let current_pid = GetCurrentProcessId();
            Self::get_process_executable_path(current_pid)
        }
    }
}
```

## Integration Strategy
1. **Icon Caching**: Extract and cache application icons for UI display
2. **Metadata Collection**: Gather application information for analysis
3. **Resource Enumeration**: Catalog embedded resources in applications
4. **System Integration**: Use for Windows-specific functionality

## Safety Considerations
- **Unsafe Code**: All winapi calls are unsafe and require careful handling
- **Memory Management**: Properly manage Windows handles and resources
- **Error Handling**: Check return values and handle Windows errors
- **Resource Cleanup**: Always clean up allocated resources

## Performance Considerations
- **Batch Operations**: Process multiple files efficiently
- **Caching**: Cache extracted icons and metadata
- **Resource Limits**: Be mindful of handle limits and memory usage

## Error Handling Patterns
```rust
use winapi::um::errhandlingapi::GetLastError;

fn handle_windows_error(operation: &str) {
    unsafe {
        let error_code = GetLastError();
        eprintln!("Windows API error in {}: {}", operation, error_code);
    }
}
```

## Documentation Links
- [Official Documentation](https://docs.rs/winapi/)
- [GitHub Repository](https://github.com/retep998/winapi-rs)
- [Crates.io Page](https://crates.io/crates/winapi)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
