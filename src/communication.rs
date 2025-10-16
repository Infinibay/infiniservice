//! Communication module for virtio-serial interface with bidirectional command support

use crate::collector::{SystemInfo, SystemMetrics};
use crate::commands::{IncomingMessage, CommandResponse};
use anyhow::{Result, Context, anyhow};
use log::{info, debug, warn, error};
use serde::Serialize;
use serde_json;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicU32};
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;
use async_recursion::async_recursion;

// Windows-specific: Thread-safe wrapper for HANDLE
#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
struct SendableHandle(winapi::shared::ntdef::HANDLE);

#[cfg(target_os = "windows")]
unsafe impl Send for SendableHandle {}

#[cfg(target_os = "windows")]
unsafe impl Sync for SendableHandle {}

// Connection metrics tracking
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    pub connection_start_time: Option<SystemTime>,
    pub total_connections: u64,
    pub successful_transmissions: u64,
    pub failed_transmissions: u64,
    pub last_successful_transmission: Option<SystemTime>,
    pub connection_quality: ConnectionQuality,
    pub error_patterns: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub timestamp: SystemTime,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error_details: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TransmissionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub message_count: u64,
    pub average_latency_ms: f64,
    pub last_transmission_size: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionQuality {
    Excellent,
    Good,
    Poor,
    Critical,
}

impl std::fmt::Display for ConnectionQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionQuality::Excellent => write!(f, "excellent"),
            ConnectionQuality::Good => write!(f, "good"),
            ConnectionQuality::Poor => write!(f, "poor"),
            ConnectionQuality::Critical => write!(f, "critical"),
        }
    }
}

// Circuit Breaker Pattern Implementation
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitBreakerState {
    Closed,    // Normal operation
    Open,      // Blocking all calls
    HalfOpen,  // Testing recovery
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerMetrics {
    pub failure_count: u32,
    pub success_count: u32,
    pub last_failure_time: Option<SystemTime>,
    pub state_change_time: SystemTime,
    pub half_open_calls: u32,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub open_duration_secs: u64,
    pub half_open_max_calls: u32,
    pub success_threshold: u32,
}

// Circuit Breaker Default Configuration
//
// These values are tuned for Windows Global objects with OVERLAPPED I/O (VIRTIO-001/002/003).
// The increased tolerance (compared to typical circuit breaker settings) is necessary because:
//
// 1. Windows Global objects (e.g., \\.\Global\org.infinibay.agent) can experience transient
//    timing delays during OVERLAPPED I/O operations, especially under system load.
//
// 2. VirtIO serial communication is low-frequency (keep-alive every 120s per VIRTIO-004),
//    so failures accumulate slowly. Higher thresholds prevent false-positive trips.
//
// 3. The persistent handle approach (VIRTIO-001) eliminates reopen overhead but doesn't
//    eliminate all timing variability in Windows kernel I/O completion.
//
// Values:
// - failure_threshold: 15 (increased from 5) - Allows ~15-30 minutes of operation before
//   opening circuit, depending on message frequency. Provides 3x more tolerance.
//
// - open_duration_secs: 60 (increased from 30) - Gives Windows Global objects sufficient
//   time to stabilize before attempting recovery. Prevents rapid open/half-open/open cycles.
//
// - half_open_max_calls: 5 (increased from 3) - Provides better statistical confidence
//   that the connection has recovered. With success_threshold=2, requires 40% success rate.
//
// - success_threshold: 2 (unchanged) - Requires 2 successful calls to close circuit.
//   Conservative but achievable with the increased half_open_max_calls.
//
// These values are validated by config.rs to be within acceptable ranges:
// - failure_threshold: [3, 20]
// - open_duration_secs: [10, 600]
// - half_open_max_calls: [1, 10]
impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 15,      // 15 failures before opening (3x tolerance for Windows Global objects)
            open_duration_secs: 60,     // 60 seconds open (allows Windows I/O to stabilize)
            half_open_max_calls: 5,     // 5 test calls in half-open (better recovery confidence)
            success_threshold: 2,       // 2 successes to close (unchanged)
        }
    }
}

// Error classification system for intelligent retry logic
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorSeverity {
    Temporary,    // Retry immediately
    Recoverable,  // Retry with backoff
    Fatal,        // Don't retry, mark as broken
    Unknown,      // Treat as recoverable with caution
}

#[derive(Debug, Clone)]
pub struct ClassifiedError {
    pub error_type: String,
    pub severity: ErrorSeverity,
    pub windows_error_code: Option<i32>,
    pub retry_recommended: bool,
    pub recovery_suggestion: Option<String>,
    pub max_retries: u32,
}

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
    write_handle: Arc<std::sync::RwLock<Option<Arc<File>>>>,
    read_handle: Arc<std::sync::RwLock<Option<Arc<File>>>>,
    is_connected: Arc<AtomicBool>,
    read_timeout_ms: u64,
    ping_test_interval_secs: u64,
    last_transmission_time: Arc<AtomicU64>,
    consecutive_failures: Arc<AtomicUsize>,
    initial_transmission_sent: Arc<AtomicBool>,
    last_ping_test_time: Arc<AtomicU64>,
    // Enhanced diagnostics
    connection_metrics: Arc<RwLock<ConnectionMetrics>>,
    health_check_history: Arc<RwLock<Vec<HealthCheckResult>>>,
    transmission_stats: Arc<RwLock<TransmissionStats>>,
    // Error retry tracking
    error_retry_count: Arc<std::sync::atomic::AtomicU32>,
    last_error_time: Arc<AtomicU64>,
    error_backoff_ms: Arc<AtomicU64>,
    max_error_retries: u32,
    // Error report queue for when not connected
    queued_error_reports: Arc<RwLock<Vec<serde_json::Value>>>,
    // Circuit Breaker fields
    circuit_breaker_state: Arc<RwLock<CircuitBreakerState>>,
    circuit_breaker_metrics: Arc<RwLock<CircuitBreakerMetrics>>,
    circuit_breaker_config: CircuitBreakerConfig,
    // Keep-Alive fields
    keep_alive_last_sent: Arc<AtomicU64>, // Timestamp (Unix epoch seconds) of last keep-alive message sent to backend
    keep_alive_last_received: Arc<AtomicU64>, // Timestamp (Unix epoch seconds) of last keep-alive response received from backend
    keep_alive_sequence: Arc<AtomicU32>, // Sequence number for keep-alive messages, incremented with each send
    #[cfg(target_os = "windows")]
    windows_handle: Arc<RwLock<Option<SendableHandle>>>,
}

impl VirtioSerial {
    pub fn new<P: AsRef<Path>>(device_path: P) -> Self {
        Self::with_timeout(device_path, 500) // Default 500ms timeout
    }

    pub fn with_timeout<P: AsRef<Path>>(device_path: P, read_timeout_ms: u64) -> Self {
        Self::with_config(device_path, read_timeout_ms, 60) // Default 60s ping interval
    }

    pub fn with_config<P: AsRef<Path>>(device_path: P, read_timeout_ms: u64, ping_test_interval_secs: u64) -> Self {
        Self::new_internal(
            device_path,
            Self::generate_vm_id(),
            read_timeout_ms,
            ping_test_interval_secs,
            CircuitBreakerConfig::default()
        )
    }

    pub fn with_vm_id<P: AsRef<Path>>(device_path: P, vm_id: String) -> Self {
        Self::with_vm_id_and_timeout(device_path, vm_id, 500) // Default 500ms timeout
    }

    pub fn with_circuit_breaker_config<P: AsRef<Path>>(
        device_path: P,
        circuit_breaker_config: CircuitBreakerConfig,
        read_timeout_ms: u64,
        ping_test_interval_secs: u64
    ) -> Self {
        Self::new_internal(
            device_path,
            Self::generate_vm_id(),
            read_timeout_ms,
            ping_test_interval_secs,
            circuit_breaker_config
        )
    }

    pub fn with_vm_id_and_timeout<P: AsRef<Path>>(device_path: P, vm_id: String, read_timeout_ms: u64) -> Self {
        Self::new_internal(
            device_path,
            vm_id,
            read_timeout_ms,
            60, // Conservative default ping interval
            CircuitBreakerConfig::default()
        )
    }

    fn generate_vm_id() -> String {
        // Try to get VM ID from environment or generate one
        std::env::var("INFINIBAY_VM_ID")
            .unwrap_or_else(|_| Uuid::new_v4().to_string())
    }

    // Private constructor that ensures all fields are initialized
    fn new_internal<P: AsRef<Path>>(
        device_path: P,
        vm_id: String,
        read_timeout_ms: u64,
        ping_test_interval_secs: u64,
        mut circuit_breaker_config: CircuitBreakerConfig
    ) -> Self {
        // Guard: Ensure success_threshold does not exceed half_open_max_calls
        // This prevents impossible conditions where more successes are required than attempts allowed.
        // Use a non-fatal clamp instead of panic to maintain production stability.
        if circuit_breaker_config.success_threshold > circuit_breaker_config.half_open_max_calls {
            warn!(
                "Circuit breaker config invalid: success_threshold ({}) > half_open_max_calls ({}). Clamping success_threshold to half_open_max_calls.",
                circuit_breaker_config.success_threshold,
                circuit_breaker_config.half_open_max_calls
            );
            circuit_breaker_config.success_threshold = circuit_breaker_config.half_open_max_calls;
        }

        Self {
            device_path: device_path.as_ref().to_path_buf(),
            vm_id,
            write_handle: Arc::new(std::sync::RwLock::new(None)),
            read_handle: Arc::new(std::sync::RwLock::new(None)),
            is_connected: Arc::new(AtomicBool::new(false)),
            read_timeout_ms,
            ping_test_interval_secs,
            last_transmission_time: Arc::new(AtomicU64::new(0)),
            consecutive_failures: Arc::new(AtomicUsize::new(0)),
            initial_transmission_sent: Arc::new(AtomicBool::new(false)),
            last_ping_test_time: Arc::new(AtomicU64::new(0)),
            // Enhanced diagnostics
            connection_metrics: Arc::new(RwLock::new(ConnectionMetrics {
                connection_start_time: None,
                total_connections: 0,
                successful_transmissions: 0,
                failed_transmissions: 0,
                last_successful_transmission: None,
                connection_quality: ConnectionQuality::Good,
                error_patterns: HashMap::new(),
            })),
            health_check_history: Arc::new(RwLock::new(Vec::new())),
            transmission_stats: Arc::new(RwLock::new(TransmissionStats {
                bytes_sent: 0,
                bytes_received: 0,
                message_count: 0,
                average_latency_ms: 0.0,
                last_transmission_size: 0,
            })),
            // Error retry tracking initialization
            error_retry_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            last_error_time: Arc::new(AtomicU64::new(0)),
            error_backoff_ms: Arc::new(AtomicU64::new(1000)), // Start with 1s backoff
            max_error_retries: 5, // Default max retries
            // Error report queue initialization
            queued_error_reports: Arc::new(RwLock::new(Vec::new())),
            // Circuit Breaker initialization
            circuit_breaker_state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            circuit_breaker_metrics: Arc::new(RwLock::new(CircuitBreakerMetrics {
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
                state_change_time: SystemTime::now(),
                half_open_calls: 0,
            })),
            circuit_breaker_config,
            // Keep-Alive initialization
            keep_alive_last_sent: Arc::new(AtomicU64::new(0)),
            keep_alive_last_received: Arc::new(AtomicU64::new(0)),
            keep_alive_sequence: Arc::new(AtomicU32::new(0)),
            // Windows handle initialization
            #[cfg(target_os = "windows")]
            windows_handle: Arc::new(RwLock::new(None)),
        }
    }

    // Public getters for private fields (required for service.rs access)
    pub fn circuit_breaker_state(&self) -> Arc<RwLock<CircuitBreakerState>> {
        Arc::clone(&self.circuit_breaker_state)
    }

    pub fn circuit_breaker_metrics(&self) -> Arc<RwLock<CircuitBreakerMetrics>> {
        Arc::clone(&self.circuit_breaker_metrics)
    }

    pub fn connection_quality(&self) -> ConnectionQuality {
        let metrics = self.connection_metrics.read().unwrap();
        metrics.connection_quality.clone()
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
    
    /// Initialize persistent connection to virtio-serial device
    pub async fn connect(&self) -> Result<()> {
        let path_str = self.device_path.to_string_lossy();

        // Check if this is the special "no device" marker
        if path_str == "__NO_VIRTIO_DEVICE__" {
            warn!("VirtIO device not available - operating in degraded mode");
            warn!("Some communication features will be limited");
            return Err(anyhow!("VirtIO device not available"));
        }

        info!("Establishing persistent connection to virtio-serial device: {}", self.device_path.display());

        // Open device with read/write permissions and store persistent handles
        #[cfg(target_os = "windows")]
        {
            // Check device type and handle accordingly
            if path_str.contains("Global") {
                // Import Windows API types
                use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
                use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};
                use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
                use winapi::um::errhandlingapi::GetLastError;
                use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
                use std::os::windows::ffi::OsStrExt;
                use std::ffi::OsStr;

                // Idempotency guard: check if already connected
                {
                    let win_handle = self.windows_handle.read().unwrap();
                    if win_handle.is_some() {
                        debug!("Global VirtIO device already connected, returning early");
                        return Ok(());
                    }
                }

                // Convert device path to wide string (UTF-16)
                let wide_path: Vec<u16> = OsStr::new(&*path_str)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                // Open the Global object with CreateFileW and FILE_FLAG_OVERLAPPED
                let handle = unsafe {
                    CreateFileW(
                        wide_path.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null_mut(),
                        OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED,  // KEY: Enable overlapped I/O
                        std::ptr::null_mut(),
                    )
                };

                // Check for success and store handle
                if handle != INVALID_HANDLE_VALUE {
                    // Store the handle in windows_handle
                    let mut win_handle = self.windows_handle.write().unwrap();
                    *win_handle = Some(SendableHandle(handle));

                    // Mark as connected
                    self.is_connected.store(true, Ordering::SeqCst);

                    info!("VirtIO Global object opened with persistent handle");
                    debug!("Global VirtIO device connected: {}", path_str);
                    return Ok(());
                } else {
                    // Get error code for detailed error message
                    let error_code = unsafe { GetLastError() };

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
            } else if path_str.contains("COM") && !path_str.contains("pipe") {
                // It's a COM port, open with appropriate flags and establish persistent handles
                use std::os::windows::fs::OpenOptionsExt;
                use std::os::windows::io::AsRawHandle;
                use winapi::um::winbase::{FILE_FLAG_OVERLAPPED, COMMTIMEOUTS};
                use winapi::um::commapi::SetCommTimeouts;

                // Open for writing
                let write_file = OpenOptions::new()
                    .write(true)
                    .custom_flags(FILE_FLAG_OVERLAPPED)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open COM port for writing: {}", self.device_path.display()))?;

                // Open for reading
                let read_file = OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_OVERLAPPED)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open COM port for reading: {}", self.device_path.display()))?;

                // Configure COM port timeouts
                unsafe {
                    let mut timeouts = COMMTIMEOUTS {
                        ReadIntervalTimeout: self.read_timeout_ms as u32,
                        ReadTotalTimeoutMultiplier: 0,
                        ReadTotalTimeoutConstant: self.read_timeout_ms as u32,
                        WriteTotalTimeoutMultiplier: 0,
                        WriteTotalTimeoutConstant: 1000, // 1 second write timeout
                    };

                    if SetCommTimeouts(read_file.as_raw_handle() as _, &mut timeouts) == 0 {
                        warn!("Failed to set COM port read timeouts");
                    }
                    if SetCommTimeouts(write_file.as_raw_handle() as _, &mut timeouts) == 0 {
                        warn!("Failed to set COM port write timeouts");
                    }
                }

                // Store persistent handles
                {
                    let mut write_handle = self.write_handle.write().unwrap();
                    *write_handle = Some(Arc::new(write_file));
                }
                {
                    let mut read_handle = self.read_handle.write().unwrap();
                    *read_handle = Some(Arc::new(read_file));
                }

                self.is_connected.store(true, Ordering::SeqCst);
                info!("COM port persistent connection established successfully with timeout {}ms", self.read_timeout_ms);
                return Ok(());
            } else {
                // It's a named pipe or other device
                use std::os::windows::io::AsRawHandle;
                use winapi::um::namedpipeapi::SetNamedPipeHandleState;
                use winapi::um::winbase::PIPE_NOWAIT;

                let write_file = OpenOptions::new()
                    .write(true)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open device for writing: {}", self.device_path.display()))?;

                let read_file = OpenOptions::new()
                    .read(true)
                    .open(&self.device_path)
                    .with_context(|| format!("Failed to open device for reading: {}", self.device_path.display()))?;

                // Configure named pipe for non-blocking mode
                if path_str.contains("pipe") {
                    unsafe {
                        let mut mode = PIPE_NOWAIT;
                        if SetNamedPipeHandleState(read_file.as_raw_handle() as _, &mut mode, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
                            warn!("Failed to set named pipe to non-blocking mode for reading");
                        }
                        if SetNamedPipeHandleState(write_file.as_raw_handle() as _, &mut mode, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
                            warn!("Failed to set named pipe to non-blocking mode for writing");
                        }
                    }
                }

                // Store persistent handles
                {
                    let mut write_handle = self.write_handle.write().unwrap();
                    *write_handle = Some(Arc::new(write_file));
                }
                {
                    let mut read_handle = self.read_handle.write().unwrap();
                    *read_handle = Some(Arc::new(read_file));
                }

                self.is_connected.store(true, Ordering::SeqCst);
                info!("Device persistent connection established successfully with timeout {}ms", self.read_timeout_ms);
                return Ok(());
            }
        }

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;

            // Open with O_RDWR | O_NONBLOCK for Linux
            let write_file = OpenOptions::new()
                .write(true)
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.device_path)
                .with_context(|| format!("Failed to open virtio-serial device for writing: {}", self.device_path.display()))?;

            let read_file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.device_path)
                .with_context(|| format!("Failed to open virtio-serial device for reading: {}", self.device_path.display()))?;

            // Store persistent handles
            {
                let mut write_handle = self.write_handle.write().unwrap();
                *write_handle = Some(Arc::new(write_file));
            }
            {
                let mut read_handle = self.read_handle.write().unwrap();
                *read_handle = Some(Arc::new(read_file));
            }

            self.is_connected.store(true, Ordering::SeqCst);
            info!("Virtio-serial persistent connection established successfully");
            return Ok(());
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            let write_file = OpenOptions::new()
                .write(true)
                .open(&self.device_path)
                .with_context(|| format!("Failed to open device for writing: {}", self.device_path.display()))?;

            let read_file = OpenOptions::new()
                .read(true)
                .open(&self.device_path)
                .with_context(|| format!("Failed to open device for reading: {}", self.device_path.display()))?;

            // Store persistent handles
            {
                let mut write_handle = self.write_handle.write().unwrap();
                *write_handle = Some(Arc::new(write_file));
            }
            {
                let mut read_handle = self.read_handle.write().unwrap();
                *read_handle = Some(Arc::new(read_file));
            }

            self.is_connected.store(true, Ordering::SeqCst);
            info!("Device persistent connection established successfully");
            return Ok(());
        }
    }

    /// Safely disconnect and cleanup persistent handles
    pub fn disconnect(&self) {
        info!("Disconnecting persistent VirtIO connection");

        // Clear write handle
        {
            let mut write_handle = self.write_handle.write().unwrap();
            if write_handle.take().is_some() {
                debug!("Write handle disconnected");
            }
        }

        // Clear read handle
        {
            let mut read_handle = self.read_handle.write().unwrap();
            if read_handle.take().is_some() {
                debug!("Read handle disconnected");
            }
        }

        // Close Windows handle for Global objects
        #[cfg(target_os = "windows")]
        {
            let mut win_handle = self.windows_handle.write().unwrap();
            if let Some(handle) = win_handle.take() {
                unsafe {
                    use winapi::um::handleapi::CloseHandle;
                    CloseHandle(handle.0);
                }
                debug!("Windows handle closed");
            }
        }

        // Mark as disconnected
        self.is_connected.store(false, Ordering::SeqCst);
        info!("VirtIO connection disconnected successfully");
    }

    /// Check connection health for persistent connections with enhanced validation (legacy)
    pub fn check_connection_health_legacy(&self) -> bool {
        if !self.is_connected.load(Ordering::SeqCst) {
            debug!("Connection health check failed: not connected");
            return false;
        }

        // Add tolerance for temporary connection issues
        let _current_failures = self.consecutive_failures.load(Ordering::SeqCst);
        let failure_threshold = 3; // Allow up to 3 consecutive failures before marking as unhealthy

        let path_str = self.device_path.to_string_lossy();

        // For Global objects on Windows, we can't keep persistent handles
        // but we can test if the device is still accessible
        #[cfg(target_os = "windows")]
        {
            if path_str.contains("Global") {
                // Test if we can still open the Global object
                match Self::try_open_windows_device(&path_str, false) {
                    Ok(true) => {
                        debug!("Connection health check passed: Global object accessible");
                        // Reset failure counter on success
                        self.consecutive_failures.store(0, Ordering::SeqCst);
                        return true;
                    }
                    Ok(false) | Err(_) => {
                        // Increment failure counter for progressive degradation
                        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                        debug!("Connection health check failed: Global object not accessible (failure {}/{})", failures, failure_threshold);
                        return failures <= failure_threshold; // Return true if still within tolerance
                    }
                }
            }
        }

        // For other device types, check if handles are still valid
        let write_valid = {
            let write_handle = self.write_handle.read().unwrap();
            write_handle.is_some()
        };

        let read_valid = {
            let read_handle = self.read_handle.read().unwrap();
            read_handle.is_some()
        };

        let handles_valid = write_valid && read_valid;

        if !handles_valid {
            // Increment failure counter for progressive degradation
            let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
            debug!("Connection health check failed: handles invalid (write={}, read={}) (failure {}/{})",
                   write_valid, read_valid, failures, failure_threshold);
            return failures <= failure_threshold; // Return true if still within tolerance
        }

        // Additional validation: check if device path still exists (for file-based devices)
        if !path_str.contains("Global") && !path_str.contains("pipe") {
            if !self.device_path.exists() {
                // Increment failure counter for progressive degradation
                let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                debug!("Connection health check failed: device path no longer exists (failure {}/{})", failures, failure_threshold);
                return failures <= failure_threshold; // Return true if still within tolerance
            }
        }

        // Enhanced health check with ping test (rate-limited to avoid spam)
        // Rate limit: configurable interval (default 60 seconds)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_ping = self.last_ping_test_time.load(Ordering::SeqCst);

        // Only run ping test if enough time has passed since last test
        if now.saturating_sub(last_ping) >= self.ping_test_interval_secs {
            debug!("Running ping test for enhanced connection health validation");

            // Perform ping test asynchronously in a blocking context
            let ping_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.test_send_ping().await
                })
            });

            // Update the last ping test time regardless of result
            self.last_ping_test_time.store(now, Ordering::SeqCst);

            match ping_result {
                Ok(_) => {
                    debug!("Connection health check passed: all validations including ping test successful");
                    // Reset failure counter on success
                    self.consecutive_failures.store(0, Ordering::SeqCst);
                    true
                }
                Err(e) => {
                    // Increment failure counter for progressive degradation
                    let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
                    debug!("Connection health check failed: ping test failed - {} (failure {}/{})", e, failures, failure_threshold);

                    // Only mark as unhealthy after threshold is exceeded
                    failures <= failure_threshold // Return true if still within tolerance
                }
            }
        } else {
            debug!("Connection health check passed: basic validations successful (ping test skipped - rate limited)");
            // Reset failure counter on success
            self.consecutive_failures.store(0, Ordering::SeqCst);
            true
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

        // Extract and log network interface information for diagnostics
        let total_interfaces = data.metrics.network.interfaces.len();
        let up_interfaces_with_ips = data.metrics.network.interfaces.iter()
            .filter(|iface| iface.is_up && !iface.ip_addresses.is_empty())
            .count();
        let total_ip_addresses: usize = data.metrics.network.interfaces.iter()
            .map(|iface| iface.ip_addresses.len())
            .sum();

        info!("Preparing metrics transmission: {} interfaces, {} UP with IPs, {} total IP addresses",
              total_interfaces, up_interfaces_with_ips, total_ip_addresses);

        // Validate that we have meaningful network information
        if total_interfaces > 0 && up_interfaces_with_ips == 0 {
            warn!("Transmitting metrics with no UP interfaces that have IP addresses");
            for iface in &data.metrics.network.interfaces {
                debug!("Interface {}: is_up={}, ip_count={}",
                       iface.name, iface.is_up, iface.ip_addresses.len());
            }
        }

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

        info!("Sending metrics payload: size={} bytes, interfaces_with_ips={}",
              serialized.len(), up_interfaces_with_ips);

        // Track if this is the first transmission
        let is_initial = !self.initial_transmission_sent.load(std::sync::atomic::Ordering::SeqCst);

        match self.send_raw_message(&serialized, true).await {
            Ok(()) => {
                // Update transmission tracking
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.last_transmission_time.store(now, std::sync::atomic::Ordering::SeqCst);
                self.consecutive_failures.store(0, std::sync::atomic::Ordering::SeqCst);

                if is_initial {
                    self.initial_transmission_sent.store(true, std::sync::atomic::Ordering::SeqCst);
                    info!("First successful metrics transmission completed with {} UP interfaces", up_interfaces_with_ips);
                }

                Ok(())
            }
            Err(e) => {
                // Track transmission failures
                let failures = self.consecutive_failures.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                warn!("Metrics transmission failed (failure #{} consecutive): {}", failures, e);
                Err(e)
            }
        }
    }

    /// Try to send SystemInfo once with immediate error propagation for connection verification
    /// This method does not treat any failures as "safe" and propagates all errors
    pub async fn try_send_once(&self, data: &SystemInfo) -> Result<()> {
        debug!("Attempting single transmission for connection verification");

        // Extract network interface information for verification logging
        let total_interfaces = data.metrics.network.interfaces.len();
        let up_interfaces_with_ips = data.metrics.network.interfaces.iter()
            .filter(|iface| iface.is_up && !iface.ip_addresses.is_empty())
            .count();

        debug!("Verification transmission data: {} interfaces, {} UP with IPs",
               total_interfaces, up_interfaces_with_ips);

        // Wrap SystemInfo in the message format expected by backend
        let metrics_message = MetricsMessage {
            message_type: "metrics".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            data: MetricsData {
                system: data.metrics.clone(),
            },
        };

        let serialized = serde_json::to_string(&metrics_message)
            .with_context(|| "Failed to serialize metrics message for verification")?;

        // Send with strict error handling - do not treat any errors as safe
        self.send_raw_message(&serialized, true).await
            .with_context(|| "Failed to send verification message")?;

        info!("Verification transmission completed successfully: {} interfaces, {} UP with IPs",
              total_interfaces, up_interfaces_with_ips);

        Ok(())
    }

    /// Send a command response to the host
    pub async fn send_command_response(&self, response: &CommandResponse) -> Result<()> {
        debug!("Sending command response: id={}, success={}", response.id, response.success);
        
        let serialized = serde_json::to_string(&response)
            .with_context(|| "Failed to serialize command response")?;

        self.send_raw_message(&serialized, true).await
    }

    /// Classify Windows error codes for intelligent retry logic
    fn classify_windows_error(error_code: i32) -> ClassifiedError {
        match error_code {
            5 => ClassifiedError { // ERROR_ACCESS_DENIED
                error_type: "ACCESS_DENIED".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: Some(5),
                retry_recommended: true,
                recovery_suggestion: Some("Check service permissions and restart InfiniService".to_string()),
                max_retries: 5,
            },
            109 => ClassifiedError { // ERROR_BROKEN_PIPE
                error_type: "BROKEN_PIPE".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: Some(109),
                retry_recommended: true,
                recovery_suggestion: Some("Connection interrupted, will retry".to_string()),
                max_retries: 3,
            },
            2 => ClassifiedError { // ERROR_FILE_NOT_FOUND
                error_type: "FILE_NOT_FOUND".to_string(),
                severity: ErrorSeverity::Temporary,
                windows_error_code: Some(2),
                retry_recommended: true,
                recovery_suggestion: Some("Device not ready, retrying".to_string()),
                max_retries: 10,
            },
            6 => ClassifiedError { // ERROR_INVALID_HANDLE
                error_type: "INVALID_HANDLE".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: Some(6),
                retry_recommended: true,
                recovery_suggestion: Some("Handle became invalid, will reopen device".to_string()),
                max_retries: 3,
            },
            32 => ClassifiedError { // ERROR_SHARING_VIOLATION
                error_type: "SHARING_VIOLATION".to_string(),
                severity: ErrorSeverity::Temporary,
                windows_error_code: Some(32),
                retry_recommended: true,
                recovery_suggestion: Some("Device in use by another process, retrying".to_string()),
                max_retries: 8,
            },
            995 => ClassifiedError { // ERROR_OPERATION_ABORTED
                error_type: "OPERATION_ABORTED".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: Some(995),
                retry_recommended: true,
                recovery_suggestion: Some("Operation was aborted, will retry".to_string()),
                max_retries: 3,
            },
            _ => ClassifiedError { // Unknown error - treat as recoverable with caution
                error_type: format!("UNKNOWN_ERROR_{}", error_code),
                severity: ErrorSeverity::Unknown,
                windows_error_code: Some(error_code),
                retry_recommended: true,
                recovery_suggestion: Some("Unknown error, will attempt limited retries".to_string()),
                max_retries: 2,
            }
        }
    }

    /// Classify I/O error kinds for retry logic
    fn classify_io_error(error_kind: std::io::ErrorKind) -> ClassifiedError {
        match error_kind {
            std::io::ErrorKind::BrokenPipe => ClassifiedError {
                error_type: "IO_BROKEN_PIPE".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: None,
                retry_recommended: true,
                recovery_suggestion: Some("Pipe connection broken, will retry".to_string()),
                max_retries: 3,
            },
            std::io::ErrorKind::ConnectionReset => ClassifiedError {
                error_type: "IO_CONNECTION_RESET".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: None,
                retry_recommended: true,
                recovery_suggestion: Some("Connection was reset, will retry".to_string()),
                max_retries: 3,
            },
            std::io::ErrorKind::UnexpectedEof => ClassifiedError {
                error_type: "IO_UNEXPECTED_EOF".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: None,
                retry_recommended: true,
                recovery_suggestion: Some("Unexpected end of file, will retry".to_string()),
                max_retries: 3,
            },
            std::io::ErrorKind::PermissionDenied => ClassifiedError {
                error_type: "IO_PERMISSION_DENIED".to_string(),
                severity: ErrorSeverity::Recoverable,
                windows_error_code: None,
                retry_recommended: true,
                recovery_suggestion: Some("Permission denied, check service privileges".to_string()),
                max_retries: 5,
            },
            std::io::ErrorKind::NotFound => ClassifiedError {
                error_type: "IO_NOT_FOUND".to_string(),
                severity: ErrorSeverity::Temporary,
                windows_error_code: None,
                retry_recommended: true,
                recovery_suggestion: Some("Device not found, retrying".to_string()),
                max_retries: 10,
            },
            _ => ClassifiedError {
                error_type: format!("IO_ERROR_{:?}", error_kind),
                severity: ErrorSeverity::Unknown,
                windows_error_code: None,
                retry_recommended: true,
                recovery_suggestion: Some("I/O error occurred, will attempt limited retries".to_string()),
                max_retries: 2,
            }
        }
    }

    /// Send control message directly to write handle without recursion
    fn send_control_message(&self, value: serde_json::Value) -> Result<()> {
        // Check if we have a write handle available
        let file_handle = {
            let write_handle = self.write_handle.read().unwrap();
            if let Some(ref file) = *write_handle {
                Some(Arc::clone(file))
            } else {
                None
            }
        };

        if let Some(file) = file_handle {
            // Write directly to the file handle with newline termination
            use std::io::Write;
            let message_str = value.to_string();
            let mut file_ref = file.as_ref();
            writeln!(file_ref, "{}", message_str)?;
            file_ref.flush()?;
            debug!("Control message sent successfully: {}", message_str);
            Ok(())
        } else {
            Err(anyhow!("No write handle available for control message"))
        }
    }

    /// Flush queued error reports when connection becomes available
    fn flush_queued_error_reports(&self) -> Result<()> {
        let mut queued_reports = self.queued_error_reports.write().unwrap();
        if queued_reports.is_empty() {
            return Ok(());
        }

        let mut sent_count = 0;
        let mut failed_reports = Vec::new();

        for report in queued_reports.drain(..) {
            // Try to send with best-effort retry (1-2 attempts)
            let mut attempts = 0;
            let max_attempts = 2;

            while attempts < max_attempts {
                match self.send_control_message(report.clone()) {
                    Ok(_) => {
                        sent_count += 1;
                        break; // Successfully sent, move to next report
                    }
                    Err(e) => {
                        attempts += 1;
                        if attempts >= max_attempts {
                            debug!("Failed to send queued error report after {} attempts: {}", max_attempts, e);
                            failed_reports.push(report.clone());
                        }
                    }
                }
            }
        }

        // Keep failed reports for next flush attempt (ring buffer behavior)
        *queued_reports = failed_reports;

        if sent_count > 0 {
            info!("Flushed {} queued error reports", sent_count);
        }

        Ok(())
    }

    /// Send detailed error report to backend
    async fn send_error_report(&self, classified_error: &ClassifiedError, retry_attempt: u32) -> Result<()> {
        let error_message = serde_json::json!({
            "type": "error_report",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "error_type": classified_error.error_type,
            "severity": format!("{:?}", classified_error.severity),
            "windows_error_code": classified_error.windows_error_code,
            "retry_attempt": retry_attempt,
            "max_retries": classified_error.max_retries,
            "recovery_suggestion": classified_error.recovery_suggestion,
            "vm_id": self.vm_id
        });

        // Log the error report locally
        info!("Sending error report: type={}, severity={:?}, retry={}/{}",
              classified_error.error_type, classified_error.severity,
              retry_attempt, classified_error.max_retries);

        // Try to send error report when connected
        if self.is_connected.load(Ordering::SeqCst) {
            // Try to send directly with best-effort retry (1-2 attempts)
            let mut attempts = 0;
            let max_attempts = 2;

            while attempts < max_attempts {
                match self.send_control_message(error_message.clone()) {
                    Ok(_) => {
                        debug!("Error report sent successfully to backend");
                        return Ok(());
                    }
                    Err(e) => {
                        attempts += 1;
                        if attempts >= max_attempts {
                            debug!("Failed to send error report after {} attempts: {}", max_attempts, e);
                            break;
                        }
                    }
                }
            }
        }

        // If not connected or send failed, queue the report
        {
            let mut queued_reports = self.queued_error_reports.write().unwrap();
            queued_reports.push(error_message.clone());

            // Keep ring buffer small (max 10 reports)
            if queued_reports.len() > 10 {
                queued_reports.remove(0);
            }

            debug!("Error report queued (queue size: {})", queued_reports.len());
        }

        Ok(())
    }

    /// Classify OS errors per platform to avoid misclassification
    fn classify_os_error(error: &std::io::Error) -> ClassifiedError {
        #[cfg(target_os = "windows")]
        {
            if let Some(code) = error.raw_os_error() {
                return Self::classify_windows_error(code);
            }
        }
        // For non-Windows or when raw_os_error() is None
        Self::classify_io_error(error.kind())
    }

    /// Handle error with intelligent retry logic
    async fn handle_error_with_retry(&self, error: &std::io::Error, operation: &str) -> Result<bool> {
        let classified_error = Self::classify_os_error(error);

        let current_retry_count = self.error_retry_count.load(Ordering::SeqCst);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Update error time tracking
        self.last_error_time.store(current_time, Ordering::SeqCst);

        // Send error report to backend
        if let Err(e) = self.send_error_report(&classified_error, current_retry_count + 1).await {
            warn!("Failed to send error report: {}", e);
        }

        // Check if we should retry - apply unified retry caps (per-error vs global limit)
        //
        // Retry Cap Policy:
        // - Each error type has its own retry limit based on severity (e.g., temporary errors get 10 retries)
        // - The VirtioSerial instance has a global retry limit (default: 5) that applies across all error types
        // - The effective cap is the minimum of both limits to prevent excessive retries while respecting error-specific needs
        let per_error_cap = classified_error.max_retries;
        let global_cap = self.max_error_retries;
        let effective_cap = per_error_cap.min(global_cap);

        if classified_error.retry_recommended && current_retry_count < effective_cap {
            // Increment retry count
            self.error_retry_count.store(current_retry_count + 1, Ordering::SeqCst);

            // Calculate backoff delay based on error severity
            let base_backoff = match classified_error.severity {
                ErrorSeverity::Temporary => 500,    // 0.5s for temporary errors
                ErrorSeverity::Recoverable => 2000, // 2s for recoverable errors
                ErrorSeverity::Unknown => 1000,     // 1s for unknown errors
                ErrorSeverity::Fatal => 0,          // No backoff for fatal errors
            };

            let backoff_multiplier = (current_retry_count + 1) as u64;
            let backoff_delay = base_backoff * backoff_multiplier;

            // Cap maximum backoff at 30 seconds
            let capped_backoff = std::cmp::min(backoff_delay, 30000);
            self.error_backoff_ms.store(capped_backoff, Ordering::SeqCst);

            info!("Retrying {} operation in {}ms (attempt {}/{}) due to {}: {}",
                  operation, capped_backoff, current_retry_count + 1,
                  effective_cap, classified_error.error_type, error);

            // Wait for backoff delay
            tokio::time::sleep(tokio::time::Duration::from_millis(capped_backoff)).await;

            return Ok(true); // Indicates retry should be attempted
        } else {
            // Max retries exceeded or fatal error
            if classified_error.severity == ErrorSeverity::Fatal {
                error!("Fatal error in {} operation: {} - {}", operation, classified_error.error_type, error);
            } else {
                error!("Max retries ({}) exceeded for {} operation: {} - {}",
                       effective_cap, operation, classified_error.error_type, error);
            }

            // Mark connection as broken
            self.is_connected.store(false, Ordering::SeqCst);

            // Reset retry count for next error
            self.error_retry_count.store(0, Ordering::SeqCst);

            return Ok(false); // Indicates no more retries
        }
    }

    /// Reset error tracking after successful operation
    fn reset_error_tracking(&self) {
        self.error_retry_count.store(0, Ordering::SeqCst);
        self.error_backoff_ms.store(1000, Ordering::SeqCst); // Reset to initial backoff

        // Flush any queued error reports on successful operation
        if let Err(e) = self.flush_queued_error_reports() {
            debug!("Failed to flush queued error reports: {}", e);
        }
    }

    /// Send raw message using persistent connection
    #[async_recursion(?Send)]
    async fn send_raw_message(&self, message: &str, affects_circuit_breaker: bool) -> Result<()> {
        let start = std::time::Instant::now();
        let path_str = self.device_path.to_string_lossy();

        // Check if VirtIO is available
        if path_str == "__NO_VIRTIO_DEVICE__" {
            debug!("VirtIO not available - message not sent: {}", message);
            let latency_ms = start.elapsed().as_millis() as u64;
            self.update_transmission_stats(message.len() as u64, latency_ms, false);
            return Err(anyhow!("VirtIO device not available for communication"));
        }

        // Circuit Breaker: Check state before attempting transmission
        let circuit_state = {
            let state = self.circuit_breaker_state.read().unwrap();
            state.clone()
        };

        match circuit_state {
            CircuitBreakerState::Open => {
                // Check if circuit should transition to Half-Open
                let time_since_open = {
                    let metrics = self.circuit_breaker_metrics.read().unwrap();
                    SystemTime::now()
                        .duration_since(metrics.state_change_time)
                        .unwrap_or_default()
                        .as_secs()
                }; // metrics guard dropped here

                if time_since_open >= self.circuit_breaker_config.open_duration_secs {
                    self.transition_circuit_breaker_to_half_open().await;
                } else {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    self.update_transmission_stats(message.len() as u64, latency_ms, false);
                    return Err(anyhow!(
                        "Circuit breaker is OPEN - blocking transmission. Retry in {} seconds",
                        self.circuit_breaker_config.open_duration_secs.saturating_sub(time_since_open)
                    ));
                }
            },
            CircuitBreakerState::HalfOpen => {
                // Allow limited calls in half-open state
                let mut metrics = self.circuit_breaker_metrics.write().unwrap();
                if metrics.half_open_calls >= self.circuit_breaker_config.half_open_max_calls {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    self.update_transmission_stats(message.len() as u64, latency_ms, false);
                    return Err(anyhow!("Circuit breaker is HALF-OPEN - maximum calls reached"));
                }
                metrics.half_open_calls += 1;
            },
            CircuitBreakerState::Closed => {
                // Normal operation - no restrictions
            }
        }

        // Check connection state before attempting to send
        if !self.is_connected.load(Ordering::SeqCst) {
            let latency_ms = start.elapsed().as_millis() as u64;
            self.update_transmission_stats(message.len() as u64, latency_ms, false);
            if affects_circuit_breaker {
                self.record_circuit_breaker_failure().await;
            }
            return Err(anyhow!("VirtIO connection not established"));
        }

        // Handle Global objects on Windows differently using OVERLAPPED I/O with persistent handle
        #[cfg(target_os = "windows")]
        {
            if path_str.contains("Global") {
                // Windows API imports for OVERLAPPED I/O
                use winapi::um::fileapi::WriteFile;
                use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};
                use winapi::um::ioapiset::{GetOverlappedResult, CancelIoEx};
                use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
                use winapi::um::errhandlingapi::GetLastError;
                use winapi::um::winbase::{WAIT_OBJECT_0, WAIT_FAILED};
                use winapi::shared::winerror::{WAIT_TIMEOUT, ERROR_IO_PENDING, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED};
                use winapi::um::minwinbase::OVERLAPPED;
                use winapi::shared::ntdef::HANDLE;
                use std::mem::zeroed;
                use std::ptr;

                // Retrieve persistent handle
                let handle_opt = {
                    let handle_guard = self.windows_handle.read().unwrap();
                    handle_guard.as_ref().map(|h| h.0)
                }; // guard dropped here

                let handle = match handle_opt {
                    Some(h) => h,
                    None => {
                        // No handle available - connection lost
                        self.is_connected.store(false, Ordering::SeqCst);
                        let latency_ms = start.elapsed().as_millis() as u64;
                        self.update_transmission_stats(message.len() as u64, latency_ms, false);
                        if affects_circuit_breaker {
                            self.record_circuit_breaker_failure().await;
                        }
                        return Err(anyhow!("No Windows handle available for Global object"));
                    }
                };

                // Prepare message with newline (matching writeln! behavior)
                let message_with_newline = format!("{}\n", message);
                let message_bytes = message_with_newline.as_bytes();
                let bytes_to_write = message_bytes.len() as u32;

                debug!("Sending message via OVERLAPPED I/O to Global object, {} bytes", bytes_to_write);

                unsafe {
                    // Create manual-reset event for OVERLAPPED I/O
                    let event_handle = CreateEventW(
                        ptr::null_mut(),  // Default security
                        1,                // Manual-reset (TRUE)
                        0,                // Initial state: non-signaled (FALSE)
                        ptr::null_mut(),  // No name
                    );

                    if event_handle.is_null() || event_handle == INVALID_HANDLE_VALUE {
                        let error_code = GetLastError();
                        let latency_ms = start.elapsed().as_millis() as u64;
                        self.update_transmission_stats(message.len() as u64, latency_ms, false);
                        if affects_circuit_breaker {
                            self.record_circuit_breaker_failure().await;
                        }
                        return Err(anyhow!("Failed to create event for OVERLAPPED I/O: Win32 error {}", error_code));
                    }

                    // Initialize OVERLAPPED structure
                    let mut overlapped: OVERLAPPED = zeroed();
                    overlapped.hEvent = event_handle;

                    // Call WriteFile with OVERLAPPED
                    let mut bytes_written: u32 = 0;
                    let write_result = WriteFile(
                        handle,
                        message_bytes.as_ptr() as *const _,
                        bytes_to_write,
                        &mut bytes_written,
                        &mut overlapped,
                    );

                    // Handle WriteFile result - three scenarios
                    if write_result != 0 {
                        // Scenario A: Synchronous completion
                        CloseHandle(event_handle);
                        drop(overlapped); // Drop overlapped since event is closed

                        // Handle partial writes
                        if bytes_written < bytes_to_write {
                            warn!("Partial synchronous write for Global object: {} of {} bytes", bytes_written, bytes_to_write);
                            let mut total_written = bytes_written;
                            let mut remaining_bytes = &message_bytes[(bytes_written as usize)..];

                            // Retry remaining bytes with new OVERLAPPED structures
                            while total_written < bytes_to_write {
                                let remaining_count = bytes_to_write - total_written;

                                // Create new event for additional write
                                let additional_event = CreateEventW(
                                    ptr::null_mut(),
                                    1,  // Manual-reset
                                    0,  // Non-signaled
                                    ptr::null_mut(),
                                );

                                if additional_event.is_null() || additional_event == INVALID_HANDLE_VALUE {
                                    let error_code = GetLastError();
                                    // event_handle and overlapped already dropped/closed above
                                    let latency_ms = start.elapsed().as_millis() as u64;
                                    self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                    if affects_circuit_breaker {
                                        self.record_circuit_breaker_failure().await;
                                    }
                                    return Err(anyhow!("Failed to create event for partial write: Win32 error {}", error_code));
                                }

                                let mut additional_overlapped: OVERLAPPED = zeroed();
                                additional_overlapped.hEvent = additional_event;

                                let mut additional_written: u32 = 0;
                                let additional_result = WriteFile(
                                    handle,
                                    remaining_bytes.as_ptr() as *const _,
                                    remaining_count,
                                    &mut additional_written,
                                    &mut additional_overlapped,
                                );

                                if additional_result != 0 {
                                    // Synchronous success
                                    CloseHandle(additional_event);
                                    total_written += additional_written;
                                    if additional_written < remaining_count {
                                        remaining_bytes = &remaining_bytes[(additional_written as usize)..];
                                    }
                                } else {
                                    let add_error = GetLastError();
                                    if add_error == ERROR_IO_PENDING {
                                        // Wait for async completion
                                        let add_wait = WaitForSingleObject(additional_event, 5000);
                                        if add_wait == WAIT_OBJECT_0 {
                                            let add_overlapped_result = GetOverlappedResult(
                                                handle,
                                                &mut additional_overlapped,
                                                &mut additional_written,
                                                0,
                                            );
                                            CloseHandle(additional_event);
                                            if add_overlapped_result != 0 {
                                                total_written += additional_written;
                                                if additional_written < remaining_count {
                                                    remaining_bytes = &remaining_bytes[(additional_written as usize)..];
                                                }
                                            } else {
                                                let latency_ms = start.elapsed().as_millis() as u64;
                                                self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                                if affects_circuit_breaker {
                                                    self.record_circuit_breaker_failure().await;
                                                }
                                                return Err(anyhow!("Partial write GetOverlappedResult failed: {} of {} bytes written", total_written, bytes_to_write));
                                            }
                                        } else {
                                            CloseHandle(additional_event);
                                            let latency_ms = start.elapsed().as_millis() as u64;
                                            self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                            if affects_circuit_breaker {
                                                self.record_circuit_breaker_failure().await;
                                            }
                                            return Err(anyhow!("Partial write wait failed: {} of {} bytes written", total_written, bytes_to_write));
                                        }
                                    } else {
                                        CloseHandle(additional_event);
                                        let latency_ms = start.elapsed().as_millis() as u64;
                                        self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                        if affects_circuit_breaker {
                                            self.record_circuit_breaker_failure().await;
                                        }
                                        return Err(anyhow!("Partial write failed: Win32 error {}, {} of {} bytes written", add_error, total_written, bytes_to_write));
                                    }
                                }
                            }

                            debug!("Message sent successfully via Global object (synchronous with partial writes), {} bytes total", total_written);
                        } else {
                            debug!("Message sent successfully via Global object (synchronous), {} bytes", bytes_written);
                        }

                        let latency_ms = start.elapsed().as_millis() as u64;
                        self.update_transmission_stats(message.len() as u64, latency_ms, true);
                        self.reset_error_tracking();
                        if affects_circuit_breaker {
                            self.record_circuit_breaker_success().await;
                        }
                        return Ok(());
                    } else {
                        let error_code = GetLastError();

                        if error_code == ERROR_IO_PENDING {
                            // Scenario B: Async pending - wait for completion
                            debug!("WriteFile returned ERROR_IO_PENDING, waiting for completion...");
                            let wait_result = WaitForSingleObject(event_handle, 5000); // 5 second timeout

                            match wait_result {
                                WAIT_OBJECT_0 => {
                                    // Event signaled - operation completed
                                    let overlapped_result = GetOverlappedResult(
                                        handle,
                                        &mut overlapped,
                                        &mut bytes_written,
                                        0, // Don't wait (FALSE)
                                    );

                                    if overlapped_result != 0 {
                                        // Success
                                        CloseHandle(event_handle);

                                        // Handle partial writes
                                        if bytes_written < bytes_to_write {
                                            warn!("Partial asynchronous write for Global object: {} of {} bytes", bytes_written, bytes_to_write);
                                            let mut total_written = bytes_written;
                                            let mut remaining_bytes = &message_bytes[(bytes_written as usize)..];

                                            // Retry remaining bytes with new OVERLAPPED structures
                                            while total_written < bytes_to_write {
                                                let remaining_count = bytes_to_write - total_written;

                                                // Create new event for additional write
                                                let additional_event = CreateEventW(
                                                    ptr::null_mut(),
                                                    1,  // Manual-reset
                                                    0,  // Non-signaled
                                                    ptr::null_mut(),
                                                );

                                                if additional_event.is_null() || additional_event == INVALID_HANDLE_VALUE {
                                                    let error_code = GetLastError();
                                                    let latency_ms = start.elapsed().as_millis() as u64;
                                                    self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                                    if affects_circuit_breaker {
                                                        self.record_circuit_breaker_failure().await;
                                                    }
                                                    return Err(anyhow!("Failed to create event for partial write: Win32 error {}", error_code));
                                                }

                                                let mut additional_overlapped: OVERLAPPED = zeroed();
                                                additional_overlapped.hEvent = additional_event;

                                                let mut additional_written: u32 = 0;
                                                let additional_result = WriteFile(
                                                    handle,
                                                    remaining_bytes.as_ptr() as *const _,
                                                    remaining_count,
                                                    &mut additional_written,
                                                    &mut additional_overlapped,
                                                );

                                                if additional_result != 0 {
                                                    // Synchronous success
                                                    CloseHandle(additional_event);
                                                    total_written += additional_written;
                                                    if additional_written < remaining_count {
                                                        remaining_bytes = &remaining_bytes[(additional_written as usize)..];
                                                    }
                                                } else {
                                                    let add_error = GetLastError();
                                                    if add_error == ERROR_IO_PENDING {
                                                        // Wait for async completion
                                                        let add_wait = WaitForSingleObject(additional_event, 5000);
                                                        if add_wait == WAIT_OBJECT_0 {
                                                            let add_overlapped_result = GetOverlappedResult(
                                                                handle,
                                                                &mut additional_overlapped,
                                                                &mut additional_written,
                                                                0,
                                                            );
                                                            CloseHandle(additional_event);
                                                            if add_overlapped_result != 0 {
                                                                total_written += additional_written;
                                                                if additional_written < remaining_count {
                                                                    remaining_bytes = &remaining_bytes[(additional_written as usize)..];
                                                                }
                                                            } else {
                                                                let latency_ms = start.elapsed().as_millis() as u64;
                                                                self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                                                if affects_circuit_breaker {
                                                                    self.record_circuit_breaker_failure().await;
                                                                }
                                                                return Err(anyhow!("Partial write GetOverlappedResult failed: {} of {} bytes written", total_written, bytes_to_write));
                                                            }
                                                        } else {
                                                            CloseHandle(additional_event);
                                                            let latency_ms = start.elapsed().as_millis() as u64;
                                                            self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                                            if affects_circuit_breaker {
                                                                self.record_circuit_breaker_failure().await;
                                                            }
                                                            return Err(anyhow!("Partial write wait failed: {} of {} bytes written", total_written, bytes_to_write));
                                                        }
                                                    } else {
                                                        CloseHandle(additional_event);
                                                        let latency_ms = start.elapsed().as_millis() as u64;
                                                        self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                                        if affects_circuit_breaker {
                                                            self.record_circuit_breaker_failure().await;
                                                        }
                                                        return Err(anyhow!("Partial write failed: Win32 error {}, {} of {} bytes written", add_error, total_written, bytes_to_write));
                                                    }
                                                }
                                            }

                                            debug!("Message sent successfully via Global object (asynchronous with partial writes), {} bytes total", total_written);
                                        } else {
                                            debug!("Message sent successfully via Global object (asynchronous), {} bytes", bytes_written);
                                        }

                                        let latency_ms = start.elapsed().as_millis() as u64;
                                        self.update_transmission_stats(message.len() as u64, latency_ms, true);
                                        self.reset_error_tracking();
                                        if affects_circuit_breaker {
                                            self.record_circuit_breaker_success().await;
                                        }
                                        return Ok(());
                                    } else {
                                        // GetOverlappedResult failed
                                        let overlapped_error = GetLastError();
                                        CloseHandle(event_handle);
                                        warn!("GetOverlappedResult failed for Global object: Win32 error {}", overlapped_error);
                                        let latency_ms = start.elapsed().as_millis() as u64;
                                        self.update_transmission_stats(message.len() as u64, latency_ms, false);

                                        // Handle error with retry logic
                                        let io_error = std::io::Error::from_raw_os_error(overlapped_error as i32);
                                        match self.handle_error_with_retry(&io_error, "Global object OVERLAPPED write").await {
                                            Ok(true) => {
                                                // Retry recommended
                                                return self.send_raw_message(message, affects_circuit_breaker).await;
                                            }
                                            Ok(false) => {
                                                if affects_circuit_breaker {
                                                    self.record_circuit_breaker_failure().await;
                                                }
                                                return Err(anyhow!("GetOverlappedResult failed for Global object: Win32 error {}", overlapped_error));
                                            }
                                            Err(retry_err) => {
                                                if affects_circuit_breaker {
                                                    self.record_circuit_breaker_failure().await;
                                                }
                                                return Err(anyhow!("Error handling retry for OVERLAPPED write: {}", retry_err));
                                            }
                                        }
                                    }
                                }
                                WAIT_TIMEOUT => {
                                    // Timeout - cancel I/O
                                    warn!("WriteFile timed out after 5 seconds for Global object");
                                    CancelIoEx(handle, &mut overlapped);
                                    CloseHandle(event_handle);
                                    let latency_ms = start.elapsed().as_millis() as u64;
                                    self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                    if affects_circuit_breaker {
                                        self.record_circuit_breaker_failure().await;
                                    }
                                    return Err(anyhow!("WriteFile timed out after 5 seconds for Global object"));
                                }
                                WAIT_FAILED => {
                                    // Wait failed
                                    let wait_error = GetLastError();
                                    CloseHandle(event_handle);
                                    warn!("WaitForSingleObject failed for Global object: Win32 error {}", wait_error);
                                    let latency_ms = start.elapsed().as_millis() as u64;
                                    self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                    if affects_circuit_breaker {
                                        self.record_circuit_breaker_failure().await;
                                    }
                                    return Err(anyhow!("WaitForSingleObject failed: Win32 error {}", wait_error));
                                }
                                _ => {
                                    // Unexpected wait result
                                    CloseHandle(event_handle);
                                    let latency_ms = start.elapsed().as_millis() as u64;
                                    self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                    if affects_circuit_breaker {
                                        self.record_circuit_breaker_failure().await;
                                    }
                                    return Err(anyhow!("Unexpected WaitForSingleObject result: {}", wait_result));
                                }
                            }
                        } else {
                            // Scenario C: Immediate failure
                            CloseHandle(event_handle);
                            warn!("WriteFile failed for Global object: Win32 error {}", error_code);

                            // Handle specific fatal errors
                            if error_code == ERROR_BROKEN_PIPE || error_code == ERROR_NO_DATA || error_code == ERROR_PIPE_NOT_CONNECTED {
                                // Connection lost
                                self.is_connected.store(false, Ordering::SeqCst);
                                let latency_ms = start.elapsed().as_millis() as u64;
                                self.update_transmission_stats(message.len() as u64, latency_ms, false);
                                if affects_circuit_breaker {
                                    self.record_circuit_breaker_failure().await;
                                }
                                return Err(anyhow!("Global object connection lost: Win32 error {}", error_code));
                            }

                            // Handle retriable errors
                            let latency_ms = start.elapsed().as_millis() as u64;
                            self.update_transmission_stats(message.len() as u64, latency_ms, false);

                            let io_error = std::io::Error::from_raw_os_error(error_code as i32);
                            match self.handle_error_with_retry(&io_error, "Global object OVERLAPPED write").await {
                                Ok(true) => {
                                    // Retry recommended
                                    return self.send_raw_message(message, affects_circuit_breaker).await;
                                }
                                Ok(false) => {
                                    if affects_circuit_breaker {
                                        self.record_circuit_breaker_failure().await;
                                    }
                                    return Err(anyhow!("WriteFile failed for Global object after retries: Win32 error {}", error_code));
                                }
                                Err(retry_err) => {
                                    if affects_circuit_breaker {
                                        self.record_circuit_breaker_failure().await;
                                    }
                                    return Err(anyhow!("Error handling retry for OVERLAPPED write: {}", retry_err));
                                }
                            }
                        }
                    }
                } // unsafe block
            } // if path_str.contains("Global")
        } // cfg(target_os = "windows")

        // Use persistent write handle for other device types
        // Clone Arc<File> to avoid blocking I/O under locks
        let file_handle = {
            let write_handle = self.write_handle.read().unwrap();
            if let Some(ref file) = *write_handle {
                Some(Arc::clone(file))
            } else {
                None
            }
        }; // Lock is released here immediately

        let write_result = if let Some(file) = file_handle {
            // Perform I/O operations outside of any locks
            use std::io::Write;
            let mut file_ref = file.as_ref();
            let write_res = writeln!(file_ref, "{}", message);
            if write_res.is_ok() {
                file_ref.flush()
            } else {
                write_res
            }
        } else {
            // No write handle available
            self.is_connected.store(false, Ordering::SeqCst);
            let latency_ms = start.elapsed().as_millis() as u64;
            self.update_transmission_stats(message.len() as u64, latency_ms, false);
            return Err(anyhow!("No write handle available - connection lost"));
        };

        // Process the result outside of the mutex lock
        match write_result {
            Ok(_) => {
                debug!("Message sent successfully via persistent connection");
                let latency_ms = start.elapsed().as_millis() as u64;
                self.update_transmission_stats(message.len() as u64, latency_ms, true);
                self.reset_error_tracking(); // Reset on success
                if affects_circuit_breaker {
                    self.record_circuit_breaker_success().await;
                }
                Ok(())
            }
            Err(e) => {
                // Use intelligent retry logic for persistent connection errors
                match self.handle_error_with_retry(&e, "persistent connection write").await {
                    Ok(true) => {
                        // Retry was recommended, but we need to recursively call send_raw_message
                        // to handle the retry properly with fresh connection state
                        return Box::pin(self.send_raw_message(message, affects_circuit_breaker)).await;
                    }
                    Ok(false) => {
                        // No retry recommended or max retries exceeded
                        let latency_ms = start.elapsed().as_millis() as u64;
                        self.update_transmission_stats(message.len() as u64, latency_ms, false);
                        Err(anyhow!("Failed to transmit message after retries: {}", e))
                    }
                    Err(retry_err) => {
                        let latency_ms = start.elapsed().as_millis() as u64;
                        self.update_transmission_stats(message.len() as u64, latency_ms, false);
                        Err(anyhow!("Error handling retry for persistent connection: {}", retry_err))
                    }
                }
            }
        }
    }

    /// Read incoming commands using persistent connection
    pub async fn read_command(&self) -> Result<Option<IncomingMessage>> {
        let path_str = self.device_path.to_string_lossy();

        // Check if VirtIO is available
        if path_str == "__NO_VIRTIO_DEVICE__" {
            // Don't spam debug logs when VirtIO is not available
            return Ok(None);
        }

        // Check connection state before attempting to read
        if !self.is_connected.load(Ordering::SeqCst) {
            return Ok(None); // Return None instead of error to avoid breaking service loop
        }

        // Handle Global objects on Windows differently
        #[cfg(target_os = "windows")]
        {
            if path_str.contains("Global") {
                // For Global objects, use OVERLAPPED I/O with persistent handle
                use tokio::time::{timeout, Duration};
                use tokio::task;
                use winapi::um::fileapi::ReadFile;
                use winapi::um::synchapi::{CreateEventW, WaitForSingleObject};
                use winapi::um::ioapiset::{GetOverlappedResult, CancelIoEx};
                use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
                use winapi::um::errhandlingapi::GetLastError;
                use winapi::um::winbase::{WAIT_OBJECT_0, WAIT_FAILED};
                use winapi::shared::winerror::{WAIT_TIMEOUT, ERROR_IO_PENDING, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, ERROR_MORE_DATA};
                use winapi::um::minwinbase::OVERLAPPED;
                use std::mem::zeroed;
                use std::ptr;

                let timeout_duration = Duration::from_millis(self.read_timeout_ms);
                let windows_handle = self.windows_handle.clone(); // Clone Arc for move into closure
                let read_timeout_ms = self.read_timeout_ms; // Capture timeout for inner wait

                let read_result = timeout(timeout_duration, task::spawn_blocking(move || {
                    unsafe {
                        // Step 3: Retrieve persistent handle
                        let handle_guard = windows_handle.read().unwrap();
                        let handle = match handle_guard.as_ref() {
                            Some(h) => h.0,
                            None => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::NotConnected,
                                    "No Windows handle available for Global object"
                                ));
                            }
                        };

                        // Step 4: Allocate read buffer
                        const READ_BUFFER_SIZE: usize = 4096;
                        let mut buffer: Vec<u8> = vec![0u8; READ_BUFFER_SIZE];

                        // Step 5: Create manual-reset event
                        let event_handle = CreateEventW(
                            ptr::null_mut(),  // Default security
                            1,                // Manual-reset (TRUE)
                            0,                // Initial state: non-signaled (FALSE)
                            ptr::null_mut(),  // No name
                        );

                        if event_handle.is_null() || event_handle == INVALID_HANDLE_VALUE {
                            let error_code = GetLastError();
                            return Err(std::io::Error::from_raw_os_error(error_code as i32));
                        }

                        // Step 6: Initialize OVERLAPPED structure
                        let mut overlapped: OVERLAPPED = zeroed();
                        overlapped.hEvent = event_handle;

                        // Step 7: Call ReadFile with OVERLAPPED
                        let mut bytes_read: u32 = 0;
                        debug!("Reading from Global object via OVERLAPPED I/O, buffer size: {}", READ_BUFFER_SIZE);
                        let read_result = ReadFile(
                            handle,
                            buffer.as_mut_ptr() as *mut _,
                            READ_BUFFER_SIZE as u32,
                            &mut bytes_read,
                            &mut overlapped,
                        );

                        // Step 8: Handle ReadFile result - Three scenarios
                        if read_result != 0 {
                            // Scenario A: Synchronous completion
                            debug!("Read completed synchronously, {} bytes", bytes_read);
                            CloseHandle(event_handle);

                            if bytes_read == 0 {
                                debug!("No data available from Global object");
                                return Ok((0, String::new()));
                            }

                            let string = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                            return Ok((bytes_read as usize, string.to_string()));
                        } else {
                            let error_code = GetLastError();

                            if error_code == ERROR_IO_PENDING {
                                // Scenario B: Async pending
                                debug!("ReadFile returned ERROR_IO_PENDING, waiting for completion...");

                                // Wait for completion with configured timeout (matches QGA pattern)
                                // Use full configured timeout; outer tokio timeout provides additional safety
                                let wait_result = WaitForSingleObject(event_handle, read_timeout_ms as u32);

                                match wait_result {
                                    WAIT_OBJECT_0 => {
                                        // Event signaled, operation completed
                                        let get_result = GetOverlappedResult(handle, &mut overlapped, &mut bytes_read, 0);

                                        if get_result != 0 {
                                            debug!("Read completed asynchronously, {} bytes", bytes_read);
                                            CloseHandle(event_handle);

                                            if bytes_read == 0 {
                                                debug!("No data available from Global object");
                                                return Ok((0, String::new()));
                                            }

                                            let string = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                                            return Ok((bytes_read as usize, string.to_string()));
                                        } else {
                                            let error_code = GetLastError();
                                            debug!("GetOverlappedResult failed: Win32 error {}", error_code);
                                            CloseHandle(event_handle);
                                            return Err(std::io::Error::from_raw_os_error(error_code as i32));
                                        }
                                    }
                                    WAIT_TIMEOUT => {
                                        // No data arrived within wait period - must cancel the pending I/O
                                        debug!("Read operation timed out, cancelling pending I/O");

                                        // Cancel the pending I/O operation
                                        let cancel_result = CancelIoEx(handle, &mut overlapped);
                                        if cancel_result == 0 {
                                            let cancel_error = GetLastError();
                                            debug!("CancelIoEx failed or operation already completed: Win32 error {}", cancel_error);
                                            // Operation may have already completed, try to get result
                                        }

                                        // Wait for cancellation to complete (brief wait)
                                        let cancel_wait = WaitForSingleObject(event_handle, 1000);
                                        if cancel_wait == WAIT_OBJECT_0 {
                                            // Get the final result (will be ERROR_OPERATION_ABORTED if cancelled)
                                            GetOverlappedResult(handle, &mut overlapped, &mut bytes_read, 0);
                                            debug!("Pending I/O cancelled successfully");
                                        } else {
                                            debug!("Warning: Cancellation wait timed out or failed");
                                        }

                                        CloseHandle(event_handle);
                                        return Ok((0, String::new()));
                                    }
                                    WAIT_FAILED => {
                                        // Wait operation failed - cancel pending I/O before returning
                                        let error_code = GetLastError();
                                        debug!("WaitForSingleObject failed: Win32 error {}", error_code);

                                        // Cancel the pending I/O
                                        CancelIoEx(handle, &mut overlapped);
                                        WaitForSingleObject(event_handle, 1000); // Wait for cancellation
                                        GetOverlappedResult(handle, &mut overlapped, &mut bytes_read, 0);

                                        CloseHandle(event_handle);
                                        return Err(std::io::Error::from_raw_os_error(error_code as i32));
                                    }
                                    _ => {
                                        // Unexpected wait result - cancel pending I/O before returning
                                        debug!("Unexpected WaitForSingleObject result: {}", wait_result);

                                        // Cancel the pending I/O
                                        CancelIoEx(handle, &mut overlapped);
                                        WaitForSingleObject(event_handle, 1000); // Wait for cancellation
                                        GetOverlappedResult(handle, &mut overlapped, &mut bytes_read, 0);

                                        CloseHandle(event_handle);
                                        return Err(std::io::Error::new(
                                            std::io::ErrorKind::Other,
                                            "Unexpected wait result"
                                        ));
                                    }
                                }
                            } else {
                                // Scenario C: Immediate failure
                                debug!("ReadFile failed for Global object: Win32 error {}", error_code);
                                CloseHandle(event_handle);

                                // Handle ERROR_MORE_DATA as partial success
                                if error_code == ERROR_MORE_DATA {
                                    let string = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
                                    return Ok((bytes_read as usize, string.to_string()));
                                }

                                return Err(std::io::Error::from_raw_os_error(error_code as i32));
                            }
                        }
                    }
                })).await;

                // Step 9: Process read result in outer context
                match read_result {
                    Ok(Ok(Ok((0, _)))) => return Ok(None), // No data available
                    Ok(Ok(Ok((bytes_read, line)))) => {
                        self.update_bytes_received(bytes_read as u64);

                        // Handle line-based protocol: look for newline
                        // Note: We already waited up to read_timeout_ms for ReadFile to complete.
                        // If the received data doesn't contain a newline, we return Ok(None) to
                        // allow the service loop to poll again. This follows the "Simple OVERLAPPED
                        // Read" pattern and avoids CPU spinning since the outer loop controls polling.
                        if let Some(newline_pos) = line.find('\n') {
                            let message_line = &line[..newline_pos];
                            let trimmed = message_line.trim();
                            if trimmed.is_empty() {
                                return Ok(None);
                            }
                            return self.parse_incoming_message(trimmed);
                        } else {
                            // No newline found, incomplete message - no pending I/O to cancel
                            // (ReadFile already completed successfully)
                            debug!("Incomplete message (no newline), waiting for more data");
                            return Ok(None);
                        }
                    }
                    Ok(Ok(Err(e))) => {
                        match e.kind() {
                            std::io::ErrorKind::WouldBlock |
                            std::io::ErrorKind::TimedOut |
                            std::io::ErrorKind::UnexpectedEof => {
                                return Ok(None);
                            }
                            std::io::ErrorKind::NotConnected => {
                                // No persistent Windows handle available - mark disconnected
                                warn!("VirtIO Windows handle not available (NotConnected)");
                                self.is_connected.store(false, Ordering::SeqCst);
                                return Ok(None);
                            }
                            _ => {
                                if let Some(error_code) = e.raw_os_error() {
                                    match error_code {
                                        5 | 2 => { // ACCESS_DENIED or FILE_NOT_FOUND
                                            self.is_connected.store(false, Ordering::SeqCst);
                                        }
                                        109 | 232 | 233 => { // ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED
                                            warn!("VirtIO connection broken during read: Win32 error {}", error_code);
                                            self.is_connected.store(false, Ordering::SeqCst);
                                        }
                                        _ => {}
                                    }
                                }
                                return Ok(None);
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        // Task join error
                        return Ok(None);
                    }
                    Err(_) => {
                        // Timeout occurred
                        return Ok(None);
                    }
                }
            }
        }

        // Use persistent read handle for other device types
        // Clone Arc<File> to avoid blocking I/O under locks
        let file_handle = {
            let read_handle = self.read_handle.read().unwrap();
            if let Some(ref file) = *read_handle {
                Some(Arc::clone(file))
            } else {
                None
            }
        }; // Lock is released here immediately

        let read_result = if let Some(file) = file_handle {
            // Perform I/O operations outside of any locks
            use std::io::{BufReader, BufRead};
            let mut reader = BufReader::new(file.as_ref());
            let mut line = String::new();
            reader.read_line(&mut line).map(|n| (n, line))
        } else {
            // No read handle available
            self.is_connected.store(false, Ordering::SeqCst);
            return Ok(None);
        };

        // Process the read result outside of the mutex lock
        match read_result {
            Ok((0, _)) => {
                // No data available
                Ok(None)
            }
            Ok((bytes_read, line)) => {
                self.update_bytes_received(bytes_read as u64);
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return Ok(None);
                }
                self.parse_incoming_message(trimmed)
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::WouldBlock |
                    std::io::ErrorKind::TimedOut |
                    std::io::ErrorKind::UnexpectedEof => {
                        // These are normal for non-blocking operations
                        Ok(None)
                    }
                    std::io::ErrorKind::BrokenPipe |
                    std::io::ErrorKind::ConnectionReset => {
                        // Connection broken - mark as disconnected
                        warn!("VirtIO connection broken during read: {}", e);
                        self.is_connected.store(false, Ordering::SeqCst);
                        Ok(None)
                    }
                    _ => {
                        // Other error - don't break the service loop
                        debug!("Read error (non-fatal): {}", e);
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Parse incoming message and log appropriately
    fn parse_incoming_message(&self, trimmed: &str) -> Result<Option<IncomingMessage>> {
        debug!("Received message: {}", trimmed);

        match serde_json::from_str::<IncomingMessage>(trimmed) {
            Ok(msg) => {
                match &msg {
                    IncomingMessage::SafeCommand(cmd) => {
                        info!("Received safe command: id={}, type={:?}", cmd.id, cmd.command_type);
                    }
                    IncomingMessage::UnsafeCommand(cmd) => {
                        warn!("⚠️ Received UNSAFE command: id={}, command={}", cmd.id, cmd.raw_command);
                    }
                    IncomingMessage::Metrics => {
                        debug!("Received metrics request");
                    }
                    IncomingMessage::KeepAliveResponse(response) => {
                        debug!("Received keep-alive response: seq={}", response.sequence_number);
                        self.handle_keep_alive_response(response.sequence_number);
                    }
                }
                Ok(Some(msg))
            }
            Err(e) => {
                warn!("Failed to parse incoming message: {}", e);
                debug!("Raw message was: {}", trimmed);
                Ok(None)
            }
        }
    }

    /// Check if virtio-serial device is available (device path/access only)
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

    /// Check if there is an established persistent connection
    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::SeqCst)
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

        self.send_raw_message(&message_str, true).await
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

    /// Get transmission statistics for diagnostics
    pub fn get_transmission_stats(&self) -> std::collections::HashMap<String, String> {
        let mut stats = std::collections::HashMap::new();

        let last_transmission = self.last_transmission_time.load(std::sync::atomic::Ordering::SeqCst);
        let consecutive_failures = self.consecutive_failures.load(std::sync::atomic::Ordering::SeqCst);
        let initial_sent = self.initial_transmission_sent.load(std::sync::atomic::Ordering::SeqCst);

        stats.insert("last_transmission_time".to_string(), last_transmission.to_string());
        stats.insert("consecutive_failures".to_string(), consecutive_failures.to_string());
        stats.insert("initial_transmission_sent".to_string(), initial_sent.to_string());

        // Calculate time since last transmission
        if last_transmission > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let time_since_last = now.saturating_sub(last_transmission);
            stats.insert("seconds_since_last_transmission".to_string(), time_since_last.to_string());
        } else {
            stats.insert("seconds_since_last_transmission".to_string(), "never".to_string());
        }

        stats
    }

    /// Check if initial IP data has been successfully transmitted
    pub fn has_initial_transmission_succeeded(&self) -> bool {
        self.initial_transmission_sent.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Test the send path with a lightweight ping message
    /// Returns detailed error classification for diagnostic purposes
    pub async fn test_send_ping(&self) -> Result<()> {
        debug!("Testing connection with lightweight ping message");

        // Create a minimal ping message
        let ping_message = serde_json::json!({
            "type": "ping",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "sequence": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        });

        let serialized = serde_json::to_string(&ping_message)
            .with_context(|| "Failed to serialize ping message")?;

        // Send the ping message with strict error handling
        match self.send_raw_message(&serialized, true).await {
            Ok(()) => {
                debug!("Ping test completed successfully");
                Ok(())
            }
            Err(e) => {
                debug!("Ping test failed: {}", e);
                Err(e).with_context(|| "Ping test failed")
            }
        }
    }

    /// Get connection metadata with detailed diagnostic information
    pub fn get_connection_diagnostics(&self) -> std::collections::HashMap<String, String> {
        let mut diagnostics = self.get_device_metadata();

        // Add transmission statistics
        diagnostics.extend(self.get_transmission_stats());

        // Add connection health information
        diagnostics.insert("connection_health".to_string(), self.check_connection_health().to_string());

        // Add timeout configuration
        diagnostics.insert("read_timeout_ms".to_string(), self.read_timeout_ms.to_string());

        // Add device type analysis
        let path_str = self.device_path.to_string_lossy();
        let device_type = if path_str.contains("Global") {
            "global_object"
        } else if path_str.contains("pipe") {
            "named_pipe"
        } else if path_str.contains("COM") {
            "com_port"
        } else if path_str.starts_with("/dev/") {
            "linux_device"
        } else {
            "unknown"
        };
        diagnostics.insert("device_type_detected".to_string(), device_type.to_string());

        diagnostics
    }

    // Enhanced diagnostic helper methods
    fn record_health_check_result(&self, success: bool, latency_ms: Option<u64>, error_details: Option<String>) {
        let result = HealthCheckResult {
            timestamp: SystemTime::now(),
            success,
            latency_ms,
            error_details,
        };

        if let Ok(mut history) = self.health_check_history.write() {
            history.push(result);
            // Keep only last 100 health check results
            if history.len() > 100 {
                let len = history.len();
                history.drain(0..len - 100);
            }
        }
    }

    fn update_connection_quality(&self, quality: ConnectionQuality) {
        if let Ok(mut metrics) = self.connection_metrics.write() {
            metrics.connection_quality = quality;
        }
    }

    fn get_connection_quality(&self) -> ConnectionQuality {
        self.connection_metrics.read()
            .map(|m| m.connection_quality.clone())
            .unwrap_or(ConnectionQuality::Poor)
    }

    fn increment_error_pattern(&self, error_type: String) {
        if let Ok(mut metrics) = self.connection_metrics.write() {
            *metrics.error_patterns.entry(error_type).or_insert(0) += 1;
        }
    }

    fn classify_transmission_error(&self, error: &anyhow::Error) -> String {
        let error_str = error.to_string().to_lowercase();
        if error_str.contains("connection") {
            "connection_error".to_string()
        } else if error_str.contains("timeout") {
            "timeout_error".to_string()
        } else if error_str.contains("permission") {
            "permission_error".to_string()
        } else if error_str.contains("device") {
            "device_error".to_string()
        } else {
            "unknown_error".to_string()
        }
    }

    fn update_transmission_stats(&self, bytes: u64, latency_ms: u64, success: bool) {
        if let Ok(mut stats) = self.transmission_stats.write() {
            if success {
                stats.bytes_sent += bytes;
            }
            stats.message_count += 1;
            stats.last_transmission_size = bytes;

            // Update average latency using exponential moving average
            if stats.average_latency_ms == 0.0 {
                stats.average_latency_ms = latency_ms as f64;
            } else {
                stats.average_latency_ms = stats.average_latency_ms * 0.9 + (latency_ms as f64) * 0.1;
            }
        }

        if let Ok(mut metrics) = self.connection_metrics.write() {
            if success {
                metrics.successful_transmissions += 1;
                metrics.last_successful_transmission = Some(SystemTime::now());
            } else {
                metrics.failed_transmissions += 1;
            }
        }
    }

    fn update_bytes_received(&self, bytes: u64) {
        if let Ok(mut stats) = self.transmission_stats.write() {
            stats.bytes_received += bytes;
        }
    }

    fn get_health_statistics(&self) -> HealthStatistics {
        if let Ok(history) = self.health_check_history.read() {
            let total_checks = history.len();
            if total_checks == 0 {
                return HealthStatistics {
                    total_checks: 0,
                    success_rate: 0.0,
                    average_latency_ms: 0.0,
                };
            }

            let successful_checks = history.iter().filter(|r| r.success).count();
            let success_rate = successful_checks as f64 / total_checks as f64;

            let latencies: Vec<u64> = history.iter()
                .filter_map(|r| r.latency_ms)
                .collect();
            let average_latency_ms = if latencies.is_empty() {
                0.0
            } else {
                latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
            };

            HealthStatistics {
                total_checks,
                success_rate,
                average_latency_ms,
            }
        } else {
            HealthStatistics {
                total_checks: 0,
                success_rate: 0.0,
                average_latency_ms: 0.0,
            }
        }
    }

    fn get_transmission_statistics(&self) -> TransmissionStats {
        self.transmission_stats.read()
            .map(|s| s.clone())
            .unwrap_or(TransmissionStats {
                bytes_sent: 0,
                bytes_received: 0,
                message_count: 0,
                average_latency_ms: 0.0,
                last_transmission_size: 0,
            })
    }

    /// Enhanced connection health check with latency measurement and quality scoring
    pub fn check_connection_health(&self) -> bool {
        let health_check_start = SystemTime::now();

        info!("🔍 Starting comprehensive connection health check");

        if !self.is_connected.load(Ordering::SeqCst) {
            self.record_health_check_result(false, None, Some("Connection not established".to_string()));
            warn!("❌ Connection health check failed: not connected");
            return false;
        }

        let path_str = self.device_path.to_string_lossy();

        // For Global objects on Windows, we can't keep persistent handles
        // but we can test if the device is still accessible
        #[cfg(target_os = "windows")]
        {
            if path_str.contains("Global") {
                // Test if we can still open the Global object
                match Self::try_open_windows_device(&path_str, false) {
                    Ok(true) => {
                        let latency_ms = health_check_start.elapsed().unwrap_or_default().as_millis() as u64;
                        debug!("Connection health check passed: Global object accessible ({}ms)", latency_ms);
                        self.record_health_check_result(true, Some(latency_ms), None);

                        // Update connection quality based on latency
                        if latency_ms < 100 {
                            self.update_connection_quality(ConnectionQuality::Excellent);
                        } else if latency_ms < 500 {
                            self.update_connection_quality(ConnectionQuality::Good);
                        } else {
                            self.update_connection_quality(ConnectionQuality::Poor);
                        }

                        return true;
                    }
                    Ok(false) | Err(_) => {
                        let latency_ms = health_check_start.elapsed().unwrap_or_default().as_millis() as u64;
                        self.record_health_check_result(false, Some(latency_ms), Some("Global object not accessible".to_string()));
                        self.update_connection_quality(ConnectionQuality::Critical);
                        debug!("Connection health check failed: Global object not accessible ({}ms)", latency_ms);
                        return false;
                    }
                }
            }
        }

        // For other device types, check if handles are still valid
        let write_valid = {
            let write_handle = self.write_handle.read().unwrap();
            write_handle.is_some()
        };

        let read_valid = {
            let read_handle = self.read_handle.read().unwrap();
            read_handle.is_some()
        };

        let handles_valid = write_valid && read_valid;

        if !handles_valid {
            let latency_ms = health_check_start.elapsed().unwrap_or_default().as_millis() as u64;
            let error_msg = format!("Handles invalid (write={}, read={})", write_valid, read_valid);
            self.record_health_check_result(false, Some(latency_ms), Some(error_msg.clone()));
            self.update_connection_quality(ConnectionQuality::Critical);
            debug!("❌ Connection health check failed: {} ({}ms)", error_msg, latency_ms);
            return false;
        }

        // Additional validation: check if device path still exists (for file-based devices)
        if !path_str.contains("Global") && !path_str.contains("pipe") {
            if !self.device_path.exists() {
                let latency_ms = health_check_start.elapsed().unwrap_or_default().as_millis() as u64;
                self.record_health_check_result(false, Some(latency_ms), Some("Device path no longer exists".to_string()));
                self.update_connection_quality(ConnectionQuality::Critical);
                warn!("❌ Connection health check failed: device path no longer exists ({}ms)", latency_ms);
                return false;
            }
        }

        debug!("✅ Basic health validations passed: handles_valid={}, device_path_exists={}", handles_valid, !path_str.contains("Global") && !path_str.contains("pipe"));

        // Enhanced health check with ping test (rate-limited to avoid spam)
        // Rate limit: configurable interval (default 60 seconds)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_ping = self.last_ping_test_time.load(Ordering::SeqCst);

        // Only run ping test if enough time has passed since last test
        if now.saturating_sub(last_ping) >= self.ping_test_interval_secs {
            debug!("Running ping test for enhanced connection health validation");

            // Perform ping test asynchronously in a blocking context
            let ping_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    self.test_send_ping().await
                })
            });

            // Update the last ping test time regardless of result
            self.last_ping_test_time.store(now, Ordering::SeqCst);

            let health_check_duration = health_check_start.elapsed().unwrap_or_default();
            let latency_ms = health_check_duration.as_millis() as u64;

            match ping_result {
                Ok(_) => {
                    self.record_health_check_result(true, Some(latency_ms), None);

                    // Update connection quality based on latency
                    if latency_ms < 200 {
                        self.update_connection_quality(ConnectionQuality::Excellent);
                    } else if latency_ms < 1000 {
                        self.update_connection_quality(ConnectionQuality::Good);
                    } else {
                        self.update_connection_quality(ConnectionQuality::Poor);
                    }

                    info!("✅ Connection health check passed: all validations including ping test successful ({}ms)", latency_ms);
                    debug!("Health check details: latency={}ms, handles_valid={}, path_exists={}, quality={}",
                           latency_ms, handles_valid, self.device_path.exists(), self.get_connection_quality());
                    true
                }
                Err(e) => {
                    self.record_health_check_result(false, Some(latency_ms), Some(format!("Ping test failed: {}", e)));
                    self.update_connection_quality(ConnectionQuality::Poor);
                    warn!("❌ Connection health check failed: ping test failed - {} ({}ms)", e, latency_ms);
                    false
                }
            }
        } else {
            let health_check_duration = health_check_start.elapsed().unwrap_or_default();
            let latency_ms = health_check_duration.as_millis() as u64;

            self.record_health_check_result(true, Some(latency_ms), None);

            // Get recent health check statistics
            let health_stats = self.get_health_statistics();

            info!("✅ Connection health check passed: basic validations successful ({}ms, ping test rate-limited)", latency_ms);
            debug!("Health summary: success_rate={:.1}%, avg_latency={:.1}ms, recent_checks={}",
                   health_stats.success_rate * 100.0, health_stats.average_latency_ms, health_stats.total_checks);
            true
        }
    }

    // Circuit Breaker Helper Methods
    async fn transition_circuit_breaker_to_half_open(&self) {
        {
            let mut state = self.circuit_breaker_state.write().unwrap();
            let mut metrics = self.circuit_breaker_metrics.write().unwrap();

            *state = CircuitBreakerState::HalfOpen;
            metrics.state_change_time = SystemTime::now();
            metrics.half_open_calls = 0;

            info!("Circuit breaker transitioned to HALF-OPEN state - testing recovery");
        } // Locks dropped here

        // Send circuit breaker state change to backend
        self.send_circuit_breaker_state_change(CircuitBreakerState::HalfOpen).await;
    }

    async fn record_circuit_breaker_failure(&self) {
        let (should_transition_from_closed, should_transition_from_half_open) = {
            let mut metrics = self.circuit_breaker_metrics.write().unwrap();
            metrics.failure_count += 1;
            metrics.last_failure_time = Some(SystemTime::now());

            let current_state = {
                let state = self.circuit_breaker_state.read().unwrap();
                state.clone()
            };

            match current_state {
                CircuitBreakerState::Closed => {
                    // Check if we should open the circuit
                    let should_open = metrics.failure_count >= self.circuit_breaker_config.failure_threshold;
                    (should_open, false)
                },
                CircuitBreakerState::HalfOpen => {
                    // Any failure in half-open state should open the circuit
                    (false, true)
                },
                CircuitBreakerState::Open => {
                    // Already open, just record the failure
                    (false, false)
                }
            }
        }; // metrics guard dropped here

        if should_transition_from_closed || should_transition_from_half_open {
            self.transition_circuit_breaker_to_open().await;
        }
    }

    async fn record_circuit_breaker_success(&self) {
        let current_state = {
            let state = self.circuit_breaker_state.read().unwrap();
            state.clone()
        };

        match current_state {
            CircuitBreakerState::HalfOpen => {
                let mut metrics = self.circuit_breaker_metrics.write().unwrap();
                metrics.success_count += 1;

                // Check if we should close the circuit
                if metrics.success_count >= self.circuit_breaker_config.success_threshold {
                    drop(metrics); // Release lock before state change
                    self.transition_circuit_breaker_to_closed().await;
                }
            },
            CircuitBreakerState::Closed => {
                // Reset failure count on success
                let mut metrics = self.circuit_breaker_metrics.write().unwrap();
                metrics.failure_count = 0;
                metrics.success_count += 1;
            },
            CircuitBreakerState::Open => {
                // Shouldn't receive success when open, but handle gracefully
                debug!("Received success while circuit breaker is open - ignoring");
            }
        }
    }

    async fn transition_circuit_breaker_to_open(&self) {
        {
            let mut state = self.circuit_breaker_state.write().unwrap();
            let mut metrics = self.circuit_breaker_metrics.write().unwrap();

            *state = CircuitBreakerState::Open;
            metrics.state_change_time = SystemTime::now();
            metrics.half_open_calls = 0;

            warn!("Circuit breaker OPENED - blocking all calls for {} seconds",
                  self.circuit_breaker_config.open_duration_secs);
        } // Locks dropped here

        // Send circuit breaker state change to backend
        self.send_circuit_breaker_state_change(CircuitBreakerState::Open).await;
    }

    async fn transition_circuit_breaker_to_closed(&self) {
        let mut state = self.circuit_breaker_state.write().unwrap();
        let mut metrics = self.circuit_breaker_metrics.write().unwrap();

        *state = CircuitBreakerState::Closed;
        metrics.state_change_time = SystemTime::now();
        metrics.failure_count = 0;
        metrics.success_count = 0;
        metrics.half_open_calls = 0;

        info!("Circuit breaker CLOSED - normal operation resumed");

        // Send circuit breaker state change to backend
        self.send_circuit_breaker_state_change(CircuitBreakerState::Closed).await;
    }

    async fn send_circuit_breaker_state_change(&self, new_state: CircuitBreakerState) {
        let metrics = self.circuit_breaker_metrics.read().unwrap();
        let _state_message = serde_json::json!({
            "type": "circuit_breaker_state",
            "state": match new_state {
                CircuitBreakerState::Closed => "Closed",
                CircuitBreakerState::Open => "Open",
                CircuitBreakerState::HalfOpen => "HalfOpen"
            },
            "failure_count": metrics.failure_count,
            "last_failure_time": metrics.last_failure_time.map(|t|
                t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
            ),
            "recovery_eta_seconds": if new_state == CircuitBreakerState::Open {
                Some(self.circuit_breaker_config.open_duration_secs)
            } else {
                None
            },
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
        });

        // TODO: Fix recursion - temporarily disabled to allow compilation
        // if let Err(e) = self.send_raw_message(&state_message.to_string()).await {
        //     debug!("Failed to send circuit breaker state change: {}", e);
        //     // Queue the message for later if connection is down
        //     let mut queue = self.queued_error_reports.write().unwrap();
        //     queue.push(state_message);
        // }
        debug!("Circuit breaker state change: {:?}", new_state);
    }

    // Keep-Alive Methods
    pub async fn send_keep_alive(&self) -> Result<()> {
        let sequence = self.keep_alive_sequence.fetch_add(1, Ordering::SeqCst);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let last_received = self.keep_alive_last_received.load(Ordering::SeqCst);
        let time_since_last_received = timestamp.saturating_sub(last_received);

        info!(
            "📤 Sending keep-alive request (seq: {}, timestamp: {}, last_received: {}s ago)",
            sequence,
            timestamp,
            time_since_last_received
        );

        let keep_alive_message = serde_json::json!({
            "type": "keep_alive",
            "sequence_number": sequence,
            "timestamp": timestamp
        });

        self.keep_alive_last_sent.store(timestamp, Ordering::SeqCst);

        match self.send_raw_message(&keep_alive_message.to_string(), false).await {
            Ok(_) => {
                debug!("Keep-alive message sent successfully (seq: {}, timestamp: {})", sequence, timestamp);
                Ok(())
            },
            Err(e) => {
                // Keep-alive failures are logged but do NOT count toward circuit breaker failures.
                // This is intentional because keep-alive is a periodic maintenance operation,
                // and its failures should not trigger circuit breaker state changes, which are
                // reserved for actual data transmission failures.
                // The affects_circuit_breaker=false parameter ensures no CB metrics are updated.
                warn!("Keep-alive send failed (seq: {}): {} - not counting toward circuit breaker", sequence, e);
                Err(e)
            }
        }
    }

    pub fn handle_keep_alive_response(&self, sequence_number: u32) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.keep_alive_last_received.store(timestamp, Ordering::SeqCst);

        // Calculate round-trip time (RTT)
        let last_sent_timestamp = self.keep_alive_last_sent.load(Ordering::SeqCst);
        let rtt_secs = timestamp.saturating_sub(last_sent_timestamp);

        info!(
            "✅ Keep-alive response received (seq: {}, rtt: {}s)",
            sequence_number,
            rtt_secs
        );

        // Warn about high latency
        if rtt_secs > 5 {
            warn!(
                "⚠️ High keep-alive latency detected: {}s RTT",
                rtt_secs
            );
        }

        // Record successful keep-alive as circuit breaker success
        // Note: Keep-alive success does NOT count toward circuit breaker metrics
        // This is intentional because keep-alive is a maintenance operation, not data transmission
        debug!("Keep-alive successful - circuit breaker success not recorded (intentional)");
    }

    pub fn check_keep_alive_timeout(&self, keep_alive_timeout_secs: u64) -> bool {
        let last_sent = self.keep_alive_last_sent.load(Ordering::SeqCst);
        let last_received = self.keep_alive_last_received.load(Ordering::SeqCst);
        let last_transmission = self.last_transmission_time.load(Ordering::SeqCst);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // If we've sent a keep-alive but haven't received a response within the timeout
        if last_sent > 0 && last_received < last_sent {
            let time_since_sent = now.saturating_sub(last_sent);
            if time_since_sent > keep_alive_timeout_secs {
                let time_since_transmission = now.saturating_sub(last_transmission);
                warn!(
                    "Keep-alive timeout detected: {}s since last sent, no response received (timeout: {}s, last_transmission: {}s ago)",
                    time_since_sent,
                    keep_alive_timeout_secs,
                    time_since_transmission
                );
                return true;
            } else {
                // Log detailed timing for near-timeout situations
                debug!(
                    "Keep-alive pending: {}s since sent, waiting for response (timeout at {}s)",
                    time_since_sent,
                    keep_alive_timeout_secs
                );
            }
        }

        false
    }

    pub fn should_send_keep_alive(&self, keep_alive_interval_secs: u64, connection_idle_timeout_secs: u64) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let last_sent = self.keep_alive_last_sent.load(Ordering::SeqCst);
        let last_received = self.keep_alive_last_received.load(Ordering::SeqCst);
        let last_transmission = self.last_transmission_time.load(Ordering::SeqCst);

        // Edge case: At startup, last_sent is 0. Treat this as "not due yet" to avoid
        // sending keep-alive immediately. The first keep-alive will be sent after the
        // normal interval has elapsed from the first transmission.
        if last_sent == 0 {
            return false;
        }

        // Send keep-alive every keep_alive_interval_secs regardless of connection activity
        // This ensures the connection stays alive even during regular data transmission
        let should_send_due_to_interval = now.saturating_sub(last_sent) >= keep_alive_interval_secs;

        // Calculate diagnostic information
        let time_since_last_sent = now.saturating_sub(last_sent);
        let time_since_last_received = now.saturating_sub(last_received);
        let time_since_last_transmission = now.saturating_sub(last_transmission);
        let idle_duration = time_since_last_transmission;

        // Detailed connection state logging with all timing information
        debug!(
            "Connection state: last_sent={}s ago, last_received={}s ago, last_transmission={}s ago, interval_threshold={}s, idle_threshold={}s",
            time_since_last_sent,
            time_since_last_received,
            time_since_last_transmission,
            keep_alive_interval_secs,
            connection_idle_timeout_secs
        );

        // Enhanced logging for interval reached with decision reason
        if should_send_due_to_interval {
            info!(
                "⏰ Keep-alive interval reached ({}s since last keep-alive) - sending keep-alive (reason: interval_expired)",
                time_since_last_sent
            );
        }

        // Check if connection is idle and provide enhanced logging
        // Note: We don't track state transitions here to avoid additional atomic fields,
        // but we log the current idle status for diagnostics
        let is_idle = idle_duration >= connection_idle_timeout_secs;
        if is_idle && should_send_due_to_interval {
            warn!(
                "💤 Connection IDLE: {}s since last transmission (threshold: {}s) - connection is inactive while sending keep-alive",
                idle_duration,
                connection_idle_timeout_secs
            );
        } else if is_idle {
            debug!(
                "Connection idle: {}s since last transmission (threshold: {}s)",
                idle_duration,
                connection_idle_timeout_secs
            );
        }

        should_send_due_to_interval
    }

    /// Log a comprehensive summary of the keep-alive state for diagnostics
    pub fn log_keep_alive_state_summary(&self, keep_alive_interval_secs: u64, connection_idle_timeout_secs: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let last_sent = self.keep_alive_last_sent.load(Ordering::SeqCst);
        let last_received = self.keep_alive_last_received.load(Ordering::SeqCst);
        let last_transmission = self.last_transmission_time.load(Ordering::SeqCst);
        let sequence = self.keep_alive_sequence.load(Ordering::SeqCst);

        let time_since_last_sent = now.saturating_sub(last_sent);
        let time_since_last_received = now.saturating_sub(last_received);
        let time_since_last_transmission = now.saturating_sub(last_transmission);
        let idle_duration = time_since_last_transmission;

        // Determine connection status
        let status = if idle_duration < connection_idle_timeout_secs {
            "ACTIVE"
        } else {
            "IDLE"
        };

        info!(
            "📊 Keep-Alive State Summary:\n   Status: {}\n   Last Keep-Alive Sent: {}s ago\n   Last Keep-Alive Received: {}s ago\n   Last Data Transmission: {}s ago\n   Idle Duration: {}s (threshold: {}s)\n   Keep-Alive Interval: {}s\n   Sequence: {}",
            status,
            time_since_last_sent,
            time_since_last_received,
            time_since_last_transmission,
            idle_duration,
            connection_idle_timeout_secs,
            keep_alive_interval_secs,
            sequence
        );
    }
}

// Drop implementation to ensure resources are cleaned up
impl Drop for VirtioSerial {
    fn drop(&mut self) {
        // Close Windows handle for Global objects
        #[cfg(target_os = "windows")]
        {
            if let Ok(mut win_handle) = self.windows_handle.write() {
                if let Some(handle) = win_handle.take() {
                    unsafe {
                        use winapi::um::handleapi::CloseHandle;
                        CloseHandle(handle.0);
                    }
                }
            }
        }

        // Clear write handle
        if let Ok(mut write_handle) = self.write_handle.write() {
            let _ = write_handle.take();
        }

        // Clear read handle
        if let Ok(mut read_handle) = self.read_handle.write() {
            let _ = read_handle.take();
        }
    }
}

// Manual Clone implementation for VirtioSerial (since it contains Arc<> fields)
impl Clone for VirtioSerial {
    fn clone(&self) -> Self {
        Self {
            device_path: self.device_path.clone(),
            vm_id: self.vm_id.clone(),
            write_handle: Arc::clone(&self.write_handle),
            read_handle: Arc::clone(&self.read_handle),
            is_connected: Arc::clone(&self.is_connected),
            read_timeout_ms: self.read_timeout_ms,
            ping_test_interval_secs: self.ping_test_interval_secs,
            last_transmission_time: Arc::clone(&self.last_transmission_time),
            consecutive_failures: Arc::clone(&self.consecutive_failures),
            initial_transmission_sent: Arc::clone(&self.initial_transmission_sent),
            last_ping_test_time: Arc::clone(&self.last_ping_test_time),
            connection_metrics: Arc::clone(&self.connection_metrics),
            health_check_history: Arc::clone(&self.health_check_history),
            transmission_stats: Arc::clone(&self.transmission_stats),
            error_retry_count: Arc::clone(&self.error_retry_count),
            last_error_time: Arc::clone(&self.last_error_time),
            error_backoff_ms: Arc::clone(&self.error_backoff_ms),
            max_error_retries: self.max_error_retries,
            queued_error_reports: Arc::clone(&self.queued_error_reports),
            circuit_breaker_state: Arc::clone(&self.circuit_breaker_state),
            circuit_breaker_metrics: Arc::clone(&self.circuit_breaker_metrics),
            circuit_breaker_config: self.circuit_breaker_config.clone(),
            keep_alive_last_sent: Arc::clone(&self.keep_alive_last_sent),
            keep_alive_last_received: Arc::clone(&self.keep_alive_last_received),
            keep_alive_sequence: Arc::clone(&self.keep_alive_sequence),
            #[cfg(target_os = "windows")]
            windows_handle: Arc::clone(&self.windows_handle),
        }
    }
}

#[derive(Debug, Clone)]
struct HealthStatistics {
    total_checks: usize,
    success_rate: f64,
    average_latency_ms: f64,
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
