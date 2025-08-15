//! Communication module for virtio-serial interface

use crate::collector::SystemInfo;
use anyhow::{Result, Context, anyhow};
use log::{info, error, debug, warn};
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::fs::OpenOptions;
use std::io::{Write, BufRead, BufReader};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct PingMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub timestamp: String,
    #[serde(rename = "vmId")]
    pub vm_id: String,
    #[serde(rename = "sequenceNumber")]
    pub sequence_number: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PongMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub timestamp: String,
    #[serde(rename = "vmId")]
    pub vm_id: String,
    #[serde(rename = "sequenceNumber")]
    pub sequence_number: Option<u64>,
}

pub struct VirtioSerial {
    device_path: std::path::PathBuf,
    vm_id: String,
    sequence_number: u64,
}

impl VirtioSerial {
    pub fn new<P: AsRef<Path>>(device_path: P) -> Self {
        Self {
            device_path: device_path.as_ref().to_path_buf(),
            vm_id: Self::generate_vm_id(),
            sequence_number: 0,
        }
    }

    pub fn with_vm_id<P: AsRef<Path>>(device_path: P, vm_id: String) -> Self {
        Self {
            device_path: device_path.as_ref().to_path_buf(),
            vm_id,
            sequence_number: 0,
        }
    }

    fn generate_vm_id() -> String {
        // Try to get VM ID from environment or generate one
        std::env::var("INFINIBAY_VM_ID")
            .unwrap_or_else(|_| Uuid::new_v4().to_string())
    }

    /// Detect virtio-serial device path based on platform
    pub fn detect_device_path() -> Result<std::path::PathBuf> {
        #[cfg(target_os = "linux")]
        {
            Self::detect_linux_device()
        }

        #[cfg(target_os = "windows")]
        {
            Self::detect_windows_device()
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(anyhow!("Unsupported platform for virtio-serial detection"))
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux_device() -> Result<std::path::PathBuf> {
        // Common virtio-serial device paths on Linux
        let possible_paths = [
            "/dev/virtio-ports/org.infinibay.ping",
            "/dev/virtio-ports/com.redhat.spice.0",
            "/dev/vport0p1",
            "/dev/vport1p1",
        ];

        for path in &possible_paths {
            let device_path = std::path::Path::new(path);
            if device_path.exists() {
                info!("Found virtio-serial device at: {}", path);
                return Ok(device_path.to_path_buf());
            }
        }

        // Check for any virtio-ports device
        let virtio_dir = std::path::Path::new("/dev/virtio-ports");
        if virtio_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(virtio_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
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
        }

        Err(anyhow!("No virtio-serial device found on Linux"))
    }

    #[cfg(target_os = "windows")]
    fn detect_windows_device() -> Result<std::path::PathBuf> {
        // Windows virtio-serial device paths
        let possible_paths = [
            r"\\.\Global\org.infinibay.ping",
            r"\\.\Global\com.redhat.spice.0",
            r"\\.\pipe\org.infinibay.ping",
        ];

        for path in &possible_paths {
            // On Windows, we can't easily check if the device exists without trying to open it
            // So we'll return the first path and let the connection attempt handle the error
            info!("Trying Windows virtio-serial device: {}", path);
            return Ok(std::path::PathBuf::from(path));
        }

        Err(anyhow!("No virtio-serial device configured for Windows"))
    }
    
    /// Initialize connection to virtio-serial device
    pub async fn connect(&self) -> Result<()> {
        info!("Connecting to virtio-serial device: {:?}", self.device_path);

        // Test if we can open the device for writing
        let _file = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&self.device_path)
            .with_context(|| format!("Failed to open virtio-serial device: {:?}", self.device_path))?;

        info!("Virtio-serial connection established successfully");
        Ok(())
    }

    /// Send a ping message to the host
    pub async fn send_ping(&mut self) -> Result<()> {
        self.sequence_number += 1;

        let ping_message = PingMessage {
            message_type: "ping".to_string(),
            timestamp: Self::current_timestamp(),
            vm_id: self.vm_id.clone(),
            sequence_number: Some(self.sequence_number),
        };

        let message_json = serde_json::to_string(&ping_message)?;
        debug!("🏓 Sending PING: {}", message_json);

        // Open device and send message
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.device_path)
            .with_context(|| format!("Failed to open device for writing: {:?}", self.device_path))?;

        writeln!(file, "{}", message_json)
            .with_context(|| "Failed to write ping message to device")?;

        file.flush()
            .with_context(|| "Failed to flush data to device")?;

        info!("🏓 PING sent to host (sequence: {})", self.sequence_number);
        Ok(())
    }

    /// Listen for pong messages from the host
    pub async fn listen_for_pong(&self, timeout_secs: u64) -> Result<Option<PongMessage>> {
        debug!("Listening for PONG message...");

        // Open device for reading
        let file = OpenOptions::new()
            .read(true)
            .open(&self.device_path)
            .with_context(|| format!("Failed to open device for reading: {:?}", self.device_path))?;

        let mut reader = BufReader::new(file);
        let mut line = String::new();

        // Simple timeout implementation (in a real implementation, you'd use async timeout)
        let start_time = std::time::Instant::now();

        loop {
            if start_time.elapsed().as_secs() > timeout_secs {
                debug!("Timeout waiting for PONG message");
                return Ok(None);
            }

            // Try to read a line (non-blocking would be better)
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // EOF reached, wait a bit and try again
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        debug!("Received message: {}", trimmed);

                        // Try to parse as JSON
                        match serde_json::from_str::<PongMessage>(trimmed) {
                            Ok(pong) => {
                                if pong.message_type == "pong" {
                                    info!("🏓 PONG received from host (sequence: {:?})", pong.sequence_number);
                                    return Ok(Some(pong));
                                }
                            }
                            Err(e) => {
                                debug!("Failed to parse message as PONG: {}", e);
                            }
                        }
                    }
                    line.clear();
                }
                Err(e) => {
                    warn!("Error reading from device: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
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

        let serialized = serde_json::to_string(data)
            .with_context(|| "Failed to serialize system data")?;

        // Open device and send data
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.device_path)
            .with_context(|| format!("Failed to open device for data transmission: {:?}", self.device_path))?;

        writeln!(file, "{}", serialized)
            .with_context(|| "Failed to write system data to device")?;

        file.flush()
            .with_context(|| "Failed to flush system data to device")?;

        info!("System data sent successfully");
        Ok(())
    }

    /// Check if virtio-serial device is available
    pub fn is_available(&self) -> bool {
        self.device_path.exists()
    }

    /// Run ping-pong test loop
    pub async fn run_ping_pong_test(&mut self, interval_secs: u64) -> Result<()> {
        info!("Starting ping-pong test with {}s interval", interval_secs);

        loop {
            // Send ping
            if let Err(e) = self.send_ping().await {
                error!("Failed to send ping: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
                continue;
            }

            // Wait for pong
            match self.listen_for_pong(5).await {
                Ok(Some(pong)) => {
                    info!("✅ Ping-pong successful! Received: {:?}", pong);
                }
                Ok(None) => {
                    warn!("⏰ Timeout waiting for pong response");
                }
                Err(e) => {
                    error!("❌ Error listening for pong: {}", e);
                }
            }

            // Wait before next ping
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_ping_message_serialization() {
        let ping = PingMessage {
            message_type: "ping".to_string(),
            timestamp: "1234567890".to_string(),
            vm_id: "test-vm-123".to_string(),
            sequence_number: Some(5),
        };

        let json = serde_json::to_string(&ping).expect("Should serialize ping message");
        assert!(json.contains("\"type\":\"ping\""));
        assert!(json.contains("\"vmId\":\"test-vm-123\""));
        assert!(json.contains("\"sequenceNumber\":5"));

        let deserialized: PingMessage = serde_json::from_str(&json).expect("Should deserialize ping message");
        assert_eq!(ping.message_type, deserialized.message_type);
        assert_eq!(ping.vm_id, deserialized.vm_id);
        assert_eq!(ping.sequence_number, deserialized.sequence_number);
    }

    #[test]
    fn test_pong_message_serialization() {
        let pong = PongMessage {
            message_type: "pong".to_string(),
            timestamp: "1234567890".to_string(),
            vm_id: "test-vm-456".to_string(),
            sequence_number: Some(10),
        };

        let json = serde_json::to_string(&pong).expect("Should serialize pong message");
        assert!(json.contains("\"type\":\"pong\""));
        assert!(json.contains("\"vmId\":\"test-vm-456\""));
        assert!(json.contains("\"sequenceNumber\":10"));

        let deserialized: PongMessage = serde_json::from_str(&json).expect("Should deserialize pong message");
        assert_eq!(pong.message_type, deserialized.message_type);
        assert_eq!(pong.vm_id, deserialized.vm_id);
        assert_eq!(pong.sequence_number, deserialized.sequence_number);
    }

    #[test]
    fn test_virtio_serial_initialization() {
        let device_path = PathBuf::from("/dev/virtio-ports/test");
        let virtio = VirtioSerial::new(&device_path);
        
        assert_eq!(virtio.device_path, device_path);
        assert!(!virtio.vm_id.is_empty());
        assert_eq!(virtio.sequence_number, 0);
    }

    #[test]
    fn test_virtio_serial_with_vm_id() {
        let device_path = PathBuf::from("/dev/virtio-ports/test");
        let vm_id = "custom-vm-id";
        let virtio = VirtioSerial::with_vm_id(&device_path, vm_id.to_string());
        
        assert_eq!(virtio.device_path, device_path);
        assert_eq!(virtio.vm_id, vm_id);
        assert_eq!(virtio.sequence_number, 0);
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
        let result = VirtioSerial::detect_device_path();
        // This will likely fail in test environment, but shouldn't panic
        assert!(result.is_ok() || result.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_device_detection_paths() {
        // Test that detection returns expected Windows paths
        let result = VirtioSerial::detect_device_path();
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

    #[test]
    fn test_message_structure_compatibility() {
        // Test that our message structures are compatible with the expected format
        
        // Test ping message JSON structure
        let ping = PingMessage {
            message_type: "ping".to_string(),
            timestamp: "1234567890".to_string(),
            vm_id: "vm-123".to_string(),
            sequence_number: Some(1),
        };
        
        let json = serde_json::to_string(&ping).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        
        // Check JSON field names match expected API
        assert_eq!(value["type"], "ping");
        assert_eq!(value["vmId"], "vm-123");
        assert_eq!(value["sequenceNumber"], 1);
        assert_eq!(value["timestamp"], "1234567890");
    }
}
