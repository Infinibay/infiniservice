//! Configuration management for Infiniservice

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Interval between data collection cycles (in seconds)
    pub collection_interval: u64,
    
    /// Path to virtio-serial device
    pub virtio_serial_path: PathBuf,
    
    /// Log level
    pub log_level: String,
    
    /// Service name/identifier
    pub service_name: String,
    
    /// Whether VirtIO is required for the service to run
    /// If false, the service will continue running even without VirtIO
    pub require_virtio: bool,
    
    /// Interval for retrying VirtIO connection (in seconds)
    pub virtio_retry_interval: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            collection_interval: 30,
            virtio_serial_path: if cfg!(windows) {
                // Empty path triggers auto-detection on Windows
                PathBuf::new()
            } else {
                PathBuf::from("/dev/virtio-ports/org.infinibay.0")
            },
            log_level: "info".to_string(),
            service_name: "infiniservice".to_string(),
            require_virtio: false, // Allow service to run without VirtIO by default
            virtio_retry_interval: 300, // Retry every 5 minutes
        }
    }
}

impl Config {
    /// Load configuration from file or use defaults
    pub fn load() -> Result<Self> {
        // TODO: Implement configuration loading from file
        // For now, return default configuration
        Ok(Self::default())
    }
}
