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
    
    /// Interval for retrying VirtIO connection (in seconds) (deprecated, use min/max backoff)
    pub virtio_retry_interval: u64,

    /// Minimum backoff interval in seconds for VirtIO retry attempts
    pub virtio_min_backoff_secs: u64,

    /// Maximum backoff interval in seconds for VirtIO retry attempts
    pub virtio_max_backoff_secs: u64,

    /// Enable automatic device change monitoring
    pub enable_device_monitoring: bool,
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
            virtio_min_backoff_secs: 5, // Start with 5 second backoff
            virtio_max_backoff_secs: 300, // Maximum 5 minute backoff
            enable_device_monitoring: true, // Enable device change monitoring by default
        }
    }
}

impl Config {
    /// Load configuration from file or use defaults
    pub fn load() -> Result<Self> {
        // TODO: Implement configuration loading from file
        // For now, return default configuration
        let mut config = Self::default();
        config.validate_and_fix();
        Ok(config)
    }

    /// Validate and fix configuration values
    pub fn validate_and_fix(&mut self) {
        // Ensure backoff values are valid
        if self.virtio_min_backoff_secs == 0 {
            self.virtio_min_backoff_secs = 5;
        }
        if self.virtio_max_backoff_secs == 0 {
            self.virtio_max_backoff_secs = 300;
        }
        if self.virtio_min_backoff_secs > self.virtio_max_backoff_secs {
            // Swap values if min > max
            let temp = self.virtio_min_backoff_secs;
            self.virtio_min_backoff_secs = self.virtio_max_backoff_secs;
            self.virtio_max_backoff_secs = temp;
        }
    }
}
