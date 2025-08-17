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
