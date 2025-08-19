//! Main service implementation

use crate::{Config, collector::DataCollector, communication::VirtioSerial};
use anyhow::Result;
use log::{info, error, warn, debug};
use std::time::Duration;
use tokio::time;

pub struct InfiniService {
    config: Config,
    collector: DataCollector,
    communication: VirtioSerial,
    debug_mode: bool,
}

impl InfiniService {
    pub fn new(config: Config, debug_mode: bool) -> Self {
        let collector = DataCollector::new();
        
        if debug_mode {
            debug!("Initializing InfiniService in debug mode");
            debug!("Configuration path: {:?}", config.virtio_serial_path);
        }

        // Try to auto-detect virtio-serial device if not specified
        let communication = if config.virtio_serial_path.to_string_lossy().is_empty() {
            if debug_mode {
                debug!("Attempting to auto-detect virtio-serial device...");
            }
            match VirtioSerial::detect_device_path(debug_mode) {
                Ok(device_path) => {
                    info!("Auto-detected virtio-serial device: {:?}", device_path);
                    VirtioSerial::new(device_path)
                }
                Err(e) => {
                    warn!("Failed to auto-detect virtio-serial device: {}", e);
                    if debug_mode {
                        debug!("Detection error details: {:?}", e);
                    }
                    VirtioSerial::new(&config.virtio_serial_path)
                }
            }
        } else {
            VirtioSerial::new(&config.virtio_serial_path)
        };

        Self {
            config,
            collector: collector.expect("DataCollector should initialize"),
            communication,
            debug_mode,
        }
    }

    
    /// Initialize the service
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing Infiniservice...");
        
        // Check if virtio-serial is available
        if !self.communication.is_available() {
            warn!("Virtio-serial device not available at {:?}", self.config.virtio_serial_path);
            warn!("Service will continue but data transmission may fail");
        }
        
        // Connect to virtio-serial
        self.communication.connect().await?;
        
        info!("Infiniservice initialized successfully");
        Ok(())
    }
    
    /// Run the main service loop
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Infiniservice main loop");

        let interval = Duration::from_secs(self.config.collection_interval);

        loop {
            match self.collect_and_send().await {
                Ok(_) => {
                    info!("Data collection and transmission completed successfully");
                }
                Err(e) => {
                    error!("Error during data collection/transmission: {}", e);
                    // Continue running even if there are errors
                }
            }

            // Wait for next collection cycle
            time::sleep(interval).await;
        }
    }

    
    /// Collect data and send it to the host
    async fn collect_and_send(&mut self) -> Result<()> {
        // Collect system information
        let system_info = self.collector.collect().await?;
        
        // Send data via virtio-serial
        self.communication.send_data(&system_info).await?;
        
        Ok(())
    }
}
