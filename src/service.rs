//! Main service implementation

use crate::{Config, collector::DataCollector, communication::VirtioSerial};
use anyhow::Result;
use log::{info, error, warn};
use std::time::Duration;
use tokio::time;

pub struct InfiniService {
    config: Config,
    collector: DataCollector,
    communication: VirtioSerial,
}

impl InfiniService {
    pub fn new(config: Config) -> Self {
        let collector = DataCollector::new();

        // Try to auto-detect virtio-serial device if not specified
        let communication = if config.virtio_serial_path.to_string_lossy().is_empty() {
            match VirtioSerial::detect_device_path() {
                Ok(device_path) => {
                    info!("Auto-detected virtio-serial device: {:?}", device_path);
                    VirtioSerial::new(device_path)
                }
                Err(e) => {
                    warn!("Failed to auto-detect virtio-serial device: {}", e);
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
        }
    }

    pub fn new_with_ping_pong(config: Config) -> Self {
        let collector = DataCollector::new();

        // Try to auto-detect virtio-serial device
        let communication = match VirtioSerial::detect_device_path() {
            Ok(device_path) => {
                info!("Auto-detected virtio-serial device for ping-pong: {:?}", device_path);
                VirtioSerial::new(device_path)
            }
            Err(e) => {
                warn!("Failed to auto-detect virtio-serial device: {}", e);
                warn!("Using configured path: {:?}", config.virtio_serial_path);
                VirtioSerial::new(&config.virtio_serial_path)
            }
        };

        Self {
            config,
            collector: collector.expect("DataCollector should initialize"),
            communication,
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

    /// Run ping-pong test mode
    pub async fn run_ping_pong(&mut self) -> Result<()> {
        info!("Starting ping-pong test mode");

        // Use a shorter interval for ping-pong testing
        let ping_interval = 10; // 10 seconds

        self.communication.run_ping_pong_test(ping_interval).await
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
