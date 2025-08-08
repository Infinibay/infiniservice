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
        let communication = VirtioSerial::new(&config.virtio_serial_path);
        
        Self {
            config,
            collector,
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
    pub async fn run(&self) -> Result<()> {
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
    async fn collect_and_send(&self) -> Result<()> {
        // Collect system information
        let system_info = self.collector.collect().await?;
        
        // Send data via virtio-serial
        self.communication.send_data(&system_info).await?;
        
        Ok(())
    }
}
