//! Main service implementation with command execution support

use crate::{Config, collector::DataCollector, communication::VirtioSerial};
use crate::commands::{IncomingMessage, executor::CommandExecutor};
use anyhow::Result;
use log::{info, error, warn, debug};
use std::time::Duration;
use tokio::time;
use tokio::select;

pub struct InfiniService {
    config: Config,
    collector: DataCollector,
    communication: VirtioSerial,
    command_executor: CommandExecutor,
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
        
        let command_executor = CommandExecutor::new()
            .expect("Failed to initialize command executor");

        Self {
            config,
            collector: collector.expect("DataCollector should initialize"),
            communication,
            command_executor,
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
    
    /// Run the main service loop with command handling
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Infiniservice main loop with command support");
        info!("Service will collect metrics every {} seconds", self.config.collection_interval);
        info!("Command execution is ENABLED - both safe and unsafe commands supported");

        let mut interval = time::interval(Duration::from_secs(self.config.collection_interval));
        let mut command_check_interval = time::interval(Duration::from_millis(100)); // Check for commands every 100ms

        loop {
            select! {
                // Periodic metrics collection
                _ = interval.tick() => {
                    match self.collect_and_send().await {
                        Ok(_) => {
                            debug!("Metrics collection and transmission completed");
                        }
                        Err(e) => {
                            error!("Error during metrics collection/transmission: {}", e);
                            // Continue running even if there are errors
                        }
                    }
                }
                
                // Check for incoming commands
                _ = command_check_interval.tick() => {
                    match self.check_and_execute_command().await {
                        Ok(true) => {
                            // Command was executed
                            debug!("Command processed successfully");
                        }
                        Ok(false) => {
                            // No command available
                        }
                        Err(e) => {
                            error!("Error processing command: {}", e);
                        }
                    }
                }
            }
        }
    }
    
    /// Check for and execute incoming commands
    async fn check_and_execute_command(&mut self) -> Result<bool> {
        // Try to read a command from the communication channel
        match self.communication.read_command().await {
            Ok(Some(message)) => {
                debug!("Received command message");
                
                // Handle different message types
                match &message {
                    IncomingMessage::Metrics => {
                        // Immediate metrics collection request
                        info!("Received immediate metrics collection request");
                        match self.collect_and_send().await {
                            Ok(_) => info!("Immediate metrics sent successfully"),
                            Err(e) => error!("Failed to send immediate metrics: {}", e),
                        }
                    },
                    IncomingMessage::SafeCommand(_) | IncomingMessage::UnsafeCommand(_) => {
                        // Execute the command
                        match self.command_executor.execute(message).await {
                            Ok(response) => {
                                // Send the response back
                                self.communication.send_command_response(&response).await?;
                                info!("Command response sent: id={}, success={}", response.id, response.success);
                            },
                            Err(e) => {
                                error!("Command execution failed: {}", e);
                            }
                        }
                    }
                }
                
                Ok(true)
            },
            Ok(None) => {
                // No command available
                Ok(false)
            },
            Err(e) => {
                // Error reading command
                debug!("Error reading command (may be expected): {}", e);
                Ok(false)
            }
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
