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
    virtio_connected: bool,
    last_virtio_retry: Option<std::time::Instant>,
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
            virtio_connected: false,
            last_virtio_retry: None,
        }
    }

    
    /// Initialize the service
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing Infiniservice...");
        
        // Check if virtio-serial is available
        if !self.communication.is_available() {
            if self.config.require_virtio {
                return Err(anyhow::anyhow!(
                    "VirtIO device is required but not available at {:?}. Use --no-virtio to run without it.",
                    self.config.virtio_serial_path
                ));
            } else {
                warn!("Virtio-serial device not available at {:?}", self.config.virtio_serial_path);
                warn!("Service will continue in degraded mode - some features may be limited");
            }
        }
        
        // Try to connect to virtio-serial
        self.virtio_connected = match self.communication.connect().await {
            Ok(_) => {
                info!("VirtIO communication established successfully");
                true
            }
            Err(e) => {
                if self.config.require_virtio {
                    return Err(anyhow::anyhow!(
                        "VirtIO connection failed and is required: {}. Use --no-virtio to run without it.",
                        e
                    ));
                } else {
                    warn!("VirtIO connection failed but continuing anyway: {}", e);
                    warn!("Service will operate in degraded mode without VirtIO communication");
                    warn!("Metrics collection will continue but data transmission will be limited");
                    warn!("Will retry VirtIO connection every {} seconds", self.config.virtio_retry_interval);
                    false
                }
            }
        };
        
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
        let mut virtio_retry_interval = time::interval(Duration::from_secs(self.config.virtio_retry_interval));

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
                
                // Periodically retry VirtIO connection if not connected
                _ = virtio_retry_interval.tick() => {
                    if !self.virtio_connected && !self.config.require_virtio {
                        match self.retry_virtio_connection().await {
                            Ok(true) => {
                                info!("✅ VirtIO connection restored successfully!");
                                self.virtio_connected = true;
                            }
                            Ok(false) => {
                                debug!("VirtIO connection still not available, will retry later");
                            }
                            Err(e) => {
                                debug!("VirtIO connection retry failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Attempt to retry VirtIO connection
    async fn retry_virtio_connection(&mut self) -> Result<bool> {
        debug!("Attempting to retry VirtIO connection...");
        
        // Try to re-detect the device if auto-detection was used initially
        if self.config.virtio_serial_path.to_string_lossy().is_empty() {
            match VirtioSerial::detect_device_path(self.debug_mode) {
                Ok(device_path) => {
                    if device_path.to_string_lossy() != "__NO_VIRTIO_DEVICE__" {
                        debug!("Re-detected VirtIO device at: {:?}", device_path);
                        self.communication = VirtioSerial::new(device_path);
                    } else {
                        return Ok(false); // Still no device available
                    }
                }
                Err(_) => {
                    return Ok(false); // Detection still fails
                }
            }
        }
        
        // Try to connect
        match self.communication.connect().await {
            Ok(_) => {
                info!("VirtIO connection retry succeeded");
                Ok(true)
            }
            Err(e) => {
                debug!("VirtIO connection retry failed: {}", e);
                Ok(false)
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
        
        // Try to send data via virtio-serial
        match self.communication.send_data(&system_info).await {
            Ok(_) => {
                debug!("System metrics sent successfully via VirtIO");
                // Mark VirtIO as connected if it wasn't before
                if !self.virtio_connected {
                    self.virtio_connected = true;
                    info!("VirtIO connection restored during data transmission");
                }
                Ok(())
            }
            Err(e) => {
                if e.to_string().contains("VirtIO device not available") {
                    // VirtIO not available - this is expected in degraded mode
                    debug!("VirtIO not available - metrics collected but not transmitted");
                    self.virtio_connected = false;
                    if self.debug_mode {
                        debug!("Collected metrics: CPU: {:.1}%, Memory: {} MB", 
                               system_info.metrics.cpu.usage_percent,
                               system_info.metrics.memory.used_kb / 1024);
                    }
                    Ok(()) // Don't treat this as an error
                } else {
                    // Actual transmission error - VirtIO might have failed
                    self.virtio_connected = false;
                    Err(e)
                }
            }
        }
    }
}
