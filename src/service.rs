//! Main service implementation with command execution support

use crate::{Config, collector::{DataCollector, SystemInfo}, communication::VirtioSerial};
use crate::commands::{IncomingMessage, executor::CommandExecutor};
use anyhow::Result;
use log::{info, error, warn, debug};
use std::time::{Duration, SystemTime};
use std::path::PathBuf;
use std::collections::HashMap;
use tokio::time;
use tokio::select;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Connected,
    ConnectedPendingIPs,
    Disconnected,
    Retrying(u64),
    Monitoring,
    CircuitBreakerOpen,  // Connection blocked by circuit breaker
    Degraded,           // Operating in reduced functionality mode
    KeepAliveTimeout,   // Connection lost due to heartbeat failure
}

// Service-level diagnostic structures
#[derive(Debug, Clone)]
pub struct ConnectionDiagnostics {
    pub service_start_time: SystemTime,
    pub total_state_changes: u64,
    pub connection_stability_score: f64,
    pub last_successful_metrics_transmission: Option<SystemTime>,
    pub consecutive_failures: u64,
}

#[derive(Debug, Clone)]
pub struct StateChangeEvent {
    pub timestamp: SystemTime,
    pub from_state: ConnectionState,
    pub to_state: ConnectionState,
    pub trigger_reason: String,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ServiceMetrics {
    pub total_collections: u64,
    pub successful_transmissions: u64,
    pub failed_transmissions: u64,
    pub average_collection_time_ms: f64,
    pub health_check_count: u64,
    pub retry_attempts: u64,
    // Graceful Degradation fields
    pub degraded_mode_active: bool,              // Track if service is in degraded mode
    pub degraded_mode_start_time: Option<SystemTime>, // When degradation started
    pub keep_alive_failures: u64,               // Count of heartbeat failures
    pub circuit_breaker_trips: u64,             // Count of circuit breaker activations
}

pub struct InfiniService {
    config: Config,
    collector: DataCollector,
    communication: VirtioSerial,
    command_executor: CommandExecutor,
    debug_mode: bool,
    virtio_connected: bool,
    last_virtio_retry: Option<std::time::Instant>,
    elevation_guidance_logged: bool,
    virtio_backoff_secs: u64,
    connection_state: ConnectionState,
    last_device_path: Option<PathBuf>,
    device_monitor_handle: Option<tokio::task::JoinHandle<()>>,
    ip_retry_backoff_secs: u64,
    first_collection_completed: bool,
    initial_ip_fast_retry_started_at: Option<std::time::Instant>,
    // Enhanced service-level diagnostics
    connection_diagnostics: ConnectionDiagnostics,
    state_change_history: Vec<StateChangeEvent>,
    service_metrics: ServiceMetrics,
}

impl InfiniService {
    pub fn new(config: Config, debug_mode: bool) -> Self {
        let collector = DataCollector::new();
        
        if debug_mode {
            debug!("Initializing InfiniService in debug mode");
            debug!("Configuration path: {:?}", config.virtio_serial_path);
        }

        // Try to auto-detect virtio-serial device if not specified
        let (communication, initial_device_path) = if config.virtio_serial_path.to_string_lossy().is_empty() {
            if debug_mode {
                debug!("Attempting to auto-detect virtio-serial device...");
            }
            match VirtioSerial::detect_device_path(debug_mode) {
                Ok(device_path) => {
                    info!("Auto-detected virtio-serial device: {:?}", device_path);
                    let comm = VirtioSerial::with_config(&device_path, config.virtio_read_timeout_ms, config.virtio_ping_test_interval_secs);
                    (comm, Some(device_path))
                }
                Err(e) => {
                    warn!("Failed to auto-detect virtio-serial device: {}", e);
                    if debug_mode {
                        debug!("Detection error details: {:?}", e);
                    }
                    (VirtioSerial::with_config(&config.virtio_serial_path, config.virtio_read_timeout_ms, config.virtio_ping_test_interval_secs), None)
                }
            }
        } else {
            (VirtioSerial::with_config(&config.virtio_serial_path, config.virtio_read_timeout_ms, config.virtio_ping_test_interval_secs), Some(config.virtio_serial_path.clone()))
        };
        
        let command_executor = CommandExecutor::new()
            .expect("Failed to initialize command executor");

        Self {
            virtio_backoff_secs: config.virtio_min_backoff_secs,
            connection_state: ConnectionState::Disconnected,
            last_device_path: initial_device_path,
            device_monitor_handle: None,
            config,
            collector: collector.expect("DataCollector should initialize"),
            communication,
            command_executor,
            debug_mode,
            virtio_connected: false,
            last_virtio_retry: None,
            elevation_guidance_logged: false,
            ip_retry_backoff_secs: 5, // Start with 5 second retry for IP detection
            first_collection_completed: false,
            initial_ip_fast_retry_started_at: None,
            // Initialize service-level diagnostics
            connection_diagnostics: ConnectionDiagnostics {
                service_start_time: SystemTime::now(),
                total_state_changes: 0,
                connection_stability_score: 1.0,
                last_successful_metrics_transmission: None,
                consecutive_failures: 0,
            },
            state_change_history: Vec::new(),
            service_metrics: ServiceMetrics {
                total_collections: 0,
                successful_transmissions: 0,
                failed_transmissions: 0,
                average_collection_time_ms: 0.0,
                health_check_count: 0,
                retry_attempts: 0,
                // Graceful Degradation fields initialization
                degraded_mode_active: false,
                degraded_mode_start_time: None,
                keep_alive_failures: 0,
                circuit_breaker_trips: 0,
            },
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
                // Check if this is a privilege-related error
                #[cfg(target_os = "windows")]
                {
                    let error_message = e.to_string();
                    let mut privilege_issue = false;

                    // Check for Windows-specific error codes
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if let Some(raw_err) = io_err.raw_os_error() {
                            if crate::windows_com::detect_privilege_requirements(raw_err as u32, &error_message) {
                                privilege_issue = true;

                                // Use helper function for consistent error formatting
                                let formatted_error = self.format_privilege_aware_error(&e, "VirtIO connection failed");
                                error!("{}", formatted_error);

                                // Provide specific elevation guidance only once per session
                                if !self.elevation_guidance_logged {
                                    match crate::windows_com::get_elevation_guidance() {
                                        Ok(guidance) => {
                                            let log_level = if self.config.require_virtio { "error" } else { "warn" };
                                            for line in guidance {
                                                if log_level == "error" {
                                                    error!("{}", line);
                                                } else {
                                                    warn!("{}", line);
                                                }
                                            }
                                            self.elevation_guidance_logged = true;
                                        }
                                        Err(guidance_err) => {
                                            error!("Could not get elevation guidance: {}", guidance_err);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // If not a privilege issue, provide general diagnostic information
                    if !privilege_issue {
                        match crate::windows_com::diagnose_virtio_installation() {
                            Ok(diagnosis) => {
                                error!("VirtIO Diagnostic Information:\n{}", diagnosis);
                            }
                            Err(diag_err) => {
                                error!("Failed to get diagnostic information: {}", diag_err);
                            }
                        }
                    }
                }

                if self.config.require_virtio {
                    let error_msg = if cfg!(target_os = "windows") {
                        format!("VirtIO connection failed and is required: {}. Use --no-virtio to run without it. If you see privilege errors above, try running as administrator.", e)
                    } else {
                        format!("VirtIO connection failed and is required: {}. Use --no-virtio to run without it.", e)
                    };
                    return Err(anyhow::anyhow!(error_msg));
                } else {
                    warn!("VirtIO connection failed but continuing anyway: {}", e);
                    warn!("Service will operate in degraded mode without VirtIO communication");
                    warn!("Metrics collection will continue but data transmission will be limited");
                    warn!("Will retry VirtIO connection with exponential backoff ({}s → {}s)", self.config.virtio_min_backoff_secs, self.config.virtio_max_backoff_secs);

                    #[cfg(target_os = "windows")]
                    {
                        warn!("If connection issues persist, try running as administrator");
                    }

                    false
                }
            }
        };

        // Update connection state if not connected
        if !self.virtio_connected {
            self.emit_connection_state_change(ConnectionState::Disconnected).await;
        }

        info!("Infiniservice initialized successfully");
        Ok(())
    }
    
    /// Run the main service loop with command handling
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Infiniservice main loop with command support");
        info!("Service will collect metrics every {} seconds", self.config.collection_interval);
        info!("Command execution is ENABLED - both safe and unsafe commands supported");

        // Graceful Degradation: Dynamic interval adjustment based on connection quality
        let mut current_collection_interval = self.config.collection_interval;
        let mut interval = time::interval(Duration::from_secs(current_collection_interval));
        let mut command_check_interval = time::interval(Duration::from_millis(500)); // Check for commands every 500ms
        let mut health_check_interval = time::interval(Duration::from_secs(self.config.virtio_health_check_interval_secs)); // Periodic health checks
        let mut keep_alive_interval = time::interval(Duration::from_secs(self.config.keep_alive_interval_secs)); // Keep-alive heartbeats

        // Initialize device monitoring if enabled
        if self.config.enable_device_monitoring {
            let (device_change_tx, mut device_change_rx) = tokio::sync::mpsc::channel::<()>(10);
            self.device_monitor_handle = Some(self.spawn_device_monitor(device_change_tx).await);
            let mut monitoring_active = true;

            // Add device change monitoring to the select loop
            loop {
                select! {
                    // Periodic metrics collection or fast retry for initial IP collection
                    _ = interval.tick() => {
                        let should_use_fast_retry = !self.first_collection_completed &&
                            !self.collector.is_initial_ip_collection_successful();

                        if should_use_fast_retry {
                            // Start fast retry timer if not already started
                            if self.initial_ip_fast_retry_started_at.is_none() {
                                self.initial_ip_fast_retry_started_at = Some(std::time::Instant::now());
                                info!("Starting fast retry for initial IP collection (every 5 seconds for 2 minutes)");
                                interval = time::interval(Duration::from_secs(5));
                            }
                        }

                        // Check if we should exit fast retry mode
                        let fast_retry_window_elapsed = self.initial_ip_fast_retry_started_at
                            .map(|t| t.elapsed() >= Duration::from_secs(120))
                            .unwrap_or(false);

                        let should_exit_fast_retry = self.collector.is_initial_ip_collection_successful() || fast_retry_window_elapsed;

                        if should_exit_fast_retry && !self.first_collection_completed {
                            info!("Transitioning from fast retry to normal collection interval (success: {}, elapsed: {})",
                                  self.collector.is_initial_ip_collection_successful(), fast_retry_window_elapsed);
                            interval = time::interval(Duration::from_secs(self.config.collection_interval));
                            self.first_collection_completed = true;
                        }

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

                    // Periodic connection health check
                    _ = health_check_interval.tick(), if self.config.enable_connection_validation => {
                        if self.virtio_connected {
                            self.service_metrics.health_check_count += 1;
                            if !self.communication.check_connection_health() {
                                warn!("Connection health check failed - marking as disconnected");
                                self.virtio_connected = false;
                                self.emit_connection_state_change(ConnectionState::Disconnected).await;
                            } else {
                                debug!("Connection health check passed");
                            }
                        }
                    }

                    // Keep-alive heartbeat management
                    _ = keep_alive_interval.tick(), if self.virtio_connected => {
                        // Check for keep-alive timeout first
                        if self.communication.check_keep_alive_timeout(self.config.keep_alive_timeout_secs) {
                            warn!("Keep-alive timeout detected - connection lost");
                            self.virtio_connected = false;
                            self.service_metrics.keep_alive_failures += 1;
                            self.emit_connection_state_change(ConnectionState::KeepAliveTimeout).await;
                        } else if self.communication.should_send_keep_alive(
                            self.config.keep_alive_interval_secs,
                            self.config.connection_idle_timeout_secs
                        ) {
                            match self.communication.send_keep_alive().await {
                                Ok(_) => {
                                    debug!("Keep-alive heartbeat sent successfully");
                                }
                                Err(e) => {
                                    warn!("Failed to send keep-alive: {}", e);
                                    // Don't immediately disconnect, let health check handle it
                                }
                            }
                        }
                    }

                    // Handle device change notifications
                    msg = device_change_rx.recv(), if monitoring_active => {
                        match msg {
                            Some(_) => {
                                info!("🔄 Device change detected, attempting immediate reconnection");
                                self.virtio_backoff_secs = self.config.virtio_min_backoff_secs; // Reset backoff
                                self.emit_connection_state_change(ConnectionState::Monitoring).await;

                                match self.retry_virtio_connection().await {
                                    Ok(true) => {
                                        info!("✅ VirtIO connection restored after device change!");
                                        self.virtio_connected = true;
                                        // Don't override connection state - retry_virtio_connection sets it appropriately
                                    }
                                    Ok(false) => {
                                        debug!("VirtIO connection still not available after device change");
                                    }
                                    Err(e) => {
                                        debug!("VirtIO connection retry failed after device change: {}", e);
                                    }
                                }
                            }
                            None => {
                                warn!("Device monitor channel closed, disabling monitoring");
                                monitoring_active = false;
                            }
                        }
                    }

                    // Dynamic backoff retry for VirtIO connection
                    _ = time::sleep(Duration::from_secs(self.virtio_backoff_secs)), if !self.virtio_connected && !self.config.require_virtio => {
                        match self.retry_virtio_connection().await {
                            Ok(true) => {
                                info!("✅ VirtIO connection restored successfully!");
                                self.virtio_connected = true;
                                self.virtio_backoff_secs = self.config.virtio_min_backoff_secs; // Reset backoff
                                // Don't override connection state - retry_virtio_connection sets it appropriately
                            }
                            Ok(false) => {
                                // Double the backoff, up to maximum
                                self.virtio_backoff_secs = std::cmp::min(
                                    self.virtio_backoff_secs * 2,
                                    self.config.virtio_max_backoff_secs
                                );
                                self.emit_connection_state_change(ConnectionState::Retrying(self.virtio_backoff_secs)).await;
                                debug!("VirtIO connection still not available, will retry in {}s", self.virtio_backoff_secs);
                            }
                            Err(e) => {
                                // Double the backoff on error too
                                self.virtio_backoff_secs = std::cmp::min(
                                    self.virtio_backoff_secs * 2,
                                    self.config.virtio_max_backoff_secs
                                );
                                self.emit_connection_state_change(ConnectionState::Retrying(self.virtio_backoff_secs)).await;
                                debug!("VirtIO connection retry failed: {}, will retry in {}s", e, self.virtio_backoff_secs);
                            }
                        }
                    }
                }
            }
        } else {
            // Fallback to simple loop without device monitoring
            loop {
                select! {
                    // Periodic metrics collection or fast retry for initial IP collection
                    _ = interval.tick() => {
                        let should_use_fast_retry = !self.first_collection_completed &&
                            !self.collector.is_initial_ip_collection_successful();

                        if should_use_fast_retry {
                            // Start fast retry timer if not already started
                            if self.initial_ip_fast_retry_started_at.is_none() {
                                self.initial_ip_fast_retry_started_at = Some(std::time::Instant::now());
                                info!("Starting fast retry for initial IP collection (every 5 seconds for 2 minutes)");
                                interval = time::interval(Duration::from_secs(5));
                            }
                        }

                        // Check if we should exit fast retry mode
                        let fast_retry_window_elapsed = self.initial_ip_fast_retry_started_at
                            .map(|t| t.elapsed() >= Duration::from_secs(120))
                            .unwrap_or(false);

                        let should_exit_fast_retry = self.collector.is_initial_ip_collection_successful() || fast_retry_window_elapsed;

                        if should_exit_fast_retry && !self.first_collection_completed {
                            info!("Transitioning from fast retry to normal collection interval (success: {}, elapsed: {})",
                                  self.collector.is_initial_ip_collection_successful(), fast_retry_window_elapsed);
                            interval = time::interval(Duration::from_secs(self.config.collection_interval));
                            self.first_collection_completed = true;
                        }

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

                    // Periodic connection health check
                    _ = health_check_interval.tick(), if self.config.enable_connection_validation => {
                        if self.virtio_connected {
                            self.service_metrics.health_check_count += 1;
                            if !self.communication.check_connection_health() {
                                warn!("Connection health check failed - marking as disconnected");
                                self.virtio_connected = false;
                                self.emit_connection_state_change(ConnectionState::Disconnected).await;
                            } else {
                                debug!("Connection health check passed");
                            }
                        }
                    }

                    // Keep-alive heartbeat management
                    _ = keep_alive_interval.tick(), if self.virtio_connected => {
                        // Check for keep-alive timeout first
                        if self.communication.check_keep_alive_timeout(self.config.keep_alive_timeout_secs) {
                            warn!("Keep-alive timeout detected - connection lost");
                            self.virtio_connected = false;
                            self.service_metrics.keep_alive_failures += 1;
                            self.emit_connection_state_change(ConnectionState::KeepAliveTimeout).await;
                        } else if self.communication.should_send_keep_alive(
                            self.config.keep_alive_interval_secs,
                            self.config.connection_idle_timeout_secs
                        ) {
                            match self.communication.send_keep_alive().await {
                                Ok(_) => {
                                    debug!("Keep-alive heartbeat sent successfully");
                                }
                                Err(e) => {
                                    warn!("Failed to send keep-alive: {}", e);
                                    // Don't immediately disconnect, let health check handle it
                                }
                            }
                        }
                    }

                    // Dynamic backoff retry for VirtIO connection
                    _ = time::sleep(Duration::from_secs(self.virtio_backoff_secs)), if !self.virtio_connected && !self.config.require_virtio => {
                        match self.retry_virtio_connection().await {
                            Ok(true) => {
                                info!("✅ VirtIO connection restored successfully!");
                                self.virtio_connected = true;
                                self.virtio_backoff_secs = self.config.virtio_min_backoff_secs; // Reset backoff
                                // Don't override connection state - retry_virtio_connection sets it appropriately
                            }
                            Ok(false) => {
                                // Double the backoff, up to maximum
                                self.virtio_backoff_secs = std::cmp::min(
                                    self.virtio_backoff_secs * 2,
                                    self.config.virtio_max_backoff_secs
                                );
                                self.emit_connection_state_change(ConnectionState::Retrying(self.virtio_backoff_secs)).await;
                                debug!("VirtIO connection still not available, will retry in {}s", self.virtio_backoff_secs);
                            }
                            Err(e) => {
                                // Double the backoff on error too
                                self.virtio_backoff_secs = std::cmp::min(
                                    self.virtio_backoff_secs * 2,
                                    self.config.virtio_max_backoff_secs
                                );
                                self.emit_connection_state_change(ConnectionState::Retrying(self.virtio_backoff_secs)).await;
                                debug!("VirtIO connection retry failed: {}, will retry in {}s", e, self.virtio_backoff_secs);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Shutdown the service and cleanup resources
    async fn shutdown(&mut self) {
        if let Some(handle) = self.device_monitor_handle.take() {
            handle.abort();
            let _ = handle.await;
            debug!("Device monitor task cleaned up");
        }
    }
    
    /// Attempt to retry VirtIO connection with persistent connection cleanup
    async fn retry_virtio_connection(&mut self) -> Result<bool> {
        debug!("Attempting to retry VirtIO connection...");

        // Intelligent Reconnection: Check circuit breaker state before attempting reconnection
        let circuit_state = {
            let state = self.communication.circuit_breaker_state().read().unwrap();
            state.clone()
        };

        match circuit_state {
            crate::communication::CircuitBreakerState::Open => {
                debug!("Circuit breaker is OPEN - skipping reconnection attempt");
                self.emit_connection_state_change(ConnectionState::CircuitBreakerOpen).await;
                return Ok(false);
            },
            crate::communication::CircuitBreakerState::HalfOpen => {
                debug!("Circuit breaker is HALF-OPEN - proceeding with cautious reconnection");
            },
            crate::communication::CircuitBreakerState::Closed => {
                debug!("Circuit breaker is CLOSED - proceeding with normal reconnection");
            }
        }

        // Use connection quality history to determine reconnection strategy
        let connection_quality = self.communication.connection_quality();

        // Check if connection quality falls below threshold for degradation
        let quality_threshold = match self.config.quality_threshold_for_degradation.as_str() {
            "excellent" => crate::communication::ConnectionQuality::Excellent,
            "good" => crate::communication::ConnectionQuality::Good,
            "fair" => crate::communication::ConnectionQuality::Good, // Fair maps to Good
            "poor" => crate::communication::ConnectionQuality::Poor,
            "critical" => crate::communication::ConnectionQuality::Critical,
            _ => crate::communication::ConnectionQuality::Poor, // Default to poor
        };

        // Switch to degraded mode if quality falls below threshold
        let should_degrade = match (&connection_quality, &quality_threshold) {
            (crate::communication::ConnectionQuality::Critical, _) => true,
            (crate::communication::ConnectionQuality::Poor, crate::communication::ConnectionQuality::Good) |
            (crate::communication::ConnectionQuality::Poor, crate::communication::ConnectionQuality::Excellent) => true,
            _ => false,
        };

        if should_degrade && !self.service_metrics.degraded_mode_active {
            warn!("🔻 Connection quality ({:?}) below threshold ({:?}) - entering degraded mode", connection_quality, quality_threshold);
            self.service_metrics.degraded_mode_active = true;
            self.service_metrics.degraded_mode_start_time = Some(SystemTime::now());
            self.emit_connection_state_change(ConnectionState::Degraded).await;

            // Adjust collection interval for degraded mode (longer intervals)
            self.current_collection_interval = (self.config.collection_interval * 2).max(30);
            info!("📉 Degraded mode: Increased collection interval to {}s", self.current_collection_interval);
        } else if !should_degrade && self.service_metrics.degraded_mode_active {
            info!("🔺 Connection quality ({:?}) restored above threshold - exiting degraded mode", connection_quality);
            self.service_metrics.degraded_mode_active = false;
            self.service_metrics.degraded_mode_start_time = None;

            // Restore normal collection interval
            self.current_collection_interval = self.config.collection_interval;
            info!("📈 Normal mode: Restored collection interval to {}s", self.current_collection_interval);
        }

        // Implement adaptive backoff based on connection quality and failure patterns
        let base_delay = match connection_quality {
            crate::communication::ConnectionQuality::Critical => {
                // Use maximum backoff for critical quality
                self.config.virtio_max_backoff_secs
            },
            crate::communication::ConnectionQuality::Poor => {
                // Use longer backoff for poor quality
                (self.config.virtio_reconnect_base_delay_secs * 3).min(self.config.virtio_max_backoff_secs)
            },
            crate::communication::ConnectionQuality::Good => {
                // Use moderate backoff for good quality
                (self.config.virtio_reconnect_base_delay_secs * 2).min(self.config.virtio_max_backoff_secs)
            },
            crate::communication::ConnectionQuality::Excellent => {
                // Use minimal backoff for excellent quality
                self.config.virtio_reconnect_base_delay_secs
            }
        };

        // Check if enough time has passed since last connection attempt based on quality
        let consecutive_failures = self.connection_diagnostics.consecutive_failures;
        if consecutive_failures > 0 {
            let backoff_multiplier = (consecutive_failures.min(5) as u64); // Cap at 5x
            let adjusted_delay = (base_delay * backoff_multiplier).min(self.config.virtio_max_backoff_secs);

            debug!("Using adaptive backoff: base={}s, failures={}, multiplier={}x, final={}s",
                   base_delay, consecutive_failures, backoff_multiplier, adjusted_delay);

            if let Some(last_attempt) = self.connection_diagnostics.last_successful_metrics_transmission {
                let time_since_last = SystemTime::now().duration_since(last_attempt).unwrap_or_default();
                if time_since_last.as_secs() < adjusted_delay {
                    debug!("Adaptive backoff not satisfied yet, skipping reconnection attempt");
                    return Ok(false);
                }
            }
        }

        // Disconnect existing connection before attempting reconnection
        self.communication.disconnect();

        // Try to re-detect the device if auto-detection was used initially
        if self.config.virtio_serial_path.to_string_lossy().is_empty() {
            match VirtioSerial::detect_device_path(self.debug_mode) {
                Ok(device_path) => {
                    if device_path.to_string_lossy() != "__NO_VIRTIO_DEVICE__" {
                        // Check if device path changed
                        let device_changed = self.last_device_path.as_ref() != Some(&device_path);
                        if device_changed {
                            debug!("Device path changed: {:?} -> {:?}", self.last_device_path, device_path);
                            self.last_device_path = Some(device_path.clone());
                        }

                        debug!("Re-detected VirtIO device at: {:?}", device_path);
                        self.communication = VirtioSerial::with_config(device_path, self.config.virtio_read_timeout_ms, self.config.virtio_ping_test_interval_secs);
                    } else {
                        if self.last_device_path.is_some() {
                            debug!("Device disappeared: {:?} -> None", self.last_device_path);
                            self.last_device_path = None;
                        }
                        return Ok(false); // Still no device available
                    }
                }
                Err(_) => {
                    if self.last_device_path.is_some() {
                        debug!("Device detection failed, assuming device disappeared");
                        self.last_device_path = None;
                    }
                    return Ok(false); // Detection still fails
                }
            }
        }

        // Try to establish persistent connection
        match self.communication.connect().await {
            Ok(_) => {
                info!("VirtIO persistent connection retry succeeded");

                // Validate connection health
                self.service_metrics.health_check_count += 1;
                if self.communication.check_connection_health() {
                    info!("Connection health check passed");

                    // Try immediate metrics transmission to verify the connection works
                    match self.collector.collect().await {
                        Ok(system_info) => {
                            // Use try_send_once for strict verification
                            match self.communication.try_send_once(&system_info).await {
                                Ok(_) => {
                                    // Verify that the transmitted data includes IP information
                                    let up_interfaces_with_ips = system_info.metrics.network.interfaces.iter()
                                        .filter(|iface| iface.is_up && !iface.ip_addresses.is_empty())
                                        .count();

                                    if up_interfaces_with_ips > 0 {
                                        info!("Initial metrics sent successfully with {} UP interfaces - connection fully verified", up_interfaces_with_ips);
                                        Ok(true)
                                    } else {
                                        warn!("Initial metrics sent but no UP interfaces with IPs detected");
                                        // Mark connection as pending IPs
                                        self.emit_connection_state_change(ConnectionState::ConnectedPendingIPs).await;
                                        Ok(true) // Connection is established, just no IPs yet
                                    }
                                }
                                Err(e) => {
                                    warn!("Initial metrics transmission failed after connection: {}", e);
                                    // Return false because transmission verification failed
                                    Ok(false)
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to collect metrics for connection verification: {}", e);
                            Ok(false)
                        }
                    }
                } else {
                    warn!("Connection health check failed after successful connect");
                    Ok(false)
                }
            }
            Err(e) => {
                debug!("VirtIO connection retry failed: {}", e);

                // Check if this is a privilege-related error and provide guidance
                #[cfg(target_os = "windows")]
                {
                    let error_message = e.to_string();
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if let Some(raw_err) = io_err.raw_os_error() {
                            if crate::windows_com::detect_privilege_requirements(raw_err as u32, &error_message) {
                                // Use helper function for consistent error formatting
                                let formatted_error = self.format_privilege_aware_error(&e, "VirtIO connection retry failed");
                                warn!("{}", formatted_error);

                                // Provide brief guidance for retry scenarios only if not already logged
                                if !self.elevation_guidance_logged {
                                    let brief_instructions = Self::get_brief_elevation_instructions();
                                    for instruction in brief_instructions {
                                        warn!("{}", instruction);
                                    }
                                    self.elevation_guidance_logged = true;
                                }
                            }
                        }
                    }
                }

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
                // Error reading command - only log occasionally to avoid spam
                use std::sync::LazyLock;
                static LOG_STATE: LazyLock<std::sync::Mutex<(std::time::Instant, u32)>> =
                    LazyLock::new(|| std::sync::Mutex::new((std::time::Instant::now(), 0)));

                if let Ok(mut state) = LOG_STATE.lock() {
                    state.1 += 1; // Increment counter
                    let now = std::time::Instant::now();

                    // Only log every 60 seconds or every 1000 errors, whichever comes first
                    if now.duration_since(state.0).as_secs() >= 60 || state.1 >= 1000 {
                        debug!("Error reading command (may be expected, {} occurrences in last interval): {}", state.1, e);
                        state.0 = now;
                        state.1 = 0;
                    }
                }
                Ok(false)
            }
        }
    }

    
    /// Collect data and send it via persistent VirtIO connection
    /// Returns Ok(true) if data was successfully transmitted, Ok(false) if collected but not transmitted
    async fn collect_and_send(&mut self) -> Result<bool> {
        let collection_start = std::time::Instant::now();

        // Collect system information
        let system_info = match self.collector.collect().await {
            Ok(info) => info,
            Err(e) => {
                let collection_time_ms = collection_start.elapsed().as_millis() as f64;
                self.update_collection_metrics(collection_time_ms, false, false);
                return Err(e);
            }
        };

        let collection_time_ms = collection_start.elapsed().as_millis() as f64;

        // Send collected data and track transmission result
        match self.send_collected_data(&system_info).await {
            Ok(transmitted) => {
                self.update_collection_metrics(collection_time_ms, true, transmitted);
                if transmitted {
                    self.connection_diagnostics.last_successful_metrics_transmission = Some(SystemTime::now());
                }
                Ok(transmitted)
            }
            Err(e) => {
                self.update_collection_metrics(collection_time_ms, true, false);
                Err(e)
            }
        }
    }

    /// Send already collected SystemInfo data via persistent VirtIO connection
    /// Returns Ok(true) if data was successfully transmitted, Ok(false) if collected but not transmitted
    async fn send_collected_data(&mut self, system_info: &SystemInfo) -> Result<bool> {

        // Log interface statistics
        let total_interfaces = system_info.metrics.network.interfaces.len();
        let up_interfaces_with_ips = system_info.metrics.network.interfaces.iter()
            .filter(|iface| iface.is_up && !iface.ip_addresses.is_empty())
            .count();

        debug!("Collected metrics: {} total interfaces, {} UP with IPs",
               total_interfaces, up_interfaces_with_ips);

        if up_interfaces_with_ips == 0 && total_interfaces > 0 {
            warn!("Metrics collected but no UP interfaces with IP addresses detected");
        }

        // Track previous connection state to detect changes
        let was_connected = self.virtio_connected;

        // Try to send data via virtio-serial using persistent connection
        match self.communication.send_data(system_info).await {
            Ok(_) => {
                info!("System metrics sent successfully via persistent VirtIO connection (interfaces: {}, UP with IPs: {})",
                      total_interfaces, up_interfaces_with_ips);

                // Mark VirtIO as connected if it wasn't before
                if !self.virtio_connected {
                    self.virtio_connected = true;
                    info!("VirtIO persistent connection restored during data transmission");
                }

                // Update connection state based on IP availability
                if up_interfaces_with_ips > 0 {
                    if self.connection_state != ConnectionState::Connected {
                        self.emit_connection_state_change(ConnectionState::Connected).await;
                    }
                } else if self.connection_state == ConnectionState::Connected {
                    // Had IPs before but not now, transition to pending
                    self.emit_connection_state_change(ConnectionState::ConnectedPendingIPs).await;
                }

                Ok(true) // Data was successfully transmitted
            }
            Err(e) => {
                let error_msg = e.to_string();

                if error_msg.contains("VirtIO device not available") {
                    // VirtIO not available - this is expected in degraded mode
                    debug!("VirtIO not available - metrics collected but not transmitted");
                    if was_connected {
                        self.virtio_connected = false;
                        self.emit_connection_state_change(ConnectionState::Disconnected).await;
                    }
                    if self.debug_mode {
                        debug!("Collected metrics: CPU: {:.1}%, Memory: {} MB",
                               system_info.metrics.cpu.usage_percent,
                               system_info.metrics.memory.used_kb / 1024);
                    }
                    Ok(false) // Don't treat this as an error - data collected but not transmitted
                } else if error_msg.contains("VirtIO connection not established") {
                    // Connection not established - mark as disconnected and trigger reconnection
                    debug!("VirtIO connection not established - marking as disconnected");
                    if was_connected {
                        self.virtio_connected = false;
                        self.emit_connection_state_change(ConnectionState::Disconnected).await;
                    }
                    Ok(false) // Don't treat this as an error - data collected but not transmitted - let retry logic handle it
                } else if error_msg.contains("VirtIO connection broken") {
                    // Connection broken during transmission - mark as disconnected
                    warn!("VirtIO connection broken during transmission: {}", e);
                    if was_connected {
                        self.virtio_connected = false;
                        self.emit_connection_state_change(ConnectionState::Disconnected).await;
                    }
                    Ok(false) // Don't treat this as an error - data collected but not transmitted - let retry logic handle reconnection
                } else {
                    // Other transmission errors - simplified error handling for persistent connections
                    if was_connected {
                        self.virtio_connected = false;
                        self.emit_connection_state_change(ConnectionState::Disconnected).await;
                    }
                    debug!("VirtIO transmission error (will retry): {}", e);

                    // For persistent connections, most errors are recoverable
                    // The retry logic will handle reconnection
                    Ok(false)
                }
            }
        }
    }

    /// Emit connection state change notifications
    async fn emit_connection_state_change(&mut self, new_state: ConnectionState) {
        if self.connection_state != new_state {
            let old_state = self.connection_state.clone();
            self.connection_state = new_state.clone();

            // Update service-level diagnostics
            self.update_service_diagnostics(&old_state, &new_state).await;

            let (state_str, details) = match &new_state {
                ConnectionState::Connected => {
                    info!("✅ VirtIO connection established with IP data");
                    ("connected", "VirtIO connection established with IP data successfully")
                }
                ConnectionState::ConnectedPendingIPs => {
                    warn!("⚠️ VirtIO connection established but no IP addresses detected");
                    ("connected_pending_ips", "VirtIO connection established but waiting for IP addresses")
                }
                ConnectionState::Disconnected => {
                    warn!("❌ VirtIO connection lost");
                    ("disconnected", "VirtIO connection lost")
                }
                ConnectionState::Retrying(backoff_secs) => {
                    warn!("⚠️ VirtIO connection failed, retrying in {}s", backoff_secs);
                    self.service_metrics.retry_attempts += 1;
                    ("retrying", "Retrying connection")
                }
                ConnectionState::Monitoring => {
                    info!("🔄 Monitoring for device changes");
                    ("monitoring", "Monitoring for device changes")
                }
                ConnectionState::CircuitBreakerOpen => {
                    warn!("🔴 Circuit breaker OPEN - connection blocked");
                    self.service_metrics.circuit_breaker_trips += 1;
                    ("circuit_breaker_open", "Circuit breaker open - blocking connections for recovery")
                }
                ConnectionState::Degraded => {
                    warn!("⚠️ Service operating in DEGRADED mode");
                    ("degraded", "Service operating with reduced functionality due to connection issues")
                }
                ConnectionState::KeepAliveTimeout => {
                    warn!("💔 Keep-alive timeout - connection lost");
                    self.service_metrics.keep_alive_failures += 1;
                    ("keep_alive_timeout", "Connection lost due to keep-alive timeout")
                }
            };

            debug!("Connection state changed: {:?} -> {:?}", old_state, new_state);

            // Send connection status to host
            if let Err(e) = self.communication.send_connection_status(state_str, details).await {
                debug!("Failed to send connection status to host: {}", e);
            }
        }
    }

    /// Spawn device monitoring task
    async fn spawn_device_monitor(&self, tx: tokio::sync::mpsc::Sender<()>) -> tokio::task::JoinHandle<()> {
        let debug_mode = self.debug_mode;

        tokio::spawn(async move {
            #[cfg(target_os = "linux")]
            {
                Self::linux_device_monitor(tx, debug_mode).await;
            }

            #[cfg(target_os = "windows")]
            {
                Self::windows_device_monitor(tx, debug_mode).await;
            }
        })
    }

    /// Linux device monitoring implementation
    #[cfg(target_os = "linux")]
    async fn linux_device_monitor(tx: tokio::sync::mpsc::Sender<()>, debug_mode: bool) {
        use notify::{Watcher, RecursiveMode, EventKind};
        use std::sync::mpsc;
        use std::time::Instant;

        let (file_tx, file_rx) = mpsc::channel();

        let mut watcher = match notify::recommended_watcher(file_tx) {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        let watch_path = std::path::Path::new("/dev/virtio-ports/");
        if let Err(e) = watcher.watch(watch_path, RecursiveMode::NonRecursive) {
            if debug_mode {
                debug!("Could not watch /dev/virtio-ports/: {}", e);
            }
            // Fallback to polling
            Self::polling_device_monitor(tx, debug_mode, Duration::from_secs(30)).await;
            return;
        }

        info!("📡 Linux device monitoring started for /dev/virtio-ports/");

        loop {
            match file_rx.try_recv() {
                Ok(Ok(event)) => {
                    if let EventKind::Create(_) | EventKind::Remove(_) = event.kind {
                        if debug_mode {
                            debug!("Device change detected: {:?}", event);
                        }

                        // Initialize debounce window
                        let debounce = Duration::from_millis(350);
                        let mut deadline = Instant::now() + debounce;

                        // Coalesce events within the debounce window
                        loop {
                            match file_rx.try_recv() {
                                Ok(Ok(inner_event)) => {
                                    if let EventKind::Create(_) | EventKind::Remove(_) = inner_event.kind {
                                        if debug_mode {
                                            debug!("Additional device change detected during debounce: {:?}", inner_event);
                                        }
                                        // Extend the debounce window
                                        deadline = Instant::now() + debounce;
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!("File watcher error during debounce: {}", e);
                                    break;
                                }
                                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                    // Channel disconnected, exit both loops
                                    return;
                                }
                                Err(std::sync::mpsc::TryRecvError::Empty) => {
                                    // No more events, check if debounce window has expired
                                    let now = Instant::now();
                                    if now >= deadline {
                                        // Window has been quiet long enough, break to send notification
                                        break;
                                    } else {
                                        // Sleep for a short time or until deadline, whichever is shorter
                                        let remaining = deadline - now;
                                        let sleep_duration = std::cmp::min(Duration::from_millis(50), remaining);
                                        tokio::time::sleep(sleep_duration).await;
                                    }
                                }
                            }
                        }

                        // Send consolidated notification after debounce window
                        if let Err(_) = tx.send(()).await {
                            break; // Main service has shut down
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("File watcher error: {}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(_) => {
                    // No events, sleep briefly
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Windows device monitoring implementation
    #[cfg(target_os = "windows")]
    async fn windows_device_monitor(tx: tokio::sync::mpsc::Sender<()>, debug_mode: bool) {
        info!("📡 Windows device monitoring started (polling every 30s)");
        Self::polling_device_monitor(tx, debug_mode, Duration::from_secs(30)).await;
    }

    /// Fallback polling device monitor for both platforms
    async fn polling_device_monitor(tx: tokio::sync::mpsc::Sender<()>, debug_mode: bool, interval: Duration) {
        let mut last_device_path: Option<PathBuf> = None;

        loop {
            tokio::time::sleep(interval).await;

            // Try to detect current device path
            match VirtioSerial::detect_device_path(debug_mode) {
                Ok(current_path) => {
                    if current_path.to_string_lossy() != "__NO_VIRTIO_DEVICE__" {
                        let current_path = Some(current_path);
                        if last_device_path != current_path {
                            if debug_mode {
                                debug!("Device path changed: {:?} -> {:?}", last_device_path, current_path);
                            }
                            last_device_path = current_path;
                            if let Err(_) = tx.send(()).await {
                                break; // Main service has shut down
                            }
                        }
                    } else if last_device_path.is_some() {
                        // Device disappeared
                        if debug_mode {
                            debug!("Device disappeared: {:?} -> None", last_device_path);
                        }
                        last_device_path = None;
                        if let Err(_) = tx.send(()).await {
                            break; // Main service has shut down
                        }
                    }
                }
                Err(_) => {
                    if last_device_path.is_some() {
                        // Device detection failed, assume device disappeared
                        if debug_mode {
                            debug!("Device detection failed, assuming device disappeared");
                        }
                        last_device_path = None;
                        if let Err(_) = tx.send(()).await {
                            break; // Main service has shut down
                        }
                    }
                }
            }
        }
    }
}

/// Helper functions for privilege-aware error handling
#[cfg(target_os = "windows")]
impl InfiniService {
    /// Format error message with privilege context
    fn format_privilege_aware_error(&self, error: &anyhow::Error, context: &str) -> String {
        let error_message = error.to_string();

        // Check if this is a privilege-related error
        if let Some(io_err) = error.downcast_ref::<std::io::Error>() {
            if let Some(raw_err) = io_err.raw_os_error() {
                if crate::windows_com::detect_privilege_requirements(raw_err as u32, &error_message) {
                    return format!(
                        "{}: {} (Administrator privileges may be required - try running as administrator)",
                        context, error_message
                    );
                }
            }
        }

        format!("{}: {}", context, error_message)
    }

    /// Get brief elevation instructions for error messages
    fn get_brief_elevation_instructions() -> Vec<String> {
        vec![
            "To run with administrator privileges:".to_string(),
            "  • Right-click infiniservice.exe → 'Run as administrator'".to_string(),
            "  • Or use: runas /user:Administrator infiniservice.exe".to_string(),
            "  • For persistent access: Install as Windows service".to_string(),
        ]
    }
}

impl InfiniService {
    // Helper methods for enhanced diagnostics
    async fn update_service_diagnostics(&mut self, from_state: &ConnectionState, to_state: &ConnectionState) {
        // Track state change
        self.connection_diagnostics.total_state_changes += 1;

        // Record state change in history (bounded to prevent memory growth)
        let state_change_event = StateChangeEvent {
            timestamp: SystemTime::now(),
            from_state: from_state.clone(),
            to_state: to_state.clone(),
            trigger_reason: self.determine_state_change_reason(from_state, to_state),
            context: {
                let mut context = HashMap::new();
                context.insert("virtio_connected".to_string(), self.virtio_connected.to_string());
                context.insert("total_collections".to_string(), self.service_metrics.total_collections.to_string());
                context.insert("consecutive_failures".to_string(), self.connection_diagnostics.consecutive_failures.to_string());
                context
            },
        };

        // Maintain bounded history (keep last 100 state changes)
        self.state_change_history.push(state_change_event);
        if self.state_change_history.len() > 100 {
            self.state_change_history.remove(0);
        }

        // Update connection stability score based on state transitions
        self.update_connection_stability_score(from_state, to_state);

        // Handle specific state transitions
        match to_state {
            ConnectionState::Connected => {
                self.connection_diagnostics.consecutive_failures = 0;
                self.connection_diagnostics.last_successful_metrics_transmission = Some(SystemTime::now());
            }
            ConnectionState::Disconnected => {
                self.connection_diagnostics.consecutive_failures += 1;
            }
            ConnectionState::Retrying(_) => {
                // Retry attempts already tracked in emit_connection_state_change
            }
            _ => {}
        }

        // Log periodic health summary (every 50 state changes)
        if self.connection_diagnostics.total_state_changes % 50 == 0 {
            self.log_service_health_summary();
        }
    }

    fn update_connection_stability_score(&mut self, from_state: &ConnectionState, to_state: &ConnectionState) {
        // Calculate stability based on transition patterns
        let transition_penalty = match (from_state, to_state) {
            (ConnectionState::Connected, ConnectionState::Disconnected) => -0.1,
            (ConnectionState::Connected, ConnectionState::ConnectedPendingIPs) => -0.05,
            (ConnectionState::Disconnected, ConnectionState::Connected) => 0.1,
            (ConnectionState::ConnectedPendingIPs, ConnectionState::Connected) => 0.05,
            (_, ConnectionState::Retrying(_)) => -0.02,
            _ => 0.0,
        };

        // Apply penalty/bonus and bound to [0.0, 1.0]
        self.connection_diagnostics.connection_stability_score =
            (self.connection_diagnostics.connection_stability_score + transition_penalty).max(0.0).min(1.0);
    }

    fn update_collection_metrics(&mut self, collection_time_ms: f64, success: bool, transmitted: bool) {
        self.service_metrics.total_collections += 1;

        // Update average collection time using exponential moving average
        if self.service_metrics.average_collection_time_ms == 0.0 {
            self.service_metrics.average_collection_time_ms = collection_time_ms;
        } else {
            self.service_metrics.average_collection_time_ms =
                self.service_metrics.average_collection_time_ms * 0.9 + collection_time_ms * 0.1;
        }

        if success && transmitted {
            self.service_metrics.successful_transmissions += 1;
        } else {
            self.service_metrics.failed_transmissions += 1;
        }
    }

    fn determine_state_change_reason(&self, from_state: &ConnectionState, to_state: &ConnectionState) -> String {
        match (from_state, to_state) {
            (ConnectionState::Disconnected, ConnectionState::Connected) => "successful_connection_establishment".to_string(),
            (ConnectionState::Disconnected, ConnectionState::ConnectedPendingIPs) => "connection_established_no_ips".to_string(),
            (ConnectionState::Connected, ConnectionState::Disconnected) => "connection_lost".to_string(),
            (ConnectionState::ConnectedPendingIPs, ConnectionState::Connected) => "ips_detected".to_string(),
            (ConnectionState::Connected, ConnectionState::ConnectedPendingIPs) => "ips_lost".to_string(),
            (_, ConnectionState::Retrying(backoff)) => format!("retry_scheduled_{}s", backoff),
            (_, ConnectionState::Monitoring) => "device_change_detected".to_string(),
            _ => "state_transition".to_string(),
        }
    }

    fn log_service_health_summary(&self) {
        let uptime = SystemTime::now()
            .duration_since(self.connection_diagnostics.service_start_time)
            .unwrap_or_default();

        let success_rate = if self.service_metrics.total_collections > 0 {
            (self.service_metrics.successful_transmissions as f64 / self.service_metrics.total_collections as f64) * 100.0
        } else {
            0.0
        };

        info!("📊 Service Health Summary:");
        info!("  🕰️ Uptime: {}s", uptime.as_secs());
        info!("  📊 Collections: {} (avg: {:.1}ms)",
              self.service_metrics.total_collections,
              self.service_metrics.average_collection_time_ms);
        info!("  ✅ Success Rate: {:.1}% ({}/{})",
              success_rate,
              self.service_metrics.successful_transmissions,
              self.service_metrics.total_collections);
        info!("  🔄 State Changes: {}", self.connection_diagnostics.total_state_changes);
        info!("  💯 Stability Score: {:.1}%", self.connection_diagnostics.connection_stability_score);
        info!("  🔄 Retry Attempts: {}", self.service_metrics.retry_attempts);
        info!("  🟡 Health Checks: {}", self.service_metrics.health_check_count);

        if let Some(last_success) = self.connection_diagnostics.last_successful_metrics_transmission {
            let time_since_success = SystemTime::now().duration_since(last_success).unwrap_or_default();
            info!("  ⏰ Last Success: {}s ago", time_since_success.as_secs());
        } else {
            info!("  ⏰ Last Success: Never");
        }
    }
}

impl Drop for InfiniService {
    fn drop(&mut self) {
        if let Some(handle) = self.device_monitor_handle.take() {
            handle.abort();
            debug!("Device monitor task aborted during drop");
        }
    }
}
