//! Main service implementation with command execution support

use crate::{Config, collector::DataCollector, communication::VirtioSerial};
use crate::commands::{IncomingMessage, executor::CommandExecutor};
use anyhow::Result;
use log::{info, error, warn, debug};
use std::time::Duration;
use std::path::PathBuf;
use tokio::time;
use tokio::select;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Connected,
    Disconnected,
    Retrying(u64),
    Monitoring,
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
                    let comm = VirtioSerial::new(&device_path);
                    (comm, Some(device_path))
                }
                Err(e) => {
                    warn!("Failed to auto-detect virtio-serial device: {}", e);
                    if debug_mode {
                        debug!("Detection error details: {:?}", e);
                    }
                    (VirtioSerial::new(&config.virtio_serial_path), None)
                }
            }
        } else {
            (VirtioSerial::new(&config.virtio_serial_path), Some(config.virtio_serial_path.clone()))
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

        let mut interval = time::interval(Duration::from_secs(self.config.collection_interval));
        let mut command_check_interval = time::interval(Duration::from_millis(500)); // Check for commands every 500ms

        // Initialize device monitoring if enabled
        if self.config.enable_device_monitoring {
            let (device_change_tx, mut device_change_rx) = tokio::sync::mpsc::channel::<()>(10);
            self.device_monitor_handle = Some(self.spawn_device_monitor(device_change_tx).await);
            let mut monitoring_active = true;

            // Add device change monitoring to the select loop
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
                                        self.emit_connection_state_change(ConnectionState::Connected).await;
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
                                self.emit_connection_state_change(ConnectionState::Connected).await;
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

                    // Dynamic backoff retry for VirtIO connection
                    _ = time::sleep(Duration::from_secs(self.virtio_backoff_secs)), if !self.virtio_connected && !self.config.require_virtio => {
                        match self.retry_virtio_connection().await {
                            Ok(true) => {
                                info!("✅ VirtIO connection restored successfully!");
                                self.virtio_connected = true;
                                self.virtio_backoff_secs = self.config.virtio_min_backoff_secs; // Reset backoff
                                self.emit_connection_state_change(ConnectionState::Connected).await;
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
    
    /// Attempt to retry VirtIO connection
    async fn retry_virtio_connection(&mut self) -> Result<bool> {
        debug!("Attempting to retry VirtIO connection...");

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
                        self.communication = VirtioSerial::new(device_path);
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
        
        // Try to connect
        match self.communication.connect().await {
            Ok(_) => {
                info!("VirtIO connection retry succeeded");
                Ok(true)
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

                    // Check if it's a device open error (rate limited)
                    if e.to_string().contains("Failed to open device for") ||
                       e.to_string().contains("Failed to open COM port for") {
                        // This is a device access error - check if it's privilege-related
                        #[cfg(target_os = "windows")]
                        {
                            let error_message = e.to_string();
                            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                                if let Some(raw_err) = io_err.raw_os_error() {
                                    if crate::windows_com::detect_privilege_requirements(raw_err as u32, &error_message) {
                                        let formatted_error = self.format_privilege_aware_error(&e, "VirtIO device access error during transmission");
                                        debug!("{}", formatted_error);
                                    } else {
                                        debug!("VirtIO device access error during transmission (rate limited): {}", e);
                                    }
                                } else {
                                    debug!("VirtIO device access error during transmission (rate limited): {}", e);
                                }
                            } else {
                                debug!("VirtIO device access error during transmission (rate limited): {}", e);
                            }
                        }
                        #[cfg(not(target_os = "windows"))]
                        {
                            debug!("VirtIO device access error during transmission (rate limited): {}", e);
                        }

                        Ok(()) // Don't treat this as an error to avoid spam
                    } else {
                        // Other transmission errors (write/flush failures)
                        #[cfg(target_os = "windows")]
                        {
                            let error_message = e.to_string();
                            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                                if let Some(raw_err) = io_err.raw_os_error() {
                                    if crate::windows_com::detect_privilege_requirements(raw_err as u32, &error_message) {
                                        let formatted_error = self.format_privilege_aware_error(&e, "VirtIO transmission failed");
                                        error!("{}", formatted_error);
                                    }
                                }
                            }
                        }

                        Err(e)
                    }
                }
            }
        }
    }

    /// Emit connection state change notifications
    async fn emit_connection_state_change(&mut self, new_state: ConnectionState) {
        if self.connection_state != new_state {
            let old_state = self.connection_state.clone();
            self.connection_state = new_state.clone();

            let (state_str, details) = match &new_state {
                ConnectionState::Connected => {
                    info!("✅ VirtIO connection established");
                    ("connected", "VirtIO connection established successfully")
                }
                ConnectionState::Disconnected => {
                    warn!("❌ VirtIO connection lost");
                    ("disconnected", "VirtIO connection lost")
                }
                ConnectionState::Retrying(backoff_secs) => {
                    warn!("⚠️ VirtIO connection failed, retrying in {}s", backoff_secs);
                    ("retrying", "Retrying connection")
                }
                ConnectionState::Monitoring => {
                    info!("🔄 Monitoring for device changes");
                    ("monitoring", "Monitoring for device changes")
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

impl Drop for InfiniService {
    fn drop(&mut self) {
        if let Some(handle) = self.device_monitor_handle.take() {
            handle.abort();
            debug!("Device monitor task aborted during drop");
        }
    }
}
