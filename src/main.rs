use log::{info, error, debug, warn};
use infiniservice::{Config, InfiniService};
use anyhow::Result;
use std::env;

#[cfg(target_os = "windows")]
use infiniservice::windows_com::diagnose_virtio_installation;

#[cfg(target_os = "windows")]
use windows_service::{
    define_windows_service,
    service_dispatcher,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
};

#[cfg(target_os = "windows")]
use std::time::Duration;
#[cfg(target_os = "windows")]
use std::ffi::OsString;

#[cfg(target_os = "windows")]
static SERVICE_NAME: &str = "Infiniservice";

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, service_main);

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // On Windows, check if we're running as a service
    #[cfg(target_os = "windows")]
    {
        // If no arguments are provided and we're on Windows, assume we're running as a service
        // Windows services are typically started without command-line arguments
        if args.len() == 1 && !args.contains(&"--console".to_string()) {
            // Try to run as Windows service
            info!("Attempting to run as Windows service...");
            match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    // If we can't start as a service, continue as console app
                    eprintln!("Failed to start as Windows service: {:?}", e);
                    eprintln!("Running in console mode instead. Use --help for options.");
                }
            }
        }
    }
    
    // Check for version flag
    if args.contains(&"--version".to_string()) || args.contains(&"-v".to_string()) {
        println!("infiniservice {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    
    // Check for help flag
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        println!("Infiniservice - VM Data Collection Service");
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        println!("\nUsage: {} [OPTIONS]\n", args[0]);
        println!("Options:");
        println!("  --help, -h        Show this help message");
        println!("  --version, -v     Show version information");
        println!("  --console         Run in console mode (Windows only)");
        println!("  --debug           Enable debug logging");
        println!("  --diagnose, --diag  Run VirtIO device diagnostics (Windows)");
        println!("  --device <path>   Manually specify device path");
        println!("  --require-virtio  Require VirtIO device to run (exit if not found)");
        println!("  --no-virtio       Allow service to run without VirtIO device");
        println!("  --virtio-min-backoff <seconds>  Set minimum VirtIO retry backoff interval");
        println!("  --virtio-max-backoff <seconds>  Set maximum VirtIO retry backoff interval");
        println!("  --connection-timeout <seconds>  Set VirtIO connection timeout (default: 10)");
        println!("  --read-timeout <ms>             Set VirtIO read timeout in milliseconds (default: 500)");
        println!("  --aggressive-retry              Enable aggressive retry for faster development");
        println!("  --validate-connection           Enable periodic connection health checks");
        println!("  --disable-device-monitoring     Disable automatic device change monitoring");
        println!("\nEnvironment Variables:");
        println!("  INFINIBAY_VM_ID=<id>          Set VM identifier");
        println!("  INFINISERVICE_DEVICE=<path>   Manually specify device path");
        println!("  INFINISERVICE_REQUIRE_VIRTIO=<true|false>  Require VirtIO device");
        println!("  INFINISERVICE_MIN_BACKOFF=<seconds>       Set minimum retry backoff");
        println!("  INFINISERVICE_MAX_BACKOFF=<seconds>       Set maximum retry backoff");
        println!("  INFINISERVICE_CONNECTION_TIMEOUT=<secs>   Set connection timeout");
        println!("  INFINISERVICE_READ_TIMEOUT=<ms>           Set read timeout");
        println!("  INFINISERVICE_AGGRESSIVE_RETRY=<true>     Enable aggressive retry");
        println!("  INFINISERVICE_VALIDATE_CONNECTION=<true>  Enable connection validation");
        println!("  INFINISERVICE_DISABLE_MONITORING=<true>   Disable device monitoring");
        println!("  RUST_LOG=<level>              Set log level (error|warn|info|debug)");
        return Ok(());
    }
    
    let debug_mode = args.contains(&"--debug".to_string());
    let diagnose_mode = args.contains(&"--diagnose".to_string()) || args.contains(&"--diag".to_string());
    let require_virtio = args.contains(&"--require-virtio".to_string());
    let no_virtio = args.contains(&"--no-virtio".to_string());
    let disable_device_monitoring = args.contains(&"--disable-device-monitoring".to_string());
    let aggressive_retry = args.contains(&"--aggressive-retry".to_string());
    let validate_connection = args.contains(&"--validate-connection".to_string());
    
    // Parse --device parameter
    let mut device_path_override: Option<String> = None;
    let mut min_backoff_override: Option<u64> = None;
    let mut max_backoff_override: Option<u64> = None;
    let mut connection_timeout_override: Option<u64> = None;
    let mut read_timeout_override: Option<u64> = None;

    for i in 0..args.len() {
        if args[i] == "--device" && i + 1 < args.len() {
            device_path_override = Some(args[i + 1].clone());
            info!("Device path override specified: {}", args[i + 1]);
        } else if args[i] == "--virtio-min-backoff" && i + 1 < args.len() {
            if let Ok(value) = args[i + 1].parse::<u64>() {
                min_backoff_override = Some(value);
                info!("Minimum backoff override specified: {}s", value);
            } else {
                warn!("Invalid minimum backoff value: {}", args[i + 1]);
            }
        } else if args[i] == "--virtio-max-backoff" && i + 1 < args.len() {
            if let Ok(value) = args[i + 1].parse::<u64>() {
                max_backoff_override = Some(value);
                info!("Maximum backoff override specified: {}s", value);
            } else {
                warn!("Invalid maximum backoff value: {}", args[i + 1]);
            }
        } else if args[i] == "--connection-timeout" && i + 1 < args.len() {
            if let Ok(value) = args[i + 1].parse::<u64>() {
                connection_timeout_override = Some(value);
                info!("Connection timeout override specified: {}s", value);
            } else {
                warn!("Invalid connection timeout value: {}", args[i + 1]);
            }
        } else if args[i] == "--read-timeout" && i + 1 < args.len() {
            if let Ok(value) = args[i + 1].parse::<u64>() {
                read_timeout_override = Some(value);
                info!("Read timeout override specified: {}ms", value);
            } else {
                warn!("Invalid read timeout value: {}", args[i + 1]);
            }
        }
    }
    
    // Check environment variable for device path
    if device_path_override.is_none() {
        if let Ok(path) = env::var("INFINISERVICE_DEVICE") {
            device_path_override = Some(path.clone());
            info!("Device path override from environment: {}", path);
        }
    }

    // Check environment variables for backoff settings
    if min_backoff_override.is_none() {
        if let Ok(value) = env::var("INFINISERVICE_MIN_BACKOFF") {
            if let Ok(parsed) = value.parse::<u64>() {
                min_backoff_override = Some(parsed);
                info!("Minimum backoff override from environment: {}s", parsed);
            }
        }
    }

    if max_backoff_override.is_none() {
        if let Ok(value) = env::var("INFINISERVICE_MAX_BACKOFF") {
            if let Ok(parsed) = value.parse::<u64>() {
                max_backoff_override = Some(parsed);
                info!("Maximum backoff override from environment: {}s", parsed);
            }
        }
    }

    // Check environment variables for timeout settings
    if connection_timeout_override.is_none() {
        if let Ok(value) = env::var("INFINISERVICE_CONNECTION_TIMEOUT") {
            if let Ok(parsed) = value.parse::<u64>() {
                connection_timeout_override = Some(parsed);
                info!("Connection timeout override from environment: {}s", parsed);
            }
        }
    }

    if read_timeout_override.is_none() {
        if let Ok(value) = env::var("INFINISERVICE_READ_TIMEOUT") {
            if let Ok(parsed) = value.parse::<u64>() {
                read_timeout_override = Some(parsed);
                info!("Read timeout override from environment: {}ms", parsed);
            }
        }
    }
    
    // Determine VirtIO requirement setting
    let virtio_required = if require_virtio {
        true
    } else if no_virtio {
        false
    } else {
        // Check environment variable
        env::var("INFINISERVICE_REQUIRE_VIRTIO")
            .unwrap_or_default()
            .parse::<bool>()
            .unwrap_or(false) // Default to not required
    };
    
    // Initialize logging with debug level if --debug flag is present
    if debug_mode {
        env::set_var("RUST_LOG", "debug");
        eprintln!("🔍 Debug mode enabled - verbose logging active");
    } else if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();
    
    if debug_mode {
        debug!("Debug mode is active");
        debug!("Command line args: {:?}", args);
        debug!("Environment variables:");
        for (key, value) in env::vars() {
            if key.starts_with("INFINI") || key == "RUST_LOG" {
                debug!("  {} = {}", key, value);
            }
        }
    }

    // Check if we're running in diagnose mode
    if diagnose_mode {
        println!("Running VirtIO device diagnostics...");
        println!("=====================================\n");
        
        #[cfg(target_os = "windows")]
        {
            match diagnose_virtio_installation() {
                Ok(diagnosis) => {
                    println!("{}", diagnosis);
                }
                Err(e) => {
                    eprintln!("Failed to run diagnostics: {}", e);
                }
            }
            
            // Also try to detect the device
            println!("\nAttempting device detection...");
            println!("==============================\n");
            
            use infiniservice::communication::VirtioSerial;
            match VirtioSerial::detect_device_path(true) {
                Ok(path) => {
                    println!("✅ Successfully detected device path: {}", path.display());
                }
                Err(e) => {
                    println!("❌ Device detection failed: {}", e);
                    println!("\nDetailed error chain:");
                    let mut source = e.source();
                    while let Some(err) = source {
                        println!("  Caused by: {}", err);
                        source = err.source();
                    }
                }
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            println!("VirtIO diagnostics is only available on Windows.");
            println!("On Linux, check for virtio-serial devices in:");
            println!("  - /dev/virtio-ports/");
            println!("  - /dev/vport*");
            println!("\nYou can use 'ls -la /dev/virtio-ports/' to list available devices.");
        }
        
        return Ok(());
    }
    
    info!("Infiniservice starting...");
    
    if debug_mode {
        info!("🔍 Running in DEBUG mode - enhanced logging enabled");
    }


    // Load configuration
    let mut config = Config::load()?;
    info!("Configuration loaded: collection interval = {}s", config.collection_interval);
    
    // Override device path if specified
    if let Some(device_path) = device_path_override {
        config.virtio_serial_path = std::path::PathBuf::from(device_path.clone());
        info!("Using device path override: {}", device_path);
    }
    
    // Apply VirtIO requirement setting
    config.require_virtio = virtio_required;
    if config.require_virtio {
        info!("VirtIO device is REQUIRED - service will exit if not found");
    } else {
        info!("VirtIO device is optional - service will continue without it if needed");
    }

    // Apply backoff overrides
    if let Some(min_backoff) = min_backoff_override {
        config.virtio_min_backoff_secs = min_backoff;
    }
    if let Some(max_backoff) = max_backoff_override {
        config.virtio_max_backoff_secs = max_backoff;
    }

    // Apply timeout overrides
    if let Some(connection_timeout) = connection_timeout_override {
        config.virtio_connection_timeout_secs = connection_timeout;
    }
    if let Some(read_timeout) = read_timeout_override {
        config.virtio_read_timeout_ms = read_timeout;
    }

    // Apply aggressive retry mode
    if aggressive_retry {
        config.apply_development_mode();
        info!("Aggressive retry mode ENABLED - using development-friendly settings");
    } else if env::var("INFINISERVICE_AGGRESSIVE_RETRY")
        .unwrap_or_default()
        .parse::<bool>()
        .unwrap_or(false)
    {
        config.apply_development_mode();
        info!("Aggressive retry mode ENABLED via environment variable");
    }

    // Apply device monitoring setting
    if disable_device_monitoring {
        config.enable_device_monitoring = false;
        info!("Device change monitoring DISABLED");
    } else if let Ok(value) = env::var("INFINISERVICE_DISABLE_MONITORING") {
        if value.parse::<bool>().unwrap_or(false) {
            config.enable_device_monitoring = false;
            info!("Device change monitoring DISABLED via environment variable");
        }
    }

    // Validate and fix configuration
    config.validate_and_fix();

    // Validate backoff values after overrides
    if config.virtio_min_backoff_secs > config.virtio_max_backoff_secs {
        warn!("Minimum backoff ({}) > maximum backoff ({}), swapping values",
              config.virtio_min_backoff_secs, config.virtio_max_backoff_secs);
    }
    
    // Apply connection validation setting
    if validate_connection {
        config.enable_connection_validation = true;
        info!("Connection validation ENABLED - periodic health checks active");
    } else if env::var("INFINISERVICE_VALIDATE_CONNECTION")
        .unwrap_or_default()
        .parse::<bool>()
        .unwrap_or(false)
    {
        config.enable_connection_validation = true;
        info!("Connection validation ENABLED via environment variable");
    }

    if debug_mode {
        debug!("Full configuration:");
        debug!("  Collection interval: {}s", config.collection_interval);
        debug!("  Virtio serial path: {:?}", config.virtio_serial_path);
        debug!("  VirtIO required: {}", config.require_virtio);
        debug!("  VirtIO retry interval: {}s (deprecated)", config.virtio_retry_interval);
        debug!("  VirtIO min backoff: {}s", config.virtio_min_backoff_secs);
        debug!("  VirtIO max backoff: {}s", config.virtio_max_backoff_secs);
        debug!("  VirtIO connection timeout: {}s", config.virtio_connection_timeout_secs);
        debug!("  VirtIO read timeout: {}ms", config.virtio_read_timeout_ms);
        debug!("  VirtIO health check interval: {}s", config.virtio_health_check_interval_secs);
        debug!("  Device monitoring enabled: {}", config.enable_device_monitoring);
        debug!("  Connection validation enabled: {}", config.enable_connection_validation);
        debug!("  System: {}", std::env::consts::OS);
        debug!("  Architecture: {}", std::env::consts::ARCH);
    }

    info!("📊 Starting in data collection mode");

    // Create and initialize service
    let mut service = InfiniService::new(config, debug_mode);
    service.initialize().await?;

    // Run the service
    info!("Starting main service loop...");
    if let Err(e) = service.run().await {
        error!("Service error: {}", e);
        return Err(e);
    }

    Ok(())
}

// Windows service implementation
#[cfg(target_os = "windows")]
fn service_main(_arguments: Vec<OsString>) {
    // Initialize logging for service mode
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();
    
    info!("Infiniservice Windows service starting...");
    
    // Create a channel to communicate with the service control handler
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    
    // Define the service control handler
    let shutdown_tx_clone = shutdown_tx.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Received stop/shutdown signal");
                // Send shutdown signal
                let _ = shutdown_tx_clone.try_send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    
    // Register the service control handler
    let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to register service control handler: {:?}", e);
            return;
        }
    };
    
    // Report that the service is running
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    
    // Run the actual service in a Tokio runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create Tokio runtime: {:?}", e);
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            return;
        }
    };
    
    runtime.block_on(async {
        // Load configuration
        let config = match Config::load() {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to load configuration: {:?}", e);
                let _ = status_handle.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(1),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                });
                return;
            }
        };
        
        info!("Configuration loaded: collection interval = {}s", config.collection_interval);
        
        // Create and initialize the service
        let mut service = InfiniService::new(config, false);
        if let Err(e) = service.initialize().await {
            error!("Failed to initialize service: {:?}", e);
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            });
            return;
        }
        
        info!("Service initialized successfully");
        
        // Run the service in the current task (not spawned)
        // Use tokio::select! to handle both the service and shutdown signal
        tokio::select! {
            result = service.run() => {
                if let Err(e) = result {
                    error!("Service error: {:?}", e);
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Shutdown signal received, stopping service...");
            }
        }
        
        // Report that the service is stopped
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
        
        info!("Service stopped");
    });
}
