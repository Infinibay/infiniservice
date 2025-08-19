use log::{info, error, debug};
use infiniservice::{Config, InfiniService};
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
async fn main() -> anyhow::Result<()> {
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
        println!("\nEnvironment Variables:");
        println!("  INFINIBAY_VM_ID=<id>          Set VM identifier");
        println!("  INFINISERVICE_DEVICE=<path>   Manually specify device path");
        println!("  RUST_LOG=<level>              Set log level (error|warn|info|debug)");
        return Ok(());
    }
    
    let debug_mode = args.contains(&"--debug".to_string());
    let diagnose_mode = args.contains(&"--diagnose".to_string()) || args.contains(&"--diag".to_string());
    
    // Parse --device parameter
    let mut device_path_override: Option<String> = None;
    for i in 0..args.len() {
        if args[i] == "--device" && i + 1 < args.len() {
            device_path_override = Some(args[i + 1].clone());
            info!("Device path override specified: {}", args[i + 1]);
            break;
        }
    }
    
    // Check environment variable for device path
    if device_path_override.is_none() {
        if let Ok(path) = env::var("INFINISERVICE_DEVICE") {
            device_path_override = Some(path.clone());
            info!("Device path override from environment: {}", path);
        }
    }
    
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
    
    if debug_mode {
        debug!("Full configuration:");
        debug!("  Collection interval: {}s", config.collection_interval);
        debug!("  Virtio serial path: {:?}", config.virtio_serial_path);
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
