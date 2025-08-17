use log::{info, error, debug, warn};
use infiniservice::{Config, InfiniService};
use std::env;

#[cfg(target_os = "windows")]
use infiniservice::windows_com::diagnose_virtio_installation;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Check for help flag
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        println!("Infiniservice - VM Data Collection Service");
        println!("\nUsage: {} [OPTIONS]\n", args[0]);
        println!("Options:");
        println!("  --help, -h        Show this help message");
        println!("  --debug           Enable debug logging");
        println!("  --diagnose, --diag  Run VirtIO device diagnostics (Windows)");
        println!("  --ping-pong       Run in ping-pong test mode");
        println!("  --device <path>   Manually specify device path");
        println!("\nEnvironment Variables:");
        println!("  INFINISERVICE_MODE=ping-pong  Run in ping-pong mode");
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

    // Check for ping-pong mode
    let ping_pong_mode = args.contains(&"--ping-pong".to_string()) ||
                        args.contains(&"ping-pong".to_string()) ||
                        env::var("INFINISERVICE_MODE").unwrap_or_default() == "ping-pong";

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

    if ping_pong_mode {
        info!("🏓 Starting in PING-PONG test mode");

        // Create service for ping-pong testing
        let mut service = InfiniService::new_with_ping_pong(config, debug_mode);
        service.initialize().await?;

        // Run ping-pong test
        info!("Starting ping-pong test...");
        if let Err(e) = service.run_ping_pong().await {
            error!("Ping-pong test error: {}", e);
            return Err(e);
        }
    } else {
        info!("📊 Starting in normal data collection mode");

        // Create and initialize service
        let mut service = InfiniService::new(config, debug_mode);
        service.initialize().await?;

        // Run the service
        info!("Starting main service loop...");
        if let Err(e) = service.run().await {
            error!("Service error: {}", e);
            return Err(e);
        }
    }

    Ok(())
}
