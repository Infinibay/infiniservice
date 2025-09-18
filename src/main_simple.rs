use log::{info, error};
use anyhow::Result;
use std::env;

mod service_simple;
use service_simple::SimpleInfiniService;

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
static SERVICE_NAME: &str = "InfiniServiceSimple";

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, service_main);

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Initialize logging
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    // Check for help flag
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        println!("InfiniService Simple - Simplified VM Service with Shutdown Support");
        println!("Usage: {} [OPTIONS]", args[0]);
        println!("Options:");
        println!("  --help, -h        Show this help message");
        println!("  --console         Run in console mode (Windows only)");
        return Ok(());
    }

    // On Windows, check if we're running as a service
    #[cfg(target_os = "windows")]
    {
        // If no arguments are provided and we're on Windows, assume we're running as a service
        if args.len() == 1 && !args.contains(&"--console".to_string()) {
            info!("Attempting to run as Windows service...");
            match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    eprintln!("Failed to start as Windows service: {:?}", e);
                    eprintln!("Running in console mode instead. Use --help for options.");
                }
            }
        }
    }

    // Run in console mode
    info!("Starting in console mode...");

    // Set up signal handling for graceful shutdown
    #[cfg(unix)]
    let shutdown_signal = async {
        use tokio::signal;
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }
    };

    #[cfg(windows)]
    let shutdown_signal = async {
        use tokio::signal;
        signal::ctrl_c().await.expect("Failed to register Ctrl+C handler")
    };

    // Create and run the service
    let mut service = SimpleInfiniService::new();

    // Run the service with graceful shutdown handling
    info!("Starting main service loop...");
    tokio::select! {
        result = service.run() => {
            if let Err(e) = result {
                error!("Service error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received, performing graceful shutdown...");
            service.shutdown().await;
        }
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

    info!("InfiniService Simple Windows service starting...");

    // Create atomic flag for shutdown signaling
    let shutdown_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Define the service control handler
    let shutdown_flag_clone = shutdown_flag.clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Received stop/shutdown signal");
                // Set shutdown flag
                shutdown_flag_clone.store(true, std::sync::atomic::Ordering::Relaxed);
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
        info!("Service initialized successfully");

        // Create the service
        let mut service = SimpleInfiniService::new();

        // Run the service with shutdown handling
        tokio::select! {
            result = service.run() => {
                if let Err(e) = result {
                    error!("Service error: {:?}", e);
                }
                info!("Service run loop ended");
            }
            _ = async {
                // Monitor shutdown flag
                while !shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => {
                info!("Shutdown signal received, stopping service...");
                // Request shutdown which will cause run() loop to exit
                service.request_shutdown();
                // Give time for run loop to exit gracefully
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        // Perform final cleanup
        service.shutdown().await;
    });

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
}