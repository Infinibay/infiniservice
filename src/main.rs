use log::{info, error};
use infiniservice::{Config, InfiniService};
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    env_logger::init();

    info!("Infiniservice starting...");

    // Check for ping-pong mode
    let args: Vec<String> = env::args().collect();
    let ping_pong_mode = args.contains(&"--ping-pong".to_string()) ||
                        args.contains(&"ping-pong".to_string()) ||
                        env::var("INFINISERVICE_MODE").unwrap_or_default() == "ping-pong";

    // Load configuration
    let config = Config::load()?;
    info!("Configuration loaded: collection interval = {}s", config.collection_interval);

    if ping_pong_mode {
        info!("🏓 Starting in PING-PONG test mode");

        // Create service for ping-pong testing
        let mut service = InfiniService::new_with_ping_pong(config);
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
        let mut service = InfiniService::new(config);
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
