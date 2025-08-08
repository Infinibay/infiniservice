use log::{info, error};
use infiniservice::{Config, InfiniService};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    env_logger::init();

    info!("Infiniservice starting...");

    // Load configuration
    let config = Config::load()?;
    info!("Configuration loaded: collection interval = {}s", config.collection_interval);

    // Create and initialize service
    let service = InfiniService::new(config);
    service.initialize().await?;

    // Run the service
    info!("Starting main service loop...");
    if let Err(e) = service.run().await {
        error!("Service error: {}", e);
        return Err(e);
    }

    Ok(())
}
