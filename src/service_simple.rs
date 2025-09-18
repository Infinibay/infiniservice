// Simplified service implementation with shutdown support
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use log::{info, error, debug};
use anyhow::Result;

pub struct SimpleInfiniService {
    shutdown_requested: Arc<AtomicBool>,
}

impl SimpleInfiniService {
    pub fn new() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn request_shutdown(&self) {
        info!("🛑 Shutdown requested");
        self.shutdown_requested.store(true, Ordering::Relaxed);
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Relaxed)
    }

    pub async fn run(&self) -> Result<()> {
        info!("🚀 Starting simplified InfiniService");
        info!("Service will check for shutdown signal every 1 second");

        let mut counter = 0;

        while !self.is_shutdown_requested() {
            counter += 1;
            info!("Service running... iteration {}", counter);

            // Simulate work
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Check shutdown periodically
            if counter % 5 == 0 {
                debug!("Checking shutdown status...");
            }
        }

        info!("✅ Service shutdown requested, exiting main loop");
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        info!("🛑 Performing graceful shutdown...");

        // Set shutdown flag
        self.shutdown_requested.store(true, Ordering::Relaxed);

        // Give time for main loop to exit
        tokio::time::sleep(Duration::from_millis(100)).await;

        info!("✅ Shutdown complete");
    }
}

impl Drop for SimpleInfiniService {
    fn drop(&mut self) {
        info!("📤 SimpleInfiniService dropped");
        self.shutdown_requested.store(true, Ordering::Relaxed);
    }
}