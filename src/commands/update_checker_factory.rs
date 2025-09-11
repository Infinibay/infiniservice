//! Update checker factory and configuration management
//!
//! This module provides centralized creation and configuration of update checkers
//! to avoid duplication and ensure consistent behavior across the application.

use anyhow::Result;
use log::{debug, warn};

use super::update_checker::{UpdateCheckCoordinator, UpdateCheckConfig};

/// Factory for creating update check coordinators with proper platform-specific checkers
pub struct UpdateCheckerFactory;

impl UpdateCheckerFactory {
    /// Create a new update check coordinator with all available platform-specific checkers
    pub async fn create_coordinator(config: Option<UpdateCheckConfig>) -> Result<UpdateCheckCoordinator> {
        let config = config.unwrap_or_default();
        let mut coordinator = UpdateCheckCoordinator::new(config);
        
        // Add Windows-specific checkers
        #[cfg(target_os = "windows")]
        {
            debug!("Adding Windows update checkers");
            
            match super::windows_update_checker::WindowsUpdateChecker::new() {
                Ok(checker) => {
                    coordinator.add_checker(Box::new(checker));
                    debug!("Successfully added Windows update checker");
                }
                Err(e) => {
                    warn!("Failed to create Windows update checker: {}", e);
                }
            }
        }
        
        // Add Linux-specific checkers
        #[cfg(target_os = "linux")]
        {
            debug!("Adding Linux update checkers");
            
            match super::linux_update_checker::LinuxUpdateChecker::new() {
                Ok(checker) => {
                    coordinator.add_checker(Box::new(checker));
                    debug!("Successfully added Linux update checker");
                }
                Err(e) => {
                    warn!("Failed to create Linux update checker: {}", e);
                }
            }
        }
        
        // Initialize all checkers
        coordinator.initialize().await?;
        
        Ok(coordinator)
    }
    
    /// Create a coordinator with custom configuration for specific use cases
    pub async fn create_coordinator_with_timeout(timeout_seconds: u64) -> Result<UpdateCheckCoordinator> {
        let config = UpdateCheckConfig {
            network_timeout_seconds: timeout_seconds,
            ..Default::default()
        };
        
        Self::create_coordinator(Some(config)).await
    }
    
    /// Create a coordinator that only checks for security updates
    pub async fn create_security_only_coordinator() -> Result<UpdateCheckCoordinator> {
        let config = UpdateCheckConfig {
            security_updates_only: true,
            network_timeout_seconds: 15, // Shorter timeout for security checks
            max_retries: 2,
            ..Default::default()
        };
        
        Self::create_coordinator(Some(config)).await
    }
    
    /// Create a coordinator optimized for single application checks
    pub async fn create_single_app_coordinator() -> Result<UpdateCheckCoordinator> {
        let config = UpdateCheckConfig {
            network_timeout_seconds: 10, // Shorter timeout for single apps
            max_retries: 1,
            ..Default::default()
        };
        
        Self::create_coordinator(Some(config)).await
    }
}

/// Centralized configuration management for update checking
pub struct UpdateConfigManager;

impl UpdateConfigManager {
    /// Get default configuration for bulk application updates
    pub fn get_bulk_update_config() -> UpdateCheckConfig {
        UpdateCheckConfig {
            network_timeout_seconds: 30,
            max_retries: 3,
            include_prereleases: false,
            security_updates_only: false,
            user_agent: Some("InfiniService/0.1.0 (Bulk Update Check)".to_string()),
            proxy_url: None,
        }
    }
    
    /// Get configuration for quick security-only checks
    pub fn get_security_check_config() -> UpdateCheckConfig {
        UpdateCheckConfig {
            network_timeout_seconds: 15,
            max_retries: 2,
            include_prereleases: false,
            security_updates_only: true,
            user_agent: Some("InfiniService/0.1.0 (Security Check)".to_string()),
            proxy_url: None,
        }
    }
    
    /// Get configuration for interactive single application checks
    pub fn get_interactive_config() -> UpdateCheckConfig {
        UpdateCheckConfig {
            network_timeout_seconds: 45,
            max_retries: 3,
            include_prereleases: false,
            security_updates_only: false,
            user_agent: Some("InfiniService/0.1.0 (Interactive)".to_string()),
            proxy_url: None,
        }
    }
    
    /// Get configuration from environment variables or defaults
    pub fn get_env_config() -> UpdateCheckConfig {
        let timeout = std::env::var("INFINIBAY_UPDATE_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
            
        let retries = std::env::var("INFINIBAY_UPDATE_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
            
        let proxy_url = std::env::var("INFINIBAY_PROXY_URL").ok();
        
        let include_prereleases = std::env::var("INFINIBAY_INCLUDE_PRERELEASES")
            .map(|s| s.to_lowercase() == "true")
            .unwrap_or(false);
        
        UpdateCheckConfig {
            network_timeout_seconds: timeout,
            max_retries: retries,
            include_prereleases,
            security_updates_only: false,
            user_agent: Some("InfiniService/0.1.0".to_string()),
            proxy_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_coordinator() {
        let coordinator = UpdateCheckerFactory::create_coordinator(None).await;
        assert!(coordinator.is_ok());
    }
    
    #[tokio::test]
    async fn test_create_coordinator_with_timeout() {
        let coordinator = UpdateCheckerFactory::create_coordinator_with_timeout(5).await;
        assert!(coordinator.is_ok());
    }
    
    #[tokio::test]
    async fn test_create_security_only_coordinator() {
        let coordinator = UpdateCheckerFactory::create_security_only_coordinator().await;
        assert!(coordinator.is_ok());
    }
    
    #[test]
    fn test_config_manager() {
        let bulk_config = UpdateConfigManager::get_bulk_update_config();
        assert_eq!(bulk_config.network_timeout_seconds, 30);
        assert_eq!(bulk_config.max_retries, 3);
        
        let security_config = UpdateConfigManager::get_security_check_config();
        assert!(security_config.security_updates_only);
        assert_eq!(security_config.network_timeout_seconds, 15);
        
        let interactive_config = UpdateConfigManager::get_interactive_config();
        assert_eq!(interactive_config.network_timeout_seconds, 45);
    }
    
    #[test]
    fn test_env_config() {
        // Set environment variables for testing
        std::env::set_var("INFINIBAY_UPDATE_TIMEOUT", "60");
        std::env::set_var("INFINIBAY_UPDATE_RETRIES", "5");
        std::env::set_var("INFINIBAY_INCLUDE_PRERELEASES", "true");
        
        let config = UpdateConfigManager::get_env_config();
        assert_eq!(config.network_timeout_seconds, 60);
        assert_eq!(config.max_retries, 5);
        assert!(config.include_prereleases);
        
        // Clean up
        std::env::remove_var("INFINIBAY_UPDATE_TIMEOUT");
        std::env::remove_var("INFINIBAY_UPDATE_RETRIES");
        std::env::remove_var("INFINIBAY_INCLUDE_PRERELEASES");
    }
}