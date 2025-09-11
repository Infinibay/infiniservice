//! Application update checking trait and common types
//!
//! This module provides a common interface for checking application updates
//! across different platforms and package managers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use async_trait::async_trait;

use super::application_inventory::Application;

/// Information about an available update
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateInfo {
    /// Current version of the application
    pub current_version: Option<String>,
    
    /// Available version for update
    pub available_version: String,
    
    /// Size of the update in bytes (if available)
    pub update_size_bytes: Option<u64>,
    
    /// Update source (Windows Update, Store, APT repository, etc.)
    pub update_source: String,
    
    /// URL or identifier where the update can be obtained
    pub update_url: Option<String>,
    
    /// Whether this is a security update
    pub is_security_update: bool,
    
    /// Release notes or update description
    pub release_notes: Option<String>,
    
    /// When this update was last checked
    pub last_checked: SystemTime,
}

/// Error types for update checking operations
#[derive(Debug, thiserror::Error)]
pub enum UpdateCheckError {
    /// Network error when checking for updates
    #[error("Network error: {0}")]
    NetworkError(String),
    
    /// Authentication error when accessing update services
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    
    /// Update service temporarily unavailable
    #[error("Update service unavailable: {0}")]
    ServiceUnavailable(String),
    
    /// Invalid application identifier
    #[error("Invalid application ID: {0}")]
    InvalidAppId(String),
    
    /// Update information parsing error
    #[error("Failed to parse update information: {0}")]
    ParsingError(String),
    
    /// Platform-specific API error
    #[error("Platform API error: {0}")]
    PlatformError(String),
    
    /// Operation timed out
    #[error("Operation timed out")]
    Timeout,
    
    /// Feature not supported on this platform
    #[error("Update checking not supported for: {0}")]
    NotSupported(String),
}

/// Result type for update checking operations
pub type UpdateCheckResult<T> = std::result::Result<T, UpdateCheckError>;

/// Configuration for update checking behavior
#[derive(Debug, Clone)]
pub struct UpdateCheckConfig {
    /// Timeout for network operations in seconds
    pub network_timeout_seconds: u64,
    
    /// Maximum number of retry attempts
    pub max_retries: u32,
    
    /// Whether to check for pre-release/beta updates
    pub include_prereleases: bool,
    
    /// Whether to include security updates only
    pub security_updates_only: bool,
    
    /// Custom user agent for HTTP requests
    pub user_agent: Option<String>,
    
    /// Proxy configuration
    pub proxy_url: Option<String>,
}

impl Default for UpdateCheckConfig {
    fn default() -> Self {
        Self {
            network_timeout_seconds: 30,
            max_retries: 3,
            include_prereleases: false,
            security_updates_only: false,
            user_agent: Some("InfiniService/0.1.0".to_string()),
            proxy_url: None,
        }
    }
}

/// Trait for platform-specific update checking implementations
#[async_trait]
pub trait UpdateChecker: Send + Sync {
    /// Check for updates for a single application
    async fn check_app_update(
        &mut self, 
        app: &Application,
        config: &UpdateCheckConfig
    ) -> UpdateCheckResult<Option<UpdateInfo>>;
    
    /// Check for updates for multiple applications
    async fn check_multiple_updates(
        &mut self,
        apps: &[Application],
        config: &UpdateCheckConfig
    ) -> UpdateCheckResult<Vec<(String, Option<UpdateInfo>)>> {
        let mut results = Vec::new();
        
        for app in apps {
            let update_info = match self.check_app_update(app, config).await {
                Ok(info) => info,
                Err(e) => {
                    log::warn!("Failed to check updates for {}: {}", app.name, e);
                    None
                }
            };
            results.push((app.name.clone(), update_info));
        }
        
        Ok(results)
    }
    
    /// Get the name of this update checker (for logging/debugging)
    fn name(&self) -> &'static str;
    
    /// Check if this updater can handle the given application
    fn can_handle(&self, app: &Application) -> bool;
    
    /// Perform any necessary initialization
    async fn initialize(&mut self) -> UpdateCheckResult<()> {
        Ok(())
    }
    
    /// Clean up resources
    async fn cleanup(&mut self) -> UpdateCheckResult<()> {
        Ok(())
    }
}

/// Main update checking coordinator that delegates to platform-specific checkers
pub struct UpdateCheckCoordinator {
    checkers: Vec<Box<dyn UpdateChecker>>,
    config: UpdateCheckConfig,
}

impl UpdateCheckCoordinator {
    /// Create a new update check coordinator
    pub fn new(config: UpdateCheckConfig) -> Self {
        Self {
            checkers: Vec::new(),
            config,
        }
    }
    
    /// Add an update checker
    pub fn add_checker(&mut self, checker: Box<dyn UpdateChecker>) {
        self.checkers.push(checker);
    }
    
    /// Initialize all registered checkers
    pub async fn initialize(&mut self) -> Result<()> {
        for checker in &mut self.checkers {
            if let Err(e) = checker.initialize().await {
                log::warn!("Failed to initialize {}: {}", checker.name(), e);
            }
        }
        Ok(())
    }
    
    /// Check for updates for a single application
    pub async fn check_app_update(&mut self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
        for checker in &mut self.checkers {
            if checker.can_handle(app) {
                log::debug!("Using {} to check updates for {}", checker.name(), app.name);
                return checker.check_app_update(app, &self.config).await;
            }
        }
        
        Err(UpdateCheckError::NotSupported(format!(
            "No update checker available for {} ({})", 
            app.name, 
            app.install_type
        )))
    }
    
    /// Check for updates for multiple applications
    pub async fn check_multiple_updates(
        &mut self,
        apps: &[Application]
    ) -> UpdateCheckResult<Vec<(String, Option<UpdateInfo>)>> {
        let mut results = Vec::new();
        
        // Group applications by compatible update checker
        for app in apps {
            let update_info = match self.check_app_update(app).await {
                Ok(info) => info,
                Err(e) => {
                    log::debug!("No update available for {}: {}", app.name, e);
                    None
                }
            };
            results.push((app.name.clone(), update_info));
        }
        
        Ok(results)
    }
    
    /// Get applications with available updates
    pub async fn get_available_updates(
        &mut self,
        apps: &[Application]
    ) -> UpdateCheckResult<Vec<(Application, UpdateInfo)>> {
        let update_results = self.check_multiple_updates(apps).await?;
        
        let mut available_updates = Vec::new();
        for (app_name, update_info) in update_results.into_iter() {
            if let Some(info) = update_info {
                if let Some(app) = apps.iter().find(|a| a.name == app_name) {
                    available_updates.push((app.clone(), info));
                }
            }
        }
        
        Ok(available_updates)
    }
    
    /// Clean up all checkers
    pub async fn cleanup(&mut self) -> Result<()> {
        for checker in &mut self.checkers {
            if let Err(e) = checker.cleanup().await {
                log::warn!("Failed to cleanup {}: {}", checker.name(), e);
            }
        }
        Ok(())
    }
}

/// Utility functions for update checking
pub mod utils {
    use super::*;
    
    /// Compare version strings (simple lexicographic comparison)
    /// Returns true if `available` is newer than `current`
    pub fn is_version_newer(current: &str, available: &str) -> bool {
        // Simple version comparison - in a real implementation,
        // this would use a proper version comparison library
        use std::cmp::Ordering;
        
        let current_parts: Vec<&str> = current.split('.').collect();
        let available_parts: Vec<&str> = available.split('.').collect();
        
        let max_len = current_parts.len().max(available_parts.len());
        
        for i in 0..max_len {
            let current_part = current_parts.get(i).unwrap_or(&"0");
            let available_part = available_parts.get(i).unwrap_or(&"0");
            
            let current_num = current_part.parse::<u32>().unwrap_or(0);
            let available_num = available_part.parse::<u32>().unwrap_or(0);
            
            match current_num.cmp(&available_num) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
        
        false
    }
    
    /// Parse update size from string (e.g., "150 MB", "1.5 GB")
    pub fn parse_update_size(size_str: &str) -> Option<u64> {
        let size_str = size_str.trim().to_lowercase();
        let parts: Vec<&str> = size_str.split_whitespace().collect();
        
        if parts.len() < 2 {
            return None;
        }
        
        let number: f64 = parts[0].parse().ok()?;
        let unit = parts[1];
        
        let bytes = match unit {
            "b" | "byte" | "bytes" => number,
            "kb" | "k" => number * 1024.0,
            "mb" | "m" => number * 1024.0 * 1024.0,
            "gb" | "g" => number * 1024.0 * 1024.0 * 1024.0,
            _ => return None,
        };
        
        Some(bytes as u64)
    }
    
    /// Extract version number from application name or description
    pub fn extract_version_from_text(text: &str) -> Option<String> {
        use regex::Regex;
        
        // Common version patterns - prioritize longer matches
        let patterns = [
            r"\bv?(\d+\.\d+\.\d+\.\d+)\b",     // 1.2.3.4 or v1.2.3.4
            r"\bv?(\d+\.\d+\.\d+)\b",          // 1.2.3 or v1.2.3
            r"\bv(\d+\.\d+)\b",                // v1.2
            r"\b(\d+\.\d+)\b",                 // 1.2 (only if no v prefix)
        ];
        
        for pattern in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if let Some(captures) = regex.captures(text) {
                    if let Some(version) = captures.get(1) {
                        return Some(version.as_str().to_string());
                    }
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::utils::*;
    
    #[test]
    fn test_version_comparison() {
        assert!(is_version_newer("1.0.0", "1.0.1"));
        assert!(is_version_newer("1.0", "1.1"));
        assert!(is_version_newer("2.0.0", "3.0.0"));
        assert!(!is_version_newer("1.1.0", "1.0.9"));
        assert!(!is_version_newer("2.0.0", "2.0.0"));
    }
    
    #[test]
    fn test_parse_update_size() {
        assert_eq!(parse_update_size("150 MB"), Some(150 * 1024 * 1024));
        assert_eq!(parse_update_size("1.5 GB"), Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64));
        assert_eq!(parse_update_size("500 KB"), Some(500 * 1024));
        assert_eq!(parse_update_size("1024 B"), Some(1024));
        assert_eq!(parse_update_size("invalid"), None);
    }
    
    #[test]
    fn test_extract_version() {
        assert_eq!(extract_version_from_text("Firefox 91.0.2"), Some("91.0.2".to_string()));
        assert_eq!(extract_version_from_text("Chrome v95.0.4638.69"), Some("95.0.4638.69".to_string()));
        assert_eq!(extract_version_from_text("App version 1.2"), Some("1.2".to_string()));
        assert_eq!(extract_version_from_text("No version here"), None);
    }
    
    #[test]
    fn test_update_check_config_default() {
        let config = UpdateCheckConfig::default();
        assert_eq!(config.network_timeout_seconds, 30);
        assert_eq!(config.max_retries, 3);
        assert!(!config.include_prereleases);
        assert!(!config.security_updates_only);
    }
}