//! Configuration management for Infiniservice

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Interval between data collection cycles (in seconds)
    pub collection_interval: u64,
    
    /// Path to virtio-serial device
    pub virtio_serial_path: PathBuf,
    
    /// Log level
    pub log_level: String,
    
    /// Service name/identifier
    pub service_name: String,
    
    /// Whether VirtIO is required for the service to run
    /// If false, the service will continue running even without VirtIO
    pub require_virtio: bool,
    
    /// Interval for retrying VirtIO connection (in seconds) (deprecated, use min/max backoff)
    pub virtio_retry_interval: u64,

    /// Minimum backoff interval in seconds for VirtIO retry attempts
    pub virtio_min_backoff_secs: u64,

    /// Maximum backoff interval in seconds for VirtIO retry attempts
    pub virtio_max_backoff_secs: u64,

    /// Enable automatic device change monitoring
    pub enable_device_monitoring: bool,

    /// Connection timeout in seconds for VirtIO connection establishment
    pub virtio_connection_timeout_secs: u64,

    /// Read timeout in milliseconds for VirtIO persistent connections
    pub virtio_read_timeout_ms: u64,

    /// Health check interval in seconds for periodic connection validation
    pub virtio_health_check_interval_secs: u64,

    /// Enable periodic connection validation
    pub enable_connection_validation: bool,

    /// Configurable ping test interval in seconds (default: 60 seconds, more conservative than current 30s)
    pub virtio_ping_test_interval_secs: u64,

    /// Message timeout for connection staleness detection in seconds (default: 900 seconds / 15 minutes)
    pub virtio_message_timeout_secs: u64,

    /// Base delay for reconnection attempts in seconds (default: 5 seconds, more conservative than current 2s)
    pub virtio_reconnect_base_delay_secs: u64,

    /// Maximum reconnection attempts (default: 15, increased from typical 10)
    pub virtio_max_reconnect_attempts: u32,

    // Circuit Breaker Configuration
    /// Number of failures before opening circuit (default: 15)
    pub circuit_breaker_failure_threshold: u32,

    /// How long circuit stays open in seconds (default: 60 seconds)
    pub circuit_breaker_open_duration_secs: u64,

    /// Max calls allowed in half-open state (default: 5)
    pub circuit_breaker_half_open_max_calls: u32,

    /// Successes needed to close circuit (default: 2)
    pub circuit_breaker_success_threshold: u32,

    // Keep-Alive Configuration
    /// Heartbeat interval in seconds - how often to send keep-alive messages (default: 30 seconds, env: INFINISERVICE_KEEP_ALIVE_INTERVAL)
    pub keep_alive_interval_secs: u64,

    /// Heartbeat response timeout in seconds - must be less than interval (default: 60 seconds, env: INFINISERVICE_KEEP_ALIVE_TIMEOUT)
    pub keep_alive_timeout_secs: u64,

    /// Max idle time before proactive ping in seconds - should be >= interval (default: 30 seconds, env: INFINISERVICE_CONNECTION_IDLE_TIMEOUT)
    pub connection_idle_timeout_secs: u64,

    // Graceful Degradation Settings
    /// Slower collection when degraded in seconds (default: 120 seconds)
    pub degraded_mode_collection_interval_secs: u64,

    /// Reduced command timeouts when degraded in seconds (default: 30 seconds)
    pub degraded_mode_max_command_timeout_secs: u64,

    /// Quality level that triggers degradation (default: "poor")
    pub quality_threshold_for_degradation: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            collection_interval: 30,
            virtio_serial_path: if cfg!(windows) {
                // Empty path triggers auto-detection on Windows
                PathBuf::new()
            } else {
                PathBuf::from("/dev/virtio-ports/org.infinibay.0")
            },
            log_level: "info".to_string(),
            service_name: "infiniservice".to_string(),
            require_virtio: false, // Allow service to run without VirtIO by default
            virtio_retry_interval: 300, // Retry every 5 minutes
            virtio_min_backoff_secs: 5, // Increased from 2 to 5 seconds for less aggressive reconnection
            virtio_max_backoff_secs: 300, // Increased from 60 to 300 seconds (5 minutes) for more patient reconnection
            enable_device_monitoring: true, // Enable device change monitoring by default
            virtio_connection_timeout_secs: 10, // 10 second connection timeout
            virtio_read_timeout_ms: 500, // 500ms read timeout for non-blocking operations
            virtio_health_check_interval_secs: 60, // Increased from 30 to 60 seconds for less frequent health checks
            enable_connection_validation: false, // Disabled by default, enabled via flag
            virtio_ping_test_interval_secs: 60, // 60 seconds (double the current hardcoded 30s)
            virtio_message_timeout_secs: 900, // 900 seconds (15 minutes, matching backend increase)
            virtio_reconnect_base_delay_secs: 5, // 5 seconds (more conservative than current 2s)
            virtio_max_reconnect_attempts: 15, // 15 attempts (increased from typical 10)

            // Circuit Breaker defaults
            circuit_breaker_failure_threshold: 15, // 15 failures before opening circuit (3x tolerance for Windows Global objects)
            circuit_breaker_open_duration_secs: 60, // Circuit stays open for 60 seconds
            circuit_breaker_half_open_max_calls: 5, // Allow 5 calls in half-open state (better recovery confidence)
            circuit_breaker_success_threshold: 2, // 2 successes needed to close circuit

            // Keep-Alive defaults
            keep_alive_interval_secs: 30, // Send heartbeat every 30 seconds
            keep_alive_timeout_secs: 60, // 60 second timeout for heartbeat response (increased from 10s for reliability)
            connection_idle_timeout_secs: 30, // 30 seconds idle before proactive ping

            // Graceful Degradation defaults
            degraded_mode_collection_interval_secs: 120, // Slower collection when degraded
            degraded_mode_max_command_timeout_secs: 30, // Reduced command timeouts when degraded
            quality_threshold_for_degradation: "poor".to_string(), // Quality level that triggers degradation
        }
    }
}

impl Config {
    /// Load configuration from file or use defaults
    pub fn load() -> Result<Self> {
        // TODO: Implement configuration loading from file
        // For now, return default configuration
        let mut config = Self::default();
        config.validate_and_fix();
        Ok(config)
    }

    /// Validate and fix configuration values
    pub fn validate_and_fix(&mut self) {
        // Ensure backoff values are valid
        if self.virtio_min_backoff_secs == 0 {
            self.virtio_min_backoff_secs = 2;
        }
        if self.virtio_max_backoff_secs == 0 {
            self.virtio_max_backoff_secs = 60;
        }
        if self.virtio_min_backoff_secs > self.virtio_max_backoff_secs {
            // Swap values if min > max
            let temp = self.virtio_min_backoff_secs;
            self.virtio_min_backoff_secs = self.virtio_max_backoff_secs;
            self.virtio_max_backoff_secs = temp;
        }

        // Validate timeout values
        if self.virtio_connection_timeout_secs == 0 {
            self.virtio_connection_timeout_secs = 10;
        }
        if self.virtio_connection_timeout_secs > 30 {
            self.virtio_connection_timeout_secs = 30; // Cap at 30 seconds
        }

        if self.virtio_read_timeout_ms == 0 {
            self.virtio_read_timeout_ms = 500;
        }
        if self.virtio_read_timeout_ms < 100 {
            self.virtio_read_timeout_ms = 100; // Minimum 100ms
        }
        if self.virtio_read_timeout_ms > 5000 {
            self.virtio_read_timeout_ms = 5000; // Maximum 5 seconds
        }

        if self.virtio_health_check_interval_secs == 0 {
            self.virtio_health_check_interval_secs = 60; // Updated to match new default
        }

        // Validate new timeout fields
        // Ensure virtio_ping_test_interval_secs is at least 30 seconds and at most 300 seconds
        if self.virtio_ping_test_interval_secs < 30 {
            self.virtio_ping_test_interval_secs = 30;
        }
        if self.virtio_ping_test_interval_secs > 300 {
            self.virtio_ping_test_interval_secs = 300;
        }

        // Ensure virtio_message_timeout_secs is at least 300 seconds (5 minutes)
        if self.virtio_message_timeout_secs < 300 {
            self.virtio_message_timeout_secs = 300;
        }

        // Validate that virtio_reconnect_base_delay_secs is reasonable (1-30 seconds)
        if self.virtio_reconnect_base_delay_secs == 0 {
            self.virtio_reconnect_base_delay_secs = 1;
        }
        if self.virtio_reconnect_base_delay_secs > 30 {
            self.virtio_reconnect_base_delay_secs = 30;
        }

        // Validate max reconnect attempts
        if self.virtio_max_reconnect_attempts == 0 {
            self.virtio_max_reconnect_attempts = 5; // Minimum 5 attempts
        }
        if self.virtio_max_reconnect_attempts > 50 {
            self.virtio_max_reconnect_attempts = 50; // Cap at 50 attempts
        }

        // Circuit Breaker validation
        if self.circuit_breaker_failure_threshold == 0 {
            self.circuit_breaker_failure_threshold = 3; // Minimum 3 failures
        }
        if self.circuit_breaker_failure_threshold > 20 {
            self.circuit_breaker_failure_threshold = 20; // Cap at 20 failures
        }

        if self.circuit_breaker_open_duration_secs < 10 {
            self.circuit_breaker_open_duration_secs = 10; // Minimum 10 seconds
        }
        if self.circuit_breaker_open_duration_secs > 600 {
            self.circuit_breaker_open_duration_secs = 600; // Cap at 10 minutes
        }

        if self.circuit_breaker_half_open_max_calls == 0 {
            self.circuit_breaker_half_open_max_calls = 1; // Minimum 1 call
        }
        if self.circuit_breaker_half_open_max_calls > 10 {
            self.circuit_breaker_half_open_max_calls = 10; // Cap at 10 calls
        }

        if self.circuit_breaker_success_threshold == 0 {
            self.circuit_breaker_success_threshold = 1; // Minimum 1 success
        }
        if self.circuit_breaker_success_threshold > self.circuit_breaker_half_open_max_calls {
            self.circuit_breaker_success_threshold = self.circuit_breaker_half_open_max_calls; // Can't need more successes than max calls
        }

        // Keep-Alive validation
        if self.keep_alive_interval_secs < 10 {
            self.keep_alive_interval_secs = 10; // Minimum 10 seconds
        }
        if self.keep_alive_interval_secs > 300 {
            self.keep_alive_interval_secs = 300; // Cap at 5 minutes
        }

        if self.keep_alive_timeout_secs < 5 {
            self.keep_alive_timeout_secs = 5; // Minimum 5 seconds
        }
        if self.keep_alive_timeout_secs > 60 {
            self.keep_alive_timeout_secs = 60; // Cap at 1 minute
        }
        // Timeout must be less than interval to detect failures before next keep-alive
        if self.keep_alive_timeout_secs >= self.keep_alive_interval_secs {
            self.keep_alive_timeout_secs = self.keep_alive_interval_secs / 2;
        }

        if self.connection_idle_timeout_secs < 30 {
            self.connection_idle_timeout_secs = 30; // Minimum 30 seconds
        }
        if self.connection_idle_timeout_secs > 1800 {
            self.connection_idle_timeout_secs = 1800; // Cap at 30 minutes
        }
        // Idle timeout should be at least as long as keep-alive interval
        if self.connection_idle_timeout_secs < self.keep_alive_interval_secs {
            self.connection_idle_timeout_secs = self.keep_alive_interval_secs;
        }

        // Graceful Degradation validation
        if self.degraded_mode_collection_interval_secs < 60 {
            self.degraded_mode_collection_interval_secs = 60; // Minimum 1 minute
        }
        if self.degraded_mode_collection_interval_secs > 600 {
            self.degraded_mode_collection_interval_secs = 600; // Cap at 10 minutes
        }

        if self.degraded_mode_max_command_timeout_secs < 10 {
            self.degraded_mode_max_command_timeout_secs = 10; // Minimum 10 seconds
        }
        if self.degraded_mode_max_command_timeout_secs > 120 {
            self.degraded_mode_max_command_timeout_secs = 120; // Cap at 2 minutes
        }

        // Validate quality threshold
        if !matches!(self.quality_threshold_for_degradation.as_str(), "excellent" | "good" | "fair" | "poor" | "critical") {
            self.quality_threshold_for_degradation = "poor".to_string();
        }
    }

    /// Apply development mode settings for faster feedback
    pub fn apply_development_mode(&mut self) {
        self.virtio_min_backoff_secs = 1; // Very fast initial retry
        self.virtio_max_backoff_secs = 10; // Quick maximum backoff
        self.virtio_connection_timeout_secs = 5; // Faster timeout
        self.virtio_read_timeout_ms = 200; // Faster read timeout
        self.virtio_health_check_interval_secs = 10; // More frequent health checks

        // Adjust the development mode settings to be less aggressive while still providing faster feedback
        self.virtio_ping_test_interval_secs = 30; // 30 seconds in dev mode (instead of the production 60s)
        self.virtio_message_timeout_secs = 300; // 300 seconds (5 minutes) in dev mode
        self.virtio_reconnect_base_delay_secs = 2; // Faster reconnection in dev mode
        self.virtio_max_reconnect_attempts = 10; // Fewer attempts in dev mode for faster feedback

        // Circuit Breaker development mode settings
        self.circuit_breaker_failure_threshold = 3; // Lower threshold for faster testing
        self.circuit_breaker_open_duration_secs = 30; // Shorter open duration for faster recovery testing
        self.circuit_breaker_half_open_max_calls = 2; // Fewer calls for faster state transitions
        self.circuit_breaker_success_threshold = 1; // Single success to close circuit for faster recovery

        // Keep-Alive development mode settings
        self.keep_alive_interval_secs = 15; // More frequent heartbeats for faster detection
        self.keep_alive_timeout_secs = 5; // Shorter timeout for faster failure detection
        self.connection_idle_timeout_secs = 30; // Shorter idle timeout for more proactive pinging
    }
}
