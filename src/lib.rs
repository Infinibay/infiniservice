//! Infiniservice - Multiplatform background service for VM data collection and command execution
//! 
//! This service runs in the background on Windows and Linux VMs to:
//! - Collect system information and metrics
//! - Communicate with the host via virtio-serial
//! - Execute safe and unsafe commands from the host

pub mod config;
pub mod collector;
pub mod communication;
pub mod service;
pub mod os_detection;
pub mod commands;

#[cfg(target_os = "windows")]
pub mod windows_com;

pub use config::Config;
pub use service::InfiniService;
pub use os_detection::{OsInfo, OsType};
pub use commands::{IncomingMessage, CommandResponse};
