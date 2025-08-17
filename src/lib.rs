//! Infiniservice - Multiplatform background service for VM data collection
//! 
//! This service runs in the background on Windows and Linux VMs to collect
//! system information and communicate with the host via virtio-serial.

pub mod config;
pub mod collector;
pub mod communication;
pub mod service;

#[cfg(target_os = "windows")]
pub mod windows_com;

pub use config::Config;
pub use service::InfiniService;
