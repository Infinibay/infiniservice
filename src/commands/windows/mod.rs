//! Windows package manager implementations
//!
//! This module provides individual update manager implementations for Windows systems,
//! each implementing the `PackageManager` trait for a unified interface.
//!
//! # Architecture
//!
//! ```text
//! WindowsUpdateChecker
//!        ↓
//!   Vec<Box<dyn PackageManager>>
//!        ↓
//! [WinGetManager, PowerShellManager, RegistryManager]
//!        ↓
//!   AsyncCache + execute_command()
//! ```
//!
//! # Package Managers
//!
//! | Manager | Backend | Cache | Apps Supported | Advantages |
//! |---------|---------|-------|----------------|------------|
//! | `WinGetManager` | WinGet CLI | AsyncCache (5 min) | Store, WinGet, common apps | Most complete, precise versions |
//! | `PowerShellManager` | PowerShell + WUA | AsyncCache (10 min) | MSI, Windows Updates | Detects security updates |
//! | `RegistryManager` | Registry queries | HashMap static | Chrome, Firefox, Edge, Java, Adobe | Fast, no external dependencies |
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::commands::windows::{WinGetManager, PowerShellManager, RegistryManager};
//! use crate::commands::traits::PackageManager;
//!
//! // Create managers based on available backends
//! let mut managers: Vec<Box<dyn PackageManager>> = Vec::new();
//!
//! if let Ok(winget) = WinGetManager::new() {
//!     managers.push(Box::new(winget));
//! }
//! if let Ok(powershell) = PowerShellManager::new() {
//!     managers.push(Box::new(powershell));
//! }
//! managers.push(Box::new(RegistryManager::new()));
//!
//! // Initialize all managers
//! for manager in &mut managers {
//!     manager.initialize().await?;
//! }
//!
//! // Check for updates
//! for manager in &managers {
//!     if let Some(update) = manager.check_update(&app).await? {
//!         println!("Update found via {}: {}", manager.name(), update.available_version);
//!         break; // Use first manager that finds an update
//!     }
//! }
//! ```
//!
//! # Priority Order
//!
//! When checking for updates, managers are queried in priority order:
//! 1. **WinGet** - Most comprehensive, covers Store + common apps with precise versions
//! 2. **PowerShell** - Windows Updates for MSI packages, security update detection
//! 3. **Registry** - Fallback for known apps (Chrome, Firefox, Edge, Java, Adobe)

pub mod golden_image;
pub mod registry_manager;
pub mod store_manager;
pub mod system_operations;
pub mod update_agent_manager;

pub use registry_manager::RegistryManager;
pub use store_manager::WinGetManager;
pub use system_operations::WindowsSystemOperations;
pub use update_agent_manager::PowerShellManager;
