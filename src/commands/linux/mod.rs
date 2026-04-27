//! Linux package manager implementations
//!
//! This module provides individual package manager implementations for Linux systems,
//! each implementing the `PackageManager` trait for a unified interface.
//!
//! # Architecture
//!
//! ```text
//! LinuxUpdateChecker
//!        ↓
//!   Vec<Box<dyn PackageManager>>
//!        ↓
//! [AptUpdateChecker, RpmUpdateChecker, SnapUpdateChecker, FlatpakUpdateChecker]
//!        ↓
//!   AsyncCache + execute_command()
//! ```
//!
//! # Package Managers
//!
//! | Manager | Description | Systems |
//! |---------|-------------|---------|
//! | `AptUpdateChecker` | Debian package manager | Debian, Ubuntu, Mint |
//! | `RpmUpdateChecker` | Red Hat package manager | RHEL, Fedora, CentOS |
//! | `SnapUpdateChecker` | Snap universal packages | Ubuntu, others |
//! | `FlatpakUpdateChecker` | Flatpak universal packages | Most distros |
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::commands::linux::{AptUpdateChecker, RpmUpdateChecker};
//! use crate::commands::traits::PackageManager;
//!
//! // Create managers based on available package managers
//! let mut managers: Vec<Box<dyn PackageManager>> = Vec::new();
//!
//! if apt_available {
//!     managers.push(Box::new(AptUpdateChecker::new()?));
//! }
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
//!     }
//! }
//! ```

pub mod apt_manager;
pub mod flatpak_manager;
pub mod golden_image;
pub mod rpm_manager;
pub mod snap_manager;
pub mod system_operations;

pub use apt_manager::AptUpdateChecker;
pub use flatpak_manager::FlatpakUpdateChecker;
pub use rpm_manager::RpmUpdateChecker;
pub use snap_manager::SnapUpdateChecker;
pub use system_operations::LinuxSystemOperations;
