//! Traits for platform and package manager abstractions
//!
//! This module provides trait definitions for abstracting platform-specific
//! operations and package manager implementations. These traits enable a
//! unified interface for update checking across different package managers
//! (APT, RPM, Snap, Flatpak, WinGet, etc.) and platforms (Linux, Windows).
//!
//! # Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      UpdateChecker (existing)                   │
//! │   High-level trait for platform-specific update coordinators    │
//! └───────────────────────────┬─────────────────────────────────────┘
//!                             │ uses
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      PlatformOperations                         │
//! │   Abstracts OS-specific operations and package manager factory  │
//! └───────────────────────────┬─────────────────────────────────────┘
//!                             │ creates
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       PackageManager                            │
//! │   Individual package manager implementations (APT, RPM, etc.)   │
//! └───────────────────────────┬─────────────────────────────────────┘
//!                             │ uses
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      CommandExecutor                            │
//! │   Abstracts shell command execution for testability             │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Implementation Guide
//!
//! To implement a new package manager:
//!
//! 1. Create a struct that holds any necessary state (cache, config, etc.)
//! 2. Implement the `PackageManager` trait for your struct
//! 3. Register your implementation in the appropriate `PlatformOperations`
//!    implementation's `create_package_managers()` method
//!
//! # Example
//!
//! ```rust,ignore
//! use async_trait::async_trait;
//! use crate::commands::traits::PackageManager;
//! use crate::commands::update_checker::{UpdateCheckResult, UpdateInfo};
//! use crate::commands::application_inventory::Application;
//!
//! struct MyPackageManager {
//!     cache: HashMap<String, PackageInfo>,
//! }
//!
//! #[async_trait]
//! impl PackageManager for MyPackageManager {
//!     async fn initialize(&mut self) -> UpdateCheckResult<()> {
//!         // Build package cache
//!         self.build_cache().await
//!     }
//!
//!     async fn check_update(&self, app: &Application) -> UpdateCheckResult<Option<UpdateInfo>> {
//!         // Check for updates using the cache
//!         self.lookup_update(app).await
//!     }
//!
//!     fn generate_package_names(&self, app_name: &str) -> Vec<String> {
//!         vec![app_name.to_lowercase()]
//!     }
//!
//!     fn name(&self) -> &'static str {
//!         "my-package-manager"
//!     }
//! }
//! ```
//!
//! # Migration Path
//!
//! Existing checkers in `linux_update_checker.rs` can be migrated to use these
//! traits by:
//!
//! 1. Extracting the individual checker structs (AptUpdateChecker, etc.)
//! 2. Implementing `PackageManager` for each
//! 3. Using `CommandExecutor` for shell operations (enables mocking in tests)
//! 4. Updating `LinuxUpdateChecker` to use `PlatformOperations::create_package_managers()`

pub mod command_executor;
pub mod package_manager;
pub mod platform_operations;
pub mod system_operations;

pub use command_executor::CommandExecutor;
pub use package_manager::PackageManager;
pub use platform_operations::{PackageManagerType, PlatformOperations};
pub use system_operations::{SystemOperationResult, SystemOperations};
