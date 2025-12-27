//! Platform abstraction integration tests
//!
//! These tests verify that the platform abstraction layer works correctly
//! on the current platform. They test the `PlatformFactory`, `SystemOperations`
//! trait implementations, and `SafeCommandExecutor` integration.

use infiniservice::commands::platform_factory::PlatformFactory;
use infiniservice::commands::traits::SystemOperations;

#[test]
fn test_platform_factory_creates_correct_implementation() {
    // Should not panic
    let _system_ops = PlatformFactory::create_system_operations();
}

#[test]
fn test_platform_is_supported() {
    assert!(PlatformFactory::is_platform_supported());
}

#[test]
fn test_platform_name() {
    let name = PlatformFactory::platform_name();

    #[cfg(target_os = "linux")]
    assert_eq!(name, "Linux");

    #[cfg(target_os = "windows")]
    assert_eq!(name, "Windows");
}

#[test]
fn test_trait_object_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Box<dyn SystemOperations>>();
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::*;

    #[tokio::test]
    async fn test_linux_list_services() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.list_services().await;

        // Should either succeed or fail with a known error (like missing systemctl)
        match result {
            Ok((stdout, stderr, _data)) => {
                assert!(!stdout.is_empty() || stderr.is_empty());
            }
            Err(e) => {
                // Acceptable if systemctl is not available in test environment
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("systemctl")
                        || err_msg.contains("not found")
                        || err_msg.contains("Failed"),
                    "Unexpected error: {}",
                    err_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_linux_list_processes() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.list_processes(Some(10)).await;

        // Process listing should always succeed
        assert!(result.is_ok(), "list_processes failed: {:?}", result.err());

        let (stdout, _, data) = result.unwrap();
        assert!(!stdout.is_empty());
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_linux_get_top_processes() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.get_top_processes(5, None).await;

        // Top processes should always succeed
        assert!(
            result.is_ok(),
            "get_top_processes failed: {:?}",
            result.err()
        );

        let (stdout, _, data) = result.unwrap();
        assert!(stdout.contains("Top"));
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_linux_list_users() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.list_users().await;

        // User listing should succeed (reading /etc/passwd)
        assert!(result.is_ok(), "list_users failed: {:?}", result.err());

        let (stdout, _, data) = result.unwrap();
        assert!(stdout.contains("users") || stdout.contains("Found"));
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_linux_check_disk_space() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.check_disk_space(80.0, 90.0).await;

        // Disk space check should succeed
        assert!(
            result.is_ok(),
            "check_disk_space failed: {:?}",
            result.err()
        );

        let (stdout, _, data) = result.unwrap();
        assert!(stdout.contains("Disk space check"));
        assert!(data.is_some());
    }
}

#[cfg(target_os = "windows")]
mod windows_tests {
    use super::*;

    #[tokio::test]
    async fn test_windows_list_services() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.list_services().await;

        // Should succeed on Windows
        assert!(result.is_ok(), "list_services failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_windows_list_processes() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.list_processes(Some(10)).await;

        // Process listing should always succeed
        assert!(result.is_ok(), "list_processes failed: {:?}", result.err());

        let (stdout, _, data) = result.unwrap();
        assert!(!stdout.is_empty());
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_windows_get_top_processes() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.get_top_processes(5, None).await;

        // Top processes should always succeed
        assert!(
            result.is_ok(),
            "get_top_processes failed: {:?}",
            result.err()
        );

        let (stdout, _, data) = result.unwrap();
        assert!(stdout.contains("Top"));
        assert!(data.is_some());
    }

    #[tokio::test]
    async fn test_windows_list_users() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.list_users().await;

        // User listing should succeed via WMI
        assert!(result.is_ok(), "list_users failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_windows_check_disk_space() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.check_disk_space(80.0, 90.0).await;

        // Disk space check should succeed
        assert!(
            result.is_ok(),
            "check_disk_space failed: {:?}",
            result.err()
        );

        let (stdout, _, data) = result.unwrap();
        assert!(stdout.contains("Disk space check"));
        assert!(data.is_some());
    }
}

/// Tests that work regardless of platform
mod cross_platform_tests {
    use super::*;

    #[tokio::test]
    async fn test_list_processes_with_limit() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.list_processes(Some(5)).await;

        assert!(result.is_ok(), "list_processes failed: {:?}", result.err());

        let (_, _, data) = result.unwrap();
        if let Some(data) = data {
            if let Some(arr) = data.as_array() {
                assert!(arr.len() <= 5, "Should respect limit");
            }
        }
    }

    #[tokio::test]
    async fn test_get_top_processes_sort_by_cpu() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.get_top_processes(10, Some("cpu")).await;

        assert!(
            result.is_ok(),
            "get_top_processes failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_get_top_processes_sort_by_memory() {
        let system_ops = PlatformFactory::create_system_operations();
        let result = system_ops.get_top_processes(10, Some("memory")).await;

        assert!(
            result.is_ok(),
            "get_top_processes failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_check_disk_space_with_thresholds() {
        let system_ops = PlatformFactory::create_system_operations();

        // Test with very high thresholds (should report OK)
        let result = system_ops.check_disk_space(99.0, 99.5).await;
        assert!(result.is_ok());

        let (_, _, data) = result.unwrap();
        if let Some(data) = data {
            let status = data.get("status").and_then(|v| v.as_str());
            assert_eq!(status, Some("ok"), "With very high thresholds, should be OK");
        }
    }
}

/// SafeCommandExecutor integration tests
///
/// These tests verify that SafeCommandExecutor correctly delegates to
/// SystemOperations through PlatformFactory.
mod safe_executor_tests {
    use infiniservice::commands::safe_executor::SafeCommandExecutor;
    use infiniservice::commands::{SafeCommandRequest, SafeCommandType};
    use uuid::Uuid;

    /// Helper to create a SafeCommandRequest with a given command type
    fn make_request(command_type: SafeCommandType) -> SafeCommandRequest {
        SafeCommandRequest {
            id: Uuid::new_v4().to_string(),
            command_type,
            params: None,
            timeout: None,
        }
    }

    #[tokio::test]
    async fn test_executor_creation() {
        // SafeCommandExecutor should successfully create with SystemOperations
        let executor = SafeCommandExecutor::new();
        assert!(executor.is_ok(), "Failed to create SafeCommandExecutor: {:?}", executor.err());
    }

    #[tokio::test]
    async fn test_executor_service_list() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::ServiceList);
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "ServiceList execution failed: {:?}", response.err());
        let response = response.unwrap();
        // The response should have success=true or an acceptable error for missing systemctl
        // In test environments, systemctl may not be available
        if !response.success {
            let stderr = response.stderr;
            assert!(
                stderr.contains("systemctl") || stderr.contains("not found") || stderr.contains("Failed"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[tokio::test]
    async fn test_executor_process_list() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::ProcessList { limit: Some(10) });
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "ProcessList execution failed: {:?}", response.err());
        let response = response.unwrap();
        assert!(response.success, "ProcessList should succeed: {}", response.stderr);
        assert!(response.data.is_some(), "ProcessList should return data");
    }

    #[tokio::test]
    async fn test_executor_package_list() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::PackageList);
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "PackageList execution failed: {:?}", response.err());
        let response = response.unwrap();
        // Package listing might fail on minimal systems without package managers
        // but should not panic or return an unexpected error
        if !response.success {
            let stderr = response.stderr;
            assert!(
                stderr.contains("dpkg") || stderr.contains("rpm") || stderr.contains("winget")
                    || stderr.contains("not found") || stderr.contains("Failed"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_executor_check_linux_updates() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::CheckLinuxUpdates);
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "CheckLinuxUpdates execution failed: {:?}", response.err());
        let response = response.unwrap();
        // Update checking might fail on systems without apt/dnf, but should not panic
        if !response.success {
            let stderr = response.stderr;
            assert!(
                stderr.contains("apt") || stderr.contains("dnf") || stderr.contains("yum")
                    || stderr.contains("not found") || stderr.contains("Failed") || stderr.contains("updates"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_executor_check_linux_security() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::CheckLinuxSecurity);
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "CheckLinuxSecurity execution failed: {:?}", response.err());
        let response = response.unwrap();
        // Security checking should succeed or fail gracefully
        if !response.success {
            let stderr = response.stderr;
            assert!(
                stderr.contains("firewall") || stderr.contains("security")
                    || stderr.contains("not found") || stderr.contains("Failed"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_executor_disk_cleanup() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::DiskCleanup {
            drive: "/".to_string(),
            targets: vec!["temp-files".to_string()],
        });
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "DiskCleanup execution failed: {:?}", response.err());
        let response = response.unwrap();
        // Disk cleanup might fail due to permissions but should not panic
        if !response.success {
            let stderr = response.stderr;
            // Expected to fail without sudo, but the error should be meaningful
            assert!(
                stderr.contains("Permission") || stderr.contains("sudo")
                    || stderr.contains("cleanup") || stderr.contains("Failed")
                    || stderr.contains("privilege"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_executor_check_windows_updates() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::CheckWindowsUpdates);
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "CheckWindowsUpdates execution failed: {:?}", response.err());
        let response = response.unwrap();
        // Windows update checking should succeed on Windows
        if !response.success {
            let stderr = response.stderr;
            assert!(
                stderr.contains("update") || stderr.contains("Windows") || stderr.contains("Failed"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_executor_check_windows_defender() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::CheckWindowsDefender);
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "CheckWindowsDefender execution failed: {:?}", response.err());
        let response = response.unwrap();
        // Defender checking should succeed on Windows
        if !response.success {
            let stderr = response.stderr;
            assert!(
                stderr.contains("Defender") || stderr.contains("security") || stderr.contains("Failed"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_executor_disk_cleanup_windows() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::DiskCleanup {
            drive: "C:".to_string(),
            targets: vec!["temp-files".to_string()],
        });
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "DiskCleanup execution failed: {:?}", response.err());
        let response = response.unwrap();
        // Windows disk cleanup should fail with our implementation (not supported)
        // or succeed if implemented
        if !response.success {
            let stderr = response.stderr;
            assert!(
                stderr.contains("not supported") || stderr.contains("Windows")
                    || stderr.contains("cleanup") || stderr.contains("Failed"),
                "Unexpected error: {}",
                stderr
            );
        }
    }

    #[tokio::test]
    async fn test_executor_user_list() {
        let executor = SafeCommandExecutor::new().expect("Failed to create executor");
        let request = make_request(SafeCommandType::UserList);
        let response = executor.execute(request).await;

        assert!(response.is_ok(), "UserList execution failed: {:?}", response.err());
        let response = response.unwrap();
        assert!(response.success, "UserList should succeed: {}", response.stderr);
        assert!(response.data.is_some(), "UserList should return data");
    }
}
