/// Example demonstrating the privilege detection functionality
/// This example shows how the new administrator privilege detection works
/// 
/// Usage:
/// cargo run --example test_privilege_detection

use infiniservice::*;

fn main() {
    println!("=== InfiniService Administrator Privilege Detection Demo ===\n");

    // Test the privilege requirement detection function
    println!("Testing privilege requirement detection:");
    
    // Test cases for different error scenarios
    let test_cases = vec![
        (5, "Access denied when opening VirtIO device", true),
        (1314, "A required privilege is not held by the client", true),
        (0, "access denied", true),
        (0, "insufficient privileges", true),
        (0, "requires administrator", true),
        (0, "elevation required", true),
        (2, "File not found", false),
        (0, "Network connection failed", false),
        (0, "Device not available", false),
    ];

    for (error_code, error_message, expected) in test_cases {
        #[cfg(target_os = "windows")]
        {
            let result = windows_com::detect_privilege_requirements(error_code, error_message);
            let status = if result == expected { "✅ PASS" } else { "❌ FAIL" };
            println!("  {} Error {}: '{}' -> {}", status, error_code, error_message, result);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let status = if expected { "⚠️  SKIP (Windows-only)" } else { "⚠️  SKIP (Windows-only)" };
            println!("  {} Error {}: '{}' -> (Windows-only)", status, error_code, error_message);
        }
    }

    println!("\n=== Current System Privilege Status ===");
    
    #[cfg(target_os = "windows")]
    {
        match windows_com::check_admin_privileges() {
            Ok(status) => {
                println!("Administrator Privilege Analysis:");
                println!("  Is Elevated: {}", status.is_elevated);
                println!("  Is Admin Member: {}", status.is_admin_member);
                println!("  Token Type: {}", status.token_elevation_type);
                println!("  UAC Enabled: {}", status.uac_enabled);
                println!("  Elevation Required: {}", status.elevation_required);
                
                if !status.guidance.is_empty() {
                    println!("\nGuidance:");
                    for line in &status.guidance {
                        println!("  {}", line);
                    }
                }
            }
            Err(e) => {
                println!("❌ Failed to check administrator privileges: {}", e);
            }
        }

        println!("\n=== Elevation Guidance ===");
        match windows_com::get_elevation_guidance() {
            Ok(guidance) => {
                for line in guidance {
                    println!("{}", line);
                }
            }
            Err(e) => {
                println!("❌ Failed to get elevation guidance: {}", e);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("⚠️  Administrator privilege detection is only available on Windows");
        println!("   This example demonstrates the functionality that would be available");
        println!("   when running on a Windows system with VirtIO device access issues.");
        println!("\nOn Windows, this would show:");
        println!("  - Current elevation status (elevated/limited/default)");
        println!("  - Administrator group membership");
        println!("  - UAC configuration status");
        println!("  - Step-by-step elevation instructions");
        println!("  - Specific guidance for VirtIO device access");
    }

    println!("\n=== VirtIO Diagnostic Integration ===");
    
    #[cfg(target_os = "windows")]
    {
        println!("Running enhanced VirtIO diagnostic with privilege analysis...");
        match windows_com::diagnose_virtio_installation() {
            Ok(diagnosis) => {
                // Show just the first part of the diagnosis to demonstrate privilege integration
                let lines: Vec<&str> = diagnosis.lines().take(20).collect();
                for line in lines {
                    println!("{}", line);
                }
                if diagnosis.lines().count() > 20 {
                    println!("... (diagnostic output truncated for demo)");
                }
            }
            Err(e) => {
                println!("❌ Failed to run VirtIO diagnostic: {}", e);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("⚠️  VirtIO diagnostic with privilege analysis is only available on Windows");
        println!("   On Windows, this would show:");
        println!("   - Administrator privilege status at the top of diagnostic output");
        println!("   - Privilege-aware error analysis for device access failures");
        println!("   - Specific guidance when privilege issues are detected");
        println!("   - Integration with existing VirtIO device detection");
    }

    println!("\n=== Demo Complete ===");
    println!("This example demonstrates the comprehensive administrator privilege");
    println!("detection and guidance system that has been integrated into InfiniService.");
    println!("\nKey features implemented:");
    println!("  ✅ Automatic privilege requirement detection from error codes");
    println!("  ✅ Current system privilege status analysis");
    println!("  ✅ Step-by-step elevation guidance");
    println!("  ✅ Integration with VirtIO diagnostic system");
    println!("  ✅ Enhanced error messages throughout the service");
}
