/// Test program to verify metrics collection functionality
/// 
/// This example demonstrates the complete metrics collection capabilities
/// of the InfiniService data collector, showing all system metrics including:
/// - CPU usage and temperature
/// - Memory statistics  
/// - Disk I/O and usage
/// - Network interface statistics
/// - Process information
/// - Port monitoring
/// - Windows services (on Windows)

use infiniservice::collector::DataCollector;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("=== InfiniService Metrics Collector Test ===\n");
    
    // Create the data collector
    println!("Initializing data collector...");
    let mut collector = DataCollector::new()?;
    println!("✓ Data collector initialized successfully\n");
    
    // Perform initial collection to establish baseline
    println!("Performing initial collection (establishing baseline)...");
    let initial_info = collector.collect().await?;
    println!("✓ Initial collection complete\n");
    
    // Wait a bit to allow for rate calculations
    println!("Waiting 2 seconds for rate calculations...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Perform second collection with rate calculations
    println!("Performing second collection (with rate calculations)...");
    let system_info = collector.collect().await?;
    println!("✓ Second collection complete\n");
    
    // Display collected metrics
    println!("=== System Metrics ===\n");
    
    // CPU Metrics
    println!("📊 CPU Metrics:");
    println!("  • Global Usage: {:.2}%", system_info.metrics.cpu.usage_percent);
    println!("  • Core Count: {}", system_info.metrics.cpu.cores_usage.len());
    if !system_info.metrics.cpu.cores_usage.is_empty() {
        println!("  • Core Usage:");
        for (i, usage) in system_info.metrics.cpu.cores_usage.iter().enumerate() {
            println!("    - Core {}: {:.2}%", i, usage);
        }
    }
    if let Some(temp) = system_info.metrics.cpu.temperature {
        println!("  • Temperature: {:.1}°C", temp);
    } else {
        println!("  • Temperature: Not available");
    }
    println!();
    
    // Memory Metrics
    println!("💾 Memory Metrics:");
    let mem = &system_info.metrics.memory;
    println!("  • Total: {:.2} GB", mem.total_kb as f64 / 1_048_576.0);
    println!("  • Used: {:.2} GB ({:.1}%)", 
        mem.used_kb as f64 / 1_048_576.0,
        (mem.used_kb as f64 / mem.total_kb as f64) * 100.0
    );
    println!("  • Available: {:.2} GB", mem.available_kb as f64 / 1_048_576.0);
    if let Some(swap_total) = mem.swap_total_kb {
        println!("  • Swap Total: {:.2} GB", swap_total as f64 / 1_048_576.0);
        if let Some(swap_used) = mem.swap_used_kb {
            println!("  • Swap Used: {:.2} GB", swap_used as f64 / 1_048_576.0);
        }
    }
    println!();
    
    // Disk Metrics
    println!("💿 Disk Metrics:");
    if !system_info.metrics.disk.usage_stats.is_empty() {
        println!("  Disk Usage:");
        for disk in &system_info.metrics.disk.usage_stats {
            println!("  • {} ({})", disk.mount_point, disk.filesystem);
            println!("    - Total: {:.2} GB", disk.total_gb);
            println!("    - Used: {:.2} GB ({:.1}%)", 
                disk.used_gb,
                (disk.used_gb / disk.total_gb) * 100.0
            );
            println!("    - Available: {:.2} GB", disk.available_gb);
        }
    } else {
        println!("  • No disk usage information available");
    }
    
    let io = &system_info.metrics.disk.io_stats;
    println!("  Disk I/O:");
    println!("    - Read: {:.2} MB/s", io.read_bytes_per_sec as f64 / 1_048_576.0);
    println!("    - Write: {:.2} MB/s", io.write_bytes_per_sec as f64 / 1_048_576.0);
    println!("    - Read Ops: {} ops/s", io.read_ops_per_sec);
    println!("    - Write Ops: {} ops/s", io.write_ops_per_sec);
    println!();
    
    // Network Metrics
    println!("🌐 Network Metrics:");
    if !system_info.metrics.network.interfaces.is_empty() {
        for interface in &system_info.metrics.network.interfaces {
            println!("  • Interface: {}", interface.name);
            println!("    - RX: {:.2} MB/s ({} packets/s)", 
                interface.bytes_received as f64 / 1_048_576.0,
                interface.packets_received
            );
            println!("    - TX: {:.2} MB/s ({} packets/s)", 
                interface.bytes_sent as f64 / 1_048_576.0,
                interface.packets_sent
            );
            if interface.errors_in > 0 || interface.errors_out > 0 {
                println!("    - Errors: {} in, {} out", 
                    interface.errors_in, 
                    interface.errors_out
                );
            }
        }
    } else {
        println!("  • No network interfaces detected");
    }
    println!();
    
    // System Information
    println!("🖥️  System Information:");
    let sys = &system_info.metrics.system;
    println!("  • Hostname: {}", sys.hostname);
    println!("  • OS: {} {}", sys.name, sys.os_version);
    println!("  • Kernel: {}", sys.kernel_version);
    println!("  • Uptime: {} hours", sys.uptime_seconds / 3600);
    if let Some(load_avg) = &sys.load_average {
        println!("  • Load Average: {:.2} {:.2} {:.2}", 
            load_avg.load_1min, 
            load_avg.load_5min, 
            load_avg.load_15min
        );
    }
    println!();
    
    // Process Metrics
    println!("⚙️  Top Processes (by CPU usage):");
    let process_count = system_info.metrics.processes.len().min(5);
    for process in &system_info.metrics.processes[..process_count] {
        println!("  • {} (PID: {})", process.name, process.id);
        println!("    - CPU: {:.2}%", process.cpu_usage_percent);
        println!("    - Memory: {:.2} MB", process.memory_usage_kb as f64 / 1024.0);
        println!("    - Status: {}", process.status);
    }
    println!();
    
    // Port Information
    println!("🔌 Open Ports:");
    let listening_ports: Vec<_> = system_info.metrics.ports.iter()
        .filter(|p| p.is_listening)
        .take(10)
        .collect();
    
    if !listening_ports.is_empty() {
        for port in listening_ports {
            let process_info = port.process_name.as_ref()
                .map(|name| format!(" ({})", name))
                .unwrap_or_default();
            println!("  • {}:{} - {}{}", 
                port.protocol, 
                port.port, 
                port.state,
                process_info
            );
        }
    } else {
        println!("  • No listening ports detected");
    }
    println!();
    
    // Windows Services (if on Windows)
    #[cfg(windows)]
    {
        println!("🪟 Windows Services:");
        let service_count = system_info.metrics.windows_services.len().min(5);
        if service_count > 0 {
            println!("  • Total services: {}", system_info.metrics.windows_services.len());
            for service in &system_info.metrics.windows_services[..service_count] {
                if let Some(name) = service.get("display_name").and_then(|v| v.as_str()) {
                    if let Some(state) = service.get("state").and_then(|v| v.as_str()) {
                        println!("    - {}: {}", name, state);
                    }
                }
            }
        } else {
            println!("  • No Windows services detected");
        }
        println!();
    }
    
    // Performance summary
    println!("=== Collection Performance ===");
    println!("  • Timestamp: {}", system_info.timestamp);
    println!("  • Collection completed successfully");
    
    // Serialize to JSON to verify structure
    let json = serde_json::to_string_pretty(&system_info)?;
    println!("\n=== JSON Output Sample (first 500 chars) ===");
    println!("{}", &json[..json.len().min(500)]);
    if json.len() > 500 {
        println!("... (truncated, total size: {} bytes)", json.len());
    }
    
    println!("\n✅ All metrics collected successfully!");
    
    Ok(())
}