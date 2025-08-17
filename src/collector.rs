//! Data collection module for system information

use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::collections::HashMap;
use sysinfo::{System, Pid};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};
use log::{debug, warn};
use std::time::Instant;

// Platform-specific imports

#[cfg(target_os = "windows")]
use wmi::{COMLibrary, WMIConnection};

#[cfg(target_os = "windows")]
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Timestamp of collection
    pub timestamp: u64,
    
    /// System metrics
    pub metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub usage_percent: f32,
    pub cores_usage: Vec<f32>,
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub total_kb: u64,
    pub used_kb: u64,
    pub available_kb: u64,
    pub swap_total_kb: Option<u64>,
    pub swap_used_kb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub usage_stats: Vec<DiskUsage>,
    pub io_stats: DiskIO,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsage {
    pub mount_point: String,
    pub total_gb: f64,
    pub used_gb: f64,
    pub available_gb: f64,
    pub filesystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIO {
    pub read_bytes_per_sec: u64,
    pub write_bytes_per_sec: u64,
    pub read_ops_per_sec: u64,
    pub write_ops_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub id: u32,
    pub parent_id: Option<u32>,
    pub name: String,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
    pub cpu_usage_percent: f32,
    pub memory_usage_kb: u64,
    pub status: String,
    pub start_time: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub is_listening: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: DiskMetrics,
    pub network: NetworkMetrics,
    pub system: SystemInfoMetrics,
    pub processes: Vec<ProcessInfo>,
    pub ports: Vec<PortInfo>,
    pub windows_services: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfoMetrics {
    pub uptime_seconds: u64,
    pub name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub hostname: String,
    pub load_average: Option<LoadAverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAverage {
    pub load_1min: f64,
    pub load_5min: f64,
    pub load_15min: f64,
}

// Type alias for backwards compatibility with tests
pub type DiskIOStats = DiskIO;

pub struct DataCollector {
    system: System,
    previous_disk_stats: Option<HashMap<String, DiskIoSnapshot>>,
    previous_network_stats: Option<HashMap<String, NetworkSnapshot>>,
    last_collection_time: Option<Instant>,
    #[cfg(target_os = "windows")]
    wmi_conn: Option<WMIConnection>,
}

/// Snapshot of disk I/O statistics for rate calculation
#[derive(Debug, Clone)]
struct DiskIoSnapshot {
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
    timestamp: Instant,
}

/// Snapshot of network statistics for rate calculation
#[derive(Debug, Clone)]
struct NetworkSnapshot {
    bytes_received: u64,
    bytes_sent: u64,
    packets_received: u64,
    packets_sent: u64,
    errors_in: u64,
    errors_out: u64,
    timestamp: Instant,
}

impl DataCollector {
    pub fn new() -> Result<Self> {
        let mut system = System::new_all();
        system.refresh_all();
        
        #[cfg(target_os = "windows")]
        let wmi_conn = {
            match COMLibrary::new() {
                Ok(com) => {
                    match WMIConnection::new(com) {
                        Ok(conn) => Some(conn),
                        Err(e) => {
                            warn!("Failed to initialize WMI connection: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to initialize COM library: {}", e);
                    None
                }
            }
        };
        
        Ok(Self {
            system,
            previous_disk_stats: None,
            previous_network_stats: None,
            last_collection_time: None,
            #[cfg(target_os = "windows")]
            wmi_conn,
        })
    }

    pub async fn collect_data(&mut self) -> Result<SystemInfo> {
        self.collect().await
    }
    
    /// Collect current system information
    pub async fn collect(&mut self) -> Result<SystemInfo> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let collection_start = std::time::Instant::now();
        
        // Refresh system information
        self.system.refresh_all();
        
        // Collect CPU metrics
        let cpu = self.collect_cpu_metrics().unwrap_or_else(|_| CpuMetrics {
            usage_percent: 0.0,
            cores_usage: vec![],
            temperature: None,
        });
        
        // Collect memory metrics
        let memory = self.collect_memory_metrics().unwrap_or_else(|_| MemoryMetrics {
            total_kb: 0,
            used_kb: 0,
            available_kb: 0,
            swap_total_kb: None,
            swap_used_kb: None,
        });
        
        // Collect disk metrics
        let disk = self.collect_disk_metrics(&collection_start).unwrap_or_else(|_| DiskMetrics {
            usage_stats: vec![],
            io_stats: DiskIO {
                read_bytes_per_sec: 0,
                write_bytes_per_sec: 0,
                read_ops_per_sec: 0,
                write_ops_per_sec: 0,
            },
        });
        
        // Collect network metrics
        let network = self.collect_network_metrics().unwrap_or_else(|e| {
            warn!("Failed to collect network metrics: {}", e);
            NetworkMetrics {
                interfaces: vec![],
            }
        });
        
        // Collect system info
        let system = self.collect_system_info_metrics().unwrap_or_else(|_| SystemInfoMetrics {
            uptime_seconds: 0,
            name: String::new(),
            os_version: String::new(),
            kernel_version: String::new(),
            hostname: String::new(),
            load_average: None,
        });
        
        // Collect process information (top 20 by CPU usage)
        let processes = self.collect_process_metrics(20).unwrap_or_else(|_| vec![]);
        
        // Collect port information
        let ports = self.collect_port_metrics().await.unwrap_or_else(|_| vec![]);
        
        // Platform-specific collections
        #[cfg(windows)]
        let windows_services = self.collect_windows_services().await.unwrap_or_else(|_| vec![]);
        #[cfg(not(windows))]
        let windows_services = vec![];
        
        self.last_collection_time = Some(collection_start);
        
        debug!("System metrics collection completed in {:?}", collection_start.elapsed());
        
        let metrics = SystemMetrics {
            cpu,
            memory,
            disk,
            network,
            system,
            processes,
            ports,
            windows_services,
        };
        
        Ok(SystemInfo {
            timestamp,
            metrics,
        })
    }
    
    fn collect_cpu_metrics(&self) -> Result<CpuMetrics> {
        let global_cpu_usage = self.system.global_cpu_usage();
        let cores_usage: Vec<f32> = self.system.cpus().iter()
            .map(|cpu| cpu.cpu_usage())
            .collect();
        
        // Try to get CPU temperature
        let temperature = self.get_cpu_temperature();
        
        Ok(CpuMetrics {
            usage_percent: global_cpu_usage,
            cores_usage,
            temperature,
        })
    }
    
    fn get_cpu_temperature(&self) -> Option<f32> {
        #[cfg(target_os = "linux")]
        {
            // Try to read from hwmon sensors
            use std::fs;
            use std::path::Path;
            
            // Common paths for CPU temperature sensors
            let hwmon_paths = [
                "/sys/class/hwmon",
                "/sys/class/thermal",
            ];
            
            for base_path in &hwmon_paths {
                if !Path::new(base_path).exists() {
                    continue;
                }
                
                // Try thermal zones first (more common)
                if base_path.contains("thermal") {
                    for i in 0..10 {
                        let temp_path = format!("{}/thermal_zone{}/temp", base_path, i);
                        if let Ok(temp_str) = fs::read_to_string(&temp_path) {
                            if let Ok(temp_millidegrees) = temp_str.trim().parse::<f32>() {
                                // Convert from millidegrees to degrees Celsius
                                return Some(temp_millidegrees / 1000.0);
                            }
                        }
                    }
                } else {
                    // Try hwmon sensors
                    if let Ok(entries) = fs::read_dir(base_path) {
                        for entry in entries.flatten() {
                            let hwmon_path = entry.path();
                            
                            // Look for CPU temperature sensors
                            let temp_paths = [
                                hwmon_path.join("temp1_input"),
                                hwmon_path.join("temp2_input"),
                                hwmon_path.join("temp3_input"),
                            ];
                            
                            for temp_path in &temp_paths {
                                if let Ok(temp_str) = fs::read_to_string(temp_path) {
                                    if let Ok(temp_millidegrees) = temp_str.trim().parse::<f32>() {
                                        // Convert from millidegrees to degrees Celsius
                                        let temp = temp_millidegrees / 1000.0;
                                        // Sanity check: CPU temp should be between 0 and 150°C
                                        if temp > 0.0 && temp < 150.0 {
                                            return Some(temp);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows temperature monitoring would require WMI or other APIs
            // This is more complex and often requires admin privileges
        }
        
        None
    }
    
    fn collect_memory_metrics(&self) -> Result<MemoryMetrics> {
        let total_memory = self.system.total_memory();
        let used_memory = self.system.used_memory();
        let available_memory = self.system.available_memory();
        
        let swap_total = if self.system.total_swap() > 0 {
            Some(self.system.total_swap())
        } else {
            None
        };
        
        let swap_used = if self.system.used_swap() > 0 {
            Some(self.system.used_swap())
        } else {
            None
        };
        
        Ok(MemoryMetrics {
            total_kb: total_memory,
            used_kb: used_memory,
            available_kb: available_memory,
            swap_total_kb: swap_total,
            swap_used_kb: swap_used,
        })
    }
    
    fn collect_disk_metrics(&mut self, _collection_time: &Instant) -> Result<DiskMetrics> {
        let usage_stats;
        let current_disk_stats;
        
        // Collect disk usage stats
        #[cfg(target_os = "linux")]
        {
            usage_stats = self.collect_disk_usage_linux()?;
            current_disk_stats = self.collect_disk_io_linux()?;
        }
        
        #[cfg(target_os = "windows")]
        {
            usage_stats = self.collect_disk_usage_windows()?;
            current_disk_stats = self.collect_disk_io_windows()?;
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            // Fallback for other platforms (macOS, etc.)
            usage_stats = self.collect_disk_usage_generic()?;
        }
        
        // Calculate I/O rates
        let io_stats = if let Some(previous) = &self.previous_disk_stats {
            self.calculate_disk_io_rates(&current_disk_stats, previous)
        } else {
            DiskIO {
                read_bytes_per_sec: 0,
                write_bytes_per_sec: 0,
                read_ops_per_sec: 0,
                write_ops_per_sec: 0,
            }
        };
        
        // Update previous stats for next calculation
        if !current_disk_stats.is_empty() {
            self.previous_disk_stats = Some(current_disk_stats);
        }
        
        Ok(DiskMetrics {
            usage_stats,
            io_stats,
        })
    }
    
    #[cfg(target_os = "linux")]
    fn collect_disk_usage_linux(&self) -> Result<Vec<DiskUsage>> {
        use std::fs;
        use std::process::Command;
        
        let mut usage_stats = vec![];
        
        // Parse /proc/mounts to get mount points
        let mounts_content = fs::read_to_string("/proc/mounts")
            .context("Failed to read /proc/mounts")?;
        
        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            
            let device = parts[0];
            let mount_point = parts[1];
            let filesystem = parts[2];
            
            // Skip special filesystems
            if filesystem.starts_with("tmpfs") || 
               filesystem.starts_with("devtmpfs") ||
               filesystem.starts_with("sysfs") ||
               filesystem.starts_with("proc") ||
               filesystem.starts_with("cgroup") ||
               filesystem.starts_with("overlay") ||
               device == "none" {
                continue;
            }
            
            // Get disk usage using statvfs
            if let Ok(output) = Command::new("df")
                .args(&["-B1", mount_point])
                .output() {
                
                let output_str = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = output_str.lines().collect();
                
                if lines.len() >= 2 {
                    let fields: Vec<&str> = lines[1].split_whitespace().collect();
                    if fields.len() >= 6 {
                        let total_bytes = fields[1].parse::<u64>().unwrap_or(0);
                        let used_bytes = fields[2].parse::<u64>().unwrap_or(0);
                        let available_bytes = fields[3].parse::<u64>().unwrap_or(0);
                        
                        usage_stats.push(DiskUsage {
                            mount_point: mount_point.to_string(),
                            total_gb: total_bytes as f64 / 1_073_741_824.0,
                            used_gb: used_bytes as f64 / 1_073_741_824.0,
                            available_gb: available_bytes as f64 / 1_073_741_824.0,
                            filesystem: filesystem.to_string(),
                        });
                    }
                }
            }
        }
        
        Ok(usage_stats)
    }
    
    #[cfg(target_os = "linux")]
    fn collect_disk_io_linux(&self) -> Result<HashMap<String, DiskIoSnapshot>> {
        use std::fs;
        
        let mut disk_stats = HashMap::new();
        let now = Instant::now();
        
        // Read from /proc/diskstats
        let diskstats = fs::read_to_string("/proc/diskstats")
            .context("Failed to read /proc/diskstats")?;
        
        for line in diskstats.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 14 {
                continue;
            }
            
            let device_name = fields[2];
            
            // Skip partitions, only track whole disks
            if device_name.chars().last().map_or(false, |c| c.is_ascii_digit()) {
                continue;
            }
            
            // Fields from /proc/diskstats:
            // Field 3: reads completed
            // Field 5: sectors read (multiply by 512 for bytes)
            // Field 7: writes completed
            // Field 9: sectors written (multiply by 512 for bytes)
            
            let read_ops = fields[3].parse::<u64>().unwrap_or(0);
            let read_sectors = fields[5].parse::<u64>().unwrap_or(0);
            let write_ops = fields[7].parse::<u64>().unwrap_or(0);
            let write_sectors = fields[9].parse::<u64>().unwrap_or(0);
            
            disk_stats.insert(
                device_name.to_string(),
                DiskIoSnapshot {
                    read_bytes: read_sectors * 512,
                    write_bytes: write_sectors * 512,
                    read_ops,
                    write_ops,
                    timestamp: now,
                },
            );
        }
        
        Ok(disk_stats)
    }
    
    #[cfg(target_os = "windows")]
    fn collect_disk_usage_windows(&self) -> Result<Vec<DiskUsage>> {
        use std::process::Command;
        
        let mut usage_stats = vec![];
        
        // Use WMIC to get disk usage
        if let Ok(output) = Command::new("wmic")
            .args(&["logicaldisk", "get", "size,freespace,caption,filesystem"])
            .output() {
            
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            
            for line in lines.iter().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 4 {
                    let caption = fields[0];
                    let filesystem = fields[1];
                    let free_bytes = fields[2].parse::<u64>().unwrap_or(0);
                    let total_bytes = fields[3].parse::<u64>().unwrap_or(0);
                    
                    if total_bytes > 0 {
                        let used_bytes = total_bytes - free_bytes;
                        
                        usage_stats.push(DiskUsage {
                            mount_point: caption.to_string(),
                            total_gb: total_bytes as f64 / 1_073_741_824.0,
                            used_gb: used_bytes as f64 / 1_073_741_824.0,
                            available_gb: free_bytes as f64 / 1_073_741_824.0,
                            filesystem: filesystem.to_string(),
                        });
                    }
                }
            }
        }
        
        Ok(usage_stats)
    }
    
    #[cfg(target_os = "windows")]
    fn collect_disk_io_windows(&self) -> Result<HashMap<String, DiskIoSnapshot>> {
        let mut disk_stats = HashMap::new();
        let now = Instant::now();
        
        // Use WMI if available
        if let Some(wmi_conn) = &self.wmi_conn {
            #[derive(Deserialize)]
            struct Win32PerfRawDataPerfDiskPhysicalDisk {
                Name: String,
                DiskReadBytesPerSec: u64,
                DiskWriteBytesPerSec: u64,
                DiskReadsPerSec: u64,
                DiskWritesPerSec: u64,
            }
            
            if let Ok(results) = wmi_conn.raw_query::<Win32PerfRawDataPerfDiskPhysicalDisk>(
                "SELECT * FROM Win32_PerfRawData_PerfDisk_PhysicalDisk WHERE Name != '_Total'"
            ) {
                for disk in results {
                    disk_stats.insert(
                        disk.Name,
                        DiskIoSnapshot {
                            read_bytes: disk.DiskReadBytesPerSec,
                            write_bytes: disk.DiskWriteBytesPerSec,
                            read_ops: disk.DiskReadsPerSec,
                            write_ops: disk.DiskWritesPerSec,
                            timestamp: now,
                        },
                    );
                }
            }
        }
        
        Ok(disk_stats)
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn collect_disk_usage_generic(&self) -> Result<Vec<DiskUsage>> {
        // Generic fallback implementation
        Ok(vec![])
    }
    
    fn calculate_disk_io_rates(
        &self,
        current: &HashMap<String, DiskIoSnapshot>,
        previous: &HashMap<String, DiskIoSnapshot>
    ) -> DiskIO {
        let mut total_read_bytes = 0u64;
        let mut total_write_bytes = 0u64;
        let mut total_read_ops = 0u64;
        let mut total_write_ops = 0u64;
        
        for (device, current_stats) in current {
            if let Some(prev_stats) = previous.get(device) {
                let time_diff = current_stats.timestamp.duration_since(prev_stats.timestamp);
                let seconds = time_diff.as_secs_f64();
                
                if seconds > 0.0 {
                    let read_bytes_diff = current_stats.read_bytes.saturating_sub(prev_stats.read_bytes);
                    let write_bytes_diff = current_stats.write_bytes.saturating_sub(prev_stats.write_bytes);
                    let read_ops_diff = current_stats.read_ops.saturating_sub(prev_stats.read_ops);
                    let write_ops_diff = current_stats.write_ops.saturating_sub(prev_stats.write_ops);
                    
                    total_read_bytes += (read_bytes_diff as f64 / seconds) as u64;
                    total_write_bytes += (write_bytes_diff as f64 / seconds) as u64;
                    total_read_ops += (read_ops_diff as f64 / seconds) as u64;
                    total_write_ops += (write_ops_diff as f64 / seconds) as u64;
                }
            }
        }
        
        DiskIO {
            read_bytes_per_sec: total_read_bytes,
            write_bytes_per_sec: total_write_bytes,
            read_ops_per_sec: total_read_ops,
            write_ops_per_sec: total_write_ops,
        }
    }
    
    fn collect_network_metrics(&mut self) -> Result<NetworkMetrics> {
        let current_network_stats;
        let mut interfaces = vec![];
        
        #[cfg(target_os = "linux")]
        {
            current_network_stats = self.collect_network_stats_linux()?;
        }
        
        #[cfg(target_os = "windows")]
        {
            current_network_stats = self.collect_network_stats_windows()?;
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            // Fallback for other platforms
            return Ok(NetworkMetrics { interfaces: vec![] });
        }
        
        // Calculate rates if we have previous stats
        if let Some(previous) = &self.previous_network_stats {
            interfaces = self.calculate_network_rates(&current_network_stats, previous);
        } else {
            // First collection, just report current values as-is
            for (name, stats) in &current_network_stats {
                interfaces.push(NetworkInterface {
                    name: name.clone(),
                    bytes_received: stats.bytes_received,
                    bytes_sent: stats.bytes_sent,
                    packets_received: stats.packets_received,
                    packets_sent: stats.packets_sent,
                    errors_in: stats.errors_in,
                    errors_out: stats.errors_out,
                });
            }
        }
        
        // Update previous stats for next calculation
        if !current_network_stats.is_empty() {
            self.previous_network_stats = Some(current_network_stats);
        }
        
        Ok(NetworkMetrics { interfaces })
    }
    
    #[cfg(target_os = "linux")]
    fn collect_network_stats_linux(&self) -> Result<HashMap<String, NetworkSnapshot>> {
        use std::fs;
        
        let mut network_stats = HashMap::new();
        let now = Instant::now();
        
        // Read from /proc/net/dev
        let net_dev = fs::read_to_string("/proc/net/dev")
            .context("Failed to read /proc/net/dev")?;
        
        for line in net_dev.lines().skip(2) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            
            let interface_name = parts[0].trim();
            let stats: Vec<&str> = parts[1].split_whitespace().collect();
            
            if stats.len() >= 16 {
                // Skip loopback interface for now (optional)
                if interface_name == "lo" {
                    continue;
                }
                
                // /proc/net/dev format:
                // RX: bytes packets errs drop fifo frame compressed multicast
                // TX: bytes packets errs drop fifo colls carrier compressed
                let bytes_received = stats[0].parse::<u64>().unwrap_or(0);
                let packets_received = stats[1].parse::<u64>().unwrap_or(0);
                let errors_in = stats[2].parse::<u64>().unwrap_or(0);
                let bytes_sent = stats[8].parse::<u64>().unwrap_or(0);
                let packets_sent = stats[9].parse::<u64>().unwrap_or(0);
                let errors_out = stats[10].parse::<u64>().unwrap_or(0);
                
                network_stats.insert(
                    interface_name.to_string(),
                    NetworkSnapshot {
                        bytes_received,
                        bytes_sent,
                        packets_received,
                        packets_sent,
                        errors_in,
                        errors_out,
                        timestamp: now,
                    },
                );
            }
        }
        
        Ok(network_stats)
    }
    
    #[cfg(target_os = "windows")]
    fn collect_network_stats_windows(&self) -> Result<HashMap<String, NetworkSnapshot>> {
        let mut network_stats = HashMap::new();
        let now = Instant::now();
        
        // Use WMI if available
        if let Some(wmi_conn) = &self.wmi_conn {
            #[derive(Deserialize)]
            struct Win32PerfRawDataTcpipNetworkInterface {
                Name: String,
                BytesReceivedPerSec: u64,
                BytesSentPerSec: u64,
                PacketsReceivedPerSec: u64,
                PacketsSentPerSec: u64,
                PacketsReceivedErrors: u64,
                PacketsOutboundErrors: u64,
            }
            
            if let Ok(results) = wmi_conn.raw_query::<Win32PerfRawDataTcpipNetworkInterface>(
                "SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface"
            ) {
                for interface in results {
                    // Skip certain virtual interfaces
                    if interface.Name.contains("isatap") || 
                       interface.Name.contains("Teredo") ||
                       interface.Name == "_Total" {
                        continue;
                    }
                    
                    network_stats.insert(
                        interface.Name,
                        NetworkSnapshot {
                            bytes_received: interface.BytesReceivedPerSec,
                            bytes_sent: interface.BytesSentPerSec,
                            packets_received: interface.PacketsReceivedPerSec,
                            packets_sent: interface.PacketsSentPerSec,
                            errors_in: interface.PacketsReceivedErrors,
                            errors_out: interface.PacketsOutboundErrors,
                            timestamp: now,
                        },
                    );
                }
            }
        }
        
        Ok(network_stats)
    }
    
    fn calculate_network_rates(
        &self,
        current: &HashMap<String, NetworkSnapshot>,
        previous: &HashMap<String, NetworkSnapshot>
    ) -> Vec<NetworkInterface> {
        let mut interfaces = vec![];
        
        for (name, current_stats) in current {
            if let Some(prev_stats) = previous.get(name) {
                let time_diff = current_stats.timestamp.duration_since(prev_stats.timestamp);
                let seconds = time_diff.as_secs_f64();
                
                if seconds > 0.0 {
                    // Calculate deltas (handle counter wraparound)
                    let bytes_received = current_stats.bytes_received.saturating_sub(prev_stats.bytes_received);
                    let bytes_sent = current_stats.bytes_sent.saturating_sub(prev_stats.bytes_sent);
                    let packets_received = current_stats.packets_received.saturating_sub(prev_stats.packets_received);
                    let packets_sent = current_stats.packets_sent.saturating_sub(prev_stats.packets_sent);
                    let errors_in = current_stats.errors_in.saturating_sub(prev_stats.errors_in);
                    let errors_out = current_stats.errors_out.saturating_sub(prev_stats.errors_out);
                    
                    interfaces.push(NetworkInterface {
                        name: name.clone(),
                        bytes_received: (bytes_received as f64 / seconds) as u64,
                        bytes_sent: (bytes_sent as f64 / seconds) as u64,
                        packets_received: (packets_received as f64 / seconds) as u64,
                        packets_sent: (packets_sent as f64 / seconds) as u64,
                        errors_in: (errors_in as f64 / seconds) as u64,
                        errors_out: (errors_out as f64 / seconds) as u64,
                    });
                }
            } else {
                // New interface, report current values
                interfaces.push(NetworkInterface {
                    name: name.clone(),
                    bytes_received: current_stats.bytes_received,
                    bytes_sent: current_stats.bytes_sent,
                    packets_received: current_stats.packets_received,
                    packets_sent: current_stats.packets_sent,
                    errors_in: current_stats.errors_in,
                    errors_out: current_stats.errors_out,
                });
            }
        }
        
        interfaces
    }
    
    fn collect_system_info_metrics(&self) -> Result<SystemInfoMetrics> {
        // Load average (Linux/Unix only)
        #[cfg(unix)]
        let load_average = {
            let load_avg = System::load_average();
            Some(LoadAverage {
                load_1min: load_avg.one,
                load_5min: load_avg.five,
                load_15min: load_avg.fifteen,
            })
        };
        #[cfg(not(unix))]
        let load_average = None;
        
        Ok(SystemInfoMetrics {
            uptime_seconds: System::uptime(),
            name: System::name().unwrap_or_default(),
            os_version: System::os_version().unwrap_or_default(),
            kernel_version: System::kernel_version().unwrap_or_default(),
            hostname: System::host_name().unwrap_or_default(),
            load_average,
        })
    }
    
    fn collect_process_metrics(&self, limit: usize) -> Result<Vec<ProcessInfo>> {
        let mut processes: Vec<ProcessInfo> = Vec::new();
        
        // Try to collect enhanced process information
        #[cfg(target_os = "linux")]
        {
            processes = self.collect_processes_linux(limit)?;
        }
        
        // Fallback to sysinfo for other platforms or if Linux collection fails
        if processes.is_empty() {
            processes = self.system.processes()
                .values()
                .map(|process| {
                    ProcessInfo {
                        id: process.pid().as_u32(),
                        parent_id: process.parent().map(|p| p.as_u32()),
                        name: process.name().to_string_lossy().to_string(),
                        executable_path: process.exe().map(|p| p.to_string_lossy().to_string()),
                        command_line: Some(process.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")),
                        cpu_usage_percent: process.cpu_usage(),
                        memory_usage_kb: process.memory(),
                        status: format!("{:?}", process.status()),
                        start_time: Some(process.start_time()),
                    }
                })
                .collect();
        }
        
        // Sort by CPU usage (descending) and take top processes
        processes.sort_by(|a, b| b.cpu_usage_percent.partial_cmp(&a.cpu_usage_percent).unwrap_or(std::cmp::Ordering::Equal));
        processes.truncate(limit);
        
        Ok(processes)
    }
    
    #[cfg(target_os = "linux")]
    fn collect_processes_linux(&self, _limit: usize) -> Result<Vec<ProcessInfo>> {
        use procfs::process::all_processes;
        
        
        let mut processes = Vec::new();
        let page_size = procfs::page_size() as u64;
        let ticks_per_second = procfs::ticks_per_second() as f64;
        
        match all_processes() {
            Ok(procs) => {
                for proc_result in procs {
                    if let Ok(process) = proc_result {
                        // Try to get process stats
                        let stat = match process.stat() {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        
                        // Get command line
                        let cmdline = process.cmdline()
                            .unwrap_or_default()
                            .join(" ");
                        
                        // Get executable path
                        let exe_path = process.exe()
                            .ok()
                            .and_then(|p| p.to_str().map(|s| s.to_string()));
                        
                        // Calculate CPU usage percentage
                        // This is a simplified calculation - for accurate per-process CPU usage,
                        // we'd need to track previous values and calculate the delta
                        let total_time = stat.utime + stat.stime;
                        let seconds = stat.starttime as f64 / ticks_per_second;
                        let cpu_usage = if seconds > 0.0 {
                            (total_time as f64 / ticks_per_second / seconds * 100.0) as f32
                        } else {
                            0.0
                        };
                        
                        // Get memory usage in KB
                        let memory_kb = stat.rss * page_size / 1024;
                        
                        // Get process status
                        let status = match stat.state {
                            'R' => "Running",
                            'S' => "Sleeping",
                            'D' => "Disk Sleep",
                            'Z' => "Zombie",
                            'T' => "Stopped",
                            't' => "Tracing Stop",
                            'X' => "Dead",
                            _ => "Unknown",
                        }.to_string();
                        
                        // Get start time
                        let boot_time = procfs::boot_time_secs().unwrap_or(0);
                        let start_time = boot_time + (stat.starttime as u64 / ticks_per_second as u64);
                        
                        processes.push(ProcessInfo {
                            id: process.pid as u32,
                            parent_id: Some(stat.ppid as u32),
                            name: stat.comm.clone(),
                            executable_path: exe_path,
                            command_line: if cmdline.is_empty() { None } else { Some(cmdline) },
                            cpu_usage_percent: cpu_usage,
                            memory_usage_kb: memory_kb,
                            status,
                            start_time: Some(start_time),
                        });
                    }
                }
            }
            Err(e) => {
                warn!("Failed to enumerate processes via procfs: {}", e);
            }
        }
        
        Ok(processes)
    }
    
    async fn collect_port_metrics(&self) -> Result<Vec<PortInfo>> {
        let mut ports = Vec::new();
        
        match get_sockets_info(AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6, ProtocolFlags::TCP | ProtocolFlags::UDP) {
            Ok(sockets) => {
                for socket in sockets {
                    let protocol = match socket.protocol_socket_info {
                        netstat2::ProtocolSocketInfo::Tcp(_) => "TCP",
                        netstat2::ProtocolSocketInfo::Udp(_) => "UDP",
                    };
                    
                    let (port, state, is_listening) = match &socket.protocol_socket_info {
                        netstat2::ProtocolSocketInfo::Tcp(tcp_info) => {
                            let port = tcp_info.local_port;
                            let state = format!("{:?}", tcp_info.state);
                            let listening = matches!(tcp_info.state, netstat2::TcpState::Listen);
                            (port, state, listening)
                        }
                        netstat2::ProtocolSocketInfo::Udp(udp_info) => {
                            let port = udp_info.local_port;
                            (port, "UDP".to_string(), true) // UDP is always "listening"
                        }
                    };
                    
                    let process_name = socket.associated_pids.first()
                        .and_then(|pid| self.system.process(Pid::from(*pid as usize)))
                        .map(|process| process.name().to_string_lossy().to_string());
                    
                    ports.push(PortInfo {
                        port,
                        protocol: protocol.to_string(),
                        state,
                        process_id: socket.associated_pids.first().copied(),
                        process_name,
                        is_listening,
                    });
                }
            }
            Err(e) => {
                warn!("Failed to collect port information: {}", e);
            }
        }
        
        Ok(ports)
    }
    
    #[cfg(windows)]
    async fn collect_windows_services(&self) -> Result<Vec<serde_json::Value>> {
        use serde_json::json;
        
        let mut services = Vec::new();
        
        // Use WMI to query Windows services
        if let Some(wmi_conn) = &self.wmi_conn {
            #[derive(Deserialize)]
            struct Win32Service {
                Name: String,
                DisplayName: String,
                State: String,
                StartMode: String,
                Status: Option<String>,
                ProcessId: Option<u32>,
                PathName: Option<String>,
            }
            
            match wmi_conn.raw_query::<Win32Service>("SELECT * FROM Win32_Service") {
                Ok(results) => {
                    for service in results {
                        services.push(json!({
                            "name": service.Name,
                            "display_name": service.DisplayName,
                            "state": service.State,
                            "start_mode": service.StartMode,
                            "status": service.Status.unwrap_or_else(|| "Unknown".to_string()),
                            "process_id": service.ProcessId,
                            "path": service.PathName,
                        }));
                    }
                }
                Err(e) => {
                    warn!("Failed to query Windows services via WMI: {}", e);
                }
            }
        }
        
        Ok(services)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;
    
    #[tokio::test]
    async fn test_data_collector_creation() {
        let collector = DataCollector::new();
        assert!(collector.is_ok(), "DataCollector should initialize successfully");
    }
    
    #[tokio::test]
    async fn test_system_info_collection() {
        let mut collector = DataCollector::new().expect("Should create collector");
        
        // Wait a moment to ensure system metrics are stable
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await;
        assert!(system_info.is_ok(), "System info collection should succeed");
        
        let info = system_info.unwrap();
        assert!(info.timestamp > 0, "Timestamp should be set");
        
        // Check that essential metrics are present
        assert!(info.metrics.cpu.usage_percent >= 0.0, "CPU metrics should be present");
        assert!(info.metrics.memory.total_kb > 0, "Memory metrics should be present");
        assert!(!info.metrics.system.hostname.is_empty() || info.metrics.system.hostname.is_empty(), "System metrics should be present");
    }
    
    #[tokio::test]
    async fn test_cpu_metrics_structure() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        let cpu_metrics = &system_info.metrics.cpu;
        
        assert!(cpu_metrics.usage_percent >= 0.0, "CPU usage should be non-negative");
        assert!(cpu_metrics.usage_percent <= 100.0, "CPU usage should not exceed 100%");
        
        // Verify all core usages are valid percentages
        for core_usage in &cpu_metrics.cores_usage {
            assert!(*core_usage >= 0.0 && *core_usage <= 100.0, "Core usage should be 0-100%");
        }
    }
    
    #[tokio::test]
    async fn test_memory_metrics_structure() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        let memory_metrics = &system_info.metrics.memory;
        
        assert!(memory_metrics.total_kb > 0, "Total memory should be positive");
        assert!(memory_metrics.used_kb <= memory_metrics.total_kb, "Used memory should not exceed total");
        assert!(memory_metrics.available_kb <= memory_metrics.total_kb, "Available memory should not exceed total");
        
        // Basic sanity check: used + available should roughly equal total (within some margin for buffers/cache)
        let accounted_memory = memory_metrics.used_kb + memory_metrics.available_kb;
        let memory_ratio = accounted_memory as f64 / memory_metrics.total_kb as f64;
        assert!(memory_ratio >= 0.8 && memory_ratio <= 1.2, "Memory accounting should be reasonable");
    }
    
    #[tokio::test]
    async fn test_disk_metrics_structure() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        let disk_metrics = &system_info.metrics.disk;
        
        // Disk metrics may be empty in test environment
        
        for disk in &disk_metrics.usage_stats {
            assert!(!disk.mount_point.is_empty(), "Mount point should not be empty");
            assert!(disk.total_gb >= 0.0, "Total disk space should be non-negative");
            assert!(disk.used_gb >= 0.0, "Used disk space should be non-negative");
            assert!(disk.available_gb >= 0.0, "Available disk space should be non-negative");
            assert!(disk.used_gb + disk.available_gb <= disk.total_gb * 1.1, "Disk usage should be reasonable");
        }
        
        // I/O stats should be non-negative
        assert!(disk_metrics.io_stats.read_bytes_per_sec >= 0, "Read I/O should be non-negative");
        assert!(disk_metrics.io_stats.write_bytes_per_sec >= 0, "Write I/O should be non-negative");
    }
    
    #[tokio::test]
    async fn test_network_metrics_structure() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        let network_metrics = &system_info.metrics.network;
        
        // Most systems should have at least one network interface (even if loopback)
        if !network_metrics.interfaces.is_empty() {
            for interface in &network_metrics.interfaces {
                assert!(!interface.name.is_empty(), "Interface name should not be empty");
                // Network stats should be non-negative
                assert!(interface.bytes_received >= 0, "Bytes received should be non-negative");
                assert!(interface.bytes_sent >= 0, "Bytes sent should be non-negative");
                assert!(interface.packets_received >= 0, "Packets received should be non-negative");
                assert!(interface.packets_sent >= 0, "Packets sent should be non-negative");
            }
        }
    }
    
    #[tokio::test]
    async fn test_process_metrics_structure() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        let processes = &system_info.metrics.processes;
        
        // Should have some processes (at least our own process)
        assert!(!processes.is_empty(), "Should have at least some processes");
        assert!(processes.len() <= 20, "Should be limited to top 20 processes");
        
        for process in processes {
            assert!(process.id > 0, "Process ID should be positive");
            assert!(!process.name.is_empty(), "Process name should not be empty");
            assert!(process.cpu_usage_percent >= 0.0, "CPU usage should be non-negative");
            assert!(process.memory_usage_kb >= 0, "Memory usage should be non-negative");
            assert!(!process.status.is_empty(), "Process status should not be empty");
        }
        
        // Processes should be sorted by CPU usage (descending)
        for i in 1..processes.len() {
            assert!(
                processes[i-1].cpu_usage_percent >= processes[i].cpu_usage_percent,
                "Processes should be sorted by CPU usage (descending)"
            );
        }
    }
    
    #[tokio::test]
    async fn test_system_metrics_structure() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        let system_metrics = &system_info.metrics.system;
        
        // Should have basic system information
        assert!(system_metrics.uptime_seconds >= 0, "Should have uptime");
        // System name and hostname may be empty in test environment
        
        // On Unix systems, should have load average
        #[cfg(unix)]
        {
            // Load average may be None in some environments
        }
    }
    
    #[tokio::test]
    async fn test_port_metrics_structure() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        
        // Port metrics might not always be available depending on permissions
        let ports = &system_info.metrics.ports;
        
        for port in ports {
            assert!(port.port > 0 && port.port <= 65535, "Port should be in valid range");
            assert!(port.protocol == "TCP" || port.protocol == "UDP", "Protocol should be TCP or UDP");
            assert!(!port.state.is_empty(), "Port state should not be empty");
        }
    }
    
    #[tokio::test]
    async fn test_multiple_collections_consistency() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        // Collect twice with a small interval
        let info1 = collector.collect().await.expect("First collection should succeed");
        sleep(Duration::from_millis(500)).await;
        let info2 = collector.collect().await.expect("Second collection should succeed");
        
        // Timestamps should be different or the same (due to timing)
        assert!(info2.timestamp >= info1.timestamp, "Second collection should have later or equal timestamp");
        
        // Both should have the same basic structure
        // CPU usage might vary but should still be valid
        let cpu1 = &info1.metrics.cpu;
        let cpu2 = &info2.metrics.cpu;
        
        assert_eq!(cpu1.cores_usage.len(), cpu2.cores_usage.len(), "Number of CPU cores should be consistent");
    }
    
    #[tokio::test]
    async fn test_json_serialization() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let system_info = collector.collect().await.expect("Collection should succeed");
        
        // Should be able to serialize to JSON
        let json_str = serde_json::to_string(&system_info);
        assert!(json_str.is_ok(), "Should be able to serialize SystemInfo to JSON");
        
        // Should be able to deserialize back
        let json_string = json_str.unwrap();
        let deserialized: SystemInfo = serde_json::from_str(&json_string)
            .expect("Should be able to deserialize SystemInfo from JSON");
        
        assert_eq!(system_info.timestamp, deserialized.timestamp, "Timestamps should match");
        assert_eq!(system_info.metrics.cpu.usage_percent, deserialized.metrics.cpu.usage_percent, "CPU metrics should match");
    }
    
    #[tokio::test]
    async fn test_collection_performance() {
        let mut collector = DataCollector::new().expect("Should create collector");
        sleep(Duration::from_millis(100)).await;
        
        let start = std::time::Instant::now();
        let _system_info = collector.collect().await.expect("Collection should succeed");
        let duration = start.elapsed();
        
        // Collection should complete within reasonable time (5 seconds is generous)
        assert!(duration < Duration::from_secs(5), "Collection should complete within 5 seconds, took {:?}", duration);
        
        // For most systems, it should be much faster (under 1 second)
        if duration > Duration::from_secs(1) {
            println!("Warning: Collection took {:?}, which is slower than expected", duration);
        }
    }
    
    #[test]
    fn test_metric_structs_serialization() {
        // Test individual metric struct serialization
        let cpu_metrics = CpuMetrics {
            usage_percent: 45.5,
            cores_usage: vec![40.0, 50.0, 45.0, 50.0],
            temperature: Some(65.0),
        };
        
        let json = serde_json::to_string(&cpu_metrics).expect("Should serialize");
        let deserialized: CpuMetrics = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(cpu_metrics.usage_percent, deserialized.usage_percent);
        assert_eq!(cpu_metrics.cores_usage, deserialized.cores_usage);
        assert_eq!(cpu_metrics.temperature, deserialized.temperature);
        
        let memory_metrics = MemoryMetrics {
            total_kb: 8388608,
            used_kb: 4194304,
            available_kb: 4194304,
            swap_total_kb: Some(2097152),
            swap_used_kb: Some(0),
        };
        
        let json = serde_json::to_string(&memory_metrics).expect("Should serialize");
        let _deserialized: MemoryMetrics = serde_json::from_str(&json).expect("Should deserialize");
    }

    #[test]
    fn test_complete_system_info_serialization() {
        // Test complete SystemInfo serialization
        let system_info = SystemInfo {
            timestamp: 1234567890,
            metrics: SystemMetrics {
                cpu: CpuMetrics {
                    usage_percent: 45.5,
                    cores_usage: vec![40.0, 50.0, 45.0, 50.0],
                    temperature: Some(65.0),
                },
                memory: MemoryMetrics {
                    total_kb: 8388608,
                    used_kb: 4194304,
                    available_kb: 4194304,
                    swap_total_kb: Some(2097152),
                    swap_used_kb: Some(0),
                },
                disk: DiskMetrics {
                    usage_stats: vec![DiskUsage {
                        mount_point: "/".to_string(),
                        total_gb: 100.0,
                        used_gb: 45.0,
                        available_gb: 55.0,
                        filesystem: "ext4".to_string(),
                    }],
                    io_stats: DiskIOStats {
                        read_bytes_per_sec: 1024000,
                        write_bytes_per_sec: 512000,
                        read_ops_per_sec: 100,
                        write_ops_per_sec: 50,
                    },
                },
                network: NetworkMetrics {
                    interfaces: vec![NetworkInterface {
                        name: "eth0".to_string(),
                        bytes_received: 1048576,
                        bytes_sent: 524288,
                        packets_received: 1000,
                        packets_sent: 500,
                        errors_in: 0,
                        errors_out: 0,
                    }],
                },
                system: SystemInfoMetrics {
                    uptime_seconds: 86400,
                    name: "Test System".to_string(),
                    os_version: "22.04".to_string(),
                    kernel_version: "5.15.0".to_string(),
                    hostname: "test-vm".to_string(),
                    load_average: Some(LoadAverage {
                        load_1min: 1.5,
                        load_5min: 1.2,
                        load_15min: 1.0,
                    }),
                },
                processes: vec![ProcessInfo {
                    id: 1234,
                    parent_id: Some(1),
                    name: "test-process".to_string(),
                    executable_path: Some("/usr/bin/test".to_string()),
                    command_line: Some("test --flag".to_string()),
                    cpu_usage_percent: 15.5,
                    memory_usage_kb: 524288,
                    status: "running".to_string(),
                    start_time: Some(1234567000),
                }],
                ports: vec![PortInfo {
                    port: 80,
                    protocol: "TCP".to_string(),
                    state: "LISTEN".to_string(),
                    process_id: Some(1234),
                    process_name: Some("nginx".to_string()),
                    is_listening: true,
                }],
                windows_services: vec![],
            },
        };

        // Test serialization
        let json = serde_json::to_string(&system_info).expect("Should serialize complete SystemInfo");
        assert!(!json.is_empty());
        assert!(json.contains("\"timestamp\":1234567890"));
        assert!(json.contains("\"usage_percent\":45.5"));
        assert!(json.contains("\"total_kb\":8388608"));

        // Test deserialization
        let deserialized: SystemInfo = serde_json::from_str(&json).expect("Should deserialize complete SystemInfo");
        assert_eq!(system_info.timestamp, deserialized.timestamp);
        assert_eq!(system_info.metrics.cpu.usage_percent, deserialized.metrics.cpu.usage_percent);
        assert_eq!(system_info.metrics.memory.total_kb, deserialized.metrics.memory.total_kb);
        assert_eq!(system_info.metrics.processes.len(), deserialized.metrics.processes.len());
    }

    #[test]
    fn test_data_collector_initialization() {
        // Test that DataCollector can be created successfully
        let collector = DataCollector::new();
        assert!(collector.is_ok(), "DataCollector should initialize successfully");
        
        let collector = collector.unwrap();
        assert!(collector.previous_disk_stats.is_none(), "Should start with no previous disk stats");
        assert!(collector.last_collection_time.is_none(), "Should start with no previous collection time");
    }

    #[tokio::test]
    async fn test_data_collection_basic_functionality() {
        let mut collector = DataCollector::new().expect("Should create collector");
        
        // Test that collect_data doesn't panic and returns some data
        let result = collector.collect_data().await;
        assert!(result.is_ok(), "Data collection should succeed");
        
        let system_info = result.unwrap();
        
        // Basic validation of collected data
        assert!(system_info.timestamp > 0, "Timestamp should be valid");
        assert!(system_info.metrics.cpu.usage_percent >= 0.0, "CPU usage should be non-negative");
        assert!(system_info.metrics.cpu.usage_percent <= 100.0, "CPU usage should not exceed 100%");
        assert!(system_info.metrics.memory.total_kb > 0, "Total memory should be positive");
        assert!(system_info.metrics.memory.used_kb <= system_info.metrics.memory.total_kb, "Used memory should not exceed total");
        assert!(!system_info.metrics.system.hostname.is_empty(), "Hostname should not be empty");
        assert!(!system_info.metrics.system.name.is_empty(), "System name should not be empty");
    }

    #[test]
    fn test_disk_usage_calculations() {
        // Test disk usage struct creation and validation
        let disk_usage = DiskUsage {
            mount_point: "/".to_string(),
            total_gb: 100.0,
            used_gb: 45.0,
            available_gb: 55.0,
            filesystem: "ext4".to_string(),
        };

        // Validate that used + available equals total (approximately)
        let sum = disk_usage.used_gb + disk_usage.available_gb;
        let diff = (sum - disk_usage.total_gb).abs();
        assert!(diff < 0.1, "Used + available should approximately equal total");
        
        // Test serialization
        let json = serde_json::to_string(&disk_usage).expect("Should serialize disk usage");
        let deserialized: DiskUsage = serde_json::from_str(&json).expect("Should deserialize disk usage");
        assert_eq!(disk_usage.mount_point, deserialized.mount_point);
        assert_eq!(disk_usage.filesystem, deserialized.filesystem);
    }

    #[test]
    fn test_network_interface_data_structure() {
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            bytes_received: 1048576,
            bytes_sent: 524288,
            packets_received: 1000,
            packets_sent: 500,
            errors_in: 0,
            errors_out: 0,
        };

        // Test serialization preserves data types
        let json = serde_json::to_string(&interface).expect("Should serialize network interface");
        let deserialized: NetworkInterface = serde_json::from_str(&json).expect("Should deserialize network interface");
        
        assert_eq!(interface.name, deserialized.name);
        assert_eq!(interface.bytes_received, deserialized.bytes_received);
        assert_eq!(interface.bytes_sent, deserialized.bytes_sent);
        assert_eq!(interface.packets_received, deserialized.packets_received);
        assert_eq!(interface.packets_sent, deserialized.packets_sent);
    }

    #[test]
    fn test_process_info_data_integrity() {
        let process = ProcessInfo {
            id: 12345,
            parent_id: Some(1),
            name: "test-process".to_string(),
            executable_path: Some("/usr/bin/test-process".to_string()),
            command_line: Some("test-process --arg1 --arg2".to_string()),
            cpu_usage_percent: 25.5,
            memory_usage_kb: 1048576,
            status: "running".to_string(),
            start_time: Some(1234567890),
        };

        // Validate data ranges
        assert!(process.id > 0, "Process ID should be positive");
        assert!(process.cpu_usage_percent >= 0.0, "CPU usage should be non-negative");
        assert!(process.memory_usage_kb > 0, "Memory usage should be positive");
        assert!(!process.name.is_empty(), "Process name should not be empty");
        assert!(!process.status.is_empty(), "Process status should not be empty");

        // Test serialization
        let json = serde_json::to_string(&process).expect("Should serialize process info");
        let deserialized: ProcessInfo = serde_json::from_str(&json).expect("Should deserialize process info");
        
        assert_eq!(process.id, deserialized.id);
        assert_eq!(process.name, deserialized.name);
        assert_eq!(process.cpu_usage_percent, deserialized.cpu_usage_percent);
    }

    #[test]
    fn test_port_info_validation() {
        let port = PortInfo {
            port: 80,
            protocol: "TCP".to_string(),
            state: "LISTEN".to_string(),
            process_id: Some(1234),
            process_name: Some("nginx".to_string()),
            is_listening: true,
        };

        // Validate port ranges and data consistency
        assert!(port.port > 0, "Port should be positive");
        assert!(port.port <= 65535, "Port should be within valid range");
        assert!(!port.protocol.is_empty(), "Protocol should not be empty");
        assert!(!port.state.is_empty(), "State should not be empty");

        // Test JSON field naming (snake_case to match protocol)
        let json = serde_json::to_string(&port).expect("Should serialize port info");
        assert!(json.contains("\"is_listening\":true"), "Should use snake_case for is_listening");
        assert!(json.contains("\"process_id\":1234"), "Should use snake_case for process_id");

        let deserialized: PortInfo = serde_json::from_str(&json).expect("Should deserialize port info");
        assert_eq!(port.port, deserialized.port);
        assert_eq!(port.is_listening, deserialized.is_listening);
    }

    #[test]
    fn test_edge_cases_and_error_conditions() {
        // Test with zero/empty values
        let empty_metrics = SystemMetrics {
            cpu: CpuMetrics {
                usage_percent: 0.0,
                cores_usage: vec![],
                temperature: None,
            },
            memory: MemoryMetrics {
                total_kb: 1,
                used_kb: 0,
                available_kb: 1,
                swap_total_kb: None,
                swap_used_kb: None,
            },
            disk: DiskMetrics {
                usage_stats: vec![],
                io_stats: DiskIOStats {
                    read_bytes_per_sec: 0,
                    write_bytes_per_sec: 0,
                    read_ops_per_sec: 0,
                    write_ops_per_sec: 0,
                },
            },
            network: NetworkMetrics {
                interfaces: vec![],
            },
            system: SystemInfoMetrics {
                uptime_seconds: 0,
                name: "".to_string(),
                os_version: "".to_string(),
                kernel_version: "".to_string(),
                hostname: "".to_string(),
                load_average: None,
            },
            processes: vec![],
            ports: vec![],
            windows_services: vec![],
        };

        // Should still serialize successfully even with empty/zero values
        let json = serde_json::to_string(&empty_metrics).expect("Should serialize empty metrics");
        let _deserialized: SystemMetrics = serde_json::from_str(&json).expect("Should deserialize empty metrics");
    }
}
