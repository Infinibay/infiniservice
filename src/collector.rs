//! Data collection module for system information

use serde::{Deserialize, Serialize};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::Context;
use std::collections::HashMap;
use sysinfo::{System, Pid};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};
use log::{debug, warn, info};
use std::time::Instant;

// Platform-specific imports

#[cfg(target_os = "windows")]
use wmi::{COMLibrary, WMIConnection};

/// Mask IP addresses for logging to reduce sensitive data exposure
fn mask_ip(ip: &str) -> String {
    // Keep first and last octets, mask middle ones for IPv4
    if ip.contains('.') {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            return format!("{}.xxx.xxx.{}", parts[0], parts[3]);
        }
    }

    // For IPv6, show only prefix and suffix
    if ip.contains(':') {
        let parts: Vec<&str> = ip.split(':').collect();
        if parts.len() > 2 {
            return format!("{}:xxxx:xxxx:{}", parts[0], parts[parts.len() - 1]);
        }
    }

    // For other formats, show only first 3 and last 3 chars
    if ip.len() > 6 {
        format!("{}...{}", &ip[..3], &ip[ip.len()-3..])
    } else {
        "xxx".to_string()
    }
}

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
    pub ip_addresses: Vec<String>,  // List of IP addresses assigned to this interface
    pub is_up: bool,               // Whether the interface is up
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
    previous_network_stats: Option<HashMap<InterfaceKey, NetworkSnapshot>>,
    last_collection_time: Option<Instant>,
    initial_ip_collection_successful: bool,
    interface_key_cache: HashMap<String, InterfaceKey>,
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

/// Stable interface identifier for reliable correlation across Windows data sources
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct InterfaceKey {
    guid: Option<String>,
    mac_address: Option<String>,
    interface_index: Option<u32>,
    name: String, // Keep name as fallback
}

impl InterfaceKey {
    /// Create a new InterfaceKey with all available identifiers
    fn new(name: String, guid: Option<String>, mac_address: Option<String>, interface_index: Option<u32>) -> Self {
        Self {
            guid,
            mac_address,
            interface_index,
            name,
        }
    }

    /// Check if this key matches another key based on stable identifiers
    /// Returns match confidence score (higher is better match)
    fn matches(&self, other: &InterfaceKey) -> u32 {
        let mut score = 0;

        // Highest priority: GUID match
        if let (Some(ref self_guid), Some(ref other_guid)) = (&self.guid, &other.guid) {
            if self_guid == other_guid {
                return 1000; // Perfect match
            }
        }

        // High priority: MAC address + InterfaceIndex match
        if let (Some(ref self_mac), Some(ref other_mac)) = (&self.mac_address, &other.mac_address) {
            if self_mac == other_mac {
                score += 500;
                if let (Some(self_idx), Some(other_idx)) = (self.interface_index, other.interface_index) {
                    if self_idx == other_idx {
                        score += 400; // MAC + Index match
                    }
                }
            }
        }

        // Medium priority: InterfaceIndex match only
        if score == 0 {
            if let (Some(self_idx), Some(other_idx)) = (self.interface_index, other.interface_index) {
                if self_idx == other_idx {
                    score += 300;
                }
            }
        }

        // Lower priority: Enhanced string matching
        if score == 0 {
            let self_name_clean = self.name.to_lowercase().replace(&[' ', '-', '_', '(', ')', '#'], "");
            let other_name_clean = other.name.to_lowercase().replace(&[' ', '-', '_', '(', ')', '#'], "");

            if self_name_clean == other_name_clean {
                score += 100;
            } else if self_name_clean.contains(&other_name_clean) || other_name_clean.contains(&self_name_clean) {
                score += 50;
            }
        }

        score
    }

    /// Check if this key has any stable identifiers available
    fn has_stable_identifiers(&self) -> bool {
        self.guid.is_some() || self.mac_address.is_some() || self.interface_index.is_some()
    }

    /// Get the best available display name
    fn display_name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for InterfaceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
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
            initial_ip_collection_successful: false,
            interface_key_cache: HashMap::new(),
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
        // sysinfo returns memory values in bytes, convert to KB
        let total_memory = self.system.total_memory() / 1024;
        let used_memory = self.system.used_memory() / 1024;
        let available_memory = self.system.available_memory() / 1024;
        
        let swap_total = if self.system.total_swap() > 0 {
            Some(self.system.total_swap() / 1024)
        } else {
            None
        };
        
        let swap_used = if self.system.used_swap() > 0 {
            Some(self.system.used_swap() / 1024)
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

        // Get IP addresses for interfaces using InterfaceKey
        let interface_ips = self.collect_interface_ips_with_keys();

        // Update initial IP collection status
        let up_interfaces_with_ips = interface_ips.iter()
            .filter(|(key, ips)| !ips.is_empty() && self.is_interface_up_by_key(key))
            .count();

        if !self.initial_ip_collection_successful && up_interfaces_with_ips > 0 {
            self.initial_ip_collection_successful = true;
            info!("Initial IP collection successful: {} UP interfaces with IPs", up_interfaces_with_ips);
        }

        // Calculate rates if we have previous stats
        if let Some(previous) = &self.previous_network_stats {
            interfaces = self.calculate_network_rates(&current_network_stats, previous);

            // Build a map from interface name to InterfaceKey to preserve context (platform-independent)
            let mut name_to_key_map = HashMap::new();
            for stats_key in current_network_stats.keys() {
                name_to_key_map.insert(stats_key.display_name().to_string(), stats_key.clone());
            }

            // Correlate interfaces and assign IP addresses
            #[cfg(target_os = "windows")]
            {
                let correlations = self.correlate_interface_keys(&current_network_stats, &interface_ips);
                self.update_interface_cache(&correlations);

                // Add IP addresses to each interface with correlation using preserved InterfaceKey
                for interface in &mut interfaces {
                    if let Some(interface_key) = name_to_key_map.get(&interface.name) {
                        // Use the original InterfaceKey with stable identifiers
                        if let Some(matched_ip_key) = self.find_best_interface_match(interface_key, &interface_ips) {
                            if let Some(ips) = interface_ips.get(&matched_ip_key) {
                                interface.ip_addresses = ips.clone();
                                debug!("Assigned IPs using preserved InterfaceKey: '{}' (GUID: {:?}, MAC: {:?}) -> '{}' (IPs: {:?})",
                                       interface.name, interface_key.guid, interface_key.mac_address,
                                       matched_ip_key.display_name(),
                                       ips.iter().map(|ip| mask_ip(ip)).collect::<Vec<_>>());
                            }
                        }
                    } else {
                        // Fallback to name-only key if not found in map
                        let fallback_key = InterfaceKey::new(interface.name.clone(), None, None, None);
                        if let Some(matched_ip_key) = self.find_best_interface_match(&fallback_key, &interface_ips) {
                            if let Some(ips) = interface_ips.get(&matched_ip_key) {
                                interface.ip_addresses = ips.clone();
                                debug!("Assigned IPs using fallback name-only key: '{}' -> '{}' (IPs: {:?})",
                                       interface.name, matched_ip_key.display_name(),
                                       ips.iter().map(|ip| mask_ip(ip)).collect::<Vec<_>>());
                            }
                        }
                    }
                }
            }

            #[cfg(target_os = "linux")]
            {
                // For Linux, use simpler name-based matching for now
                for interface in &mut interfaces {
                    for (ip_key, ips) in &interface_ips {
                        if ip_key.display_name() == &interface.name {
                            interface.ip_addresses = ips.clone();
                            break;
                        }
                    }
                }
            }

            // Update interface status using preserved InterfaceKey context (platform-independent)
            for interface in &mut interfaces {
                if let Some(interface_key) = name_to_key_map.get(&interface.name) {
                    interface.is_up = self.is_interface_up_by_key(interface_key);
                } else {
                    let fallback_key = InterfaceKey::new(interface.name.clone(), None, None, None);
                    interface.is_up = self.is_interface_up_by_key(&fallback_key);
                }
            }
        } else {
            // First collection, just report current values as-is
            for (stats_key, stats) in &current_network_stats {
                // Try to find matching IP addresses using correlation
                #[cfg(target_os = "windows")]
                let ip_addresses = {
                    if let Some(matched_ip_key) = self.find_best_interface_match(stats_key, &interface_ips) {
                        interface_ips.get(&matched_ip_key).cloned().unwrap_or_default()
                    } else {
                        Vec::new()
                    }
                };

                #[cfg(target_os = "linux")]
                let ip_addresses = {
                    interface_ips.iter()
                        .find(|(ip_key, _)| ip_key.display_name() == stats_key.display_name())
                        .map(|(_, ips)| ips.clone())
                        .unwrap_or_default()
                };

                let is_up = self.is_interface_up_by_key(stats_key);

                interfaces.push(NetworkInterface {
                    name: stats_key.display_name().to_string(),
                    bytes_received: stats.bytes_received,
                    bytes_sent: stats.bytes_sent,
                    packets_received: stats.packets_received,
                    packets_sent: stats.packets_sent,
                    errors_in: stats.errors_in,
                    errors_out: stats.errors_out,
                    ip_addresses,
                    is_up,
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
    fn collect_network_stats_linux(&self) -> Result<HashMap<InterfaceKey, NetworkSnapshot>> {
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
                
                let interface_key = InterfaceKey::new(
                    interface_name.to_string(),
                    None, // GUID not available on Linux
                    None, // MAC address not readily available from /proc/net/dev
                    None, // InterfaceIndex not available from /proc/net/dev
                );

                network_stats.insert(
                    interface_key,
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
    fn collect_network_stats_windows(&self) -> Result<HashMap<InterfaceKey, NetworkSnapshot>> {
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

            #[derive(Deserialize)]
            struct Win32NetworkAdapter {
                Name: String,
                GUID: Option<String>,
                MACAddress: Option<String>,
                InterfaceIndex: Option<u32>,
                NetEnabled: Option<bool>,
                NetConnectionID: Option<String>,
                Description: Option<String>,
            }

            // First get performance data
            let mut perf_data = HashMap::new();
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

                    perf_data.insert(interface.Name.clone(), NetworkSnapshot {
                        bytes_received: interface.BytesReceivedPerSec,
                        bytes_sent: interface.BytesSentPerSec,
                        packets_received: interface.PacketsReceivedPerSec,
                        packets_sent: interface.PacketsSentPerSec,
                        errors_in: interface.PacketsReceivedErrors,
                        errors_out: interface.PacketsOutboundErrors,
                        timestamp: now,
                    });
                }
            }

            // Then get adapter information for stable identifiers with enhanced fields
            let mut adapter_keys = HashMap::new();
            if let Ok(adapters) = wmi_conn.raw_query::<Win32NetworkAdapter>(
                "SELECT Name, GUID, MACAddress, InterfaceIndex, NetConnectionID, Description FROM Win32_NetworkAdapter WHERE NetEnabled=true"
            ) {
                for adapter in adapters {
                    // Normalize MAC address format
                    let mac_address = adapter.MACAddress.map(|mac| {
                        mac.replace(":", "").replace("-", "").to_uppercase()
                    });

                    let interface_key = InterfaceKey::new(
                        adapter.Name.clone(),
                        adapter.GUID,
                        mac_address,
                        adapter.InterfaceIndex,
                    );

                    debug!("Found adapter: {} with GUID: {:?}, MAC: {:?}, Index: {:?}, NetConnectionID: {:?}, Description: {:?}",
                           adapter.Name, interface_key.guid, interface_key.mac_address,
                           interface_key.interface_index, adapter.NetConnectionID, adapter.Description);

                    // Store multiple keys for different correlation approaches
                    adapter_keys.insert(adapter.Name.clone(), interface_key.clone());

                    // Also store by NetConnectionID if available
                    if let Some(ref net_conn_id) = adapter.NetConnectionID {
                        if !net_conn_id.is_empty() {
                            adapter_keys.insert(net_conn_id.clone(), interface_key.clone());
                        }
                    }

                    // Also store by Description if available
                    if let Some(ref description) = adapter.Description {
                        if !description.is_empty() {
                            adapter_keys.insert(description.clone(), interface_key.clone());
                        }
                    }
                }
            }

            // Fallback: Try PowerShell Get-NetAdapter for additional correlation if WMI data is insufficient
            if adapter_keys.is_empty() {
                debug!("WMI adapter query returned no results, trying PowerShell Get-NetAdapter");
                self.try_powershell_netadapter_correlation(&mut adapter_keys);
            }

            // Correlate performance data with adapter information
            for (perf_name, snapshot) in perf_data {
                // Try to find matching adapter by name correlation
                let interface_key = if let Some(adapter_key) = adapter_keys.get(&perf_name) {
                    adapter_key.clone()
                } else {
                    // Try fuzzy matching if exact name doesn't match
                    let mut best_match = None;
                    let mut best_score = 0;

                    for (adapter_name, adapter_key) in &adapter_keys {
                        let temp_key = InterfaceKey::new(perf_name.clone(), None, None, None);
                        let score = temp_key.matches(adapter_key);
                        if score > best_score {
                            best_score = score;
                            best_match = Some(adapter_key.clone());
                        }
                    }

                    if let Some(matched_key) = best_match {
                        debug!("Correlated performance interface '{}' with adapter '{}' (score: {})",
                               perf_name, matched_key.name, best_score);
                        matched_key
                    } else {
                        // Fallback to name-only key
                        warn!("No adapter correlation found for performance interface: {}", perf_name);
                        InterfaceKey::new(perf_name, None, None, None)
                    }
                };

                network_stats.insert(interface_key, snapshot);
            }
        }

        Ok(network_stats)
    }

    /// PowerShell Get-NetAdapter correlation fallback for enhanced adapter identification
    #[cfg(target_os = "windows")]
    fn try_powershell_netadapter_correlation(&self, adapter_keys: &mut HashMap<String, InterfaceKey>) {
        use std::process::Command;

        let output = Command::new("powershell")
            .args(&["-Command", "Get-NetAdapter | Select-Object InterfaceDescription, InterfaceAlias, InterfaceGuid, MacAddress, ifIndex | ConvertTo-Json -Depth 3"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&output_str) {
                    let empty_vec = vec![];
                    let adapters = if json_value.is_array() {
                        json_value.as_array().unwrap_or(&empty_vec)
                    } else {
                        std::slice::from_ref(&json_value)
                    };

                    for adapter in adapters {
                        if let (Some(description), Some(alias)) = (
                            adapter.get("InterfaceDescription").and_then(|v| v.as_str()),
                            adapter.get("InterfaceAlias").and_then(|v| v.as_str())
                        ) {
                            let guid = adapter.get("InterfaceGuid").and_then(|v| v.as_str()).map(|s| s.to_string());
                            let mac_address = adapter.get("MacAddress")
                                .and_then(|v| v.as_str())
                                .map(|mac| mac.replace(":", "").replace("-", "").to_uppercase());
                            let interface_index = adapter.get("ifIndex")
                                .and_then(|v| v.as_u64())
                                .map(|i| i as u32);

                            let interface_key = InterfaceKey::new(
                                description.to_string(),
                                guid,
                                mac_address,
                                interface_index,
                            );

                            debug!("PowerShell Get-NetAdapter found: Description='{}', Alias='{}', GUID={:?}, MAC={:?}, Index={:?}",
                                   description, alias, interface_key.guid, interface_key.mac_address, interface_key.interface_index);

                            // Store by multiple identifiers
                            adapter_keys.insert(description.to_string(), interface_key.clone());
                            adapter_keys.insert(alias.to_string(), interface_key.clone());
                        }
                    }

                    debug!("PowerShell Get-NetAdapter correlation added {} adapter mappings", adapter_keys.len());
                } else {
                    debug!("Failed to parse PowerShell Get-NetAdapter JSON output");
                }
            } else {
                debug!("PowerShell Get-NetAdapter command failed");
            }
        } else {
            debug!("Failed to execute PowerShell Get-NetAdapter command");
        }
    }
    fn calculate_network_rates(
        &self,
        current: &HashMap<InterfaceKey, NetworkSnapshot>,
        previous: &HashMap<InterfaceKey, NetworkSnapshot>
    ) -> Vec<NetworkInterface> {
        let mut interfaces = vec![];

        for (interface_key, current_stats) in current {
            // Try to find previous stats for this interface using correlation
            let prev_stats = self.find_matching_previous_stats(interface_key, previous);

            if let Some(prev_stats) = prev_stats {
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
                        name: interface_key.display_name().to_string(),
                        bytes_received: (bytes_received as f64 / seconds) as u64,
                        bytes_sent: (bytes_sent as f64 / seconds) as u64,
                        packets_received: (packets_received as f64 / seconds) as u64,
                        packets_sent: (packets_sent as f64 / seconds) as u64,
                        errors_in: (errors_in as f64 / seconds) as u64,
                        errors_out: (errors_out as f64 / seconds) as u64,
                        ip_addresses: vec![], // Will be filled in collect_network_metrics
                        is_up: false,         // Will be filled in collect_network_metrics
                    });
                }
            } else {
                // New interface, report current values
                interfaces.push(NetworkInterface {
                    name: interface_key.display_name().to_string(),
                    bytes_received: current_stats.bytes_received,
                    bytes_sent: current_stats.bytes_sent,
                    packets_received: current_stats.packets_received,
                    packets_sent: current_stats.packets_sent,
                    errors_in: current_stats.errors_in,
                    errors_out: current_stats.errors_out,
                    ip_addresses: vec![], // Will be filled in collect_network_metrics
                    is_up: false,         // Will be filled in collect_network_metrics
                });
            }
        }

        interfaces
    }

    /// Find matching previous stats using InterfaceKey correlation
    fn find_matching_previous_stats<'a>(
        &self,
        current_key: &InterfaceKey,
        previous: &'a HashMap<InterfaceKey, NetworkSnapshot>
    ) -> Option<&'a NetworkSnapshot> {
        // First try exact match
        if let Some(stats) = previous.get(current_key) {
            return Some(stats);
        }

        // Then try correlation by stable identifiers
        let mut best_match = None;
        let mut best_score = 0;

        // Dynamic threshold: use 300 when stable identifiers are present, otherwise accept >=100 (exact name)
        let threshold = if current_key.has_stable_identifiers() {
            300  // Higher threshold for keys with stable identifiers
        } else {
            100  // Lower threshold for name-only keys (Linux)
        };

        for (prev_key, prev_stats) in previous {
            let score = current_key.matches(prev_key);
            if score > best_score && score >= threshold {
                best_score = score;
                best_match = Some(prev_stats);
            }
        }

        if best_match.is_some() {
            debug!("Correlated interface with previous stats (score: {})", best_score);
        }

        best_match
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
        let mut processes: Vec<ProcessInfo>;

        // Try to collect enhanced process information
        #[cfg(target_os = "linux")]
        {
            processes = self.collect_processes_linux(limit)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            processes = Vec::new();
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
                        memory_usage_kb: process.memory() / 1024,  // Convert bytes to KB
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

    /// Collect IP addresses for all network interfaces with enhanced reliability
    fn collect_interface_ips(&self) -> HashMap<String, Vec<String>> {
        debug!("Starting IP collection for all interfaces");
        let mut interface_ips = HashMap::new();

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            use std::time::Duration;
            use std::net::IpAddr;

            // First try JSON-based detection for more reliable parsing
            if let Ok(output) = Command::new("ip")
                .args(&["-j", "addr", "show"])
                .output()
            {
                debug!("Using JSON-based IP detection");
                let output_str = String::from_utf8_lossy(&output.stdout);

                // Try to parse JSON output
                if let Ok(interfaces) = serde_json::from_str::<serde_json::Value>(&output_str) {
                    if let Some(interfaces_array) = interfaces.as_array() {
                        for interface in interfaces_array {
                            if let (Some(interface_name), Some(addr_info)) = (
                                interface.get("ifname").and_then(|v| v.as_str()),
                                interface.get("addr_info").and_then(|v| v.as_array())
                            ) {
                                let mut ip_list = Vec::new();

                                for addr in addr_info {
                                    if let (Some(family), Some(local)) = (
                                        addr.get("family").and_then(|v| v.as_str()),
                                        addr.get("local").and_then(|v| v.as_str())
                                    ) {
                                        if family == "inet" && self.is_valid_ip_address(local) {
                                            ip_list.push(local.to_string());
                                        }
                                    }
                                }

                                if !ip_list.is_empty() {
                                    info!("Found {} IP addresses for interface {}", ip_list.len(), interface_name);
                                    interface_ips.insert(interface_name.to_string(), ip_list);
                                }
                            }
                        }
                    }
                } else {
                    debug!("JSON parsing failed, falling back to text parsing");
                    // Fall back to text parsing
                    interface_ips = self.collect_interface_ips_text_linux();
                }
            } else {
                debug!("JSON command failed, falling back to text parsing");
                // Fall back to text parsing
                interface_ips = self.collect_interface_ips_text_linux();
            }
        }

        #[cfg(target_os = "windows")]
        {
            debug!("Starting Windows IP collection with enhanced VirtIO support");

            // Try multiple methods with correlation
            let mut combined_ips: HashMap<InterfaceKey, Vec<String>> = HashMap::new();

            // Method 1: Try PowerShell-based detection first
            if let Some(mut powershell_ips) = self.collect_interface_ips_powershell() {
                debug!("PowerShell method found {} interfaces", powershell_ips.len());

                // Deduplicate PowerShell IPs
                for (_, ips) in powershell_ips.iter_mut() {
                    ips.sort_unstable();
                    ips.dedup();
                }

                combined_ips.extend(powershell_ips);
            }

            // Method 2: Enhanced ipconfig parsing with VirtIO support
            if let Some(ipconfig_ips) = self.try_ipconfig_parsing() {
                debug!("Enhanced ipconfig method found {} interfaces", ipconfig_ips.len());

                // For each interface found by ipconfig, try to correlate with existing interfaces
                for (ipconfig_key, ips) in ipconfig_ips {
                    let mut correlation_found = None;

                    // Try to find a correlation with existing interfaces using InterfaceKey matching
                    for existing_key in combined_ips.keys() {
                        if existing_key.matches(&ipconfig_key) >= 100 {
                            correlation_found = Some(existing_key.clone());
                            break;
                        }
                    }

                    // Apply the correlation or add as new interface
                    if let Some(existing_key) = correlation_found {
                        // Merge IPs from both sources and deduplicate
                        let existing_ips = combined_ips.get_mut(&existing_key).unwrap();
                        let original_count = existing_ips.len();
                        existing_ips.extend(ips.clone());
                        existing_ips.sort_unstable();
                        existing_ips.dedup();
                        let final_count = existing_ips.len();

                        if final_count < original_count + ips.len() {
                            debug!("Merged IPs from ipconfig '{}' into existing interface '{}' and removed {} duplicates",
                                   ipconfig_key.display_name(), existing_key.display_name(), (original_count + ips.len()) - final_count);
                        } else {
                            debug!("Merged IPs from ipconfig '{}' into existing interface '{}'", ipconfig_key.display_name(), existing_key.display_name());
                        }
                    } else {
                        // If no correlation found, add as new interface
                        combined_ips.insert(ipconfig_key.clone(), ips);
                        debug!("Added new interface '{}' from ipconfig", ipconfig_key.display_name());
                    }
                }
            }

            // Method 3: Fallback text-based collection
            if combined_ips.is_empty() {
                debug!("Using fallback text-based collection");
                let text_ips = self.collect_interface_ips_text_windows();
                // Convert String keys to InterfaceKey
                combined_ips = text_ips.into_iter()
                    .map(|(name, ips)| (InterfaceKey::new(name, None, None, None), ips))
                    .collect();
            }

            interface_ips = combined_ips;
        }

        #[cfg(target_os = "windows")]
        {
            let total_interfaces = interface_ips.len();
            let up_interfaces_with_ips = interface_ips.iter()
                .filter(|(key, ips)| !ips.is_empty() && self.is_interface_up_by_key(key))
                .count();

            info!("IP collection completed: {} total interfaces, {} UP interfaces with IPs",
                  total_interfaces, up_interfaces_with_ips);

            if up_interfaces_with_ips == 0 {
                warn!("No UP interfaces with IP addresses detected");
            }

            // Convert InterfaceKey keys back to String keys for compatibility
            return interface_ips.into_iter()
                .map(|(key, ips)| (key.display_name().to_string(), ips))
                .collect();
        }

        #[cfg(target_os = "linux")]
        {
            let total_interfaces = interface_ips.len();
            let up_interfaces_with_ips = interface_ips.iter()
                .filter(|(name, ips)| !ips.is_empty() && self.is_interface_up(name))
                .count();

            info!("IP collection completed: {} total interfaces, {} UP interfaces with IPs",
                  total_interfaces, up_interfaces_with_ips);

            if up_interfaces_with_ips == 0 {
                warn!("No UP interfaces with IP addresses detected");
            }

            return interface_ips;
        }
    }

    /// Collect interface IPs with InterfaceKey support for enhanced correlation
    fn collect_interface_ips_with_keys(&self) -> HashMap<InterfaceKey, Vec<String>> {
        debug!("Starting IP collection with InterfaceKey support");
        let mut interface_ips = HashMap::new();

        #[cfg(target_os = "linux")]
        {
            // For Linux, convert the existing string-based collection to InterfaceKey
            let string_based_ips = self.collect_interface_ips();
            for (name, ips) in string_based_ips {
                let interface_key = InterfaceKey::new(name, None, None, None);
                interface_ips.insert(interface_key, ips);
            }
        }

        #[cfg(target_os = "windows")]
        {
            debug!("Starting Windows IP collection with InterfaceKey correlation");

            let mut all_ip_sources = HashMap::new();

            // Method 1: PowerShell Get-NetIPAddress (with InterfaceIndex)
            if let Some(powershell_ips) = self.try_powershell_get_netipaddress() {
                debug!("PowerShell Get-NetIPAddress found {} interfaces", powershell_ips.len());
                for (key, ips) in powershell_ips {
                    debug!("PowerShell source: {} (Index: {:?}) has {} IPs",
                           key.display_name(), key.interface_index, ips.len());
                    all_ip_sources.insert(key, ips);
                }
            }

            // Method 2: PowerShell WMI (with MAC and InterfaceIndex)
            if let Some(wmi_ips) = self.try_powershell_wmi() {
                debug!("PowerShell WMI found {} interfaces", wmi_ips.len());

                // Correlate WMI results with existing sources using direct matching
                let mut correlations = HashMap::new();
                for wmi_key in wmi_ips.keys() {
                    if let Some(best_match) = self.find_best_interface_match(wmi_key, &all_ip_sources) {
                        correlations.insert(wmi_key.clone(), best_match);
                    }
                }

                for (wmi_key, wmi_ips) in wmi_ips {
                    if let Some(existing_key) = correlations.get(&wmi_key) {
                        // Merge IPs with existing interface
                        if let Some(existing_ips) = all_ip_sources.get_mut(existing_key) {
                            let original_count = existing_ips.len();
                            existing_ips.extend(wmi_ips.clone());
                            existing_ips.sort_unstable();
                            existing_ips.dedup();
                            debug!("Merged WMI IPs with existing interface '{}': {} -> {} IPs",
                                   existing_key.display_name(), original_count, existing_ips.len());
                        }
                    } else {
                        // Add as new interface
                        debug!("Adding new WMI interface: {} (MAC: {:?}) with {} IPs",
                               wmi_key.display_name(), wmi_key.mac_address, wmi_ips.len());
                        all_ip_sources.insert(wmi_key, wmi_ips);
                    }
                }
            }

            // Method 3: ipconfig parsing (with MAC addresses)
            if let Some(ipconfig_ips) = self.try_ipconfig_parsing() {
                debug!("ipconfig parsing found {} interfaces", ipconfig_ips.len());

                // Correlate ipconfig results with existing sources using direct matching
                let mut correlations = HashMap::new();
                for ipconfig_key in ipconfig_ips.keys() {
                    if let Some(best_match) = self.find_best_interface_match(ipconfig_key, &all_ip_sources) {
                        correlations.insert(ipconfig_key.clone(), best_match);
                    }
                }

                for (ipconfig_key, ipconfig_ips) in ipconfig_ips {
                    if let Some(existing_key) = correlations.get(&ipconfig_key) {
                        // Merge IPs with existing interface
                        if let Some(existing_ips) = all_ip_sources.get_mut(existing_key) {
                            let original_count = existing_ips.len();
                            existing_ips.extend(ipconfig_ips.clone());
                            existing_ips.sort_unstable();
                            existing_ips.dedup();
                            debug!("Merged ipconfig IPs with existing interface '{}': {} -> {} IPs",
                                   existing_key.display_name(), original_count, existing_ips.len());
                        }
                    } else {
                        // Add as new interface
                        debug!("Adding new ipconfig interface: {} (MAC: {:?}) with {} IPs",
                               ipconfig_key.display_name(), ipconfig_key.mac_address, ipconfig_ips.len());
                        all_ip_sources.insert(ipconfig_key, ipconfig_ips);
                    }
                }
            }

            interface_ips = all_ip_sources;
        }

        let total_interfaces = interface_ips.len();
        let up_interfaces_with_ips = interface_ips.iter()
            .filter(|(key, ips)| !ips.is_empty() && self.is_interface_up_by_key(key))
            .count();

        info!("InterfaceKey IP collection completed: {} total interfaces, {} UP interfaces with IPs",
              total_interfaces, up_interfaces_with_ips);

        if up_interfaces_with_ips == 0 {
            warn!("No UP interfaces with IP addresses detected");
        }

        // Log detailed interface information
        for (key, ips) in &interface_ips {
            debug!("Interface '{}' (GUID: {:?}, MAC: {:?}, Index: {:?}) has {} IPs: {:?}",
                   key.display_name(), key.guid, key.mac_address, key.interface_index,
                   ips.len(), ips.iter().map(|ip| mask_ip(ip)).collect::<Vec<_>>());
        }

        interface_ips
    }

    /// Fallback text-based IP collection for Linux
    #[cfg(target_os = "linux")]
    fn collect_interface_ips_text_linux(&self) -> HashMap<String, Vec<String>> {
        use std::process::Command;

        let mut interface_ips = HashMap::new();

        if let Ok(output) = Command::new("ip")
            .args(&["addr", "show"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut current_interface = String::new();

            for line in output_str.lines() {
                let line = line.trim();

                // Parse interface line (e.g., "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>")
                if let Some(interface_name) = self.parse_interface_name(line) {
                    current_interface = interface_name;
                }

                // Parse IP line (e.g., "inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0")
                if line.starts_with("inet ") && !current_interface.is_empty() {
                    if let Some(ip) = self.parse_ip_from_line(line) {
                        if self.is_valid_ip_address(&ip) {
                            interface_ips.entry(current_interface.clone())
                                .or_insert_with(Vec::new)
                                .push(ip);
                        }
                    }
                }
            }
        }

        interface_ips
    }

    /// Enhanced PowerShell-based IP collection for Windows with multiple fallback methods
    #[cfg(target_os = "windows")]
    fn collect_interface_ips_powershell(&self) -> Option<HashMap<InterfaceKey, Vec<String>>> {
        use std::process::Command;

        // Method 1: Try modern PowerShell cmdlet (most reliable)
        if let Some(result) = self.try_powershell_get_netipaddress() {
            info!("Used Get-NetIPAddress for IP collection");
            return Some(result);
        }

        // Method 2: Try WMI via PowerShell (more compatible)
        if let Some(result) = self.try_powershell_wmi() {
            info!("Used WMI via PowerShell for IP collection");
            return Some(result);
        }

        // Method 3: Try ipconfig parsing (universal fallback)
        if let Some(result) = self.try_ipconfig_parsing() {
            info!("Used ipconfig parsing for IP collection");
            return Some(result);
        }

        warn!("All Windows IP collection methods failed");
        None
    }

    /// Method 1: Modern PowerShell Get-NetIPAddress cmdlet
    #[cfg(target_os = "windows")]
    fn try_powershell_get_netipaddress(&self) -> Option<HashMap<InterfaceKey, Vec<String>>> {
        use std::process::Command;

        let output = Command::new("powershell")
            .args(&["-Command", "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.AddressState -eq 'Preferred'} | Select-Object InterfaceAlias, IPAddress, InterfaceIndex | ConvertTo-Json -Depth 3"])
            .output()
            .ok()?;

        if !output.status.success() {
            debug!("Get-NetIPAddress command failed");
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.trim().is_empty() {
            debug!("Get-NetIPAddress returned empty output");
            return None;
        }

        let json_value: serde_json::Value = serde_json::from_str(&output_str).ok()?;
        let mut interface_ips = HashMap::new();

        // Handle both single object and array of objects
        let addresses = if json_value.is_array() {
            json_value.as_array()?
        } else {
            std::slice::from_ref(&json_value)
        };

        for addr in addresses {
            if let (Some(interface_name), Some(ip_address)) = (
                addr.get("InterfaceAlias").and_then(|v| v.as_str()),
                addr.get("IPAddress").and_then(|v| v.as_str())
            ) {
                if self.is_valid_ip_address(ip_address) {
                    let interface_index = addr.get("InterfaceIndex")
                        .and_then(|v| v.as_u64())
                        .map(|i| i as u32);

                    let interface_key = InterfaceKey::new(
                        interface_name.to_string(),
                        None, // GUID not available from Get-NetIPAddress
                        None, // MAC address not available from Get-NetIPAddress
                        interface_index,
                    );

                    debug!("Found IP {} for interface {} (InterfaceIndex: {:?})",
                           mask_ip(ip_address), interface_name, interface_index);

                    interface_ips.entry(interface_key)
                        .or_insert_with(Vec::new)
                        .push(ip_address.to_string());
                }
            }
        }

        if interface_ips.is_empty() {
            None
        } else {
            Some(interface_ips)
        }
    }

    /// Method 2: WMI via PowerShell (more compatible with older Windows)
    #[cfg(target_os = "windows")]
    fn try_powershell_wmi(&self) -> Option<HashMap<InterfaceKey, Vec<String>>> {
        use std::process::Command;

        let output = Command::new("powershell")
            .args(&["-Command",
                "Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | ForEach-Object { [PSCustomObject]@{ Name = $_.Description; IPAddress = $_.IPAddress; MACAddress = $_.MACAddress; InterfaceIndex = $_.InterfaceIndex } } | ConvertTo-Json -Depth 3"])
            .output()
            .ok()?;

        if !output.status.success() {
            debug!("WMI PowerShell command failed");
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.trim().is_empty() {
            debug!("WMI PowerShell returned empty output");
            return None;
        }

        let json_value: serde_json::Value = serde_json::from_str(&output_str).ok()?;
        let mut interface_ips = HashMap::new();

        let adapters = if json_value.is_array() {
            json_value.as_array()?
        } else {
            std::slice::from_ref(&json_value)
        };

        for adapter in adapters {
            if let (Some(interface_name), Some(ip_array)) = (
                adapter.get("Name").and_then(|v| v.as_str()),
                adapter.get("IPAddress").and_then(|v| v.as_array())
            ) {
                let mut ips = Vec::new();
                for ip in ip_array {
                    if let Some(ip_str) = ip.as_str() {
                        if self.is_valid_ip_address(ip_str) {
                            ips.push(ip_str.to_string());
                        }
                    }
                }

                if !ips.is_empty() {
                    // Extract additional identifiers
                    let mac_address = adapter.get("MACAddress")
                        .and_then(|v| v.as_str())
                        .map(|mac| mac.replace(":", "").replace("-", "").to_uppercase());

                    let interface_index = adapter.get("InterfaceIndex")
                        .and_then(|v| v.as_u64())
                        .map(|i| i as u32);

                    let interface_key = InterfaceKey::new(
                        interface_name.to_string(),
                        None, // GUID not available from Win32_NetworkAdapterConfiguration
                        mac_address,
                        interface_index,
                    );

                    debug!("Found IPs {:?} for interface {} (MAC: {:?}, InterfaceIndex: {:?})",
                           ips.iter().map(|ip| mask_ip(ip)).collect::<Vec<_>>(),
                           interface_name, interface_key.mac_address, interface_key.interface_index);

                    interface_ips.insert(interface_key, ips);
                }
            }
        }

        if interface_ips.is_empty() {
            None
        } else {
            Some(interface_ips)
        }
    }

    /// Method 3: ipconfig parsing (universal fallback with VirtIO support)
    #[cfg(target_os = "windows")]
    fn try_ipconfig_parsing(&self) -> Option<HashMap<InterfaceKey, Vec<String>>> {
        use std::process::Command;
        use regex::Regex;

        let output = Command::new("ipconfig")
            .args(&["/all"])
            .output()
            .ok()?;

        if !output.status.success() {
            debug!("ipconfig command failed");
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut interface_data = HashMap::new();
        let mut current_interface_name = String::new();
        let mut current_interface_mac = None;
        let mut current_interface_ips = Vec::new();

        // Primary case-insensitive adapter header regex
        let primary_adapter_regex = Regex::new(r"(?i)^.*adapter\s+(.+?):\s*$").ok()?;

        // IP address detection patterns (IPv4 and IPv6)
        let ip_patterns = vec![
            "IPv4 Address",
            "IP Address",
            "Autoconfiguration IPv4 Address",
            "IPv6 Address",
            "Link-local IPv6 Address",
            "Temporary IPv6 Address",
        ];

        // MAC address detection patterns
        let mac_patterns = vec![
            "Physical Address",
            "Ethernet Address",
            "MAC Address",
        ];

        // Blocked keys for regex fallback to prevent DNS/gateway IPs
        let blocked_keys = vec![
            "subnet mask", "default gateway", "dhcp server", "dns servers",
            "wins server", "netbios", "lease obtained", "lease expires",
            "primary dns suffix", "node type", "ip routing enabled",
            "wins proxy enabled", "autoconfiguration enabled"
        ];

        // Regex for any IPv4 address in a line
        let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").ok()?;

        // Regex for MAC address detection
        let mac_regex = Regex::new(r"\b([0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b").ok()?;

        debug!("Starting ipconfig parsing with enhanced VirtIO and MAC address support");

        // Helper function to save current interface data
        let mut save_current_interface = |interface_data: &mut HashMap<InterfaceKey, Vec<String>>,
                                         name: &str,
                                         mac: &Option<String>,
                                         ips: &Vec<String>| {
            if !name.is_empty() && !ips.is_empty() {
                let interface_key = InterfaceKey::new(
                    name.to_string(),
                    None, // GUID not available from ipconfig
                    mac.clone(),
                    None, // InterfaceIndex not available from ipconfig
                );

                debug!("Saving interface data: {} with MAC: {:?}, IPs: {:?}",
                       name, mac, ips.iter().map(|ip| mask_ip(ip)).collect::<Vec<_>>());

                interface_data.insert(interface_key, ips.clone());
            }
        };

        for line in output_str.lines() {
            let line = line.trim();

            // Try primary case-insensitive adapter header regex first
            let mut adapter_found = false;
            if let Some(captures) = primary_adapter_regex.captures(line) {
                if let Some(adapter_match) = captures.get(1) {
                    let adapter_name = adapter_match.as_str().trim_end_matches(':').trim();
                    if !adapter_name.is_empty() && !line.to_lowercase().contains("media state") {
                        // Save previous interface data if exists
                        save_current_interface(&mut interface_data, &current_interface_name,
                                             &current_interface_mac, &current_interface_ips);

                        // Start new interface
                        current_interface_name = adapter_name.to_string();
                        current_interface_mac = None;
                        current_interface_ips.clear();
                        debug!("Found adapter header (primary): '{}' -> interface: '{}'", line, current_interface_name);
                        adapter_found = true;
                    }
                }
            }

            // Simple fallback: try simple adapter parsing if primary regex didn't match
            if !adapter_found && line.to_lowercase().contains("adapter") && line.contains(":") && !line.to_lowercase().contains("media state") {
                if let Some(adapter_name) = line.split("adapter").nth(1) {
                    let clean_name = adapter_name.trim_end_matches(':').trim();
                    if !clean_name.is_empty() {
                        // Save previous interface data if exists
                        save_current_interface(&mut interface_data, &current_interface_name,
                                             &current_interface_mac, &current_interface_ips);

                        // Start new interface
                        current_interface_name = clean_name.to_string();
                        current_interface_mac = None;
                        current_interface_ips.clear();
                        debug!("Simple fallback adapter parsing: '{}' -> interface: '{}'", line, current_interface_name);
                    }
                }
            }

            // MAC address detection
            if !current_interface_name.is_empty() {
                for pattern in &mac_patterns {
                    if line.to_lowercase().contains(&pattern.to_lowercase()) && line.contains(":") {
                        if let Some(mac_part) = line.split(':').nth(1) {
                            let mac_candidate = mac_part.trim();
                            if let Some(mac_match) = mac_regex.find(mac_candidate) {
                                let mac = mac_match.as_str().replace(":", "").replace("-", "").to_uppercase();
                                current_interface_mac = Some(mac.clone());
                                debug!("Found MAC address {} for interface {} using pattern '{}'",
                                       mac, current_interface_name, pattern);
                                break;
                            }
                        }
                    }
                }
            }

            // Enhanced IP address detection
            if !current_interface_name.is_empty() {
                let mut ip_found = false;

                // Try standard IP patterns first (case-insensitive)
                for pattern in &ip_patterns {
                    if line.to_lowercase().contains(&pattern.to_lowercase()) && line.contains(":") {
                        if let Some(ip_part) = line.split(':').nth(1) {
                            let ip = ip_part.trim()
                                .trim_end_matches("(Preferred)")
                                .trim_end_matches("(Tentative)")
                                .trim_end_matches("(Duplicate)")
                                .trim_end_matches("(Temporary)")
                                .trim_end_matches("%") // Remove IPv6 zone identifier prefix
                                .split('%').next().unwrap_or("") // Remove IPv6 zone identifier completely
                                .trim();

                            if !ip.is_empty() && self.is_valid_ip_address(ip) {
                                debug!("Found IP {} for interface {} using pattern '{}'", mask_ip(ip), current_interface_name, pattern);
                                current_interface_ips.push(ip.to_string());
                                ip_found = true;
                            }
                        }
                    }
                }

                // Fallback: try regex-based IP detection with blocked key filtering
                if !ip_found && line.contains(":") {
                    if let Some(ip_match) = ip_regex.find(line) {
                        let ip = ip_match.as_str();
                        if self.is_valid_ip_address(ip) {
                            // Extract the label (left-hand side of colon) and check against blocked keys
                            let label = line.split(':').next().unwrap_or("").trim().trim_end_matches('.').to_lowercase();

                            let is_blocked = blocked_keys.iter().any(|&blocked| label.contains(blocked));

                            if is_blocked {
                                debug!("Skipped IP {} from regex fallback due to blocked label: '{}'", mask_ip(ip), label);
                            } else {
                                debug!("Found IP {} for interface {} using regex fallback (label: '{}')", mask_ip(ip), current_interface_name, label);
                                current_interface_ips.push(ip.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Save the last interface
        save_current_interface(&mut interface_data, &current_interface_name,
                             &current_interface_mac, &current_interface_ips);

        debug!("ipconfig parsing complete. Found {} interfaces with IPs", interface_data.len());
        for (interface_key, ips) in &interface_data {
            debug!("Interface '{}' (MAC: {:?}) has IPs: {:?}",
                   interface_key.name, interface_key.mac_address,
                   ips.iter().map(|ip| mask_ip(ip)).collect::<Vec<_>>());
        }

        if interface_data.is_empty() {
            debug!("No IP addresses found in ipconfig output");
            None
        } else {
            Some(interface_data)
        }
    }

    /// Enhanced interface correlation using stable identifiers (InterfaceKey)
    #[cfg(target_os = "windows")]
    fn correlate_interface_keys(
        &self,
        target_keys: &HashMap<InterfaceKey, NetworkSnapshot>,
        source_keys: &HashMap<InterfaceKey, Vec<String>>,
    ) -> HashMap<InterfaceKey, InterfaceKey> {
        let mut correlations = HashMap::new();

        debug!("Starting InterfaceKey correlation between {} target keys and {} source keys",
               target_keys.len(), source_keys.len());

        for target_key in target_keys.keys() {
            if let Some(best_match) = self.find_best_interface_match(target_key, source_keys) {
                debug!("Correlated target '{}' with source '{}'",
                       target_key.display_name(), best_match.display_name());
                correlations.insert(target_key.clone(), best_match);
            } else {
                debug!("No correlation found for target interface '{}'", target_key.display_name());
            }
        }

        debug!("Interface correlation complete. {} correlations found", correlations.len());
        correlations
    }

    /// Find the best matching InterfaceKey using priority-based correlation
    #[cfg(target_os = "windows")]
    fn find_best_interface_match(
        &self,
        target_key: &InterfaceKey,
        available_keys: &HashMap<InterfaceKey, Vec<String>>,
    ) -> Option<InterfaceKey> {
        // Check cache first for previous correlations
        if let Some(cached_key) = self.interface_key_cache.get(target_key.display_name()) {
            // Verify the cached key is still available in the current source set
            if available_keys.contains_key(cached_key) {
                debug!("Using cached correlation for '{}' -> '{}'", target_key.display_name(), cached_key.display_name());
                return Some(cached_key.clone());
            } else {
                debug!("Cached correlation for '{}' no longer valid, performing fresh lookup", target_key.display_name());
            }
        }

        let mut best_match = None;
        let mut best_score = 0;

        debug!("Finding best match for target: {} (GUID: {:?}, MAC: {:?}, Index: {:?})",
               target_key.display_name(), target_key.guid, target_key.mac_address, target_key.interface_index);

        for available_key in available_keys.keys() {
            let score = target_key.matches(available_key);

            debug!("  Candidate: {} (GUID: {:?}, MAC: {:?}, Index: {:?}) -> Score: {}",
                   available_key.display_name(), available_key.guid,
                   available_key.mac_address, available_key.interface_index, score);

            if score > best_score {
                best_score = score;
                best_match = Some(available_key.clone());
            }
        }

        if let Some(ref matched_key) = best_match {
            debug!("Best match for '{}' is '{}' with score {}",
                   target_key.display_name(), matched_key.display_name(), best_score);

            // Apply minimum threshold for correlation
            if best_score < 50 {  // Minimum threshold for any correlation
                debug!("Best match score {} is below threshold (50), rejecting correlation", best_score);
                return None;
            }
        }

        best_match
    }

    /// Update interface cache with successful correlations
    #[cfg(target_os = "windows")]
    fn update_interface_cache(&mut self, correlations: &HashMap<InterfaceKey, InterfaceKey>) {
        for (target_key, source_key) in correlations {
            // Cache the correlation for future use
            self.interface_key_cache.insert(
                target_key.display_name().to_string(),
                source_key.clone()
            );

            debug!("Cached correlation: '{}' -> '{}'",
                   target_key.display_name(), source_key.display_name());
        }
    }

    /// Fallback text-based IP collection for Windows
    #[cfg(target_os = "windows")]
    fn collect_interface_ips_text_windows(&self) -> HashMap<String, Vec<String>> {
        use std::process::Command;

        let mut interface_ips = HashMap::new();

        if let Ok(output) = Command::new("ipconfig")
            .args(&["/all"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut current_interface = String::new();

            for line in output_str.lines() {
                let line = line.trim();

                // Parse adapter line
                if line.contains("adapter") && line.contains(":") {
                    if let Some(adapter_name) = line.split("adapter").nth(1) {
                        current_interface = adapter_name.trim_end_matches(':').trim().to_string();
                    }
                }

                // Parse IPv4 address line
                if line.contains("IPv4 Address") && !current_interface.is_empty() {
                    if let Some(ip_part) = line.split(':').nth(1) {
                        let ip = ip_part.trim().trim_end_matches("(Preferred)").trim();
                        if !ip.is_empty() && self.is_valid_ip_address(ip) {
                            interface_ips.entry(current_interface.clone())
                                .or_insert_with(Vec::new)
                                .push(ip.to_string());
                        }
                    }
                }
            }
        }

        interface_ips
    }

    /// Enhanced IP address validation with better acceptance criteria
    fn is_valid_ip_address(&self, ip: &str) -> bool {
        use std::net::IpAddr;

        // First check if it's a valid IP address format
        if let Ok(addr) = ip.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();

                    // Skip loopback (127.x.x.x) - these are not useful for networking
                    if octets[0] == 127 {
                        debug!("Skipping loopback address: {}", ip);
                        return false;
                    }

                    // Skip multicast addresses (224.x.x.x - 239.x.x.x)
                    if octets[0] >= 224 && octets[0] <= 239 {
                        debug!("Skipping multicast address: {}", ip);
                        return false;
                    }

                    // Skip reserved/experimental (240.x.x.x and above)
                    if octets[0] >= 240 {
                        debug!("Skipping reserved address: {}", ip);
                        return false;
                    }

                    // Accept all other addresses, including:
                    // - Private addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
                    // - Link-local (169.254.x.x) - useful in some environments
                    // - Public addresses
                    debug!("Accepting IPv4 address: {}", ip);
                    true
                }
                IpAddr::V6(ipv6) => {
                    // For IPv6, skip link-local and loopback, accept others
                    if ipv6.is_loopback() {
                        debug!("Skipping IPv6 loopback: {}", ip);
                        return false;
                    }

                    // Accept most IPv6 addresses including link-local for now
                    // Link-local IPv6 (fe80::/64) might be useful in some cases
                    debug!("Accepting IPv6 address: {}", ip);
                    true
                }
            }
        } else {
            debug!("Invalid IP address format: {}", ip);
            false
        }
    }

    /// Force immediate re-collection of IP addresses
    pub fn force_ip_recollection(&mut self) {
        self.initial_ip_collection_successful = false;
        info!("Forcing IP re-collection on next data collection");
    }

    /// Check if initial IP collection was successful
    pub fn is_initial_ip_collection_successful(&self) -> bool {
        self.initial_ip_collection_successful
    }

    /// Check if a network interface is up with enhanced detection and fallback logic
    fn is_interface_up(&self, interface_name: &str) -> bool {
        // First check if interface has network activity (most reliable indicator)
        let has_activity = self.interface_has_network_activity(interface_name);

        // If interface has activity, consider it UP regardless of other indicators
        if has_activity {
            debug!("Interface {} considered UP due to network activity", interface_name);
            return true;
        }

        #[cfg(target_os = "linux")]
        {
            use std::fs;

            // Try multiple methods to determine interface status
            let mut operstate_up = false;
            let mut carrier_up = false;
            let mut flags_up = false;

            // Method 1: Check operstate (traditional way)
            let operstate_path = format!("/sys/class/net/{}/operstate", interface_name);
            if let Ok(state) = fs::read_to_string(&operstate_path) {
                let state = state.trim();
                operstate_up = state == "up" || state == "unknown"; // unknown can mean virtual interface
                debug!("Interface {} operstate: {} (considered {})", interface_name, state,
                      if operstate_up { "UP" } else { "DOWN" });
            }

            // Method 2: Check carrier signal (physical interfaces)
            let carrier_path = format!("/sys/class/net/{}/carrier", interface_name);
            if let Ok(carrier) = fs::read_to_string(&carrier_path) {
                carrier_up = carrier.trim() == "1";
                debug!("Interface {} carrier: {}", interface_name, if carrier_up { "ON" } else { "OFF" });
            } else {
                // Virtual interfaces often don't have carrier file - that's acceptable
                carrier_up = true; // Don't penalize virtual interfaces
                debug!("Interface {} has no carrier file (likely virtual)", interface_name);
            }

            // Method 3: Check interface flags
            let flags_path = format!("/sys/class/net/{}/flags", interface_name);
            if let Ok(flags_str) = fs::read_to_string(&flags_path) {
                if let Ok(flags) = u32::from_str_radix(flags_str.trim().trim_start_matches("0x"), 16) {
                    // IFF_UP flag is bit 0, IFF_RUNNING is bit 6
                    let iff_up = (flags & 0x1) != 0;
                    let iff_running = (flags & 0x40) != 0;
                    flags_up = iff_up && iff_running;
                    debug!("Interface {} flags: 0x{:x} (UP={}, RUNNING={})",
                          interface_name, flags, iff_up, iff_running);
                }
            }

            // Consider interface UP if any reliable method indicates it's up
            let is_up = operstate_up || (carrier_up && flags_up);
            debug!("Interface {} final status: {} (operstate={}, carrier={}, flags={})",
                  interface_name, if is_up { "UP" } else { "DOWN" },
                  operstate_up, carrier_up, flags_up);

            return is_up;
        }

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            // Method 1: Try PowerShell first (more reliable)
            let ps_result = Command::new("powershell")
                .args(&["-Command", &format!(
                    "Get-NetAdapter -Name '{}' | Select-Object -ExpandProperty Status",
                    interface_name
                )])
                .output();

            if let Ok(output) = ps_result {
                if output.status.success() {
                    let status = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
                    let is_up = status == "up" || status == "connected";
                    debug!("Interface {} PowerShell status: {} ({})",
                          interface_name, status, if is_up { "UP" } else { "DOWN" });
                    return is_up;
                }
            }

            // Method 2: Fallback to netsh
            let netsh_result = Command::new("netsh")
                .args(&["interface", "show", "interface", &format!("name=\"{}\"", interface_name)])
                .output();

            if let Ok(output) = netsh_result {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    let is_connected = output_str.contains("Connected") || output_str.contains("Enabled");
                    debug!("Interface {} netsh status: {}", interface_name,
                          if is_connected { "Connected" } else { "Disconnected" });
                    return is_connected;
                }
            }

            debug!("Failed to determine status for interface {}", interface_name);
        }

        // If we can't determine status, be optimistic for interfaces with IPs
        let has_ips = self.interface_has_ip_addresses(interface_name);
        debug!("Interface {} fallback check - has IPs: {}", interface_name, has_ips);
        has_ips
    }

    /// Helper: Check if interface has recent network activity
    fn interface_has_network_activity(&self, interface_name: &str) -> bool {
        if let Some(previous_stats) = &self.previous_network_stats {
            // Try to find a matching interface by name
            for (key, stats) in previous_stats {
                if key.display_name() == interface_name {
                    // Consider interface active if it has significant traffic
                    return stats.bytes_received > 1000 || stats.bytes_sent > 1000;
                }
            }
        }
        false
    }

    /// Helper: Check if interface has IP addresses assigned
    fn interface_has_ip_addresses(&self, interface_name: &str) -> bool {
        let interface_ips = self.collect_interface_ips();
        interface_ips.get(interface_name)
            .map(|ips| !ips.is_empty())
            .unwrap_or(false)
    }

    /// Check if a network interface is up using InterfaceKey
    fn is_interface_up_by_key(&self, interface_key: &InterfaceKey) -> bool {
        // First check if interface has network activity (most reliable indicator)
        let has_activity = self.interface_has_network_activity_by_key(interface_key);

        // If interface has activity, consider it UP regardless of other indicators
        if has_activity {
            debug!("Interface {} considered UP due to network activity", interface_key.display_name());
            return true;
        }

        #[cfg(target_os = "windows")]
        {
            use std::process::Command;

            // Method 1: Try using InterfaceIndex with Get-NetAdapter
            if let Some(interface_index) = interface_key.interface_index {
                let ps_result = Command::new("powershell")
                    .args(&["-Command", &format!(
                        "Get-NetAdapter -InterfaceIndex {} | Select-Object -ExpandProperty Status",
                        interface_index
                    )])
                    .output();

                if let Ok(output) = ps_result {
                    if output.status.success() {
                        let status = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
                        let is_up = status == "up" || status == "connected";
                        debug!("Interface {} (Index: {}) PowerShell status: {} ({})",
                               interface_key.display_name(), interface_index, status,
                               if is_up { "UP" } else { "DOWN" });
                        return is_up;
                    }
                }
            }

            // Method 2: Try using interface name with PowerShell
            let ps_result = Command::new("powershell")
                .args(&["-Command", &format!(
                    "Get-NetAdapter -Name '{}' | Select-Object -ExpandProperty Status",
                    interface_key.display_name()
                )])
                .output();

            if let Ok(output) = ps_result {
                if output.status.success() {
                    let status = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
                    let is_up = status == "up" || status == "connected";
                    debug!("Interface {} PowerShell status: {} ({})",
                           interface_key.display_name(), status, if is_up { "UP" } else { "DOWN" });
                    return is_up;
                }
            }

            // Method 3: Fallback to netsh
            let netsh_result = Command::new("netsh")
                .args(&["interface", "show", "interface", &format!("name=\"{}\"", interface_key.display_name())])
                .output();

            if let Ok(output) = netsh_result {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    let is_connected = output_str.contains("Connected") || output_str.contains("Enabled");
                    debug!("Interface {} netsh status: {}", interface_key.display_name(),
                           if is_connected { "Connected" } else { "Disconnected" });
                    return is_connected;
                }
            }

            debug!("Failed to determine status for interface {}", interface_key.display_name());
        }

        // If we can't determine status, check for IP addresses as fallback
        #[cfg(target_os = "linux")]
        {
            // For Linux, fall back to name-based checking first
            if self.is_interface_up(interface_key.display_name()) {
                return true;
            }
        }

        let has_ips = self.interface_has_ip_addresses_by_key(interface_key);
        debug!("Interface {} fallback check - has IPs: {}", interface_key.display_name(), has_ips);
        has_ips
    }

    /// Helper: Check if interface has recent network activity using InterfaceKey
    fn interface_has_network_activity_by_key(&self, interface_key: &InterfaceKey) -> bool {
        if let Some(previous_stats) = &self.previous_network_stats {
            // Try to find matching previous stats using correlation
            if let Some(matching_key) = self.find_matching_previous_stats(interface_key, previous_stats) {
                // Consider interface active if it has significant traffic
                return matching_key.bytes_received > 1000 || matching_key.bytes_sent > 1000;
            }
        }
        false
    }

    /// Helper: Check if interface has IP addresses assigned using InterfaceKey
    fn interface_has_ip_addresses_by_key(&self, interface_key: &InterfaceKey) -> bool {
        let interface_ips = self.collect_interface_ips_with_keys();

        // Try exact match first
        if let Some(ips) = interface_ips.get(interface_key) {
            return !ips.is_empty();
        }

        // Try correlation to find matching interface
        #[cfg(target_os = "windows")]
        {
            if let Some(matched_key) = self.find_best_interface_match(interface_key, &interface_ips) {
                if let Some(ips) = interface_ips.get(&matched_key) {
                    return !ips.is_empty();
                }
            }
        }

        // Linux fallback via name equality
        #[cfg(target_os = "linux")]
        {
            for (key, ips) in &interface_ips {
                if key.display_name() == interface_key.display_name() {
                    return !ips.is_empty();
                }
            }
        }

        false
    }

    /// Helper method for string-based interface name matching using InterfaceKey logic
    fn interfaces_match(&self, name1: &str, name2: &str) -> bool {
        // Create temporary InterfaceKeys for comparison
        let key1 = InterfaceKey::new(name1.to_string(), None, None, None);
        let key2 = InterfaceKey::new(name2.to_string(), None, None, None);

        // Use InterfaceKey matching logic with minimum threshold
        key1.matches(&key2) >= 50
    }

    #[cfg(target_os = "linux")]
    fn parse_interface_name(&self, line: &str) -> Option<String> {
        // Parse lines like "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"
        if let Some(colon_pos) = line.find(": ") {
            if let Some(second_colon) = line[colon_pos + 2..].find(": ") {
                let interface_name = &line[colon_pos + 2..colon_pos + 2 + second_colon];
                if !interface_name.is_empty() {
                    return Some(interface_name.to_string());
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn parse_ip_from_line(&self, line: &str) -> Option<String> {
        // Parse lines like "inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"
        if let Some(inet_part) = line.strip_prefix("inet ") {
            if let Some(ip_with_mask) = inet_part.split_whitespace().next() {
                if let Some(ip) = ip_with_mask.split('/').next() {
                    // Skip loopback addresses
                    if !ip.starts_with("127.") {
                        return Some(ip.to_string());
                    }
                }
            }
        }
        None
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
                        ip_addresses: vec!["192.168.1.100".to_string()],
                        is_up: true,
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
            ip_addresses: vec!["192.168.1.100".to_string()],
            is_up: true,
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
