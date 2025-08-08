# filetime Library Documentation

## Overview
`filetime` is a cross-platform Rust library for reading and writing file timestamps. It provides essential functionality for tracking file access times, which is crucial for determining application usage patterns in our infiniservice project.

## Version
- **Current Version**: 0.2.25
- **Trust Level**: ✅ **TRUSTABLE** - Standard Rust ecosystem crate

## Key Features
- **Cross-platform support**: Windows, Linux, macOS
- **Timestamp operations**: Read and write file access, modification, and creation times
- **High precision**: Nanosecond precision timestamps where supported
- **Metadata access**: Access to all file time attributes
- **Efficient operations**: Minimal overhead for timestamp operations

## Use Cases in Infiniservice
1. **Application Usage Detection**
   - Track when applications were last accessed
   - Determine application usage frequency
   - Identify unused applications based on access times

2. **File Access Analytics**
   - Monitor document and file usage patterns
   - Track configuration file modifications
   - Analyze user behavior through file access patterns

3. **Usage Statistics**
   - Generate reports on application usage
   - Identify applications not used for extended periods
   - Track file modification patterns

## Basic Usage Examples

### Reading File Timestamps
```rust
use filetime::FileTime;
use std::fs;
use std::path::Path;

fn get_file_timestamps(path: &Path) -> std::io::Result<()> {
    let metadata = fs::metadata(path)?;
    
    // Get access time
    let accessed = FileTime::from_last_access_time(&metadata);
    println!("Last accessed: {}", accessed.unix_seconds());
    
    // Get modification time
    let modified = FileTime::from_last_modification_time(&metadata);
    println!("Last modified: {}", modified.unix_seconds());
    
    // Get creation time (if available)
    if let Ok(created) = metadata.created() {
        let created_ft = FileTime::from_system_time(created);
        println!("Created: {}", created_ft.unix_seconds());
    }
    
    Ok(())
}
```

### Application Usage Tracker
```rust
use filetime::FileTime;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct ApplicationUsageTracker {
    application_paths: Vec<PathBuf>,
    usage_cache: HashMap<PathBuf, u64>, // Path -> last access timestamp
}

impl ApplicationUsageTracker {
    fn new() -> Self {
        Self {
            application_paths: Vec::new(),
            usage_cache: HashMap::new(),
        }
    }

    fn add_application_path(&mut self, path: PathBuf) {
        self.application_paths.push(path);
    }

    fn scan_application_usage(&mut self) -> std::io::Result<()> {
        for app_path in &self.application_paths {
            if let Ok(metadata) = fs::metadata(app_path) {
                let access_time = FileTime::from_last_access_time(&metadata);
                let timestamp = access_time.unix_seconds() as u64;
                
                // Check if access time has changed
                if let Some(&cached_time) = self.usage_cache.get(app_path) {
                    if timestamp > cached_time {
                        println!("Application used: {:?}", app_path);
                        self.record_usage(app_path.clone(), timestamp);
                    }
                } else {
                    // First time seeing this application
                    self.record_usage(app_path.clone(), timestamp);
                }
                
                self.usage_cache.insert(app_path.clone(), timestamp);
            }
        }
        Ok(())
    }

    fn record_usage(&self, path: PathBuf, timestamp: u64) {
        // Record usage in database or log file
        println!("Recording usage: {:?} at {}", path, timestamp);
    }

    fn find_unused_applications(&self, days_threshold: u64) -> Vec<PathBuf> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let threshold_seconds = days_threshold * 24 * 60 * 60;
        
        self.usage_cache
            .iter()
            .filter(|(_, &last_access)| {
                current_time - last_access > threshold_seconds
            })
            .map(|(path, _)| path.clone())
            .collect()
    }
}
```

### Document Access Monitoring
```rust
use filetime::FileTime;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

struct DocumentAccessMonitor;

impl DocumentAccessMonitor {
    fn check_recent_access(file_path: &Path, hours_threshold: u64) -> std::io::Result<bool> {
        let metadata = fs::metadata(file_path)?;
        let access_time = FileTime::from_last_access_time(&metadata);
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let threshold_seconds = hours_threshold * 60 * 60;
        let time_diff = current_time - (access_time.unix_seconds() as u64);
        
        Ok(time_diff <= threshold_seconds)
    }

    fn get_access_age_days(file_path: &Path) -> std::io::Result<u64> {
        let metadata = fs::metadata(file_path)?;
        let access_time = FileTime::from_last_access_time(&metadata);
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let age_seconds = current_time - (access_time.unix_seconds() as u64);
        Ok(age_seconds / (24 * 60 * 60)) // Convert to days
    }

    fn update_access_time(file_path: &Path) -> std::io::Result<()> {
        let current_time = FileTime::now();
        filetime::set_file_atime(file_path, current_time)
    }
}
```

### Batch File Analysis
```rust
use filetime::FileTime;
use std::fs;
use std::path::{Path, PathBuf};

struct FileAnalyzer;

impl FileAnalyzer {
    fn analyze_directory_usage(dir_path: &Path) -> std::io::Result<Vec<(PathBuf, u64, u64)>> {
        let mut results = Vec::new();
        
        if dir_path.is_dir() {
            for entry in fs::read_dir(dir_path)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    if let Ok(metadata) = fs::metadata(&path) {
                        let access_time = FileTime::from_last_access_time(&metadata);
                        let modified_time = FileTime::from_last_modification_time(&metadata);
                        
                        results.push((
                            path,
                            access_time.unix_seconds() as u64,
                            modified_time.unix_seconds() as u64,
                        ));
                    }
                }
            }
        }
        
        Ok(results)
    }

    fn find_stale_files(dir_path: &Path, days_threshold: u64) -> std::io::Result<Vec<PathBuf>> {
        let analysis = Self::analyze_directory_usage(dir_path)?;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let threshold_seconds = days_threshold * 24 * 60 * 60;
        
        let stale_files = analysis
            .into_iter()
            .filter(|(_, access_time, _)| {
                current_time - access_time > threshold_seconds
            })
            .map(|(path, _, _)| path)
            .collect();
        
        Ok(stale_files)
    }
}
```

## Integration Strategy
1. **Periodic Scanning**: Regularly check file access times to detect usage
2. **Baseline Establishment**: Create initial snapshots of file timestamps
3. **Change Detection**: Monitor for timestamp changes to identify activity
4. **Data Persistence**: Store usage patterns for historical analysis

## Platform-Specific Notes
- **Windows**: Full support for creation, access, and modification times
- **Linux**: Access time updates may be disabled (noatime mount option)
- **macOS**: Consistent behavior across file systems

## Performance Considerations
- **Batch Operations**: Process multiple files efficiently
- **Caching**: Cache timestamps to detect changes
- **I/O Optimization**: Minimize file system calls

## Limitations
- **Access Time Updates**: Some systems disable access time updates for performance
- **Precision**: Timestamp precision varies by file system
- **Permissions**: May require appropriate permissions to read file metadata

## Documentation Links
- [Official Documentation](https://docs.rs/filetime/)
- [GitHub Repository](https://github.com/alexcrichton/filetime)
- [Crates.io Page](https://crates.io/crates/filetime)
