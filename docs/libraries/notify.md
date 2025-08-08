# notify Library Documentation

## Overview
`notify` is a cross-platform filesystem notification library for Rust. It provides real-time monitoring of file system events, which is essential for tracking application usage and file access patterns in our infiniservice project.

## Version
- **Current Version**: 8.2.0
- **Maintainer**: notify-rs organization (multiple maintainers)
- **Downloads**: 43+ million downloads
- **Trust Level**: ✅ **HIGHLY TRUSTABLE** - Very well-established project

## Key Features
- **Cross-platform support**: Windows, Linux, macOS
- **Real-time monitoring**: Immediate notification of file system changes
- **Event types**: Create, modify, delete, rename, access events
- **Recursive watching**: Monitor entire directory trees
- **Efficient implementation**: Uses platform-native APIs for optimal performance

## Use Cases in Infiniservice
1. **Application Usage Tracking**
   - Monitor when applications are launched (executable access)
   - Track document and file access patterns
   - Detect application activity through file modifications

2. **File Access Monitoring**
   - Track which files are being accessed by applications
   - Monitor configuration file changes
   - Detect temporary file creation/deletion patterns

3. **Usage Analytics**
   - Determine application usage frequency
   - Identify unused applications based on file access
   - Track user behavior patterns

## Basic Usage Examples

### Basic File System Watcher
```rust
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

fn watch_directory(path: &str) -> notify::Result<()> {
    let (tx, rx) = channel();

    // Create a watcher object, delivering debounced events
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            tx.send(res).unwrap();
        },
        Config::default(),
    )?;

    // Add a path to be watched
    watcher.watch(Path::new(path), RecursiveMode::Recursive)?;

    // Process events
    for res in rx {
        match res {
            Ok(event) => {
                println!("Event: {:?}", event);
                handle_file_event(event);
            }
            Err(e) => println!("Watch error: {:?}", e),
        }
    }

    Ok(())
}

fn handle_file_event(event: Event) {
    match event.kind {
        notify::EventKind::Access(_) => {
            println!("File accessed: {:?}", event.paths);
        }
        notify::EventKind::Create(_) => {
            println!("File created: {:?}", event.paths);
        }
        notify::EventKind::Modify(_) => {
            println!("File modified: {:?}", event.paths);
        }
        notify::EventKind::Remove(_) => {
            println!("File removed: {:?}", event.paths);
        }
        _ => {}
    }
}
```

### Application Launch Detection
```rust
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;

struct ApplicationMonitor {
    watcher: RecommendedWatcher,
    executable_paths: Vec<PathBuf>,
}

impl ApplicationMonitor {
    fn new() -> notify::Result<Self> {
        let (tx, rx) = channel();
        
        let watcher = RecommendedWatcher::new(
            move |res| {
                if let Ok(event) = res {
                    Self::process_event(event);
                }
            },
            Config::default(),
        )?;

        Ok(Self {
            watcher,
            executable_paths: Vec::new(),
        })
    }

    fn add_executable_path(&mut self, path: &Path) -> notify::Result<()> {
        self.executable_paths.push(path.to_path_buf());
        self.watcher.watch(path, RecursiveMode::NonRecursive)
    }

    fn process_event(event: Event) {
        if let EventKind::Access(_) = event.kind {
            for path in &event.paths {
                if path.extension().map_or(false, |ext| ext == "exe") {
                    println!("Application launched: {:?}", path);
                    // Record application usage
                }
            }
        }
    }
}
```

### Document Access Tracking
```rust
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

struct DocumentTracker {
    access_log: HashMap<PathBuf, Vec<u64>>, // Path -> timestamps
}

impl DocumentTracker {
    fn new() -> Self {
        Self {
            access_log: HashMap::new(),
        }
    }

    fn start_monitoring(&mut self, documents_path: &str) -> notify::Result<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                tx.send(res).unwrap();
            },
            Config::default(),
        )?;

        watcher.watch(
            std::path::Path::new(documents_path),
            RecursiveMode::Recursive,
        )?;

        for res in rx {
            if let Ok(event) = res {
                self.handle_document_event(event);
            }
        }

        Ok(())
    }

    fn handle_document_event(&mut self, event: Event) {
        if let EventKind::Access(_) = event.kind {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            for path in event.paths {
                if self.is_document_file(&path) {
                    self.access_log
                        .entry(path.clone())
                        .or_insert_with(Vec::new)
                        .push(timestamp);
                    
                    println!("Document accessed: {:?} at {}", path, timestamp);
                }
            }
        }
    }

    fn is_document_file(&self, path: &PathBuf) -> bool {
        if let Some(extension) = path.extension() {
            matches!(
                extension.to_str().unwrap_or("").to_lowercase().as_str(),
                "pdf" | "doc" | "docx" | "txt" | "rtf" | "odt"
            )
        } else {
            false
        }
    }

    fn get_usage_stats(&self) -> HashMap<PathBuf, usize> {
        self.access_log
            .iter()
            .map(|(path, timestamps)| (path.clone(), timestamps.len()))
            .collect()
    }
}
```

## Integration Strategy
1. **Multi-Path Monitoring**: Watch key directories like Program Files, Applications, Documents
2. **Event Filtering**: Focus on access events for usage tracking
3. **Data Aggregation**: Combine with process information from `sysinfo`
4. **Performance Optimization**: Use appropriate recursive modes and filters

## Platform-Specific Implementation
- **Windows**: Uses ReadDirectoryChangesW API
- **Linux**: Uses inotify for efficient file system monitoring
- **macOS**: Uses FSEvents for native file system notifications

## Performance Considerations
- **Selective Monitoring**: Only watch relevant directories to reduce overhead
- **Event Debouncing**: Use built-in debouncing to reduce noise
- **Resource Management**: Properly manage watcher lifecycle

## Error Handling
- Handle permission errors gracefully
- Implement retry logic for transient failures
- Log and recover from watcher failures

## Documentation Links
- [Official Documentation](https://docs.rs/notify/)
- [GitHub Repository](https://github.com/notify-rs/notify)
- [Crates.io Page](https://crates.io/crates/notify)
