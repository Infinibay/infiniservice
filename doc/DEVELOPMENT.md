# InfiniService Development Guide

## Development Environment Setup

### Prerequisites

1. **Rust Installation**
```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

2. **Development Tools**
```bash
# Linux
sudo apt-get install build-essential pkg-config libssl-dev

# Windows
# Install Visual Studio Build Tools or MinGW-w64
```

3. **Cross-Compilation Setup**
```bash
# Add Windows target
rustup target add x86_64-pc-windows-gnu

# Install MinGW-w64 for Windows cross-compilation
sudo apt-get install mingw-w64
```

### IDE Setup

#### Visual Studio Code

Recommended extensions:
- rust-analyzer
- CodeLLDB (debugging)
- Better TOML
- Error Lens

`.vscode/settings.json`:
```json
{
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.checkOnSave.command": "clippy",
  "editor.formatOnSave": true,
  "rust-analyzer.inlayHints.enable": true
}
```

`.vscode/launch.json`:
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug InfiniService",
      "cargo": {
        "args": ["build", "--bin=infiniservice"],
        "filter": {
          "name": "infiniservice",
          "kind": "bin"
        }
      },
      "args": ["--debug"],
      "cwd": "${workspaceFolder}",
      "env": {
        "RUST_LOG": "debug",
        "RUST_BACKTRACE": "1"
      }
    }
  ]
}
```

## Project Structure

```
infiniservice/
├── src/
│   ├── main.rs              # Entry point
│   ├── lib.rs               # Library exports
│   ├── service.rs           # Service orchestration
│   ├── collector.rs         # Metrics collection
│   ├── communication.rs     # VirtIO communication
│   ├── config.rs            # Configuration management
│   ├── os_detection.rs      # Platform detection
│   ├── windows_com.rs       # Windows-specific code
│   └── commands/            # Command execution
│       ├── mod.rs           # Module definitions
│       ├── executor.rs      # Command dispatcher
│       ├── safe_executor.rs # Safe commands
│       └── unsafe_executor.rs # Unsafe commands
├── tests/
│   ├── integration/         # Integration tests
│   └── unit/               # Unit tests
├── examples/
│   └── test_collector.rs   # Example usage
├── Cargo.toml              # Project dependencies
└── build.rs                # Build script (if needed)
```

## Development Workflow

### Building

```bash
# Debug build (fast compilation, with debug symbols)
cargo build

# Release build (optimized)
cargo build --release

# Cross-compile for Windows
cargo build --release --target x86_64-pc-windows-gnu
```

### Running

```bash
# Run with default settings
cargo run

# Run with debug output
RUST_LOG=debug cargo run -- --debug

# Run diagnostics
cargo run -- --diagnose

# Run with custom device
cargo run -- --device /dev/vport0p1
```

### Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_metrics_collection

# Run integration tests only
cargo test --test '*'

# Run with coverage (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### Code Quality

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run linter
cargo clippy -- -D warnings

# Security audit
cargo install cargo-audit
cargo audit

# Check for outdated dependencies
cargo install cargo-outdated
cargo outdated
```

## Code Patterns and Best Practices

### Error Handling

Use `anyhow` for application errors and `thiserror` for library errors:

```rust
use anyhow::{Result, Context, anyhow};
use thiserror::Error;

// Library errors with thiserror
#[derive(Error, Debug)]
pub enum CollectorError {
    #[error("Failed to collect metrics: {0}")]
    CollectionFailed(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// Application code with anyhow
pub fn collect_metrics() -> Result<SystemMetrics> {
    let data = read_proc_stat()
        .context("Failed to read /proc/stat")?;
    
    parse_metrics(data)
        .map_err(|e| anyhow!("Parse error: {}", e))
}
```

### Async Programming

Use Tokio for async operations:

```rust
use tokio::time::{sleep, Duration, interval};
use tokio::select;

pub async fn service_loop() -> Result<()> {
    let mut metrics_interval = interval(Duration::from_secs(30));
    let mut command_interval = interval(Duration::from_millis(100));
    
    loop {
        select! {
            _ = metrics_interval.tick() => {
                self.collect_and_send().await?;
            }
            _ = command_interval.tick() => {
                self.check_commands().await?;
            }
        }
    }
}
```

### Serialization

Use Serde for JSON serialization:

```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct SystemMetrics {
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}
```

### Platform-Specific Code

Use conditional compilation:

```rust
#[cfg(target_os = "windows")]
mod windows {
    pub fn collect_wmi_data() -> Result<WmiData> {
        // Windows-specific implementation
    }
}

#[cfg(target_os = "linux")]
mod linux {
    pub fn read_proc_stat() -> Result<String> {
        // Linux-specific implementation
    }
}

// Platform abstraction
pub fn collect_system_metrics() -> Result<SystemMetrics> {
    #[cfg(target_os = "windows")]
    return windows::collect_metrics();
    
    #[cfg(target_os = "linux")]
    return linux::collect_metrics();
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    return Err(anyhow!("Unsupported platform"));
}
```

### Logging

Use the `log` crate with structured logging:

```rust
use log::{info, debug, warn, error};

pub fn process_command(cmd: &Command) -> Result<()> {
    info!("Processing command: id={}, type={:?}", cmd.id, cmd.cmd_type);
    debug!("Command details: {:?}", cmd);
    
    match execute_command(cmd) {
        Ok(result) => {
            info!("Command succeeded: id={}", cmd.id);
            Ok(result)
        }
        Err(e) => {
            error!("Command failed: id={}, error={}", cmd.id, e);
            Err(e)
        }
    }
}
```

## Testing Strategy

### Unit Tests

Place unit tests in the same file as the code:

```rust
// src/collector.rs
pub fn calculate_cpu_usage(prev: &CpuStats, curr: &CpuStats) -> f32 {
    // Implementation
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cpu_usage_calculation() {
        let prev = CpuStats { user: 100, system: 50, idle: 850 };
        let curr = CpuStats { user: 110, system: 55, idle: 860 };
        
        let usage = calculate_cpu_usage(&prev, &curr);
        assert!((usage - 0.25).abs() < 0.01);
    }
}
```

### Integration Tests

Create integration tests in `tests/` directory:

```rust
// tests/integration_test.rs
use infiniservice::{Config, InfiniService};

#[tokio::test]
async fn test_service_initialization() {
    let config = Config::default();
    let service = InfiniService::new(config, false);
    
    assert!(service.initialize().await.is_ok());
}
```

### Mock Testing

Use mockall for mocking:

```rust
use mockall::{automock, predicate::*};

#[automock]
trait VirtioDevice {
    fn read(&self) -> Result<String>;
    fn write(&self, data: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_communication() {
        let mut mock = MockVirtioDevice::new();
        mock.expect_write()
            .with(eq("test"))
            .times(1)
            .returning(|_| Ok(()));
            
        assert!(mock.write("test").is_ok());
    }
}
```

## Debugging

### Debug Output

```bash
# Enable all debug output
RUST_LOG=debug cargo run

# Filter by module
RUST_LOG=infiniservice::collector=debug cargo run

# Enable backtrace
RUST_BACKTRACE=1 cargo run
```

### GDB/LLDB Debugging

```bash
# Build with debug symbols
cargo build

# Debug with GDB
gdb target/debug/infiniservice

# Debug with LLDB
lldb target/debug/infiniservice
```

### Performance Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Generate flamegraph
cargo flamegraph --bin infiniservice

# Use perf (Linux)
perf record -g target/release/infiniservice
perf report
```

### Memory Profiling

```bash
# Use Valgrind (Linux)
valgrind --leak-check=full target/debug/infiniservice

# Use heaptrack
heaptrack target/release/infiniservice
heaptrack_gui heaptrack.infiniservice.*
```

## Contributing

### Code Style Guidelines

1. **Naming Conventions**
   - Use `snake_case` for functions and variables
   - Use `PascalCase` for types and traits
   - Use `SCREAMING_SNAKE_CASE` for constants

2. **Documentation**
   - Document all public APIs
   - Use `///` for doc comments
   - Include examples in documentation

3. **Error Messages**
   - Be specific and actionable
   - Include context
   - Suggest solutions

### Commit Guidelines

Follow conventional commits:

```
feat: Add Windows service detection
fix: Resolve VirtIO device detection on Linux
docs: Update API documentation
test: Add integration tests for command execution
refactor: Simplify metrics collection logic
perf: Optimize memory usage in collector
```

### Pull Request Process

1. Create feature branch from `main`
2. Write tests for new functionality
3. Ensure all tests pass
4. Update documentation
5. Run `cargo fmt` and `cargo clippy`
6. Submit PR with clear description

## Common Tasks

### Adding a New Command

1. Define command type in `src/commands/mod.rs`:
```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum SafeCommandType {
    // ...existing commands...
    NewCommand { param: String },
}
```

2. Implement handler in appropriate executor:
```rust
// src/commands/safe_executor.rs
fn execute_new_command(param: &str) -> Result<CommandResponse> {
    // Implementation
}
```

3. Add to command dispatcher:
```rust
match command_type {
    SafeCommandType::NewCommand { param } => {
        execute_new_command(&param)
    }
}
```

4. Write tests:
```rust
#[test]
fn test_new_command() {
    let result = execute_new_command("test");
    assert!(result.is_ok());
}
```

### Adding Platform Support

1. Add platform detection in `src/os_detection.rs`
2. Implement platform-specific code with `#[cfg]`
3. Update `Cargo.toml` with platform dependencies
4. Test on target platform
5. Update documentation

### Performance Optimization

1. **Profile First**: Use flamegraph to identify bottlenecks
2. **Optimize Hot Paths**: Focus on frequently called code
3. **Reduce Allocations**: Use references where possible
4. **Cache Results**: Cache expensive computations
5. **Benchmark**: Use `criterion` for benchmarks

```rust
// benches/metrics_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_metrics_collection(c: &mut Criterion) {
    c.bench_function("collect metrics", |b| {
        b.iter(|| {
            collect_metrics()
        });
    });
}

criterion_group!(benches, benchmark_metrics_collection);
criterion_main!(benches);
```

## Troubleshooting Development Issues

### Common Build Errors

1. **Missing Dependencies**
```bash
# Update and rebuild
cargo clean
cargo update
cargo build
```

2. **Windows Cross-Compilation Fails**
```bash
# Ensure MinGW is installed
sudo apt-get install mingw-w64

# Set linker in .cargo/config
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

3. **Out of Memory During Compilation**
```bash
# Reduce parallel jobs
cargo build -j 2
```

### Runtime Issues

1. **VirtIO Device Not Found**
   - Check device permissions
   - Run with sudo for testing
   - Use `--diagnose` flag

2. **High CPU Usage**
   - Check collection interval
   - Profile with flamegraph
   - Review async task scheduling

3. **Memory Leaks**
   - Use valgrind or heaptrack
   - Check for circular references
   - Review buffer management

## Resources

### Documentation
- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Serde Documentation](https://serde.rs/)

### Tools
- [cargo-edit](https://github.com/killercup/cargo-edit) - Add/remove dependencies
- [cargo-watch](https://github.com/passcod/cargo-watch) - Auto-rebuild on changes
- [cargo-expand](https://github.com/dtolnay/cargo-expand) - Expand macros

### Community
- [Rust Users Forum](https://users.rust-lang.org/)
- [Rust Discord](https://discord.gg/rust-lang)
- [r/rust Reddit](https://www.reddit.com/r/rust/)